"""``chokepoint-policy`` — hold a policy to the decisions it is written to make.

    chokepoint-policy check POLICY CASES

CASES is a YAML file of tool calls, each naming the verdict and rule id it must
get::

    cases:
      - tool: read_file
        arguments: {path: /workspace/src/main.py}
        verdict: allow
        rule_id: fs-read-scoped

POLICY goes through :func:`policy.load_policy` and every case through
:func:`engine.decide`, the same loader and engine both doors use, and in the
envelope both doors build: the bare tool name, the arguments, and ``server``
when the case names one. One line per case, then a summary.

Two things a door does are deliberately NOT done here, so a cases file means
the same on every machine that runs it:

* **No run state.** The envelope carries ``run_state=None`` — the hook's
  envelope — so ``limits:`` and ``taint:`` are not consulted.
* **No path canonicalization.** The doors resolve symlinks and case against the
  filesystem they run on (``pep.canonicalize``); a case is judged on the path as
  written.

Exit codes: 0 every case got its verdict and rule id, 1 at least one did not,
2 the policy or the cases file did not load (argparse's usage errors are 2 too).
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

import yaml

from engine import ToolCall, Verdict, decide
from pep.log import loggable_tool

from .loader import PolicyError, _parse_verdict, _StrictLoader, ambiguous_server_identity, load_policy

#: PyYAML's pure-Python parser takes seconds per hundred KiB and slows further
#: with flow nesting (measured: 1 MiB of ``[x, x, ...]`` 7 s, of 64-deep
#: ``[[...]]`` 20 s, one 100 000-deep ``[[...]]`` 164 s), so both are capped
#: before anything is built. 256 KiB holds well over a thousand cases.
MAX_CASES_BYTES = 256 * 1024
MAX_CASES_DEPTH = 64

_FILE_KEYS = {"cases"}
_CASE_KEYS = {"tool", "arguments", "server", "verdict", "rule_id"}
_REQUIRED_CASE_KEYS = ("tool", "verdict", "rule_id")


class CasesError(ValueError):
    """The cases file is invalid. The message says where and why."""


@dataclass(frozen=True)
class Case:
    """One tool call and the decision it must get."""

    call: ToolCall
    verdict: Verdict
    rule_id: str


def load_cases(path: str | Path) -> tuple[Case, ...]:
    """Load and validate a cases file. Raises :class:`CasesError` on any problem.

    Every other exception is converted, the way :func:`policy.load_policy` does
    it (D-030): an unreadable file or bad UTF-8 is a cases file that did not
    load, never a traceback.
    """
    try:
        return _load_cases(path)
    except CasesError:
        raise
    except Exception as exc:  # noqa: BLE001 — deliberate: see the docstring
        raise CasesError(f"{path}: cases could not be loaded: {type(exc).__name__}: {exc}") from exc


def _load_cases(path: str | Path) -> tuple[Case, ...]:
    # is_file() first: open() on a FIFO waits for a writer instead of failing.
    if not Path(path).is_file():
        raise CasesError(f"{path}: not a regular file (missing, a directory or a pipe)")
    with open(path, "rb") as handle:
        data = handle.read(MAX_CASES_BYTES + 1)
    if len(data) > MAX_CASES_BYTES:
        raise CasesError(f"{path}: larger than {MAX_CASES_BYTES} bytes")
    text = data.decode("utf-8")
    try:
        _refuse_expansion(text, path)
        raw = yaml.load(text, Loader=_StrictLoader)  # SafeLoader + duplicate-key refusal
    except PolicyError as exc:
        raise CasesError(f"{path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise CasesError(f"{path}: not valid YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise CasesError(f"{path}: cases file must be a YAML mapping, got {type(raw).__name__}")
    unknown = set(raw) - _FILE_KEYS
    if unknown:
        raise CasesError(f"{path}: unknown top-level keys: {sorted(unknown, key=str)}")
    cases = raw.get("cases")
    if not isinstance(cases, list) or not cases:
        raise CasesError(f"{path}: cases must be a non-empty list")
    return tuple(_parse_case(case, f"{path}: case {index}") for index, case in enumerate(cases, 1))


def _refuse_expansion(text: str, path: str | Path) -> None:
    """Walk the YAML events once, stopping at the first alias or past the depth cap.

    An alias lets a few hundred bytes expand into an argument tree the engine's
    scans would walk billions of times. The depth check runs on the event
    stream, so the parser stops at level ``MAX_CASES_DEPTH + 1`` instead of
    paying for the rest of the nesting.
    """
    depth = 0
    for event in yaml.parse(text, Loader=_StrictLoader):
        if isinstance(event, yaml.AliasEvent):
            raise CasesError(f"{path}: YAML aliases (*name) are not accepted in a cases file")
        if isinstance(event, yaml.CollectionStartEvent):
            depth += 1
            if depth > MAX_CASES_DEPTH:
                raise CasesError(f"{path}: nested deeper than {MAX_CASES_DEPTH} levels")
        elif isinstance(event, yaml.CollectionEndEvent):
            depth -= 1


def _parse_case(raw: Any, where: str) -> Case:
    if not isinstance(raw, dict):
        raise CasesError(f"{where} must be a mapping")
    unknown = set(raw) - _CASE_KEYS
    if unknown:
        raise CasesError(f"{where} has unknown keys: {sorted(unknown, key=str)}")
    for required in _REQUIRED_CASE_KEYS:
        if required not in raw:
            raise CasesError(f"{where} is missing required key {required!r}")
    tool = _non_empty_str(raw["tool"], f"{where}: tool")
    rule_id = _non_empty_str(raw["rule_id"], f"{where}: rule_id")
    try:
        verdict = _parse_verdict(raw["verdict"], f"{where}: verdict")
    except PolicyError as exc:
        raise CasesError(str(exc)) from exc
    arguments = raw.get("arguments")
    # Both doors only ever hand the engine an object (or nothing), so a case
    # with any other shape describes a call no door would judge.
    if arguments is not None and not isinstance(arguments, dict):
        raise CasesError(f"{where}: arguments must be a mapping")
    server = None
    if "server" in raw:
        server = _non_empty_str(raw["server"], f"{where}: server")
        # B-034: a name no door can frame unambiguously is refused at both
        # doors, so no call ever reaches the engine carrying it.
        if ambiguous_server_identity(server):
            raise CasesError(f"{where}: server {server!r} is not a usable MCP server identity")
    return Case(call=ToolCall(tool=tool, arguments=arguments, server=server), verdict=verdict, rule_id=rule_id)


def _non_empty_str(value: Any, where: str) -> str:
    if not isinstance(value, str) or not value:
        raise CasesError(f"{where} must be a non-empty string")
    return value


def _one_line(text: str) -> str:
    """``text``, or its repr when it carries a newline or an invisible character."""
    return text if text.isprintable() else repr(text)


def check(policy_path: str | Path, cases_path: str | Path) -> tuple[int, str]:
    """Judge every case. Returns ``(exit code, report)``; raises on a load failure."""
    policy = load_policy(policy_path)
    cases = load_cases(cases_path)
    hidden = policy.hidden_context.all_segments
    lines: list[str] = []
    failed = 0
    for index, case in enumerate(cases, 1):
        decision = decide(policy, case.call)
        tool = _one_line(loggable_tool(case.call.tool, hidden))
        got = f"{decision.verdict} {_one_line(decision.rule_id)}"
        if decision.verdict is case.verdict and decision.rule_id == case.rule_id:
            lines.append(f"PASS case {index}: {tool} -> {got}")
        else:
            failed += 1
            want = f"{case.verdict} {_one_line(case.rule_id)}"
            lines.append(f"FAIL case {index}: {tool} -> expected {want}, got {got}")
    lines.append(f"{len(cases) - failed} of {len(cases)} cases match")
    return (1 if failed else 0), "\n".join(lines) + "\n"


def _parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="chokepoint-policy",
        description="Work with a chokepoint policy file.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    check_parser = commands.add_parser(
        "check",
        help="judge a YAML file of tool calls against a policy",
        description=(
            "Judge every case in CASES against POLICY with the loader and engine both doors "
            "use, and print one line per case."
        ),
        epilog=(
            "Exit 0 when every case gets its verdict and rule id, 1 when any case does not, "
            "2 when POLICY or CASES does not load."
        ),
    )
    check_parser.add_argument("policy", metavar="POLICY", help="policy file to load")
    check_parser.add_argument(
        "cases", metavar="CASES", help="YAML file of cases: tool, arguments, server, verdict, rule_id"
    )
    return parser.parse_args(list(argv))


def run(argv: Sequence[str]) -> tuple[int, str]:
    """Returns ``(exit code, text)``. Exit 2 is an input that did not load, not a crash."""
    args = _parse_args(argv)
    try:
        return check(args.policy, args.cases)
    except PolicyError as exc:
        return 2, f"chokepoint-policy: policy did not load: {exc}\n"
    except CasesError as exc:
        return 2, f"chokepoint-policy: cases did not load: {exc}\n"


def main(argv: Sequence[str] | None = None) -> int:
    code, text = run(sys.argv[1:] if argv is None else argv)
    stream = sys.stderr if code == 2 else sys.stdout
    stream.write(text)
    return code


if __name__ == "__main__":
    sys.exit(main())
