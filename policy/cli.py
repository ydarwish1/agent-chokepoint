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
import json
import math
import os
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

import yaml

from engine import Policy, ToolCall, Verdict, decide
from pep.log import loggable_arguments, loggable_tool

from .loader import PolicyError, _parse_verdict, _StrictLoader, ambiguous_server_identity, load_policy

#: PyYAML's pure-Python parser takes seconds per hundred KiB and slows further
#: with flow nesting (measured: 1 MiB of ``[x, x, ...]`` 7 s, of 64-deep
#: ``[[...]]`` 20 s, one 100 000-deep ``[[...]]`` 164 s), so both inputs are
#: capped before anything is built. 256 KiB holds well over a thousand cases,
#: and the shipped pack is under 20 KiB.
MAX_INPUT_BYTES = 256 * 1024
MAX_INPUT_DEPTH = 64

_FILE_KEYS = {"cases"}
_CASE_KEYS = {"tool", "arguments", "server", "verdict", "rule_id"}
_REQUIRED_CASE_KEYS = ("tool", "verdict", "rule_id")

#: Plain scalars YAML 1.1 reads as one of these types must be spelled the way
#: JSON spells that type: ``no`` is a bool and ``0755`` an int to YAML, while a
#: door only ever receives JSON, where they would be quoted strings.
_JSON_SPELLED_TAGS = {
    "tag:yaml.org,2002:bool": bool,
    "tag:yaml.org,2002:int": int,
    "tag:yaml.org,2002:float": float,
}
_RESOLVER = yaml.resolver.Resolver()


class CasesError(ValueError):
    """The cases file is invalid. The message says where and why."""


@dataclass(frozen=True)
class Case:
    """One tool call and the decision it must get."""

    call: ToolCall
    verdict: Verdict
    rule_id: str


def _guarded_text(path: str | Path, error: type[ValueError], *, cases: bool) -> str:
    """The text of ``path``, or ``error`` unless it is a regular UTF-8 file inside both caps.

    One descriptor is opened non-blocking, checked and read, so a FIFO cannot
    hold the open waiting for a writer and the file checked is the file read.
    Every other exception is converted, the way :func:`policy.load_policy` does
    it (D-030): an unreadable file or bad UTF-8 is an input that did not load,
    never a traceback.
    """
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise error(f"{path}: not a regular file")
            with open(fd, "rb", closefd=False) as handle:
                data = handle.read(MAX_INPUT_BYTES + 1)
        finally:
            os.close(fd)
        if len(data) > MAX_INPUT_BYTES:
            raise error(f"{path}: larger than {MAX_INPUT_BYTES} bytes")
        text = data.decode("utf-8")
        _check_events(text, path, error, cases=cases)
        return text
    except error:
        raise
    except yaml.YAMLError as exc:
        raise error(f"{path}: {_yaml_problem(exc)}") from exc
    except Exception as exc:  # noqa: BLE001 — deliberate: see the docstring
        raise error(f"{path}: could not be read: {type(exc).__name__}: {exc}") from exc


def _check_events(text: str, path: str | Path, error: type[ValueError], *, cases: bool) -> None:
    """Walk the YAML events once, stopping at the first thing this command refuses.

    The depth check runs on the event stream, so the parser stops at level
    ``MAX_INPUT_DEPTH + 1`` instead of paying for the rest of the nesting. A
    cases file also refuses aliases — a few hundred bytes of them expand into
    an argument tree the engine's scans would walk billions of times — and plain
    scalars YAML and JSON would read differently. A policy keeps both, because
    the doors' loader accepts them.
    """
    depth = 0
    for event in yaml.parse(text, Loader=_StrictLoader):
        if isinstance(event, yaml.CollectionStartEvent):
            depth += 1
            if depth > MAX_INPUT_DEPTH:
                raise error(f"{path}: nested deeper than {MAX_INPUT_DEPTH} levels")
        elif isinstance(event, yaml.CollectionEndEvent):
            depth -= 1
        elif cases and isinstance(event, yaml.AliasEvent):
            raise error(f"{path}: YAML aliases (*name) are not accepted in a cases file")
        elif cases and isinstance(event, yaml.ScalarEvent) and not _spelled_as_json(event):
            raise error(
                f"{path}: line {event.start_mark.line + 1}: a plain value YAML reads as a "
                "number or boolean that JSON would not; quote it if it is a string"
            )


def _spelled_as_json(event: yaml.ScalarEvent) -> bool:
    if event.style is not None or not event.implicit[0]:
        return True
    kind = _JSON_SPELLED_TAGS.get(_RESOLVER.resolve(yaml.ScalarNode, event.value, event.implicit))
    if kind is None:
        return True
    try:
        return type(json.loads(event.value)) is kind
    except ValueError:
        return False


def _yaml_problem(exc: yaml.YAMLError) -> str:
    """PyYAML's error without the source snippet it quotes, which may hold a credential."""
    mark = getattr(exc, "problem_mark", None)
    where = f" at line {mark.line + 1}, column {mark.column + 1}" if mark is not None else ""
    return f"not valid YAML{where}: {getattr(exc, 'problem', None) or type(exc).__name__}"


def load_cases(path: str | Path) -> tuple[Case, ...]:
    """Load and validate a cases file. Raises :class:`CasesError` on any problem."""
    text = _guarded_text(path, CasesError, cases=True)
    try:
        raw = yaml.load(text, Loader=_StrictLoader)  # SafeLoader + duplicate-key refusal
    except PolicyError as exc:
        raise CasesError(f"{path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise CasesError(f"{path}: {_yaml_problem(exc)}") from exc
    if not isinstance(raw, dict):
        raise CasesError(f"{path}: cases file must be a YAML mapping, got {type(raw).__name__}")
    unknown = set(raw) - _FILE_KEYS
    if unknown:
        raise CasesError(f"{path}: unknown top-level keys: {sorted(unknown, key=str)}")
    cases = raw.get("cases")
    if not isinstance(cases, list) or not cases:
        raise CasesError(f"{path}: cases must be a non-empty list")
    return tuple(_parse_case(case, f"{path}: case {index}") for index, case in enumerate(cases, 1))


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
    # Both doors only ever hand the engine a JSON object (or nothing), so a case
    # with any other shape describes a call no door would judge.
    if arguments is not None and not isinstance(arguments, dict):
        raise CasesError(f"{where}: arguments must be a mapping")
    if arguments is not None and not _json_shaped(arguments):
        raise CasesError(
            f"{where}: arguments may hold only what JSON carries: strings, finite numbers, "
            "booleans, null, lists and mappings with string keys"
        )
    server = None
    if "server" in raw:
        server = _non_empty_str(raw["server"], f"{where}: server")
        # B-034: a name no door can frame unambiguously is refused at both
        # doors, so no call ever reaches the engine carrying it.
        if ambiguous_server_identity(server):
            # Not echoed: a credential welded to `__` escapes the `\b`-anchored
            # matchers the redaction relies on.
            raise CasesError(f"{where}: server is not a usable MCP server identity ('__' is the delimiter)")
    return Case(call=ToolCall(tool=tool, arguments=arguments, server=server), verdict=verdict, rule_id=rule_id)


def _json_shaped(value: Any) -> bool:
    """True when ``value`` is something ``json.loads`` could have produced.

    Recursion is bounded by ``MAX_INPUT_DEPTH``, checked before the file loaded.
    """
    if value is None or isinstance(value, (str, bool, int)):
        return True
    if isinstance(value, float):
        return math.isfinite(value)
    if isinstance(value, list):
        return all(_json_shaped(item) for item in value)
    if isinstance(value, dict):
        return all(isinstance(key, str) and _json_shaped(item) for key, item in value.items())
    return False


def _non_empty_str(value: Any, where: str) -> str:
    if not isinstance(value, str) or not value:
        raise CasesError(f"{where} must be a non-empty string")
    return value


def _shown(text: str, hidden: Sequence[str]) -> str:
    """A tool name or rule id as printed: redacted, and on one line."""
    logged = loggable_tool(text, hidden)
    return logged if logged.isprintable() else repr(logged)


def check(policy: Policy, cases: Sequence[Case]) -> tuple[int, str]:
    """Judge every case. Returns ``(exit code, report)``."""
    hidden = policy.hidden_context.all_segments
    lines: list[str] = []
    failed = 0
    for index, case in enumerate(cases, 1):
        decision = decide(policy, case.call)
        tool = _shown(case.call.tool, hidden)
        got = f"{decision.verdict} {_shown(decision.rule_id, hidden)}"
        if decision.verdict is case.verdict and decision.rule_id == case.rule_id:
            lines.append(f"PASS case {index}: {tool} -> {got}")
        else:
            failed += 1
            want = f"{case.verdict} {_shown(case.rule_id, hidden)}"
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
        _guarded_text(args.policy, PolicyError, cases=False)
        policy = load_policy(args.policy)
    except PolicyError as exc:
        # No declared hidden context exists yet: the section did not load.
        return 2, _refusal("policy", exc, ())
    try:
        cases = load_cases(args.cases)
    except CasesError as exc:
        return 2, _refusal("cases", exc, policy.hidden_context.all_segments)
    return check(policy, cases)


def _refusal(what: str, exc: ValueError, hidden: Sequence[str]) -> str:
    """The load error, redacted: messages can quote values out of either file."""
    return f"chokepoint-policy: {what} did not load: {loggable_arguments(str(exc), hidden, truncate=False)}\n"


def main(argv: Sequence[str] | None = None) -> int:
    code, text = run(sys.argv[1:] if argv is None else argv)
    stream = sys.stderr if code == 2 else sys.stdout
    stream.write(text)
    return code


if __name__ == "__main__":
    sys.exit(main())
