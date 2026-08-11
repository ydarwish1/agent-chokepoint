"""One engine, two doors, judged side by side.

The property demonstrated here: *the same engine returns identical verdicts
through the proxy and through the Claude Code hook for the same tool call.*
This script is that demonstration, and it writes its own transcript — every
verdict in the output was produced by a program during the run, never typed.

Three sections, and the distinction between them is the honest part:

**Part A — the literal comparison.** MCP tool calls, because those give the two
doors a byte-identical envelope. The proxy leg is a real ``tools/call`` over a
real stdio wire (``proxy/demo/run_demo.py``'s wiring, reused); the hook leg is
``hooks/chokepoint_hook.py`` run as a real subprocess with a ``PreToolUse``
payload whose ``tool_name`` is ``mcp__demo__<tool>`` and whose ``tool_input`` is
the same arguments object. The hook strips the prefix and passes the arguments
through unchanged, so both doors hand the engine the same ``ToolCall``. That is
checked rather than asserted: the two decision events log their arguments and
this script compares them.

**Part B — the translated comparison.** Claude Code's own built-ins (``Read``,
``Bash``, ``WebFetch``) reaching the engine through ``NATIVE_TOOLS``. These
envelopes are **not** identical — the hook adds the canonical key to a copy of
the payload and keeps the rest — so the claim here is narrower: the translation
lands on the same verdict the proxy gives the equivalent MCP call. Plus one
unmapped tool (``Grep``), which produces no decision at all.

**Part C — where the two doors deliberately differ**, demonstrated rather than
described: ``ask`` enforcement, ``limits:`` enforcement, and the unmapped-tool
gap.

**Every case carries the verdict and rule id it is EXPECTED to produce**, as
data next to the call rather than as a comment beside it. Agreement alone is a
weak property: a regression that hits both doors equally — a policy file edited,
a predicate broken in the engine both doors share — reads as perfect agreement
while the answers are wrong. The expectation column is what makes this harness
test the policy's behaviour rather than merely test the two doors against each
other.

    .venv/bin/python hooks/demo/side_by_side.py
    .venv/bin/python hooks/demo/side_by_side.py --out FILE

Exit 0 only when every property the transcript asserts holds — they are listed
individually, each with its own PASS/FAIL, in the closing VERDICT block. A door
that wrote no decision event has not agreed with anything: an absent verdict is
a failure here, never a match. Exit 1 otherwise; a failure is a finding, not a
formatting problem.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

if __package__ in (None, ""):
    # Run as a bare script (`python hooks/demo/side_by_side.py`), sys.path[0] is
    # THIS directory, so `policy` would not import. Same guard, same reason, as
    # hooks/chokepoint_hook.py. Imported as `hooks.demo.side_by_side` (the test)
    # __package__ is set and sys.path is left alone.
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import anyio  # noqa: E402

from mcp import Client, MCPError, StdioServerParameters, stdio_client  # noqa: E402

from engine import Verdict  # noqa: E402

from policy import load_policy  # noqa: E402

# The only strings a decision event's `verdict` may hold, read off the engine's
# own enum rather than written here. Anything else in a verdict column — the
# `<n events>` sentinel below, most of all — means that door was not measured,
# and an unmeasured door has not agreed with anything.
VERDICTS: frozenset[str] = frozenset(str(v) for v in Verdict)

REPO_ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = REPO_ROOT / "policy" / "policy.example.yaml"
UPSTREAM = REPO_ROOT / "proxy" / "demo" / "upstream_server.py"
HOOK = REPO_ROOT / "hooks" / "chokepoint_hook.py"

# The commit B-006 landed on, and the base of the engine freeze check: adding the
# second enforcement point required zero engine changes, so
# `git diff <this> -- engine/` must return empty. Printed by this script rather
# than asserted in prose, because "the same engine" is the headline claim here.
ENGINE_FREEZE_BASE = "db4c532"

# The MCP server label in the hook payload. Claude Code namespaces MCP tools as
# `mcp__<server>__<tool>`; the server name is the agent's local wiring and never
# reaches the engine, which sees the bare tool name from either door.
MCP_SERVER_LABEL = "demo"


@dataclass(frozen=True)
class Case:
    """One MCP call, and the answer ``policy/policy.example.yaml`` owes it.

    ``expect_verdict``/``expect_rule`` are DATA, checked against both doors, not
    a comment. Without them this harness asserts only that the two doors say the
    same thing — which a regression reaching both of them satisfies perfectly.
    """

    tool: str
    args: dict
    expect_verdict: str
    expect_rule: str
    why: str

    @property
    def label(self) -> str:
        return f"{self.tool} {compact(self.args)}"


@dataclass(frozen=True)
class NativeCase:
    """One Claude Code built-in payload and the MCP call it translates to."""

    name: str
    payload: dict
    equivalent: Case

    @property
    def label(self) -> str:
        return f"{self.name} -> {self.equivalent.tool}"


# --- Part A: six MCP calls covering every verdict the policy can produce. -----
# Expectations read off policy/policy.example.yaml (absolute prefixes since B-006).
MCP_CASES: list[Case] = [
    Case("read_file", {"path": "/workspace/notes.txt"}, "allow", "fs-read-scoped",
         "inside path_within and under no deny prefix"),
    Case("fetch_url", {"url": "https://docs.python.org/3/"}, "allow", "net-fetch-allowlist",
         "docs.python.org is in domain_in"),
    Case("fetch_url", {"url": "https://example.net/data.json"}, "block", "default:on_no_match",
         "domain is not on the allowlist and no other rule matches"),
    Case("write_file", {"path": "/workspace/out.txt"}, "ask", "fs-write-scoped",
         "writes surface to a human in this policy"),
    Case("run_command", {"command": "chmod 777 /tmp/shared"}, "block", "shell-destructive",
         "command_matches_any hits the 'chmod 777' regex"),
    # The B-006 property, exercised rather than described: a path INSIDE the
    # allow prefix but under one of the deny prefixes nested in it. Before B-006
    # the deny half changed 0 of 15 path decisions while reading as protective,
    # and no case in this file would have noticed — every other read here is
    # either plainly inside the allow prefix or plainly outside it, and both of
    # those answer the same way whether path_not_within works or not.
    Case("read_file", {"path": "/workspace/.ssh/config"}, "block", "default:on_no_match",
         "inside path_within but under path_not_within, so fs-read-scoped does not match"),
]

# --- Part B: native Claude Code tools and the MCP call they translate to. -----
NATIVE_CASES: list[NativeCase] = [
    NativeCase(
        "Read",
        {"file_path": "/workspace/src/main.py"},
        Case("read_file", {"path": "/workspace/src/main.py"}, "allow", "fs-read-scoped",
             "inside path_within and under no deny prefix"),
    ),
    NativeCase(
        "Bash",
        {"command": "chmod 777 /tmp/shared", "description": "Loosen permissions on the shared dir"},
        Case("run_command", {"command": "chmod 777 /tmp/shared"}, "block", "shell-destructive",
             "command_matches_any hits the 'chmod 777' regex"),
    ),
    NativeCase(
        "WebFetch",
        {"url": "https://docs.python.org/3/", "prompt": "Summarise this page"},
        Case("fetch_url", {"url": "https://docs.python.org/3/"}, "allow", "net-fetch-allowlist",
             "docs.python.org is in domain_in"),
    ),
]

# Outside NATIVE_TOOLS: the hook makes no decision and writes no event.
UNMAPPED_CASE: tuple[str, dict] = ("Grep", {"pattern": "TODO", "path": "/workspace/src"})

# --- Part C: the limits divergence. -------------------------------------------
# The call is repeated one time more than the policy's own
# max_repeated_identical_calls, so the last attempt is the first one a limit can
# refuse. The cap is READ from the policy rather than written here — a number in
# this file would be a claim about a file it does not own. The hook sends
# run_state=None and never sees a limit at all.
LIMIT_TOOL, LIMIT_ARGS = "read_file", {"path": "/workspace/notes.txt"}

lines: list[str] = []


def say(text: str = "") -> None:
    lines.append(text)
    print(text, flush=True)


def rule(title: str, width: int = 72) -> None:
    say(f"--- {title} " + "-" * max(0, width - len(title) - 5))


def compact(obj: object) -> str:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True)


# ------------------------------------------------------------------ the proxy leg


def child_env() -> dict[str, str]:
    """A stdio child does not inherit the parent environment (the SDK passes an
    allow-list). The proxy and upstream both need to find this project."""
    env = {k: os.environ[k] for k in ("HOME", "PATH", "LOGNAME", "SHELL", "TERM", "USER") if k in os.environ}
    env["PYTHONPATH"] = str(REPO_ROOT)
    return env


def proxy_argv(sandbox: Path, log_file: Path) -> list[str]:
    return [
        "-m", "proxy",
        "--policy", str(POLICY_PATH),
        "--agent-id", "proxy-leg",
        "--log-file", str(log_file),
        "--", sys.executable, str(UPSTREAM), "--sandbox", str(sandbox),
    ]


def proxied_params(sandbox: Path, log_file: Path) -> StdioServerParameters:
    return StdioServerParameters(
        command=sys.executable, args=proxy_argv(sandbox, log_file), cwd=str(REPO_ROOT), env=child_env()
    )


async def one_call(client: Client, tool: str, args: dict) -> str:
    """What the CLIENT saw — the enforcement, not the verdict."""
    try:
        result = await client.call_tool(tool, args)
        return "RESULT   " + result.content[0].text.replace("\n", " ")[:100].strip()
    except MCPError as exc:
        return f"REFUSED  code={exc.error.code} {exc.error.message}"


async def proxy_leg(calls: list[tuple[str, dict]], sandbox: Path, log_file: Path) -> tuple[list[str], list[dict]]:
    """Drive ``calls`` through one proxy process. Returns (outcomes, tools/call events).

    One client session for the whole list on purpose: the proxy's run-state
    counters live in the process, so Part C's repeated-call limit only exists
    while the session does.
    """
    outcomes: list[str] = []
    async with Client(stdio_client(proxied_params(sandbox, log_file))) as client:
        for tool, args in calls:
            outcomes.append(await one_call(client, tool, args))
    return outcomes, [e for e in read_events(log_file) if e.get("method") == "tools/call"]


def executed(sandbox: Path) -> list[str]:
    """The upstream's own record of what reached it — the ground truth for the
    proxy leg. A line appears exactly when a call reaches the tool process."""
    log = sandbox / "EXECUTED.log"
    return log.read_text(encoding="utf-8").splitlines() if log.is_file() else []


# ------------------------------------------------------------------- the hook leg


def hook_argv(log_file: Path) -> list[str]:
    return [
        sys.executable, str(HOOK),
        "--policy", str(POLICY_PATH),
        "--agent-id", "hook-leg",
        "--log-file", str(log_file),
    ]


def hook_payload(tool_name: str, tool_input: dict) -> dict:
    """One PreToolUse envelope, key-for-key as captured from a real headless
    Claude Code 2.1.220. ``effort`` is an object, not a string."""
    return {
        "cwd": "/workspace",
        "effort": {"level": "high"},
        "hook_event_name": "PreToolUse",
        "permission_mode": "default",
        "prompt_id": "side-by-side",
        "session_id": "side-by-side",
        "tool_input": tool_input,
        "tool_name": tool_name,
        "tool_use_id": "toolu_side_by_side",
        "transcript_path": "/dev/null",
    }


@dataclass(frozen=True)
class HookRun:
    exit_code: int
    stdout: str
    events: list[dict]

    @property
    def permission_decision(self) -> str | None:
        if not self.stdout.strip():
            return None
        return json.loads(self.stdout)["hookSpecificOutput"]["permissionDecision"]


def hook_leg(tool_name: str, tool_input: dict, log_file: Path, cwd: Path) -> HookRun:
    """Run the hook the way Claude Code runs it: a real subprocess, JSON on
    stdin, the user's project as the working directory (never the repo root —
    that is why the hook puts its own repo on ``sys.path``)."""
    before = len(read_events(log_file))
    done = subprocess.run(
        hook_argv(log_file),
        input=json.dumps(hook_payload(tool_name, tool_input)),
        capture_output=True,
        text=True,
        cwd=str(cwd),
    )
    return HookRun(done.returncode, done.stdout, read_events(log_file)[before:])


def read_events(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


# ------------------------------------------------------------------- comparison


@dataclass(frozen=True)
class Row:
    label: str
    proxy_verdict: str
    proxy_rule: str
    hook_verdict: str
    hook_rule: str
    expect_verdict: str
    expect_rule: str

    @property
    def measured(self) -> bool:
        """Did BOTH doors actually produce a verdict for this call?

        The load-bearing question, and the one this harness used to get wrong: a
        door that wrote no decision event lands in its verdict column as the
        ``<0 events>`` sentinel, and two sentinels compare equal. That scored a
        pair of silent doors as perfect agreement — the exact shape of evidence
        that cannot fail. A sentinel is not a verdict; a row holding one has
        measured nothing and is a failure, not a match.
        """
        return self.proxy_verdict in VERDICTS and self.hook_verdict in VERDICTS

    @property
    def agree(self) -> bool:
        return self.measured and (self.proxy_verdict, self.proxy_rule) == (self.hook_verdict, self.hook_rule)

    @property
    def as_expected(self) -> bool:
        """Both doors agreed AND the answer is the one the policy owes this call."""
        return self.agree and (self.proxy_verdict, self.proxy_rule) == (self.expect_verdict, self.expect_rule)

    @property
    def status(self) -> str:
        if not self.measured:
            return "NOT MEASURED"
        if not self.agree:
            return "DISAGREE"
        if not self.as_expected:
            return "UNEXPECTED"
        return "AGREE"


def verdict_of(events: list[dict]) -> tuple[str, str]:
    """(verdict, rule_id) from exactly one decision event.

    A count other than one is reported as itself rather than smoothed over: a
    door that emitted no event, or two, has not agreed with anything. The
    sentinel is deliberately not a member of :data:`VERDICTS`, which is what
    makes :attr:`Row.measured` false for it.
    """
    if len(events) != 1:
        return (f"<{len(events)} events>", "-")
    return (str(events[0]["verdict"]), str(events[0]["rule_id"]))


def render(rows: list[Row]) -> None:
    heads = ("call", "expected verdict / rule", "proxy verdict / rule", "hook verdict / rule")
    cols = [
        [r.label for r in rows],
        [f"{r.expect_verdict} / {r.expect_rule}" for r in rows],
        [f"{r.proxy_verdict} / {r.proxy_rule}" for r in rows],
        [f"{r.hook_verdict} / {r.hook_rule}" for r in rows],
    ]
    widths = [max([len(h)] + [len(c) for c in col]) for h, col in zip(heads, cols)]
    say("  " + "  ".join(f"{h:<{w}}" for h, w in zip(heads, widths)) + "  result")
    say("  " + "  ".join("-" * w for w in widths) + "  ------------")
    for row, *cells in zip(rows, *cols):
        say("  " + "  ".join(f"{c:<{w}}" for c, w in zip(cells, widths)) + f"  {row.status}")


def translation_carried(proxy_event: dict, run: HookRun) -> bool:
    """Did the hook's TRANSLATED envelope carry the proxy's canonical argument?

    Part A has an envelope check; Part B had none, so three rows that measured
    nothing still reported "disagreements: 0". This is Part B's equivalent, and
    it is deliberately not an equality: the two envelopes here are different on
    purpose (the hook adds the canonical key to a copy of the payload and keeps
    the rest). What must be true is narrower — every key/value the proxy handed
    the engine is present, unchanged, in what the hook handed the engine. A row
    where the hook logged nothing, or logged a different path, fails.
    """
    if not run.events:
        return False
    proxy_args = proxy_event.get("arguments")
    hook_args = run.events[0].get("arguments")
    if not isinstance(proxy_args, dict) or not isinstance(hook_args, dict) or not proxy_args:
        return False
    return all(hook_args.get(key) == value for key, value in proxy_args.items())


def aligned(results: Results, section: str, expected: int, **legs: list) -> str | None:
    """Record a leg-length mismatch instead of letting ``zip`` swallow it.

    ``zip(cases, proxy_events, hook_runs)`` stops at the shortest leg. Two proxy
    events where five were expected therefore produced two rows and a cheerful
    "0 of 2" — three cases vanished and nothing said so. Every section states
    how many rows it expects and how many each leg produced; a mismatch is an
    error carried into :attr:`Results.ok`, not a smaller table. Returned as well
    as recorded, so the section that found it prints it where it happened.
    """
    sizes = {name: len(seq) for name, seq in legs.items()}
    if all(size == expected for size in sizes.values()):
        return None
    problem = (
        f"{section}: expected {expected} row(s) from each leg, got {sizes} — "
        f"{max(0, expected - min(sizes.values()))} case(s) would have been dropped silently by zip()"
    )
    results.leg_errors.append(problem)
    return problem


@dataclass
class Results:
    rows_a: list[Row] = field(default_factory=list)
    rows_b: list[Row] = field(default_factory=list)
    envelope_matches: int = 0
    translation_matches: int = 0
    limit_attempts: int = 0
    limit_rows: int = 0
    limit_proxy_blocks: int = 0
    limit_hook_blocks: int = 0
    unmapped_hook_events: int = -1
    unmapped_hook_stdout: str = "<not measured>"
    leg_errors: list[str] = field(default_factory=list)

    @property
    def rows(self) -> list[Row]:
        return self.rows_a + self.rows_b

    @property
    def disagreements(self) -> int:
        return sum(1 for r in self.rows if not r.agree)

    @property
    def envelope_mismatches(self) -> int:
        return len(self.rows_a) - self.envelope_matches

    @property
    def translation_mismatches(self) -> int:
        return len(self.rows_b) - self.translation_matches

    @property
    def checks(self) -> list[tuple[str, bool, str]]:
        """(name, passed, detail) for every property this transcript asserts.

        ``ok`` used to be ``disagreements == 0 and envelope_mismatches == 0`` —
        two of the eight. The other six were printed as findings and enforced by
        nothing, so a run could report an unmapped tool that emitted an ``allow``,
        a proxy that had stopped enforcing limits, and a hook that had started,
        and still exit 0. Every line the VERDICT block prints is now a line that
        can fail the run.
        """
        unmeasured = [r for r in self.rows if not r.measured]
        disagreed = [r for r in self.rows if r.measured and not r.agree]
        unexpected = [r for r in self.rows if r.agree and not r.as_expected]
        return [
            (
                "every case produced one row per leg (no leg truncated)",
                not self.leg_errors
                and len(self.rows_a) == len(MCP_CASES)
                and len(self.rows_b) == len(NATIVE_CASES),
                "; ".join(self.leg_errors)
                or f"part A {len(self.rows_a)}/{len(MCP_CASES)}, part B {len(self.rows_b)}/{len(NATIVE_CASES)}",
            ),
            (
                "both doors produced exactly one decision event per call",
                not unmeasured,
                "; ".join(
                    f"{r.label}: proxy={r.proxy_verdict} hook={r.hook_verdict}" for r in unmeasured
                ) or f"{len(self.rows)} of {len(self.rows)} rows measured at both doors",
            ),
            (
                "the two doors agreed on verdict AND rule id",
                not disagreed,
                "; ".join(
                    f"{r.label}: proxy={r.proxy_verdict}/{r.proxy_rule} hook={r.hook_verdict}/{r.hook_rule}"
                    for r in disagreed
                ) or f"{len(self.rows)} of {len(self.rows)} rows agree",
            ),
            (
                "every verdict is the one the policy owes the call (expectation, not agreement)",
                not unexpected,
                "; ".join(
                    f"{r.label}: expected {r.expect_verdict}/{r.expect_rule}, got {r.proxy_verdict}/{r.proxy_rule}"
                    for r in unexpected
                ) or f"{len(self.rows)} of {len(self.rows)} rows match their stated expectation",
            ),
            (
                "part A envelopes byte-identical at both doors",
                self.envelope_mismatches == 0 and len(self.rows_a) > 0,
                f"{self.envelope_matches} of {len(self.rows_a)} identical",
            ),
            (
                "part B translations carried the canonical argument unchanged",
                self.translation_mismatches == 0 and len(self.rows_b) > 0,
                f"{self.translation_matches} of {len(self.rows_b)} carried",
            ),
            (
                "the unmapped native tool produced no decision and no event",
                self.unmapped_hook_events == 0 and self.unmapped_hook_stdout == "",
                f"{self.unmapped_hook_events} event(s), stdout={self.unmapped_hook_stdout!r}",
            ),
            (
                "the documented limits gap is exactly as documented",
                self.limit_attempts > 0
                and self.limit_rows == self.limit_attempts
                and self.limit_proxy_blocks == 1
                and self.limit_hook_blocks == 0,
                f"{self.limit_rows} of {self.limit_attempts} attempts compared; "
                f"proxy blocked {self.limit_proxy_blocks} (expected 1), "
                f"hook blocked {self.limit_hook_blocks} (expected 0)",
            ),
        ]

    @property
    def ok(self) -> bool:
        return all(passed for _name, passed, _detail in self.checks)


# ------------------------------------------------------------------------ header


def engine_freeze() -> str:
    """`git diff <B-006 commit> --stat -- engine/`, run rather than claimed."""
    try:
        done = subprocess.run(
            ["git", "-C", str(REPO_ROOT), "diff", ENGINE_FREEZE_BASE, "--stat", "--", "engine/"],
            capture_output=True,
            text=True,
        )
    except OSError as exc:  # git missing: say so, never imply a clean result
        return f"<could not run git: {exc}>"
    if done.returncode != 0:
        return f"<git exited {done.returncode}: {done.stderr.strip()}>"
    return done.stdout.strip() or f"<empty — engine/ unchanged since {ENGINE_FREEZE_BASE}>"


def header(sandbox_root: Path, proxy_log: Path, hook_log: Path) -> None:
    say("Agent-Chokepoint — one engine, two doors, judged side by side")
    say("=" * 78)
    say()
    say("The property this artifact demonstrates:")
    say('  "the same engine returns identical verdicts through the proxy and through')
    say('   the Claude Code hook for the same tool call, demonstrated side by side"')
    say()
    say("This file is generated by hooks/demo/side_by_side.py. Every verdict below was")
    say("read out of a decision event a program wrote during this run.")
    say()
    say(f"  date:    {datetime.now().astimezone().isoformat(timespec='seconds')}")
    say(f"  python:  {sys.version.split()[0]}  ({sys.executable})")
    say(f"  policy:  {POLICY_PATH.relative_to(REPO_ROOT)} (the committed file, unmodified — both doors load it)")
    say( "  agent:   none. Parts A-C are driven by this script, not by an LLM. The hook")
    say( "           is exercised as a real subprocess with the payload shape a real")
    say( "           Claude Code 2.1.220 sends (measured 2026-08-02).")
    say(f"  engine:  git diff {ENGINE_FREEZE_BASE} --stat -- engine/  ->  {engine_freeze()}")
    say()
    say("  this transcript was generated by:")
    say(f"    {sys.executable} {' '.join(sys.argv)}")
    say()
    say("  proxy leg command (spawned per section, real stdio wire):")
    say(f"    {sys.executable} \\")
    say("      " + " ".join(proxy_argv(Path("<sandbox>"), Path("<proxy-decisions.jsonl>"))))
    say("  hook leg command (one subprocess per call, PreToolUse JSON on stdin):")
    say("    " + " ".join(hook_argv(Path("<hook-decisions.jsonl>"))))
    say()
    say("GROUND TRUTH, per claim:")
    say("  - verdict + rule id, PROXY leg: the proxy's own decision events, written by")
    say(f"    proxy/server.py to {proxy_log.name}. Not the client's account of itself.")
    say("  - verdict + rule id, HOOK leg: the hook's own decision events, written by")
    say(f"    hooks/chokepoint_hook.py to {hook_log.name}, one line per JUDGED call.")
    say("    (Each section gets its own pair of log files and its own sandbox, so no")
    say("     section can read another's events; the names above are Part A's.)")
    say("  - what actually REACHED the tool, proxy leg: the upstream's EXECUTED.log,")
    say("    written by proxy/demo/upstream_server.py when a call arrives at it.")
    say("  - what the hook told Claude Code to do: the permissionDecision on its stdout")
    say("    and its exit code, captured from the subprocess.")
    say("  The hook leg has no upstream: a PreToolUse hook answers before the tool runs")
    say("  and never sees it execute, so 'reached the tool' is a proxy-leg claim only.")
    say()
    say("NOTE: the upstream RECORDS every call instead of executing it — run_command")
    say("      never runs a shell. That substitution is the point: the observable is")
    say("      reach, and proving it with a real destructive command would be reckless.")
    say(f"      sandboxes: {sandbox_root}")
    say()


# -------------------------------------------------------------------- the sections


async def part_a(tmp: Path, results: Results) -> None:
    rule("PART A — MCP calls: one arguments object, two doors (LITERAL)")
    say()
    say("MCP tool calls are used here because they are the case where the two doors")
    say("receive a byte-identical envelope. The proxy hands the engine the wire's own")
    say("`name` + `arguments`; the hook strips `mcp__demo__` and hands over `tool_input`")
    say("unchanged. Nothing is translated, so a disagreement could only be the engine")
    say("being called differently.")
    say()

    sandbox = tmp / "part-a"
    sandbox.mkdir()
    (sandbox / "notes.txt").write_text("benign sandbox file\n", encoding="utf-8")
    proxy_log = tmp / "proxy-part-a.jsonl"
    hook_log = tmp / "hook-part-a.jsonl"

    outcomes, proxy_events = await proxy_leg([(c.tool, c.args) for c in MCP_CASES], sandbox, proxy_log)
    hook_runs = [
        hook_leg(f"mcp__{MCP_SERVER_LABEL}__{c.tool}", c.args, hook_log, sandbox) for c in MCP_CASES
    ]
    short = aligned(results, "part A", len(MCP_CASES), proxy_events=proxy_events, hook_runs=hook_runs)

    say("  the calls, as each door received them, with the answer the policy owes each:")
    say()
    for i, case in enumerate(MCP_CASES, 1):
        say(f"    {i}. proxy  tools/call  name={case.tool}")
        say(f"       hook   PreToolUse  tool_name=mcp__{MCP_SERVER_LABEL}__{case.tool}")
        say(f"       arguments / tool_input = {compact(case.args)}")
        say(f"       expected: {case.expect_verdict} / {case.expect_rule}  ({case.why})")
    say()

    for case, event, run in zip(MCP_CASES, proxy_events, hook_runs):
        pv, pr = verdict_of([event])
        hv, hr = verdict_of(run.events)
        results.rows_a.append(Row(case.label, pv, pr, hv, hr, case.expect_verdict, case.expect_rule))
        if run.events and event.get("arguments") == run.events[0].get("arguments"):
            results.envelope_matches += 1

    if short:
        say(f"  LEG ERROR — {short}")
        say()
    render(results.rows_a)
    say()
    say("  envelope check — the arguments each door logged, compared field for field:")
    for i, (event, run) in enumerate(zip(proxy_events, hook_runs), 1):
        logged_hook = run.events[0].get("arguments") if run.events else None
        same = event.get("arguments") == logged_hook
        say(f"    {i}. {'IDENTICAL' if same else 'DIFFERENT'}  proxy={compact(event.get('arguments'))}  hook={compact(logged_hook)}")
    say()
    say("  what each door DID with that verdict (enforcement, not decision):")
    for i, (outcome, run) in enumerate(zip(outcomes, hook_runs), 1):
        say(f"    {i}. proxy: {outcome}")
        say(f"       hook : permissionDecision={run.permission_decision!r} exit={run.exit_code}")
    say()

    reached = executed(sandbox)
    say(f"  upstream EXECUTED.log ({len(reached)} line(s)) — what actually reached the tool:")
    for line in reached:
        say(f"    | {line}")
    if not reached:
        say("    | <empty>")
    say()
    say(f"  part A rows: {len(results.rows_a)} of {len(MCP_CASES)} case(s)")
    say(f"  part A not measured at one or both doors: {sum(1 for r in results.rows_a if not r.measured)}")
    say(f"  part A disagreements: {sum(1 for r in results.rows_a if r.measured and not r.agree)} of {len(results.rows_a)}")
    say(f"  part A verdicts differing from the stated expectation: "
        f"{sum(1 for r in results.rows_a if r.agree and not r.as_expected)} of {len(results.rows_a)}")
    say(f"  part A envelopes identical: {results.envelope_matches} of {len(results.rows_a)}")
    say()


async def part_b(tmp: Path, results: Results) -> None:
    rule("PART B — native Claude Code tools (TRANSLATED, not identical)")
    say()
    say("These calls are NOT byte-identical between the doors and this section does not")
    say("claim they are. Claude Code's built-ins are not the policy's vocabulary, so the")
    say("hook translates them through NATIVE_TOOLS: it ADDS the canonical key to a copy")
    say("of the payload and keeps every other key (a private key pasted into Write.content")
    say("must still trip args_match_any). The proxy never sees a `Read` at all.")
    say()
    say("  The claim here is narrower: the translation lands on the SAME engine verdict")
    say("  the proxy gives the equivalent MCP call. Not 'same envelope' — 'same answer'.")
    say()
    say("  Narrower is not unchecked. Part A proves its envelopes identical; this section")
    say("  proves the weaker property its own claim rests on — every key/value the proxy")
    say("  handed the engine is present, unchanged, in what the HOOK handed the engine.")
    say("  Without that check three rows where neither door logged anything would read")
    say("  'disagreements: 0' and pass, which is a demonstration of nothing.")
    say()

    sandbox = tmp / "part-b"
    sandbox.mkdir()
    proxy_log = tmp / "proxy-part-b.jsonl"
    hook_log = tmp / "hook-part-b.jsonl"

    equivalents = [(c.equivalent.tool, c.equivalent.args) for c in NATIVE_CASES]
    outcomes, proxy_events = await proxy_leg(equivalents, sandbox, proxy_log)
    hook_runs = [hook_leg(c.name, c.payload, hook_log, sandbox) for c in NATIVE_CASES]
    short = aligned(results, "part B", len(NATIVE_CASES), proxy_events=proxy_events, hook_runs=hook_runs)

    for case, event, run in zip(NATIVE_CASES, proxy_events, hook_runs):
        pv, pr = verdict_of([event])
        hv, hr = verdict_of(run.events)
        results.rows_b.append(
            Row(case.label, pv, pr, hv, hr, case.equivalent.expect_verdict, case.equivalent.expect_rule)
        )
        if translation_carried(event, run):
            results.translation_matches += 1

    say("  the two envelopes, side by side — deliberately different:")
    say()
    for case, event, run in zip(NATIVE_CASES, proxy_events, hook_runs):
        logged_hook = run.events[0].get("arguments") if run.events else None
        say(f"    {case.name}")
        say(f"      hook  tool_input       = {compact(case.payload)}")
        say(f"      hook  engine arguments = {compact(logged_hook)}")
        say(f"      proxy tools/call {case.equivalent.tool}")
        say(f"      proxy engine arguments = {compact(event.get('arguments'))}")
        say(f"      canonical argument carried through: "
            f"{'YES' if translation_carried(event, run) else 'NO — this row measured nothing'}")
        say(f"      expected verdict: {case.equivalent.expect_verdict} / "
            f"{case.equivalent.expect_rule}  ({case.equivalent.why})")
    say()

    if short:
        say(f"  LEG ERROR — {short}")
        say()
    render(results.rows_b)
    say()

    reached = executed(sandbox)
    say(f"  upstream EXECUTED.log ({len(reached)} line(s)) — proxy leg only:")
    for line in reached:
        say(f"    | {line}")
    if not reached:
        say("    | <empty>")
    say("  (read_file resolves by basename into an empty sandbox, so the upstream")
    say("   answers '<no such file>'. That is the tool's business; the verdict is the")
    say("   engine's, and it is what this section compares.)")
    say()

    unmapped_name, unmapped_input = UNMAPPED_CASE
    unmapped_log = tmp / "hook-unmapped.jsonl"
    unmapped = hook_leg(unmapped_name, unmapped_input, unmapped_log, sandbox)
    results.unmapped_hook_events = len(unmapped.events)
    results.unmapped_hook_stdout = unmapped.stdout
    say(f"  unmapped native tool — {unmapped_name} {compact(unmapped_input)}")
    say(f"    hook stdout        : {unmapped.stdout!r}")
    say(f"    hook exit code     : {unmapped.exit_code}")
    say(f"    hook decision events written: {results.unmapped_hook_events}")
    say(f"    permissionDecision : {unmapped.permission_decision!r}")
    say("    There is no proxy row: Grep is a Claude Code built-in, not an MCP tool, so")
    say("    it never crosses the proxy. The hook prints nothing and exits 0, which means")
    say("    'no decision' — Claude Code's own permission flow decides. It is NOT an")
    say("    allow: a control that answered 'allow' for tools it cannot describe would")
    say("    widen the user's permissions instead of narrowing them.")
    say()
    say(f"  part B rows: {len(results.rows_b)} of {len(NATIVE_CASES)} case(s)")
    say(f"  part B not measured at one or both doors: {sum(1 for r in results.rows_b if not r.measured)}")
    say(f"  part B disagreements: {sum(1 for r in results.rows_b if r.measured and not r.agree)} of {len(results.rows_b)}")
    say(f"  part B verdicts differing from the stated expectation: "
        f"{sum(1 for r in results.rows_b if r.agree and not r.as_expected)} of {len(results.rows_b)}")
    say(f"  part B translations carrying the canonical argument: "
        f"{results.translation_matches} of {len(results.rows_b)}")
    say()


async def part_c(tmp: Path, results: Results) -> None:
    rule("PART C — where the two doors deliberately differ")
    say()
    say("Same engine verdict, different enforcement. Each of these is a decision with a")
    say("reason, and each is shown happening rather than asserted.")
    say()

    say("  C1. `ask` — the proxy fails closed, the hook reaches the human.")
    say()
    ask_rows = [(r, i) for i, r in enumerate(results.rows_a) if r.hook_verdict == "ask"]
    for row, _ in ask_rows:
        say(f"      engine verdict, both doors: {row.proxy_verdict} / {row.proxy_rule}")
    say("      proxy : refused with MCP error -32001 (D-005 — no approval channel is")
    say("              wired to it, so absence of a human must not become an allow).")
    say("      hook  : permissionDecision \"ask\" and exit 0 — Claude Code IS an approval")
    say("              channel, so the verdict reaches the human it was written for.")
    say("      The verdicts above are equal; only the enforcement differs. See the Part A")
    say("      enforcement block for the verbatim -32001 message and the hook's stdout.")
    say()

    say("  C2. `limits:` — the proxy carries run_state and enforces them; the hook")
    say("      passes run_state=None and does not. Demonstrated, not claimed:")
    say()
    cap = load_policy(str(POLICY_PATH)).limits.max_repeated_identical_calls
    attempts = cap + 1
    say(f"      {POLICY_PATH.name} sets max_repeated_identical_calls: {cap} (read from the")
    say(f"      file, not from this script), so attempt {attempts} is the first one a limit")
    say("      can refuse.")
    say(f"      call repeated {attempts}x: {LIMIT_TOOL} {compact(LIMIT_ARGS)}")
    say()

    sandbox = tmp / "part-c"
    sandbox.mkdir()
    (sandbox / "notes.txt").write_text("benign sandbox file\n", encoding="utf-8")
    proxy_log = tmp / "proxy-part-c.jsonl"
    hook_log = tmp / "hook-part-c.jsonl"

    repeated = [(LIMIT_TOOL, LIMIT_ARGS)] * attempts
    outcomes, proxy_events = await proxy_leg(repeated, sandbox, proxy_log)
    hook_runs = [
        hook_leg(f"mcp__{MCP_SERVER_LABEL}__{LIMIT_TOOL}", LIMIT_ARGS, hook_log, sandbox)
        for _ in range(attempts)
    ]
    short = aligned(results, "part C", attempts, proxy_events=proxy_events, hook_runs=hook_runs)
    if short:
        say(f"      LEG ERROR — {short}")
        say()
    results.limit_attempts = attempts

    limit_rows = []
    for event, run in zip(proxy_events, hook_runs):
        pv, pr = verdict_of([event])
        hv, hr = verdict_of(run.events)
        limit_rows.append((pv, pr, hv, hr))
        if pv == "block":
            results.limit_proxy_blocks += 1
        if hv == "block":
            results.limit_hook_blocks += 1
    results.limit_rows = len(limit_rows)

    width = max([1] + [len(f"{pv} / {pr}") for pv, pr, _, _ in limit_rows])
    say(f"      #  {'proxy verdict / rule':<{width}}  hook verdict / rule")
    say(f"      -  {'-' * width}  {'-' * width}")
    for i, (pv, pr, hv, hr) in enumerate(limit_rows, 1):
        marker = "   <- DIVERGENCE" if (pv, pr) != (hv, hr) else ""
        say(f"      {i}  {pv + ' / ' + pr:<{width}}  {hv + ' / ' + hr}{marker}")
    say()
    say("      what the client saw at each door:")
    for i, (outcome, run) in enumerate(zip(outcomes, hook_runs), 1):
        say(f"        {i}. proxy: {outcome}")
        say(f"           hook : permissionDecision={run.permission_decision!r} exit={run.exit_code}")
    say()
    reached = executed(sandbox)
    say(f"      upstream EXECUTED.log ({len(reached)} line(s)) — ground truth for reach:")
    for line in reached:
        say(f"        | {line}")
    if not reached:
        say("        | <empty>")
    say()
    say(f"      proxy blocked {results.limit_proxy_blocks} of {attempts}; "
        f"hook blocked {results.limit_hook_blocks} of {attempts}.")
    say("      This is a REAL coverage gap in the hook, not a rounding error: a hook is")
    say("      one process per tool call with no cross-call counters, so it sends")
    say("      run_state=None and decide() skips the limit block by its own documented")
    say("      contract. A counter file shared between hook processes is a separate")
    say("      piece of work with its own concurrency questions. hooks/README.md states")
    say("      the difference; the numbered table above is the measurement behind it.")
    say()
    say("      The `taint:` block rides the same divergence and is NOT compared anywhere")
    say("      in this transcript. Taint is carried on run_state, which this door sends as")
    say("      None, and it is set on a tool RESULT — a PreToolUse hook answers before the")
    say("      tool runs and never sees one. A taint row would be a case one door cannot")
    say("      represent, and scoring it would make the disagreement count above mean less")
    say("      than it does. docs/LIMITATIONS.md §19 states the asymmetry and what closing")
    say("      it would take; engine/tests/test_decide.py asserts the inertness.")
    say()

    say("  C3. Unmapped native tools are neither judged nor logged by the hook.")
    say(f"      {UNMAPPED_CASE[0]} produced {results.unmapped_hook_events} decision event(s) and "
        f"{len(results.unmapped_hook_stdout)} byte(s) of stdout — see Part B.")
    say("      Consequence: the hook does not stop a file read performed by Grep, and")
    say("      such a call is absent from the audit trail entirely. Closing the gap means")
    say("      growing the policy vocabulary, which is a schema question, not a hook one.")
    say()


async def run_all(tmp: Path) -> Results:
    """Every section, in order, into a fresh transcript. Returns the measurements."""
    lines.clear()
    results = Results()
    header(tmp, tmp / "proxy-part-a.jsonl", tmp / "hook-part-a.jsonl")
    await part_a(tmp, results)
    await part_b(tmp, results)
    await part_c(tmp, results)

    rule("VERDICT")
    say()
    say("  Every property this transcript asserts, each one able to fail the run on its")
    say("  own. `ok` used to be two of these eight; the other six were printed and")
    say("  enforced by nothing, so a run could report an unmapped tool answering `allow`")
    say("  and still exit 0.")
    say()
    width = max(len(name) for name, _, _ in results.checks)
    for name, passed, detail in results.checks:
        say(f"  {'PASS' if passed else 'FAIL'}  {name:<{width}}  {detail}")
    say()
    say(f"  rows compared: {len(results.rows)} ({len(results.rows_a)} part A + {len(results.rows_b)} part B)")
    say(f"  disagreements: {results.disagreements} of {len(results.rows)}")
    say()
    if results.ok:
        say("  PASS — the same engine, reached through two enforcement points, returned the")
        say("         same verdict and the same rule id for every comparable call, and each")
        say("         of those verdicts is the one the policy owes that call. Where the")
        say("         doors differ they differ in ENFORCEMENT (Part C), and those")
        say("         differences are shown, not hidden.")
    else:
        say("  FAIL — one or more of the properties above does not hold. Read the FAIL")
        say("         line(s): a disagreement, a wrong verdict, an unmeasured row and a")
        say("         truncated leg are four different findings and this block names which.")
    return results


async def main_async(out: Path | None) -> None:
    with tempfile.TemporaryDirectory(prefix="chokepoint-side-by-side-") as tmp:
        results = await run_all(Path(tmp))
    if out is not None:
        out.write_text("\n".join(lines) + "\n", encoding="utf-8")
        print(f"\n[transcript written to {out}]", flush=True)
    if not results.ok:
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Side-by-side demo: the same engine through the proxy and through the hook."
    )
    parser.add_argument("--out", type=Path, default=None, help="also write the transcript here")
    args = parser.parse_args()
    anyio.run(main_async, args.out)


if __name__ == "__main__":
    main()
