"""D-011 acceptance artifact: B-007 and B-008 closed at BOTH doors, on a real tree.

``hooks/demo/side_by_side.py`` proves the two enforcement points agree on the
shipped policy's calls. This proves the thing that policy cannot express: that a
path is judged as the file the kernel would open, not as the string the agent
typed. It builds a real directory tree with a real ``.ssh`` directory and a real
symlink out of the sandbox, then drives both doors against it.

Six properties, and the third is the one that makes the others mean anything.
Properties 5 and 6 were added on 2026-08-02, after two spellings walked straight
through the first version of this file, and they are numbered last rather than
folded into 1 so the gap stays visible:

1. **Case (B-007).** ``<t>/workspace/.SSH/id_rsa`` and
   ``<t>/workspace/.ssh/id_rsa`` are the same file on a case-insensitive
   volume. The deny list names the second; the agent asks for the first.
2. **Symlink (B-008).** ``<t>/workspace/public/keys`` is a symlink to
   ``<t>/home/alice/.ssh``, so a path under it passes every lexical check while
   the kernel opens a file outside the namespace. The harness reads the marker
   file THROUGH the escaping path, so the escape is measured rather than
   assumed.
3. **A guard-off control for each.** Every path in a deny-by-default policy
   blocks unless a rule matches it, so a policy whose allow rule was simply
   DEAD would print an identical "blocked" result — that is the standing trap in
   triaging one of these, and B-006 is what it cost. Each
   blocking leg is therefore paired with a leg where the SAME path ALLOWS and
   reaches the tool, differing only in the policy's predicate. Two legs that
   cannot fail differently are not a test and a control; they are the same leg
   twice.
4. **Refusal.** A path the enforcement point cannot place — ``~``-relative, or
   relative to a working directory it does not know — is refused with its own
   attributed rule id rather than passed through unresolved.
5. **Case beyond ASCII (B-028), added after the fact.** The first version of
   this harness tested ``.SSH`` and ``.Ssh`` and stopped there, so it passed
   green while ``.<U+017F><U+017F>h`` -- LATIN SMALL LETTER LONG S, which
   ``str.lower()`` leaves alone and ``casefold()`` turns into ``ss`` -- read the
   same file. This harness did not catch that; it is covered now.
6. **A normalization variant in an ANCESTOR (B-029), same story.** APFS stores
   what it was given and opens either form, so ``<NFD cafe>`` and ``<NFC
   cafe>`` are one directory to the kernel and two strings here. The old walk
   abandoned the path at that component and left everything below it
   un-case-resolved, which is why leg 10 spells the ancestor NFC and the LEAF
   ``.SSH``: the leaf is a bypass this harness already proved it could catch,
   and an unconfirmed ancestor was enough to switch that off.

Ground truth, per claim, never the harness's own account of itself:

* **proxy leg, did it reach the tool:** the upstream's own ``EXECUTED.log``,
  written by ``proxy/demo/upstream_server.py`` when a call arrives at it. Same
  observable ``proxy/demo/run_demo.py`` uses.
* **proxy leg, what was decided:** the proxy's decision events.
* **hook leg:** the ``permissionDecision`` on the hook's stdout plus its own
  decision event. A PreToolUse hook answers before the tool runs and never sees
  it execute, so "reached the tool" is a proxy-leg claim only.

    .venv/bin/python pep/demo/two_doors_paths.py
    .venv/bin/python pep/demo/two_doors_paths.py --repo-root <pre-fix-export>

``--repo-root`` is not configuration for its own sake: it is what makes the
pre-fix comparison single-variable. The same harness, the same interpreter, the
same tree — pointed at a tree without D-011, legs 1 and 3 come back ALLOW and
the payload reaches the tool, which is the measurement that says these tests
would have failed before the fix. Legs 8 and 10 do the same against a `cd5fc1d`
export, which HAS D-011 and not B-028/B-029's fix. Exit 0 only when every named
check passes.
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
    # Run as a bare script, sys.path[0] is THIS directory. Same guard, same
    # reason, as hooks/demo/side_by_side.py. Note that the harness imports
    # nothing from this repo — that is deliberate, so it can be pointed at
    # another checkout without importing half of it.
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import anyio  # noqa: E402

from mcp import Client, MCPError, StdioServerParameters, stdio_client  # noqa: E402

MCP_SERVER_LABEL = "demo"
CASE_MARKER = "CASE-MARKER-PRIVATE-KEY"
ESCAPE_MARKER = "ESCAPE-MARKER-PRIVATE-KEY"
NESTED_MARKER = "NESTED-MARKER-PRIVATE-KEY"
BENIGN_TEXT = "benign sandbox file\n"

# The two spellings this harness did NOT cover when it was written, and that
# later walked through it: B-028 (a case fold outside ASCII) and
# B-029 (a normalization variant in an ANCESTOR). Escapes, never literal bytes
# -- a lone COMBINING ACUTE ACCENT is invisible in a diff, and a vector whose
# entire point is which code points it carries must not depend on an editor's
# idea of how to normalize this file.
LONG_S = "\u017f"        # LATIN SMALL LETTER LONG S: lowercases to itself, casefolds to "s"
NFD_CAFE = "cafe\u0301"  # c a f e + COMBINING ACUTE ACCENT: how the directory is CREATED
NFC_CAFE = "caf\u00e9"   # c a f + LATIN SMALL LETTER E WITH ACUTE: how the agent SPELLS it
FOLD_DIR = "." + LONG_S + LONG_S + "h"

lines: list[str] = []


def say(text: str = "") -> None:
    lines.append(text)
    print(text, flush=True)


def rule(title: str, width: int = 78) -> None:
    say(f"--- {title} " + "-" * max(0, width - len(title) - 5))


def compact(obj: object) -> str:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True)


# ------------------------------------------------------------------- the tree


def build_tree(root: Path) -> None:
    """B-007's and B-008's repros, built rather than described.

    ``root`` is already ``realpath``-ed by the caller. That is not tidiness: the
    PEP canonicalizes the call path and ``policy/loader.py`` deliberately does
    NOT canonicalize policy prefixes, so on macOS — where ``/var`` is a symlink
    to ``/private/var`` — a prefix written from the raw ``mkdtemp`` path would
    never match a canonicalized call path and every leg would block for the
    wrong reason. Resolving once, at the root, keeps the A/B single-variable.
    """
    (root / "workspace" / ".ssh").mkdir(parents=True)
    (root / "workspace" / ".ssh" / "id_rsa").write_text(CASE_MARKER, encoding="utf-8")
    (root / "workspace" / "notes.txt").write_text(BENIGN_TEXT, encoding="utf-8")
    (root / "workspace" / "public").mkdir()
    (root / "home" / "alice" / ".ssh").mkdir(parents=True)
    (root / "home" / "alice" / ".ssh" / "id_rsa").write_text(ESCAPE_MARKER, encoding="utf-8")
    os.symlink(str(root / "home" / "alice" / ".ssh"), str(root / "workspace" / "public" / "keys"))
    # B-029's repro needs no new leaf, only an ANCESTOR whose stored bytes are
    # not the bytes an agent would type. Created NFD; the attack legs spell it
    # NFC. Nothing about the .ssh directory under it is unusual -- that is the
    # finding: an ancestor this module could not confirm used to disable the
    # deny list for everything below it, however ordinary the rest was.
    (root / "workspace" / NFD_CAFE / ".ssh").mkdir(parents=True)
    (root / "workspace" / NFD_CAFE / ".ssh" / "id_rsa").write_text(
        NESTED_MARKER, encoding="utf-8"
    )


def write_policy(root: Path, name: str, allow: list[str], deny: list[str]) -> Path:
    """One ``read_file`` rule. ``deny`` empty means the predicate is absent —
    which is exactly what a guard-off control needs."""
    body = [
        "version: 0",
        "defaults: {decision: block, on_no_match: block}",
        "rules:",
        "  - id: fs-read-scoped",
        "    owasp: LLM01",
        "    tool: read_file",
        "    decision: allow",
        "    when:",
        "      path_within: [" + ", ".join(f'"{p}"' for p in allow) + "]",
    ]
    if deny:
        body.append("      path_not_within: [" + ", ".join(f'"{p}"' for p in deny) + "]")
    path = root / name
    path.write_text("\n".join(body) + "\n", encoding="utf-8")
    return path


# ------------------------------------------------------------------- the legs


@dataclass(frozen=True)
class Leg:
    label: str
    policy: Path
    call_path: str
    why: str
    expect_reach: bool           # should the payload reach the tool?
    expect_rule: str | None      # rule id both doors should attribute it to


@dataclass
class Measured:
    leg: Leg
    proxy_outcome: str = "<not measured>"
    proxy_verdict: str = "<no event>"
    proxy_rule: str = "-"
    reached: int = -1
    hook_decision: str | None = None
    hook_exit: int = -1
    hook_verdict: str = "<no event>"
    hook_rule: str = "-"
    # The two halves of D-011's must-not-change: what the ENGINE was asked about
    # (the proxy's decision event) and what the TOOL received (the upstream's
    # own EXECUTED.log line). They are deliberately not the same string.
    engine_arguments: object = "<no event>"
    executed_lines: list = field(default_factory=list)

    @property
    def doors_agree(self) -> bool:
        return (self.proxy_verdict, self.proxy_rule) == (self.hook_verdict, self.hook_rule) and (
            self.proxy_verdict not in ("<no event>", "<2 events>")
        )

    @property
    def reach_as_expected(self) -> bool:
        return self.reached == (1 if self.leg.expect_reach else 0)

    @property
    def rule_as_expected(self) -> bool:
        if self.leg.expect_rule is None:
            return True
        return self.proxy_rule == self.leg.expect_rule and self.hook_rule == self.leg.expect_rule

    @property
    def enforcement_as_expected(self) -> bool:
        expected_decision = "allow" if self.leg.expect_reach else "deny"
        return self.hook_decision == expected_decision and self.reach_as_expected

    @property
    def status(self) -> str:
        if not self.doors_agree:
            return "DISAGREE"
        if not self.enforcement_as_expected:
            return "WRONG ENFORCEMENT"
        if not self.rule_as_expected:
            return "WRONG RULE"
        return "OK"


# ---------------------------------------------------------------- proxy leg


def child_env(repo_root: Path) -> dict[str, str]:
    env = {
        k: os.environ[k]
        for k in ("HOME", "PATH", "LOGNAME", "SHELL", "TERM", "USER")
        if k in os.environ
    }
    env["PYTHONPATH"] = str(repo_root)
    return env


def proxy_argv(repo_root: Path, policy: Path, sandbox: Path, log_file: Path) -> list[str]:
    return [
        "-m", "proxy",
        "--policy", str(policy),
        "--agent-id", "proxy-leg",
        "--log-file", str(log_file),
        "--", sys.executable, str(repo_root / "proxy" / "demo" / "upstream_server.py"),
        "--sandbox", str(sandbox),
    ]


async def proxy_leg(repo_root: Path, leg: Leg, sandbox: Path, log_file: Path) -> tuple[str, list[dict]]:
    params = StdioServerParameters(
        command=sys.executable,
        args=proxy_argv(repo_root, leg.policy, sandbox, log_file),
        cwd=str(repo_root),
        env=child_env(repo_root),
    )
    async with Client(stdio_client(params)) as client:
        try:
            result = await client.call_tool("read_file", {"path": leg.call_path})
            outcome = "RESULT   " + result.content[0].text.replace("\n", " ")[:80].strip()
        except MCPError as exc:
            outcome = f"REFUSED  code={exc.error.code} {exc.error.message[:80]}"
    return outcome, [e for e in read_events(log_file) if e.get("method") == "tools/call"]


def executed(sandbox: Path) -> list[str]:
    log = sandbox / "EXECUTED.log"
    return log.read_text(encoding="utf-8").splitlines() if log.is_file() else []


# ----------------------------------------------------------------- hook leg


def hook_payload(tool_name: str, tool_input: dict) -> dict:
    """One PreToolUse envelope, the shape a real Claude Code 2.1.220 sends
    (captured 2026-08-02)."""
    return {
        "cwd": "/workspace",
        "effort": {"level": "high"},
        "hook_event_name": "PreToolUse",
        "permission_mode": "default",
        "prompt_id": "two-doors-paths",
        "session_id": "two-doors-paths",
        "tool_input": tool_input,
        "tool_name": tool_name,
        "tool_use_id": "toolu_two_doors_paths",
        "transcript_path": "/dev/null",
    }


def hook_leg(repo_root: Path, leg: Leg, log_file: Path, cwd: Path) -> tuple[str | None, int, list[dict]]:
    before = len(read_events(log_file))
    done = subprocess.run(
        [
            sys.executable, str(repo_root / "hooks" / "chokepoint_hook.py"),
            "--policy", str(leg.policy),
            "--agent-id", "hook-leg",
            "--log-file", str(log_file),
        ],
        input=json.dumps(
            hook_payload(f"mcp__{MCP_SERVER_LABEL}__read_file", {"path": leg.call_path})
        ),
        capture_output=True,
        text=True,
        cwd=str(cwd),
    )
    decision = (
        json.loads(done.stdout)["hookSpecificOutput"]["permissionDecision"]
        if done.stdout.strip()
        else None
    )
    return decision, done.returncode, read_events(log_file)[before:]


def read_events(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def verdict_of(events: list[dict]) -> tuple[str, str]:
    if len(events) != 1:
        return (f"<{len(events)} events>", "-")
    return (str(events[0]["verdict"]), str(events[0]["rule_id"]))


# ------------------------------------------------------------------- results


@dataclass
class Results:
    measured: list[Measured] = field(default_factory=list)
    case_alias_real: bool = False
    escape_real: bool = False
    fold_alias_real: bool = False
    nfc_ancestor_real: bool = False
    case_alias_detail: str = "<not measured>"
    escape_detail: str = "<not measured>"
    fold_alias_detail: str = "<not measured>"
    nfc_ancestor_detail: str = "<not measured>"

    def leg(self, label: str) -> Measured:
        return next(m for m in self.measured if m.leg.label == label)

    @property
    def checks(self) -> list[tuple[str, bool, str]]:
        blocking = [m for m in self.measured if not m.leg.expect_reach and m.leg.expect_rule != "pep:unresolvable-path"]
        controls = [m for m in self.measured if m.leg.expect_reach]
        refusals = [m for m in self.measured if m.leg.expect_rule == "pep:unresolvable-path"]
        return [
            (
                "the case alias is real on this volume (B-007 is reachable here)",
                self.case_alias_real,
                self.case_alias_detail,
            ),
            (
                "the symlink escape is real (marker read THROUGH the escaping path)",
                self.escape_real,
                self.escape_detail,
            ),
            (
                "the U+017F fold alias is real on this volume (B-028 is reachable here)",
                self.fold_alias_real,
                self.fold_alias_detail,
            ),
            (
                "the NFC/NFD ancestor alias is real on this volume (B-029 is reachable here)",
                self.nfc_ancestor_real,
                self.nfc_ancestor_detail,
            ),
            (
                "every blocked leg reached the tool 0 times, at both doors",
                bool(blocking) and all(m.enforcement_as_expected for m in blocking),
                "; ".join(
                    f"{m.leg.label}: reached={m.reached} hook={m.hook_decision}" for m in blocking
                ),
            ),
            (
                "every guard-off control ALLOWED the same path and reached the tool",
                bool(controls) and all(m.enforcement_as_expected for m in controls),
                "; ".join(
                    f"{m.leg.label}: reached={m.reached} hook={m.hook_decision}" for m in controls
                ),
            ),
            (
                "unplaceable paths are refused with the shared rule id at both doors",
                bool(refusals) and all(m.rule_as_expected for m in refusals),
                "; ".join(
                    f"{m.leg.label}: proxy={m.proxy_rule} hook={m.hook_rule}" for m in refusals
                ),
            ),
            (
                "the two doors agreed on verdict AND rule id for every leg",
                all(m.doors_agree for m in self.measured),
                "; ".join(
                    f"{m.leg.label}: proxy={m.proxy_verdict}/{m.proxy_rule} "
                    f"hook={m.hook_verdict}/{m.hook_rule}"
                    for m in self.measured
                    if not m.doors_agree
                )
                or f"{len(self.measured)} of {len(self.measured)} legs agree",
            ),
            (
                "every leg landed on the rule id its policy owes it",
                all(m.rule_as_expected for m in self.measured),
                "; ".join(
                    f"{m.leg.label}: expected {m.leg.expect_rule}, "
                    f"proxy={m.proxy_rule} hook={m.hook_rule}"
                    for m in self.measured
                    if not m.rule_as_expected
                )
                or f"{len(self.measured)} of {len(self.measured)} legs as expected",
            ),
        ]

    @property
    def ok(self) -> bool:
        return all(passed for _name, passed, _detail in self.checks)


# -------------------------------------------------------------------- driver


def provenance(repo_root: Path) -> list[str]:
    """Which tree the child processes actually import — asked of Python, not
    inferred from the argument. The whole pre-fix comparison rests on this."""
    probe = (
        "import engine, policy, proxy.server\n"
        "print('engine ', engine.__file__)\n"
        "print('policy ', policy.__file__)\n"
        "print('proxy  ', proxy.server.__file__)\n"
        "try:\n"
        "    import pep\n"
        "    print('pep    ', pep.__file__)\n"
        "except Exception as exc:\n"
        "    print('pep     <absent:', type(exc).__name__, str(exc)[:60] + '>')\n"
    )
    done = subprocess.run(
        [sys.executable, "-c", probe],
        cwd=str(repo_root),
        env=child_env(repo_root),
        capture_output=True,
        text=True,
    )
    if done.returncode != 0:
        return [f"<provenance probe exited {done.returncode}: {done.stderr.strip()[:200]}>"]
    return done.stdout.strip().splitlines()


def header(repo_root: Path, root: Path, results: Results) -> None:
    say("Agent-Chokepoint — D-011 acceptance: path canonicalization at BOTH enforcement points")
    say("=" * 88)
    say()
    say("B-007 (case) and B-008 (symlink escape) are closed by resolving the path in the")
    say("enforcement point before the engine judges it. The engine is untouched: it is pure")
    say("and has no filesystem, so it cannot know which file a path names.")
    say()
    say(f"  date:       {datetime.now().astimezone().isoformat(timespec='seconds')}")
    say(f"  python:     {sys.version.split()[0]}  ({sys.executable})")
    say(f"  repo root:  {repo_root}")
    say(f"  tree:       {root}")
    say()
    say("  what the child processes IMPORT (asked of Python, not assumed from the path):")
    for line in provenance(repo_root):
        say(f"    {line}")
    say()
    say("  the tree, built for this run:")
    say(f"    {root}/workspace/.ssh/id_rsa            <- the file the deny list protects")
    say(f"    {root}/workspace/notes.txt              <- a benign file, the always-allowed control")
    say(f"    {root}/workspace/public/keys -> {root}/home/alice/.ssh   (symlink)")
    say(f"    {root}/home/alice/.ssh/id_rsa           <- outside the workspace entirely")
    say(f"    {root}/workspace/<NFD cafe>/.ssh/id_rsa <- created NFD; legs 10-11 spell it NFC")
    say()
    say("  is the bug reachable on this volume?")
    say(f"    case alias:     {results.case_alias_detail}")
    say(f"    symlink escape: {results.escape_detail}")
    say(f"    U+017F fold:    {results.fold_alias_detail}")
    say(f"    NFC ancestor:   {results.nfc_ancestor_detail}")
    say()
    say("GROUND TRUTH, per claim:")
    say("  - proxy leg, reach: the upstream's own EXECUTED.log — a line appears exactly")
    say("    when a call arrives at the tool process (proxy/demo/upstream_server.py).")
    say("  - proxy leg, decision: the proxy's own decision events, not the client's")
    say("    account of itself.")
    say("  - hook leg: the permissionDecision the hook printed, its exit code, and its own")
    say("    decision event. A PreToolUse hook answers BEFORE the tool runs and never sees")
    say("    it execute, so 'reached the tool' is a proxy-leg claim only.")
    say()
    say("  NOTE: the upstream RECORDS calls instead of executing them. Reach is the")
    say("        observable; proving it with a real credential read would be reckless.")
    say()


def measure_reachability(root: Path, results: Results) -> None:
    """Is either bypass even reachable here? Asked before anything is claimed."""
    try:
        through_case = (root / "workspace" / ".SSH" / "id_rsa").read_text(encoding="utf-8")
        results.case_alias_real = through_case == CASE_MARKER
        results.case_alias_detail = (
            "reading .SSH/id_rsa returned the bytes written to .ssh/id_rsa — "
            "case-insensitive volume, B-007 is reachable"
            if results.case_alias_real
            else f"reading .SSH/id_rsa returned {through_case!r}"
        )
    except OSError as exc:
        results.case_alias_real = False
        results.case_alias_detail = (
            f"reading .SSH/id_rsa raised {type(exc).__name__} — this volume is CASE-SENSITIVE, "
            "so B-007's bypass does not exist here and the case legs below are inapplicable"
        )
    try:
        through_link = (root / "workspace" / "public" / "keys" / "id_rsa").read_text(encoding="utf-8")
        results.escape_real = through_link == ESCAPE_MARKER
        results.escape_detail = (
            "reading workspace/public/keys/id_rsa returned the bytes written to "
            "home/alice/.ssh/id_rsa — the escape is real"
            if results.escape_real
            else f"reading through the symlink returned {through_link!r}"
        )
    except OSError as exc:
        results.escape_real = False
        results.escape_detail = f"reading through the symlink raised {type(exc).__name__}"
    # B-028: a case fold outside ASCII. LATIN SMALL LETTER LONG S lowercases to
    # itself, so the pre-fix walk never offered `.ssh` as a candidate at all.
    try:
        through_fold = (root / "workspace" / FOLD_DIR / "id_rsa").read_text(encoding="utf-8")
        results.fold_alias_real = through_fold == CASE_MARKER
        results.fold_alias_detail = (
            "reading .<U+017F><U+017F>h/id_rsa returned the bytes written to .ssh/id_rsa "
            "- this volume folds beyond ASCII, B-028 is reachable"
            if results.fold_alias_real
            else f"reading the U+017F spelling returned {through_fold!r}"
        )
    except OSError as exc:
        results.fold_alias_real = False
        results.fold_alias_detail = (
            f"reading the U+017F spelling raised {type(exc).__name__} - this volume does not fold "
            "beyond ASCII, so B-028's bypass does not exist here and its legs are inapplicable"
        )
    # B-029: the ancestor is spelled NFC and stored NFD, and the leaf under it is
    # an ordinary ASCII case variant. Both halves in one read, because both
    # halves in one path is what the bug was.
    try:
        through_nfc = (root / "workspace" / NFC_CAFE / ".SSH" / "id_rsa").read_text(encoding="utf-8")
        results.nfc_ancestor_real = through_nfc == NESTED_MARKER
        results.nfc_ancestor_detail = (
            "reading <NFC cafe>/.SSH/id_rsa returned the bytes written to <NFD cafe>/.ssh/id_rsa "
            "- this volume is normalization-insensitive, B-029 is reachable"
            if results.nfc_ancestor_real
            else f"reading the NFC ancestor returned {through_nfc!r}"
        )
    except OSError as exc:
        results.nfc_ancestor_real = False
        results.nfc_ancestor_detail = (
            f"reading the NFC ancestor raised {type(exc).__name__} - this volume is "
            "normalization-SENSITIVE, so B-029's bypass does not exist here and its legs "
            "are inapplicable"
        )


async def run_leg(repo_root: Path, root: Path, index: int, leg: Leg) -> Measured:
    sandbox = root / f"sandbox-{index}"
    sandbox.mkdir()
    (sandbox / "notes.txt").write_text(BENIGN_TEXT, encoding="utf-8")
    proxy_log = root / f"proxy-{index}.jsonl"
    hook_log = root / f"hook-{index}.jsonl"

    outcome, proxy_events = await proxy_leg(repo_root, leg, sandbox, proxy_log)
    decision, exit_code, hook_events = hook_leg(repo_root, leg, hook_log, sandbox)

    pv, pr = verdict_of(proxy_events)
    hv, hr = verdict_of(hook_events)
    reached = executed(sandbox)
    return Measured(
        leg=leg,
        proxy_outcome=outcome,
        proxy_verdict=pv,
        proxy_rule=pr,
        reached=len(reached),
        hook_decision=decision,
        hook_exit=exit_code,
        hook_verdict=hv,
        hook_rule=hr,
        engine_arguments=proxy_events[0].get("arguments") if len(proxy_events) == 1 else "<no event>",
        executed_lines=reached,
    )


def render(results: Results) -> None:
    heads = ("leg", "expected", "proxy verdict / rule", "hook verdict / rule", "reached", "hook says")
    rows = [
        (
            m.leg.label,
            ("allow+reach" if m.leg.expect_reach else "block+no reach") + f" / {m.leg.expect_rule}",
            f"{m.proxy_verdict} / {m.proxy_rule}",
            f"{m.hook_verdict} / {m.hook_rule}",
            str(m.reached),
            str(m.hook_decision),
        )
        for m in results.measured
    ]
    widths = [max(len(h), *(len(r[i]) for r in rows)) for i, h in enumerate(heads)]
    say("  " + "  ".join(f"{h:<{w}}" for h, w in zip(heads, widths)) + "  result")
    say("  " + "  ".join("-" * w for w in widths) + "  ------------------")
    for measured, row in zip(results.measured, rows):
        say("  " + "  ".join(f"{c:<{w}}" for c, w in zip(row, widths)) + f"  {measured.status}")


async def run_all(repo_root: Path, root: Path) -> Results:
    lines.clear()
    results = Results()
    build_tree(root)
    measure_reachability(root, results)
    header(repo_root, root, results)

    workspace = f"{root}/workspace/"
    guard_on = write_policy(
        root, "guard-on.yaml", allow=[workspace], deny=[f"{root}/workspace/.ssh/"]
    )
    case_control = write_policy(root, "case-control.yaml", allow=[workspace], deny=[])
    symlink_control = write_policy(
        root, "symlink-control.yaml", allow=[workspace, f"{root}/home/alice/.ssh/"], deny=[]
    )
    # The deny prefix is written in the ancestor's ON-DISK (NFD) spelling, which
    # is the only spelling an operator could learn by listing the directory. The
    # attack legs send NFC. Nothing here folds or normalizes the POLICY -- that
    # is deliberate and is documented as a deployment trap in LIMITATIONS.md
    # section 10; the fix is that the CALL path arrives resolved.
    nested_guard_on = write_policy(
        root,
        "nested-guard-on.yaml",
        allow=[workspace],
        deny=[f"{root}/workspace/{NFD_CAFE}/.ssh/"],
    )
    nested_control = write_policy(root, "nested-control.yaml", allow=[workspace], deny=[])

    legs = [
        Leg(
            "1 case, guard ON",
            guard_on,
            f"{root}/workspace/.SSH/id_rsa",
            "the deny list names .ssh; the agent asks for .SSH; on this volume they are one file",
            expect_reach=False,
            expect_rule="default:on_no_match",
        ),
        Leg(
            "2 case, guard OFF (control)",
            case_control,
            f"{root}/workspace/.SSH/id_rsa",
            "same path, deny predicate REMOVED — if this also blocked, leg 1 would prove nothing",
            expect_reach=True,
            expect_rule="fs-read-scoped",
        ),
        Leg(
            "3 symlink, guard ON",
            guard_on,
            f"{root}/workspace/public/keys/id_rsa",
            "resolves out of the workspace, so the allow prefix no longer covers it",
            expect_reach=False,
            expect_rule="default:on_no_match",
        ),
        Leg(
            "4 symlink, guard OFF (control)",
            symlink_control,
            f"{root}/workspace/public/keys/id_rsa",
            "same path, allow prefix now covers where it RESOLVES to",
            expect_reach=True,
            expect_rule="fs-read-scoped",
        ),
        Leg(
            "5 refusal, ~ path",
            guard_on,
            "~/.ssh/id_rsa",
            "the PEP has no more right than the engine to guess a home directory",
            expect_reach=False,
            expect_rule="pep:unresolvable-path",
        ),
        Leg(
            "6 refusal, relative path",
            guard_on,
            ".ssh/id_rsa",
            "the PEP cannot know the TOOL's working directory (B-006's rule)",
            expect_reach=False,
            expect_rule="pep:unresolvable-path",
        ),
        Leg(
            "7 benign (control)",
            guard_on,
            f"{root}/workspace/notes.txt",
            "the guard is not simply blocking everything",
            expect_reach=True,
            expect_rule="fs-read-scoped",
        ),
        Leg(
            "8 unicode fold, guard ON",
            guard_on,
            f"{root}/workspace/{FOLD_DIR}/id_rsa",
            "U+017F lowercases to ITSELF and casefolds to 's'; legs 1-2 only ever tested ASCII",
            expect_reach=False,
            expect_rule="default:on_no_match",
        ),
        Leg(
            "9 unicode fold, guard OFF (control)",
            case_control,
            f"{root}/workspace/{FOLD_DIR}/id_rsa",
            "same path, deny predicate REMOVED -- if this also blocked, leg 8 would prove nothing",
            expect_reach=True,
            expect_rule="fs-read-scoped",
        ),
        Leg(
            "10 NFC ancestor, guard ON",
            nested_guard_on,
            f"{root}/workspace/{NFC_CAFE}/.SSH/id_rsa",
            "the ANCESTOR is stored NFD and spelled NFC; the old walk gave up there and left "
            ".SSH un-resolved",
            expect_reach=False,
            expect_rule="default:on_no_match",
        ),
        Leg(
            "11 NFC ancestor, guard OFF (control)",
            nested_control,
            f"{root}/workspace/{NFC_CAFE}/.SSH/id_rsa",
            "same path, deny predicate REMOVED -- the leg that makes leg 10 enforcement",
            expect_reach=True,
            expect_rule="fs-read-scoped",
        ),
    ]

    rule("THE LEGS")
    say()
    for leg in legs:
        say(f"  {leg.label}")
        say(f"    policy    {leg.policy.name}")
        say(f"    call      read_file {compact({'path': leg.call_path})}")
        say(f"    why       {leg.why}")
        say(f"    expected  {'allow, reaches the tool' if leg.expect_reach else 'block, never reaches the tool'}"
            f"  ({leg.expect_rule})")
    say()

    for index, leg in enumerate(legs, 1):
        results.measured.append(await run_leg(repo_root, root, index, leg))

    rule("MEASURED")
    say()
    render(results)
    say()
    say("  what the client saw, and what the hook told Claude Code:")
    for measured in results.measured:
        say(f"    {measured.leg.label}")
        say(f"      proxy: {measured.proxy_outcome}")
        say(f"      proxy: upstream EXECUTED.log lines = {measured.reached}")
        for line in measured.executed_lines:
            say(f"        | {line}")
        say(f"      hook : permissionDecision={measured.hook_decision!r} exit={measured.hook_exit}")
    say()
    say("  D-011's must-not-change, shown rather than asserted: the ENGINE is judged on")
    say("  the resolved path, the TOOL receives what the agent sent. The two columns")
    say("  below differ on exactly the legs where resolution did something — and a hook")
    say("  cannot rewrite its tool's input at all, which is why the proxy does not either.")
    say()
    for measured in results.measured:
        say(f"    {measured.leg.label}")
        say(f"      agent sent        {compact({'path': measured.leg.call_path})}")
        say(f"      engine was asked  {compact(measured.engine_arguments)}")
        say(f"      tool received     {measured.executed_lines[0] if measured.executed_lines else '<never reached the tool>'}")
    say()

    rule("VERDICT")
    say()
    width = max(len(name) for name, _, _ in results.checks)
    for name, passed, detail in results.checks:
        say(f"  {'PASS' if passed else 'FAIL'}  {name:<{width}}  {detail}")
    say()
    if results.ok:
        say("  PASS — a case-variant path and a symlink-escaping path are both judged on the")
        say("         file they actually name, at both enforcement points, and neither reaches")
        say("         the tool. The paired guard-off legs allow the SAME paths, so the blocks")
        say("         above are enforcement rather than deny-by-default.")
    else:
        say("  FAIL — read the FAIL line(s). Against a tree without D-011 this is the expected")
        say("         result and the measurement IS the point: legs 1 and 3 come back allow and")
        say("         the payload reaches the tool.")
    return results


async def main_async(repo_root: Path, out: Path | None) -> None:
    with tempfile.TemporaryDirectory(prefix="chokepoint-two-doors-paths-") as tmp:
        results = await run_all(repo_root, Path(os.path.realpath(tmp)))
    if out is not None:
        out.write_text("\n".join(lines) + "\n", encoding="utf-8")
        print(f"\n[transcript written to {out}]", flush=True)
    if not results.ok:
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="D-011 acceptance: path canonicalization at both enforcement points."
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parents[2],
        help="the checkout to drive; point it at a pre-fix export for the A/B",
    )
    parser.add_argument("--out", type=Path, default=None, help="also write the transcript here")
    args = parser.parse_args()
    anyio.run(main_async, args.repo_root.resolve(), args.out)


if __name__ == "__main__":
    main()
