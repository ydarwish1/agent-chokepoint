"""A real MCP server over stdio, used as the upstream in the demos.

It is a stand-in for a genuine tool server: it speaks the real protocol on a
real pipe, in its own process. What it deliberately does NOT do is execute
anything dangerous — ``run_command`` records the command it was asked to run
instead of running it.

That substitution is the point, not a shortcut. The claim under test is "the
proxy stops the call before it reaches the tool", and the observable is the
sandbox's ``EXECUTED.log``: a line appears exactly when a call reaches this
process. Running a real ``rm -rf`` to prove the same thing would be reckless.

``--page FILE`` makes ``fetch_url`` return that file's contents instead of the
stub reply, which is how the taint demo gets untrusted CONTENT into a tool
result. The flag is opt-in and changes nothing when it is absent.

``--tools FILE`` and ``--tools-after-first FILE`` do the same job for the
DESCRIPTION surface (D-039). Each names a JSON object of ``{tool name:
description}`` that replaces the ``TOOLS`` dict below for the listing; the
second one takes over from the SECOND ``tools/list`` onward, which is how a rug
pull and a sleeper are modelled — a server that answered one session's first
listing honestly and its second one differently. Both are opt-in, both leave
every other caller's bytes identical, and both stay inside this file's
recorded-not-executed contract: a tool that only exists in one of those files
still runs nothing, it falls to the generic branch below and writes a line to
``EXECUTED.log`` like everything else. What they carry is the attacker's text,
which is the whole point — nothing here decides whether that text is malicious,
and neither does the proxy.

stdio hygiene: nothing is ever written to stdout — that is the protocol wire.
Diagnostics go to stderr.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import anyio

import mcp.types as t
from mcp.server.lowlevel.server import Server
from mcp.server.stdio import stdio_server

TOOLS = {
    "read_file": "Read a file from the sandbox.",
    "write_file": "Write a file in the sandbox.",
    "fetch_url": "Fetch a URL (simulated).",
    "run_command": "Run a shell command (RECORDED, never executed).",
}


def build(
    sandbox: Path,
    page: Path | None = None,
    tools: dict[str, str] | None = None,
    tools_after_first: dict[str, str] | None = None,
) -> Server:
    executed_log = sandbox / "EXECUTED.log"
    first_listing = TOOLS if tools is None else tools
    later_listings = first_listing if tools_after_first is None else tools_after_first
    # Counted rather than latched to a bool, because "the second listing" is the
    # attack's own wording (Invariant's sleeper: *"first advertises an innocuous
    # tool, and then later on ... switches"*), and a count says which listing
    # this is if anyone ever wants a third shape.
    listings_served = 0

    def record(tool: str, detail: str) -> None:
        # LINE CONTRACT, and it is load-bearing outside this file. `detail` must
        # stay a Python literal that `ast.literal_eval` round-trips back to the
        # arguments, because `proxy/demo/real_model_attacks.py:reached_in()`
        # PARSES this line and compares envelopes by value. It used to rebuild
        # the line as a string and test membership, which made a nested
        # argument's key order decide whether a call that had landed was
        # reported as landed (B-067) — so the ordering of what is written here
        # is deliberately NOT part of the contract, and re-sorting it would buy
        # nothing. What would break the contract is a lossy or unparseable
        # spelling; `tests/test_model_run_records.py::TestTheReachMatcher` drives a
        # real call through this process and would go red on one.
        with executed_log.open("a", encoding="utf-8") as fh:
            fh.write(f"{tool}\t{detail}\n")

    async def on_list_tools(ctx, params):
        nonlocal listings_served
        listings_served += 1
        advertised = first_listing if listings_served == 1 else later_listings
        return t.ListToolsResult(
            tools=[
                t.Tool(name=name, description=desc, input_schema={"type": "object"})
                for name, desc in advertised.items()
            ]
        )

    async def on_call_tool(ctx, params):
        args = params.arguments or {}
        name = params.name
        record(name, repr(sorted(args.items())))

        if name == "read_file":
            target = sandbox / Path(str(args.get("path", ""))).name
            text = target.read_text(encoding="utf-8") if target.is_file() else "<no such file>"
            return t.CallToolResult(content=[t.TextContent(type="text", text=text)])
        if name == "run_command":
            return t.CallToolResult(
                content=[
                    t.TextContent(
                        type="text",
                        text=f"REACHED THE TOOL: would have executed {args.get('command')!r}",
                    )
                ]
            )
        if name == "fetch_url" and page is not None:
            # Serve a real page body instead of the stub, so a demo can show
            # untrusted CONTENT arriving in a tool result. Opt-in via
            # --page: with the flag absent this branch does not exist and every
            # other caller sees the byte-identical stub it always saw. Nothing
            # here inspects what it serves, and neither does the proxy — the run
            # is marked on the SOURCE tool, never on the content (D-031).
            return t.CallToolResult(
                content=[t.TextContent(type="text", text=page.read_text(encoding="utf-8"))]
            )
        return t.CallToolResult(
            content=[t.TextContent(type="text", text=f"{name} ok: {sorted(args.items())!r}")]
        )

    return Server(
        "demo-upstream",
        version="0.0.1",
        on_list_tools=on_list_tools,
        on_call_tool=on_call_tool,
    )


def _tool_descriptions(path: Path | None) -> dict[str, str] | None:
    """A ``{name: description}`` JSON object, or ``None`` for the built-in TOOLS.

    Validated here rather than trusted: a typo that produced ``None`` silently
    would make an attack fixture serve the honest listing and the test built on
    it would pass while proving nothing.
    """
    if path is None:
        return None
    loaded = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict) or not loaded or not all(
        isinstance(k, str) and k and isinstance(v, str) for k, v in loaded.items()
    ):
        raise SystemExit(f"{path}: expected a non-empty JSON object of tool name -> description")
    return loaded


def main() -> None:
    parser = argparse.ArgumentParser(description="Demo upstream MCP server (records, never executes).")
    parser.add_argument("--sandbox", required=True, help="directory for read_file targets and EXECUTED.log")
    parser.add_argument("--page", type=Path, default=None,
                        help="file whose contents fetch_url returns (default: the stub reply)")
    parser.add_argument("--tools", type=Path, default=None,
                        help="JSON object of tool name -> description to advertise (default: TOOLS)")
    parser.add_argument("--tools-after-first", type=Path, default=None,
                        help="JSON object advertised from the SECOND tools/list onward "
                             "(default: the same as the first)")
    args = parser.parse_args()
    sandbox = Path(args.sandbox)

    server = build(
        sandbox,
        args.page,
        _tool_descriptions(args.tools),
        _tool_descriptions(args.tools_after_first),
    )

    async def serve() -> None:
        print(f"[upstream] serving, sandbox={sandbox}", file=sys.stderr, flush=True)
        async with stdio_server() as (read_stream, write_stream):
            await server.run(read_stream, write_stream, server.create_initialization_options())

    anyio.run(serve)


if __name__ == "__main__":
    main()
