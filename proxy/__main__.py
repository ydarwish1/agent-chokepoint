"""Run the proxy over stdio in front of a stdio upstream server.

    python -m proxy --policy policy/policy.example.yaml -- <upstream command...>

The agent (e.g. Claude Code) is configured to spawn THIS command as its MCP
server; the proxy spawns the real upstream and stands in the path. Decision
events go to stderr as JSON lines (or --log-file).

Status: entrypoint is smoke-tested (imports, --help); the live end-to-end run
with a real agent is recorded in the committed transcripts under ``demo/``,
not claimed here.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone

import anyio

from mcp import Client, StdioServerParameters, stdio_client
from mcp.server.stdio import stdio_server

from policy import PolicyError, load_policy
from policy.loader import ambiguous_server_identity
from proxy.server import build_proxy, watch_for_unparseable_frames

# The hook's `hook:policy-error`, at this door (D-029). Inside the reserved
# `proxy:` prefix, which the loader already refuses policy rules from claiming
# (D-026), so no policy author can collide with it.
RULE_POLICY_ERROR = "proxy:policy-error"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m proxy",
        description="MCP security proxy: judge every tool call against a deny-by-default policy.",
    )
    parser.add_argument("--policy", required=True, help="path to the policy YAML")
    parser.add_argument("--agent-id", default="default", help="agent identity for decisions/events")
    # D-015 (B-011): the identity a rule's `server:` key binds to. A flag rather
    # than something read per call, because this proxy fronts exactly ONE
    # upstream — the wire carries no server name and deriving one from the
    # upstream argv would be a guess. Unset means this proxy claims no identity,
    # and a rule carrying `server:` then matches nothing here. A value whose
    # framing is ambiguous is refused in main() below (B-034, B-037): the other
    # door cannot represent it, and the policy loader refuses to write it down.
    # An explicitly EMPTY value is refused there too, and separately (B-038):
    # it is not ambiguous, it is absent, and `--server-name=` is not a spelling
    # of leaving the flag off.
    parser.add_argument(
        "--server-name",
        default=None,
        help="MCP server identity this proxy fronts; rules with a 'server:' key bind to it",
    )
    parser.add_argument("--log-file", default=None, help="append decision events here instead of stderr")
    parser.add_argument("upstream", nargs=argparse.REMAINDER, help="-- upstream server command")
    return parser


def _upstream_command(upstream: list[str]) -> list[str]:
    """Drop the single leading ``--`` separator; everything after it is verbatim (B-016).

    The old form was ``[a for a in upstream if a != "--"]``, which dropped
    EVERY ``--``, so an upstream command legitimately carrying one — e.g.
    ``npx -y server -- --verbose`` — reached the upstream mangled.

    Measured against the real parser on this repo's interpreter (Python 3.14.6,
    2026-08-02): ``argparse.REMAINDER`` keeps the separator it stopped at
    (``-- prog -- inner`` → ``['--', 'prog', '--', 'inner']``), omits it
    entirely when the caller does (``prog arg`` → ``['prog', 'arg']``), and
    treats a second one as the first token of the upstream command
    (``-- -- prog`` → ``['--', '--', 'prog']``). Hence: consume at most one,
    and only in position 0.
    """
    if upstream and upstream[0] == "--":
        return upstream[1:]
    return upstream


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    upstream_cmd = _upstream_command(args.upstream)
    if not upstream_cmd:
        parser.error("upstream server command required after --")

    # B-038: refuse an EMPTY identity. This is a different rejection with a
    # different reason, which is why it is its own check rather than one more
    # clause in the one below. `ambiguous_server_identity('')` is False, and
    # correctly so -- `"" + "__"` carries the delimiter exactly once, so an
    # empty identity is not ambiguous, it is absent -- so a guard gating only
    # on ambiguity let `--server-name=` straight through, while
    # `policy/loader.py` refuses `server: ""` and the hook denies the wire name
    # it produces. Two checks here because the loader has two: folding
    # emptiness into `ambiguous_server_identity` would make that function's
    # name a lie and break the equivalence its docstring is built on.
    #
    # Whitespace is deliberately NOT included. The loader LOADS `server: "   "`
    # -- its check is `not server`, which is false for a space -- so refusing
    # it at this door alone would open the same door-disagreement this closes,
    # pointing the other way. Both doors take it or neither does, and widening
    # both is a policy-schema change, not this fix.
    if args.server_name is not None and not args.server_name:
        parser.error(
            "--server-name must be a non-empty string naming one MCP server "
            f"(got {args.server_name!r}): omit the flag entirely for a proxy "
            "that claims no identity (B-011, B-038)"
        )

    # B-034: refuse an identity the OTHER door cannot represent. The hook
    # recovers `(server, tool)` by splitting `mcp__<server>__<tool>` on `__`,
    # which is not escapable, so `--server-name prod__west` and a hook seeing
    # `mcp__prod__west__read_file` describe the same deployment with two
    # different envelopes. Refused at the door that could have accepted it,
    # exactly as `policy/loader.py` refuses the same string in a rule's
    # `server:` key. Before load_policy, because it costs nothing and an
    # operator should hear about the flag they typed.
    #
    # B-037: the same condition, widened at the same time as the loader's and
    # by the same function, because two doors holding one rule apart by hand is
    # how B-034 came back. `--server-name prod_` frames to
    # `mcp__prod___read_file`, which the hook reads two ways and therefore
    # denies -- so accepting it here is the disagreement, not a convenience.
    if args.server_name is not None and ambiguous_server_identity(args.server_name):
        parser.error(
            f"--server-name must not contain '__' or end with '_' (got "
            f"{args.server_name!r}): framing it as `mcp__<server>__<tool>` would put "
            "the delimiter in the name more than once, and it is not escapable, so "
            "the hook cannot tell this identity apart from a different "
            "server-and-tool pair (B-034, B-037)"
        )

    # The sink is built BEFORE the policy loads, and that order is the point
    # (D-029): a proxy whose policy failed to load used to exit before it could
    # write anything, so its outage produced zero events and was invisible in
    # the stream — where the hook's identical failure emits `hook:policy-error`.
    if args.log_file:
        log_handle = open(args.log_file, "a", encoding="utf-8")

        def sink(event: dict) -> None:
            log_handle.write(json.dumps(event, default=str) + "\n")
            log_handle.flush()
    else:
        def sink(event: dict) -> None:
            print(json.dumps(event, default=str), file=sys.stderr, flush=True)

    try:
        policy = load_policy(args.policy)
    except (PolicyError, OSError) as exc:
        # Same exception pair the hook refuses on. One final decision-shaped
        # event, then refuse to start — never serve without a policy. The shape
        # is the ordinary decision event (it validates against the published
        # schema unchanged, asserted in proxy/tests/test_policy_error_event.py):
        # null tool and arguments because this refusal precedes any call, null
        # run_id because the run it would identify was never created, and
        # decision_ms 0.0 marking a refusal made before the engine ran. Startup
        # failures BEFORE this point (unparseable flags — where --log-file
        # itself may be the broken flag) still emit nothing; the schema's
        # WHO-WRITES-THE-FILE section says exactly that.
        sink(
            {
                "ts": datetime.now(timezone.utc).isoformat(),
                "agent_id": args.agent_id,
                "run_id": None,
                "server": args.server_name,
                "method": "tools/call",
                "tool": None,
                "arguments": None,
                "verdict": "block",
                "rule_id": RULE_POLICY_ERROR,
                "owasp": None,
                "reason": f"policy {args.policy!r} did not load: {exc}",
                "decision_ms": 0.0,
            }
        )
        print(
            f"agent-chokepoint proxy: policy {args.policy!r} did not load: {exc} "
            f"— refusing to start (decision event {RULE_POLICY_ERROR} written)",
            file=sys.stderr,
            flush=True,
        )
        raise SystemExit(2)

    async def serve() -> None:
        upstream_params = StdioServerParameters(command=upstream_cmd[0], args=upstream_cmd[1:])
        async with Client(stdio_client(upstream_params)) as upstream:
            server = build_proxy(
                upstream,
                policy,
                agent_id=args.agent_id,
                on_decision=sink,
                server_name=args.server_name,
            )
            async with stdio_server() as (read_stream, write_stream):
                # B-112: a frame the transport cannot parse is refused loudly —
                # one decision event, and an error reply when the request id is
                # recoverable — instead of being dropped at DEBUG with no trace.
                # The wrap goes here and not in `build_proxy` because the stream
                # does not exist until the transport is open.
                async with watch_for_unparseable_frames(
                    read_stream, write_stream, server
                ) as watched:
                    await server.run(
                        watched, write_stream, server.create_initialization_options()
                    )

    anyio.run(serve)


if __name__ == "__main__":
    main()
