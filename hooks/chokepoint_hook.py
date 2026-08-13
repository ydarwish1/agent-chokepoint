"""The Claude Code hook — the second enforcement point (PEP).

Claude Code runs this file once per tool call, *before* the tool executes: the
PreToolUse payload arrives as one JSON object on stdin, and the decision goes
back as one JSON object on stdout. Same engine as ``proxy/server.py``, same
policy file, a different door. That split is the thing this file exists to
demonstrate, so it holds no policy logic of its own and imports ``engine``
unmodified: adding a second enforcement point required no engine change at all.

Deliberate differences from the proxy, each one a decision rather than an
oversight:

* **``ask`` maps to Claude Code's ``ask``, not to a block.** The proxy fails
  closed on ``ask`` (D-005) because it has no approval channel wired to it.
  Claude Code *is* an approval channel, so the same engine verdict reaches the
  human it was written for. D-005's rule is that the absence of a human must
  never become an allow; ``ask`` here is not an allow, it is the human.
* **No run-state, therefore no ``limits:`` enforcement.** One process per call
  and no cross-call counters, so the envelope carries ``run_state=None`` and
  ``decide()`` skips the limit block by its own documented contract
  (``engine/decide.py``). The proxy enforces limits; this hook does not. A
  counter file shared between processes is a separate piece of work with its
  own concurrency questions, not a default. Stated in ``hooks/README.md`` and
  in ``docs/LIMITATIONS.md``.
* **Native tools are translated, not judged under their own names.** Claude
  Code's built-ins (``Read``, ``Bash``, …) are mapped onto the policy's tool
  vocabulary by :data:`NATIVE_TOOLS`, measured against real captured payloads.
  A native tool with no mapping produces **no decision at all** — never an
  ``allow``; see :func:`_translate`.

Paths are canonicalized before the engine sees them (D-011,
``pep.canonicalize``), at the same point and with the same rule id as
``proxy/server.py``: this process runs on the operator's own machine and the
engine has no filesystem at all. A path this hook cannot resolve is DENIED,
never passed through unresolved. What the hook cannot do is hand the tool the
resolved path — PreToolUse returns a verdict, not modified input — which is
exactly why the proxy does not either; see ``docs/LIMITATIONS.md`` §10 and §15.

Exit codes follow the published hook contract: exit 0 with a decision on
stdout is a decision; exit 0 with empty stdout defers to Claude Code's normal
permission flow; exit 2 blocks. Exit 1 means "non-blocking error, run the tool
anyway", which is why every path that fails to reach a decision returns 2 —
an uncaught traceback in a security control must not become permission to
proceed. That covers exceptions raised while judging (:func:`main`), the write
of the decision itself (CP-03 — a stdout nobody is reading is a way to fail
too), the stderr message that *reports* such a failure (CP-03's twin: the
commonest reason stdout will not take the answer is a parent that stopped
reading, and that parent has usually stopped reading stderr too), *and*
first-party imports that fail at module scope, which are guarded separately
because ``main``'s ``except`` is not yet on the stack when they run.

What this hook does **not** override: a decision of ``allow`` is this control
declining to object, not a grant. Claude Code still applies the user's own
``permissions`` rules on top of it — measured, both directions, in
``hooks/README.md`` §"What an allow does not do".
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from dataclasses import replace
from pathlib import Path
from typing import Any, Mapping, Sequence

if __package__ in (None, ""):
    # Claude Code invokes a hook as a bare command line with the user's own
    # project as cwd, so the only thing on sys.path is THIS file's directory —
    # `engine` would not import. Put the repo root in front of the first-party
    # imports below. When the module is imported as `hooks.chokepoint_hook`
    # (the tests, or an installed package) __package__ is set and sys.path is
    # left alone.
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# The first-party imports are GUARDED, because a failure here is the one crash
# `main()`'s try/except structurally cannot see: it happens at module scope,
# before `main` exists to catch it, and CPython exits 1 on an uncaught
# exception. Exit 1 in this protocol means "non-blocking error, run the tool
# anyway", so a missing PyYAML would become permission to proceed — the exact
# fail-open this file's docstring says it is written to prevent.
#
# Measured before the guard existed: running this hook under an interpreter
# without PyYAML (`/usr/bin/python3` on this machine) gave exit 1, empty stdout,
# and an uncaught ModuleNotFoundError from `policy/loader.py` (2026-08-02).
# The realistic trigger is not exotic — an operator writes `python3` instead of
# the venv path in settings.json, or the venv is rebuilt after a Python upgrade.
_IMPORT_ERROR: Exception | None = None
try:
    from engine import ToolCall, Verdict, decide  # noqa: E402
    from pep import RULE_UNRESOLVABLE_PATH, UnresolvablePath, canonicalized_arguments  # noqa: E402
    from pep.log import (  # noqa: E402
        decision_event,
        loggable_arguments,
        loggable_reason,
        loggable_tool,
    )
    from policy import PolicyError, load_policy  # noqa: E402

    # The engine says "block"; the hook protocol spells the same answer "deny".
    # One explicit table rather than str(verdict), so the day a fourth verdict
    # appears this raises a KeyError instead of emitting something Claude Code
    # does not understand. It is built inside the guard because it needs
    # `Verdict`: if the import above failed there is no table to build, and
    # `main()` exits 2 before any code could reach it.
    PERMISSION_DECISION = {Verdict.ALLOW: "allow", Verdict.BLOCK: "deny", Verdict.ASK: "ask"}
except Exception as exc:  # noqa: BLE001 — deliberate: any import failure fails closed
    _IMPORT_ERROR = exc

HOOK_EVENT_NAME = "PreToolUse"
DEFAULT_AGENT_ID = "claude-code-hook"

# Synthetic rule ids for the two refusals no policy rule produces, in the shape
# the proxy already uses for its own (`proxy:uninspectable-input-channel`).
# Every decision this hook emits carries an attribution, exactly like the
# engine's `default:on_no_match`.
RULE_UNPARSEABLE = "hook:unparseable-input"
RULE_POLICY_ERROR = "hook:policy-error"
# The third one, `pep:unresolvable-path`, is imported rather than spelled here:
# the proxy emits the same string for the same refusal, and side_by_side.py
# reports any difference between the doors as a disagreement. One constant, one
# spelling (see pep/canonicalize.py).

MCP_PREFIX = "mcp__"

# Claude Code built-in -> (engine tool, canonical argument key, payload key).
#
# Confirmed by measurement, not by reading docs: a real headless Claude Code
# 2.1.220 was driven with a logging PreToolUse hook, and the payloads these
# three columns are read off are the ones it sent. `Edit` and `NotebookEdit`
# both land on `write_file` because the policy's vocabulary describes what a
# call DOES, not which button the harness pressed.
NATIVE_TOOLS: dict[str, tuple[str, str, str]] = {
    "Read": ("read_file", "path", "file_path"),
    "Write": ("write_file", "path", "file_path"),
    "Edit": ("write_file", "path", "file_path"),
    "NotebookEdit": ("write_file", "path", "notebook_path"),
    "Bash": ("run_command", "command", "command"),
    "WebFetch": ("fetch_url", "url", "url"),
}

class UnparseableInput(ValueError):
    """Input this hook refuses to judge.

    Always converted to a deny, never to silence: the proxy refuses
    uninspectable input rather than passing it through (B-005), and a hook that
    cannot understand its own stdin is in exactly that position.
    """


def _parse_payload(stdin_text: str) -> tuple[str, Mapping[str, Any]]:
    """The ``(tool_name, tool_input)`` pair, or :class:`UnparseableInput`.

    ``tool_input`` is checked to be an object because the engine's ``ToolCall``
    is typed ``Mapping | None`` and every predicate calls ``.get`` on it: a
    JSON array there would raise from inside ``decide()``, i.e. a crash where a
    decision belongs. Absent or null is fine and means "no arguments" — the
    mapped predicates then find nothing and deny-by-default applies.

    **``RecursionError`` is caught beside ``ValueError``, and that is the whole
    of CP-01.** ``json.loads`` raises it on input nested past the parser's own
    budget — about 116,000 levels on CPython 3.14 (measured, B-110), about a
    thousand on an interpreter whose guard counts recursion units rather than
    stack bytes — and ``RecursionError`` is **not** a ``ValueError``, so it used
    to escape this function, escape :func:`run`, and land in :func:`main`'s
    blanket handler: exit 2, **no decision event, no rule id**. Fail-closed and
    therefore no wrong allow; silent, which is the half that matters. The
    documented refusal for input this door cannot read is exit 0, ``deny``, and
    one ``hook:unparseable-input`` event, and that is the posture the proxy
    took for the same class of input in **B-112**
    (``proxy:uninspectable-input-channel``): refuse *loudly*, with an event,
    rather than drop the attempt out of the audit stream. Measured before the
    catch widened, shipped policy, payload built by string concatenation so the
    probe had no ceiling of its own — malformed JSON gave
    ``exit=0 deny events=1``, a 200,000-level payload gave
    ``exit=2 <no decision> events=0``.
    """
    try:
        payload = json.loads(stdin_text)
    except (ValueError, RecursionError) as exc:  # json.JSONDecodeError is a ValueError
        raise UnparseableInput(f"stdin is not JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise UnparseableInput(f"stdin is JSON but not an object (got {type(payload).__name__})")
    tool_name = payload.get("tool_name")
    if not isinstance(tool_name, str) or not tool_name:
        raise UnparseableInput("payload carries no non-empty string 'tool_name'")
    tool_input = payload.get("tool_input")
    if tool_input is None:
        tool_input = {}
    if not isinstance(tool_input, dict):
        raise UnparseableInput(f"'tool_input' is not an object (got {type(tool_input).__name__})")
    return tool_name, tool_input


def _translate(tool_name: str, tool_input: Mapping[str, Any], agent_id: str) -> ToolCall | None:
    """One PreToolUse payload as an engine envelope, or ``None`` for no decision.

    **MCP calls** (``mcp__<server>__<tool>``) hand the engine the bare tool name
    and the arguments object *unchanged*, which makes the envelope byte-identical
    to the one ``proxy/server.py`` builds for the same call arriving over MCP.
    That is what makes "both doors, one brain" a literal claim rather than an
    analogy. A name that does not split into a non-empty server and a non-empty
    tool is refused rather than guessed at, and so is one that splits in more
    than one place (B-034). The server half is also carried
    across in ``ToolCall.server`` (D-015, B-011) — the one field where the two
    doors' envelopes may legitimately differ, because the proxy learns its
    single upstream's name from a flag rather than from the wire.

    **Native calls** are translated through :data:`NATIVE_TOOLS`. The canonical
    key is ADDED to a copy of the payload, never substituted for it: the other
    keys must survive because ``args_match_any`` scans every string anywhere in
    ``arguments``, so a private key pasted into ``Write.content`` still trips
    ``private_key_block``. Optional keys are read with ``.get`` semantics
    throughout — the capture shows they are simply absent, not null
    (``Read`` without ``offset``, ``Bash`` without ``timeout``,
    ``NotebookEdit`` in insert mode without ``cell_id``). When the source key is
    missing the canonical key is omitted, the path/command/url predicate is
    unsatisfied, and the call falls to deny-by-default.

    **An unmapped native tool returns ``None``** — ``Grep``, ``Glob``, ``Task``,
    ``TodoWrite``, ``WebSearch``, ``ToolSearch`` and every other built-in this
    policy vocabulary cannot describe. The caller prints nothing and exits 0, so
    Claude Code's normal permission flow decides. It must NOT emit an "allow":
    this hook can only ever narrow what the user already permitted, and a
    security control that widens its host's permissions is a vulnerability, not
    a feature. The gap is real and named in ``hooks/README.md``.
    """
    if tool_name.startswith(MCP_PREFIX):
        rest = tool_name[len(MCP_PREFIX):]
        # Every position where `__` could be the separator with a non-empty half
        # on each side. One position is a name this door can read; two or more is
        # a name it can only guess at.
        splits = [i for i in range(1, len(rest) - 2) if rest.startswith("__", i)]
        if not splits:
            raise UnparseableInput(
                f"MCP tool name {tool_name!r} does not split into server and tool"
            )
        # B-034: `__` is the framing delimiter and it is not escapable, so
        # `mcp__probe__west__read_file` is the name of BOTH (server 'probe',
        # tool 'west__read_file') AND (server 'probe__west', tool 'read_file').
        # This file used to take the first split silently. Measured on the
        # pre-fix tree: with a rule scoped `server: probe, tool: west__read_file`,
        # a call from a server actually named `probe__west` came back
        # `allow / trusted-west-read` here while a proxy told the true name via
        # `--server-name probe__west` returned `block / default:on_no_match` for
        # the identical deployment. One wire name, two deployments, and the
        # guess decides which rule answers.
        #
        # This door cannot refuse Claude Code's naming -- it does not choose it --
        # but it can decline to guess, and refusing is the only place the
        # ambiguity closes: the loader and `--server-name` now refuse a server
        # identity containing `__` (so the OTHER reading can no longer be written
        # down), yet the rule that answers here names `probe`, which is legal.
        # Cost, stated rather than waved at: an MCP tool whose own name contains
        # `__` is denied instead of judged. That is a false BLOCK, it is loud (a
        # decision event with this rule id), and it is the direction this project
        # takes when it cannot tell two configurations apart.
        if len(splits) > 1:
            raise UnparseableInput(
                f"MCP tool name {tool_name!r} splits into server and tool in "
                f"{len(splits)} places; '__' is the delimiter and is not "
                "escapable, so which half is the server is a guess (B-034)"
            )
        server, tool = rest[: splits[0]], rest[splits[0] + 2 :]
        # B-011 / D-015: the server half used to be split off and dropped on the
        # floor, so a rule written for one server's `read_file` answered for
        # EVERY server's. Measured on the pre-fix tree at HEAD 385b56b, both as
        # real subprocesses: `mcp__trusted__read_file` and
        # `mcp__attacker__read_file` on {"path": "/workspace/README.md"} both
        # came back permissionDecision "allow" from `fs-read-scoped`.
        #
        # It rides in its own `ToolCall` field rather than in `tool`: the
        # engine still judges the BARE tool name, so the envelope this door
        # hands the engine stays the one the proxy hands it for the same call.
        # Judging `mcp__server__tool` instead was the rejected alternative
        # (D-015) — it would rewrite every shipped rule and break the
        # byte-identical envelope `hooks/demo/side_by_side.py` checks.
        return ToolCall(tool=tool, arguments=tool_input, agent_id=agent_id, server=server)

    mapping = NATIVE_TOOLS.get(tool_name)
    if mapping is None:
        return None
    engine_tool, canonical_key, source_key = mapping
    arguments = dict(tool_input)
    if source_key in tool_input:
        arguments[canonical_key] = tool_input[source_key]
    else:
        # Setting the canonical key only when the source key is present is not
        # enough: a payload that carries the canonical key ITSELF would keep it
        # and satisfy the predicate on its own, which is the opposite of the
        # paragraph above. Measured against the pre-fix file — a `Read` whose
        # `tool_input` was `{"path": "/workspace/README.md"}`, with no
        # `file_path` anywhere, came back `allow` from `fs-read-scoped`
        # (2026-08-02). Removing it restores the documented behaviour: the
        # predicate is unsatisfied and the call falls to deny-by-default.
        #
        # Safe against turning a block into an allow: `decide()` ranks matching
        # rules block > ask > allow, so dropping a string can only ever remove a
        # match, never promote one. For Bash and WebFetch the canonical and
        # source keys are the same name, which makes this a no-op.
        arguments.pop(canonical_key, None)
    # `server` is left at its default `None`: a Claude Code built-in arrives
    # from no MCP server, so there is no identity to claim. That is not a
    # weaker answer than an MCP call's — a rule carrying `server:` deliberately
    # does not match a call whose server is None (D-015, `engine/decide.py`), so
    # a native tool can never inherit a server-scoped allow.
    return ToolCall(tool=engine_tool, arguments=arguments, agent_id=agent_id)


def _event(
    *,
    agent_id: str,
    run_id: str | None,
    server: str | None,
    tool: str | None,
    arguments: Any,
    verdict: str,
    rule_id: str,
    owasp: str | None,
    reason: str,
    decision_ms: float,
) -> dict[str, Any]:
    """One decision event, same key set as ``proxy/server.py``'s ``_emit``.

    ``method`` is the hook event rather than a JSON-RPC method, and ``tool`` is
    the tool name **as it arrived at this door** (``Read``, ``mcp__probe__echo_note``)
    rather than the engine name it was translated to. The translation is
    deterministic in that direction and lossy in the other — three built-ins map
    onto ``write_file`` — so the arriving name is the one worth keeping; the
    rule id says what judged it.

    ``server`` (D-023) is the identity the call was JUDGED under —
    ``ToolCall.server``, the half ``_translate`` splits off an ``mcp__`` name —
    not a re-parse of the ``tool`` field. ``None`` for a native tool (no MCP
    server to claim) and for a refusal reached before translation, where no
    identity was ever established. At the proxy door the same key carries
    ``--server-name``; the two doors may legitimately differ here, for the
    reason ``_translate``'s docstring gives.

    ``run_id`` (D-025) is **always None at this door, and that is the answer
    rather than a gap**. A run is one MCP client session with the proxy (D-022);
    this hook is one short-lived process per tool call, holds no session and no
    ``RunState`` (``decide()`` is called with ``run_state=None`` — limits are the
    proxy's job), so there is no run here to identify. Minting a per-process id
    would be worse than null: every call would look like its own run, and a
    consumer grouping by it would silently see runs of exactly one event. The
    key is present-and-null rather than absent so both doors keep one key set.

    ``tool`` and ``reason`` arrive here ALREADY passed through
    :func:`pep.log.loggable_tool` / :func:`pep.log.loggable_reason` (B-015) —
    the same shape ``proxy/server.py`` uses, where ``logged_tool`` is computed
    once and every branch writes it. A new caller that skips them writes a
    credential-bearing tool name straight into the audit trail.
    """
    return decision_event(
        agent_id=agent_id,
        run_id=run_id,
        server=server,
        method=HOOK_EVENT_NAME,
        tool=tool,
        arguments=arguments,
        verdict=verdict,
        rule_id=rule_id,
        owasp=owasp,
        reason=reason,
        decision_ms=decision_ms,
    )


def _write_event(event: Mapping[str, Any], log_path: str | None) -> None:
    """One JSON line to ``--log-file``/``$CHOKEPOINT_LOG``, else to stderr.

    Append mode, one line, flushed: a hook is one short-lived process per tool
    call, so the file is opened and closed around each write rather than held.
    A failure here is deliberately not swallowed — see :func:`main`.
    """
    line = json.dumps(event, default=str)
    if log_path is None:
        print(line, file=sys.stderr, flush=True)
        return
    with open(log_path, "a", encoding="utf-8") as handle:
        handle.write(line + "\n")


def _decision_json(permission_decision: str, reason: str) -> str:
    return json.dumps(
        {
            "hookSpecificOutput": {
                "hookEventName": HOOK_EVENT_NAME,
                "permissionDecision": permission_decision,
                "permissionDecisionReason": reason,
            }
        }
    )


def _reason_text(verdict: Verdict, rule_id: str, owasp: str | None, reason: str) -> str:
    """The sentence Claude Code shows the user. Mirrors the proxy's error text."""
    owasp_part = f" ({owasp})" if owasp else ""
    if verdict is Verdict.BLOCK:
        return f"agent-chokepoint: blocked by rule {rule_id}{owasp_part}: {reason}"
    if verdict is Verdict.ASK:
        return (
            f"agent-chokepoint: approval required by rule {rule_id}{owasp_part}: {reason} "
            "— answer in Claude Code's permission prompt"
        )
    return f"agent-chokepoint: allowed by rule {rule_id}{owasp_part}"


def _parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="chokepoint_hook",
        description="Judge one Claude Code PreToolUse payload against a chokepoint policy.",
    )
    parser.add_argument("--policy", help="policy file to load; defaults to $CHOKEPOINT_POLICY")
    parser.add_argument("--agent-id", default=DEFAULT_AGENT_ID, help="identity stamped on decision events")
    parser.add_argument(
        "--log-file", help="decision events, one JSON per line; defaults to $CHOKEPOINT_LOG, else stderr"
    )
    return parser.parse_args(list(argv))


def run(argv: Sequence[str], stdin_text: str) -> tuple[int, str]:
    """Judge one payload. Returns ``(exit code, stdout text)``.

    Order of operations, which is itself a decision: the policy is loaded
    **before** the tool is translated, so a policy that will not load denies
    every tool including the unmapped ones. The alternative — check the mapping
    first, stay silent for unmapped tools even when the policy is broken —
    means a misconfigured install quietly enforces nothing on the tools it does
    not cover while reporting no error. A broken security control fails closed;
    it does not defer.
    """
    args = _parse_args(argv)
    agent_id = args.agent_id
    log_path = args.log_file or os.environ.get("CHOKEPOINT_LOG")

    def refuse(rule_id: str, detail: str, tool: str | None = None) -> tuple[int, str]:
        # B-015: the LOG gets the redacted name and a reason with the name
        # substituted out; the sentence returned to Claude Code keeps `detail`
        # verbatim. See the block at the decision event below for why the two
        # differ — it is the same line the proxy draws between its decision log
        # and the MCPError it hands back to the agent.
        _write_event(
            _event(
                agent_id=agent_id,
                run_id=None,  # D-025: this door holds no session; see _event
                server=None,  # refused before translation: no identity established
                # Empty declared set, and that is the answer rather than a
                # gap (B-116): every caller of `refuse` is a refusal reached
                # BEFORE the policy loaded or because it would not load, so
                # there is no `hidden_context:` section to read. Passed
                # explicitly for ``loggable_tool``'s reason — there is no
                # spelling of this call that redacts less by accident.
                tool=None if tool is None else loggable_tool(tool, ()),
                arguments=None,  # unjudgeable input is never echoed into the log
                verdict=str(Verdict.BLOCK),
                rule_id=rule_id,
                owasp=None,  # a hook-internal refusal is not a policy finding
                reason=detail if tool is None else loggable_reason(detail, tool, ()),
                decision_ms=0.0,
            ),
            log_path,
        )
        return 0, _decision_json("deny", f"agent-chokepoint: refused — {rule_id}: {detail}")

    try:
        tool_name, tool_input = _parse_payload(stdin_text)
    except UnparseableInput as exc:
        return refuse(RULE_UNPARSEABLE, str(exc))

    policy_path = args.policy or os.environ.get("CHOKEPOINT_POLICY")
    if not policy_path:
        return refuse(
            RULE_POLICY_ERROR,
            "no policy configured; pass --policy or set $CHOKEPOINT_POLICY",
            tool_name,
        )
    try:
        policy = load_policy(policy_path)
    except (PolicyError, OSError) as exc:
        return refuse(RULE_POLICY_ERROR, f"policy {policy_path!r} did not load: {exc}", tool_name)

    try:
        call = _translate(tool_name, tool_input, agent_id)
    except UnparseableInput as exc:
        return refuse(RULE_UNPARSEABLE, str(exc), tool_name)
    if call is None:
        # No decision: exit 0, print nothing, emit nothing. See _translate.
        return 0, ""

    # D-011: resolve the path against the operator's filesystem before the
    # engine judges it — the same call the proxy makes, at the same point, so
    # both doors hand the engine the same canonical envelope for the same call.
    # The engine cannot do this itself: it is pure, and `/workspace/.SSH/id_rsa`
    # (B-007) and a symlink out of the sandbox (B-008) are facts only a
    # filesystem holds.
    #
    # A path that cannot be resolved goes through `refuse()` like unparseable
    # stdin and an unloadable policy: deny, exit 0, one decision event. Passing
    # it through unresolved would be the fail-open B-006 established the rule
    # against.
    try:
        call = replace(call, arguments=canonicalized_arguments(call.arguments))
    except UnresolvablePath as exc:
        return refuse(RULE_UNRESOLVABLE_PATH, f"path could not be resolved: {exc}", tool_name)

    started = time.perf_counter()
    decision = decide(policy, call)  # run_state=None: limits are the proxy's job
    decision_ms = (time.perf_counter() - started) * 1000.0

    # B-015 at this door. Two fields carry the name into the log and both are
    # covered: `tool` holds it as it ARRIVED, and `decision.reason` quotes the
    # TRANSLATED name the engine judged, so each is scanned against the name it
    # actually contains.
    #
    # `permissionDecisionReason` below deliberately keeps the real name, which
    # is the proxy's own line (it keeps `decision.reason` unredacted in the
    # MCPError it hands the agent) applied to this door's third surface. Three
    # reasons, and the middle one is the decisive one: that sentence goes to the
    # operator sitting at the keyboard, not into a log a third party reads;
    # Claude Code has ALREADY recorded the tool call, name and all, in its own
    # transcript before it ever ran this hook, so redacting our sentence removes
    # nothing from that surface; and a refusal that cannot say which call it
    # refused is a worse control than one that can. B-015 is about the decision
    # LOG — the artifact that ships to telemetry.
    _write_event(
        _event(
            agent_id=agent_id,
            run_id=None,  # D-025: this door holds no session; see _event
            server=call.server,  # D-023: the identity the engine judged under
            tool=loggable_tool(tool_name, policy.hidden_context.all_segments),
            arguments=loggable_arguments(
                call.arguments, policy.hidden_context.all_segments, truncate=True
            ),
            verdict=str(decision.verdict),
            rule_id=decision.rule_id,
            owasp=decision.owasp,
            reason=loggable_reason(
                decision.reason, call.tool, policy.hidden_context.all_segments
            ),
            decision_ms=round(decision_ms, 3),
        ),
        log_path,
    )
    return 0, _decision_json(
        PERMISSION_DECISION[decision.verdict],
        _reason_text(decision.verdict, decision.rule_id, decision.owasp, decision.reason),
    )


def _silence_pending_stream(fd: int) -> None:
    """Point ``fd`` at ``/dev/null`` so a failed flush cannot overrule exit 2.

    CPython flushes ``sys.stdout`` and ``sys.stderr`` again on the way out, and a
    ``BufferedWriter`` whose flush just failed **still holds the unwritten
    bytes** — so the shutdown flush raises the same error a second time, where no
    code can catch it, and the interpreter replaces the chosen exit code with
    **120**. Finalisation treats a failed flush of *either* stream that way,
    which is why this takes the fd rather than assuming 1.

    Measured on this door for CP-03: with the read end of its stdout pipe closed,
    moving the write and an explicit flush inside :func:`main`'s ``try`` changed
    the exit code not at all, still 120. Redirecting fd 1 first gives that
    shutdown flush somewhere to succeed, and the 2 the caller returns is then the
    code the parent sees. With the read end of BOTH pipes closed the same 120 came
    back one line further on, from the handler's own stderr message — see
    :func:`_warn_on_stderr`.

    Failures here are swallowed on purpose. This runs on the way out of a
    refusal that is already decided, and an exception raised while tidying up
    would leave ``main`` on an uncaught traceback — exit 1, "run the tool
    anyway", the precise fail-open this file exists to prevent.
    """
    try:
        os.dup2(os.open(os.devnull, os.O_WRONLY), fd)
    except OSError:
        pass


def _warn_on_stderr(message: str) -> None:
    """Say ``message`` on stderr, and never let *saying* it become the failure.

    Both callers are one line from ``return 2`` on a refusal that is already
    decided, so an exception raised here escapes :func:`main` as an uncaught
    traceback — and an uncaught traceback in this protocol is exit 1, "run the
    tool anyway".

    That is not hypothetical, and it is **CP-03's twin**. The first half of CP-03
    moved the decision write inside ``main``'s ``try`` so a stdout that will not
    take the answer becomes exit 2; the commonest reason stdout will not take the
    answer is that the parent stopped reading, and a parent that stopped reading
    stdout has usually stopped reading stderr too. Measured on this door with the
    read end of both pipes closed, on a call the engine had BLOCKED and already
    written to the decision log: the handler's own message raised
    ``BrokenPipeError`` out of ``main`` and the process exited **120** — the same
    "event on disk says block, answer says proceed" the move was supposed to end,
    surviving one line below the line that moved. Exit 2 after the guard.

    The message is optional; the exit code is not. Losing the explanation on a
    stderr nobody is reading costs an operator nothing, because there is nobody
    on the other end to read it.

    Both halves are load-bearing, and the second one is not obvious: catching the
    exception without redirecting fd 2 leaves the exit code at **120** anyway,
    because the bytes are still in ``sys.stderr``'s buffer for the shutdown flush
    to fail on. Measured as the third arm of the same probe — guard absent 120,
    catch only 120, catch plus redirect 2.

    ``sys.stderr is None`` is checked first because ``print(..., file=None)``
    means ``sys.stdout``, and this prose on the decision channel is not a
    decision. That is not theoretical either: fd 2 closed at spawn (which is what
    makes ``sys.stderr`` ``None``) plus an unwritable log gave exit 2 with
    ``agent-chokepoint hook failed…`` sitting in stdout, where Claude Code looks
    for the verdict. Saying nothing is the correct answer when there is nowhere
    to say it.
    """
    if sys.stderr is None:
        return
    try:
        print(message, file=sys.stderr, flush=True)
    except Exception:  # noqa: BLE001 — any failure to speak is still just a failure to speak
        _silence_pending_stream(2)


def main() -> int:
    """stdin in, decision out. Any failure to reach a decision becomes exit 2.

    Python exits 1 on an uncaught exception, and exit 1 in this protocol means
    "non-blocking error — run the tool anyway". A crashing security control
    would therefore permit exactly the call it failed to judge. Exit 2 blocks,
    and the message on stderr is what Claude Code shows.

    Two distinct failures, because the try/except below can only catch one of
    them: an exception raised while judging (caught here), and a first-party
    import that never completed (checked first, via ``_IMPORT_ERROR`` — that one
    happens at module scope, before this function exists).

    **The write of the decision is inside that ``try``, and it did not used to
    be (CP-03).** Handing the answer to Claude Code is as much a way to fail as
    judging is: the flush can fail because nobody is reading the other end of
    the pipe, or because fd 1 is not a file at all. Both were measured on a call
    the engine BLOCKED — no reader gave exit **120**, an unusable fd 1 gave exit
    **1** — with the block sitting in the decision log the whole time. The event
    on disk said block and the answer said proceed, which is worse than either
    failure alone. The flush is explicit for the same reason: without it a small
    decision sits in the buffer and the error surfaces at shutdown, outside any
    ``try`` this function can write. See :func:`_silence_pending_stream` for the
    second half, which the move alone does not buy, and :func:`_warn_on_stderr`
    for the third: the handler below reports the failure on stderr, and with the
    read end of both pipes closed *that* raised out of this function and the door
    exited 120 again. Both stderr writes in this function go through the guard,
    and the import branch is not there by analogy — it was measured on the same
    two conditions: with the read end of both pipes closed it exited **120**,
    and with fd 2 closed at spawn it put ``agent-chokepoint hook could not
    import its own engine…`` on **stdout**, the channel Claude Code reads the
    verdict from, because ``file=None`` means ``sys.stdout``. Both fd conditions
    are now driven at BOTH branches in ``hooks/tests/test_hook.py``; they were
    driven at only the handler until then, and a guard nothing drives is a guard
    the next edit removes with the suite still green.

    One residual case is outside any runtime guard: if this FILE will not
    compile — a syntax error, a truncated copy — the interpreter exits 1 before
    a single line of it runs, and no code inside it can intervene. Verify the
    hook runs once after editing or upgrading it; ``hooks/README.md`` says so.
    """
    if _IMPORT_ERROR is not None:
        _warn_on_stderr(
            "agent-chokepoint hook could not import its own engine, blocking the call: "
            f"{_IMPORT_ERROR!r}"
        )
        return 2
    try:
        code, out = run(sys.argv[1:], sys.stdin.read())
        if out:
            sys.stdout.write(out)
            sys.stdout.flush()
    except Exception as exc:  # noqa: BLE001 — deliberate: see the docstring
        _warn_on_stderr(f"agent-chokepoint hook failed, blocking the call: {exc!r}")
        _silence_pending_stream(1)
        return 2
    return code


if __name__ == "__main__":
    sys.exit(main())
