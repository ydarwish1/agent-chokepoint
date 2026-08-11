"""The MCP proxy — primary enforcement point (PEP).

Sits between an agent and one upstream MCP server. Every ``tools/call`` is
judged by the pure engine; the proxy carries out the verdict and emits one
decision event. Enforcement lives in **registered handlers** — never in
``Server.middleware``, which the SDK marks provisional (checked 2026-08-02;
middleware is reserved for telemetry).

Verdict execution:

- **allow** — forward the call upstream over the raw untyped channel and hand
  the raw result dict back untouched. Typed models are ``extra="ignore"`` and
  would silently drop fields the SDK doesn't know; the raw dict path keeps the
  proxied result identical to what the same client gets talking to the
  upstream directly (both cross the same wire-layer result sieve).
- **block** — raise ``MCPError`` code ``-32000`` carrying the rule id: the
  call visibly fails and never reaches the upstream.
- **ask** — **fails closed** (D-005). No approval channel is wired here, so
  ``ask`` blocks with code ``-32001`` and says why. An elicitation-based
  approval flow is future work; absence of a human must never convert to an
  allow.

Run-state counters (for the policy ``limits:``) live here, not in the engine:
attempts are counted *before* the verdict and include blocked calls, so
blocked-then-retry loops trip ``max_repeated_identical_calls``.

``tools/list`` is judged too, when — and only when — the policy carries a
``tool_listing:`` section (D-039). Four of Invariant Labs' eight published MCP
attack classes arrive in a tool DESCRIPTION rather than in a call, and until
that section existed this handler emitted one telemetry line and returned the
upstream's response untouched. The check is an INTEGRITY one: each advertised
definition is reduced to a digest and compared against the ones the operator
approved, and against the ones this run has already been handed. No description
is read, scored or pattern-matched anywhere — the engine is given
``(name, digest)`` pairs, so a description never reaches it. With no
``tool_listing:`` section the handler behaves exactly as it did before, event
included.

Path canonicalization (D-011) lives here for the same reason: this process has
a filesystem and the engine has none. ``pep.canonicalize`` resolves
``arguments["path"]`` before ``decide()`` sees it, closing B-007 (case) and
B-008 (symlink escape), and a path it cannot resolve is refused with
``-32003`` rather than passed through unresolved. The engine is judged on the
canonical path; the UPSTREAM still receives the agent's original ``params``,
untouched — see :func:`build_proxy`'s ``on_call_tool``.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
import time
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, suppress
from datetime import datetime, timezone
from typing import Any, Callable

import anyio
from pydantic import TypeAdapter

import mcp.types as t
from mcp import Client, MCPError
from mcp.server.lowlevel.server import Server
from mcp.shared._context_streams import create_context_streams
from mcp.shared.message import SessionMessage

from engine import (
    Policy,
    RunState,
    ToolCall,
    ToolDefinition,
    ToolListing,
    UndigestibleDefinition,
    Verdict,
    contains_hidden_context,
    contains_sensitive,
    decide,
    decide_listing,
    tool_definition_digest,
)

# CP-05. The string bound and the walk that applies it are the HOOK's, imported
# rather than restated, for D-036 Decision 1's reason — two copies of a bound
# are two things free to drift, and this door has to be able to say which number
# the other one cut at.
# The direction is safe and was checked rather than assumed: nothing under
# `hooks/`, `engine/`, `pep/` or `policy/` imports `proxy`
# (`/usr/bin/grep -rn -e 'import proxy' -e 'from proxy' hooks/ pep/ engine/ policy/`
# exits 1), so there is no cycle; `hooks` is a declared package in
# `pyproject.toml:[tool.setuptools] packages` and `deploy/Dockerfile` COPYs it
# into the image, so the name resolves in the shipped container and not only in
# this repo's own test run. `proxy/tests/test_proxy.py` already imports this
# module's `_loggable_tool` for the same reason.
#
# The residual, stated rather than mechanised: `chokepoint_hook`'s first-party
# imports sit inside a `try/except Exception` that deliberately swallows failure
# so `main()` can exit 2, and `_truncated`'s depth branch reads a
# `DEPTH_BOUND_MARKER` built inside that guard. Everything in the guard except
# `policy` is imported unguarded by THIS module above, so the only way to reach
# an unbound name here is an install with no PyYAML — which cannot run
# `python -m proxy` at all, since `proxy/__main__.py` loads the policy file.
# The right long-term home for the walk is `pep/`, the package both doors
# already share; moving it there is a separate change.
#
# `MAX_LOGGED_STRING` rides along with the walk that uses it because the bound
# this door applies has to be findable AT this door: CP-05's own tell was
# `/usr/bin/grep -n -e MAX_LOGGED -e truncat proxy/server.py` exiting 1, and a
# bound you cannot grep out of the file that applies it is how a missing one
# stays invisible.
#
# The walk has exactly three call sites here and none of them is "every call's
# arguments" — that spelling was measured and rejected, `_loggable_arguments`
# says why. It is the first stage of `_within_the_line_bound`, and the cut
# `_loggable_tool` and the `reason` substitution make on their two
# agent-chosen fields. `MAX_LOGGED_STRING` is read once more, by `_summarised`,
# as the per-FIELD ceiling of the line bound's last stage.
from hooks.chokepoint_hook import MAX_LOGGED_STRING, _truncated
from pep import RULE_UNRESOLVABLE_PATH, UnresolvablePath, canonicalized_arguments

# JSON-RPC implementation-defined server-error range (-32000..-32099).
BLOCKED_ERROR_CODE = -32000
ASK_FAIL_CLOSED_ERROR_CODE = -32001
UNINSPECTABLE_ERROR_CODE = -32002
# A path this proxy could not resolve. Its own code rather than BLOCKED's: the
# agent is being told "I could not place this path", which is a different fact
# from "a rule refused it", and a client that retries on -32000 should not
# retry on this.
UNRESOLVABLE_PATH_ERROR_CODE = -32003

# A `tools/list` response this proxy could not reduce to (name, digest) pairs
# while the tool-listing door was armed (D-039). Inside the `proxy:` prefix the
# loader already reserves (D-026), beside `proxy:uninspectable-input-channel`,
# because it states the same fact about a different method: input this door
# cannot judge is refused rather than passed through unjudged.
RULE_UNINSPECTABLE_LISTING = "proxy:uninspectable-listing"

_RAW_DICT = TypeAdapter(dict)

DecisionEventSink = Callable[[dict[str, Any]], None]

#: One envelope scalar of a JSON-RPC frame, read out of the frame's LEADING
#: scalar members only — every member before the first `{` or `[` (B-112).
#:
#: Deliberately a pattern and not a parser. The frame this runs on is one the
#: transport's own parser refused; parsing it again with a more permissive
#: parser and acting on the result is the thing :func:`build_proxy`'s
#: ``_refuse_unparseable_frame`` docstring forbids. The leading-scalar
#: restriction is what makes it safe to read agent-controlled bytes: a `"id"`
#: planted inside `params` sits behind a `{`, so the alternation cannot reach
#: it and the answer is "not recoverable" rather than the attacker's value.
#: Members before the wanted one: any run of `"name": <scalar>,` pairs. The
#: alternation carries no `{` or `[`, which is the whole safety property.
_LEADING_MEMBERS = (
    r'\A\s*\{\s*(?:"(?:[^"\\]|\\.)*"\s*:\s*'
    r'(?:"(?:[^"\\]|\\.)*"|-?\d+(?:\.\d+)?|true|false|null)\s*,\s*)*?'
)
#: The wanted member's value: a bounded string or an integer, nothing else.
_SCALAR_VALUE = r'"\s*:\s*(?P<value>"(?:[^"\\]|\\.){0,128}"|-?\d+)'

#: Concatenated per call rather than `.format`-ed: the pattern is full of regex
#: braces, and `str.format` reads `\{` and `{0,128}` as format fields — which it
#: did, raising `ValueError: unmatched '{' in format spec` inside the relay and
#: taking the whole session down with it. Caught by running B-112's own probe
#: against the fix rather than by reading the fix.
_LEADING_SCALAR_CACHE: dict[str, re.Pattern[str]] = {}


def _leading_scalar(raw: str, key: str) -> str | int | None:
    """``key``'s value, or ``None`` if it is not among the frame's leading scalars."""
    if not raw:
        return None
    pattern = _LEADING_SCALAR_CACHE.get(key)
    if pattern is None:
        pattern = re.compile(_LEADING_MEMBERS + '"' + re.escape(key) + _SCALAR_VALUE)
        _LEADING_SCALAR_CACHE[key] = pattern
    match = pattern.match(raw[:4096])
    if match is None:
        return None
    value = match.group("value")
    try:
        return json.loads(value)
    except ValueError:  # pragma: no cover - the pattern already constrains this
        return None


def _one_line(text: str, limit: int = 200) -> str:
    """A foreign exception's text, flattened and capped before it enters an event."""
    flat = " ".join(text.split())
    return flat if len(flat) <= limit else flat[: limit - 1] + "…"


@asynccontextmanager
async def watch_for_unparseable_frames(
    read_stream: Any, write_stream: Any, server: Server
) -> "AsyncIterator[Any]":
    """Relay ``read_stream``, refusing loudly whatever the transport could not parse.

    **B-112.** ``mcp/server/stdio.py`` sends the parse exception down the read
    stream and ``mcp/shared/jsonrpc_dispatcher.py`` drops it at DEBUG when no
    ``on_stream_exception`` observer is registered — and the SDK exposes no seam
    to register one through ``Server.run``, which builds its dispatcher two
    frames deep in ``mcp/server/runner.py``. So the observation happens here,
    on the stream itself, where this repository owns both ends.

    Additive by construction: every item is forwarded onward unchanged, so the
    dispatcher behaves exactly as it did. What is added is the decision event
    and, when the request id is recoverable, the error reply — the three costs
    B-112 names, in the order it names them.

    One hazard, stated rather than mechanised: a frame carrying the id of a
    legitimately in-flight request would draw an error reply for that id. Both
    frames come from the same agent, so this is self-harm and not a crossing of
    a trust boundary, and refusing to answer any id would cost every honest
    client its reply to keep one dishonest client from confusing itself.
    """
    refuse = getattr(server, "chokepoint_refuse_unparseable_frame", None)
    send, receive = create_context_streams[Any](0)

    async def relay() -> None:
        async with send:
            try:
                async for item in read_stream:
                    if isinstance(item, Exception) and refuse is not None:
                        # Contained, and this is not defensive decoration: the
                        # first version of this fix raised inside `refuse` and
                        # the exception went up through the task group and
                        # killed the session — turning a SILENT drop into a
                        # dead proxy, which is worse than the defect. An
                        # observer bolted onto the enforcement path must never
                        # be able to take the door down; the frame is forwarded
                        # either way and the failure is announced on stderr.
                        try:
                            reply = refuse(item)
                        except Exception as observer_failure:  # noqa: BLE001
                            print(
                                "agent-chokepoint proxy: the unparseable-frame observer raised "
                                f"and was contained: {observer_failure!r}",
                                file=sys.stderr, flush=True,
                            )
                            reply = None
                        if reply is not None:
                            with suppress(anyio.BrokenResourceError, anyio.ClosedResourceError):
                                await write_stream.send(
                                    SessionMessage(t.jsonrpc_message_adapter.validate_python(reply))
                                )
                    await send.send(item)
            except (anyio.BrokenResourceError, anyio.ClosedResourceError):
                # The dispatcher closed its end first; same as end of input.
                pass

    async with anyio.create_task_group() as tg:
        tg.start_soon(relay)
        try:
            yield receive
        finally:
            tg.cancel_scope.cancel()


#: CP-05. The longest decision event this proxy hands a sink, in bytes of the
#: serialisation the sinks actually write — ``json.dumps(event, default=str)``,
#: spelled identically in :func:`_stderr_sink` below and in
#: ``proxy/__main__.py``'s ``--log-file`` sink, so the number counted here is the
#: number appended.
#:
#: 16 KiB, and the two constraints it sits between were measured rather than
#: guessed. Above it: the largest decision line in any committed artifact is
#: **487 bytes** (``telemetry/samples/proxy-decisions.jsonl``; the longest string
#: in any of the seven sample files is 154 characters), and the largest an
#: ordinary run can produce is a ``tools/list`` drift sentence, which carries a
#: name and two digests per offending tool — measured against
#: ``engine/listing.py``, **183 bytes each** at scale (264 for a lone one), so
#: the sentence stays whole up to roughly eighty-five tools drifting at once.
#: Below it: with the shipped ``limits.max_tool_calls_per_run: 100`` one run can
#: now write at most 1.6 MB whatever the agent sends, and the chart's 512Mi
#: ``sizeLimit`` (``deploy/chart/templates/deployment.yaml``) holds 32,768 lines
#: of this size.
MAX_LOGGED_LINE = 16384


def _line_length(event: dict[str, Any]) -> int:
    """Bytes a sink will write for ``event`` — its encoder, its defaults."""
    return len(json.dumps(event, default=str).encode("utf-8"))


def _summarised(value: Any) -> Any:
    """One event FIELD, replaced by its encoded size once it is past reading.

    :data:`MAX_LOGGED_STRING` reused as a per-field ceiling rather than a third
    constant: a single field that needs more bytes than the longest string this
    project is willing to log is already a field no operator reads. The summary
    names the size, so the event still says how big the thing it dropped was —
    the fact an operator needs when the question is "what filled this volume".
    """
    encoded = _line_length({"": value}) - len('{"": }')
    if encoded <= MAX_LOGGED_STRING:
        return value
    return f"<{encoded} bytes omitted: over the {MAX_LOGGED_LINE}-byte decision-line bound>"


def _within_the_line_bound(event: dict[str, Any]) -> dict[str, Any]:
    """``event``, or as much of it as fits in :data:`MAX_LOGGED_LINE` bytes.

    **CP-05, and this is the round-3 correction to it.** Nothing on the proxy
    path bounded what ONE decision event could write, so a ``tools/call`` the
    gateway REFUSED — never forwarded, ``block / default:on_no_match`` — still
    chose how many bytes the gateway appended to its audit trail. In the shipped
    chart that trail is ``decisions.jsonl`` on an emptyDir
    (``deploy/demo/gateway_driver.py:590``), which is the other half of the
    entry.

    The first attempt bounded the arguments per STRING, with the hook's own
    ``_truncated``, and that does not close the entry's harm sentence. Measured
    on this tree (CPython 3.14.6) under the test suite's own ``agent_id``, one
    variable — the SHAPE of an 8 MiB payload, not its size — on a call refused
    and never forwarded:

    ==============================  =================  =================
    8 MiB argument, shaped as       per-string bound   this bound
    ==============================  =================  =================
    one 8,388,608-character string  393 bytes          392 bytes
    32,768 strings of 256 chars     8,520,043 bytes    420 bytes
    ==============================  =================  =================

    Read the single-byte differences in the first row as noise and not as an
    effect: ``decision_ms`` is rounded to three places and is in every line, so
    two runs of the same call differ by a digit. The second row is what the same
    call wrote with no bound at all — every string in it is exactly at the
    cutoff, so a per-string walk has nothing to cut. A bound on the LINE cannot
    be shaped around, because the line is the thing the sink writes.

    **Three stages, and the first two exist so that bounding the line costs the
    operator as little as possible.**

    1. Under the bound — every event this repo has ever emitted, and every
       event in ``telemetry/samples/*.jsonl`` — the event is handed to the sink
       exactly as it was built. Nothing is walked, nothing is rewritten, and no
       test, sample or Sigma rule that reads an ordinary event sees a change.
       This is the property a per-string cut could not have: it changed every
       call, which is how it turned ``proxy/tests/test_decision_log_encoding.py``
       red (see :func:`_loggable_arguments`).
    2. Over it, the hook's per-string walk runs — reused rather than restated,
       for D-036 Decision 1's reason — so the single-huge-string shape keeps the
       structure an operator reads: ``{"body": "<str len=8388608 truncated>"}``
       names the offending FIELD and its size, where a dropped ``arguments``
       object would name neither.
    3. Still over it, every remaining field past :data:`MAX_LOGGED_STRING` is
       replaced by its size. That stage is what makes the bound a bound rather
       than a heuristic, and the arithmetic is worth stating because it is what
       proves the last stage always lands: the events this module builds carry
       at most twelve keys, all of them literals in this file, so a stage-3 line
       is at most twelve times (256 bytes of value + its key) ≈ 3.3 KB — under
       16 KiB with room to spare, whatever arrived on the wire. Measured on an
       event whose every field is over the ceiling, the real worst case is
       **855 bytes**, because the summary is shorter than the ceiling it
       replaces. ``proxy/tests/test_proxy.py``'s
       ``test_the_last_stage_is_bounded_by_the_field_count_and_not_by_hope``
       asserts both halves — the relation between the two constants, and the
       function driven on that event.

    **Logging only, and it is the last thing that happens to an event.** The
    verdict is already made, the upstream already has (or does not have) the
    call, and ``_call_signature`` keyed the repeat counter off the arguments the
    agent sent long before this. No stage can change a verdict, and the
    ``MCPError`` the agent gets back is built from ``decision`` rather than from
    the event.

    **The cost is one extra ``json.dumps`` per event**, since the sink encodes
    again to write. Measured on an ordinary 368-byte decision event, this
    function costs **6.8 µs**, against a ``decision_ms`` the same events record
    in the tens of microseconds; the stages past the first run only on events
    that are already abusive. Handing the sink a pre-encoded line instead would
    remove the second encode and change ``DecisionEventSink``'s contract, which
    ``proxy/__main__.py`` and every test in this suite implement — a wider
    change than this entry, for microseconds.

    **What it costs, and every log bound costs this.** An agent can now pad an
    argument past 16 KiB and have the decision event record a size instead of
    the text, so a detection that greps argument TEXT stops seeing that call's
    arguments. Three things keep it from being a hole worth trading for. The
    verdict is unaffected — ``decide()`` is handed the full arguments and this
    runs after it, so the call is refused or allowed on exactly what the agent
    sent. Both redaction markers are unaffected — they are produced by
    :func:`_loggable_arguments` before this, and a redacted field is a short
    string this function then has nothing to do to, so "a credential was in this
    call" survives at any payload size. And the alternative is not "the text is
    searchable": before this bound the same agent wrote 8 MiB into the audit
    file per refused call, which is not a searchable log either. The residual is
    real and belongs in ``docs/LIMITATIONS.md`` beside the other things this door
    does not reach.

    **What it does not reach**, stated rather than left to be found: the
    policy-error event in ``proxy/__main__.py`` goes to the sink directly rather
    than through :func:`build_proxy`'s ``_emit``, so it is not bounded here. Its
    fields are the operator's own ``--agent-id``/``--server-name`` and the
    exception from loading the operator's own policy file — nothing an agent
    supplies.
    """
    if _line_length(event) <= MAX_LOGGED_LINE:
        return event

    walked = dict(event)
    # `in`, not `.get`: `_emit({"method": "tools/list", "action": "forwarded"})`
    # carries no `arguments` key at all, and inventing one here would change the
    # shape of a published event to describe a case it cannot reach.
    if "arguments" in walked:
        walked["arguments"] = _truncated(walked["arguments"])
    if _line_length(walked) <= MAX_LOGGED_LINE:
        return walked

    return {key: _summarised(value) for key, value in walked.items()}


def _stderr_sink(event: dict[str, Any]) -> None:
    print(json.dumps(event, default=str), file=sys.stderr, flush=True)


def _call_signature(name: str, arguments: Any) -> str:
    """A fixed-width key for "has this exact call been made before this run".

    **CP-05, the resident half.** This used to return the serialisation itself,
    and ``_ProxyState.signature_counts`` keeps every distinct signature for the
    life of the run (``build_proxy``'s ``on_call_tool``) — so an 8 MiB argument
    stayed in the proxy's memory until the session ended, on a call the gateway
    had already REFUSED. The line it wrote is bounded now and the file it wrote
    into has a ``sizeLimit``; without this, the third copy an agent got for free
    from a refused call was the one nobody could see.

    The digest changes nothing about what is counted. The key is compared only
    for equality, never read back or logged, so the only property required of it
    is that two calls collide exactly when their serialisations are equal —
    which is what ``max_repeated_identical_calls`` means by identical.
    SHA-256 rather than ``hash()``: this is per-run state whose count feeds a
    policy limit, and ``hash()`` is randomised per process AND truncates to 64
    bits, which is a collision an agent could search for to make two different
    calls share one counter. The full serialisation is still built here, so the
    peak allocation for one call is unchanged; what is bounded is what SURVIVES
    the call.

    ``json.dumps`` defaults to ``ensure_ascii=True``, so ``serialised`` is ASCII
    whatever the arguments carried — a lone surrogate arrives as a six-character
    ``\\udXXX`` escape — and the encode below cannot raise on it. That matters
    because this runs before the engine is asked anything: an exception here
    would be a refusal the policy never chose.
    """
    serialised = json.dumps({"name": name, "arguments": arguments}, sort_keys=True, default=str)
    return hashlib.sha256(serialised.encode("utf-8")).hexdigest()


# Its own marker rather than the credential one below, for the reason
# `TOOL_NAME_REDACTION_MARKER` has its own: the two state different facts about
# WHAT was in the arguments — a published credential format, or material this
# deployment's operator declared — and one grep for `[REDACTED:` still finds
# both. `hooks/chokepoint_hook.py` keeps a byte-identical constant, because the
# two doors' events are compared field for field (`hooks/demo/side_by_side.py`).
HIDDEN_CONTEXT_REDACTION_MARKER = "[REDACTED: declared hidden context detected in arguments]"


def _loggable_arguments(arguments: Any, hidden_segments: Any) -> Any:
    """Never write a detected secret, or declared hidden context, into the log.

    Redaction keys off argument CONTENT, not off which rule fired: a
    credential in an argument must stay out of the log even when the call was
    allowed (no egress rule covering that tool) or blocked by an unrelated
    rule. A telemetry schema with field-level redaction is future work.

    ``hidden_segments`` is ``policy.hidden_context.all_segments`` — D-049. It is
    passed rather than defaulted so a new call site cannot forget it and quietly
    write the material out; there is no spelling of this call that redacts less
    by accident. **Every declared set, not the sets some rule arms**, for the
    same reason as the line above: declaring material keeps it out of the log
    even where no rule refuses the call carrying it.

    Why it is here at all, and it is not tidiness: without it a refusal whose
    whole point is *this material must not leave* writes that material verbatim
    into a file — and under the shipped example policy that file is readable by
    the agent whenever the operator keeps it inside an allowed prefix (B-088).
    A control that leaks what it protects is worse than no control, because the
    operator believes it worked.

    The credential check runs first so a call carrying both is attributed to the
    credential, which is the narrower and more actionable fact.

    **CP-05 deliberately does NOT cut length here, and that is the round-3
    correction to this entry.** The audit is right that nothing on the proxy
    path bounded what a refused call wrote — ``/usr/bin/grep -n -e MAX_LOGGED
    -e truncat proxy/server.py`` exited 1 with no output while the hook door had
    been bounded since B-111. The first attempt closed it by returning
    ``_truncated(arguments)`` from this line, cutting every logged string at
    ``hooks/chokepoint_hook.py:MAX_LOGGED_STRING``. Measured, that fixes one
    payload SHAPE and not the defect: an 8 MiB argument sent as 32,768 strings
    of exactly 256 characters wrote the same **8,520,043-byte** decision line
    with the walk in place as without it, because a per-string bound has nothing
    to cut when every string is already at the cutoff. The bound that answers
    the entry is on the LINE — :func:`_within_the_line_bound`, applied at
    ``_emit``.

    Two further things went wrong when the cut was made here, and they are why
    the line is the RIGHT place rather than merely a bigger hammer:

    * ``proxy/tests/test_decision_log_encoding.py`` proves that a control
      character in an argument cannot forge a log line, and its last assertion
      is deliberately "these payloads never reached the log at all" — the
      control that stops the other three passing vacuously. Every forgery vector
      is longer than 256 characters, so a cut here summarised them away and
      turned that file's three legs red. A bound that fires on ORDINARY events
      deletes the evidence other properties are measured on.
    * the events this suite asserts on, the committed
      ``telemetry/samples/*.jsonl`` and ``hooks/demo/side_by_side.py``'s
      field-for-field comparison all read ordinary events, and a cut here
      changes every one of them. The line bound changes none: an event under
      :data:`MAX_LOGGED_LINE` reaches the sink exactly as this function built it.

    So the two doors still differ on this field between 256 characters and the
    line bound, exactly as they did before this entry, and the asymmetry has a
    reason rather than being an oversight: the hook cuts per string because a
    Claude Code ``Write`` payload carries a whole file body and an ``Edit``
    payload two whole strings, which is a size and privacy hazard this door has
    never faced. What both doors now have is a bound; they do not have the same
    one.

    **Logging only, exactly as at the hook.** ``decide()`` has already been
    handed the full ``judged_arguments`` by the time this runs, and
    ``_call_signature`` builds the repeat-detection key from the arguments the
    agent sent, before any of this. No verdict and no counter moves.
    """
    if contains_sensitive(arguments):
        return "[REDACTED: sensitive content detected in arguments]"
    if contains_hidden_context(hidden_segments, arguments):
        return HIDDEN_CONTEXT_REDACTION_MARKER
    return arguments


# Its own marker rather than the arguments one above: the two state different
# facts about where the credential was, and one grep for `[REDACTED:` still
# finds both. `hooks/chokepoint_hook.py` keeps the arguments marker as a
# byte-identical constant for that reason; its `tool` field is written verbatim
# today and wants this one.
TOOL_NAME_REDACTION_MARKER = "[REDACTED: sensitive content detected in tool name]"

# The declared-material twin of the marker above (B-116, schema 1.7.0). Its own
# string for the same reason `HIDDEN_CONTEXT_REDACTION_MARKER` is its own: the
# two state different facts about what was in the name — a published credential
# FORMAT, or material THIS deployment declared — and one grep for `[REDACTED:`
# still finds both. Byte-identical at the hook.
HIDDEN_CONTEXT_TOOL_NAME_REDACTION_MARKER = (
    "[REDACTED: declared hidden context detected in tool name]"
)


def _loggable_tool(name: str, hidden_segments: Any) -> str:
    r"""Never write detected material into the decision log — B-015, B-116.

    The tool name is an agent-controlled string exactly like an argument, and
    this proxy wrote it verbatim, so ``read_file_AKIAIOSFODNN7EXAMPLE`` landed
    in the decision log while the identical credential sitting in ``arguments``
    was redacted in the same run.

    **Why the name is split before it is scanned.** Every matcher in
    ``ARG_MATCHERS`` is anchored on ``\b`` and ``_`` is a word character, so a
    plain ``contains_sensitive(name)`` is False on B-015's own repro
    string — measured on this interpreter, not assumed:
    ``contains_sensitive("read_file_AKIAIOSFODNN7EXAMPLE") is False``. That fix
    would have closed B-015 in form and left it open in fact. ``_`` is the
    separator in MCP tool naming (``mcp__server__tool``), so every
    underscore-delimited SUFFIX of the name is offered to the matchers too. The
    first candidate is the whole name, so nothing the plain call caught is lost
    — the GitHub/Slack token patterns carry a ``_`` inside the pattern itself
    and are only found that way.

    Rejected: loosening the ``\b`` in ``engine/predicates.py``. That is the same
    regex ``args_match_any`` evaluates for every policy — it would change
    enforcement to fix a log line.

    **Redacted whole, not in part.** ``contains_sensitive`` is a boolean union
    over the matchers and carries no span, so partial redaction would have to
    guess where the credential ends and could leave the head of it behind — the
    bug it was meant to fix. Field-level redaction is future work, the same line
    ``_loggable_arguments`` draws. The event survives losing the name:
    it still carries the verdict, the rule id, the reason, the timestamp and the
    agent id, and a tool named after a credential matches no rule in a
    deny-by-default policy, so what the trail records is "a call whose NAME
    carried a credential was refused" — the auditable fact. A legitimate tool is
    not named after an AWS key.

    **The residual is wider than this docstring used to say** (B-045). Every
    candidate is a ``_``-delimited SUFFIX, so the credential needs a word
    boundary on BOTH sides of some candidate: on the left, the name starts there
    or a ``_`` (a split point) or a non-word character precedes it; on the right,
    the name ends there or a non-word character follows. Measured at both doors
    over 320 names across all four credential families; the doors agree on every
    one:

    ==================================  ==========================  =============
    shape                               AWS / Google (fixed len)    GitHub / Slack
    ==================================  ==========================  =============
    the credential alone                redacted                    redacted
    after ``_``/non-word, ends the name redacted                    redacted
    after ``_``/non-word, then ``-x``   redacted                    redacted
    ``…AKIA…_tail``                     **missed**                  **missed**
    ``…AKIA…x``  (fused after)          **missed**                  redacted
    ``…xAKIA…``  (fused before)         **missed**                  **missed**
    ``readnoteAKIA…`` (no separator)    **missed**                  **missed**
    ==================================  ==========================  =============

    Rows 4 and 6 hold for every family. Row 5 splits because a fixed-length
    pattern has nowhere left to consume while an open-ended one (GitHub
    ``{36,}``, Slack ``{10,}``) takes the extra character and finds its boundary
    one place later. And read rows 2 and 6 together: **ending the name is not on
    its own sufficient** — ``read_note_xAKIA…`` ends the name and is still
    missed, because the fused letter destroys the leading boundary. ``_`` after
    the credential is fatal for everyone, because it is a word character AND the
    split delimiter, so no candidate ever ENDS at the credential.

    ``contains_sensitive("read_note_AKIA…")`` is **False**, which is why adding
    the ``_``-delimited PREFIXES does not close the gap: a prefix supplies the
    trailing boundary and loses the leading one. Measured before it was proposed.

    Closing it properly needs every contiguous RUN of segments as a candidate,
    which is O(n²) candidates over an agent-controlled string — a new denial
    surface bought for a log line — or the ``\b`` loosened in
    ``engine/predicates.py``, which is the same regex every policy's
    ``args_match_any`` evaluates and would change ENFORCEMENT to fix logging.
    Both are rejected; the shape above is pinned instead by
    ``proxy/tests/test_proxy.py::TestToolNameRedactionBoundary`` so it cannot
    drift silently, and it is written down for operators in
    ``docs/LIMITATIONS.md`` §17.

    Logging only. The ENGINE and the UPSTREAM are handed ``params.name``
    untouched — redacting at the source would change which rule matches and
    would hand the upstream a tool it does not have.

    **CP-05's twin, and after round 3 it is about COST rather than volume.**
    ``params.name`` is agent-chosen exactly like an argument — read straight off
    the wire, with nothing on this path validating it — and it lands in TWO
    fields of the same event: ``tool``, and ``reason``, which quotes the name
    back (``engine/decide.py`` writes ``rule {id} matched tool {call.tool!r}``
    and ``no rule matched tool {call.tool!r}``; cited by their text rather than
    by line, which has already moved once). :func:`_within_the_line_bound`
    catches an over-long name on its own: measured on this tree, one
    ``tools/call`` whose NAME was 8 MiB, refused ``block / default:on_no_match``
    and never forwarded, wrote **421 bytes** with this guard and **410** with
    the guard's two lines deleted and nothing else changed. So the volume is not
    what this buys.

    Three things are. First, the candidate build below is **quadratic in the
    number of segments** — every ``_``-delimited suffix is materialised before
    the matchers see any of them — and that cost is paid inside the decision
    path, before any event is built, so no bound on the OUTPUT can reach it.
    Same A/B, at 500 / 1000 / 2000 / 4000 segments and quoted as a range across
    two runs because a stopwatch on a laptop is noisy: **0.003–0.005 /
    0.010–0.017 / 0.039–0.059 / 0.154–0.215 s** unguarded against about a
    microsecond guarded, the last from a 16 KB name that materialises ~32 MB of
    candidate strings. Second, the event stays readable: with the guard the
    ``tool`` field carries the hook's own ``<str len=N truncated>`` and every
    other field is untouched, where without it the whole event drops to the line
    bound's third stage. Third, a bound in the field that carries the name is
    findable by an operator grepping this file, which is how CP-05 was missed.

    **Why the guard comes before the scan.**
    :func:`~hooks.chokepoint_hook._truncated` replaces an over-length string
    WHOLE — it is a summary, ``<str len=N truncated>``, not a prefix cut — so a
    name past the bound carries no name text into the event whatever this
    function decides. Scanning it first cannot keep anything out of the log that
    the summary does not already keep out; it can only spend the quadratic build
    on a string nobody will read. What is given up is stated rather than hidden,
    and it is attribution, not containment: for a name past the bound the event
    records a length instead of *which* marker applied, so an operator reads
    "a 300-character name was refused" where they would have read "this name
    carried a credential". Containment is what a security product owes here and
    it is unchanged — the material does not reach the event on either path,
    which ``TestTheToolNameIsBounded`` asserts directly rather than argues, with
    the same shape under the bound as its control so the marker leg is visibly
    still live.

    **The doors legitimately diverge on this bound.** Every other redaction in
    this function is asserted identical at both doors
    (``TestToolNameRedactionBoundary``), because ``side_by_side.py`` compares
    their events field for field. This bound is not, because the two names have
    different provenance: this door reads ``params.name`` straight off the wire,
    unvalidated, so an agent picks its length; the hook door is handed a name
    Claude Code already resolved to a registered tool, so there is no 8 MiB name
    to write. The hook's ``_loggable_tool`` is still unbounded, and if a name
    ever can reach it from outside that registry it wants this same guard —
    recorded here rather than changed, because no name of that size can reach
    that door today. It is not the only divergence: :func:`_loggable_arguments`
    says why the ARGUMENTS field differs between the doors too, and why that
    difference is older than this entry rather than introduced by it.
    """
    # See the docstring section above for why this precedes the scan.
    if len(name) > MAX_LOGGED_STRING:
        return _truncated(name)
    segments = name.split("_")
    candidates = ["_".join(segments[i:]) for i in range(len(segments))]
    if contains_sensitive(candidates):
        return TOOL_NAME_REDACTION_MARKER
    # B-116. The arguments path runs `contains_sensitive` AND
    # `contains_hidden_context`; this path ran only the first, so declared
    # material arriving one field over was written into the decision log in
    # full. Second, so a name carrying both is attributed to the credential —
    # the same order, and for the same reason, as `_loggable_arguments`.
    #
    # The WHOLE name is offered as well as the suffixes: a declared segment is
    # ordinary prose rather than a `\b`-anchored pattern, so the underscore
    # splitting that B-015 needed buys nothing here and would miss a name that
    # simply IS the declared sentence.
    if contains_hidden_context(hidden_segments, [name, *candidates]):
        return HIDDEN_CONTEXT_TOOL_NAME_REDACTION_MARKER
    return name


class UninspectableListing(ValueError):
    """A ``tools/list`` result this door cannot reduce to (name, digest) pairs."""


def listing_definitions(result: Any, hidden_segments: Any) -> tuple[ToolDefinition, ...]:
    """The advertised tools in one raw ``tools/list`` result, as name + digest.

    This is the wire-format half, and it lives at the enforcement point for the
    reason ``ToolCall`` is built here rather than in the engine: the engine is
    handed neutral envelopes and knows nothing about MCP. It is also what keeps
    "this door never reads a description" true of the CODE — the engine is given
    digests, so no description ever crosses into it.

    Fails closed on anything it cannot place, and the list is deliberately
    short-tempered:

    * a result that is not a mapping, or whose ``tools`` is not a list of
      mappings, or a tool with no non-empty string ``name``;
    * **two definitions under one name in one listing.** A pin answers "is THE
      definition of X the approved one", and a listing offering two of them has
      no such thing. Refusing is the only answer that does not pick one.
    * a definition :func:`~engine.listing.tool_definition_digest` cannot
      serialise (a ``NaN`` survives ``json.loads`` and no other parser).

    Every message that names a tool runs the name through :func:`_loggable_tool`
    first — B-015's rule, and the refusals here reach both the decision log and
    the agent. Found by asking what else had the shape of the fix one function
    over: the judged path's redaction was written first and this path's messages
    were not.

    An unarmed proxy never calls this: it forwards the listing without parsing
    it, exactly as it did before this door existed.
    """
    if not isinstance(result, dict):
        raise UninspectableListing(f"result is {type(result).__name__}, not an object")
    tools = result.get("tools")
    if not isinstance(tools, list):
        raise UninspectableListing(f"result.tools is {type(tools).__name__}, not a list")
    definitions: list[ToolDefinition] = []
    seen: set[str] = set()
    for index, definition in enumerate(tools):
        if not isinstance(definition, dict):
            raise UninspectableListing(f"result.tools[{index}] is not an object")
        name = definition.get("name")
        if not isinstance(name, str) or not name:
            raise UninspectableListing(f"result.tools[{index}] has no usable name")
        if name in seen:
            raise UninspectableListing(
                f"result.tools carries two definitions named "
                f"{_loggable_tool(name, hidden_segments)!r}"
            )
        seen.add(name)
        try:
            definitions.append(ToolDefinition(name=name, digest=tool_definition_digest(definition)))
        except UndigestibleDefinition as exc:
            raise UninspectableListing(
                f"result.tools[{index}] ({_loggable_tool(name, hidden_segments)!r}): {exc}"
            ) from exc
    return tuple(definitions)


async def observed_tool_pins(upstream: Client, hidden_segments: Any = ()) -> dict[str, str]:
    """What ``tool_listing.approved`` would have to say to approve ``upstream`` now.

    The operator on-ramp, and the reason it is a function rather than a flag: it
    makes the pins come from the SAME parse and the SAME digest the door itself
    uses, so an approval block can never be computed by a second serialisation of
    the same objects — which is the whole of B-067. The other on-ramp needs no
    code at all: every refusal this door emits names each offending tool and the
    digest the gateway computed for it, so arming a fresh server once and reading
    its refusal yields the same block.
    """
    return {
        definition.name: definition.digest
        for definition in listing_definitions(
            await upstream.session.send_request(t.ListToolsRequest(params=None), _RAW_DICT),
            hidden_segments,
        )
    }


class _ProxyState:
    """The run. One MCP client session with this proxy (D-022).

    ``run_id`` is generated here, beside the counters it identifies, because
    they are the same fact: the limits in ``policy.limits`` are counted over
    exactly this object's lifetime, so the identifier a detection groups by has
    to be born and die with it. A deployment that recycles its session (D-022)
    gets a new proxy process, a new ``_ProxyState``, and therefore a new
    ``run_id`` — which is what makes the recycle visible in telemetry instead of
    looking like one endless run whose caps mysteriously never trip.
    """

    def __init__(self) -> None:
        self.calls_attempted = 0
        self.signature_counts: dict[str, int] = {}
        self.started = time.monotonic()
        self.run_id = uuid.uuid4().hex
        # D-031: has this run consumed a result from a tool the policy calls an
        # untrusted source? Latched — a run does not become clean again,
        # because the agent's context does not forget what it read. It lives here
        # rather than in the engine for the same reason the counters do: it is a
        # fact about one MCP session, and the engine owns no state.
        self.tainted = False
        # D-039: name -> digest for every tool definition this run has
        # been HANDED. Only allowed listings land here — a refused listing never
        # reached the agent, so it never became part of what the agent was told
        # exists, and treating it as a baseline would make the next honest
        # listing look like the change. Same session scope as the counters and
        # the taint mark: a recycled session (D-022) is a new run with an empty
        # map, which is correct, since the new agent session was told nothing yet.
        self.listing_digests: dict[str, str] = {}


def build_proxy(
    upstream: Client,
    policy: Policy,
    *,
    agent_id: str = "default",
    on_decision: DecisionEventSink = _stderr_sink,
    name: str = "agent-chokepoint",
    server_name: str | None = None,
) -> Server:
    """Build the proxy server in front of an already-connected upstream client.

    The caller owns the upstream client's lifecycle (it must be entered before
    the proxy serves and stay open while it does).

    ``server_name`` (D-015, B-011) is the identity every call through this proxy
    is judged under — ``ToolCall.server``, which a rule's ``server:`` key binds
    to. It is a per-PROXY setting and not a per-call one because this process
    fronts exactly one upstream: there is nothing on the wire to read it from,
    and inventing one from the upstream command line would be a guess. Default
    ``None`` means "this proxy claims no server identity", and a rule carrying
    ``server:`` then does not match at all — deliberately, so the strict
    spelling is never weaker than the loose one. ``proxy/__main__.py`` exposes
    it as ``--server-name``.
    """
    state = _ProxyState()

    def _emit(event: dict[str, Any]) -> None:
        # `server` joined the envelope with D-023: D-015 made rules
        # scope to a server, and a detection that wants to tell two upstreams
        # apart needs the identity ON the event, not in the proxy's argv. It is
        # stamped here, once, because it is a per-proxy fact exactly like
        # `agent_id` — every event this process emits was judged under it.
        # `None` means this proxy claims no identity (no `--server-name`).
        #
        # CP-05: the line bound goes on LAST, here, and this is the only place
        # it can go. Every event this proxy writes passes through this function:
        # `/usr/bin/grep -n -e '_emit(' proxy/server.py` returns ten lines —
        # this definition, two mentions in prose, and SEVEN calls — and
        # `on_decision` appears on exactly three lines of this file: its own
        # parameter, this sentence, and the call below. So one wrapper covers
        # the `tools/call` events, both `tools/list` shapes and the
        # unparseable-frame observer, including any emit added later.
        # Bounding at each call site instead would be seven copies of a bound,
        # which is the drift D-036 Decision 1 is about.
        on_decision(
            _within_the_line_bound(
                {
                    "ts": datetime.now(timezone.utc).isoformat(),
                    "agent_id": agent_id,
                    # D-025: the run these counters belong to. Without it the
                    # `limit:` rule ids name a scope no consumer can group by,
                    # and every stateful detection has to approximate a run with
                    # (agent_id, time window) — where agent_id is unauthenticated
                    # config that defaults to "default".
                    "run_id": state.run_id,
                    "server": server_name,
                    **event,
                }
            )
        )

    async def _forward(request: t.Request[Any, Any]) -> dict[str, Any]:
        """Forward one request upstream and return the upstream's RAW result dict.

        Two deliberate choices, both measured against the SDK rather than assumed:

        * The request is a **typed request model** carrying the params object
          this proxy's handler was given. A generic ``types.Request`` coerces
          its params into the bare ``RequestParams`` base, whose
          ``extra="ignore"`` silently discards ``name`` and ``arguments`` — the
          upstream then receives a call with no tool name. Typed models keep the
          full params, nested nulls included.
        * The result type is ``TypeAdapter(dict)``, so the upstream's result
          comes back as the raw dict it sent. Parsing into a typed result model
          would drop any field this SDK version does not know
          (``extra="ignore"``), which is exactly the passthrough-fidelity
          hazard this choice avoids.

        ``ClientSession.send_request`` also re-stamps the hop keys in
        ``params._meta`` (protocol version, client info, client capabilities) for
        the proxy→upstream leg, so an agent cannot spoof its identity or
        negotiated version to the upstream through the proxy. Non-hop ``_meta``
        keys the agent set are forwarded unchanged.
        """
        return await upstream.session.send_request(request, _RAW_DICT)

    async def on_call_tool(ctx: Any, params: t.CallToolRequestParams) -> dict[str, Any]:
        # Computed once, up here: every branch below emits exactly one event and
        # every one of them writes this field.
        logged_tool = _loggable_tool(params.name, policy.hidden_context.all_segments)
        arguments = params.arguments  # None is legal on the wire; pass through unmassaged

        # B-043: the counters advance HERE, above every refusal below, because
        # every one of those refusals is a call the agent ATTEMPTED. They used to
        # sit under the two refusals, on the reasoning that input this door cannot
        # judge should be refused before any state changes — and that contradicted
        # both this module's own docstring ("attempts are counted before the
        # verdict and include blocked calls") and `engine/model.py:RunState`
        # ("blocked attempts must count"). Measured, one variable, both controls in
        # the same run: three `pep:unresolvable-path` refusals then a legitimate
        # `read_file` came back ALLOW and reached the tool, while three ordinary
        # `default:on_no_match` blocks then the identical call came back
        # `block / limit:max_tool_calls_per_run` with the tool untouched. So an
        # agent pushed its own per-run cap out by any number of calls it knew this
        # door would refuse, and `max_repeated_identical_calls` — whose stated job
        # is "loop / retry-after-block abuse" — never saw a retry loop on a path
        # the door could not resolve.
        #
        # The refusals below keep their own rule ids rather than being routed
        # through the limit check: the verdict is `block` either way, and
        # "I could not resolve this path" is the more specific and more useful
        # attribution than "you are over your cap". What changes is only that the
        # attempt is counted, so the next call the engine DOES judge sees it.
        #
        # The signature keeps using the ORIGINAL arguments — a repeat is a repeat
        # of what the agent sent, not of what canonicalization made of it.
        signature = _call_signature(params.name, arguments)
        run_state = RunState(
            calls_made=state.calls_attempted,
            elapsed_seconds=time.monotonic() - state.started,
            identical_calls=state.signature_counts.get(signature, 0),
            tainted=state.tainted,
        )
        state.calls_attempted += 1
        state.signature_counts[signature] = state.signature_counts.get(signature, 0) + 1

        # Multi-round-trip input is a SECOND agent-controlled channel into the
        # tool, and the engine judges `name` + `arguments` only. Forwarding it
        # would let an agent get a call approved on a benign `arguments` and
        # then hand the tool the real target in `inputResponses` — the policy
        # sees `{"path": "./README.md"}` and the tool receives `/etc/passwd`.
        # No approval channel is wired at all (`ask` fails closed, D-005),
        # so nothing legitimately needs this yet: refuse it rather than pass
        # through what cannot be inspected. Modelling MRTR properly — deciding
        # on the resolved input, tying `requestState` to an approved call — is
        # its own piece of work, not a default.
        if params.input_responses is not None or params.request_state is not None:
            _emit(
                {
                    "method": "tools/call",
                    "tool": logged_tool,
                    "arguments": _loggable_arguments(
                        params.arguments, policy.hidden_context.all_segments
                    ),
                    "verdict": "block",
                    "rule_id": "proxy:uninspectable-input-channel",
                    "owasp": "LLM01",
                    "reason": "tools/call carried multi-round-trip input the engine cannot inspect",
                    "decision_ms": 0.0,
                }
            )
            raise MCPError(
                code=UNINSPECTABLE_ERROR_CODE,
                message=(
                    "agent-chokepoint: refused — this call carries multi-round-trip input "
                    "(inputResponses/requestState) that the policy engine cannot inspect"
                ),
                data={"verdict": "block", "rule_id": "proxy:uninspectable-input-channel", "owasp": "LLM01"},
            )

        # D-011: resolve the path against THIS process's filesystem before the
        # engine is asked about it. The engine is pure and has none, so it
        # cannot know that `/workspace/.SSH/id_rsa` names the file the deny
        # list protects (B-007), or that `/workspace/public/keys` is a symlink
        # out of the sandbox (B-008). A proxy that fronts the upstream can.
        #
        # Placed after the run-state counters (B-043) and before the engine, for
        # the same reason the MRTR refusal above sits where it does: input this
        # door cannot judge is refused before the engine is asked about it. The
        # attempt is still counted — a call this door refuses is a call the agent
        # made.
        #
        # What deliberately does NOT happen: the upstream is not handed the
        # canonical path. `_forward` sends the agent's own `params` untouched.
        # A PreToolUse hook returns a verdict and cannot rewrite its tool's
        # input at all, so rewriting here would make the two doors behave
        # differently, and "one engine, two doors" would stop being literal.
        # The residual decide-then-open race that leaves is docs/LIMITATIONS.md
        # §15.
        try:
            judged_arguments = canonicalized_arguments(arguments)
        except UnresolvablePath as exc:
            _emit(
                {
                    "method": "tools/call",
                    "tool": logged_tool,
                    "arguments": _loggable_arguments(
                        arguments, policy.hidden_context.all_segments
                    ),
                    "verdict": "block",
                    "rule_id": RULE_UNRESOLVABLE_PATH,
                    "owasp": "LLM01",
                    "reason": f"path could not be resolved: {exc}",
                    "decision_ms": 0.0,
                }
            )
            raise MCPError(
                code=UNRESOLVABLE_PATH_ERROR_CODE,
                message=(
                    f"agent-chokepoint: refused — {RULE_UNRESOLVABLE_PATH}: {exc}"
                ),
                data={"verdict": "block", "rule_id": RULE_UNRESOLVABLE_PATH, "owasp": "LLM01"},
            ) from exc

        started = time.perf_counter()
        decision = decide(
            policy,
            ToolCall(
                tool=params.name,
                arguments=judged_arguments,
                agent_id=agent_id,
                run_state=run_state,
                server=server_name,
            ),
        )
        decision_ms = (time.perf_counter() - started) * 1000.0

        # The engine quotes the tool name inside its reason — `no rule matched
        # tool 'read_file_AKIA...'` (engine/decide.py:124 and :132) — so
        # redacting the `tool` field alone leaves the credential in the very
        # same event, one field over. Measured, not assumed: with only the field
        # redacted, the key was still in `str(event)`. Substituting the marker
        # for the name keeps the sentence readable instead of dropping the whole
        # explanation, and it is a no-op whenever the name was not redacted.
        #
        # The MCPError raised below keeps `decision.reason` UNredacted on
        # purpose: that message goes back to the agent that chose the tool name,
        # so it is not a disclosure, and an error that cannot say which call
        # failed is a worse tool than one that can. B-015 is about the decision
        # LOG, which is the artifact a third party reads.
        #
        # **CP-05: the substitution is not on its own a bound, and that was
        # measured rather than reasoned about.** The engine writes the name with
        # `{call.tool!r}`, so anything `repr` escapes makes the raw name stop
        # being a substring of its own reason and the `replace` below silently
        # does nothing. Measured on this tree, four names of the SAME length
        # (601) differing in one character: plain, the reason goes 649 -> 71
        # bytes; with an embedded newline 650 -> 650; with a backslash
        # 650 -> 650; with U+2028 654 -> 654. So `_truncated` is applied to the
        # RESULT, and the two together are what make the field bounded: the
        # substitution keeps the sentence readable in the case that matters to a
        # reader, and the bound holds when the substitution cannot land.
        #
        # It is a no-op on every ordinary event — `no rule matched tool
        # 'send_email'; policy default is block` is 58 bytes against a bound of
        # 256 — and `TestTheToolNameIsBounded`'s
        # `test_the_control_an_ordinary_name_and_reason_are_untouched` pins that
        # rather than assuming it.
        #
        # NOT applied to `_listing_reason`'s output, and the asymmetry is
        # deliberate: that sentence names one drifted tool and its two digests
        # per offending tool, which is the operator's actionable output and
        # legitimately runs past 256 bytes with a handful of tools. The names in
        # it are interpolated raw rather than through `!r`, so the substitution
        # there always lands and `_loggable_tool`'s own bound already covers the
        # per-name half. What is left there — a malicious upstream advertising
        # very many tools makes that sentence long by COUNT rather than by any
        # one name — is upstream-driven amplification rather than CP-05's
        # agent-driven one, and it is caught by the LINE bound rather than by a
        # second per-field cut here: `_within_the_line_bound` leaves the
        # sentence whole up to 16 KiB — measured at 183 bytes per offending
        # tool, roughly eighty-five of them — and summarises it past that. The
        # operator keeps the actionable output in every case a real upstream
        # produces.
        reason = decision.reason
        if logged_tool != params.name:
            reason = reason.replace(params.name, logged_tool)
        reason = _truncated(reason)

        _emit(
            {
                "method": "tools/call",
                "tool": logged_tool,
                # The judged arguments, not the raw ones: `rule_id` is an answer
                # about the canonical path, and an event pairing that verdict with a
                # different path would be a lie in the audit trail. The hook logs the
                # judged arguments too, which is what keeps the two doors' events
                # comparable (hooks/demo/side_by_side.py compares them field for field).
                "arguments": _loggable_arguments(
                    judged_arguments, policy.hidden_context.all_segments
                ),
                "verdict": str(decision.verdict),
                "rule_id": decision.rule_id,
                "owasp": decision.owasp,
                "reason": reason,
                "decision_ms": round(decision_ms, 3),
            }
        )

        if decision.verdict is Verdict.ALLOW:
            result = await _forward(t.CallToolRequest(params=params))
            # D-031. The run is marked tainted when a call to a tool the
            # policy calls an untrusted source has been forwarded and returned —
            # at that point the agent has consumed the result.
            #
            # **The result is never inspected.** Taint keys off the SOURCE, not
            # the content: this proxy does not read one byte of `result`, does not
            # copy it, and returns the upstream's raw dict exactly as `_forward`
            # produced it. That is deliberate twice over — the passthrough
            # fidelity property (`test_allowed_result_is_identical_to_unproxied`)
            # is load-bearing, and deciding whether content is malicious is
            # content filtering, which this project rules out of scope and could
            # not measure.
            #
            # After the await, not before: a forward that raises means the agent
            # consumed nothing, so a failed fetch does not taint the run.
            if params.name in policy.taint.sources:
                state.tainted = True
            return result
        if decision.verdict is Verdict.ASK:
            raise MCPError(
                code=ASK_FAIL_CLOSED_ERROR_CODE,
                message=(
                    f"agent-chokepoint: approval required by rule {decision.rule_id}; "
                    "no approval channel is wired — failing closed (D-005)"
                ),
                data={"verdict": str(decision.verdict), "rule_id": decision.rule_id, "owasp": decision.owasp},
            )
        raise MCPError(
            code=BLOCKED_ERROR_CODE,
            message=f"agent-chokepoint: blocked by rule {decision.rule_id} ({decision.owasp}): {decision.reason}",
            data={"verdict": str(decision.verdict), "rule_id": decision.rule_id, "owasp": decision.owasp},
        )

    def _listing_reason(reason: str, definitions: tuple[ToolDefinition, ...]) -> str:
        """``reason`` with any credential-bearing tool NAME redacted — B-015, at this door.

        The engine composes the sentence from the names it was handed, because a
        pure function has no logging policy; the substitution is the same one
        ``on_call_tool`` makes on ``decision.reason`` one screen up, widened from
        one name to the listing's. A tool name is upstream-controlled text and a
        malicious upstream is exactly the actor this door exists for, so writing
        one verbatim into the decision log is the hole B-015 closed on the call
        door — in a method that did not judge anything when B-015 was written.

        Longest name first: ``read_file`` is a substring of
        ``read_file_AKIA…``, and replacing the short one first would leave the
        credential's tail in the sentence.

        Unlike the call door, the redacted sentence is also what goes back to the
        AGENT in the ``MCPError``. There the unredacted message is not a
        disclosure because the agent chose the tool name; here the UPSTREAM chose
        it, and the listing carrying it is being refused, so the agent has not
        seen those names and must not learn them from the refusal.
        """
        for name in sorted((d.name for d in definitions), key=len, reverse=True):
            logged = _loggable_tool(name, policy.hidden_context.all_segments)
            if logged != name:
                reason = reason.replace(name, logged)
        return reason

    async def on_list_tools(ctx: Any, params: t.PaginatedRequestParams | None) -> dict[str, Any]:
        # The upstream is asked FIRST, and that is not the order `tools/call`
        # uses, for a reason worth stating rather than hiding: the thing being
        # judged here IS the upstream's answer. So this door does not stop the
        # upstream being asked — it stops the answer reaching the agent. A
        # malicious upstream still learns a listing was requested, and any side
        # effect it attaches to `tools/list` still happens. `docs/LIMITATIONS.md`
        # says so beside the rest of what this door does not reach.
        result = await _forward(t.ListToolsRequest(params=params))

        if policy.tool_listing is None:
            # Not armed: byte-for-byte the behaviour every policy written before
            # D-039 had, down to the event. A forwarding event means "not
            # judged"; a decision event with method tools/list means "judged".
            _emit({"method": "tools/list", "action": "forwarded"})
            return result

        try:
            definitions = listing_definitions(result, policy.hidden_context.all_segments)
        except UninspectableListing as exc:
            _emit(
                {
                    "method": "tools/list",
                    "tool": None,
                    "arguments": None,
                    "verdict": "block",
                    "rule_id": RULE_UNINSPECTABLE_LISTING,
                    "owasp": "LLM04",
                    "reason": f"tools/list carried a listing this door cannot inspect: {exc}",
                    "decision_ms": 0.0,
                }
            )
            raise MCPError(
                code=UNINSPECTABLE_ERROR_CODE,
                message=(
                    "agent-chokepoint: refused — this tools/list response cannot be "
                    f"reduced to approvable tool definitions: {exc}"
                ),
                data={"verdict": "block", "rule_id": RULE_UNINSPECTABLE_LISTING, "owasp": "LLM04"},
            ) from exc

        started = time.perf_counter()
        decision = decide_listing(
            policy, ToolListing(tools=definitions, seen=state.listing_digests)
        )
        decision_ms = (time.perf_counter() - started) * 1000.0

        _emit(
            {
                "method": "tools/list",
                # Null on purpose, allow and block alike: this decision is about
                # the LISTING, and picking one of several offenders to put in a
                # single-valued field would be a choice no consumer could read
                # back. Every offender is named in `reason`, in the order the
                # upstream advertised them.
                "tool": None,
                "arguments": None,
                "verdict": str(decision.verdict),
                "rule_id": decision.rule_id,
                "owasp": decision.owasp,
                "reason": _listing_reason(decision.reason, definitions),
                "decision_ms": round(decision_ms, 3),
            }
        )

        if decision.verdict is Verdict.ALLOW:
            # After the verdict, never before: what this run has been HANDED is
            # what it was allowed to receive.
            state.listing_digests.update({d.name: d.digest for d in definitions})
            return result
        raise MCPError(
            code=BLOCKED_ERROR_CODE,
            message=(
                f"agent-chokepoint: blocked by rule {decision.rule_id} ({decision.owasp}): "
                f"{_listing_reason(decision.reason, definitions)}"
            ),
            data={"verdict": str(decision.verdict), "rule_id": decision.rule_id, "owasp": decision.owasp},
        )

    def _refuse_unparseable_frame(exc: Exception) -> dict[str, Any] | None:
        """One decision event for a frame the transport could not parse (B-112).

        Returns the JSON-RPC error reply the agent should get, or ``None`` when
        the request id could not be recovered — in which case the event is still
        written, because the audit record is the half that matters.

        **This does not judge the frame and must never start.** The transport's
        own parser refused it; re-reading it with a more permissive one and then
        deciding on the result would mean this door forming a verdict from a
        different reading of the bytes than the one the session runs on, which
        is B-067's shape at the front door. What is recovered is the two
        envelope scalars needed to answer and to attribute — nothing from
        ``params`` — and both are read by :data:`_LEADING_SCALARS` from the
        frame's leading scalar members only, so a `"id"` or `"method"` planted
        inside a nested object cannot be picked up. Unrecoverable degrades to
        "no reply", never to a guess.
        """
        raw = ""
        errors = getattr(exc, "errors", None)
        if callable(errors):
            try:
                first = (errors() or [{}])[0]
            except Exception:  # noqa: BLE001 — a foreign exception type; treat as no detail
                first = {}
            candidate = first.get("input") if isinstance(first, dict) else None
            raw = candidate if isinstance(candidate, str) else ""

        request_id = _leading_scalar(raw, "id")
        method = _leading_scalar(raw, "method")
        # The schema's `method` is an enum of three (1.6.0), so a frame whose
        # method is not recoverable — or is not one this door serves — is
        # recorded under `tools/call` with the reason saying exactly that,
        # rather than adding a fourth value to a published artifact for a branch
        # a conforming client never takes. Considered and declined: bumping the
        # schema. It would change what every consumer's `method IN (…)` filter
        # means, including the committed dashboard's, to describe the case where
        # a client wrote `params` before `method`.
        recovered = method in ("tools/call", "tools/list")
        _emit(
            {
                "method": method if recovered else "tools/call",
                "tool": None,
                "arguments": None,
                "verdict": "block",
                "rule_id": "proxy:uninspectable-input-channel",
                "owasp": "LLM01",
                "reason": (
                    "a frame arrived that the transport could not parse, so the engine was "
                    "never asked about it: " + _one_line(str(exc))
                    + ("" if recovered else
                       " — the JSON-RPC method was not recoverable from the frame's envelope, "
                       "so this event is filed under tools/call")
                    + ("" if request_id is not None else
                       " — the request id was not recoverable either, so no reply was sent")
                ),
                "decision_ms": 0.0,
            }
        )
        if request_id is None:
            return None
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {
                "code": UNINSPECTABLE_ERROR_CODE,
                "message": (
                    "agent-chokepoint: refused — this frame could not be parsed by the "
                    "transport, so the policy engine could not be asked about it"
                ),
                "data": {
                    "verdict": "block",
                    "rule_id": "proxy:uninspectable-input-channel",
                    "owasp": "LLM01",
                },
            },
        }

    server: Server = Server(
        name,
        version="0.0.1",
        instructions=(
            "MCP security proxy: every tools/call is judged allow/block/ask by a "
            "deny-by-default policy before it reaches the upstream server."
        ),
    )
    # Registered handlers, never Server.middleware: the middleware seam is marked
    # provisional in the 2.0.0 source (TODO(L54), lowlevel/server.py:436) and the
    # published docs say to observe with it, not build on it. Telemetry may use it
    # later; enforcement never does.
    #
    # `add_request_handler` and the `on_call_tool=`/`on_list_tools=` constructor
    # kwargs populate the same `_request_handlers` entry (server.py:458 vs :472),
    # so this is a typing choice, not a mechanism one: the registered-handler
    # signature returns `HandlerResult` (BaseModel | dict | None), which is what
    # raw passthrough actually returns; the constructor kwargs are typed to the
    # parsed result models.
    server.add_request_handler("tools/call", t.CallToolRequestParams, on_call_tool)
    server.add_request_handler("tools/list", t.PaginatedRequestParams, on_list_tools)

    # B-112. The transport hands the dispatcher an `Exception` for any frame it
    # could not parse, and the SDK drops it at DEBUG when nothing observes it
    # (the `_dispatch` method in `mcp/shared/jsonrpc_dispatcher.py`), so a `tools/call` nesting
    # 198 levels or deeper vanished: no reply, no event, nothing on stderr, and
    # the session serving the next ordinary call normally. Attached to the
    # server object rather than returned, because `build_proxy` returns a
    # `Server` at a hundred call sites and the stream this has to wrap does not
    # exist until `proxy/__main__.py` opens the transport. Pinned by
    # `proxy/tests/test_proxy.py::TestUninspectableFrames::test_the_attribute_the_entrypoint_reaches_for_is_here`
    # so a refactor that drops the attribute is a red test and not a silent
    # return to dropping frames.
    server.chokepoint_refuse_unparseable_frame = _refuse_unparseable_frame  # type: ignore[attr-defined]
    return server
