"""The decision log cannot be forged by a tool argument — LLM10:2026 mitigation 8.

That mitigation reads, verbatim: *"Sanitize control characters from model output
before writing to terminals or logs."* It lands on this project directly. The
proxy writes one decision event per judged call to ``--log-file``, tool arguments
go into those events, and the arguments are chosen by whatever is driving the
agent. A carriage return, an ANSI escape or a newline in one of them would let a
caller write its own line into the audit trail of the control that refused it,
which is an evidence-integrity defect in a security gateway rather than a
cosmetic one.

**It does not reproduce, and this file is what says so with both controls.**
``proxy/__main__.py``'s file sink is ``json.dumps(event, default=str)``, whose
default ``ensure_ascii=True`` escapes every C0 and C1 control AND every non-ASCII
code point, so the two line terminators outside ``[\\x00-\\x1F\\x7F-\\x9F]`` —
``U+2028`` and ``U+2029`` — land as ``\\u2028`` escapes rather than as line
breaks. One event stays one line, whatever the argument carries.

A property that holds is worth exactly as much as the control beside it, so this
file has two, and they remove different halves of the same call:

* ``ensure_ascii=False`` — ONE keyword, the same real events — and
  ``str.splitlines()`` reads more lines out of the file than there are events,
  because ``U+2028`` is a line terminator to Python's own line reader (and to a
  good many log shippers). That is the non-ASCII half.
* a plain-text sink that interpolates the argument the way a logfmt-style logger
  would, over the same events, and the payload's own forged object arrives as a
  separate, parseable line. That is the C0 half, which ``json.dumps`` gives no
  keyword to turn off.

What this file does NOT claim. It measures the proxy's ``--log-file`` sink, which
is what an operator reads. ``proxy/server.py:_stderr_sink`` and
``hooks/chokepoint_hook.py:_write_event`` write the same call with the same
defaults, and neither is exercised here; the same encoder is the reason, not a
measurement of those two doors. Nor is this a claim about the whole event: what
is asserted is that the FILE is one JSON object per event and that the payload
really was carried into one of them.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import anyio

from mcp import Client, MCPError, stdio_client

from proxy.demo import run_demo

#: A whole decision event, well formed, that the payload tries to smuggle onto a
#: line of its own. Its ``agent_id`` is what a reader of the file greps for: if
#: this object is ever parseable as its own line, an argument has written a
#: verdict into the audit trail.
FORGED_EVENT = json.dumps(
    {
        "ts": "2020-01-01T00:00:00+00:00",
        "agent_id": "forged-by-an-argument",
        "run_id": "forged",
        "server": None,
        "method": "tools/call",
        "tool": "run_command",
        "arguments": {"command": "pwd"},
        "verdict": "allow",
        "rule_id": "shell-readonly",
        "owasp": "LLM01",
        "reason": "this line was written by a tool argument",
        "decision_ms": 0.1,
    }
)

#: name -> the argument value. Every one is a `run_command` the shipped policy
#: refuses, so the shipped configuration is what is measured; what varies is the
#: character used to try to end the line early.
FORGERY_VECTORS = {
    "newline": "pwd" + chr(0x0A) + FORGED_EVENT,
    "carriage return": "pwd" + chr(0x0D) + FORGED_EVENT,
    "ansi erase line": "pwd" + chr(0x1B) + "[2K" + chr(0x1B) + "[1A" + FORGED_EVENT,
    "U+0085 next line": "pwd" + chr(0x85) + FORGED_EVENT,
    "U+2028 line separator": "pwd" + chr(0x2028) + FORGED_EVENT,
    "U+2029 paragraph separator": "pwd" + chr(0x2029) + FORGED_EVENT,
}

#: Everything `str.splitlines()` breaks on, plus DELETE and the rest of C0/C1 —
#: the bytes that must not reach the file raw. LF is excluded: it is the format's
#: own record separator.
FORBIDDEN_RAW = frozenset(
    chr(code) for code in [*range(0x00, 0x20), 0x7F, *range(0x80, 0xA0), 0x2028, 0x2029]
) - {chr(0x0A)}


def drive_the_proxy_and_read_its_log(tmp: Path) -> tuple[list[str], str]:
    """Every vector above through the real ``python -m proxy --log-file``.

    Three real processes over real stdio, exactly as ``run_demo`` runs them:
    reusing its parameter builder rather than writing a second one keeps this
    test measuring the command an operator actually runs.

    Returns (the errors the agent saw, the raw text of the log file).
    """
    sandbox = tmp / "sandbox"
    sandbox.mkdir()
    log_file = tmp / "decisions.jsonl"
    errors: list[str] = []

    async def drive() -> None:
        params = run_demo.proxied_params(sandbox, log_file)
        async with Client(stdio_client(params)) as agent:
            for payload in FORGERY_VECTORS.values():
                try:
                    await agent.call_tool("run_command", {"command": payload})
                except MCPError as exc:
                    errors.append(exc.error.data.get("rule_id", ""))

    anyio.run(drive)
    return errors, log_file.read_text(encoding="utf-8")


class TestTheDecisionLogCannotBeForgedByAnArgument:
    """The property, measured on the file the proxy writes.

    Four assertions, and the last one is what stops the first three passing
    vacuously: the payload has to have REACHED the log. A proxy that dropped the
    arguments entirely would satisfy "one line per event" perfectly.
    """

    def test_control_characters_in_an_argument_cannot_forge_a_log_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            errors, raw = drive_the_proxy_and_read_its_log(Path(tmp))

        assert len(errors) == len(FORGERY_VECTORS), (
            f"every vector must have been judged; the agent saw {errors}")

        lines = [line for line in raw.splitlines() if line.strip()]
        assert len(lines) == len(FORGERY_VECTORS), (
            f"{len(FORGERY_VECTORS)} calls produced {len(lines)} lines: an argument split a record")

        events = []
        for line in lines:
            events.append(json.loads(line))  # a line that does not parse fails here, by name

        raw_controls = sorted({hex(ord(ch)) for ch in raw if ch in FORBIDDEN_RAW})
        assert not raw_controls, f"raw control characters reached the log file: {raw_controls}"

        assert not [e for e in events if e.get("agent_id") == "forged-by-an-argument"], (
            "an argument wrote its own decision event into the log")

        # ...and the payload really was carried. Read back through the parser,
        # every vector is present verbatim, control characters included — so the
        # three assertions above are about the ENCODING and not about a proxy
        # that logged nothing.
        logged = {json.dumps(e.get("arguments")) for e in events}
        missing = [name for name, payload in FORGERY_VECTORS.items()
                   if json.dumps({"command": payload}) not in logged]
        assert not missing, f"these payloads never reached the log at all: {missing}"


class TestTheJsonEncodingIsWhatStopsIt:
    """The two guard-off controls, over the SAME real events.

    Neither is a rewrite of the proxy: both take the events the proxy actually
    wrote and encode them a second time, one thing changed. Without them,
    "nothing bad happened" reads identically to "the payload was broken".
    """

    @staticmethod
    def real_events() -> list[dict]:
        with tempfile.TemporaryDirectory() as tmp:
            _, raw = drive_the_proxy_and_read_its_log(Path(tmp))
        events = [json.loads(line) for line in raw.splitlines() if line.strip()]
        assert events, "no events to re-encode; this control would prove nothing"
        return events

    @staticmethod
    def readable_records(text: str) -> tuple[int, int]:
        """(lines, lines a per-line JSON reader can actually parse)."""
        lines = [line for line in text.splitlines() if line.strip()]
        readable = 0
        for line in lines:
            try:
                json.loads(line)
            except json.JSONDecodeError:
                continue
            readable += 1
        return len(lines), readable

    def test_the_same_events_without_ascii_escaping_split_the_log(self):
        events = self.real_events()
        shipped = "".join(json.dumps(e, default=str) + "\n" for e in events)
        loosened = "".join(json.dumps(e, default=str, ensure_ascii=False) + "\n" for e in events)

        shipped_lines, shipped_readable = self.readable_records(shipped)
        loosened_lines, loosened_readable = self.readable_records(loosened)

        assert (shipped_lines, shipped_readable) == (len(events), len(events)), (
            "the shipped spelling must be one readable line per event, or the control below "
            "is not a single-variable comparison")
        assert loosened_lines > len(events), (
            f"with ensure_ascii=False the U+2028 and U+2029 vectors must break {len(events)} "
            f"events into more than {len(events)} lines; got {loosened_lines}")
        # Landed, and this is the damage rather than a difference in shape: a
        # reader that parses one JSON object per line now recovers FEWER records
        # than were written, because an argument ended a record early.
        assert loosened_readable < len(events), (
            f"every line still parsed ({loosened_readable} of {len(events)}), so nothing "
            "observable was lost and this control shows nothing")

    def test_the_same_events_through_a_plain_text_sink_carry_the_forged_event(self):
        """The C0 half, which ``json.dumps`` has no keyword for.

        A logfmt-style sink is not a straw man: it is what a log line looks like
        in most gateways, and it is one formatting decision away from this one.
        Over the same events, the payload's own object arrives as a separate line
        that parses as a decision event, with the verdict the attacker chose.
        """
        events = self.real_events()
        plain = "".join(
            f"{e['ts']} {e['verdict']} {e['rule_id']} {json.loads(json.dumps(e))['arguments']['command']}\n"
            for e in events
        )
        forged = []
        for line in plain.splitlines():
            try:
                parsed = json.loads(line)
            except json.JSONDecodeError:
                continue
            if parsed.get("agent_id") == "forged-by-an-argument":
                forged.append(parsed)

        assert forged, "the plain-text sink must carry the forged event; otherwise the payload is broken"
        assert forged[0]["verdict"] == "allow", forged[0]
        assert len(plain.splitlines()) > len(events), (
            f"{len(events)} events produced {len(plain.splitlines())} plain-text lines")
