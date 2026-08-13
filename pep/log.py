"""Shared decision-log helpers for both enforcement points.

``pep.canonicalize`` stays filesystem-only and is what ``import pep`` loads.
This module is imported by name (``from pep.log import ...``) because it uses
the engine's scanners — the same ``contains_sensitive`` /
``contains_hidden_context`` the PDP uses — so a credential the engine saw
cannot reach the audit trail. It does not call ``decide()``, import ``proxy``
or ``hooks``, or perform I/O.

Logging only. ``decide()`` still receives the full arguments and the real tool
name; redacting at the source would change which rule matches.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping

from engine import contains_hidden_context, contains_sensitive
from engine.predicates import _MAX_SCAN_DEPTH

MAX_LOGGED_STRING = 256

REDACTION_MARKER = "[REDACTED: sensitive content detected in arguments]"
HIDDEN_CONTEXT_REDACTION_MARKER = "[REDACTED: declared hidden context detected in arguments]"
TOOL_NAME_REDACTION_MARKER = "[REDACTED: sensitive content detected in tool name]"
HIDDEN_CONTEXT_TOOL_NAME_REDACTION_MARKER = (
    "[REDACTED: declared hidden context detected in tool name]"
)
DEPTH_BOUND_MARKER = f"<not inspected: nesting past the {_MAX_SCAN_DEPTH}-level scan bound>"


def truncated(value: Any) -> Any:
    """Replace every string longer than :data:`MAX_LOGGED_STRING` with its length.

    Iterative and bounded at the engine's scan depth (B-111): a recursive walk
    at depth 1000 still dies under ``main()`` because CPython's recursion limit
    is 1000. Keys are left alone. A container at or past the bound becomes
    :data:`DEPTH_BOUND_MARKER`, so the log cannot carry a string the scan
    could not see.
    """
    root: list[Any] = [None]
    stack: list[tuple[Any, int, Any, Any]] = [(value, 0, root, 0)]
    while stack:
        node, depth, target, key = stack.pop()
        if isinstance(node, str):
            target[key] = (
                f"<str len={len(node)} truncated>" if len(node) > MAX_LOGGED_STRING else node
            )
        elif isinstance(node, Mapping):
            if depth >= _MAX_SCAN_DEPTH:
                target[key] = DEPTH_BOUND_MARKER
                continue
            built: dict[Any, Any] = {k: None for k in node}
            target[key] = built
            for k, item in node.items():
                stack.append((item, depth + 1, built, k))
        elif isinstance(node, (list, tuple)):
            if depth >= _MAX_SCAN_DEPTH:
                target[key] = DEPTH_BOUND_MARKER
                continue
            items: list[Any] = [None] * len(node)
            target[key] = items
            for index, item in enumerate(node):
                stack.append((item, depth + 1, items, index))
        else:
            target[key] = node
    return root[0]


def loggable_arguments(arguments: Any, hidden_segments: Any, *, truncate: bool) -> Any:
    """What the decision event may say about arguments.

    Order is load-bearing: scan the FULL value, then optionally truncate.
    Truncating first would let a secret sitting past the cutoff land in the log.

    ``truncate=True`` is the hook (a Claude Code Write carries a whole file).
    ``truncate=False`` is the proxy (the line bound in ``proxy.server`` is the
    volume cap; a per-string cut there broke ordinary events — CP-05).
    """
    if contains_sensitive(arguments):
        return REDACTION_MARKER
    if contains_hidden_context(hidden_segments, arguments):
        return HIDDEN_CONTEXT_REDACTION_MARKER
    return truncated(arguments) if truncate else arguments


def loggable_tool(name: str, hidden_segments: Any, *, max_len: int | None = None) -> str:
    r"""Never write detected material into the ``tool`` field.

    Matchers in ``ARG_MATCHERS`` are ``\b``-anchored and ``_`` is a word
    character, so ``contains_sensitive(name)`` misses ``read_file_AKIA…``.
    Every underscore-delimited suffix is offered, whole name first.

    ``max_len`` is the proxy's cost cap on an agent-chosen MCP name (quadratic
    suffix build). The hook leaves it ``None``: Claude Code only hands names it
    already resolved. Residual shapes (credential welded with no separator) are
    ``docs/LIMITATIONS.md`` §17, pinned by
    ``proxy/tests/test_proxy.py::TestToolNameRedactionBoundary``.
    """
    if max_len is not None and len(name) > max_len:
        return truncated(name)
    segments = name.split("_")
    candidates = ["_".join(segments[i:]) for i in range(len(segments))]
    if contains_sensitive(candidates):
        return TOOL_NAME_REDACTION_MARKER
    if contains_hidden_context(hidden_segments, [name, *candidates]):
        return HIDDEN_CONTEXT_TOOL_NAME_REDACTION_MARKER
    return name


def loggable_reason(
    reason: str, name: str, hidden_segments: Any, *, max_len: int | None = None
) -> str:
    """``reason`` with a redactable tool ``name`` replaced by the marker.

    Redacting ``tool`` alone is useless: engine reasons quote the name.
    ``name`` is the spelling that actually appears in ``reason`` (translated
    vs arriving), so each caller passes the one its string contains.
    """
    logged = loggable_tool(name, hidden_segments, max_len=max_len)
    return reason if logged == name else reason.replace(name, logged)


def decision_event(
    *,
    agent_id: str,
    run_id: str | None,
    server: str | None,
    method: str,
    tool: str | None,
    arguments: Any,
    verdict: str,
    rule_id: str,
    owasp: str | None,
    reason: str,
    decision_ms: float,
) -> dict[str, Any]:
    """The published 12-key decision event both doors emit."""
    return {
        "ts": datetime.now(timezone.utc).isoformat(),
        "agent_id": agent_id,
        "run_id": run_id,
        "server": server,
        "method": method,
        "tool": tool,
        "arguments": arguments,
        "verdict": verdict,
        "rule_id": rule_id,
        "owasp": owasp,
        "reason": reason,
        "decision_ms": decision_ms,
    }
