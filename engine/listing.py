"""decide_listing() — the pure decision function for ``tools/list`` (D-039).

Four of Invariant Labs' eight published MCP attack classes arrive in a tool
DESCRIPTION rather than in a tool call — tool poisoning, the rug pull, tool
shadowing and the sleeper — and OWASP LLM04:2026's one leg that reaches this
door is the same surface: the integrity of the tool definitions the agent is
handed. Until this module existed, ``proxy/server.py``'s ``on_list_tools``
emitted one telemetry line and returned the upstream's response untouched.

**What is decidable here, and what is not.** Integrity and provenance are
decidable: *is this the definition the operator approved*, and *has this run
already been handed a different definition of this same tool*. Both are answered
by comparing digests, and neither reads a word of any description. Whether a
description is malicious is NOT decidable here — that is content filtering,
which ``README.md`` rules out of scope and which this project could not measure
anyway. Nothing in this module inspects the text of anything: it is handed
:class:`~engine.model.ToolDefinition` pairs of name and digest, so a description
never enters the engine at all.

Semantics, in evaluation order:

1. **Mid-run change** — a tool whose digest differs from one this run was
   already served (``listing.seen``). ``listing:definition-changed-mid-run``.
2. **Approval** — every tool must appear in ``policy.tool_listing.approved``
   with a matching digest. A tool with no entry is
   ``listing:unpinned-tool``; a tool with an entry that differs is
   ``listing:definition-drift``.
3. Otherwise ``allow`` with ``listing:approved``.

The order is a PRECEDENCE, not just a sequence, and it is by severity rather
than by listing order. A listing can violate more than one clause at once, and
the id is the only place the event says what this gateway saw — the same
reasoning B-046 settled for the three ``taint:`` ids, applied here: report the
most specific true fact, and name every offender in the ``reason`` so nothing
the weaker clauses found is lost. Mid-run change is the most specific because no
benign server upgrade can produce it: a run is one MCP client session (D-022),
and a server that answered one session's two ``tools/list`` calls differently
did so under one connection.

**Deny by default, at the listing level.** One offending definition refuses the
WHOLE listing rather than dropping the tool and forwarding the rest. Dropping is
the gateway lying to the model about what exists, and a filtered listing is
indistinguishable to the agent from a server that never had the tool — see
D-039 for the alternative that was rejected and why (agentgateway does the
filtering version, for a different question).
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping

from .model import (
    LISTING_APPROVED_RULE_ID,
    LISTING_DRIFT_RULE_ID,
    LISTING_MIDRUN_RULE_ID,
    LISTING_OWASP,
    LISTING_UNPINNED_RULE_ID,
    Decision,
    Policy,
    ToolListing,
    Verdict,
)

#: The one digest spelling this engine produces and the loader accepts.
DIGEST_PREFIX = "sha256:"


class UndigestibleDefinition(ValueError):
    """A tool definition that cannot be reduced to a digest at all.

    Raised rather than answered with a placeholder digest: a definition this
    function cannot serialise is one whose identity is unknown, and an unknown
    identity must not be comparable to anything. The enforcement point turns it
    into a refusal (``proxy:uninspectable-listing``), which is the same posture
    ``pep:unresolvable-path`` takes on a path that will not resolve.
    """


def tool_definition_digest(definition: Mapping[str, Any]) -> str:
    """``sha256:<64 hex>`` over one advertised tool definition, WHOLE.

    The digest covers the definition exactly as the upstream sent it, every
    field of it, not only ``description``. Three reasons, in order of how much
    they cost to learn the hard way:

    * A shadowing or poisoning instruction fits in an input-schema property
      description as comfortably as in the tool's own; pinning ``description``
      alone would pin the door shut and leave the window open.
    * Fields this SDK version does not model still arrive in the raw dict the
      proxy forwards (measured: ``annotations``, ``outputSchema``, ``title`` all
      round-trip), and a pin that ignored unknown fields would be silent about
      exactly the fields a future protocol version adds.
    * "The definition changed" is then one question with one answer, rather than
      a list of fields somebody has to keep current.

    **Canonicalisation, and why each choice is not arbitrary.** ``sort_keys``
    makes the digest independent of key order, which JSON does not fix and which
    is the whole of B-067 — a call that had landed was reported as not landed
    because two independent serialisations of one object ordered a nested
    object's keys differently. ``separators`` removes whitespace, which no JSON
    parser preserves. ``ensure_ascii=True`` makes the payload pure ASCII, so the
    bytes hashed are unambiguous on every platform and a zero-width character or
    a homoglyph inside a description lands as a distinct ``\\uNNNN`` escape and
    therefore a distinct digest — which is integrity working, not a bonus
    feature. ``allow_nan=False`` refuses the one value ``json.loads`` accepts
    that ``json.dumps`` cannot round-trip through any other parser.

    Pure: no I/O, no clock. Same definition in, same digest out, in any process.
    """
    try:
        payload = json.dumps(
            definition, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
        )
    except (TypeError, ValueError) as exc:
        raise UndigestibleDefinition(f"tool definition cannot be serialised: {exc}") from exc
    return DIGEST_PREFIX + hashlib.sha256(payload.encode("ascii")).hexdigest()


def _offenders(listing: ToolListing, approved: Mapping[str, str]) -> tuple[list[str], list[str], list[str]]:
    """(changed mid-run, drifted from approved, never approved) — names, in listing order."""
    changed, drifted, unpinned = [], [], []
    for tool in listing.tools:
        was = listing.seen.get(tool.name)
        if was is not None and was != tool.digest:
            changed.append(tool.name)
        entry = approved.get(tool.name)
        if entry is None:
            unpinned.append(tool.name)
        elif entry != tool.digest:
            drifted.append(tool.name)
    return changed, drifted, unpinned


def _digest_of(listing: ToolListing, name: str) -> str:
    return next(tool.digest for tool in listing.tools if tool.name == name)


def _also_offending(
    listing: ToolListing,
    approved: Mapping[str, str],
    drifted: list[str],
    unpinned: list[str],
) -> str:
    """The clause naming offenders the mid-run branch would otherwise drop (B-114).

    Empty when there are none, so an ordinary mid-run refusal reads exactly as
    it always did and only the two-class case grows a sentence. A tool can be
    both changed and drifted — `seen` and `approved` are independent — so the
    same name may appear in both halves of the reason, and that is correct
    rather than a duplicate: they are two different facts about it.
    """
    others = listing_order(listing, drifted + unpinned)
    if not others:
        return ""
    detail = ", ".join(
        f"{name} is {_digest_of(listing, name)} and this policy approves "
        + (f"{approved[name]}" if name in approved else "no definition of it")
        for name in others
    )
    return (
        f"; also refused in this listing, {len(others)} of {len(listing.tools)} "
        f"tool definitions are not the ones this policy approved — {detail}"
    )


def decide_listing(policy: Policy, listing: ToolListing) -> Decision:
    """Judge one ``tools/list`` response against one policy. Pure function.

    Raises :class:`ValueError` when ``policy.tool_listing`` is ``None`` — that
    policy has not armed this door, and answering anyway would mean inventing a
    verdict for a question the operator never asked. Loud rather than open is the
    same posture ``decide()`` takes on an unknown predicate and on a
    non-:class:`~engine.model.Verdict` rule decision (B-013).
    """
    if policy.tool_listing is None:
        raise ValueError(
            "decide_listing() called on a policy with no `tool_listing:` section — "
            "that door is not armed, and the enforcement point must forward the "
            "listing rather than ask for a verdict"
        )
    approved = policy.tool_listing.approved
    changed, drifted, unpinned = _offenders(listing, approved)

    if changed:
        detail = ", ".join(
            f"{name} was served {listing.seen[name]} earlier in this run and is now "
            f"{_digest_of(listing, name)}"
            for name in changed
        )
        # B-114. The id stays the most specific true fact — a mid-run change is
        # more specific than a tool nobody approved — but the reason names EVERY
        # offender, which is what `telemetry/event-schema.json` and this
        # module's own docstring both promise. This branch used to return here
        # with `changed` alone, so a tool that was drifted or unapproved in the
        # SAME listing was an offender the weaker clauses had found and the
        # event then lost. The listing is refused whole either way (D-039
        # Decision 3), so nothing about the verdict moves; what was missing is
        # the record of why, which is the operator's on-ramp to arming the
        # server correctly in one pass instead of two.
        also = _also_offending(listing, approved, drifted, unpinned)
        return Decision(
            verdict=Verdict.BLOCK,
            rule_id=LISTING_MIDRUN_RULE_ID,
            owasp=LISTING_OWASP,
            reason=(
                f"tools/list refused: this run has already been served a different definition "
                f"of {len(changed)} of its {len(listing.tools)} tools — {detail}" + also
            ),
        )

    if drifted or unpinned:
        detail = ", ".join(
            f"{name} is {_digest_of(listing, name)} and this policy approves "
            + (f"{approved[name]}" if name in approved else "no definition of it")
            for name in listing_order(listing, drifted + unpinned)
        )
        return Decision(
            verdict=Verdict.BLOCK,
            # A drifted APPROVED tool is the more specific fact than a tool
            # nobody approved, so it supplies the id when a listing carries both.
            rule_id=LISTING_DRIFT_RULE_ID if drifted else LISTING_UNPINNED_RULE_ID,
            owasp=LISTING_OWASP,
            reason=(
                f"tools/list refused: {len(drifted) + len(unpinned)} of {len(listing.tools)} "
                f"tool definitions are not the ones this policy approved — {detail}"
            ),
        )

    return Decision(
        verdict=Verdict.ALLOW,
        rule_id=LISTING_APPROVED_RULE_ID,
        owasp=LISTING_OWASP,
        reason=(
            f"tools/list allowed: all {len(listing.tools)} tool definitions match the "
            "digests this policy approves"
        ),
    )


def listing_order(listing: ToolListing, names: list[str]) -> list[str]:
    """``names``, in the order the upstream advertised them.

    The reason line is the operator's on-ramp — a fresh arming is armed by
    reading the digests out of the refusal it produces — so its order has to be
    the listing's own, not the order two separate loops happened to append in.
    """
    wanted = set(names)
    return [tool.name for tool in listing.tools if tool.name in wanted]
