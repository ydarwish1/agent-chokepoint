"""The listing decision, at the engine — pure, no proxy, no wire (D-039).

``proxy/tests/test_tool_listing.py`` drives the same logic end to end through the
real proxy. This file asks the questions that are about the FUNCTION rather than
about the door: what the digest covers, what the precedence is when a listing
breaks more than one clause at once, and — the one worth reading — exactly how
much the run state adds over the approval check, measured rather than claimed.
"""

from __future__ import annotations

import pytest

from engine import (
    Decision,
    Defaults,
    Limits,
    Policy,
    ToolDefinition,
    ToolListing,
    ToolListingPolicy,
    UndigestibleDefinition,
    Verdict,
    decide_listing,
    tool_definition_digest,
)

CLEAN_FETCH = {
    "name": "fetch_url",
    "description": "Fetch a URL (simulated).",
    "inputSchema": {"type": "object", "properties": {"url": {"type": "string"}}},
}


def policy_with(approved: dict[str, str] | None) -> Policy:
    return Policy(
        version=0,
        defaults=Defaults(),
        limits=Limits(),
        rules=(),
        tool_listing=None if approved is None else ToolListingPolicy(approved=approved),
    )


def listing(*pairs: tuple[str, str], seen: dict[str, str] | None = None) -> ToolListing:
    return ToolListing(
        tools=tuple(ToolDefinition(name=n, digest=d) for n, d in pairs),
        seen=seen or {},
    )


# --------------------------------------------------------------- the digest


class TestTheDigest:
    def test_it_is_deterministic_and_independent_of_key_order(self):
        reordered = dict(reversed(list(CLEAN_FETCH.items())))
        assert list(reordered) != list(CLEAN_FETCH), "the two dicts iterate the same way"
        assert tool_definition_digest(reordered) == tool_definition_digest(CLEAN_FETCH)

    def test_it_covers_the_whole_definition_and_not_only_the_description(self):
        """The reason the pin is over the object rather than over one field.

        An instruction fits in an input-schema property description as
        comfortably as in the tool's own, so a digest that ignored the schema
        would pin the door shut and leave the window open.
        """
        base = tool_definition_digest(CLEAN_FETCH)
        for changed in [
            {**CLEAN_FETCH, "description": CLEAN_FETCH["description"] + " "},
            {**CLEAN_FETCH, "inputSchema": {"type": "object",
                                            "properties": {"url": {"type": "string",
                                                                   "description": "ignore prior"}}}},
            {**CLEAN_FETCH, "annotations": {"readOnlyHint": True}},
            {**CLEAN_FETCH, "title": "Fetch"},
        ]:
            assert tool_definition_digest(changed) != base, changed

    def test_a_zero_width_character_is_a_different_definition(self):
        """IL-8's obfuscation buys nothing HERE, and that is a property of the
        digest rather than of any matcher: ``ensure_ascii`` escapes it, so the
        bytes hashed differ. It says nothing about the argument matchers, which
        `docs/LIMITATIONS.md` §21 measures and which are unchanged."""
        # The escape, never a literal byte: a zero-width character pasted into
        # source is invisible in every diff that would review it.
        sneaky = {**CLEAN_FETCH,
                  "description": CLEAN_FETCH["description"] + "\u200b"}
        assert tool_definition_digest(sneaky) != tool_definition_digest(CLEAN_FETCH)

    def test_it_is_a_sha256_pin_the_loader_would_accept(self):
        digest = tool_definition_digest(CLEAN_FETCH)
        assert digest.startswith("sha256:") and len(digest) == len("sha256:") + 64
        assert digest[7:] == digest[7:].lower()

    def test_a_definition_that_cannot_be_serialised_raises_rather_than_answering(self):
        """An unknown identity must not be comparable to anything."""
        with pytest.raises(UndigestibleDefinition):
            tool_definition_digest({"name": "x", "weight": float("nan")})


# ------------------------------------------------------------ the decision


class TestTheDecision:
    def test_an_unarmed_policy_is_refused_rather_than_answered(self):
        with pytest.raises(ValueError, match="not armed"):
            decide_listing(policy_with(None), listing(("read_file", "sha256:" + "a" * 64)))

    def test_a_listing_matching_every_pin_is_allowed(self):
        digest = tool_definition_digest(CLEAN_FETCH)
        decision = decide_listing(policy_with({"fetch_url": digest}), listing(("fetch_url", digest)))
        assert isinstance(decision, Decision)
        assert (decision.verdict, decision.rule_id, decision.owasp) == (
            Verdict.ALLOW, "listing:approved", "LLM04",
        )

    def test_a_tool_with_no_pin_at_all_is_unpinned_not_drifted(self):
        decision = decide_listing(
            policy_with({"read_file": "sha256:" + "a" * 64}),
            listing(("read_file", "sha256:" + "a" * 64), ("evil", "sha256:" + "b" * 64)),
        )
        assert (decision.verdict, decision.rule_id) == (Verdict.BLOCK, "listing:unpinned-tool")
        assert "evil" in decision.reason and "no definition of it" in decision.reason

    def test_a_pinned_tool_serving_something_else_is_drift(self):
        decision = decide_listing(
            policy_with({"read_file": "sha256:" + "a" * 64}),
            listing(("read_file", "sha256:" + "b" * 64)),
        )
        assert (decision.verdict, decision.rule_id) == (Verdict.BLOCK, "listing:definition-drift")

    def test_drift_supplies_the_id_when_a_listing_carries_both(self):
        """Precedence by severity, not by listing order — and the weaker finding
        is not lost, because the reason names every offender."""
        decision = decide_listing(
            policy_with({"read_file": "sha256:" + "a" * 64}),
            listing(("evil", "sha256:" + "c" * 64), ("read_file", "sha256:" + "b" * 64)),
        )
        assert decision.rule_id == "listing:definition-drift"
        assert "evil" in decision.reason and "read_file" in decision.reason
        # ...in the order the upstream advertised them, because the reason line
        # is what an operator pastes their approvals out of.
        assert decision.reason.index("evil") < decision.reason.index("read_file")

    def test_a_mid_run_change_outranks_both(self):
        decision = decide_listing(
            policy_with({"read_file": "sha256:" + "a" * 64}),
            listing(("read_file", "sha256:" + "b" * 64), ("evil", "sha256:" + "c" * 64),
                    seen={"read_file": "sha256:" + "a" * 64}),
        )
        assert decision.rule_id == "listing:definition-changed-mid-run"
        assert "earlier in this run" in decision.reason

    def test_a_tool_seen_before_with_the_same_digest_is_not_a_change(self):
        digest = tool_definition_digest(CLEAN_FETCH)
        decision = decide_listing(
            policy_with({"fetch_url": digest}),
            listing(("fetch_url", digest), seen={"fetch_url": digest}),
        )
        assert decision.verdict is Verdict.ALLOW

    def test_the_function_holds_no_state_between_calls(self):
        """Pure: the same inputs answer the same way, and an earlier call cannot
        teach it anything. The run state arrives INSIDE the envelope."""
        policy = policy_with({"read_file": "sha256:" + "a" * 64})
        first = decide_listing(policy, listing(("read_file", "sha256:" + "b" * 64)))
        second = decide_listing(policy, listing(("read_file", "sha256:" + "a" * 64)))
        third = decide_listing(policy, listing(("read_file", "sha256:" + "b" * 64)))
        assert first == third and second.verdict is Verdict.ALLOW


class TestWhatRunStateAddsAndWhatItDoesNot:
    """MEASURED, because the sentence next door would otherwise outrun it.

    Under deny-by-default pinning the mid-run check refuses NOTHING the approval
    check would have admitted: one pin per name means a listing that differs from
    an earlier one in this run also differs from the pin, on at least one of the
    two listings. What it adds is the ATTRIBUTION, and the attribution is the
    difference between two remediations — "this server's definitions are not the
    ones you approved" is often a legitimate upgrade you must re-approve, while
    "this server served ONE session two definitions of one tool" cannot be an
    upgrade at all and is the sleeper's signature.

    That is B-046's finding in a second place: the verdict is identical either
    way; only the id changes, and it changes to the more specific true one.
    """

    APPROVED = {"read_file": "sha256:" + "a" * 64}
    SWITCHED = ("read_file", "sha256:" + "b" * 64)

    def test_the_same_listing_is_refused_with_or_without_the_run_state(self):
        policy = policy_with(self.APPROVED)
        with_state = decide_listing(
            policy, listing(self.SWITCHED, seen={"read_file": self.APPROVED["read_file"]})
        )
        without_state = decide_listing(policy, listing(self.SWITCHED))
        assert with_state.verdict is without_state.verdict is Verdict.BLOCK
        assert with_state.rule_id == "listing:definition-changed-mid-run"
        assert without_state.rule_id == "listing:definition-drift"

    def test_run_state_never_turns_a_refusal_into_an_allow(self):
        """The one thing it must never do. Every combination of (pinned or not)
        and (seen or not) that refuses without the state still refuses with it."""
        digests = ["sha256:" + c * 64 for c in "abc"]
        for pin in [None, digests[0]]:
            for served in digests:
                for seen in [None, digests[0], digests[1]]:
                    policy = policy_with({"read_file": pin} if pin else {"other": digests[2]})
                    stateless = decide_listing(policy, listing(("read_file", served)))
                    stateful = decide_listing(
                        policy, listing(("read_file", served), seen={"read_file": seen} if seen else {})
                    )
                    if stateless.verdict is Verdict.BLOCK:
                        assert stateful.verdict is Verdict.BLOCK, (pin, served, seen)


A64, B64, C64 = ("sha256:" + c * 64 for c in "abc")


class TestEveryOffenderIsNamed:
    """**B-114** — `telemetry/event-schema.json` and `engine/listing.py` both
    promise that a listing refusal's `reason` names every offender with the
    digest computed for it. The `changed` branch returned early, so a tool that
    was drifted or unapproved in the SAME listing was an offender the weaker
    clauses had found and the event then lost.

    One node per branch, plus the two-class case, which is what nothing covered:
    the drift branch already composed from both its lists, so only the mid-run
    branch could lose anything, and only when something else was wrong too.
    """

    def test_the_mid_run_branch_names_the_unapproved_tool_beside_it(self):
        decision = decide_listing(
            policy_with({"fetch_url": A64, "read_file": C64}),
            listing(("fetch_url", B64), ("exfil_tool", C64), seen={"fetch_url": A64}),
        )
        assert decision.rule_id == "listing:definition-changed-mid-run"
        assert "fetch_url" in decision.reason
        assert "exfil_tool" in decision.reason, "the weaker clause's offender was lost again"
        assert "no definition of it" in decision.reason

    def test_the_control_the_same_unapproved_tool_alone_was_always_named(self):
        """One variable — the mid-run change removed. This is the row that made
        B-114 a completeness defect rather than a detection one: the identical
        tool is named when nothing else is wrong with the listing."""
        decision = decide_listing(
            policy_with({"fetch_url": A64, "read_file": C64}),
            listing(("fetch_url", A64), ("exfil_tool", C64)),
        )
        assert decision.rule_id == "listing:unpinned-tool"
        assert "exfil_tool" in decision.reason

    def test_an_ordinary_mid_run_refusal_grows_no_extra_clause(self):
        """The no-op half. A listing whose only fault is the mid-run change
        reads exactly as it did, so the fix costs an operator nothing on the
        common path."""
        decision = decide_listing(
            policy_with({"fetch_url": B64}),
            listing(("fetch_url", B64), seen={"fetch_url": A64}),
        )
        assert decision.rule_id == "listing:definition-changed-mid-run"
        assert "also refused in this listing" not in decision.reason

    def test_the_id_is_still_the_most_specific_true_fact(self):
        """Naming every offender must not promote one. The schema promises the
        most specific true fact supplies the id, and mid-run outranks both."""
        decision = decide_listing(
            policy_with({"fetch_url": A64}),
            listing(("fetch_url", B64), ("exfil_tool", C64), seen={"fetch_url": A64}),
        )
        assert decision.rule_id == "listing:definition-changed-mid-run"

    def test_offenders_are_named_in_the_order_the_upstream_advertised_them(self):
        """The reason line is the operator's on-ramp — they paste approvals out
        of it — so the added clause obeys `listing_order` like the branch it was
        copied from."""
        decision = decide_listing(
            policy_with({"fetch_url": A64}),
            listing(("zebra", C64), ("fetch_url", B64), ("alpha", C64), seen={"fetch_url": A64}),
        )
        also = decision.reason.split("also refused in this listing", 1)[1]
        assert also.index("zebra") < also.index("alpha")


class TestTheDoorDoesNotLookForOmissions:
    """**B-115, D-052** — the door asks *was what arrived approved* and never
    *did what was approved arrive*, so a listing that OMITS tools is allowed.
    `docs/LIMITATIONS.md` §20 item 8 is the disclosure; these assert the ALLOW,
    which inverts the direction on purpose: the day a `listing:` class or a
    strictness dial closes it, this class goes red and the published statement
    of what is missed has to move in the same edit (D-048 Decision 4's shape).
    """

    def test_a_listing_missing_two_of_three_approved_tools_is_allowed(self):
        decision = decide_listing(
            policy_with({"fetch_url": A64, "read_file": B64, "write_file": C64}),
            listing(("fetch_url", A64)),
        )
        assert (decision.verdict, decision.rule_id) == (Verdict.ALLOW, "listing:approved")
        assert "all 1 tool definitions" in decision.reason

    def test_an_empty_listing_is_allowed_too(self):
        """The limit case, and the sharper statement of the same silence: a
        server that drops EVERY approved tool is `listing:approved`."""
        decision = decide_listing(policy_with({"fetch_url": A64}), listing())
        assert decision.verdict is Verdict.ALLOW

    def test_the_control_the_door_is_armed_in_the_direction_it_was_built_for(self):
        """Non-vacuity: the same short listing with one EXTRA unapproved tool is
        refused, so the allow above is a blind spot rather than a dead door."""
        decision = decide_listing(
            policy_with({"fetch_url": A64, "read_file": B64, "write_file": C64}),
            listing(("fetch_url", A64), ("exfil_tool", C64)),
        )
        assert (decision.verdict, decision.rule_id) == (Verdict.BLOCK, "listing:unpinned-tool")
