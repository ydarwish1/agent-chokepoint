"""The two-doors acceptance criterion, as a test rather than only as a text file.

The criterion: the same engine returns identical verdicts through both
enforcement points for the same call, demonstrated side by side.
``hooks/demo/side_by_side.py`` is that demonstration and it self-asserts — but
nothing runs it automatically, so the committed transcript would keep reading
"disagreements: 0" long after the two doors had drifted apart. This file is what
makes drift a CI failure.

It is deliberately ONE run of the real harness with assertions on the
measurements it returns, rather than a set of unit tests around its formatting:
the thing worth pinning is the behaviour, and the only way to observe it is to
spawn the proxy, the upstream and the hook for real. That costs a few seconds,
which is the whole price of the acceptance criterion being checked at all.

Agreement is only half of what is pinned here, and the weaker half: two doors
sharing one engine agree on a wrong answer as readily as on a right one. Each
case therefore carries the verdict and rule id the policy owes it, and that
expectation is asserted alongside the agreement.

One assertion pins a *difference* on purpose. The proxy enforces ``limits:``
and the hook does not; that gap is documented in ``hooks/README.md`` and shown
in the transcript. If someone closes it, this test fails and the transcript's
Part C has to be regenerated rather than quietly becoming false.
"""

from __future__ import annotations

import anyio
import pytest

from hooks.demo.side_by_side import MCP_CASES, NATIVE_CASES, Results, Row, run_all


@pytest.fixture(scope="module")
def results(tmp_path_factory) -> Results:
    """One full side-by-side run, shared by every assertion below."""
    return anyio.run(run_all, tmp_path_factory.mktemp("side-by-side"))


def test_every_property_the_transcript_asserts_holds(results: Results) -> None:
    """The harness's own PASS, checked as a whole.

    ``Results.ok`` is the conjunction of every named check; asserting it here
    means a check added to the transcript is a check CI applies, without this
    file having to grow a mirror of each one.
    """
    failed = [(name, detail) for name, passed, detail in results.checks if not passed]
    assert failed == [], "; ".join(f"{name}: {detail}" for name, detail in failed)
    assert results.ok


def test_both_doors_return_the_same_verdict_and_rule_for_every_call(results: Results) -> None:
    disagreed = [r for r in results.rows if not r.agree]
    assert disagreed == [], (
        "the proxy and the hook disagreed: "
        + "; ".join(
            f"{r.label}: proxy={r.proxy_verdict}/{r.proxy_rule} hook={r.hook_verdict}/{r.hook_rule}"
            for r in disagreed
        )
    )
    # Every case produced a row: `zip` truncates to the shortest leg, so a run
    # that lost three of its calls would otherwise report "0 of 2" and pass.
    assert len(results.rows_a) == len(MCP_CASES)
    assert len(results.rows_b) == len(NATIVE_CASES)
    assert results.leg_errors == []


def test_every_verdict_matches_the_expectation_stated_with_the_case(results: Results) -> None:
    """Agreement is the weak half; this is the half that tests the POLICY.

    Two doors sharing one engine agree on a wrong answer just as readily as on a
    right one, so a regression that reaches both — a predicate broken in the
    shared engine, a rule edited out of the policy file — reads as perfect
    agreement. Each case carries the verdict and rule id it is owed.
    """
    wrong = [r for r in results.rows if not r.as_expected]
    assert wrong == [], "; ".join(
        f"{r.label}: expected {r.expect_verdict}/{r.expect_rule}, "
        f"proxy={r.proxy_verdict}/{r.proxy_rule} hook={r.hook_verdict}/{r.hook_rule}"
        for r in wrong
    )


def test_a_door_that_wrote_no_event_is_not_scored_as_agreeing() -> None:
    """The sentinel must never compare equal to itself into a PASS.

    Both doors silent used to render as AGREE, because ``verdict_of([])``
    returns the same ``("<0 events>", "-")`` pair for each of them. A harness
    that scores two silent doors as agreement cannot fail, and a harness that
    cannot fail is not evidence.
    """
    silent = Row("nothing happened", "<0 events>", "-", "<0 events>", "-", "block", "some-rule")
    assert not silent.measured
    assert not silent.agree
    assert not silent.as_expected
    assert silent.status == "NOT MEASURED"


def test_a_path_under_a_deny_prefix_is_exercised(results: Results) -> None:
    """B-006's property needs a case that can only pass if the deny half works.

    A read plainly inside the allow prefix and a read plainly outside it answer
    the same way whether ``path_not_within`` is enforced or ignored — which is
    how B-006 shipped with the deny half changing 0 of 15 decisions.
    """
    deny_cases = [
        c for c in MCP_CASES
        if c.tool == "read_file"
        and any(seg in str(c.args.get("path", "")) for seg in ("/.ssh/", "/.aws/", "/.git/"))
    ]
    assert deny_cases, "no case reads a path under one of the policy's deny prefixes"
    for case in deny_cases:
        assert case.expect_verdict == "block"
        row = next(r for r in results.rows_a if r.label == case.label)
        assert row.as_expected, f"{row.label}: {row.proxy_verdict}/{row.proxy_rule}"


def test_the_mcp_leg_hands_both_doors_the_same_arguments(results: Results) -> None:
    # Part A's whole claim. If the envelopes ever differ, "identical verdicts"
    # would be an analogy rather than a measurement, even while every row agrees.
    assert results.envelope_mismatches == 0
    assert results.envelope_matches == len(results.rows_a)


def test_the_native_leg_actually_translated_something(results: Results) -> None:
    """Part B's equivalent of the envelope check.

    Part A was protected and Part B was not, so three native rows where neither
    door logged anything reported "disagreements: 0" and passed. The property
    here is weaker than Part A's by design — the envelopes differ on purpose —
    but it is not nothing: the proxy's canonical argument must appear unchanged
    in what the hook handed the engine.
    """
    assert results.translation_mismatches == 0
    assert results.translation_matches == len(results.rows_b)


def test_the_documented_limits_gap_is_still_real(results: Results) -> None:
    assert results.limit_proxy_blocks == 1, "the proxy stopped enforcing max_repeated_identical_calls"
    assert results.limit_hook_blocks == 0, (
        "the hook now enforces a run limit — hooks/README.md and the Part C transcript "
        "both say it does not"
    )


def test_an_unmapped_native_tool_produces_no_decision_and_no_event(results: Results) -> None:
    assert results.unmapped_hook_events == 0
    assert results.unmapped_hook_stdout == ""
