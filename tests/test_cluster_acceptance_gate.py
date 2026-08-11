"""The cluster acceptance criterion, as a test rather than only as a transcript.

``deploy/demo/cluster_acceptance.py`` is a proof artifact: its exit code IS the
claim that the hardened deployment enforces the policy without breaking the
workload. Nothing runs it automatically, so a committed transcript would keep
reading PASS long after the chart had drifted. This file is what makes that a
test failure.

**Why this file lives in ``tests/`` and not in ``deploy/tests/``.**
``pyproject.toml:54`` is ``testpaths = ["engine", "policy", "proxy", "hooks",
"pep", "tests"]``. ``deploy`` is not in it. A test placed under ``deploy/tests/``
collects **zero** items while ``pytest`` still exits 0 and reports a pass — a
gate that cannot fail, in the shape of a gate that looks fine. ``tests/`` IS in
testpaths, so this file is collected.

**Why the module is loaded by path.** ``deploy/`` and ``deploy/demo/`` carry no
``__init__.py`` — every package in this repo has one — and adding one to make
this import work would change what ``deploy/`` is. Loading the module from its
path keeps the import honest and adds no file outside this one.

Two kinds of test here, and the split is deliberate:

* The PURE ones need no cluster and run in CI (``.github/workflows/ci.yml`` runs
  pytest and has no cluster step). They pin the *scoring rules* — the part of
  the harness that decides what counts as a pass. A harness that scores an
  unmeasured leg as a success cannot fail, and a harness that cannot fail is not
  evidence.
* The cluster one drives the real deployed pod and skips, with its reason
  stated, when there is nothing to drive.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

from engine import ToolCall, decide

from policy import load_policy

REPO_ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = REPO_ROOT / "policy" / "policy.example.yaml"
MODULE_PATH = REPO_ROOT / "deploy" / "demo" / "cluster_acceptance.py"

_MODULE_NAME = "deploy_demo_cluster_acceptance"
_spec = importlib.util.spec_from_file_location(_MODULE_NAME, MODULE_PATH)
assert _spec is not None and _spec.loader is not None, MODULE_PATH
ca = importlib.util.module_from_spec(_spec)
# Registered BEFORE exec: `@dataclass` resolves `sys.modules[cls.__module__]`
# while processing a class whose annotations it has to look up, and a module
# missing from sys.modules makes that an AttributeError on None (measured on
# Python 3.14.6, 2026-08-03 — the module executes fine as a script, and only
# path-loading hit it).
sys.modules[_MODULE_NAME] = ca
_spec.loader.exec_module(ca)


def _cluster_status() -> tuple[bool, str]:
    """(is there a pod to drive, why not).

    Asked once, at collection. In CI ``kubectl`` is absent, which surfaces as
    exit 127 from :func:`cluster_acceptance.run` rather than an exception, so
    this is a skip and never a collection error."""
    done = ca.run(
        [ca.KUBECTL, "--context", ca.CONTEXT, "-n", ca.NAMESPACE, "get", "pods", "-o", "json"],
        timeout=30,
    )
    if done.code != 0:
        return False, f"no reachable cluster: {done.failed[:160]}"
    items = json.loads(done.out).get("items", [])
    if len(items) != 1:
        return False, (
            f"context {ca.CONTEXT} namespace {ca.NAMESPACE} holds {len(items)} pod(s); "
            "the acceptance harness drives exactly one"
        )
    return True, ""


HAVE_CLUSTER, NO_CLUSTER_REASON = _cluster_status()


# ------------------------------------------------------- pure: the scoring rules


def test_a_leg_that_measured_nothing_is_not_scored_as_reaching_the_tool_zero_times() -> None:
    """The one that matters most, and the reason ``reached`` starts at ``-1``.

    "The attack reached the tool 0 times" is the headline claim of the whole
    artifact, and a harness that never reached the cluster has *also* observed
    the attack reaching the tool zero times. Those are different facts and only
    one of them is evidence. With a default of ``0`` — or a check spelled ``not
    measured.reached`` or ``measured.reached <= 0`` — a totally failed run
    produces the most reassuring transcript the harness can print.
    """
    never_ran = ca.Measured()
    assert never_ran.reached == -1
    assert ca.reached_as_expected(never_ran, 0) is False
    assert ca.reached_as_expected(never_ran, 1) is False


def test_a_leg_that_really_measured_zero_is_scored_as_reaching_the_tool_zero_times() -> None:
    """The positive control. Without it, a scoring rule hardwired to ``False``
    satisfies the test above perfectly."""
    assert ca.reached_as_expected(ca.Measured(reached=0), 0) is True
    assert ca.reached_as_expected(ca.Measured(reached=1), 1) is True
    assert ca.reached_as_expected(ca.Measured(reached=1), 0) is False


def test_a_leg_whose_proxy_wrote_no_decision_event_is_not_scored_as_the_expected_verdict() -> None:
    """An absent verdict is a failure, never a match.

    ``leg_verdict`` reports "no event" and "two events" as the sentinel
    ``<n events>`` rather than smoothing either into a verdict. The sentinel is
    deliberately not a member of ``VERDICTS``, so it cannot compare its way into
    a pass — the same property ``hooks/demo/side_by_side.py`` needed after two
    silent doors scored as perfect agreement.
    """
    case = next(c for c in ca.CASES if c.key == "attack")
    assert ca.verdict_as_expected(ca.Measured(), case) is False
    assert ca.verdict_as_expected(ca.Measured(verdict="<0 events>", rule="-"), case) is False
    assert ca.verdict_as_expected(ca.Measured(verdict=ca.NO_PROXY, rule="-"), case) is False
    # The positive control, same shape as above.
    real = ca.Measured(verdict=case.expect_verdict, rule=case.expect_rule)
    assert ca.verdict_as_expected(real, case) is True
    # Right verdict, wrong rule id: still a failure. The rule id is the answer to
    # "why", and a block for the wrong reason is a different deployment.
    assert ca.verdict_as_expected(ca.Measured(verdict=case.expect_verdict, rule="something-else"), case) is False


def test_a_run_that_measured_nothing_at_all_reports_not_ok() -> None:
    """The whole-harness version of the rule above: an empty ``Results`` is the
    state a run has when the cluster was never reached, and it must not be a
    pass. Every reach and verdict check has to be FAILing for that to hold."""
    empty = ca.Results()
    assert empty.ok is False
    failed = [name for name, passed, _detail in empty.checks if not passed]
    # One per case per leg (verdict, reach on, reach off), both B-002 paths,
    # every pod fact, the uid, and the one-container check.
    assert len(failed) >= 3 * len(ca.CASES) + len(ca.WORKSPACE_PATHS) + len(ca.POD_FACTS) + 2


def test_a_leg_appended_from_outside_the_harness_can_fail_the_whole_run() -> None:
    """The NetworkPolicy and D-020 controls need a deliberately weakened ``helm
    install`` and are therefore not this harness's to run. They append through
    ``Results.extra`` — which is only useful if an appended FAIL is carried into
    ``ok`` rather than merely printed beside it."""
    results = ca.Results()
    results.extra.append(("appended: the NetworkPolicy blocked egress", False, "measured"))
    assert ("appended: the NetworkPolicy blocked egress", False, "measured") in results.checks
    assert results.ok is False


def test_every_case_expects_the_verdict_and_rule_the_shipped_policy_actually_owes_it() -> None:
    """The expectations are DATA, so they can go stale. This is what stops them.

    ``Case.expect_verdict``/``expect_rule`` are what make the harness test the
    POLICY rather than merely test the deployment against itself — and they were
    transcribed from a contract table. One cell of that table did not survive
    measurement: the ``curl … | sh`` call is blocked by the ``shell-destructive``
    rule that MATCHES it, not by ``default:on_no_match``. Asking the engine here
    means the next such drift is a CI failure instead of a transcript that
    quietly stops being true.
    """
    policy = load_policy(str(POLICY_PATH))
    for case in ca.CASES:
        decision = decide(
            policy, ToolCall(tool=case.tool, arguments=case.args, agent_id="cluster-acceptance")
        )
        assert (str(decision.verdict), decision.rule_id) == (case.expect_verdict, case.expect_rule), (
            f"{case.label}: cluster_acceptance expects "
            f"{case.expect_verdict}/{case.expect_rule}, the shipped policy answers "
            f"{decision.verdict}/{decision.rule_id}"
        )


def test_no_case_uses_write_file_as_a_control() -> None:
    """``write_file`` is ``ask`` and ``ask`` fails closed (D-005) — there is no
    approval channel in a cluster. A ``write_file`` availability control would
    therefore fail on a perfectly healthy deployment, and be "fixed" by
    weakening the policy."""
    assert [c for c in ca.CASES if c.tool == "write_file"] == []


def test_the_three_legs_cover_enforcement_availability_and_the_deny_half() -> None:
    """Enforcement alone is the B-017 shape: a proxy that blocks 100% of traffic
    passes an enforcement-only gate. And a read plainly inside the allow prefix
    plus one plainly outside it answer the same way whether the deny predicate
    works or is ignored (B-006), so a path under a deny prefix has to be one of
    the cases."""
    by_key = {c.key: c for c in ca.CASES}
    assert by_key["attack"].expect_reach_on == 0 and by_key["attack"].expect_reach_off == 1
    assert by_key["benign"].expect_verdict == "allow"
    assert by_key["benign"].expect_reach_on == 1, "availability is asserted, not assumed"
    assert "/.ssh/" in by_key["denied"].args["path"]
    assert by_key["denied"].expect_verdict == "block"
    # Every enforcement claim carries its guard-off control: a leg with
    # expect_reach_off == 0 would be "nothing happened", which a broken probe
    # produces just as readily as a working guard.
    assert all(c.expect_reach_off == 1 for c in ca.CASES)


# ----------------------------------------------------------- the cluster itself


@pytest.mark.skipif(not HAVE_CLUSTER, reason=NO_CLUSTER_REASON)
def test_the_deployed_pod_passes_every_acceptance_check() -> None:
    """One full run of the real harness against the real pod.

    Deliberately one run with assertions on what it returns, rather than unit
    tests around its formatting: the thing worth pinning is the deployment's
    behaviour, and the only way to observe it is to drive the pod for real.
    """
    results = ca.run_all()
    failed = [(name, detail) for name, passed, detail in results.checks if not passed]
    assert failed == [], "; ".join(f"{name}: {detail}" for name, detail in failed)
    assert results.ok
