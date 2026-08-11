"""``proxy/demo/tainted_run.py``'s gate fails for each reason it claims to check.

The demo is a proof artifact: its exit code IS the claim that the same
call is allowed in a clean run and refused after the run has consumed an
untrusted result. B-017 is the standing lesson about that arrangement — a gate
that asserts only the refusal prints ``PASS`` while the control underneath it is
broken, because "the call was refused" reads identically whether taint refused
it or the policy never permitted it at all.

So this file drives the real demo three times and asserts the gate discriminates
in both directions:

- **PASS leg** — the shipped policy, untouched. All five checks pass and the
  demo exits 0. Without this a gate wired to fail unconditionally would satisfy
  the two below.
- **FAIL leg A, the control breaks** — ``shell-readonly`` removed, so the send is
  refused in the clean run too. The refusal in leg 2 is still there and the
  enforcement check still passes; the demo must nonetheless FAIL, because a
  refusal with no matching allow beside it proves nothing.
- **FAIL leg B, enforcement breaks** — ``taint.sources`` pointed at a tool the
  demo never calls, so the run is never marked and the send goes through after
  the page. Both controls are intact and the enforcement check is the one that
  must go red.

Each policy is the committed ``policy.example.yaml`` with exactly one thing
changed, loaded and re-dumped rather than retyped, so a leg cannot pass by
testing a rulebook that does not exist.

Each test drives real processes over real stdio pipes, so this file costs
seconds where the rest of the suite costs milliseconds — the same price
``test_run_demo_gate.py`` pays for testing the real harness.
"""

from __future__ import annotations

import re
import tempfile
from pathlib import Path

import anyio
import yaml

from proxy.demo import tainted_run

REPO_ROOT = Path(__file__).resolve().parents[2]
SHIPPED_POLICY = REPO_ROOT / "policy" / "policy.example.yaml"

#: The label is `[a-z-]+`, not `\w+`, and every label is distinct. Both facts
#: are load-bearing: the first version of this file keyed on `\w+` while the
#: demo printed two checks called "control", so `dict(checks(...))` kept only
#: the second and a FAILING clean control read as PASS. That is B-017's exact
#: shape, in the gate written to prevent B-017's shape, caught by the mutation
#: leg below rather than by review.
CHECK_RE = re.compile(r"\[(PASS|FAIL)\]\s+([a-z-]+):")
VERDICT_RE = re.compile(r"(PASS|FAIL)\s")
ALL_FIVE = {"enforcement", "control-clean", "availability", "control-unguarded", "attribution"}


def checks(lines: list[str]) -> dict[str, str]:
    """``{"enforcement": "PASS", "control-clean": "FAIL", …}``.

    Read out of the transcript rather than recomputed. The demo's reader is a
    human, and a check the gate enforces but never prints is invisible to them —
    B-017 was a printed ``PASS`` beside a broken proof. The length assertion is
    what stops a duplicate label collapsing two checks into one again.
    """
    found = [(m[2], m[1]) for m in (CHECK_RE.search(line) for line in lines) if m]
    assert len(found) == len(ALL_FIVE), f"expected {len(ALL_FIVE)} distinct checks, printed {found}"
    return dict(found)


def final_verdict(lines: list[str]) -> str:
    """The headline verdict word. The per-check ``[PASS]``/``[FAIL]`` lines are
    indented and do not match at the start of the stripped line."""
    verdicts = [line.strip() for line in lines if VERDICT_RE.match(line.strip())]
    assert len(verdicts) == 1, verdicts
    return verdicts[0].split()[0]


def mutate(tmp: str, name: str, change) -> Path:
    """The shipped policy with one thing changed, written inside the repo.

    Inside, because the demo prints ``POLICY_PATH.relative_to(REPO_ROOT)``, which
    raises ValueError for a path outside the tree — the run would die before
    reaching the gate and the test would prove nothing about it.
    """
    doc = yaml.safe_load(SHIPPED_POLICY.read_text(encoding="utf-8"))
    change(doc)
    out = Path(tmp) / name
    out.write_text(yaml.safe_dump(doc), encoding="utf-8")
    return out


def run_gate(monkeypatch, policy: Path | None) -> tuple[bool, list[str]]:
    """Run the real demo end to end; return (gate passed, transcript lines)."""
    if policy is not None:
        monkeypatch.setattr(tainted_run, "POLICY_PATH", policy)
    # `lines` is a module-level accumulator, so a second run in the same process
    # would otherwise inherit the first one's transcript.
    transcript: list[str] = []
    monkeypatch.setattr(tainted_run, "lines", transcript)
    try:
        anyio.run(tainted_run.main_async, None)
    except SystemExit as exc:
        assert exc.code == 1, exc.code
        return False, transcript
    return True, transcript


def test_gate_passes_on_the_shipped_policy(monkeypatch):
    passed, lines = run_gate(monkeypatch, None)

    seen = checks(lines)
    assert set(seen) == ALL_FIVE, seen
    assert all(verdict == "PASS" for verdict in seen.values()), seen
    assert passed is True
    assert final_verdict(lines) == "PASS"


def test_gate_fails_when_the_clean_control_is_not_actually_allowed(monkeypatch):
    """B-017's shape, aimed at this demo: the refusal survives, the proof does not."""
    with tempfile.TemporaryDirectory(dir=REPO_ROOT, prefix="taint-gate-") as tmp:
        policy = mutate(
            tmp, "no-shell-allow.yaml",
            lambda doc: doc["rules"].__setitem__(
                slice(None), [r for r in doc["rules"] if r["id"] != "shell-readonly"]),
        )
        passed, lines = run_gate(monkeypatch, policy)

    seen = checks(lines)
    # The refusal is still there, and so is the ordinary work either side of it...
    assert seen["enforcement"] == "PASS", seen
    assert seen["availability"] == "PASS", seen
    assert seen["control-unguarded"] == "PASS", seen
    # ...and yet the identical call was never permitted in the clean run, so the
    # demo's one-variable claim is unsupported and both dependent checks go red.
    assert seen["control-clean"] == "FAIL", seen
    assert seen["attribution"] == "FAIL", seen
    assert passed is False
    assert final_verdict(lines) == "FAIL"


def test_gate_fails_when_the_run_is_never_marked(monkeypatch):
    """The other direction: nothing taints, so the send lands and enforcement is
    the check that must notice."""
    # `sources: []` is NOT the mutation, because the loader refuses it outright
    # ("taint.sources must be a non-empty list of strings") and the proxy exits 2
    # without serving — that is D-029/D-031 failing closed, and it would test the
    # loader rather than this gate. Pointing `sources` at a tool the demo never
    # calls leaves a valid, loadable policy in which nothing marks the run.
    with tempfile.TemporaryDirectory(dir=REPO_ROOT, prefix="taint-gate-") as tmp:
        policy = mutate(tmp, "unreachable-source.yaml",
                        lambda doc: doc["taint"].__setitem__("sources", ["write_file"]))
        passed, lines = run_gate(monkeypatch, policy)

    seen = checks(lines)
    assert seen["enforcement"] == "FAIL", seen
    assert seen["attribution"] == "FAIL", seen
    # The control legs are untouched — the failure is attributable to taint being
    # disarmed and not to the harness falling over.
    assert seen["control-clean"] == "PASS", seen
    assert seen["control-unguarded"] == "PASS", seen
    assert seen["availability"] == "PASS", seen
    assert passed is False
    assert final_verdict(lines) == "FAIL"
