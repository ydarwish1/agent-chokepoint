"""B-017 regression: the demo's gate must assert availability, not only enforcement.

``proxy/demo/run_demo.py`` is a proof artifact — its exit code IS the claim that
the proxy stops the attack and leaves ordinary work untouched. The gate used to
read ``ok = not guarded_reached and unguarded_reached`` with both lists filtered
to the ATTACK tool, so a proxy that blocked 100% of traffic — the benign call
with it — still printed ``PASS`` and exited 0. That claim covers the benign
call; the gate never asserted it.

Both legs live in this file on purpose. A gate test with only the failing leg
cannot tell "the gate works" from "the gate always fails".

- FAIL leg: the demo is pointed at a policy whose ``read_file`` rule BLOCKS
  inside the allow prefix. The OLD gate's condition is still satisfied there —
  the attack is stopped with the guard on and lands with it off, and this test
  asserts that too, so the new failure is attributable to the benign call and
  not to the harness falling over — and the gate must now FAIL.
- PASS leg: the shipped policy, untouched, still passes, with all four counts.

Only ``run_demo.POLICY_PATH`` is redirected, exactly as B-017's repro did. The
gate is the code under test and is never patched: ``main_async`` reports failure
by exiting 1, so ``SystemExit`` IS the gate's FAIL, and the printed verdict word
is asserted next to it because B-017 was a printed ``PASS`` beside a broken
proof.

Each test drives three real processes (client, proxy, upstream) over real stdio
pipes, so this file costs seconds where the rest of the suite costs
milliseconds. That is the price of testing the real harness instead of a
re-implementation of it.
"""

from __future__ import annotations

import re
import tempfile
from pathlib import Path

import anyio

from proxy.demo import run_demo

REPO_ROOT = Path(__file__).resolve().parents[2]

# The shipped policy with exactly one thing changed: `fs-read-scoped` blocks
# where it allows. The attack rule is carried over verbatim so the attack leg
# behaves as it does in the real run and the only new fact is that the benign
# call is refused too — B-017's repro, as a file. Every rule carries a `when:`.
BENIGN_BLOCKING_POLICY = r"""
version: 0

defaults:
  decision: block
  on_no_match: block

rules:

  - id: fs-read-scoped
    owasp: LLM01
    tool: read_file
    decision: block
    when:
      path_within: ["/workspace/"]

  - id: shell-destructive
    owasp: LLM01
    tool: run_command
    decision: block
    when:
      command_matches_any:
        - 'curl[^|]*\|\s*(ba)?sh\b'
"""

COUNT_RE = re.compile(r"(attack|benign) reached the tool with the guard (ON|OFF)\s*:\s*(\d+)$")
VERDICT_RE = re.compile(r"(PASS|FAIL)\s")
ALL_FOUR = {"attack ON", "attack OFF", "benign ON", "benign OFF"}


def counts(lines: list[str]) -> dict[str, int]:
    """The counts the verdict block prints, keyed ``"attack ON"`` / ``"benign OFF"``.

    Read out of the transcript rather than recomputed, because the demo's reader
    is a human: a count the gate enforces but never prints is invisible to them,
    and this file is what keeps it printed.
    """
    matches = (COUNT_RE.search(line) for line in lines)
    return {f"{m[1]} {m[2]}": int(m[3]) for m in matches if m}


def final_verdict(lines: list[str]) -> str:
    """The word the transcript's own headline verdict prints. The per-check
    ``[PASS]``/``[FAIL]`` lines do not match — this is the summary line."""
    verdicts = [line.strip() for line in lines if VERDICT_RE.match(line.strip())]
    assert len(verdicts) == 1, verdicts
    return verdicts[0].split()[0]


def run_gate(monkeypatch, policy: Path | None) -> tuple[bool, list[str]]:
    """Run the real demo end to end; return (gate passed, transcript lines)."""
    if policy is not None:
        monkeypatch.setattr(run_demo, "POLICY_PATH", policy)
    # `lines` is a module-level accumulator, so the second demo in a process
    # would otherwise inherit the first one's transcript.
    transcript: list[str] = []
    monkeypatch.setattr(run_demo, "lines", transcript)
    try:
        anyio.run(run_demo.main_async, None)
    except SystemExit as exc:
        assert exc.code == 1, exc.code
        return False, transcript
    return True, transcript


def test_gate_fails_when_the_guard_blocks_the_benign_call(monkeypatch):
    # The policy file lives INSIDE the repo because run_demo prints
    # `POLICY_PATH.relative_to(REPO_ROOT)`, which raises ValueError for a path
    # outside it (measured 2026-08-02) — the run would die before reaching the
    # gate. Redirecting POLICY_PATH stays the whole mutation.
    with tempfile.TemporaryDirectory(dir=REPO_ROOT, prefix="b017-policy-") as tmp:
        policy = Path(tmp) / "blocks-the-benign-call.yaml"
        policy.write_text(BENIGN_BLOCKING_POLICY, encoding="utf-8")
        passed, lines = run_gate(monkeypatch, policy)

    seen = counts(lines)
    assert seen.keys() == ALL_FOUR, seen
    # The old gate's condition still holds here...
    assert seen["attack ON"] == 0, seen
    assert seen["attack OFF"] >= 1, seen
    # ...and yet the benign call never reached the tool. This combination is
    # what printed PASS and exited 0 before B-017 was fixed.
    assert seen["benign ON"] == 0, seen
    assert passed is False
    assert final_verdict(lines) == "FAIL"


def test_gate_passes_on_the_shipped_policy(monkeypatch):
    # The positive control: without it, a gate wired to fail unconditionally
    # would satisfy the test above.
    passed, lines = run_gate(monkeypatch, None)

    assert counts(lines) == {"attack ON": 0, "attack OFF": 1, "benign ON": 1, "benign OFF": 1}
    assert passed is True
    assert final_verdict(lines) == "PASS"
