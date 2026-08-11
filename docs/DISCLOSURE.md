# DISCLOSURE — security findings in other projects

**This project does not hunt for these** (D-010 cut the bypass hunt, and filing a finding is no longer a deliverable). But five turned up incidentally while reading other projects during the prior-art work, and they are sitting in gitignored `findings/`. This runbook exists for if and when one of them is acted on — and for any future finding that arrives the same way, unlooked-for.

Every finding follows these steps **in this order** — no skipping, no reordering. Defects in Agent-Chokepoint itself are tracked as ordinary internal bugs; the two workflows never mix.

## The steps

1. **Reproduce.** Minimal proof of concept against the target's latest release *and* current main. Everything goes in `findings/F-###.md` — gitignored, local only, never committed, because this repository is public and its history stays intact.
2. **Assess.** Impact, affected versions, suggested fix.
3. **Get approval.** Contacting a maintainer is an external send. Nothing leaves before an explicit OK on the specific report. Follow-up messages inside an approved disclosure thread are covered; new artifacts — a PR, a publication — each get fresh approval.
4. **Find the private channel.** The target's SECURITY.md → GitHub private vulnerability reporting → maintainer email, in that order. Never a public issue or PR for an exploitable bug.
5. **Report privately.** Description, impact, repro, suggested fix, and the disclosure window: 90 days by default, extendable for a good-faith fix in progress.
6. **Support the fix.** Answer questions; offer a PR if the maintainers welcome one.
7. **Publish after the fix ships or the window expires**, coordinated with the maintainer where possible. The writeup goes to `docs/advisories/F-###.md` — the first committed trace of the finding. Credit the maintainers' response plainly; never shame.
8. **Take the lesson into the policy.** If the bug class generalizes — a fail-open default, an unanchored glob, an evaluation order that lets an allow preempt a deny — add a test to this project's own suite proving Agent-Chokepoint does not have it.

Non-security bugs found in other projects: an ordinary public issue — still an external send, still approved before it goes.

## Finding record template — `findings/F-###.md` (gitignored)

```markdown
# F-### · <target project> · <one-line title>
**Date found:** YYYY-MM-DD
**Target version:** release + commit
**Class:** e.g. policy bypass · OWASP LLM id
**Impact:**
**Repro:** exact steps / payload
**Suggested fix:**
**Status:** draft | approved | reported | fix-in-progress | fixed | published
**Timeline:** dated log of every contact and event
```
