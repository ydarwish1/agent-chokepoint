"""`docs/ATTACK-COVERAGE.md` is the matrix; this is the guard that stops it lying.

Before this pair existed, nothing in the repository named the lists it is
measured against. `policy/policy.example.yaml` carries an `owasp:` field per
rule, which is a mapping and not a coverage claim, and the OWASP list itself
MOVED on 2026-08-04 - Excessive Agency renumbered to LLM03 and Hidden Context
Exposure appeared at LLM08 with no counterpart in the list this project was
built against. So "coverage" was an opinion, and an opinion cannot go stale
loudly.

Five things are checked, and each one exists because the cheap way to lose this
file is different from the last:

1. **The row sets are exact.** The ten 2026 ids and titles, and the eight
   Invariant classes, are frozen here as literals, in document order. A row
   quietly dropped, renamed, or added is red. This is the check that survives
   the list moving again: the next edition renumbers something, this test fails,
   and a human has to look at both documents rather than at one.
2. **A COVERED row's node ids resolve against the LIVE suite** - resolved by
   asking pytest to collect, never by a regex over source files, and through
   `collect_node_ids()` in `tests/nodeids.py`, the one place that asks pytest
   what exists, so no two checks can drift into accepting different spellings
   of the same node id (D-036 Decision 1).
3. **A COVERED row's control is its OWN node** - decided by the FUNCTION each
   citation names rather than by the two strings, because pytest answers to more
   than one spelling of a node and this check was bypassed by exactly that
   (B-078). A control asserted inside the refusing test cannot fail
   independently of it and disappears the moment somebody narrows the refusal.
   That is the exact failure this matrix exists to make visible; it must not
   inherit it.
4. **An UNREACHED row's limitation exists, carries the same grading, and names
   the row.** UNREACHED is graded `structural` (nothing at this door can see the
   leg) or `unbuilt` (the door judges it; no pair pins it). The grading is
   D-038's answer to the way this escape hatch would otherwise be abused: a row
   nobody got to becomes a sentence in `docs/LIMITATIONS.md` naming it, rather
   than a status that reads like a property of the gateway.
5. **A row is COVERED or UNREACHED, and nothing else** - and a COVERED row may
   not say "none", nor an UNREACHED row cite a node.
6. **A row is a `### ` heading or it is not a row** - a row-shaped bold line or
   h4, and a `- **Field:**` line outside any row block, are failures rather than
   silences, and a field stated twice in one block cannot replace the first.
   **B-102**, and it is the check that makes claim 1's word *added* true.

WHAT THIS DOES NOT CHECK, and the first one is the largest.

**That a Control is a guard-off control at all.** Check 3 asks whether the two
citations are two independently-failing nodes. It does not ask whether the
second one fires the SAME payload with the guard removed, which is what
`docs/ATTACK-COVERAGE.md` promises a Control is. Any unrelated passing test
satisfies it - measured, not reasoned, and re-measured on 2026-08-08 after check
6 landed: setting LLM10:2026's Control to
`tests/test_attack_coverage.py::test_a_covered_row_never_says_none` leaves this
module at 18 passed, exit 0. Closing it means comparing what two tests DO, which
no check here attempts; D-043 Decision 1 makes no claim to it either. It is
named here because the omission a docstring leaves out is the one that gets read
as covered - B-060's shape, and this file's own subject.

**A row-shaped line carrying no fields and no middot.** Check 6 recognises a row
by `<id> · <title>`, so `**IL-9 - Invented class**` with a hyphen is not seen as
a row heading. What stops that being a hole is that a row with no fields claims
nothing, and the moment it carries one the field lands outside a block and check
6 reports it. A row-shaped line with a hyphen AND no fields is invisible here,
and it is also inert.

**An INDENTED field line inside a row's block.** `FIELD` anchors at column 0, so
`  - **Control:** <anything>` appended inside IL-8's block is neither read as
that row's field nor reported as a duplicate, while the identical line
flush-left IS reported. Named here rather than left silent because this block is
the one this repository has filed three entries about presenting itself as
complete (B-085, B-089, B-090) - and named WITH the reason it is not a hole,
which was measured rather than argued. Four legs on one scratch copy, 2026-08-08:
the honest matrix is 18 passed / exit 0; the indented duplicate is **18 passed /
exit 0**, invisible; the same line flush-left is **2 failed**, which is the
control saying the duplicate check is awake; and the indented duplicate placed
on a row whose real Refusal has been pointed at a phantom node is **1 failed** -
the phantom still caught. So the row's real fields still bind and are still
checked, and an indented line adds nothing an attacker or a careless editor can
use. Closing it would mean accepting indented fields as fields, which is a
parser change in exchange for a silence that hides nothing.

That a cited test PASSES: the suite it lives in is what says that, and re-running
it here would be a second, weaker copy of the same signal. That the leg sentence
is true: no test reads English. That a row's evidence is unique to it - two rows
may cite one pair where this door meets both with one mechanism (LLM01:2026 and
IL-7 do), which is a fact about the taxonomies and is stated in the rows
themselves. That a grading is HONEST: it holds the matrix and the limitation
entry to the same word, and two documents agreeing on a wrong word is B-079.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from tests.nodeids import collect_node_ids, node_id_aliases

REPO_ROOT = Path(__file__).resolve().parents[1]
MATRIX = REPO_ROOT / "docs" / "ATTACK-COVERAGE.md"
LIMITATIONS = REPO_ROOT / "docs" / "LIMITATIONS.md"

OWASP_SECTION = "OWASP GenAI LLM Top 10 — 2026 edition"
INVARIANT_SECTION = "Invariant Labs — MCP attack classes"

#: (id, title, a string the row's Source must contain). Pulled from the 2026
#: edition's own README and the filenames under `2026/final/`, which agree.
#: Frozen here as literals ON PURPOSE: this is the copy that fails when the doc
#: is edited, so it may never be derived from the doc.
OWASP_2026 = (
    ("LLM01:2026", "Prompt Injection", "LLM01_PromptInjection.md"),
    ("LLM02:2026", "Sensitive Information Disclosure", "LLM02_SensitiveInformationDisclosure.md"),
    ("LLM03:2026", "Excessive Agency", "LLM03_ExcessiveAgency.md"),
    ("LLM04:2026", "Supply Chain", "LLM04_SupplyChain.md"),
    ("LLM05:2026", "Data and Model Poisoning", "LLM05_DataModelPoisoning.md"),
    ("LLM06:2026", "Unbounded Consumption", "LLM06_UnboundedConsumption.md"),
    ("LLM07:2026", "Misinformation", "LLM07_Misinformation.md"),
    ("LLM08:2026", "Hidden Context Exposure", "LLM08_HiddenContextExposure.md"),
    ("LLM09:2026", "Vector and Embedding Weaknesses", "LLM09_VectorAndEmbeddingWeaknesses.md"),
    ("LLM10:2026", "Improper Output Handling", "LLM10_ImproperOutputHandling.md"),
)

#: Invariant published no single taxonomy page, so each class is pinned to the
#: post that introduced it.
INVARIANT_CLASSES = (
    ("IL-1", "Tool Poisoning Attack", "Tool Poisoning Attacks"),
    ("IL-2", "MCP Rug Pull", "Tool Poisoning Attacks"),
    ("IL-3", "Tool Shadowing", "Tool Poisoning Attacks"),
    ("IL-4", "Authentication Hijacking", "Tool Poisoning Attacks"),
    ("IL-5", "Sleeper / delayed activation", "WhatsApp MCP Exploited"),
    ("IL-6", "Toxic Agent Flow", "GitHub MCP Exploited"),
    ("IL-7", "Indirect prompt injection via tool output", "WhatsApp MCP Exploited"),
    ("IL-8", "Payload obfuscation", "WhatsApp MCP Exploited"),
)

COVERED = "COVERED"
GRADINGS = ("structural", "unbuilt")
UNREACHED_STATUSES = tuple(f"UNREACHED · {grading}" for grading in GRADINGS)
REQUIRED_FIELDS = ("Source", "Leg", "Refusal", "Control", "Status")

SECTION_HEADING = re.compile(r"^## (.+?)\s*$")
ROW_HEADING = re.compile(r"^### (\S+) · (.+?)\s*$")
FIELD = re.compile(r"^- \*\*([A-Za-z]+):\*\* (.*?)\s*$")

#: A line in a row's SHAPE — an id, a middot, a title — spelled as any other
#: heading level or as a bold line. `#### IL-9 · x` and `**IL-9 · x**` both read
#: as a row to a human and as nothing at all to `ROW_HEADING`, which is half of
#: B-102: an added row was invisible to both pinned id sets. The `- **Status:**
#: UNREACHED · structural` lines also carry a middot and are not matched, because
#: this pattern requires the line to OPEN with a heading marker or a bold run.
ROW_SHAPED = re.compile(r"^(?:(#{1,6}) |\*\*)(\S+) · (.+?)(?:\*\*)?\s*$")

#: `**20. some title — LLM04:2026, IL-1. Grading: structural.**`. Imported
#: rather than spelled twice: two copies of an entry parser is one edit away
#: from two checks that disagree about what an entry is.
from tests.docparse import (  # noqa: E402
    LIMITATION_ENTRY,
    limitation_entries,
)

assert LIMITATION_ENTRY and limitation_entries


class Row:
    def __init__(self, section: str, row_id: str, title: str, lineno: int):
        self.section = section
        self.id = row_id
        self.title = title
        self.lineno = lineno
        self.fields: dict[str, str] = {}
        #: fields stated twice in one block. The FIRST value is kept, so a
        #: second `- **Refusal:**` cannot quietly replace a row's citation.
        self.duplicate_fields: list[str] = []

    @property
    def where(self) -> str:
        return f"docs/ATTACK-COVERAGE.md:{self.lineno} ({self.id})"


def parse_rows(text: str) -> list[Row]:
    """Every `###` row block, in document order, with its `- **Field:** value` lines.

    **A field attaches to the row block it is INSIDE, not to `rows[-1]`.**
    Until 2026-08-08 it attached to the last row seen, wherever it appeared —
    so five field lines appended after the file's own footer overwrote IL-8's,
    disarming that row's citation checks while the suite stayed green, and a
    duplicate Refusal/Control pair inserted mid-document did the same to
    LLM01:2026. That is B-102, and the sentence it falsified is this file's own
    trust claim at `docs/ATTACK-COVERAGE.md:13`.

    A block opens at a `### ` row heading and closes at the first line that is
    neither blank nor a field — a `## ` section heading, a horizontal rule, the
    footer, or any prose. What that closes out is reported by
    `matrix_shape_problems()`; dropping it silently here would trade one silence
    for another.
    """
    rows: list[Row] = []
    section = ""
    open_row: Row | None = None
    for lineno, line in enumerate(text.splitlines(), 1):
        heading = SECTION_HEADING.match(line)
        if heading:
            section, open_row = heading.group(1), None
            continue
        row = ROW_HEADING.match(line)
        if row:
            open_row = Row(section, row.group(1), row.group(2), lineno)
            rows.append(open_row)
            continue
        field = FIELD.match(line)
        if field:
            if open_row is not None:
                if field.group(1) in open_row.fields:
                    open_row.duplicate_fields.append(field.group(1))
                else:
                    open_row.fields[field.group(1)] = field.group(2)
            continue
        if line.strip():
            open_row = None
    return rows


def matrix_shape_problems(text: str) -> list[str]:
    """Anything that reads as a row, or as a row's field, and is not one.

    The second half of B-102's fix. `parse_rows()` no longer lets a stray field
    overwrite a real row's; this is what stops the stray being *silent* — an
    added row has to be a failure rather than a thing the guard cannot see.

    Factored out so it can be fired at a document built to bypass it, which is
    the only way to know a guard works.
    """
    problems: list[str] = []
    open_row: Row | None = None
    rows = parse_rows(text)
    by_line = {row.lineno: row for row in rows}
    for lineno, line in enumerate(text.splitlines(), 1):
        if SECTION_HEADING.match(line):
            open_row = None
            continue
        if lineno in by_line:
            open_row = by_line[lineno]
            continue
        if FIELD.match(line):
            if open_row is None:
                problems.append(
                    f"docs/ATTACK-COVERAGE.md:{lineno}: a `- **Field:**` line outside "
                    f"any ### row block - a row is a ### heading or it is not a row: {line.strip()[:90]}")
            continue
        shaped = ROW_SHAPED.match(line)
        if shaped and shaped.group(1) != "###":
            problems.append(
                f"docs/ATTACK-COVERAGE.md:{lineno}: a line in a row's shape that is not a "
                f"### row heading, so no id set can see it: {line.strip()[:90]}")
        if line.strip():
            open_row = None
    problems.extend(
        f"{row.where}: {field} is stated twice in one block; the first value is the one "
        "this guard reads, and the second is how a row's citation gets replaced quietly"
        for row in rows for field in row.duplicate_fields)
    return problems


@pytest.fixture(scope="module")
def rows() -> list[Row]:
    assert MATRIX.exists(), "docs/ATTACK-COVERAGE.md is gone - every check here is vacuous without it"
    parsed = parse_rows(MATRIX.read_text(encoding="utf-8"))
    assert parsed, "docs/ATTACK-COVERAGE.md parsed to no rows at all - the row format changed"
    return parsed


@pytest.fixture(scope="module")
def limitations() -> dict[int, str]:
    entries = limitation_entries(LIMITATIONS.read_text(encoding="utf-8"))
    assert entries, "docs/LIMITATIONS.md yielded no numbered entries - the citation scheme is gone"
    return entries


def _in_section(rows: list[Row], section: str) -> list[Row]:
    return [row for row in rows if row.section == section]


# ------------------------------------------------------------ the row sets


def test_the_owasp_rows_are_exactly_the_ten_2026_ids(rows):
    """The 2026 edition, in its own order and its own spelling.

    Frozen as literals above rather than read from the doc, because a check that
    derives its expectation from the thing under test passes whatever that thing
    says. When the list moves again this is the test that goes red, and the fix
    is to read both documents - not to edit this tuple until it matches.
    """
    found = [(row.id, row.title) for row in _in_section(rows, OWASP_SECTION)]
    assert found == [(id_, title) for id_, title, _ in OWASP_2026], (
        "docs/ATTACK-COVERAGE.md's OWASP rows are not the 2026 list.\n"
        f"  in the doc : {found}\n"
        f"  the 2026 ten: {[(i, t) for i, t, _ in OWASP_2026]}"
    )


def test_every_owasp_row_names_its_source_file(rows):
    wrong = [f"{row.where}: Source does not name {source}"
             for row, (_, _, source) in zip(_in_section(rows, OWASP_SECTION), OWASP_2026)
             if source not in row.fields.get("Source", "")]
    assert not wrong, "\n  " + "\n  ".join(wrong)


def test_the_invariant_rows_are_exactly_the_eight_classes(rows):
    found = [(row.id, row.title) for row in _in_section(rows, INVARIANT_SECTION)]
    assert found == [(id_, title) for id_, title, _ in INVARIANT_CLASSES], (
        "docs/ATTACK-COVERAGE.md's Invariant rows are not the eight classes.\n"
        f"  in the doc: {found}\n"
        f"  expected  : {[(i, t) for i, t, _ in INVARIANT_CLASSES]}"
    )


def test_every_invariant_row_names_the_post_that_introduced_it(rows):
    wrong = [f"{row.where}: Source does not name {post!r}"
             for row, (_, _, post) in zip(_in_section(rows, INVARIANT_SECTION), INVARIANT_CLASSES)
             if post not in row.fields.get("Source", "")]
    assert not wrong, "\n  " + "\n  ".join(wrong)


def test_nothing_that_looks_like_a_row_is_outside_a_row_heading():
    """**B-102.** An added row turns the suite red, which the file says it does.

    `docs/ATTACK-COVERAGE.md:13` promises *"A row added, removed or renamed turns
    the suite red, which is the only reason this file can be trusted after the
    next list moves."* Removed and renamed were true. **Added was not** — a row
    written as a bold line, an `####` h4, or as bare field bullets after the
    footer was invisible to both pinned id sets, and worse: its fields landed on
    the last real row, so appending a block DISARMED that row's citation checks.
    Measured with both controls before this test existed: IL-8's Refusal pointed
    at a node that does not exist is exit 1; the same phantom with a bold block
    appended is 16 passed, exit 0.
    """
    problems = matrix_shape_problems(MATRIX.read_text(encoding="utf-8"))
    assert not problems, "\n  " + "\n  ".join(problems)


def test_the_shape_check_catches_each_way_a_row_can_be_added():
    """B-102's four shapes, fired at the checker, plus the honest control.

    The control is what makes the four mean anything: the shipped matrix, which
    differs only in not carrying the added block, is NOT flagged. Without it a
    checker that flagged every document would pass this test just as well.
    """
    honest = MATRIX.read_text(encoding="utf-8")
    assert matrix_shape_problems(honest) == [], (
        "the shipped matrix must be clean, or the four cases below prove nothing")

    # Every node id below is a REAL collected test. A made-up one would be a
    # citation naming nothing, planted by this file into the very document the
    # citation checks read — carelessness dressed as a fixture.
    real = ("proxy/tests/test_proxy.py::TestAttackBlocked::"
            "test_same_attack_lands_when_unguarded")
    bold = f"\n**IL-9 · Invented class**\n\n- **Source:** *Nowhere*\n- **Refusal:** {real}\n"
    h4 = f"\n#### IL-9 · Invented class\n\n- **Source:** *Nowhere*\n- **Refusal:** {real}\n"
    bullets = f"\n- **Refusal:** {real}\n"
    duplicate = (
        "- **Control:** proxy/tests/test_proxy.py::TestTaintTracking::"
        "test_a_clean_run_is_unaffected_by_the_taint_block\n"
        "- **Refusal:** proxy/tests/test_proxy.py::TestTaintTracking::"
        "test_secrets_only_refuses_a_credential_bearing_call_after_taint\n"
        f"- **Control:** {real}\n")

    for label, mutated in (
        ("a bold row block after the footer", honest + bold),
        ("an h4 row block after the footer", honest + h4),
        ("bare field bullets after the footer", honest + bullets),
        ("a second Control inside the first row's block",
         honest.replace(
             "- **Status:** COVERED\n- **Note:** what those two assert, and the whole of it: "
             "`echo <an AKIA-shaped string>`",
             duplicate + "- **Status:** COVERED\n- **Note:** what those two assert, and the "
             "whole of it: `echo <an AKIA-shaped string>`", 1)),
    ):
        assert mutated != honest, f"the mutation for {label!r} did not land"
        assert matrix_shape_problems(mutated), f"{label} is not caught"


def test_no_row_sits_outside_the_two_taxonomy_sections(rows):
    """Both sections exist and hold every row between them.

    Without this, deleting a `##` heading would move ten rows into a section
    neither set-check looks at, and both of those checks would then compare an
    empty list against an empty list.
    """
    strays = [row.where for row in rows if row.section not in (OWASP_SECTION, INVARIANT_SECTION)]
    assert not strays, "rows outside the two taxonomy sections:\n  " + "\n  ".join(strays)
    assert len(rows) == len(OWASP_2026) + len(INVARIANT_CLASSES)


# --------------------------------------------------------------- the fields


def test_every_row_carries_every_required_field(rows):
    missing = [f"{row.where}: no {field} line"
               for row in rows for field in REQUIRED_FIELDS if field not in row.fields]
    assert not missing, "\n  " + "\n  ".join(missing)


def test_every_row_is_covered_or_unreached_and_nothing_else(rows):
    """The status vocabulary is closed. A row with no status, a typo, or an
    invented third state is red rather than silently uncounted."""
    known = (COVERED,) + UNREACHED_STATUSES
    wrong = [f"{row.where}: Status is {row.fields.get('Status')!r}"
             for row in rows if row.fields.get("Status") not in known]
    assert not wrong, (
        f"every row is one of {known}:\n  " + "\n  ".join(wrong)
    )


# ------------------------------------------------------------ COVERED rows


def test_every_covered_row_resolves_both_node_ids_against_the_live_suite(rows):
    """Asked of pytest, not of a regex over source files.

    A citation that names no collected test is the defect this whole file is
    aimed at: it reads exactly like proof and is worth nothing, and renaming a
    test class is all it takes to create one.
    """
    collected = collect_node_ids()
    assert len(collected) > 50, "pytest collected almost nothing - this check would be vacuous"

    covered = [row for row in rows if row.fields.get("Status") == COVERED]
    phantom = []
    for row in covered:
        for field in ("Refusal", "Control"):
            cited = row.fields.get(field, "")
            if cited not in collected:
                phantom.append(f"{row.where}: {field} names no collected test: {cited!r}")
    assert not phantom, "\n  " + "\n  ".join(phantom)


def rows_whose_control_is_not_its_own_node(rows: list[Row],
                                           aliases: dict[str, frozenset[str]]) -> list[str]:
    """Rows whose two citations can name one collected test function.

    Factored out so it can be fired at a row built to bypass it, which is the
    only way to know a guard works: a check that has only ever seen honest input
    is not a check that has been tested.

    Compared by the FUNCTIONS each spelling names, never by the strings. pytest
    answers to several spellings of one node - with the class, without it, with
    and without a parametrization bracket - so two different strings routinely
    name one body, and a body cannot fail independently of itself.
    """
    problems = []
    for row in rows:
        if row.fields.get("Status") != COVERED:
            continue
        refusal, control = row.fields.get("Refusal", ""), row.fields.get("Control", "")
        shared = aliases.get(refusal, frozenset()) & aliases.get(control, frozenset())
        if refusal == control:
            problems.append(f"{row.where}: Refusal and Control are the same string")
        elif shared:
            problems.append(
                f"{row.where}: Refusal {refusal!r} and Control {control!r} are two spellings "
                f"of {sorted(shared)}, so the control cannot fail on its own")
    return problems


def test_a_covered_rows_control_is_its_own_node(rows):
    """The control has to be able to fail on its own.

    A control asserted inside the refusing test dies with it - narrow the
    refusal and the control goes quiet in the same edit, which is how a table
    like this rots without a single red run.
    """
    problems = rows_whose_control_is_not_its_own_node(rows, node_id_aliases())
    assert not problems, "\n  " + "\n  ".join(problems)


def test_the_control_check_sees_through_a_class_less_alias_of_the_refusal():
    """B-078, with both controls, on the exact mutation that bypassed it.

    Set a row's Control to its own Refusal with the enclosing class stripped and
    every check in this module used to stay green: `collect_node_ids()`
    deliberately registers that spelling, so the citation RESOLVES, and the
    distinctness check compared the two fields as strings, which differ. A row
    could therefore ship COVERED with no guard-off control while this file and
    this module's docstring both asserted it had one - the load-bearing half of
    the whole matrix, gone, with no red run anywhere.

    The second half is the control and it is what makes the first mean anything:
    the honest pairing, which differs only in that the two names are different
    tests, is NOT flagged. Without it a check that flagged every row would pass
    this test just as well.
    """
    aliases = node_id_aliases()
    refusal = ("proxy/tests/test_proxy.py::TestAttackBlocked::"
               "test_destructive_command_is_blocked_with_rule_id")
    alias = "proxy/tests/test_proxy.py::test_destructive_command_is_blocked_with_rule_id"
    honest = "proxy/tests/test_proxy.py::TestAttackBlocked::test_same_attack_lands_when_unguarded"
    assert alias in aliases, (
        "the alias has to RESOLVE or this proves nothing - the bypass worked precisely because "
        "a class-less spelling is accepted everywhere else in this repo")
    assert alias != refusal, "the two strings must differ, or the old check would have caught it"

    def row_with(control: str) -> Row:
        row = Row(OWASP_SECTION, "LLM10:2026", "Improper Output Handling", 0)
        row.fields = {"Status": COVERED, "Refusal": refusal, "Control": control}
        return row

    assert rows_whose_control_is_not_its_own_node([row_with(alias)], aliases), (
        "a Control that is the Refusal with its class stripped is not a second node")
    assert rows_whose_control_is_not_its_own_node([row_with(honest)], aliases) == [], (
        "the shipped LLM10 pairing is two different tests and must pass")


def test_every_covered_rows_citation_names_exactly_one_test(rows):
    """A row points at a node, not at a family.

    A class name, or a method name two classes in one file share, resolves - and
    then nobody can say which test the row is claiming. It is also the spelling
    the bypass above rode in on, so requiring the citation to be unambiguous is
    the second lock on the same door: a bare class name resolves to every method
    of that class, and a row citing one as its control is citing its own refusal
    among others.
    """
    aliases = node_id_aliases()
    vague = []
    for row in rows:
        if row.fields.get("Status") != COVERED:
            continue
        for field in ("Refusal", "Control"):
            named = aliases.get(row.fields.get(field, ""), frozenset())
            if len(named) > 1:
                vague.append(f"{row.where}: {field} names {len(named)} tests: {sorted(named)}")
    assert not vague, "\n  " + "\n  ".join(vague)


def test_a_covered_row_never_says_none(rows):
    empty = [f"{row.where}: Status is COVERED but {field} is {row.fields.get(field)!r}"
             for row in rows if row.fields.get("Status") == COVERED
             for field in ("Refusal", "Control")
             if row.fields.get(field, "").strip().lower() in ("", "none")]
    assert not empty, "\n  " + "\n  ".join(empty)


# ---------------------------------------------------------- UNREACHED rows


def _unreached(rows: list[Row]) -> list[Row]:
    return [row for row in rows if row.fields.get("Status", "").startswith("UNREACHED")]


def test_every_unreached_row_cites_a_limitation_that_exists(rows, limitations):
    """The escape hatch costs a numbered entry in `docs/LIMITATIONS.md`.

    The suite has to be green at every commit, so a row with no pair cannot
    simply fail - and an UNREACHED that costs nothing is a row nobody will ever
    come back to.
    """
    problems = []
    for row in _unreached(rows):
        cited = row.fields.get("Limitation", "")
        match = re.search(r"docs/LIMITATIONS\.md §(\d+)", cited)
        if not match:
            problems.append(f"{row.where}: Limitation does not cite docs/LIMITATIONS.md §N: {cited!r}")
            continue
        number = int(match.group(1))
        if number not in limitations:
            problems.append(
                f"{row.where}: cites §{number}; docs/LIMITATIONS.md numbers {sorted(limitations)}"
            )
    assert not problems, "\n  " + "\n  ".join(problems)


def test_every_unreached_rows_limitation_carries_the_same_grading(rows, limitations):
    """`structural` and `unbuilt` are opposite claims, so the doc and the entry
    have to make the same one.

    Structural is a property of this gateway. Unbuilt is a debt of this
    repository. Letting the second wear the first's clothes is the abuse D-038
    exists to price, and the price is that somebody has to type the word into
    `docs/LIMITATIONS.md` beside the row's own id.
    """
    problems = []
    for row in _unreached(rows):
        grading = row.fields["Status"].split("·")[-1].strip()
        match = re.search(r"docs/LIMITATIONS\.md §(\d+)", row.fields.get("Limitation", ""))
        if not match or int(match.group(1)) not in limitations:
            continue  # the test above owns that failure
        entry = limitations[int(match.group(1))]
        if f"Grading: {grading}" not in entry:
            problems.append(
                f"{row.where}: graded {grading!r}, but §{match.group(1)} does not say "
                f"'Grading: {grading}'"
            )
    assert not problems, "\n  " + "\n  ".join(problems)


def test_every_unreached_rows_limitation_names_the_row(rows, limitations):
    """The entry has to name the row, so the citation reads in both directions.

    Without it, one general-purpose limitation entry answers any number of rows
    and nothing says which - and a reader of `docs/LIMITATIONS.md` cannot tell
    which taxonomy legs it is claimed to account for.
    """
    problems = []
    for row in _unreached(rows):
        match = re.search(r"docs/LIMITATIONS\.md §(\d+)", row.fields.get("Limitation", ""))
        if not match or int(match.group(1)) not in limitations:
            continue
        entry = limitations[int(match.group(1))]
        if row.id not in entry:
            problems.append(f"{row.where}: §{match.group(1)} never names {row.id}")
    assert not problems, "\n  " + "\n  ".join(problems)


def test_an_unreached_row_cites_no_test(rows):
    """An UNREACHED row states `none` for both halves.

    A row carrying a real node id under an UNREACHED status is either a status
    that should have moved or a citation nobody checks; both are worth a red run.
    """
    wrong = [f"{row.where}: Status is {row.fields['Status']!r} but {field} is "
             f"{row.fields.get(field)!r}"
             for row in _unreached(rows) for field in ("Refusal", "Control")
             if row.fields.get(field, "").strip().lower() != "none"]
    assert not wrong, "\n  " + "\n  ".join(wrong)
