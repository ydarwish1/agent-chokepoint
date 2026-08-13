"""Every refusal branch and every resolution branch of ``pep.canonicalize``.

These are unit tests on a REAL filesystem — a temp tree with real directories,
real symlinks and real permission bits — because the module's entire job is to
know things only a filesystem knows. A mocked ``os.stat`` here would test the
mock's idea of macOS.

**Two of these tests are filesystem-dependent and say so in their names.** This
repo is developed on APFS (case-insensitive) and CI runs ubuntu-latest
(case-sensitive), and the correct behaviour is *different* on the two: on APFS
``.SSH`` must be corrected to the on-disk ``.ssh``, and on ext4 it must be left
alone, because there the two really are different files and folding them would
be a false BLOCK. Each is skipped on the volume where its claim is false, so
the pair covers both worlds and neither lies about the one it is not running
on.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from pep import (
    RULE_UNRESOLVABLE_PATH,
    UnresolvablePath,
    canonical_path,
    canonicalized_arguments,
)

MARKER = "PRIVATE-KEY-MARKER"

# The spellings B-028 and B-029 were found with. Written as escapes and never as
# literal bytes: a lone COMBINING ACUTE ACCENT is invisible in a diff, and a
# vector whose whole point is which code points it contains must not depend on
# an editor's idea of how to normalize this source file.
LONG_S = "\u017f"                 # LATIN SMALL LETTER LONG S
DZE = "\u0455"                    # CYRILLIC SMALL LETTER DZE: a homoglyph, not a fold
NFD_CAFE = "cafe\u0301"           # c a f e + COMBINING ACUTE ACCENT
NFC_CAFE = "caf\u00e9"            # c a f + LATIN SMALL LETTER E WITH ACUTE


def _volume_is_case_insensitive() -> bool:
    """Measured, not assumed, and measured on the volume the tests build on."""
    with tempfile.TemporaryDirectory() as tmp:
        (Path(tmp) / "CaseProbe").write_text("x", encoding="utf-8")
        return (Path(tmp) / "caseprobe").exists()


def _volume_is_normalization_insensitive() -> bool:
    """A SEPARATE property from case insensitivity, so it gets its own probe.

    APFS is normalization-insensitive and normalization-PRESERVING: it opens a
    directory created NFD when it is spelled NFC, and ``scandir`` still hands
    back the NFD bytes it stored. ext4 is neither. Deriving one from the other
    would be assuming what B-029 is about.
    """
    with tempfile.TemporaryDirectory() as tmp:
        (Path(tmp) / NFD_CAFE).write_text("x", encoding="utf-8")
        return (Path(tmp) / NFC_CAFE).exists()


CASE_INSENSITIVE = _volume_is_case_insensitive()
NORMALIZATION_INSENSITIVE = _volume_is_normalization_insensitive()

# A root-owned process bypasses the permission bits these two tests rely on, so
# the refusal they check would never fire and the test would fail for a reason
# that is not the code's.
UNPRIVILEGED = hasattr(os, "geteuid") and os.geteuid() != 0


@pytest.fixture
def root(tmp_path: Path) -> Path:
    """``tmp_path``, resolved.

    Everything this module returns has been through ``realpath``, so a test
    that compared against the raw ``tmp_path`` would be asserting that macOS
    does not symlink ``/var`` to ``/private/var``. It does.
    """
    return Path(os.path.realpath(tmp_path))


@pytest.fixture
def tree(root: Path) -> Path:
    """B-008's repro as a fixture: a symlink out of the sandbox, and a real
    ``.ssh`` directory so B-007's case resolution has something to resolve."""
    (root / "workspace" / ".ssh").mkdir(parents=True)
    (root / "workspace" / ".ssh" / "id_rsa").write_text(MARKER, encoding="utf-8")
    (root / "workspace" / "public").mkdir()
    (root / "home" / "alice" / ".ssh").mkdir(parents=True)
    (root / "home" / "alice" / ".ssh" / "id_rsa").write_text(MARKER, encoding="utf-8")
    os.symlink(str(root / "home" / "alice" / ".ssh"), str(root / "workspace" / "public" / "keys"))
    return root


# ------------------------------------------------------------------ refusals


@pytest.mark.parametrize("raw", [None, 7, [], b"/workspace/x", "", {}])
def test_a_path_that_is_not_a_non_empty_string_is_refused(raw):
    with pytest.raises(UnresolvablePath) as exc:
        canonical_path(raw)
    assert "non-empty string" in str(exc.value)


@pytest.mark.parametrize("raw", ["~", "~/.ssh/id_rsa", "~alice/.ssh/id_rsa"])
def test_a_home_relative_path_is_refused(raw):
    """The PEP has no more right to guess a home than the engine does (D-017).

    ``os.path.expanduser`` would answer — with THIS process's home, which in a
    container is the proxy's and not the user's. That is B-002 pointed at a
    call path instead of a policy prefix.
    """
    with pytest.raises(UnresolvablePath) as exc:
        canonical_path(raw)
    assert "'~'" in str(exc.value)


@pytest.mark.parametrize("raw", ["notes.txt", "./notes.txt", ".ssh/id_rsa", "../etc/passwd"])
def test_a_relative_path_is_refused(raw):
    """B-006's rule: the PEP cannot know the TOOL's working directory.

    ``realpath`` would happily resolve these — against the enforcement point's
    own cwd, which is a different directory in every deployment and is not the
    one the tool will open from.
    """
    with pytest.raises(UnresolvablePath) as exc:
        canonical_path(raw)
    assert "not absolute" in str(exc.value)


def test_a_symlink_loop_is_refused(root: Path):
    """The branch non-strict mode would swallow.

    Measured: ``realpath(strict=True)`` raises ``OSError`` errno 62 (ELOOP)
    here, while ``strict=False`` returns the unresolved string with no error at
    all. Retrying unconditionally would turn "I could not resolve this" into an
    answer, so the retry is narrowed to the two absent-name errors and this
    path refuses.
    """
    os.symlink(str(root / "b"), str(root / "a"))
    os.symlink(str(root / "a"), str(root / "b"))
    with pytest.raises(UnresolvablePath) as exc:
        canonical_path(str(root / "a" / "x"))
    assert "resolving symlinks" in str(exc.value)


@pytest.mark.skipif(not UNPRIVILEGED, reason="running as root bypasses the permission bits")
def test_an_unreadable_component_is_refused(root: Path):
    """EACCES during ``realpath`` — a failure to resolve, not an absent name."""
    closed = root / "closed"
    (closed / "child").mkdir(parents=True)
    os.chmod(closed, 0o000)
    try:
        with pytest.raises(UnresolvablePath) as exc:
            canonical_path(str(closed / "child" / "leaf.txt"))
    finally:
        os.chmod(closed, 0o755)  # so pytest can clean the tree up
    assert "PermissionError" in str(exc.value)


@pytest.mark.skipif(not UNPRIVILEGED, reason="running as root bypasses the permission bits")
def test_an_unlistable_parent_is_refused(root: Path):
    """EACCES during the CASE walk, which is a different branch from the one
    above: mode ``0o111`` is searchable but not listable, so ``realpath``
    succeeds on the full path and ``scandir`` is the call that fails. Without
    its own refusal that would raise out of the door as a crash where a
    decision belongs.
    """
    nolist = root / "nolist"
    (nolist / "child").mkdir(parents=True)
    (nolist / "child" / "leaf.txt").write_text("x", encoding="utf-8")
    os.chmod(nolist, 0o111)
    try:
        assert os.path.realpath(str(nolist / "child" / "leaf.txt"), strict=True)  # realpath is fine
        with pytest.raises(UnresolvablePath) as exc:
            canonical_path(str(nolist / "child" / "leaf.txt"))
    finally:
        os.chmod(nolist, 0o755)
    assert "listing a parent directory" in str(exc.value)


# ---------------------------------------------------------------- resolution


@pytest.mark.skipif(
    Path("/workspace").exists(),
    reason="this test's premise is that /workspace is absent (true on CI; this host is /workspace)",
)
def test_a_wholly_non_existent_absolute_path_is_the_identity():
    """Why the existing corpus survives this change untouched.

    Every ``/workspace/...`` path in the test suite, in ``run_demo.py`` and in
    ``side_by_side.py`` names a directory that does not exist on any machine
    this runs on. ``realpath`` returns such a path unchanged and the case walk
    stops at the first missing component, so canonicalization is the identity
    on all of them and no existing expectation moves.
    """
    assert canonical_path("/workspace/notes.txt") == "/workspace/notes.txt"
    assert canonical_path("/workspace/.ssh/id_rsa") == "/workspace/.ssh/id_rsa"


def test_a_missing_absolute_path_is_the_identity():
    """The same mechanism as the ``/workspace`` corpus, on a name this host
    cannot possibly have. The skip above is environment-shaped; this one always
    runs.
    """
    missing = "/this-path-must-not-exist-for-pep-canonicalize-tests"
    assert not Path(missing).exists()
    assert canonical_path(missing + "/notes.txt") == missing + "/notes.txt"
    assert canonical_path(missing + "/.ssh/id_rsa") == missing + "/.ssh/id_rsa"


def test_a_symlink_escape_is_resolved_to_its_target(tree: Path):
    """B-008. The kernel read is the control on the fixture itself: if the
    escape were not real, the block this enables would be theatre."""
    escaping = tree / "workspace" / "public" / "keys" / "id_rsa"
    assert escaping.read_text(encoding="utf-8") == MARKER  # the escape is real
    assert canonical_path(str(escaping)) == str(tree / "home" / "alice" / ".ssh" / "id_rsa")


def test_a_symlink_escape_with_a_missing_leaf_is_still_resolved(tree: Path):
    """The case ``strict=True`` alone cannot serve.

    ``write_file`` creates files that do not exist yet, so strict mode raises
    ``FileNotFoundError`` on the ordinary write. The non-strict retry still
    follows the escaping symlink, which is what keeps B-008 closed for writes
    and not only for reads.
    """
    escaping = tree / "workspace" / "public" / "keys" / "new-file.txt"
    assert not escaping.exists()
    assert canonical_path(str(escaping)) == str(tree / "home" / "alice" / ".ssh" / "new-file.txt")


def test_exact_spellings_are_returned_unchanged(tree: Path):
    """The overwhelmingly common case, and the one that must not be perturbed:
    every component matches an entry exactly, so nothing is substituted."""
    exact = tree / "workspace" / ".ssh" / "id_rsa"
    assert canonical_path(str(exact)) == str(exact)


@pytest.mark.skipif(not CASE_INSENSITIVE, reason="volume is case-sensitive; see the paired test")
@pytest.mark.parametrize("spelling", [".SSH", ".Ssh", ".sSh"])
def test_case_variant_is_corrected_on_a_case_insensitive_volume(tree: Path, spelling: str):
    """B-007. ``realpath`` does NOT do this — measured, it returns ``.SSH``
    unchanged — so the component walk is what closes the bypass."""
    given = tree / "workspace" / spelling / "id_rsa"
    assert given.read_text(encoding="utf-8") == MARKER  # the alias is real on this volume
    assert canonical_path(str(given)) == str(tree / "workspace" / ".ssh" / "id_rsa")


@pytest.mark.skipif(CASE_INSENSITIVE, reason="volume is case-insensitive; see the paired test")
def test_case_variant_is_left_verbatim_on_a_case_sensitive_volume(tree: Path):
    """The other half, and the reason the stat-identity check exists.

    On ext4 ``/workspace/.SSH`` and ``/workspace/.ssh`` are two different files
    and only one of them exists. Substituting would be a false BLOCK on the
    non-existent one — exactly the objection that kept case folding out of the
    engine (D-011's rejected alternative). ``os.stat`` on the given spelling
    raises here, the identity fails, and nothing is substituted.
    """
    given = tree / "workspace" / ".SSH" / "id_rsa"
    assert not given.exists()
    assert canonical_path(str(given)) == str(given)


@pytest.mark.skipif(not CASE_INSENSITIVE, reason="volume is case-sensitive; the alias does not exist")
@pytest.mark.parametrize(
    "spelling",
    ["." + LONG_S + LONG_S + "h", "." + LONG_S + "sh"],
    ids=["long-s-twice", "long-s-once"],
)
def test_a_non_ascii_case_fold_variant_is_corrected(tree: Path, spelling: str):
    """B-028: ``str.lower()`` is not a caseless match, and this module used it.

    LATIN SMALL LETTER LONG S (U+017F) lowercases to ITSELF and casefolds to
    ``s``. The old candidate test was ``name.lower() == component.lower()``, so
    the on-disk ``.ssh`` was never even a candidate for this spelling, nothing
    was substituted, and the deny list saw a name it had never heard of. The
    kernel, meanwhile, opens the same file -- which the first assertion below
    measures rather than assumes, because if the alias were not real on this
    volume the correction would be theatre.

    The two ``fold`` assertions are the single-variable A/B, in the test rather
    than in a comment: the old comparison still says these are different names,
    the new one says they are the same, and only the second matches what the
    filesystem just did.
    """
    given = tree / "workspace" / spelling / "id_rsa"
    assert given.read_text(encoding="utf-8") == MARKER   # the alias is real on this volume
    assert spelling.lower() != ".ssh"                    # what the pre-fix code compared
    assert spelling.casefold() == ".ssh"                 # what closes it
    assert canonical_path(str(given)) == str(tree / "workspace" / ".ssh" / "id_rsa")


@pytest.mark.skipif(
    not NORMALIZATION_INSENSITIVE, reason="volume is normalization-sensitive; see the paired test"
)
def test_a_normalization_variant_ancestor_does_not_abandon_the_walk(tree: Path):
    """B-029, and the reason the walk no longer stops at an unconfirmed name.

    APFS is normalization-insensitive and normalization-PRESERVING: a directory
    created NFD opens when spelled NFC, and ``scandir`` returns the NFD bytes.
    So an ANCESTOR can be perfectly real and still match neither the exact test
    nor any case fold of the stored spelling. The old walk gave up there and
    returned the remainder verbatim -- which left ``.SSH`` un-case-resolved and
    allowed the read, even though the ``.SSH`` component on its own was the one
    thing this module already knew how to fix.

    The three assertions below are the finding in order: the two spellings are
    different strings that ``casefold`` alone does not reconcile, the kernel
    treats them as one directory, and the canonical path now comes back with
    BOTH the ancestor and the leaf in their on-disk spelling.
    """
    nested = tree / "workspace" / NFD_CAFE / ".ssh"
    nested.mkdir(parents=True)
    (nested / "id_rsa").write_text(MARKER, encoding="utf-8")
    given = tree / "workspace" / NFC_CAFE / ".SSH" / "id_rsa"
    assert NFC_CAFE.casefold() != NFD_CAFE.casefold()    # casefold alone is not enough
    assert given.read_text(encoding="utf-8") == MARKER   # one directory to the kernel
    assert canonical_path(str(given)) == str(nested / "id_rsa")


@pytest.mark.skipif(
    NORMALIZATION_INSENSITIVE, reason="volume is normalization-insensitive; see the paired test"
)
def test_a_normalization_variant_is_left_verbatim_on_a_normalizing_volume(tree: Path):
    """The other half of B-029, and the reason the identity check still guards.

    On ext4 the NFC and NFD spellings are two different directories and only one
    of them exists, so substituting would be a false BLOCK on a path that names
    nothing -- the same objection that keeps case folding out of the engine.
    ``scandir`` on the NFC ancestor raises, the remainder comes back verbatim.
    """
    (tree / "workspace" / NFD_CAFE / ".ssh").mkdir(parents=True)
    given = tree / "workspace" / NFC_CAFE / ".SSH" / "id_rsa"
    assert not given.exists()
    assert canonical_path(str(given)) == str(given)


def test_a_homoglyph_is_not_folded_to_the_name_it_resembles(tree: Path):
    """The control on the widened candidate test, and it runs on every volume.

    CYRILLIC SMALL LETTER DZE (U+0455) renders like an ``s`` and is not one.
    ``_fold`` is Unicode's canonical caseless match, not a similarity score: if
    it reached homoglyphs, this module would start substituting names the kernel
    considers unrelated, and B-028's fix would have bought a false BLOCK class
    in exchange for a false ALLOW one.
    """
    given = tree / "workspace" / ("." + DZE + "sh") / "id_rsa"
    assert not given.exists()
    assert canonical_path(str(given)) == str(given)


@pytest.mark.parametrize("bad", ["\x00", "\ud800"], ids=["nul", "lone-surrogate"])
@pytest.mark.parametrize("parent", ["real", "absent"], ids=["real-parent", "absent-parent"])
def test_a_path_the_os_cannot_encode_is_refused_and_not_raised(tree: Path, bad: str, parent: str):
    """B-031: a bare ``ValueError`` walked straight out of this module.

    ``os.path.realpath``, ``os.stat`` and ``os.scandir`` raise ``ValueError`` --
    never ``OSError`` -- for a path the C layer cannot encode: an embedded NUL,
    or a lone surrogate. Nothing caught it, so the doors fell back on their
    outermost crash handler: the hook exited 2 with no decision JSON and **no
    decision event**, the proxy answered ``-32603 Internal server error`` with a
    traceback. Both fail closed, so the verdict was never wrong -- but the
    documented ``pep:unresolvable-path`` attribution was bypassed, the two doors
    answered differently, and an agent could delete its own audit-trail entry for
    any call by appending one byte.

    Parametrized over BOTH parents because which of the two ``realpath`` calls
    raises depends on the tree: with a real parent ``strict=True`` gets far
    enough to ``lstat`` the bad component and raises, with an absent parent it
    raises ``FileNotFoundError`` first and the ``ValueError`` surfaces from the
    non-strict retry. Catching only the one the first repro happened to hit
    would have closed half of it.
    """
    base = str(tree / "workspace") if parent == "real" else "/workspace"
    given = base + "/.ssh" + bad + "/id_rsa"
    with pytest.raises(UnresolvablePath) as exc:
        canonical_path(given)
    assert "the path failed" in str(exc.value)
    assert bad not in str(exc.value)  # the refusal message never echoes the path
    with pytest.raises(UnresolvablePath):
        canonicalized_arguments({"path": given})
    # The control, one code point apart: the same path without the unencodable
    # character resolves, so "refused" is not "refuses everything".
    assert canonical_path(base + "/.ssh/id_rsa").endswith("/.ssh/id_rsa")


@pytest.mark.skipif(CASE_INSENSITIVE, reason="a case-insensitive volume cannot hold both spellings")
def test_an_ambiguous_case_variant_is_left_verbatim(tree: Path):
    """"Exactly one" is load-bearing: two candidates means no proof."""
    (tree / "workspace" / ".SSH").mkdir()
    given = tree / "workspace" / ".Ssh" / "id_rsa"
    assert canonical_path(str(given)) == str(given)


def test_the_walk_stops_at_the_first_missing_component(tree: Path):
    """The remainder is left verbatim, case included: a component that does not
    exist cannot have children whose spelling this filesystem could prove."""
    given = tree / "workspace" / "NoSuchDir" / "Deep" / "Leaf.TXT"
    assert canonical_path(str(given)) == str(given)


def test_a_file_in_the_middle_of_the_path_stops_the_walk(tree: Path):
    """``NotADirectoryError`` is an absent-name error, not a resolution
    failure: the path is nonsense but it is the agent's nonsense, and
    deny-by-default is what answers it."""
    given = tree / "workspace" / ".ssh" / "id_rsa" / "deeper.txt"
    assert canonical_path(str(given)) == str(given)


def test_the_root_and_doubled_separators_are_normalized():
    """POSIX gives exactly two leading slashes an implementation-defined
    meaning and ``engine/predicates.py:_norm`` collapses them before comparing,
    so emitting them here would be a string the engine never matches."""
    assert canonical_path("/") == "/"
    assert canonical_path("//workspace/x") == "/workspace/x"


# ------------------------------------------------------- canonicalized_arguments


def test_arguments_get_a_copy_with_only_the_path_replaced(tree: Path):
    given = {"path": str(tree / "workspace" / "public" / "keys" / "id_rsa"), "encoding": "utf-8"}
    out = canonicalized_arguments(given)
    assert out is not given                      # a copy, never in-place
    assert given["path"].endswith("/public/keys/id_rsa")  # the caller's dict is untouched
    assert out["path"] == str(tree / "home" / "alice" / ".ssh" / "id_rsa")
    assert out["encoding"] == "utf-8"


@pytest.mark.parametrize(
    "arguments",
    [None, {}, {"command": "ls -la"}, {"path": None}, {"path": 7}, {"path": ""}, {"path": []}],
    ids=["none", "empty", "no-path", "null-path", "int-path", "empty-path", "list-path"],
)
def test_arguments_without_a_resolvable_path_are_returned_unchanged(arguments):
    """Not a refusal, deliberately. The engine already treats an absent or
    malformed path as an unsatisfied predicate and deny-by-default catches the
    call; refusing here would turn every argument-free tool call into an error.
    """
    assert canonicalized_arguments(arguments) is arguments


@pytest.mark.parametrize("raw", ["~/.ssh/id_rsa", "notes.txt"])
def test_arguments_carrying_an_unresolvable_path_raise(raw):
    with pytest.raises(UnresolvablePath):
        canonicalized_arguments({"path": raw})


# ------------------------------------------------------------------ contracts


def test_the_rule_id_is_the_one_string_both_doors_emit():
    """``hooks/demo/side_by_side.py`` compares rule ids across the two doors, so
    a second spelling of this constant would surface as the two doors
    disagreeing rather than as a typo."""
    assert RULE_UNRESOLVABLE_PATH == "pep:unresolvable-path"


def test_importing_pep_does_not_import_the_engine():
    """D-011's whole point: ``engine/`` is untouched and stays a pure PDP.

    Asserted in a subprocess with a clean interpreter, because in-process the
    engine is already imported by every other test in the suite and the check
    would pass vacuously.
    """
    probe = "import pep, sys; print(sorted(m for m in sys.modules if m in {'engine', 'policy'}))"
    done = subprocess.run(
        [sys.executable, "-c", probe],
        cwd=str(Path(__file__).resolve().parents[2]),
        capture_output=True,
        text=True,
    )
    assert done.returncode == 0, done.stderr
    assert done.stdout.strip() == "[]"
