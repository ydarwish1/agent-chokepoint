"""Resolve a call path against the real filesystem, or refuse it (D-011).

This module is the whole of D-011's mechanism. The engine is pure and has no
filesystem, so it cannot know that ``/workspace/.SSH/id_rsa`` and
``/workspace/.ssh/id_rsa`` name the same file (B-007), nor where a symlink
points (B-008). An enforcement point can. ``engine/predicates.py``'s
``_resolvable_path`` docstring named this fix before it existed: "If
canonicalization is ever wanted, it belongs in the enforcement point (which may
call ``realpath``), not here — and it would then have to be a filesystem the
tool actually shares."

Two rules govern everything below:

* **Resolve, then judge.** The engine is handed the canonical path; the TOOL is
  handed the arguments the agent sent, unmodified. Rewriting the tool's
  arguments would make the two doors behave differently — a PreToolUse hook
  returns a verdict, not modified input, so it physically cannot rewrite them.
  The residual decide-then-open race is stated in ``docs/LIMITATIONS.md``.
* **Fail loudly, never open.** A path this module cannot resolve is refused
  with :class:`UnresolvablePath`, never passed through unresolved. That is the
  rule B-006 established for the engine and D-011 extends to the doors.

Measured on this machine, 2026-08-02 (macOS 15, APFS, Python 3.14.6); each
number below drove a design choice rather than confirming one after the fact:

===============================================  ==============================
probe                                            result
===============================================  ==============================
``realpath('<t>/workspace/.SSH/id_rsa')``        ``.SSH`` unchanged — realpath
                                                 does NOT fix case
``realpath(<missing leaf>, strict=True)``        ``FileNotFoundError``
``realpath(<symlink loop>, strict=True)``        ``OSError`` errno 62 (ELOOP)
``realpath(<symlink loop>, strict=False)``       no raise — returns the path
``realpath(<EACCES dir>/x, strict=True)``        ``PermissionError`` errno 13
``realpath(<EACCES dir>/x, strict=False)``       no raise — returns the path
``scandir(<mode 0o000 dir>)``                    ``PermissionError`` errno 13
===============================================  ==============================

The last four rows are why the retry is narrowed to ``FileNotFoundError`` and
``NotADirectoryError``: non-strict mode swallows a symlink loop and an EACCES
and hands back a path that was never resolved. Retrying unconditionally would
turn "I could not resolve this" into "here is your answer", which is the
fail-open this module exists to prevent.

Re-measured 2026-08-02 on the same machine, after the first version of this
module shipped. Three rows it did not have, and each one was a live bypass
rather than a rough edge (B-028, B-029, B-030):

==============================================  ===============================
probe                                           result
==============================================  ===============================
LATIN SMALL LETTER LONG S (U+017F) twice, as    kernel opens ``.ssh``'s file;
``.<U+017F><U+017F>h``                          ``str.lower()`` leaves it alone
                                                and ``casefold()`` folds it to
                                                ``.ssh``
"cafe" + acute, stored NFD, spelled NFC         same directory to the kernel;
                                                unequal as ``str``, unequal
                                                after ``lower()``, unequal
                                                after ``casefold()``, equal
                                                only once both are NFD
``realpath('<real tree>/x\\x00/y', strict=1)``   bare ``ValueError`` -- not an
``os.stat`` / ``os.scandir`` on the same        ``OSError``, so the refusal
                                                path never fired
==============================================  ===============================

They are three faces of one mistake: this module compared **spellings** where
the kernel compares **names**. The comparison is now Unicode's canonical
caseless match (:func:`_fold`), the walk no longer abandons the path at the
first component it cannot confirm, and every syscall that can fail with a
``ValueError`` instead of an ``OSError`` refuses like any other failure to
resolve.
"""

from __future__ import annotations

import os
import unicodedata
from typing import Any, Mapping

# The rule id BOTH enforcement points emit for this refusal. It lives here, not
# in either door, because `hooks/demo/side_by_side.py` compares the two doors'
# rule ids and reports any difference as a disagreement: two copies of a string
# literal are two chances to drift, and the drift would surface as that harness
# failing rather than as an obvious typo.
RULE_UNRESOLVABLE_PATH = "pep:unresolvable-path"

# The one argument key this module touches. `engine/predicates.py` documents
# `arguments["path"]` as the binding for BOTH path predicates, so canonicalizing
# any other key would resolve a string no predicate reads.
PATH_ARGUMENT = "path"


class UnresolvablePath(ValueError):
    """A path the enforcement point was asked to resolve and could not.

    Always converted to a block at the door, never passed through: an
    enforcement point that forwards a path it could not place is certifying a
    file it cannot name. Deliberately NOT raised for a call that simply carries
    no path — that is an unsatisfied predicate, which deny-by-default already
    handles, and refusing it would turn every argument-free tool call into an
    error.
    """


def canonical_path(raw: str) -> str:
    """The path the tool will actually open, or :class:`UnresolvablePath`.

    Four refusals, in order. The first three are spellings whose meaning
    depends on state this process does not share with the tool; the fourth is a
    real failure to resolve.

    1. Not a non-empty ``str`` — there is nothing to resolve.
    2. A leading ``~``. The PEP has no more right to guess which home directory
       that means than the engine does: expanding it binds the decision to the
       home of whichever process happens to be judging, which is D-017's
       finding about policy prefixes (B-002) pointed at call paths instead. In
       a container the proxy's ``$HOME`` is not the user's.
    3. Not absolute. The PEP cannot know the *tool's* working directory —
       B-006's rule. ``realpath`` would resolve it against the PEP's own cwd,
       which is a different directory in every deployment.
    4. An ``OSError`` other than ``FileNotFoundError``/``NotADirectoryError``,
       **or a ``ValueError``**, anywhere in resolution: a symlink loop, an
       EACCES, a stat that fails for a reason that is not "absent". Those are
       failures to resolve, and a failure to resolve is a refusal.

    The ``ValueError`` half of 4 is B-031, and it was a real hole rather than
    tidiness. ``os.path.realpath``, ``os.stat`` and ``os.scandir`` raise a bare
    ``ValueError`` -- never an ``OSError`` -- for a path the C layer cannot even
    encode: an embedded NUL, or a lone surrogate. Measured, the NUL escaped this
    function uncaught, and both doors then fell back on their outermost crash
    handler: the hook exited 2 with a raw ``repr`` on stderr and **no decision
    event**, the proxy answered ``-32603 Internal server error`` with a full
    traceback and ``rule_id: None``. Both failed CLOSED, so no wrong verdict --
    but an agent could suppress its own audit-trail entry for any call by
    appending one byte, and the two doors answered differently about the same
    path, which is the one property this project's two-door equivalence exists
    to hold. Refusal 4 now covers it, so the answer is ``pep:unresolvable-path``
    at both doors like every other unplaceable path.

    Otherwise the path comes back with symlinks followed and, where this
    filesystem proves it, the on-disk spelling of each component substituted.
    """
    if not isinstance(raw, str) or not raw:
        raise UnresolvablePath(
            "path argument is not a non-empty string, so there is nothing to resolve"
        )
    if raw.startswith("~"):
        raise UnresolvablePath(
            "path starts with '~': the enforcement point cannot know which home "
            "directory the TOOL would expand that against, and expanding it here "
            "would bind the decision to this process's own home (see D-017/B-002)"
        )
    if not os.path.isabs(raw):
        raise UnresolvablePath(
            "path is not absolute: the enforcement point cannot know the tool's "
            "working directory, so it cannot place this path (see B-006)"
        )
    return _case_resolved(_symlinks_resolved(raw))


def canonicalized_arguments(arguments: Mapping[str, Any] | None) -> Mapping[str, Any] | None:
    """A copy of ``arguments`` with ``path`` canonicalized, or it unchanged.

    Unchanged when there is no ``path`` key, or when its value is not a
    non-empty string. That is deliberately NOT a refusal: the engine already
    treats an absent or malformed path as an unsatisfied predicate and
    deny-by-default catches the call. Refusal is reserved for a path we were
    asked to resolve and could not — a call that carries no path never asked.
    """
    if not isinstance(arguments, Mapping):
        return arguments
    raw = arguments.get(PATH_ARGUMENT)
    if not isinstance(raw, str) or not raw:
        return arguments
    canonical = dict(arguments)
    canonical[PATH_ARGUMENT] = canonical_path(raw)
    return canonical


# ------------------------------------------------------------------ symlinks


def _symlinks_resolved(raw: str) -> str:
    """``realpath``, strict first, non-strict only for a missing name (B-008).

    ``strict=True`` is the mode that reports a failure instead of guessing, and
    it is tried first for exactly that reason. It is unusable ALONE because a
    missing leaf is ordinary: ``write_file`` creates files that do not exist
    yet, and strict mode raises ``FileNotFoundError`` on every one of them.

    The retry is therefore narrowed to the two "that name is not there" errors.
    Non-strict mode still follows every symlink it can — measured, a symlink
    into ``<t>/home/alice/.ssh`` resolves even when the leaf under it is
    missing — so B-008's escape is caught on both paths. What non-strict mode
    also does is swallow a symlink loop and an EACCES and hand back the
    unresolved string, which is why those never reach it.

    Both calls also catch ``ValueError`` (B-031). It is listed AFTER the two
    absent-name errors and never around anything that calls back into this
    module, which matters because :class:`UnresolvablePath` is itself a
    ``ValueError``: a handler placed any wider would catch this module's own
    refusals and re-wrap them, losing the message that says which of the four
    refusals fired. Nothing inside either ``try`` below can raise one --
    ``os.path.realpath`` is C and the standard library, and it does not call us.

    Which of the two calls raises the ``ValueError`` depends on the tree, which
    is why both are covered rather than only the one the first repro happened to
    hit. Measured on a NUL path: with a real parent directory ``strict=True``
    gets far enough to ``lstat`` the NUL component and raises it; with an absent
    parent (``/workspace/...``, the shape the whole test corpus uses) strict mode
    raises ``FileNotFoundError`` first and the ``ValueError`` comes out of the
    non-strict retry instead.
    """
    try:
        return os.path.realpath(raw, strict=True)
    except (FileNotFoundError, NotADirectoryError):
        pass
    except (OSError, ValueError) as exc:
        raise UnresolvablePath(_resolution_failure("resolving symlinks in", exc)) from exc
    try:
        return os.path.realpath(raw, strict=False)
    except (OSError, ValueError) as exc:
        raise UnresolvablePath(_resolution_failure("resolving symlinks in", exc)) from exc


# ---------------------------------------------------------------------- case


def _case_resolved(path: str) -> str:
    """Each component replaced by its on-disk spelling where that is PROVEN.

    ``realpath`` does not do this: measured on this case-insensitive volume,
    ``realpath('<t>/workspace/.SSH/id_rsa')`` returns ``.SSH`` unchanged while
    the kernel opens the file written as ``.ssh``. That is B-007 — the deny
    list defeated by one character's case.

    The walk starts at the root and, for each component, lists the parent:

    * an entry matching **exactly** is kept — the overwhelmingly common case,
      and the one that must not be perturbed;
    * otherwise, if **exactly one** entry is a canonical caseless match for the
      component (:func:`_fold`) AND ``os.stat`` says the given spelling and that
      entry are the same ``(st_dev, st_ino)``, the on-disk spelling is
      substituted;
    * otherwise the component is kept exactly as given, and the walk carries on
      to the next one.

    The stat-identity check is what makes this correct on a case-**sensitive**
    filesystem, where it is not a no-op but a guard: there ``/workspace/.SSH``
    genuinely is not ``/workspace/.ssh``, ``os.stat`` on the given spelling
    raises ``FileNotFoundError``, the identity fails and nothing is
    substituted. Folding case unconditionally would produce a false BLOCK on
    Linux, which is precisely the objection that kept this fix out of the
    engine (D-011's rejected alternative). It is also what makes the widened
    candidate test of B-028/B-029 safe: :func:`_fold` decides only what is worth
    ``stat``-ing, and identity decides what is substituted.

    **The walk used to stop at the first component it could not confirm**, on
    the reasoning that a component which does not exist cannot have children
    whose spelling this filesystem could prove. That reasoning is sound for the
    case it was written about -- an ABSENT parent, which is the ``scandir``
    branch below and still returns early -- and false for the case it was
    actually applied to. B-029: a directory created NFD opens when spelled NFC,
    so an ancestor can be perfectly real, perfectly openable, and still fail
    both the exact and the folded test. The old walk abandoned the path there
    and left every component below it un-case-resolved, which silently disabled
    the deny list for the whole subtree: measured, ``<t>/workspace/<NFC
    cafe>/.SSH/id_rsa`` came back ``allow`` while ``<t>/workspace/<NFC
    cafe>/.ssh/id_rsa`` blocked, on the same file.

    So an unconfirmed component now keeps its given spelling and the walk
    continues. **What that costs**, stated rather than waved at: up to one
    ``scandir`` per remaining component instead of stopping, on paths whose
    ancestors this module cannot confirm -- bounded by path depth, the same
    order as the walk already is, and paid only after an exact match has already
    failed. **What it cannot cost**, which is why it is safe: the next parent is
    the GIVEN spelling, so on a case-sensitive volume where that spelling does
    not exist ``scandir`` raises ``FileNotFoundError`` on the very next
    iteration and the remainder comes back verbatim -- byte for byte the old
    answer. The change is only ever visible where the unconfirmed component is
    one the kernel can actually open, and there the old answer was wrong.

    Leading ``//`` is collapsed on the way out (the join below always emits one
    leading slash). POSIX gives exactly two leading slashes an
    implementation-defined meaning and ``engine/predicates.py:_norm`` collapses
    them before comparing, so emitting them here would be a string the engine
    never compares against a prefix.
    """
    components = [component for component in path.split("/") if component]
    resolved: list[str] = []
    for index, component in enumerate(components):
        parent = _joined(resolved)
        try:
            with os.scandir(parent) as entries:
                names = {entry.name for entry in entries}
        except (FileNotFoundError, NotADirectoryError):
            # The parent is not there. Nothing below it can be confirmed by any
            # number of further syscalls, so this early return is the one the
            # original reasoning was right about.
            return _joined(resolved + components[index:])
        except (OSError, ValueError) as exc:
            raise UnresolvablePath(_resolution_failure("listing a parent directory of", exc)) from exc
        if component in names:
            resolved.append(component)
            continue
        # Folded once, outside the comprehension: this is O(entries) per
        # unconfirmed component and it only runs after the exact match failed,
        # so the common path pays nothing for it.
        wanted = _fold(component)
        aliases = [name for name in names if _fold(name) == wanted]
        if len(aliases) == 1 and _same_file(_joined(resolved + [component]), _joined(resolved + aliases)):
            resolved.append(aliases[0])
            continue
        resolved.append(component)
    return _joined(resolved)


def _fold(name: str) -> str:
    """One path component's Unicode canonical caseless key.

    ``NFD(casefold(NFD(x)))`` -- Unicode's D145, "canonical caseless match".
    Both halves are load-bearing and both replaced something measurably weaker:

    * **``casefold``, not ``lower``.** ``str.lower`` is not a caseless match.
      Measured: ``'.'`` + LATIN SMALL LETTER LONG S (U+017F) twice + ``'h'``
      lowercases to ITSELF and casefolds to ``'.ssh'``, and on this volume the
      kernel hands back ``.ssh/id_rsa``'s bytes when asked for the U+017F
      spelling. That is B-028 -- the same bypass B-007 named, one code point out
      of the ASCII range. U+017F is the classic instance and the full-fold table
      has around a hundred more, so enumerating them was never an option.
    * **NFD on both sides.** APFS is normalization-INSENSITIVE and
      normalization-PRESERVING: a directory created NFD opens when spelled NFC,
      and ``scandir`` hands back the NFD bytes it stored. Measured on "cafe"
      with an acute accent, the two spellings are unequal as ``str``, unequal
      after ``lower()``, unequal after ``casefold()``, and equal only once both
      are normalized. That is B-029.

    NFD **after** the fold rather than NFC, and applied a second time, because
    the fold table emits combining marks of its own -- LATIN CAPITAL LETTER I
    WITH DOT ABOVE (U+0130) casefolds to ``i`` + COMBINING DOT ABOVE -- so
    normalizing only the input would leave the two sides in different forms.

    This only ever widens the CANDIDATE set. A fold match on its own substitutes
    nothing: ``_same_file`` still has to prove ``(st_dev, st_ino)`` identity,
    which is what keeps the widening correct on a case-sensitive volume where
    the fold is a lie about the filesystem. Measured on this tree, ``.sshfoo``
    and ``notes.gitignore`` do not fold to ``.ssh`` and a Cyrillic homoglyph
    (U+0455) does not either -- the fold is a case/normalization equivalence,
    not a similarity score.
    """
    return unicodedata.normalize("NFD", unicodedata.normalize("NFD", name).casefold())


def _same_file(given: str, candidate: str) -> bool:
    """Are these two spellings the same file? ``(st_dev, st_ino)``, not names.

    ``FileNotFoundError``/``NotADirectoryError`` on the given spelling is the
    ordinary case-sensitive-filesystem answer — the spelling the agent sent
    simply is not there — and means "not the same file", not "cannot resolve".
    Any other ``OSError`` -- or a ``ValueError``, B-031 -- is a failure to
    resolve and refuses the whole path.
    """
    try:
        left = os.stat(given)
        right = os.stat(candidate)
    except (FileNotFoundError, NotADirectoryError):
        return False
    except (OSError, ValueError) as exc:
        raise UnresolvablePath(_resolution_failure("comparing a case variant of", exc)) from exc
    return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)


# --------------------------------------------------------------------- plumbing


def _joined(components: list[str]) -> str:
    return "/" + "/".join(components)


def _resolution_failure(stage: str, exc: BaseException) -> str:
    """The refusal message — error class and errno, never the path itself.

    ``str(OSError)`` embeds the filename, and this message travels into the
    decision event's ``reason`` and into the error the agent receives. The
    ``arguments`` field of that same event is the place a path belongs, and it
    is the field the redaction pass covers (``contains_sensitive``); a path
    copied into ``reason`` would be a second, unredacted copy of an argument
    that may carry a credential. B-015 is the same mistake made with a tool
    name. ``str(ValueError)`` does not embed the path, but it is left out for
    the same reason rather than for a different one -- one rule, not two.

    The errno is dropped when there is none. B-031's ``ValueError`` carries no
    ``errno`` attribute at all, and ``(errno=None)`` would read as an OS error
    that failed to say why rather than as an encoding failure that never
    reached the OS.
    """
    errno = getattr(exc, "errno", None)
    named = type(exc).__name__ if errno is None else f"{type(exc).__name__} (errno={errno})"
    return f"{stage} the path failed: {named}"
