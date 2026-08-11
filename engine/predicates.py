"""The fixed predicate vocabulary (D-006) and named argument matchers.

Every predicate answers one question about one tool call, deterministically,
with no I/O. A predicate that cannot find or parse what it needs is
UNSATISFIED — never an exception, never a pass. Combined with deny-by-default,
malformed input falls to ``defaults.on_no_match`` (block) instead of slipping
through.

That rule is about the CALL. A malformed *policy* is the opposite case: a
prefix the predicate cannot enforce raises, because an unenforceable deny
prefix silently reads as "not denied" and becomes an allow (see
:func:`_is_within` and B-006). Bad input fails closed; a broken rule fails
loudly.

Argument binding is fixed by convention for v0 policies and documented here:

====================================  =========================================
predicate                             reads
====================================  =========================================
``path_within``                       ``arguments["path"]``
``path_not_within``                   ``arguments["path"]``
``path_segment_not_in``               ``arguments["path"]`` (per component)
``domain_in``                         ``arguments["url"]`` (parsed hostname)
``command_matches_any``               ``arguments["command"]`` (regex search)
``args_match_any``                    every string anywhere in ``arguments``
``args_contain_invisible_characters`` every string anywhere in ``arguments``
``args_contain_hidden_context``       every string anywhere in ``arguments``
====================================  =========================================

Making the binding explicit in the policy schema is a known v1 question; the
convention keeps v0 readable, which is the bar a policy file has to clear — a
reader must be able to predict a decision from the file.
"""

from __future__ import annotations

import posixpath
import re
import string
from typing import Any, Callable, Iterator, Mapping
from urllib.parse import urlsplit

Args = Mapping[str, Any]
Predicate = Callable[[Any, Args], bool]


# ---------------------------------------------------------------- paths

def _norm(path: str) -> str:
    """Normalize a path for prefix comparison.

    ``..`` never reaches here — :func:`_resolvable_path` rejects it — so this is
    only collapsing ``.`` and redundant separators. POSIX gives a leading ``//``
    implementation-defined meaning and ``posixpath.normpath`` preserves exactly
    two leading slashes, so ``//etc/passwd`` would not compare against ``/etc/``;
    collapse it first.
    """
    normalized = posixpath.normpath(path)
    if normalized.startswith("//"):
        normalized = "/" + normalized.lstrip("/")
    return normalized


def _is_within(path: str, prefix: str) -> bool:
    """True iff normalized ``path`` sits at or under absolute ``prefix``.

    ``prefix`` MUST be absolute. A relative one raises rather than returning
    ``False``, because here a ``False`` becomes an ALLOW one level up:
    :func:`path_not_within` returns ``not any(_is_within(...))``, so a deny
    prefix that quietly matched nothing would report "this path is not in the
    denied set", the rule would match, and the call would be allowed. That
    silent fail-open is B-006 — the shipped ``fs-read-scoped`` paired a relative
    ``path_within`` with absolute deny prefixes, its deny half changed 0 of 15
    path decisions, and ``read_file`` on ``.ssh/id_rsa`` came back ALLOW.

    ``policy/loader.py`` rejects a relative prefix at load time, so this raise is
    unreachable for any loaded policy; it fires only for a :class:`Policy` built
    by hand around the loader. It mirrors ``decide.py``'s refusal of an unknown
    predicate: fail loudly, never open.
    """
    if not prefix.startswith("/"):
        raise ValueError(
            f"path prefix {prefix!r} is not absolute — path prefixes must be "
            "absolute. A relative prefix cannot be compared against the paths "
            "this engine judges (it refuses relative call paths outright), so "
            "it would silently match nothing and turn path_not_within into an "
            "allow. Fail loudly, never open."
        )
    p = _norm(path)
    pre = _norm(prefix)
    if not p.startswith("/"):
        return False
    return p == pre or p.startswith(pre.rstrip("/") + "/")


def _resolvable_path(args: Args) -> str | None:
    """The candidate path, or ``None`` if absent or unresolvable.

    Three spellings are unresolvable to a *pure* engine, and all three are
    bypasses if judged textually:

    * A leading ``~`` is an alias for an absolute path the engine cannot expand
      (no home directory, no I/O) — but the tool WOULD expand it, so
      ``~/.ssh/id_rsa`` reads as an innocent relative path.
    * A ``..`` component cannot be collapsed soundly without the filesystem.
      ``posixpath.normpath`` rewrites ``/workspace/link/../etc/passwd`` to
      ``/workspace/etc/passwd`` and calls it in-scope, but if ``link`` is a
      symlink the kernel resolves the ORIGINAL string somewhere else entirely —
      the tool opens the file the engine just certified as safe. Textual
      collapsing is guesswork about a filesystem the engine cannot see.
    * A path that is not absolute names a different file depending on where the
      tool runs, and the engine cannot know the tool's working directory. If a
      filesystem MCP server is started in the user's home — an ordinary way to
      run one — then ``.ssh/id_rsa`` IS ``~/.ssh/id_rsa``. Placing it would be
      guessing. This is the engine half of B-006, where a relative
      ``path_within`` prefix made an absolute deny list unreachable and
      ``read_file`` on ``.ssh/id_rsa`` returned ALLOW.

    All three therefore satisfy neither ``path_within`` nor ``path_not_within``,
    and the call falls to deny-by-default. The cost is that an agent must send
    already-normalized absolute paths; the alternative is a gateway that
    certifies paths it cannot actually place. If canonicalization is ever
    wanted, it belongs in the enforcement point (which may call ``realpath``),
    not here — and it would then have to be a filesystem the tool actually
    shares.
    """
    path = args.get("path")
    if not isinstance(path, str) or not path or path.startswith("~"):
        return None
    if not path.startswith("/"):
        return None
    if ".." in path.split("/"):
        return None
    return path


def path_within(spec: Any, args: Args) -> bool:
    path = _resolvable_path(args)
    if path is None:
        return False
    return any(_is_within(path, prefix) for prefix in spec)


def path_not_within(spec: Any, args: Args) -> bool:
    path = _resolvable_path(args)
    if path is None:
        return False
    return not any(_is_within(path, prefix) for prefix in spec)


def path_segment_not_in(spec: Any, args: Args) -> bool:
    """True iff no COMPONENT of the call's path is one of the listed names.

    D-014, closing B-009. ``path_not_within`` denies a prefix, so it protects
    exactly the depth it is written at. Measured at HEAD ``bbb8d15`` against the
    shipped ``fs-read-scoped``: ``/workspace/.ssh/id_rsa`` blocked, while
    ``/workspace/project/.ssh/id_rsa``, ``/workspace/project/.aws/credentials``
    and ``/workspace/a/b/.git/config`` all came back **allow** — 3 of 3 nested
    credential directories open, with the rule reading as though it covered
    them. That is B-006's "reads protective, is not" failure in a narrower form.
    This predicate says the other thing: the NAME is denied wherever it appears.

    Comparison is exact per component, never substring, so
    ``/workspace/.sshfoo/file`` is not a ``.ssh`` hit. A substring test would
    also deny ``.gitignore`` and ``/workspace/mygitrepo``, and a deny rule that
    fires on ordinary files is one an operator stops writing. The leaf counts as
    a component: a *file* named ``.ssh`` is denied for the same reason the
    directory is.

    The path is read through :func:`_resolvable_path`, exactly like the other
    two, so a relative, ``~``-prefixed or ``..``-containing path is unresolvable
    at this entry point too and the rule simply does not match — B-006's rule is
    not re-opened by adding a predicate. And as everywhere in this module an
    unsatisfied predicate is a rule that does not fire, never an exception.

    What it sees, since D-011: both enforcement points canonicalize
    ``arguments["path"]`` before ``decide()`` is called, so the components
    compared here are the RESOLVED ones. A symlink named ``project`` pointing at
    ``/home/alice/.ssh`` arrives spelled ``/home/alice/.ssh/...`` and is caught;
    conversely a link *named* ``.ssh`` that resolves elsewhere is not. That is
    the intended direction — the deny list is about the file that will be
    opened — and it is a property of the doors, not of this function, which
    stays a pure comparison over whatever string it is handed.

    Rejected: enumerating more prefixes in the shipped policy (protects the
    depths someone thought of and silently misses the rest, which is the defect
    rather than the fix); redefining ``path_not_within`` to match at any depth
    (silently changes a predicate every existing rule uses, and "prefix" would
    stop meaning prefix).
    """
    path = _resolvable_path(args)
    if path is None:
        return False
    # `_norm` first so `/workspace//.ssh/x` and `/workspace/./.ssh/x` split the
    # same way `path_within` compares them; `..` never reaches here.
    segments = set(_norm(path).split("/"))
    return not any(name in segments for name in spec)


# ---------------------------------------------------------------- network

# Characters that make a URL's authority parse differently in different URL
# implementations. The engine decides with Python's urlsplit; the tool that
# performs the fetch usually does not. Any disagreement is an egress bypass, so
# an ambiguous URL is refused rather than resolved.
#
# The one that bites: WHATWG (browsers, Node/undici, Deno, Bun — i.e. most
# TypeScript MCP fetch servers) treats a backslash as a path separator for
# http(s), so `https://evil.com\@pypi.org/x` is host `evil.com` there and host
# `pypi.org` to urlsplit. Judging it with urlsplit alone allowlists the attacker.
_AMBIGUOUS_URL_CHARS = frozenset('\\"<>^{}|`')
_ALLOWED_URL_SCHEMES = frozenset({"http", "https"})


def _unambiguous_host(url: Any) -> str | None:
    """The URL's host, or ``None`` if any parser could disagree about it.

    Refused, in order: non-strings; anything outside printable ASCII (control
    characters and whitespace are stripped by some parsers and rejected by
    others; non-ASCII invites IDN homographs); the characters above; a scheme
    that is not http(s); and anything urlsplit cannot parse into a host.
    """
    if not isinstance(url, str) or not url:
        return None
    if any(ch < "\x21" or ch > "\x7e" for ch in url):
        return None
    if _AMBIGUOUS_URL_CHARS & set(url):
        return None
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    if parts.scheme.lower() not in _ALLOWED_URL_SCHEMES:
        return None
    try:
        host = parts.hostname
    except ValueError:
        return None
    return host or None


def domain_in(spec: Any, args: Args) -> bool:
    """Exact hostname match against an unambiguously-parsed URL.

    ``urlsplit().hostname`` strips port and userinfo, so the plain userinfo
    spoof ``https://good.org@evil.com/`` correctly resolves to ``evil.com``.
    Spellings where parsers disagree are refused outright — see
    :func:`_unambiguous_host`.
    """
    host = _unambiguous_host(args.get("url"))
    if host is None:
        return False
    return host.lower() in {entry.lower() for entry in spec}


# ---------------------------------------------------------------- commands

def command_matches_any(spec: Any, args: Args) -> bool:
    command = args.get("command")
    if not isinstance(command, str):
        return False
    return any(re.search(pattern, command) for pattern in spec)


# ---------------------------------------------------------------- arg scans

# Named matchers for ``args_match_any``. A fixed list of published credential
# formats — deliberately NOT entropy scoring and NOT a classifier. D-027
# settled that open question that way, and the published event schema
# documents the same list with the same limits (a credential in a format not
# listed here is not detected). Each pattern is a published credential format,
# not a guess. Widening the list means, per new pattern: a secret-shaped
# positive control AND its nearest benign neighbour in
# ``engine/tests/test_predicates.py`` (D-021 applies to matchers exactly as to
# rules — B-041 is what a pattern with neither looks like), plus the schema's
# redaction wording and the egress Sigma rule's false-positive note updated in
# the same commit.
_SECRET_PATTERNS = (
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),          # AWS access key id
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),  # GitHub token family
    re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b"),  # Slack token family
    re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),      # Google API key
)
_PRIVATE_KEY_PATTERN = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")


# B-014: this walk recursed once per nesting level, so ``decide()`` raised
# ``RecursionError`` on deeply nested ``arguments`` — 20 000 levels, measured at
# HEAD bbb8d15. That contradicts this module's own contract that a predicate is
# "never an exception", and the shape is what matters: in the proxy an exception
# out of ``decide()`` suppresses the decision event, and an enforcement point
# that crashes while judging has no verdict to enforce.
#
# The walk is ITERATIVE rather than recursion with a depth counter. A counter
# still burns one frame per level, so its safe ceiling is whatever the CALLER
# left on the stack — and this engine is a library: the proxy reaches it from
# inside an asyncio handler, the hook from ``main()``, a test from pytest.
# Measured on CPython 3.14.6, the recursive version survived 993 nesting levels
# called from a bare two-frame stack and fewer from any deeper one, so one
# payload could decide in a test and raise in production. An explicit stack
# decouples the bound from the caller: the constant below is then a statement
# about payloads rather than a guess about frame budget, and the same call
# decides the same way at every enforcement point.
#
# Why 1000:
#   * it clears the pre-fix ceiling (993 from a bare stack, less from any real
#     caller), so nothing this engine ever successfully scanned is truncated
#     now — the bound is the old reach minus the crash, not a reduction;
#   * the deepest structure anywhere in this repo's committed corpus is 6 levels
#     (``hooks/settings.example.json``, a settings file rather than a call), and
#     across the 32 ``arguments`` literals in the committed tree the deepest is
#     1, so legitimate call input sits three orders of magnitude below the cap;
#   * iterative makes height cheap: 0.34 ms to walk a 20 000-deep hostile
#     payload down to the cap, against 0.54 ms for a realistic wide one.
# A fixed constant, not ``sys.getrecursionlimit()``: reading the interpreter's
# limit would let the same call decide differently in two processes (a proxy
# that raised its limit would scan deeper than a hook that did not), and
# ``decide()`` is a pure function of policy and call. Nor can the doors be
# relied on to cap it — ``json.loads`` accepts 116 215 levels of nesting here.
_MAX_SCAN_DEPTH = 1000


def _strings_in(value: Any) -> Iterator[str]:
    """Every string anywhere in an argument structure — values, keys, list
    items, nested up to :data:`_MAX_SCAN_DEPTH` levels.

    What the bound costs, stated rather than hidden: the walk stops DESCENDING
    at the cap, it never stops scanning, so every string above the cap is still
    yielded and nothing shallower is skipped. A string buried below it is not
    seen, so ``args_match_any`` reports unsatisfied — and for the shipped
    ``net-egress-sensitive`` (a BLOCK rule) an unsatisfied predicate is a rule
    that does not fire. The residual risk of this fix is therefore a false ALLOW
    on a secret nested past 1000 levels, in the case where some other rule
    allows the call. Three things bound it: nothing legitimate is anywhere near
    the cap (the deepest ``arguments`` literal in the committed corpus is one
    level); deny-by-default still takes the call when no allow rule matches;
    and each tool reads its arguments at the binding depth
    documented at the top of this module (``url``, ``command``, ``path`` — depth
    1), so a string the tool never reads is not a string the tool exfiltrates.
    :func:`contains_sensitive` rides the same walk, so that same secret would
    also miss the enforcement points' log redaction. The alternative — treating
    unscannable input as MATCHING, which fails closed for a block rule —
    inverts to fail-open in an allow rule and contradicts this module's stated
    posture for input it cannot parse, so it is a policy-schema question rather
    than a predicate one.

    The bound also terminates a reference cycle, which an unbounded iterative
    walk would not. Neither enforcement point can deliver one (both parse JSON,
    which yields a tree), but ``arguments`` is typed as a Mapping and this
    engine judges what it is handed.
    """
    stack: list[tuple[Any, int]] = [(value, 0)]
    while stack:
        node, depth = stack.pop()
        if isinstance(node, str):
            yield node
        elif depth >= _MAX_SCAN_DEPTH:
            continue
        elif isinstance(node, Mapping):
            # Pushed in reverse so this LIFO stack yields keys and values in the
            # same order the recursive version did: the depth bound is the only
            # behaviour that changes.
            for k, v in reversed(list(node.items())):
                stack.append((v, depth + 1))
                stack.append((k, depth + 1))
        elif isinstance(node, (list, tuple)):
            for item in reversed(node):
                stack.append((item, depth + 1))


def _secret_like(text: str) -> bool:
    return any(p.search(text) for p in _SECRET_PATTERNS)


def _private_key_block(text: str) -> bool:
    return bool(_PRIVATE_KEY_PATTERN.search(text))


ARG_MATCHERS: dict[str, Callable[[str], bool]] = {
    "secret_like": _secret_like,
    "private_key_block": _private_key_block,
}


def args_match_any(spec: Any, args: Args) -> bool:
    matchers = [ARG_MATCHERS[name] for name in spec]  # loader guarantees names
    return any(m(s) for s in _strings_in(args) for m in matchers)


# ------------------------------------------------- characters nobody can see

#: Named classes of characters a human reader cannot see, for
#: :func:`args_contain_invisible_characters`. Each class is a fixed, enumerated
#: set of code points — the boring option D-027 already chose for the credential
#: formats, for the same reason: a set derived from a Unicode PROPERTY (say
#: ``Default_Ignorable_Code_Point``) is a set that changes with the interpreter's
#: Unicode version, and this engine's contract is that the same call decides the
#: same way at every enforcement point. That is the argument ``_MAX_SCAN_DEPTH``
#: already makes against reading ``sys.getrecursionlimit()``.
#:
#: The classes are separate because their FALSE-POSITIVE profiles are different,
#: and the class list is the operator's dial:
#:
#: ``zero_width``
#:     Renders as nothing. ``U+200C``/``U+200D`` are the exception inside this
#:     class and it is a measured one — they are ordinary in Persian, Arabic and
#:     Indic text and in emoji sequences (``docs/LIMITATIONS.md``, "Known
#:     false-positive sources"), so a deployment carrying such text leaves this
#:     class unarmed rather than fighting it.
#: ``bidi_controls``
#:     Reorders what a reader sees without changing a byte. This is the half of
#:     IL-8 that makes a payload "only visible when the user scrolls to the
#:     right".
#: ``c0_c1_controls``
#:     ``U+0000``–``U+001F``, ``U+007F`` and ``U+0080``–``U+009F``. **``U+0085``
#:     NEL is in here**, not in ``line_separators``: it sits inside
#:     ``[\x00-\x1F\x7F-\x9F]`` (measured — ``0x85`` is between ``0x7F`` and
#:     ``0x9F``), so the character class that misses the other two line
#:     terminators does not miss this one. This class also holds tab, LF and CR,
#:     which are ordinary in a file body — so it belongs on tools whose arguments
#:     are single-line (a url, a path, a command) and not on a `write_file`.
#: ``line_separators``
#:     ``U+2028`` and ``U+2029``, the two line terminators that really are
#:     outside that character class. ``str.splitlines()`` breaks on both, so they
#:     are the pair that turns one record into two for a reader that counts
#:     lines.
#: ``soft_hyphen``
#:     ``U+00AD`` renders as a hyphen at a line break and as nothing everywhere
#:     else. Its own class because its false-positive profile is text copied out
#:     of a typeset document, which is nothing like the others'.
#: ``tag_characters``
#:     ``U+E0000``–``U+E007F``, the Tags block. ``U+E0000 + ord(c)`` spells an
#:     ASCII string in code points that render as nothing, which is the shape
#:     that carries a whole instruction rather than one character — D-048, and
#:     the reason this class exists. Its false-positive profile is emoji TAG
#:     SEQUENCES: the RGI flags of England, Scotland and Wales are
#:     ``U+1F3F4`` followed by a subdivision code spelled in this block and
#:     ``U+E007F``, so an operator whose traffic carries those leaves this class
#:     unarmed. Measured, not assumed (``docs/LIMITATIONS.md`` false-positive
#:     class 14).
#: ``variation_selectors``
#:     ``U+FE00``–``U+FE0F`` and ``U+E0100``–``U+E01EF``. Zero-width by
#:     definition — they select a glyph for the character before them and render
#:     as nothing themselves. Its own class because its false-positive profile is
#:     the widest here and is entirely ordinary text: ``U+FE0F`` is in every emoji
#:     presentation sequence, ``U+FE0E`` in every text presentation sequence, and
#:     ``U+E0100`` upward in the ideographic variation sequences of Japanese
#:     typesetting.
#:
#: **This enumeration is not exhaustive, and cannot be.** Decision 2 of D-046
#: chose a fixed set over a Unicode PROPERTY, and D-048 states what that choice
#: costs rather than leaving it as an absence: code points a reader cannot see
#: that no class here holds are not seen at all. The residual is measured and
#: listed in ``docs/LIMITATIONS.md`` §21 item 4 and pinned by
#: ``engine/tests/test_predicates.py::TestTheEnumerationIsNotExhaustive``, which
#: goes red the day one of them is added — so growing the set is a deliberate
#: edit in both places and never a silent widening of a published claim.
INVISIBLE_CHARACTER_CLASSES: dict[str, frozenset[str]] = {
    # Written as code points, never as literal characters: a source file whose
    # own bytes are invisible is one nobody can review, and a copy-paste through
    # any editor that normalizes text would silently change the set.
    "zero_width": frozenset(
        chr(code) for code in [
            *range(0x200B, 0x200E),   # ZWSP, ZWNJ, ZWJ
            *range(0x2060, 0x2065),   # word joiner, the four invisible operators
            0xFEFF,                   # ZWNBSP / BOM
        ]
    ),
    "bidi_controls": frozenset(
        chr(code) for code in [
            *range(0x200E, 0x2010),   # LRM, RLM
            *range(0x202A, 0x202F),   # embedding, override, pop
            *range(0x2066, 0x206A),   # the four isolates
        ]
    ),
    "c0_c1_controls": frozenset(
        chr(code) for code in [*range(0x00, 0x20), 0x7F, *range(0x80, 0xA0)]
    ),
    "line_separators": frozenset(chr(code) for code in (0x2028, 0x2029)),
    "soft_hyphen": frozenset(chr(0x00AD)),
    "tag_characters": frozenset(chr(code) for code in range(0xE0000, 0xE0080)),
    "variation_selectors": frozenset(
        chr(code) for code in [
            *range(0xFE00, 0xFE10),   # VS1-VS16
            *range(0xE0100, 0xE01F0),  # VS17-VS256
        ]
    ),
}


def args_contain_invisible_characters(spec: Any, args: Args) -> bool:
    """True iff any string anywhere in ``arguments`` holds a character from one
    of the named classes above.

    D-046 and D-048, for IL-8's *hidden whitespace and unicode the user never
    sees* half: the WhatsApp MCP attack hid its payload in whitespace so it was
    "only visible when the user scrolls to the right". Every matcher beside this one reads what
    the text SAYS; this one reads what the reader cannot see, which is a
    different question and needs a different predicate rather than another entry
    in :data:`ARG_MATCHERS`.

    **Why not a matcher.** :func:`contains_sensitive` is the union of
    ``ARG_MATCHERS``, and it is what both enforcement points key log redaction on
    and what ``taint``'s ``secrets_only`` mode asks. Adding invisibility there
    would redact the arguments of every call carrying a tab and would attribute
    such a call to ``taint:secret-egress`` — a rule id naming a credential that
    is not there. The classes are their own predicate so that neither of those
    moves.

    **It decides; it does not normalize.** LLM09:2026's mitigation 2 asks for the
    class to be STRIPPED at extraction. This gateway returns allow/block/ask and
    forwards a call's arguments untouched, so what it can do with the class the
    mitigation names is refuse the call that carries it. The consequence is worth
    stating because it is easy to assume away: arming this changes nothing about
    what ``secret_like`` sees, so an AWS key id with a zero-width space in it is
    still invisible to ``net-egress-sensitive`` and is refused — under a policy
    that arms this predicate — by THIS rule and under THIS rule's id.
    ``docs/LIMITATIONS.md`` §21 carries the measurement.

    **What it does NOT see, which is a named set and not an absence.** The
    classes above are a fixed enumeration (D-046 Decision 2), so a code point a
    reader cannot see that no class holds passes this predicate with every class
    armed. That is a cost of the enumeration and D-048 measures it rather than
    asserting it away: with every class armed, ``U+180E``, ``U+3164``,
    ``U+FFA0``, ``U+115F``, ``U+2800`` and ``U+1D173`` — among others — are not
    detected. ``docs/LIMITATIONS.md`` §21 item 4 carries the measurement and
    ``TestTheEnumerationIsNotExhaustive`` holds it to the code.

    Homoglyphs are deliberately NOT here. That is confusable detection, a
    different mechanism with a real false-positive cost on legitimate non-Latin
    text, and the argument and its measurement are in D-046 and in
    ``docs/LIMITATIONS.md`` §21.

    Rides :func:`_strings_in`, so it inherits that walk exactly: dict keys are
    scanned as well as values, a non-string is ignored rather than coerced, and
    a string nested below :data:`_MAX_SCAN_DEPTH` is not seen (§18).
    """
    wanted: frozenset[str] = frozenset().union(
        *(INVISIBLE_CHARACTER_CLASSES[name] for name in spec)  # loader guarantees names
    )
    return any(not wanted.isdisjoint(text) for text in _strings_in(args))


# ------------------------------------------ operator-declared hidden context

#: Minimum length, in characters and after whitespace normalization, of a
#: segment derived from a hidden-context declaration (D-049). Fixed, not an
#: operator knob, for the reason :data:`_MAX_SCAN_DEPTH` is fixed: the same call
#: must decide the same way at every enforcement point.
#:
#: **Measured before it was chosen**, over this repository's tracked text files
#: — 171 of them at ``3a3b4f0`` under the filter the correction appended to D-049
#: states, a count that moves with the tree and means nothing without the ref
#: (**B-091**, **B-092**) — by declaring one of them and counting the segments
#: that also appear in some OTHER tracked file. Below the floor the collisions
#: are structure rather
#: than content and identify nothing — ```` ```markdown ```` (11) dies at 12,
#: ``|---|---|---|`` (13) at 16, ``# Agent-Chokepoint`` (18) and
#: ``agent-chokepoint/`` (17) at 24, ``| Project | What it is |`` (24) at 32. At
#: 32 every remaining collision in that corpus is a sentence that genuinely does
#: appear in both files, which is the matcher being right rather than a false
#: positive. What the floor costs is measured too: a 20-line declaration yields
#: 9 segments with no floor and 7 at 32. ``docs/LIMITATIONS.md`` false-positive
#: class 15 carries both halves.
HIDDEN_CONTEXT_MIN_SEGMENT_CHARS = 32

#: A segment ends at a line break or at a sentence terminator followed by
#: whitespace. Lines alone were measured first and rejected: a declaration
#: written as ONE paragraph then yields one all-or-nothing segment, and a single
#: reworded phrase inside it drops detection to zero, while the identical text
#: written a line per instruction yields six. Splitting on both makes the two
#: shapes behave the same — 6 segments each, and a one-word edit still leaves 5
#: of 6 matching. Mis-splitting an abbreviation (``e.g. foo``) only produces
#: shorter pieces, which the floor above then drops; it can never merge two
#: sentences into one.
_HIDDEN_CONTEXT_SEGMENT_SPLIT = re.compile(r"(?<=[.!?])\s+|\n")

#: ASCII case folding and nothing else. ``str.casefold()`` and ``str.lower()``
#: both consult Unicode case mappings, which change with the interpreter's
#: Unicode version — the exact property D-046 Decision 2 refused for this engine,
#: whose contract is that the same call decides the same way at every enforcement
#: point, and the proxy in a pod and the hook on a laptop are not one interpreter.
#: The ASCII mappings are frozen forever, and English prose re-cased mid-sentence
#: is the case that actually occurs.
_ASCII_CASE_FOLD = str.maketrans(string.ascii_uppercase, string.ascii_lowercase)


def normalized_for_comparison(text: str) -> str:
    """``text`` with whitespace runs collapsed to one space and ASCII case folded.

    Applied to the declared material AND to every argument string before they are
    compared. Two things it buys, both measured rather than assumed:

    * **Re-wrapping.** A recitation arrives as one JSON string with the newlines
      turned into ``\\n`` escapes or into spaces, and neither spelling should be
      the difference between a refusal and an allow.
    * **Re-casing.** A declared sentence quoted inside a longer one is re-cased
      at its first letter, and that alone defeated a case-sensitive matcher —
      measured: the declared *The internal billing service is reachable at
      billing.acme.internal on port 8443.* is not a substring of *FYI the
      internal billing service is reachable … Please advise.* until both sides
      are folded.

    What the fold costs was measured over this repository's tracked text before
    it was taken, by declaring four of its own documents and counting the
    segments that also appear in another file. Stated with the ref it was
    measured at, because a segment count of a document this repository edits
    constantly goes stale by the act of committing the edit that reports it — at
    ``3a3b4f0``, over the 171 tracked text files there: folding adds **0**
    collisions for three of the four, and **3** out of 880 segments for
    `docs/LIMITATIONS.md` — each of those three a sentence that genuinely does
    appear in two files with different capitalisation.

    This paragraph said *3 out of 1127* over *171 tracked text files*, with no
    filter and no ref, until 2026-08-06. The **3** and the three zeros reproduce;
    1127 names no committed state of this repository (880 at ``3a3b4f0``, 1245 in
    the working tree that corrected it); and the corpus figure reproduces exactly
    once the filter is written down. **B-091**, and the correction appended to
    **D-049**, which carries the method and the whole table.
    """
    return " ".join(text.split()).translate(_ASCII_CASE_FOLD)


def hidden_context_segments(text: str) -> tuple[str, ...]:
    """The matchable segments of one hidden-context declaration.

    Pure: the file read happens in ``policy/loader.py``, which is this engine's
    I/O boundary. Order is the declaration's own and duplicates are dropped, so
    the tuple reads like the file it came from.

    Segments shorter than :data:`HIDDEN_CONTEXT_MIN_SEGMENT_CHARS` are dropped
    rather than matched, and that is the whole of the false-positive control
    here — see that constant for what the floor was measured against.
    """
    segments: list[str] = []
    seen: set[str] = set()
    for piece in _HIDDEN_CONTEXT_SEGMENT_SPLIT.split(text):
        piece = normalized_for_comparison(piece)
        if len(piece) >= HIDDEN_CONTEXT_MIN_SEGMENT_CHARS and piece not in seen:
            seen.add(piece)
            segments.append(piece)
    return tuple(segments)


def contains_hidden_context(segments: Any, value: Any) -> bool:
    """True if any of ``segments`` appears in any string anywhere in ``value``.

    The policy-independent half of :func:`args_contain_hidden_context`, and the
    reason it is a separate public function: both enforcement points call it to
    keep declared material out of the decision LOG, whatever verdict the call
    received and whether or not any rule arms the predicate. That mirrors
    :func:`contains_sensitive`, and it has to, because a refusal whose event
    writes the protected material into a file is a control that leaks the thing
    it protects.

    **It is NOT folded into** :func:`contains_sensitive`, which is a different
    decision from the one that looks the same. ``contains_sensitive`` takes a
    value and no policy, it is the union of :data:`ARG_MATCHERS`, and
    ``taint``'s ``secrets_only`` mode asks it: joining would attribute
    ``taint:secret-egress`` — an id whose whole job is to say a CREDENTIAL was
    seen — to a call carrying a system prompt and no credential. Same objection
    D-046 raised one predicate over, same answer.

    Empty ``segments`` is False rather than a match-everything: a policy that
    declares no hidden context must behave exactly as every policy written
    before this existed.
    """
    if not segments:
        return False
    return any(
        any(segment in normalized_for_comparison(text) for segment in segments)
        for text in _strings_in(value)
    )


def args_contain_hidden_context(spec: Any, args: Args) -> bool:
    """True iff any string anywhere in ``arguments`` carries declared material.

    D-049, for OWASP **LLM08:2026** Hidden Context Exposure at the one leg that
    reaches this door: the EGRESS. Nothing here can stop a model being talked
    into reciting its system prompt — that happens in the model's output, which
    this gateway never sees — but the recitation only becomes an exposure when
    it leaves, and leaving means a tool call.

    **``spec`` is the resolved SEGMENTS, not the names the operator wrote.** The
    policy names one or more sets declared in the file's ``hidden_context:``
    section and ``policy/loader.py`` substitutes their segments here, because a
    predicate is handed its spec and nothing else — see D-049 Decision 3 for the
    two alternatives and what each costs.

    **Operator-declared, never inferred.** It matches material the operator
    named; it forms no opinion about whether a string "looks like" a system
    prompt or a tool schema. That is content filtering, which this project rules
    out of scope in ``README.md`` and could not measure, and it is also what
    would make this predicate undecidable.

    What it does not reach is one thing and it is large: **paraphrase.** A model
    that describes its instructions in its own words carries no declared segment
    and is allowed. That is a property of every literal matcher, it is measured
    rather than asserted in ``docs/LIMITATIONS.md`` §26, and no floor, unit or
    normalization changes it.

    Rides :func:`_strings_in`, so it inherits that walk exactly: dict keys are
    scanned as well as values, a non-string is ignored rather than coerced, and
    a string nested below :data:`_MAX_SCAN_DEPTH` is not seen (§18).
    """
    return contains_hidden_context(spec, args)


def contains_sensitive(value: Any) -> bool:
    """True if any known credential format appears anywhere in ``value``.

    The union of every matcher in :data:`ARG_MATCHERS`, independent of policy.
    Enforcement points use it to keep credentials out of decision logs — a
    call may carry a secret whatever verdict it received.
    """
    return any(m(s) for s in _strings_in(value) for m in ARG_MATCHERS.values())


PREDICATES: dict[str, Predicate] = {
    "path_within": path_within,
    "path_not_within": path_not_within,
    "path_segment_not_in": path_segment_not_in,
    "domain_in": domain_in,
    "command_matches_any": command_matches_any,
    "args_match_any": args_match_any,
    "args_contain_invisible_characters": args_contain_invisible_characters,
    "args_contain_hidden_context": args_contain_hidden_context,
}
