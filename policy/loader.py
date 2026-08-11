"""Policy loader — YAML file in, immutable ``engine.Policy`` out.

This is the engine's I/O boundary: the engine never reads a file, this module
never makes a decision. Validation is strict and fails closed — an unknown
key, predicate, matcher, decision word, or malformed value raises
:class:`PolicyError` at load time rather than becoming a silent no-op rule at
decide time.

Deny by default: a policy that omits ``defaults`` gets BLOCK for both
``decision`` and ``on_no_match``. An explicit non-block default is honored —
that is the operator's written choice, visible in the file.

Path prefixes are written out in full: absolute, and with no ``~``. A relative
prefix enforces nothing and is refused (B-006); a ``~`` is refused too, because
expanding it binds the rule to whatever home the *loading process* happens to
have rather than the home it was written to protect (B-002, D-017). Everything
else is passed through untouched.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

# D-018's anchor check reads a pattern through the same parser `re.compile`
# uses, because no scan of the pattern's TEXT was sound — see `_fully_anchored`
# below (B-039). The module is private and was renamed in 3.11, so both
# spellings are tried; if neither resolves this module does not import at all,
# which is the right failure: a policy this file cannot validate must not load.
try:  # Python 3.11+
    from re import _parser as _re_parser
except ImportError:  # pragma: no cover - Python 3.10 spells it sre_parse
    import sre_parse as _re_parser

import yaml

from engine.listing import DIGEST_PREFIX
from engine.model import (
    Defaults,
    EgressMode,
    HiddenContext,
    Limits,
    Policy,
    Rule,
    Taint,
    ToolListingPolicy,
    Verdict,
)
from engine.predicates import (
    ARG_MATCHERS,
    HIDDEN_CONTEXT_MIN_SEGMENT_CHARS,
    INVISIBLE_CHARACTER_CLASSES,
    PREDICATES,
    hidden_context_segments,
)

_VERDICTS = {v.value: v for v in Verdict}
_OWASP_RE = re.compile(r"^LLM\d{2}$")
# D-026: rule-id prefixes the ENGINE and the enforcement points use for decisions
# no policy rule produced, and which a policy rule therefore may not claim. Every
# one is already emitted today: `default:on_no_match` (engine/model.py),
# `limit:` (engine/model.py LIMIT_RULE_PREFIX), `pep:unresolvable-path`
# (pep/canonicalize.py), `proxy:uninspectable-input-channel` (proxy/server.py),
# `hook:unparseable-input` / `hook:policy-error` (hooks/chokepoint_hook.py).
# Published as a detection contract in telemetry/event-schema.json.
RESERVED_RULE_ID_PREFIXES = ("default:", "limit:", "pep:", "proxy:", "hook:", "taint:", "listing:")
# The predicates whose entries are absolute path PREFIXES, and therefore the
# only ones the `~`/absolute checks below apply to. `path_segment_not_in`
# (D-014) is deliberately NOT here: its entries are single path components —
# `.ssh`, `.aws`, `.git` — so the absolute-prefix check would reject the shipped
# policy outright. Adding it here is the obvious-looking edit and it breaks
# `policy.example.yaml` at load; the set is about the shape of the VALUE, not
# about which argument the predicate reads.
_PATH_PREDICATES = {"path_within", "path_not_within"}
# The predicates that say what an argument is NOT. This groups by POLARITY, not
# by the shape of the value, which is why it is a second set rather than an
# addition to `_PATH_PREDICATES` above: that one is about entries being absolute
# path prefixes and deliberately excludes `path_segment_not_in`, while this one
# is about what the predicate asserts. D-019 (B-033): a `when` built only of
# these never says what it permits, so it matches every argument the author
# never thought to exclude.
_NEGATIVE_PREDICATES = frozenset({"path_not_within", "path_segment_not_in"})
# The two tokens `_fully_anchored` below compares against, derived by parsing the
# escapes themselves rather than by naming a private constant: whatever `\A` and
# `\Z` parse to in this interpreter is exactly what the check looks for.
_ANCHOR_START = _re_parser.parse("\\A")[0]
_ANCHOR_END = _re_parser.parse("\\Z")[0]
_LIMIT_KEYS = {
    "max_tool_calls_per_run",
    "max_wall_clock_seconds",
    "max_repeated_identical_calls",
}
#: The schema versions this loader knows how to read (CP-07). Every other field
#: in this module is checked against a closed set; `version` was checked only for
#: being an integer, so `999` and `-7` loaded and produced a working Policy.
#:
#: The blast radius of a WRONG version is bounded in one direction and not the
#: other: a future schema that ADDS a key already fails closed against
#: `_DOCUMENT_KEYS`, but a key whose MEANING changes does not — the file reads as
#: one contract and enforces another. That is not hypothetical here. `version: 0` has
#: been frozen while this loader's meanings moved at least three times: D-014 grew
#: the predicate vocabulary, D-018 narrowed which `command_matches_any` patterns
#: an allow rule may carry, and D-019 outlawed an all-negative `when`. A policy
#: written against the pre-D-019 meaning of `version: 0` is a different contract
#: from one written after it, and nothing in the file distinguishes them.
#:
#: Refusing the rest costs nothing today — measured across the tree, every policy
#: YAML is `version: 0`, fixtures under `policy/tests/` and `hooks/tests/`
#: included. It also gives the schema bumps `docs/LIMITATIONS.md` plans somewhere
#: to land: adding `1` here is the whole registration step, and a policy that
#: names a version this build cannot read is refused at load rather than
#: silently reinterpreted.
SUPPORTED_POLICY_VERSIONS = frozenset({0})
_DOCUMENT_KEYS = {
    "version", "defaults", "limits", "rules", "taint", "tool_listing", "hidden_context",
}
_TOOL_LISTING_KEYS = {"approved"}
#: The one digest spelling accepted in `tool_listing.approved`. Lowercase hex
#: only: `sha256:AB…` and `sha256:ab…` would be the same digest written two ways,
#: and a pin that compares unequal to itself is a pin that refuses every listing
#: for a reason no operator would find. The algorithm is named in the value so
#: the file says what it is rather than relying on a length nobody counts.
_DIGEST_RE = re.compile(r"^" + re.escape(DIGEST_PREFIX) + r"[0-9a-f]{64}$")
#: Distinguishes an ABSENT `tool_listing:` from one present with an empty value.
#: `raw.get()` cannot: YAML gives `None` for both, and they are opposite
#: instructions — the same reason `server: null` is refused rather than read as
#: "any server" (D-015).
_ABSENT = object()
_TAINT_KEYS = {"sources", "egress_tools", "egress_mode", "on_taint", "allowed_domains"}
_EGRESS_MODES = {m.value: m for m in EgressMode}
# `on_taint: allow` is refused: a taint block whose refusal is an allow reads as
# enforcing and enforces nothing, which is the shape this loader already refuses
# for an empty `when` (D-012) and an all-negative one (D-019).
_TAINT_VERDICTS = {Verdict.BLOCK, Verdict.ASK}
_DEFAULTS_KEYS = {"decision", "on_no_match"}
_RULE_KEYS = {"id", "owasp", "tool", "decision", "when", "note", "server"}


class PolicyError(ValueError):
    """The policy file is invalid. The message says where and why."""


class _StrictLoader(yaml.SafeLoader):
    """SafeLoader that refuses duplicate mapping keys.

    PyYAML's default is last-one-wins, silently. In a policy file that means a
    rule can *read* as ``decision: block`` while enforcing ``allow`` — the file
    and the control disagree, and the file is what gets reviewed.
    """


def _no_duplicate_keys(loader: yaml.Loader, node: yaml.MappingNode, deep: bool = False) -> dict:
    seen: set = set()
    for key_node, _ in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in seen
        except TypeError:  # unhashable key; construct_mapping reports it properly below
            duplicate = False
        if duplicate:
            raise PolicyError(f"duplicate key {key!r} at line {key_node.start_mark.line + 1}")
        try:
            seen.add(key)
        except TypeError:
            pass
    return yaml.SafeLoader.construct_mapping(loader, node, deep=deep)


_StrictLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    lambda loader, node: _no_duplicate_keys(loader, node),
)


def ambiguous_server_identity(server: str) -> bool:
    """True when ``server`` may not be used as an MCP server identity (B-034, B-037).

    Derived from the wire format rather than from a list of bad spellings.
    Claude Code frames an MCP tool as ``mcp__<server>__<tool>`` and the hook
    recovers the halves by finding every position where ``__`` splits the name
    into two non-empty halves: exactly one such position is a name that door can
    read, two or more is a guess it refuses. The tool half is chosen upstream
    and arrives unannounced, so the only thing an identity can be held to is its
    own framing -- ``<server>__`` must contain the delimiter exactly ONCE, the
    occurrence that IS the delimiter.

    A second occurrence has only two sources, which is why this one condition
    replaces the two spellings it would otherwise take: it sits wholly inside
    the identity (``prod__west``, B-034), or it straddles the identity's last
    character (``prod_``, B-037 -- ``prod_`` framed is ``prod___``, which reads
    as server ``prod`` + tool ``_...`` exactly as well as server ``prod_`` +
    tool ``...``). Measured against the hook's real split expression: ``prod``
    and ``prod_west`` frame to one split position, ``prod_`` and ``prod__west``
    to two.

    Conservative at one edge, deliberately: this counts an occurrence at
    position 0, which the hook's split never considers (it would leave an empty
    server half). Two spellings land there and a differential over 28 identities
    at all three doors found both — ``__x``, and ``_`` itself, whose framing
    ``___`` the hook reads unambiguously as server ``_``. Both are refused here
    and at ``--server-name`` while the hook would have read them. That is an
    over-refusal, not a hole: no rule can name such a server, so a call from one
    falls to the unscoped rules and then to deny-by-default at every door, and
    B-034 already refused these shapes. *(The clause used to name only the
    ``__`` prefix; the second spelling was found 2026-08-05 by that same
    differential, which turned up no door DISagreement that was not this
    over-refusal.)*
    """
    framed = server + "__"
    return sum(1 for i in range(len(framed) - 1) if framed.startswith("__", i)) > 1


def _require_str_list(value: Any, where: str) -> list[str]:
    if not isinstance(value, list) or not value or not all(isinstance(x, str) and x for x in value):
        raise PolicyError(f"{where} must be a non-empty list of strings")
    return value


def _parse_verdict(value: Any, where: str) -> Verdict:
    if not isinstance(value, str) or value not in _VERDICTS:
        raise PolicyError(f"{where} must be one of {sorted(_VERDICTS)}, got {value!r}")
    return _VERDICTS[value]


def _parse_defaults(raw: Any) -> Defaults:
    if raw is None:
        return Defaults()
    if not isinstance(raw, dict):
        raise PolicyError("defaults must be a mapping")
    unknown = set(raw) - _DEFAULTS_KEYS
    if unknown:
        raise PolicyError(f"defaults has unknown keys: {sorted(unknown)}")
    decision = _parse_verdict(raw["decision"], "defaults.decision") if "decision" in raw else Verdict.BLOCK
    # `on_no_match` is the field the engine reads. When it is absent, the
    # broader `defaults.decision` supplies it, so an operator who writes only
    # `decision:` is not silently ignored; when both are present the specific
    # one wins. The example policy sets both to block, which makes the two
    # fields redundant — collapsing them is a v1 policy-schema question, not
    # something the loader decides.
    on_no_match = (
        _parse_verdict(raw["on_no_match"], "defaults.on_no_match") if "on_no_match" in raw else decision
    )
    return Defaults(decision=decision, on_no_match=on_no_match)


def _parse_limits(raw: Any) -> Limits:
    # Limits are per RUN, and a run is one MCP client session with the proxy —
    # one proxy process, since the stdio proxy serves exactly one session per
    # process (D-022, B-040). The hook door passes run_state=None (limits are
    # the proxy's job), and a long-lived deployment recycles its session under
    # these caps so no run outlives them (deploy/demo/gateway_driver.py).
    if raw is None:
        return Limits()
    if not isinstance(raw, dict):
        raise PolicyError("limits must be a mapping")
    unknown = set(raw) - _LIMIT_KEYS
    if unknown:
        raise PolicyError(f"limits has unknown keys: {sorted(unknown)}")
    values: dict[str, int] = {}
    for key, value in raw.items():
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            raise PolicyError(f"limits.{key} must be a positive integer, got {value!r}")
        values[key] = value
    return Limits(**values)


def _parse_taint(raw: Any) -> Taint:
    """Policy ``taint:`` — D-031. Absent means taint can never fire.

    Validated as strictly as everything else here, and one refusal is worth its
    own sentence: a ``taint:`` block that names ``sources`` but no
    ``egress_tools`` (or the reverse) can never refuse anything, while reading in
    the file as though the run were being contained. That is D-012's shape — a
    rule that reads as scoped and enforces nothing — so it is refused rather than
    loaded. Omit the whole block for a policy that does not track taint.
    """
    if raw is None:
        return Taint()
    if not isinstance(raw, dict):
        raise PolicyError("taint must be a mapping")
    unknown = set(raw) - _TAINT_KEYS
    if unknown:
        raise PolicyError(f"taint has unknown keys: {sorted(unknown)}")

    for required in ("sources", "egress_tools"):
        if required not in raw:
            raise PolicyError(
                f"taint is missing required key {required!r} — a taint block naming only one "
                "of sources/egress_tools can never refuse anything while reading as though it "
                "contained the run. Omit the whole `taint:` block for a policy that does not "
                "track taint (see D-031)."
            )
    sources = tuple(_require_str_list(raw["sources"], "taint.sources"))
    egress_tools = tuple(_require_str_list(raw["egress_tools"], "taint.egress_tools"))

    mode_raw = raw.get("egress_mode", EgressMode.SECRETS_ONLY.value)
    if not isinstance(mode_raw, str) or mode_raw not in _EGRESS_MODES:
        raise PolicyError(
            f"taint.egress_mode must be one of {sorted(_EGRESS_MODES)}, got {mode_raw!r}"
        )
    mode = _EGRESS_MODES[mode_raw]

    on_taint = _parse_verdict(raw["on_taint"], "taint.on_taint") if "on_taint" in raw else Verdict.BLOCK
    if on_taint not in _TAINT_VERDICTS:
        raise PolicyError(
            f"taint.on_taint must be 'block' or 'ask', got {on_taint} — an `allow` there is a "
            "taint control that refuses nothing while reading as though it did (see "
            "B-010 for the same shape in a rule's `when`)."
        )

    # Absent is legal under every mode, including `secrets_and_new_domains`,
    # where it means no host is exempt and every url-bearing egress call is
    # refused after taint. That fails closed, so it loads; the example policy's
    # comment warns that it is easy to write by accident.
    allowed_domains: tuple[str, ...] = ()
    if "allowed_domains" in raw:
        allowed_domains = tuple(_require_str_list(raw["allowed_domains"], "taint.allowed_domains"))

    return Taint(
        sources=sources,
        egress_tools=egress_tools,
        egress_mode=mode,
        on_taint=on_taint,
        allowed_domains=allowed_domains,
    )


def _parse_tool_listing(raw: Any) -> ToolListingPolicy | None:
    """Policy ``tool_listing:`` — D-039. Absent means the door is not armed.

    Four refusals, each one the shape this loader already refuses elsewhere
    rather than a new kind of strictness:

    * ``tool_listing:`` present with no value. YAML gives ``None`` for that and
      for the key being absent, and they are opposite instructions — one arms a
      door and the other does not. Refused rather than collapsed into "absent",
      exactly as ``server: null`` is refused rather than read as "any server"
      (D-015). The ``_ABSENT`` sentinel is what tells the two apart.
    * No ``approved`` key, or an empty one. A ``tool_listing:`` block that
      approves nothing refuses every listing the upstream can serve, which is a
      gateway that advertises no tools at all — a real instruction, but one no
      operator writes on purpose, and indistinguishable in the file from having
      forgotten the list. Omit the whole block to leave the door unarmed; drop
      the upstream to serve none of its tools.
    * A digest that is not ``sha256:<64 lowercase hex>``. A malformed pin can
      never equal any digest this engine computes, so it would refuse every
      listing while reading in the file as an approval — D-012's shape (a rule
      that reads as scoped and enforces nothing) pointing the other way, and the
      operator would be hunting a rule id that says the definition drifted when
      the drift is in their own file.
    * Anything else under ``tool_listing:``. There is deliberately no verdict
      knob and no report-only mode (see :class:`~engine.model.ToolListingPolicy`),
      so a key here is a setting the operator believes exists and this door does
      not have.
    """
    if raw is _ABSENT:
        return None
    if raw is None:
        raise PolicyError(
            "tool_listing is present but empty — an empty `tool_listing:` reads as arming "
            "the tools/list door and arms nothing, and this loader cannot tell it apart "
            "from the key being absent. Omit the key entirely to leave that door unarmed "
            "(see D-039)."
        )
    if not isinstance(raw, dict):
        raise PolicyError("tool_listing must be a mapping")
    unknown = set(raw) - _TOOL_LISTING_KEYS
    if unknown:
        raise PolicyError(
            f"tool_listing has unknown keys: {sorted(unknown)} — the only key is 'approved'. "
            "There is no verdict knob and no report-only mode at this door: `ask` has no "
            "approver here (D-005) and the hook door never sees a tools/list at all, so the "
            "setting would have exactly one honest value (see D-039)."
        )
    approved_raw = raw.get("approved")
    if not isinstance(approved_raw, dict) or not approved_raw:
        raise PolicyError(
            "tool_listing.approved must be a non-empty mapping of tool name -> "
            f"'{DIGEST_PREFIX}<64 hex>' — a tool_listing block approving nothing refuses "
            "every listing this upstream can serve while reading as though it approved "
            "some. Omit the whole `tool_listing:` block to leave the door unarmed."
        )
    approved: dict[str, str] = {}
    for name, digest in approved_raw.items():
        if not isinstance(name, str) or not name:
            raise PolicyError(
                f"tool_listing.approved has a key that is not a non-empty tool name: {name!r}"
            )
        if not isinstance(digest, str) or not _DIGEST_RE.match(digest):
            raise PolicyError(
                f"tool_listing.approved[{name!r}] must be '{DIGEST_PREFIX}<64 lowercase hex>', "
                f"got {digest!r} — a malformed pin equals no digest this engine computes, so "
                "it would refuse every listing while reading in this file as an approval. "
                "Each refusal names the digest the gateway computed for the tool it refused; "
                "that is where the value to paste here comes from."
            )
        approved[name] = digest
    return ToolListingPolicy(approved=approved)


def _parse_hidden_context(raw: Any) -> HiddenContext:
    """Policy ``hidden_context:`` — D-049. Absent means nothing is declared.

    A mapping of NAME -> absolute path. The name is what a rule's
    ``args_contain_hidden_context`` arms; the file's text is read HERE, at this
    module's I/O boundary, and reduced to segments by
    ``engine.predicates.hidden_context_segments`` so the engine stays a pure
    function of what it is handed.

    **Why a path and never the text.** Inlining the material would put the
    hidden context into a file that is reviewed, diffed and committed — and, per
    B-088, into a file a call can read whenever the operator keeps it inside an
    allowed ``path_within`` prefix. A control whose configuration discloses what
    it protects is the shape this whole entry exists to refuse.

    Six refusals, each the shape this loader already refuses elsewhere:

    * ``hidden_context:`` present with no value. YAML gives ``None`` for that
      and for the key being absent, and they are opposite instructions. Refused
      rather than collapsed, exactly as ``tool_listing:`` is (D-039) and
      ``server: null`` is (D-015); the ``_ABSENT`` sentinel tells them apart.
    * A path that is not a non-empty string, or a name that is not one.
    * A ``~`` in the path — D-017 (B-002): it expands against the home of
      whichever process loads this file, so the same line would declare a
      different file in a container than on a laptop.
    * A relative path — B-006's reason moved one key over: it resolves against
      whatever working directory the loading process happens to have, so the
      same policy would declare different material at each door.
    * A file that cannot be read. Refused loudly rather than treated as an empty
      declaration, because an empty one matches nothing while reading in the
      file as protection — D-012's shape, and the exact way this control would
      fail silently in production (a renamed prompt file).
    * A file yielding no segment at or above
      :data:`~engine.predicates.HIDDEN_CONTEXT_MIN_SEGMENT_CHARS`. Same reason,
      one step later: the file exists, the declaration reads as armed, and every
      call is allowed. The message says the floor and what it is measured
      against so the operator is not left guessing why their file was refused.
    """
    if raw is _ABSENT:
        return HiddenContext()
    if raw is None:
        raise PolicyError(
            "hidden_context is present but empty — an empty `hidden_context:` reads as "
            "declaring material that must not leave and declares none, and this loader "
            "cannot tell it apart from the key being absent. Omit the key entirely for a "
            "policy that declares nothing (see D-049)."
        )
    if not isinstance(raw, dict) or not raw:
        raise PolicyError(
            "hidden_context must be a non-empty mapping of name -> absolute path to the "
            "file whose CONTENT must not leave through a tool call"
        )
    segments: dict[str, tuple[str, ...]] = {}
    sources: dict[str, str] = {}
    for name, path in raw.items():
        if not isinstance(name, str) or not name:
            raise PolicyError(
                f"hidden_context has a key that is not a non-empty declaration name: {name!r}"
            )
        if not isinstance(path, str) or not path:
            raise PolicyError(
                f"hidden_context[{name!r}] must be a non-empty absolute path, got {path!r} — "
                "the material itself is deliberately not accepted here: a policy file "
                "carrying the hidden context is a reviewed, committed, and possibly readable "
                "copy of the thing this declaration exists to keep in (see B-088)."
            )
        if path.startswith("~"):
            raise PolicyError(
                f"hidden_context[{name!r}] path {path!r} starts with '~' — write it out in "
                "full. A '~' expands against the home of whichever process loads this file, "
                "so the same line declares a different file in a container than it does on a "
                "laptop (see B-002)."
            )
        if not path.startswith("/"):
            raise PolicyError(
                f"hidden_context[{name!r}] path {path!r} is not absolute — a relative path "
                "resolves against whatever working directory the loading process happens to "
                "have, so the same policy would declare different material at each door "
                "(see B-006 for the same failure one key over)."
            )
        try:
            text = Path(path).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise PolicyError(
                f"hidden_context[{name!r}] could not read {path!r}: "
                f"{type(exc).__name__}: {exc} — a declaration this loader cannot read would "
                "match nothing while reading in this file as protection, which is the shape "
                "refused for an empty `when` (D-012). Fix the path or remove the declaration."
            ) from exc
        derived = hidden_context_segments(text)
        if not derived:
            raise PolicyError(
                f"hidden_context[{name!r}]: {path!r} yielded no segment of at least "
                f"{HIDDEN_CONTEXT_MIN_SEGMENT_CHARS} characters, so it would match nothing "
                "while reading in this file as protection. Segments are lines and sentences "
                "with whitespace collapsed; shorter ones are dropped because below that "
                "length they are structure rather than content and collide with ordinary "
                "text (see D-049 and docs/LIMITATIONS.md class 15)."
            )
        segments[name] = derived
        sources[name] = path
    return HiddenContext(segments=segments, sources=sources)


def _fully_anchored(pattern: str) -> bool:
    # D-018: an `allow` rule's `command_matches_any` pattern has to match the
    # WHOLE command string — anchored at both ends, with nothing at the top level
    # that can split those two anchors apart. The engine matches these with
    # `re.search` over the whole command string, so an unanchored allow pattern
    # permits any compound command that merely CONTAINS the permitted form:
    # `^ls\b` admits `ls -la; cat /etc/shadow`.
    #
    # B-039: the first implementation of this check was a hand-written scan of
    # the pattern TEXT — count `(` and `)`, track `[`...`]`, refuse a `|` at
    # depth 0, remember the last token — and it was unsound, because the text is
    # not what the regex parser reads. Inside a `(?#...)` comment group, and
    # inside a `#` comment within a `(?x:...)` verbose group, Python treats `[`,
    # `(` and `)` as ordinary text, so a comment hides the structure the scan
    # counts. Measured end to end, not argued: `\A(?# ls (or dir )ls|dir\Z`
    # LOADED on an allow rule and `decide()` then returned allow/shell-listing
    # both for `ls -la; cat /etc/shadow` and for a `curl -d @/etc/passwd` exfil
    # command. The same alternation without the comment (`\Als|dir\Z`) is
    # refused, so the guard was live and the comment is what defeated it.
    #
    # Patching the scan was measured one boundary short too: adding
    # `depth == 0 and not in_class` to its final test kills three of the four
    # families, and `\A(?#()x|y(?x:#)\n)\Z` survives it — a `(` hidden in a
    # comment group skews the depth up, a `)` hidden in a verbose comment brings
    # it back down, so the scan ends balanced while the parser sees a top-level
    # alternation. That is the B-034 -> B-037 -> B-038 shape a FOURTH time, which
    # is why the scan is deleted here rather than patched: the answer comes from
    # the parser that actually reads the pattern.
    #
    # Why that answer is sound: the parsed top-level sequence must BEGIN with the
    # `\A` token and END with the `\Z` token, so every match starts at 0 and ends
    # at `len(command)`. A top-level alternation makes the whole pattern a single
    # BRANCH item, which fails the first test — D-018's "reject a top-level `|`"
    # is satisfied by construction, with no separate check to argue with. (The
    # per-branch spelling `\Afoo\Z|\Abar\Z` is caught at the other end: the parser
    # factors the shared `\A` out in front, leaving the BRANCH itself last.)
    #
    # The source-level `startswith` stays. Position 0 cannot be spoofed — a
    # backslash there always begins an escape — and the parser alone would accept
    # an inline-flag prefix: `(?i)\Als\Z` parses to exactly the same token list as
    # `\Als\Z` (measured). The text test is what keeps that frozen conservative
    # refusal.
    #
    # Ordering: this runs only after the `re.compile` loop in `_parse_when`
    # below, so a pattern that does not COMPILE is refused with the loader's own
    # message first. Ordered the other way, `_fully_anchored(r"\A(rm\Z")` raises
    # `re.PatternError` (measured), a non-`PolicyError` out of `load_policy`,
    # where the old text scan only got the message wrong.
    #
    # It does NOT make `parse` unraisable. `re.compile` is cached and `parse` is
    # not, so on a second load of the same pattern in one process the compile
    # returns without parsing while this parse still runs — and under
    # warnings-as-errors a pattern whose parse merely WARNS raises out of
    # `load_policy`. Measured: `\A[[a]]\Z` ("Possible nested set"), cache primed,
    # `simplefilter("error")` — the pre-B-039 scan loaded it, this parse raises.
    # Fail-closed at both doors (the hook's `main()` catch-all returns exit 2,
    # the proxy aborts at startup), and this repo sets no warnings filter.
    if not pattern.startswith("\\A"):
        return False
    parsed = _re_parser.parse(pattern)
    return len(parsed) >= 2 and parsed[0] == _ANCHOR_START and parsed[-1] == _ANCHOR_END


def _parse_when(
    raw: Any, rule_id: str, decision: Verdict, hidden_context: HiddenContext
) -> dict[str, Any]:
    if raw is not None and not isinstance(raw, dict):
        raise PolicyError(f"rule {rule_id!r}: when must be a mapping")
    # D-012 (B-010): a rule with no predicates is refused at load. All three
    # spellings arrive here as `None` or `{}` — `_parse_rule` reads the key with
    # `raw.get("when")`, so an ABSENT `when:` is indistinguishable from
    # `when: null` — and `_matches` treats an empty predicate set as satisfied,
    # so all three produced a rule that matched every call to its tool.
    # Measured at HEAD bbb8d15: a policy whose only rule was
    # `{tool: read_file, decision: allow, when: null}` returned allow on 3 of 3
    # hostile inputs, `/etc/passwd` included. The rule reads as scoped and
    # enforces nothing, which is the shape this loader already refuses
    # everywhere else — relative prefixes, duplicate keys, unknown predicates,
    # unknown matchers, invalid regexes.
    if not raw:
        raise PolicyError(
            f"rule {rule_id!r}: when must name at least one predicate — a rule with "
            "no predicates matches EVERY call to its tool while reading as though it "
            "were scoped (see B-010). Write the condition out, or delete "
            f"the rule. Fixed vocabulary: {sorted(PREDICATES)}."
        )
    when: dict[str, Any] = {}
    for name, spec in raw.items():
        if name not in PREDICATES:
            raise PolicyError(
                f"rule {rule_id!r}: unknown predicate {name!r} "
                f"(fixed vocabulary: {sorted(PREDICATES)})"
            )
        entries = _require_str_list(spec, f"rule {rule_id!r}: {name}")
        if name == "args_match_any":
            unknown = [m for m in entries if m not in ARG_MATCHERS]
            if unknown:
                raise PolicyError(
                    f"rule {rule_id!r}: unknown matcher(s) {unknown} "
                    f"(known: {sorted(ARG_MATCHERS)})"
                )
        if name == "args_contain_invisible_characters":
            # D-046. The same refusal `args_match_any` gets one branch up, and
            # for the same reason: the entries are names of a fixed set, and a
            # misspelled one would raise `KeyError` from inside `decide()` — at
            # the moment a call is being judged, on a control whose whole job is
            # to answer then. The names are the operator's dial, so a typo in one
            # is a class the operator believes is armed and is not.
            unknown = [c for c in entries if c not in INVISIBLE_CHARACTER_CLASSES]
            if unknown:
                raise PolicyError(
                    f"rule {rule_id!r}: unknown invisible-character class(es) {unknown} "
                    f"(known: {sorted(INVISIBLE_CHARACTER_CLASSES)})"
                )
        if name == "args_contain_hidden_context":
            # D-049. The entries are names of declarations in this file's own
            # `hidden_context:` section, and an unknown one is refused for the
            # reason an unknown matcher and an unknown invisible-character class
            # are: it is a set the operator believes is armed and is not, and it
            # would otherwise raise from inside `decide()` at the moment a call
            # is being judged.
            declared = hidden_context.segments
            unknown = [n for n in entries if n not in declared]
            if unknown:
                raise PolicyError(
                    f"rule {rule_id!r}: undeclared hidden-context set(s) {unknown} "
                    f"(declared: {sorted(declared)}) — a rule may only name sets this "
                    "file's own `hidden_context:` section declares (see D-049)."
                )
            # THE SUBSTITUTION, and it is the one place in this loader where a
            # stored `when` value is not the operator's own words: what goes
            # into the rule is the SEGMENTS, not the names. A predicate is
            # handed its spec and nothing else — `engine/decide.py:_matches`
            # calls `predicate(spec, args)` — so the alternatives were widening
            # every predicate's signature to take the Policy, or a module-level
            # registry the loader writes, which is global mutable state two
            # policies in one process would share. D-049 Decision 3 records
            # both. The cost is that `rule.when` for this predicate holds
            # declared material, so nothing may print it: no decision event
            # does (they carry `rule_id`, `verdict`, `owasp` and a `reason`
            # built from the rule ID and the tool name), and every refusal
            # message in this module names sets and paths rather than content.
            merged: dict[str, None] = {}
            for n in entries:
                for segment in declared[n]:
                    merged.setdefault(segment, None)
            when[name] = tuple(merged)
            continue
        if name == "command_matches_any":
            # These are regexes. An invalid one would otherwise sail through the
            # loader and raise from inside decide(), i.e. at the moment a call is
            # being judged, on a control whose whole job is to answer then.
            for pattern in entries:
                try:
                    re.compile(pattern)
                except re.error as exc:
                    raise PolicyError(
                        f"rule {rule_id!r}: {name} entry {pattern!r} is not a valid regex: {exc}"
                    ) from exc
                # D-018: on an `allow` rule it must also be fully anchored — see
                # `_fully_anchored` above for what the two ends are tested on and
                # what the source-level test adds. After the compile, so an invalid
                # regex is still reported as one; block and ask rules are
                # unaffected, where matching a broad set is the point.
                if decision is Verdict.ALLOW and not _fully_anchored(pattern):
                    raise PolicyError(
                        f"rule {rule_id!r}: {name} entry {pattern!r} is not fully "
                        "anchored — an allow rule's command pattern is matched with "
                        "re.search over the whole command string, so an unanchored "
                        "pattern permits any compound command that contains the "
                        "permitted form. Start the pattern with \\A, end it with "
                        "\\Z, and parenthesise any alternation "
                        "(see D-018)."
                    )
        if name in _PATH_PREDICATES:
            for entry in entries:
                # D-017 (B-002): the check fires on the RAW entry, before any
                # expansion, and it subsumes the unresolvable-`~` check that
                # used to sit here — one spelling, one message, one remedy.
                # `os.path.expanduser` ran at this point and bound the stored
                # prefix to the POLICY-LOADING process's HOME: measured at HEAD
                # bbb8d15, `path_not_within: ['~/.ssh/']` stored
                # ('/home/alice/.ssh/',) under HOME=/home/alice and
                # ('/home/bob/.ssh/',) under HOME=/home/bob — one file guarding
                # a different directory in every process that reads it. In the
                # shipped chart the proxy runs in a container under its own
                # ServiceAccount, where `~/.ssh/` protects the proxy's home and
                # not the user's. The `~` that could NOT be expanded was
                # already refused, for the narrower reason that expanduser
                # returns the string unchanged (an unknown ~user, or a container
                # with no passwd entry and no HOME — exactly the hardened,
                # non-root pod this gateway is meant to run in), leaving a
                # relative prefix that matches nothing and turns a
                # `path_not_within` deny entry into an ALLOW. Both cases are now
                # the same refusal.
                if entry.startswith("~"):
                    raise PolicyError(
                        f"rule {rule_id!r}: {name} entry {entry!r} starts with '~' — path "
                        "prefixes must be written out in full. A '~' expands against the "
                        "home of whichever process loads this file, not the home the rule "
                        "was written to protect, so the same line guards a different "
                        "directory in a container than it does on a laptop; where it cannot "
                        "be expanded at all the prefix stays relative and silently matches "
                        "nothing (see B-002)."
                    )
                # B-006: the engine refuses to judge a relative call path at all
                # (it cannot know the tool's working directory), so a relative
                # prefix can never match anything it is asked about. In a
                # `path_not_within` deny list that is worse than useless: the
                # predicate reports "not denied" and the rule ALLOWS. The
                # shipped example paired a relative `path_within` with absolute
                # deny prefixes and its deny half changed 0 of 15 decisions.
                # Refuse the spelling rather than ship the trap again.
                if not entry.startswith("/"):
                    raise PolicyError(
                        f"rule {rule_id!r}: {name} entry {entry!r} is not an absolute "
                        "path prefix — path prefixes must start with '/'. A relative prefix "
                        "matches nothing the engine will judge, so the entry would enforce "
                        "nothing (see B-006). Write the path out in full."
                    )
        when[name] = tuple(entries)
    # D-019 (B-033): a whole-`when` shape check, so it runs after the per-predicate
    # loop and not before it. Existing tests build an all-negative `when` on
    # purpose to assert a per-entry message — a relative prefix, a `~` prefix —
    # and they stay right only while those refusals still fire first. `when` is
    # non-empty here: the D-012 guard above already refused the empty spellings,
    # which are a separate question and stay separate.
    if all(name in _NEGATIVE_PREDICATES for name in when):
        raise PolicyError(
            f"rule {rule_id!r}: when uses only negative predicates "
            f"({sorted(when)}) — a negative predicate says what an argument is "
            "NOT, so a rule built only of them matches every argument the "
            "author never thought to exclude, and enforces nothing it reads as "
            "enforcing. Add at least one positive predicate "
            f"({sorted(set(PREDICATES) - _NEGATIVE_PREDICATES)}) "
            "(see B-033 and D-019)."
        )
    return when


def _parse_rule(
    raw: Any, index: int, seen_ids: set[str], hidden_context: HiddenContext
) -> Rule:
    if not isinstance(raw, dict):
        raise PolicyError(f"rules[{index}] must be a mapping")
    unknown = set(raw) - _RULE_KEYS
    if unknown:
        raise PolicyError(f"rules[{index}] has unknown keys: {sorted(unknown)}")
    for required in ("id", "owasp", "tool", "decision"):
        if required not in raw:
            raise PolicyError(f"rules[{index}] is missing required key {required!r}")
    rule_id = raw["id"]
    if not isinstance(rule_id, str) or not rule_id:
        raise PolicyError(f"rules[{index}].id must be a non-empty string")
    if rule_id in seen_ids:
        raise PolicyError(f"duplicate rule id {rule_id!r}")
    # D-026: the reserved namespaces are the ENGINE's, and a policy rule may not
    # borrow one. The published event schema (telemetry/event-schema.json) tells
    # a detection author that `limit:*` means a per-run cap tripped and `hook:*`
    # means the hook refused input it could not judge; a policy free to name a
    # rule `limit:custom-egress` turns that contract into a suggestion, and the
    # detection that trusts it misattributes a policy decision to the engine.
    # Enforced here rather than documented, for the reason D-018 and D-019 give:
    # a discipline the schema does not enforce is one the next author does not
    # know about. Costs nothing in this tree — measured before ruling: of the 25
    # rules across every policy YAML in the repo, 0 carry a reserved prefix.
    borrowed = next((p for p in RESERVED_RULE_ID_PREFIXES if rule_id.startswith(p)), None)
    if borrowed is not None:
        raise PolicyError(
            f"rule {rule_id!r}: {borrowed!r} is a reserved rule-id namespace and a policy "
            f"rule may not use it (reserved: {', '.join(sorted(RESERVED_RULE_ID_PREFIXES))}). "
            "Decision events publish these prefixes as the engine's own attributions - see "
            "telemetry/event-schema.json - so a policy rule wearing one would be read as an "
            "engine decision by every detection built on that schema."
        )
    seen_ids.add(rule_id)
    owasp = raw["owasp"]
    if not isinstance(owasp, str) or not _OWASP_RE.match(owasp):
        raise PolicyError(f"rule {rule_id!r}: owasp must match LLMNN, got {owasp!r}")
    tool = raw["tool"]
    if not isinstance(tool, str) or not tool:
        raise PolicyError(f"rule {rule_id!r}: tool must be a non-empty string")
    note = raw.get("note")
    if note is not None and not isinstance(note, str):
        raise PolicyError(f"rule {rule_id!r}: note must be a string")
    # D-015 (B-011): optional, and absent is not the same as empty. An absent
    # `server:` means "any server" — today's behaviour, which every rule in
    # `policy.example.yaml` keeps. A `server:` that is present must name one, so
    # `server: ""` and `server: null` are refused rather than silently collapsed
    # into "any": both read as a scoping the file does not have, which is the
    # shape this loader already refuses for `when: {}` (D-012), for a relative
    # path prefix (B-006) and for a `~` prefix (D-017). The message says what to
    # write instead, like the rest of them.
    server = raw.get("server")
    if "server" in raw and (not isinstance(server, str) or not server):
        raise PolicyError(
            f"rule {rule_id!r}: server must be a non-empty string naming one MCP "
            f"server, got {server!r} — omit the key entirely for a rule that "
            "matches calls from any server (see B-011)."
        )
    # B-034: and it must be a name BOTH doors can represent. Claude Code frames
    # an MCP tool as `mcp__<server>__<tool>`, and the hook recovers the two
    # halves by splitting on that delimiter, which is not escapable. A server
    # named `prod__west` therefore reaches the hook as `server='prod',
    # tool='west__<tool>'` while a proxy told the same name via `--server-name`
    # reaches the engine as `server='prod__west', tool='<tool>'` -- one
    # deployment, two envelopes, which is precisely the property D-015 rests on.
    # Refused here rather than accepted and mis-meant, like a relative path
    # prefix (B-006), a `~` prefix (D-017) and an empty `when` (D-012).
    #
    # B-037: `__ in server` was not the whole condition. `prod_` contains no
    # `__` and frames to `mcp__prod___read_file`, which splits readably in TWO
    # places -- so the hook denies it while this door LOADED it, the same
    # door-disagreement B-034 exists to close, one boundary over. The condition
    # is read off the wire format by `ambiguous_server_identity` above rather
    # than spelled out twice here.
    if isinstance(server, str) and ambiguous_server_identity(server):
        raise PolicyError(
            f"rule {rule_id!r}: server must not contain '__' or end with '_', got "
            f"{server!r} -- framing it as `mcp__<server>__<tool>` would put the "
            "delimiter in the name more than once, and it is not escapable, so a "
            "server named this way cannot be told apart from a different "
            "server-and-tool pair (see B-034, B-037)."
        )
    # Hoisted out of the `Rule(...)` call because `_parse_when` needs it now:
    # D-018's anchoring check applies to `allow` rules only, and the verdict is
    # not otherwise reachable from inside a when-block.
    decision = _parse_verdict(raw["decision"], f"rule {rule_id!r}: decision")
    return Rule(
        id=rule_id,
        owasp=owasp,
        tool=tool,
        decision=decision,
        when=_parse_when(raw.get("when"), rule_id, decision, hidden_context),
        note=note,
        server=server,
    )


def load_policy(path: str | Path) -> Policy:
    """Load and validate a policy file. Raises :class:`PolicyError` on any
    problem — there is no partially-loaded policy.

    That sentence is now enforced rather than intended (**D-030**). It used to be
    untrue in five measured cases, and the two that had been written down were
    the least interesting ones. Measured over the loader, 2026-08-05:

    ======================================  ====================
    policy file                             escaped as
    ======================================  ====================
    missing / a directory                   ``OSError`` subclass
    **invalid UTF-8 bytes**                 ``UnicodeDecodeError``
    a regex with ~5000 nested groups        ``RecursionError``
    a pattern whose parse WARNS, ``-W error``  ``FutureWarning``
    ======================================  ====================

    All of them fail closed, so none was a wrong verdict — but three of them cost
    the audit trail, which is the thing D-029 exists to protect. Measured at both
    doors on an invalid-UTF-8 policy, against an ordinary ``PolicyError`` control
    in the same run:

    ==========================  ==================  ==================
    policy problem              proxy               hook
    ==========================  ==================  ==================
    bad YAML (control)          exit 2, **1** event  exit 0, ``deny`` + event
    invalid UTF-8               exit 1, **0** events  exit 2, no event, raw repr
    ==========================  ==================  ==================

    So the proxy's ``proxy:policy-error`` outage signal — the whole of D-029 —
    was reachable only for the exception types someone had thought to name, and a
    policy file with one bad byte produced the silent exit D-029 was written to
    abolish. Converting here rather than widening each door's ``except`` clause
    keeps one rule in one place: a door cannot fail to know about an exception
    type this function does not raise.

    The doors keep catching ``(PolicyError, OSError)`` rather than narrowing to
    ``PolicyError`` alone. The ``OSError`` arm is now unreachable through this
    function, and it stays as defence in depth: if this wrapper ever regresses,
    the commonest broken deployment (a policy path that names no file) still
    lands on a clean refusal instead of a crash handler.
    """
    try:
        return _load_policy(path)
    except PolicyError:
        raise
    except Exception as exc:  # noqa: BLE001 — deliberate: see the docstring
        raise PolicyError(f"{path}: policy could not be loaded: {type(exc).__name__}: {exc}") from exc


def _load_policy(path: str | Path) -> Policy:
    text = Path(path).read_text(encoding="utf-8")
    try:
        raw = yaml.load(text, Loader=_StrictLoader)  # SafeLoader + duplicate-key refusal
    except PolicyError as exc:
        raise PolicyError(f"{path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise PolicyError(f"{path}: not valid YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise PolicyError(f"{path}: policy must be a YAML mapping, got {type(raw).__name__}")
    unknown = set(raw) - _DOCUMENT_KEYS
    if unknown:
        raise PolicyError(f"{path}: unknown top-level keys: {sorted(unknown)}")
    if "version" not in raw:
        raise PolicyError(f"{path}: missing required key 'version'")
    version = raw["version"]
    if not isinstance(version, int) or isinstance(version, bool):
        raise PolicyError(f"{path}: version must be an integer, got {version!r}")
    # CP-07: an integer is not a schema. See SUPPORTED_POLICY_VERSIONS above for
    # why an unrecognised version has to be a refusal rather than a value nobody
    # reads — the unknown-key check catches an ADDED key, not a REDEFINED one.
    if version not in SUPPORTED_POLICY_VERSIONS:
        raise PolicyError(
            f"{path}: version must be one of {sorted(SUPPORTED_POLICY_VERSIONS)}, got {version!r}"
        )

    raw_rules = raw.get("rules")
    if raw_rules is None:
        raw_rules = []
    if not isinstance(raw_rules, list):
        raise PolicyError(f"{path}: rules must be a list")
    # Parsed BEFORE the rules: a rule's `args_contain_hidden_context` names
    # declarations from this section and the loader substitutes their segments
    # into the rule, so the section has to exist before any rule is read.
    hidden_context = _parse_hidden_context(raw.get("hidden_context", _ABSENT))
    seen_ids: set[str] = set()
    rules = tuple(_parse_rule(r, i, seen_ids, hidden_context) for i, r in enumerate(raw_rules))

    return Policy(
        version=version,
        defaults=_parse_defaults(raw.get("defaults")),
        limits=_parse_limits(raw.get("limits")),
        rules=rules,
        taint=_parse_taint(raw.get("taint")),
        tool_listing=_parse_tool_listing(raw.get("tool_listing", _ABSENT)),
        hidden_context=hidden_context,
    )
