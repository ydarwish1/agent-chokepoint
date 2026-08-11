"""Data model for the decision engine (the PDP).

Pure data, no I/O. The policy loader (``policy/loader.py``) is the only thing
that constructs a :class:`Policy` from a file; enforcement points construct
:class:`ToolCall` envelopes and read :class:`Decision` results.

Frozen dataclasses throughout: a policy is immutable once loaded, and a
decision is a value, not a process.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Mapping


class Verdict(enum.Enum):
    """The three answers the engine can give."""

    ALLOW = "allow"
    BLOCK = "block"
    ASK = "ask"

    def __str__(self) -> str:  # so f-strings and logs read "allow", not "Verdict.ALLOW"
        return self.value


# Synthetic rule-id prefixes for decisions no policy rule produced.
# Every decision carries an attribution, even when no rule matched.
DEFAULT_RULE_ID = "default:on_no_match"
LIMIT_RULE_PREFIX = "limit:"
TAINT_RULE_PREFIX = "taint:"
LISTING_RULE_PREFIX = "listing:"

# OWASP LLM10:2025 "Unbounded Consumption" — the mapping for limit blocks.
LIMITS_OWASP = "LLM10"
# OWASP LLM01:2025 "Prompt Injection" — the mapping for taint blocks. A taint
# refusal is the third leg of the lethal trifecta being cut: the run has consumed
# untrusted content and is now trying to send something out.
TAINT_OWASP = "LLM01"

# The three rule ids a taint refusal can carry, by REASON rather than by mode —
# a detection wants to know what the gateway saw, and the mode is operator config
# it cannot read off the event. All three sit under the reserved `taint:` prefix,
# which `policy/loader.py` refuses to policy authors (D-026).
TAINT_SECRET_RULE_ID = TAINT_RULE_PREFIX + "secret-egress"
TAINT_NEW_DOMAIN_RULE_ID = TAINT_RULE_PREFIX + "new-domain-egress"
TAINT_EGRESS_RULE_ID = TAINT_RULE_PREFIX + "egress"

# OWASP LLM04:2026 "Supply Chain" — the mapping for tool-listing decisions
# (D-039). The 2026 document's own eight scenarios are model-artifact scenarios
# and it routes MCP servers and tool registries to OWASP's separate Agentic
# Supply Chain document, so the ONE leg of LLM04 that can arrive at this door is
# the integrity of the tool definitions the agent is handed — which is what these
# ids are about and all they are about.
LISTING_OWASP = "LLM04"

# The four rule ids a tool-listing decision can carry, by REASON rather than by
# which policy key produced them — the same discipline the `taint:` ids follow
# (B-046): the id is the only place the event says what this gateway SAW, and an
# operator's configuration is not readable off the event.
#: The listing matched the operator's approved definitions exactly.
LISTING_APPROVED_RULE_ID = LISTING_RULE_PREFIX + "approved"
#: The listing carried a tool this policy approves no definition of at all.
LISTING_UNPINNED_RULE_ID = LISTING_RULE_PREFIX + "unpinned-tool"
#: A tool this policy DOES approve arrived with a different definition.
LISTING_DRIFT_RULE_ID = LISTING_RULE_PREFIX + "definition-drift"
#: One run was served two different definitions of the same tool. Strictly the
#: strongest of the three: no benign server upgrade can produce it inside one
#: MCP client session (D-022's definition of a run).
LISTING_MIDRUN_RULE_ID = LISTING_RULE_PREFIX + "definition-changed-mid-run"


class EgressMode(enum.Enum):
    """How much a tainted run is allowed to send (D-031). Operator-selectable.

    An enum rather than a string for the reason ``Verdict`` is one: a mode this
    engine does not know must raise where it is read, not silently evaluate to
    "refuse nothing".
    """

    #: Refuse an egress call carrying a credential pattern. The narrowest, and
    #: the shipped default: it adds no new MATCHING — `net-egress-sensitive`
    #: already does this for `fetch_url` — it widens where that matching applies.
    SECRETS_ONLY = "secrets_only"
    #: The above, plus an egress call naming a host outside ``allowed_domains``.
    SECRETS_AND_NEW_DOMAINS = "secrets_and_new_domains"
    #: Every egress call after taint. Strictest; it will break ordinary research.
    ALL_EGRESS = "all_egress"

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class Rule:
    """One policy rule. ``when`` holds fixed-vocabulary predicates (D-006), and
    is wrapped in a :class:`~types.MappingProxyType` at construction so a loaded
    policy cannot be edited in place (B-012)."""

    id: str
    owasp: str
    tool: str
    decision: Verdict
    when: Mapping[str, Any] = field(default_factory=dict)
    note: str | None = None
    # D-015 (B-011): the MCP server this rule binds to, or ``None`` for "any
    # server", which is every rule written before this field existed and every
    # rule in ``policy/policy.example.yaml``. ``engine/decide.py:_matches``
    # holds the comparison and the trap that goes with it.
    #
    # Appended rather than slotted in beside ``tool``, where it reads more
    # naturally: every construction site in this repo passes keywords (checked,
    # 2026-08-02 — ``engine/tests``, ``policy/loader.py``, ``proxy/server.py``,
    # ``hooks/chokepoint_hook.py``), so the position is free either way, and the
    # end of the list is the position that stays free if one ever does not.
    server: str | None = None

    def __post_init__(self) -> None:
        # B-012: ``frozen=True`` freezes the binding, not the object bound. A
        # plain dict here meant a loaded policy could be edited under the
        # engine: measured at HEAD bbb8d15, popping ``path_not_within`` off
        # ``policy.rules[0].when`` turned ``/workspace/.ssh/id_rsa`` from
        # ``block / default:on_no_match`` into ``allow / fs-read-scoped``.
        # Defence in depth rather than a live bypass — it needs code already
        # running in-process — but the module docstring above claims an
        # immutability this type did not have, and this slot is exactly where an
        # in-process policy reload would land.
        #
        # The proxy wraps a private copy, not the caller's mapping: a proxy over
        # a dict the caller still holds is a view, and their own ``.pop`` reaches
        # straight through it.
        #
        # Measured before writing it, so nothing downstream shifts: equality is
        # unchanged (a mappingproxy compares as its underlying dict, so both
        # ``Rule == Rule`` and ``rule.when == {...}`` still hold); ``Rule`` was
        # already unhashable and still is (dict and mappingproxy are both
        # unhashable, so ``hash(Rule)`` raised ``TypeError`` before and after);
        # and ``dataclasses.replace`` re-enters here and re-wraps cleanly, which
        # is how ``policy/tests/test_example_policy_rules.py`` builds its
        # guard-off control. Only ``repr`` changes — ``when=mappingproxy({...})``
        # — and nothing in the repo asserts on a Rule's repr.
        #
        # Shallow by construction, and that is enough here: ``policy/loader.py``
        # stores each predicate's entries as a tuple, so a loaded policy is
        # immutable through and through; a hand-built Rule that passes a list as
        # a value keeps that list mutable.
        object.__setattr__(self, "when", MappingProxyType(dict(self.when)))


@dataclass(frozen=True)
class Limits:
    """Run-level caps (policy ``limits:``). ``None`` means uncapped."""

    max_tool_calls_per_run: int | None = None
    max_wall_clock_seconds: int | None = None
    max_repeated_identical_calls: int | None = None


@dataclass(frozen=True)
class Defaults:
    """Policy ``defaults:``. Deny by default — both fields fall back to BLOCK."""

    decision: Verdict = Verdict.BLOCK
    on_no_match: Verdict = Verdict.BLOCK


@dataclass(frozen=True)
class Taint:
    """Policy ``taint:`` — what a run that has consumed untrusted content may do.

    D-031. The gateway does not try to decide whether consumed content is
    malicious; that is content filtering, which this project rules out of scope
    and could not measure anyway. It records a FACT — this run has consumed a
    result from a source the operator called untrusted — and lets the policy
    tighten what is allowed afterwards.

    ``sources`` are tools whose RESULTS mark the run tainted. ``egress_tools`` are
    tools whose ARGUMENTS can carry data out of the trust boundary; the two are
    deliberately separate lists, because a tool that returns untrusted content
    (`read_file` on a cloned repo) is not the same set as a tool that sends data
    out (`run_command` with a network command), even though `fetch_url` is both.

    Empty by default, and an empty ``sources`` or ``egress_tools`` means taint can
    never fire — which is exactly the behaviour of every policy written before
    this field existed.
    """

    sources: tuple[str, ...] = ()
    egress_tools: tuple[str, ...] = ()
    egress_mode: EgressMode = EgressMode.SECRETS_ONLY
    on_taint: Verdict = Verdict.BLOCK
    #: Hosts still reachable AFTER taint, for ``SECRETS_AND_NEW_DOMAINS``. This is
    #: deliberately its own list rather than the allow rules' ``domain_in``
    #: entries: "which hosts may this run reach once it has read something
    #: untrusted" is a different question from "which hosts may it reach at all",
    #: and the answer is legitimately narrower. Empty means no host is exempt.
    allowed_domains: tuple[str, ...] = ()


@dataclass(frozen=True)
class ToolListingPolicy:
    """Policy ``tool_listing:`` — the tool definitions the operator APPROVED.

    D-039. ``approved`` maps a tool name to the digest of the exact
    definition the operator signed off, spelled ``sha256:<64 lowercase hex>``;
    :func:`engine.listing.tool_definition_digest` is what produces one.

    **This is an integrity control, not a content filter.** Nothing here reads a
    description, looks for instructions in one, or forms any opinion about what a
    description says — that is content filtering, which this project rules out of
    scope in ``README.md`` and could not measure. The only question asked is
    *is this the definition the operator approved*, and the only two answers are
    yes and no. A hostile description the operator approved is approved; that is
    written down in ``docs/LIMITATIONS.md`` rather than papered over.

    There is deliberately no "report only" mode and no ``on_unapproved:`` verdict
    knob. At this door ``ask`` has no approver (D-005 fails it closed) and the
    hook door never sees a listing at all, so the knob would have exactly one
    honest value — D-022's own reason for refusing a ``limits.scope:`` knob.
    """

    approved: Mapping[str, str]

    def __post_init__(self) -> None:
        # B-012's lesson: ``frozen=True`` freezes the binding, not the object
        # bound, and this mapping is consulted on every listing decision.
        object.__setattr__(self, "approved", MappingProxyType(dict(self.approved)))


@dataclass(frozen=True)
class HiddenContext:
    """Policy ``hidden_context:`` — material the operator says must not leave.

    D-049, for OWASP LLM08:2026. Each declaration is a NAME the policy's rules
    can arm and a FILE the loader read at load time; ``segments`` holds what
    ``engine.predicates.hidden_context_segments`` derived from that file's text
    and ``sources`` holds the path it came from, so a reader can say which
    declaration a rule names without the content being in the policy file.

    **The content is deliberately not in the policy file.** An operator who
    pasted their system prompt into ``policy.yaml`` would have moved the hidden
    context into a document that is reviewed, diffed and committed — and, under
    the shipped example policy, into a file a call can read whenever it sits
    inside an allowed prefix (B-088). The loader accepts a path and nothing else
    for that reason.

    Empty by default, so every Policy built before this field existed carries a
    declaration set that can never match — which is exactly what those policies
    did.
    """

    #: name -> the segments derived from that declaration's file.
    segments: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    #: name -> the absolute path declared for it. Never the content.
    sources: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # B-012's lesson: `frozen=True` freezes the binding, not the object
        # bound, and both mappings are consulted on every judged call.
        object.__setattr__(self, "segments", MappingProxyType(dict(self.segments)))
        object.__setattr__(self, "sources", MappingProxyType(dict(self.sources)))

    @property
    def all_segments(self) -> tuple[str, ...]:
        """Every declared segment, from every set, deduplicated.

        What the enforcement points redact on. Deliberately every set rather
        than the sets some rule arms: redaction keys off CONTENT, not off which
        rule fired (``proxy/server.py:_loggable_arguments``), so declaring
        material keeps it out of the log even where no rule refuses the call
        that carries it.
        """
        seen: dict[str, None] = {}
        for segments in self.segments.values():
            for segment in segments:
                seen.setdefault(segment, None)
        return tuple(seen)


@dataclass(frozen=True)
class ToolDefinition:
    """One advertised tool, reduced to the two facts a listing decision needs.

    The enforcement point parses the wire and computes the digest; the engine is
    handed this neutral pair, exactly as it is handed a :class:`ToolCall` rather
    than an MCP request. The engine therefore never holds a description, which is
    what makes "this door does not read descriptions" a property of the code
    rather than a promise about it.
    """

    name: str
    digest: str


@dataclass(frozen=True)
class ToolListing:
    """The envelope handed to :func:`engine.listing.decide_listing`.

    ``seen`` is name -> digest for every definition ALREADY handed to this run —
    the enforcement point supplies it, the way it supplies :class:`RunState`,
    because a run is a session and the engine has none. Only definitions that
    were ALLOWED THROUGH belong in it: a refused listing never reached the agent,
    so it never became part of what the agent was told exists.
    """

    tools: tuple[ToolDefinition, ...]
    seen: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "seen", MappingProxyType(dict(self.seen)))


@dataclass(frozen=True)
class Policy:
    version: int
    defaults: Defaults
    limits: Limits
    rules: tuple[Rule, ...]
    # Appended with a default, so every Policy built before taint existed — in
    # tests, in the loader, by hand — constructs unchanged and carries taint
    # that can never fire.
    taint: Taint = Taint()
    # D-039. ``None`` means the tool-listing door is NOT ARMED and
    # ``tools/list`` forwards exactly as it did before this field existed, which
    # is what every Policy built before it keeps. It is ``None`` rather than an
    # empty :class:`ToolListingPolicy` because "the operator approved nothing"
    # and "the operator is not pinning definitions" are opposite instructions,
    # and the loader refuses the first spelling outright.
    tool_listing: ToolListingPolicy | None = None
    # D-049. Empty means no material is declared, which is what every Policy
    # built before this field existed carries — and an empty declaration set can
    # never match, so those policies behave exactly as they did.
    hidden_context: HiddenContext = HiddenContext()


@dataclass(frozen=True)
class RunState:
    """Counters an enforcement point supplies so limit checks stay pure.

    All counts are of calls *already attempted* before the call being decided,
    blocked attempts included — ``max_repeated_identical_calls`` exists to
    catch blocked-then-retry loops, so blocked attempts must count.
    """

    calls_made: int = 0
    elapsed_seconds: float = 0.0
    identical_calls: int = 0
    #: Has this run consumed a result from a tool in ``Taint.sources``? D-031.
    #: The ENFORCEMENT POINT sets it and passes it in; the engine only
    #: reads it, which is what keeps the engine pure — taint is a fact about a
    #: session, and the engine has no session, no clock and no I/O. Default False,
    #: so an enforcement point that does not track taint (the Claude Code hook,
    #: which holds no run at all) behaves exactly as it did before.
    tainted: bool = False


@dataclass(frozen=True)
class ToolCall:
    """The envelope handed to the engine — one tool call to judge.

    ``arguments`` is whatever the agent sent, unmassaged; the MCP SDK does not
    validate tool arguments, and ``None`` is a legal value on the wire.
    ``agent_id`` is the D-007 working assumption: rules may later scope to it.
    ``run_state`` is optional — without it, limit checks are skipped (the
    enforcement point owns the counters; the engine owns no state).

    ``server`` is the MCP server the call arrived from, or ``None`` when there
    is no server to name (D-015, B-011). The enforcement point supplies it, the
    way it supplies ``run_state``: the hook reads it off the ``mcp__<server>__``
    prefix it was already splitting and throwing away, and the proxy takes it
    from its ``--server-name`` flag because it fronts exactly one upstream. It
    is deliberately NOT derived from ``tool``, which stays the bare tool name at
    both doors — that is what keeps the envelope the two doors judge identical
    apart from this one field, and the byte-identical envelope is what
    ``hooks/demo/side_by_side.py`` exists to demonstrate.
    """

    tool: str
    arguments: Mapping[str, Any] | None = None
    agent_id: str | None = None
    run_state: RunState | None = None
    server: str | None = None


@dataclass(frozen=True)
class Decision:
    """The engine's answer. ``rule_id`` is always set (AgentJail-style
    attribution): a real rule id, ``limit:<name>``, or ``default:on_no_match``.
    """

    verdict: Verdict
    rule_id: str
    owasp: str | None
    reason: str
