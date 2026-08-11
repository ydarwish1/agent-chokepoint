"""decide() — the pure decision function of the decision point (PDP).

Semantics, in evaluation order:

1. **Limits** (only when the envelope carries ``run_state``): checked before
   any rule, in this order — ``max_tool_calls_per_run``,
   ``max_wall_clock_seconds``, ``max_repeated_identical_calls``. The first
   exceeded cap blocks with rule id ``limit:<name>`` (OWASP LLM10).

2. **Rules**: a rule matches when its ``tool`` equals the call's tool, its
   ``server`` binds (D-015 — a rule naming a server matches only that server,
   including never matching a call with no server; a rule naming none matches
   any), AND every ``when`` predicate is satisfied. A predicate that cannot
   find or parse its argument is unsatisfied (see ``predicates.py``);
   ``arguments`` with nothing to read by key — ``None``, a JSON array or
   scalar, anything else the wire delivered — reaches each predicate in the
   only shape that predicate can read: ``{}`` for the five that bind to one
   key, and the value itself for the three that scan every string in the
   envelope (CP-06, :data:`_SCANNED_PREDICATES`).

2b. **Taint** (D-031): when ``run_state.tainted`` is set and the call
   goes to a tool in ``policy.taint.egress_tools``, the mode in
   ``policy.taint.egress_mode`` may produce a ``taint:`` verdict. It is applied
   AFTER steps 3 and 4 below have produced a decision, and only when it is
   STRICTLY TIGHTER than that decision — so taint can never loosen one and never
   changes an attribution it did not decide. See :func:`_tightened_by_taint`,
   which also records why the first design (append a synthetic rule to the
   matching set and let precedence sort it out) was unsound.

3. **Precedence across all matching rules: block > ask > allow.** File order
   is NOT precedence — the example policy's own ``net-egress-sensitive``
   (block) must override the earlier ``net-fetch-allowlist`` (allow) when a
   secret rides an otherwise-permitted request. Within the winning verdict,
   the first matching rule in file order supplies the id. A matching rule whose
   ``decision`` is not a :class:`Verdict` raises, the way an unknown predicate
   does — the engine never silently drops a rule it cannot read (B-013).

4. **No rule matches** → ``defaults.on_no_match`` (block unless the policy
   explicitly says otherwise) with rule id ``default:on_no_match``.

Every decision carries a rule id. No I/O, no clock, no network: elapsed time
arrives inside ``run_state``, supplied by the enforcement point.
"""

from __future__ import annotations

from typing import Any

from .model import (
    DEFAULT_RULE_ID,
    LIMIT_RULE_PREFIX,
    LIMITS_OWASP,
    TAINT_EGRESS_RULE_ID,
    TAINT_NEW_DOMAIN_RULE_ID,
    TAINT_OWASP,
    TAINT_SECRET_RULE_ID,
    Decision,
    EgressMode,
    Policy,
    Rule,
    ToolCall,
    Verdict,
)
from .predicates import PREDICATES, contains_sensitive, domain_in

_PRECEDENCE = (Verdict.BLOCK, Verdict.ASK, Verdict.ALLOW)

#: The predicates that read the WHOLE envelope instead of one key, and so must
#: be handed ``call.arguments`` as it arrived (CP-06, second half).
#:
#: Every predicate is typed ``(spec, Args) -> bool`` with ``Args`` a Mapping, but
#: the vocabulary splits in two underneath that annotation, and the halves answer
#: a malformed envelope differently:
#:
#: * ``path_within``, ``path_not_within``, ``path_segment_not_in``, ``domain_in``
#:   and ``command_matches_any`` bind to ONE key — ``args.get("path")``,
#:   ``args.get("url")``, ``args.get("command")``. A value that answers no
#:   ``get`` has no key to bind and the read raises ``AttributeError``. ``{}``
#:   is the honest substitute: the argument is absent, so the predicate is
#:   unsatisfied, which is what ``predicates.py`` already promises for an
#:   argument it cannot find.
#: * ``args_match_any``, ``args_contain_invisible_characters`` and
#:   ``args_contain_hidden_context`` ask about every string ANYWHERE in the
#:   arguments and ride ``_strings_in``, which walks str, Mapping, list and tuple
#:   alike. They read a malformed envelope perfectly well, and they are the
#:   credential, invisible-character and declared-material scans — three
#:   questions whose answer must not depend on the shape of the container the
#:   strings arrived in.
#:
#: Normalising to ``{}`` for all eight — the first spelling of this fix — deleted
#: the second half's matches in order to stop the first half's crash. Measured
#: one variable apart (HEAD a4f614a's ``engine/`` with only ``decide.py``
#: swapped), against a policy whose ``fetch_url`` rules are scans only
#: (``net-egress-sensitive``, ``args_match_any: [secret_like,
#: private_key_block]``, plus an ``args_contain_invisible_characters`` rule
#: beside it) under ``on_no_match: allow``:
#:
#:     arguments=[<AKIA-shaped str>]   pre block/net-egress-sensitive   blanket allow/default:on_no_match
#:     arguments=<AKIA-shaped str>     pre block/net-egress-sensitive   blanket allow/default:on_no_match
#:     arguments=[<zero-width str>]    pre block/args-invisible         blanket allow/default:on_no_match
#:     arguments={"k": <AKIA>} ctrl    pre block/net-egress-sensitive   blanket block/net-egress-sensitive
#:
#: Three refusals deleted by a crash fix, with the Mapping control unmoved beside
#: them. Under ``on_no_match: block`` the verdict survives and the ATTRIBUTION
#: flips to ``default:on_no_match``, so the event stops saying what this gateway
#: saw — the same loss ``_taint_rule_id``'s B-046 note refuses one function down.
#:
#: The scope of that loss is narrower than "any malformed envelope", and stating
#: it narrowly is the point. It needs a policy whose MATCHING rules on that tool
#: are scans only. ``policy/policy.example.yaml`` is not one: it puts
#: ``net-fetch-allowlist`` (``domain_in``) on ``fetch_url`` ahead of
#: ``net-egress-sensitive``, so the keyed rule is evaluated first and the pre-fix
#: tree RAISES on the same call — under the shipped file this fix only ever adds
#: a decision where there was a crash, and nothing is lost either way.
#:
#: The shape is not contrived, though, and it is not hypothetical either: the
#: vocabulary has three predicates that bind to no key at all, so any rule
#: written with only those and no key-bound rule beside it on the same tool is
#: scan-only by construction. ``args_contain_invisible_characters`` and
#: ``args_contain_hidden_context`` appear in no shipped policy file today
#: (grepped: the only ``args_match_any`` uses are ``policy.example.yaml``,
#: ``hooks/demo/policy.sandbox.example.yaml``, ``hooks/tests/policy.fixture.yaml``
#: and the rendered chart manifest), so this is a statement about what an
#: operator can write, not about a rule that ships broken.
#:
#: This is the split :func:`_taint_rule_id` already makes between its ``scanned``
#: and ``keyed`` reads, applied to the identical question one function earlier.
#: Both sites now go through :func:`_scanned_arguments` / :func:`_keyed_arguments`
#: so they cannot drift apart again. An unlisted name falls to the keyed half,
#: which is the fail-closed direction for a new key-bound predicate;
#: ``engine/tests/test_decide.py::TestTheEnvelopeSplitMatchesTheVocabulary``
#: measures this set
#: against ``PREDICATES`` rather than trusting it, so a new scanning predicate
#: cannot be added without classifying it here.
_SCANNED_PREDICATES = frozenset(
    {
        "args_match_any",
        "args_contain_invisible_characters",
        "args_contain_hidden_context",
    }
)


def _scanned_arguments(call: ToolCall) -> Any:
    """``call.arguments`` as it arrived, for the predicates in
    :data:`_SCANNED_PREDICATES`; ``{}`` for ``None`` (CP-06).

    ``None`` is the one off-Mapping value with nothing in it to read — the MCP
    wire allows ``arguments`` to be absent entirely — and ``None`` and ``{}``
    produce the same empty walk through ``_strings_in``, so that substitution is
    bookkeeping rather than policy. Every other value passes through untouched.
    """
    return call.arguments if call.arguments is not None else {}


def _keyed_arguments(call: ToolCall) -> Any:
    """``call.arguments`` for the reads that bind to a key; ``{}`` when there is
    no key to read out of it (CP-06).

    ``ToolCall.arguments`` is typed ``Mapping[str, Any] | None``, but nothing on
    the wire enforces that — ``model.py`` says it is "whatever the agent sent,
    unmassaged". The old spelling special-cased ``None`` and handed everything
    else straight through, so any rule reaching one of the five key-bound
    predicates — each of which calls ``args.get(...)`` — left ``decide()`` as an
    uncaught ``AttributeError`` when handed a list, str, int or bool. Measured at
    HEAD a4f614a against one allow rule on ``read_file``:

        dict (control)     allow / fs-read-scoped
        None (control)     block / default:on_no_match
        list/str/int/bool  RAISED AttributeError: 'X' object has no attribute 'get'

    A crash where a decision belongs, and it contradicted three statements in
    this package: ``predicates.py``'s "never an exception, never a pass ...
    malformed input falls to ``defaults.on_no_match``", this module's own
    docstring, and ``model.py``'s ``ToolCall``.

    Graded as a contract violation rather than a live bypass, because both
    shipped doors guard the type upstream today — ``hooks/chokepoint_hook.py``'s
    ``_parse_payload`` refuses a non-object ``tool_input`` naming this exact
    hazard ("a JSON array there would raise from inside ``decide()``"), and the
    proxy takes ``arguments`` off a pydantic-typed params model. But the engine
    is the piece this project promises is "importable standalone"
    (``engine/README.md``), so the door's guard is not the engine's
    contract, and a third enforcement point would inherit the crash.

    With the read checked here, an envelope with no key to bind leaves every
    KEY-BOUND predicate unsatisfied — none of them can find their argument — so a
    rule that binds to a key stops matching instead of raising, and absent any
    other match the call falls to ``defaults.on_no_match``, which is what the
    module docstring already promised for malformed input.

    The three whole-envelope scans are deliberately NOT routed through here: they
    can read the raw value and they lose real matches if handed ``{}``. They take
    :func:`_scanned_arguments` instead, and :data:`_SCANNED_PREDICATES` carries
    the measurement of what routing them through here cost.

    **The test is ``hasattr(..., "get")`` and not ``isinstance(..., Mapping)``,
    and the difference was measured rather than argued.** The nominal spelling
    was written first, and it NARROWS what this engine reads: a mapping-like
    object that never registered with ``collections.abc.Mapping`` answers ``get``
    perfectly well, so the pre-fix engine judged it, and a nominal check sends it
    to ``{}`` instead. Measured one variable apart — HEAD a4f614a's ``engine/``
    against the nominal spelling, with a hand-rolled mapping exposing
    ``get``/``keys``/``values``/``__getitem__`` and one block rule per row:

        deny    duck {"command": <destructive>}  pre block/<the rule>  nominal block/default:on_no_match
        deny    duck {"path": <denied prefix>}   pre block/<the rule>  nominal block/default:on_no_match
        permit  duck {"command": <destructive>}  pre block/<the rule>  nominal allow/default:on_no_match
        permit  duck {"path": <denied prefix>}   pre block/<the rule>  nominal allow/default:on_no_match
        dict control beside each of the four                           unmoved

    Under the shipped deny default those are ATTRIBUTIONS deleted — the event
    stops saying what this gateway saw, the same loss ``_taint_rule_id``'s B-046
    note refuses one function down. Under an explicitly permissive default they
    are REFUSALS deleted, which is the exact ground on which the blanket-``{}``
    spelling was rejected for the scanning predicates
    (:data:`_SCANNED_PREDICATES`), and the same standard has to answer here. The
    taint path pays it twice over: with ``{}`` there is no ``url`` for
    ``_taint_rule_id`` to place, so the post-taint host check is skipped as well.

    So the check asks the only question these five reads actually ask: is there a
    ``get`` to bind a key through? That closes every shape CP-06 names without
    moving a single decision. It costs nothing on the wire either: ``json.loads``
    produces dict, list, str, int, float, bool or ``None``, and of those only
    ``dict`` answers ``get`` (measured), so for both shipped doors the two
    spellings are indistinguishable and the narrowing would bite only in-process
    callers — precisely the standalone-import case this fix exists for. Driven
    across a grid of rule shapes x argument shapes x defaults x taint modes, every
    cell the pre-fix engine DECIDED is decided identically here; the only cells
    that move are the ones that used to raise.

    Its cost, stated rather than left implied: an object that answers ``get``
    with an incompatible signature still raises, exactly as it did pre-fix. This
    change neither worsens nor closes that, and it is deliberately not pinned by
    a test — asserting a crash as required behaviour is what
    ``predicates.py``'s own "never an exception" promise forbids.
    """
    return call.arguments if hasattr(call.arguments, "get") else {}


def _check_limits(policy: Policy, call: ToolCall) -> Decision | None:
    state = call.run_state
    if state is None:
        return None
    limits = policy.limits
    exceeded: str | None = None
    if limits.max_tool_calls_per_run is not None and state.calls_made >= limits.max_tool_calls_per_run:
        exceeded = "max_tool_calls_per_run"
    elif limits.max_wall_clock_seconds is not None and state.elapsed_seconds >= limits.max_wall_clock_seconds:
        exceeded = "max_wall_clock_seconds"
    elif (
        limits.max_repeated_identical_calls is not None
        and state.identical_calls >= limits.max_repeated_identical_calls
    ):
        exceeded = "max_repeated_identical_calls"
    if exceeded is None:
        return None
    return Decision(
        verdict=Verdict.BLOCK,
        rule_id=LIMIT_RULE_PREFIX + exceeded,
        owasp=LIMITS_OWASP,
        reason=f"run limit {exceeded} reached",
    )


def _matches(rule: Rule, call: ToolCall) -> bool:
    if rule.tool != call.tool:
        return False
    # D-015 (B-011): a rule that names a server matches only that server. A rule
    # that names none is unchanged — `rule.server is None` short-circuits before
    # `call.server` is ever read, so every rule written before this field existed
    # keeps today's behaviour exactly.
    #
    # THE TRAP, and the reason this is `!=` against a possibly-None call rather
    # than "match when the call does not contradict the rule": a rule carrying
    # `server: trusted` must NOT match a call whose server is None. Otherwise the
    # strict spelling would be WEAKER than the loose one — an allow rule scoped
    # to one server would also answer for every call arriving with no server
    # identity at all, which at the proxy door is every call until an operator
    # remembers `--server-name`. `None != "trusted"` is False here, so the rule
    # does not match and the call falls to the other rules and then to
    # deny-by-default. Asserted by name in `engine/tests/test_decide.py`.
    #
    # What this closes, measured on the pre-fix tree at HEAD 385b56b by driving
    # `hooks/chokepoint_hook.py` as a real subprocess with the shipped policy:
    # `mcp__trusted__read_file` and `mcp__attacker__read_file` on
    # {"path": "/workspace/README.md"} BOTH returned permissionDecision "allow"
    # from rule `fs-read-scoped`, because the hook stripped the prefix and the
    # engine had no way to tell the two servers apart.
    if rule.server is not None and rule.server != call.server:
        return False
    # CP-06: each half of the vocabulary gets the envelope in the only shape it
    # can read. Both are computed once per rule rather than per predicate —
    # neither allocates when `arguments` already answers `get`.
    keyed = _keyed_arguments(call)
    scanned = _scanned_arguments(call)
    for name, spec in rule.when.items():
        predicate = PREDICATES.get(name)
        if predicate is None:
            # The loader validates the vocabulary; reaching this means a Policy
            # was built by hand around it. Fail loudly, never open.
            raise ValueError(f"unknown predicate {name!r} in rule {rule.id!r}")
        if not predicate(spec, scanned if name in _SCANNED_PREDICATES else keyed):
            return False
    return True


def _taint_rule_id(policy: Policy, call: ToolCall) -> str | None:
    """The ``taint:`` rule id this call earns, or ``None`` if taint says nothing.

    D-031. This answers only "does taint have an opinion, and which of the
    three questions produced it". Whether that opinion is ALLOWED to change
    the decision is :func:`_tightened_by_taint`'s job, and the split is the
    correction to this function's first design — see that docstring.

    Reads ``run_state.tainted``, which the enforcement point set. The engine
    never decides that a run is tainted — it has no session and no results.

    What the modes ask, all of it over ``arguments`` this engine was handed:

    * ``SECRETS_ONLY`` — does any string in the arguments match a published
      credential format? This adds no new matching: it is ``contains_sensitive``,
      the same union of ``ARG_MATCHERS`` that ``args_match_any`` evaluates and
      that both doors already use for log redaction. Under the shipped policy it
      is a no-op for ``fetch_url``, where ``net-egress-sensitive`` blocks the same
      calls untainted — what taint adds is that matching on the OTHER egress
      tools, which D-028 deliberately left out of that rule's scope.
    * ``SECRETS_AND_NEW_DOMAINS`` — the above, or a call carrying a ``url`` whose
      host is not in ``allowed_domains``. An unparseable or ambiguous URL is a
      host this engine cannot place, so it counts as new: fail closed, the same
      answer ``domain_in`` already gives everywhere else.
    * ``ALL_EGRESS`` — any call to an egress tool.

    A call to a tool that is not in ``egress_tools`` is never taint-refused,
    whatever the mode: taint bounds what leaves, not what the agent may do.

    **The credential question is asked FIRST, under every mode** (B-046). The
    mode decides *whether* taint has an opinion; it must never decide *which of
    the three facts gets reported*, because the id is the only place the event
    says what this gateway saw — ``telemetry/event-schema.json`` promises a
    detection author exactly that, and ``engine/model.py`` says the ids are "by
    REASON rather than by mode". Measured before this ordering: under
    ``all_egress`` an ``echo <AKIA-shaped string>`` was attributed
    ``taint:egress``, byte-identical to the ``pwd`` control beside it, so a
    detection filtering on ``taint:secret-egress`` saw nothing in the one
    deployment that refuses the most. The verdict was — and still is —
    identical either way; only the attribution changes, and it changes to the
    more specific true one.

    ``allowed_domains`` stays consulted under ``SECRETS_AND_NEW_DOMAINS`` only,
    which is what the policy file's own comment promises: reading it under
    ``all_egress`` would put ``taint:new-domain-egress`` on every url-bearing
    call in a mode whose operator never wrote that list.
    """
    taint = policy.taint
    state = call.run_state
    if state is None or not state.tainted:
        return None
    if call.tool not in taint.egress_tools:
        return None

    # CP-06's second site, and the same split :func:`_matches` makes — one shared
    # pair of helpers now, because applying it on one branch and not the
    # identical branch beside it is exactly how the first attempt at this fix
    # went wrong.
    #
    # `contains_sensitive` takes ``Any`` and rides ``_strings_in``, which walks
    # str, Mapping, list and tuple alike, so it reads a malformed envelope's
    # strings perfectly well. Normalising it to ``{}`` would DROP a refusal this
    # engine makes today: measured pre-fix, a tainted ``fetch_url`` carrying
    # ``arguments=[<AKIA-shaped string>]`` under a permissive
    # ``defaults.on_no_match`` returned block/``taint:secret-egress``, and it
    # still does. So the credential question keeps the raw value.
    #
    # The two reads below bind to the key ``url`` and cannot: pre-fix they raised
    # ``AttributeError: 'list' object has no attribute 'get'`` straight out of
    # ``decide()`` — on the taint path, with ``_matches`` never consulted, because
    # an empty rule set reaches this line without touching the arguments at all.
    # Fixing only ``_matches`` would have left that counterexample live underneath
    # a test asserting the contract holds, which is precisely the half-tested
    # shape :func:`_tightened_by_taint` records below.
    scanned = _scanned_arguments(call)
    keyed = _keyed_arguments(call)
    mode = taint.egress_mode

    if contains_sensitive(scanned):
        return TAINT_SECRET_RULE_ID
    if mode is EgressMode.SECRETS_AND_NEW_DOMAINS and keyed.get("url") is not None and not domain_in(
        taint.allowed_domains, keyed
    ):
        return TAINT_NEW_DOMAIN_RULE_ID
    if mode is EgressMode.ALL_EGRESS:
        return TAINT_EGRESS_RULE_ID
    if mode in (EgressMode.SECRETS_ONLY, EgressMode.SECRETS_AND_NEW_DOMAINS):
        return None
    # Unreachable for the three members above, and deliberately loud rather than
    # open if a fourth is ever added without being handled here — the same
    # posture `_matches` takes on an unknown predicate.
    raise ValueError(f"unhandled taint egress_mode {mode!r}")


def _tightened_by_taint(policy: Policy, call: ToolCall, decision: Decision) -> Decision:
    """``decision``, or the taint verdict when that is STRICTLY TIGHTER.

    **This function is a correction, and the correction is the interesting part.**
    Taint was first implemented by appending a synthetic rule to the matching set
    and letting the ``block > ask > allow`` precedence sort it out, on the
    argument that adding an element to that set can only move the winning verdict
    up the precedence — so tightening was true "by construction". That argument
    was falsified and the counterexample reproduced immediately: the precedence
    loop is not the only way ``decide`` answers. When NO rule matches,
    it falls through to ``defaults.on_no_match``, and that fallthrough is outside
    the matching set the argument was about. Appending a synthetic rule made the
    set non-empty, so the taint verdict REPLACED the default instead of competing
    with it. Measured on the pre-fix tree, no ``fetch_url`` rule, default block:

        on_taint: block   clean block/default:on_no_match   tainted block/taint:egress
        on_taint: ask     clean block/default:on_no_match   tainted ASK/taint:egress
        on_taint: allow   clean block/default:on_no_match   tainted ALLOW/taint:egress

    The last two are taint LOOSENING a decision, which is the one thing it must
    never do. (``on_taint: allow`` is refused by the loader, but the engine judges
    hand-built policies too, and the test written to cover exactly that case
    missed it because it always supplied a matching block rule — so the emergent
    property was never really tested, only its easy half.)

    So tightening is now CHECKED rather than emergent: compare the taint verdict
    against the decision that was actually reached — rule-matched or default —
    and take it only when it sits strictly earlier in ``_PRECEDENCE``. A taint
    verdict equal to or weaker than the base changes nothing, which also fixes
    the second half of that finding: ``default:on_no_match`` keeps its
    attribution, where append-last could not preserve it.

    An ``on_taint`` outside :class:`Verdict` raises out of ``.index`` rather than
    being silently ignored — B-013's posture, and the reason this is not a
    ``try``.
    """
    rule_id = _taint_rule_id(policy, call)
    if rule_id is None:
        return decision
    on_taint = policy.taint.on_taint
    if _PRECEDENCE.index(on_taint) >= _PRECEDENCE.index(decision.verdict):
        return decision
    return Decision(
        verdict=on_taint,
        rule_id=rule_id,
        owasp=TAINT_OWASP,
        reason=(
            f"rule {rule_id} tightened {decision.verdict} from {decision.rule_id} to {on_taint}: "
            f"this run has consumed untrusted content"
        ),
    )


def decide(policy: Policy, call: ToolCall) -> Decision:
    """Judge one tool call against one policy. Pure function."""
    limit_decision = _check_limits(policy, call)
    if limit_decision is not None:
        return limit_decision

    return _tightened_by_taint(policy, call, _decide_on_rules(policy, call))


def _decide_on_rules(policy: Policy, call: ToolCall) -> Decision:
    """The decision the policy's own rules produce, taint not consulted."""
    matching = [rule for rule in policy.rules if _matches(rule, call)]

    # B-013: mirror ``_matches``, which already raises on an unknown predicate.
    # The precedence loop below asks ``rule.decision is verdict`` against the
    # three Verdict members, so a decision outside the enum matches none of them
    # and the rule simply disappears: measured at HEAD bbb8d15, a hand-built
    # ``Rule(..., decision="block")`` (the string) under ``on_no_match=ALLOW``
    # returned ``allow / default:on_no_match`` — the block rule dropped in
    # silence. Both conditions that finding needs are stated honestly: the
    # Policy must have been built around the loader (which parses ``decision:``
    # into a Verdict), and the default must be non-block — under the shipped
    # posture this already fails closed. Consistency with the predicate path,
    # not a live bypass.
    #
    # Scoped to the MATCHING rules rather than swept upfront over
    # ``policy.rules``: the common path then pays one isinstance per rule that
    # already survived ``_matches`` (0 or 1 of them for the shipped policy),
    # not one per rule in the file, and the raise stays limited to rules this
    # call actually reached — which is the same contract ``_matches`` has, where
    # a bad predicate on a rule for another tool is never looked at either.
    for rule in matching:
        if not isinstance(rule.decision, Verdict):
            raise ValueError(f"non-Verdict decision {rule.decision!r} in rule {rule.id!r}")

    for verdict in _PRECEDENCE:
        for rule in matching:  # file order within the winning verdict
            if rule.decision is verdict:
                return Decision(
                    verdict=verdict,
                    rule_id=rule.id,
                    owasp=rule.owasp,
                    reason=f"rule {rule.id} matched tool {call.tool!r}",
                )

    on_no_match = policy.defaults.on_no_match
    return Decision(
        verdict=on_no_match,
        rule_id=DEFAULT_RULE_ID,
        owasp=None,
        reason=f"no rule matched tool {call.tool!r}; policy default is {on_no_match}",
    )
