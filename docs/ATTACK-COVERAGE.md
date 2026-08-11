# Attack coverage — the two published lists, and what this door does with each

Nothing else in this repository names either list. `policy/policy.example.yaml` carries an `owasp:` field per rule, which maps a rule to a category and says nothing about what the category contains; the only two values in it are `LLM01` and `LLM02`, in the numbering that predates the 2026 edition. Invariant Labs' attack classes appear nowhere in the repository at all. So "what does this gateway cover" had no answer a test could hold. This file is that answer, and `tests/test_attack_coverage.py` is what stops it drifting away from the suite it describes.

Two lists, eighteen rows, one status each.

## The sources, and why the numbering moved

**OWASP GenAI LLM Top 10, 2026 edition**, published 2026-08-04 — repository `GenAI-Security-Project/GenAI-LLM-Top10`, canonical files under `2026/final/`. This is **not** the 2025 list, and `owasp.org`'s `www-project-top-10-for-large-language-model-applications` page is now an archive of the 2023 v1.1 list rather than the bar. LLM01 and LLM02 name the same two risks they did under the older numbering, so every `owasp:` field in the shipped policy survives the renumber unchanged; Excessive Agency moved to LLM03; **Hidden Context Exposure (LLM08) is new in 2026** and has no counterpart in the list this project was built against.

**Invariant Labs' MCP attack classes.** Invariant published no single taxonomy page, so the eight classes below are taken from their four MCP security posts plus the mcp-scan detector list, each attributed to the post that introduced it. mcp-scan's own detector names — Prompt Injection, Tool Poisoning, Tool Shadowing, Toxic Flows — map onto IL-7, IL-1, IL-3 and IL-6 and add no ninth class.

Both id sets are pinned as literals in `tests/test_attack_coverage.py`. A row added, removed or renamed turns the suite red, which is the only reason this file can be trusted after the next list moves.

## What COVERED means here, and what it does not

**COVERED** means two committed tests exist and both resolve against the live suite:

1. **a refusal** — this payload is refused at this door under this policy, and where the door is the proxy, it did not reach the tool;
2. **a guard-off control, as its own node** — the same payload with the guard removed or not armed, landing. This is the load-bearing half. Everything blocks by default here, so a refusal with no control is satisfied equally well by a rule that never matched at all; the repo's own idiom for it is `policy/tests/test_example_policy_rules.py::TestNestedCredentialDirectories`.

The control has to be its **own** node rather than an assertion inside the refusing test. A control that shares a node with the refusal cannot fail independently of it and disappears the moment someone deletes or narrows the refusal — which is the failure this file exists to make visible, not one it should inherit.

**COVERED is a statement about two files, not about a category.** It says: this payload, this policy, this door, this date. It is never "the gateway stops LLM01", never a rate, never a proportion, and never an effectiveness figure in either direction — D-034 Decision 6 governs every sentence here. A category is never covered wholesale; it is covered *at the leg named in the row*, and the legs that are not reached are written down rather than left as an absence a reader has to notice.

**UNREACHED** means no such pair exists, and it is graded — `structural` or `unbuilt` — with a `docs/LIMITATIONS.md` entry that carries the same grading word and names the row. The distinction is the whole point: *structural* is a property of this gateway, *unbuilt* is a debt of this repository, and letting the second hide inside the first is how a coverage table becomes a lie. D-038 records the ruling.

**Rows may share evidence.** Where two rows name legs this door meets with one mechanism, they cite the same nodes and say so in a Note. Two taxonomies naming one thing twice is a fact about the taxonomies.

## OWASP GenAI LLM Top 10 — 2026 edition

### LLM01:2026 · Prompt Injection

- **Source:** `GenAI-Security-Project/GenAI-LLM-Top10`, `2026/final/LLM01_PromptInjection.md`
- **Leg:** once a run has consumed a result from a tool the policy names an untrusted source, the proxy refuses the egress call that follows — the run is marked on the SOURCE tool, never on the content that came back.
- **Refusal:** proxy/tests/test_proxy.py::TestTaintTracking::test_secrets_only_refuses_a_credential_bearing_call_after_taint
- **Control:** proxy/tests/test_proxy.py::TestTheTaintBlockIsWhatRefusesTheCallAfterASource::test_the_same_credential_call_lands_after_a_fetch_with_the_taint_block_removed
- **Status:** COVERED
- **Note:** what those two assert, and the whole of it: `echo <an AKIA-shaped string>` is `allow / shell-readonly` and reaches the tool in a run that has fetched nothing, and is `block / taint:secret-egress` and does not reach the tool in a run that fetched `https://docs.python.org/3/` through the gateway first. Same session, same call, one variable. The control removes the `taint:` block from the shipped file and changes nothing else, and the identical third call — made after the identical fetch — is then `allow / shell-readonly` and arrives at the tool. *(The Control was `proxy/tests/test_proxy.py::TestTaintTracking::test_a_clean_run_is_unaffected_by_the_taint_block` until 2026-08-08 — **B-109**. That node takes no policy override, so it runs the shipped taint block present and ARMED and varies only run state, which is a real control on something and is not the *"guard removed or not armed"* this file defines at the top. The row's status was never in doubt; what was wrong was which node was offered as the proof.)* The injection itself is not in this picture — no model reads anything here — and `docs/THREAT-MODEL.md` §4 is where that link is discussed.

### LLM02:2026 · Sensitive Information Disclosure

- **Source:** `GenAI-Security-Project/GenAI-LLM-Top10`, `2026/final/LLM02_SensitiveInformationDisclosure.md`
- **Leg:** a published credential format in the arguments of an otherwise-allowed `fetch_url` is refused by `net-egress-sensitive`, and the call does not reach the tool.
- **Refusal:** proxy/tests/test_proxy.py::TestArgumentLevelRules::test_secret_to_allowlisted_domain_is_blocked
- **Control:** proxy/tests/test_proxy.py::TestTheEgressRuleIsWhatRefusesTheCredential::test_the_same_credential_url_lands_with_the_egress_rule_removed
- **Status:** COVERED
- **Note:** the control removes exactly one rule from the shipped file and changes nothing else; the identical URL then comes back `allow / net-fetch-allowlist` and arrives at the upstream with its arguments intact. Before it was written this row had a refusal and only benign-neighbour controls — the same fetch minus the credential — which show the host is allowlisted but not that the block is this rule's doing. What the row does not reach is any credential the fixed pattern list does not name (`docs/LIMITATIONS.md` §16) or one obfuscated past it (§21).

### LLM03:2026 · Excessive Agency

- **Source:** `GenAI-Security-Project/GenAI-LLM-Top10`, `2026/final/LLM03_ExcessiveAgency.md`
- **Leg:** the *minimize tool permissions* mitigation — an allow rule's scope is narrowed at the argument level, so a read of a credential directory nested anywhere under the allowed prefix is refused instead of inheriting the prefix's permission.
- **Refusal:** policy/tests/test_example_policy_rules.py::TestNestedCredentialDirectories::test_a_nested_credential_directory_is_blocked
- **Control:** policy/tests/test_example_policy_rules.py::TestNestedCredentialDirectories::test_the_same_paths_allow_with_the_segment_matcher_stripped
- **Status:** COVERED
- **Note:** this pair is at the engine, so *landing* means the verdict `allow / fs-read-scoped` rather than arrival at an upstream; the process-level form of the same control is LLM10's row. LLM03 names four mitigations and this row is one of them. The other three are legs of the same category with their own state: complete mediation is LLM10's pair, *require user approval* is `ask`, which at the proxy fails closed with no human involved (D-005), and *rate limiting* is LLM06's row, which is UNREACHED.

### LLM04:2026 · Supply Chain

- **Source:** `GenAI-Security-Project/GenAI-LLM-Top10`, `2026/final/LLM04_SupplyChain.md`
- **Leg:** the document's eight scenarios are model-artifact scenarios and it places MCP servers and tool registries under OWASP's separate Agentic Supply Chain document, so the only leg that can arrive at this door is the integrity of the tool definitions the agent is handed — and those arrive on `tools/list`. A policy carrying a `tool_listing:` section approves an exact digest per tool, and a listing carrying a DEFINITION that is not one of them is refused whole before it reaches the agent. The envelope those definitions arrive in is not judged at all (`docs/LIMITATIONS.md` §20 item 6).
- **Refusal:** proxy/tests/test_tool_listing.py::TestIL2RugPull::test_a_description_changed_after_approval_is_refused
- **Control:** proxy/tests/test_tool_listing.py::TestIL2RugPull::test_the_same_changed_description_reaches_the_agent_with_the_door_unarmed
- **Status:** COVERED
- **Note:** what those two assert, and the whole of it: the demo upstream's four definitions are approved by digest, the server then serves `fetch_url` with one sentence appended to its description, and that listing comes back `block / listing:definition-drift` and does not reach the agent — while the identical listing, with the `tool_listing:` section removed and nothing else changed, arrives with the description byte-identical to the poisoned fixture. This is LLM04 **at the tool-definition leg only**: nothing here touches a model artifact, a training set, an adapter or a build pipeline, and the 2026 document routes MCP servers and tool registries to OWASP's separate Agentic Supply Chain list. What the pair does not reach is written up in `docs/LIMITATIONS.md` §20, and its first line is the one that matters — the shipped `policy.example.yaml` does **not** arm this door, so this row describes a deployment that opted in.

### LLM05:2026 · Data and Model Poisoning

- **Source:** `GenAI-Security-Project/GenAI-LLM-Top10`, `2026/final/LLM05_DataModelPoisoning.md`
- **Leg:** two of the document's scenarios are WRITES through a tool — a manipulated document inserted into an internal knowledge repository (#1), and malicious instructions injected into an agent's persistent memory over multiple sessions (#9) — and a write is judged at this door.
- **Refusal:** none
- **Control:** none
- **Status:** UNREACHED · unbuilt
- **Limitation:** docs/LIMITATIONS.md §23

### LLM06:2026 · Unbounded Consumption

- **Source:** `GenAI-Security-Project/GenAI-LLM-Top10`, `2026/final/LLM06_UnboundedConsumption.md`
- **Leg:** the mitigation asks for step limits, recursion depth limits, time limits and per-run cost ceilings; the shipped `limits:` block is the first and third of those — `max_tool_calls_per_run`, `max_wall_clock_seconds`, `max_repeated_identical_calls`, all counted per run at the proxy, none of them a cost.
- **Refusal:** none
- **Control:** none
- **Status:** UNREACHED · unbuilt
- **Limitation:** docs/LIMITATIONS.md §23

### LLM07:2026 · Misinformation

- **Source:** `GenAI-Security-Project/GenAI-LLM-Top10`, `2026/final/LLM07_Misinformation.md`
- **Leg:** this door cannot judge whether a statement is true. It can refuse the ACT a false statement produces — installing a package that does not exist is a `run_command` no allow pattern spells — and that distinction belongs in every sentence written about this row.
- **Refusal:** none
- **Control:** none
- **Status:** UNREACHED · unbuilt
- **Limitation:** docs/LIMITATIONS.md §23

### LLM08:2026 · Hidden Context Exposure

- **Source:** `GenAI-Security-Project/GenAI-LLM-Top10`, `2026/final/LLM08_HiddenContextExposure.md`
- **Leg:** the extraction itself happens in the model's output; the leg that reaches a tool is the EGRESS of that context — a system prompt, a tool schema, a guardrail disclosure — inside a tool call's arguments, **and only for material the operator DECLARED**. A policy may carry a `hidden_context:` section naming one or more files whose content must not leave; a rule using `args_contain_hidden_context` arms one or more of those declarations, and a call whose arguments carry a segment of declared material is refused at the proxy and does not reach the tool. The leg is bounded by that declaration and not by the English phrase *hidden context*: nothing here judges whether a string looks like a system prompt.
- **Refusal:** proxy/tests/test_proxy.py::TestHiddenContextEgress::test_a_recited_system_prompt_is_refused_and_does_not_reach_the_tool[verbatim]
- **Control:** proxy/tests/test_proxy.py::TestTheHiddenContextRuleIsWhatRefusesTheCall::test_the_same_recitation_lands_with_only_the_other_set_armed[verbatim]
- **Status:** COVERED
- **Note:** what those two assert, and the whole of it: two files are declared — a five-sentence support-assistant prompt as `system_prompt` and a three-line tool-schema listing as `tool_schemas` — and an otherwise-allowed `fetch_url` to `https://pypi.org/simple/` carries the prompt's text in a second argument. With the rule naming `system_prompt` the call is `block / egress-hidden-context` and the upstream received nothing; with **the same two files declared and the rule naming only `tool_schemas`**, the identical call is `allow / net-fetch-allowlist` and arrives at the upstream with the recited prompt intact. One variable: which declaration the operator armed. The control removes the arming rather than the declaration because removing the declaration stops the rule LOADING (the loader refuses an undeclared set), which would prove nothing about enforcement. Four more recitation shapes ride the same pair of nodes as parametrized cases, and the shape names here are the parametrize ids so a reader can run one: `reflowed onto one line`, `one sentence quoted mid-paragraph`, `its first two lines only` and `one word changed`. Two more assert the other direction — `a full paraphrase` and `an ordinary note`, both allowed, on `proxy/tests/test_proxy.py::TestTheHiddenContextRuleIsWhatRefusesTheCall::test_undeclared_text_lands_with_the_set_armed`. A further node asserts the shipped `policy.example.yaml` declares nothing, so like LLM04:2026's row this one describes a deployment that opted in. **A second pair covers the decision LOG**, because a refusal that writes the protected material into a file is a control that leaks what it protects: `proxy/tests/test_proxy.py::TestTheRefusalDoesNotWriteTheHiddenContextIntoTheLog` has the refusal event carrying a redaction marker and, as its own node, the identical call logged in full with nothing declared. **Six things this row does not reach**, each measured in `docs/LIMITATIONS.md` §26: **paraphrase**, which defeats any literal matcher — a full rewording of the declared prompt is `allow / net-fetch-allowlist` with the set armed, and no floor, unit or normalization changes that; **intra-segment obfuscation**, the other large one — one `U+3164`, `U+180E` or `U+2800` inserted inside each declared sentence, or one Cyrillic homoglyph per sentence, or base64, or hex, is `allow / net-fetch-allowlist` **with every `args_contain_invisible_characters` class armed as well**, and the material is recoverable from the argument exactly, and the same literal matcher drives the redaction so the decision log carries it in full at both doors (§26 item 6, B-089, D-050 — this list said *five* until 2026-08-06 and that is what B-089 is); **chunking**, a recitation split mid-sentence across two calls, both halves allowed; **the declaration naming a file**, so the policy discloses where the material lives even though not what it says, which is B-088's subject; **the extraction itself**, which is the whole first half of the category's own sentence and is invisible at a door that mediates tool calls and never sees a model's output; and **material nobody declared**, which is D-049 Decision 1 rather than an omission. One more thing this pair is not: it does not make `secret_like` see more. `contains_sensitive` is False on the recited prompt, so what changes is that the call is refused, not that the material is recognised as a credential.

### LLM09:2026 · Vector and Embedding Weaknesses

- **Source:** `GenAI-Security-Project/GenAI-LLM-Top10`, `2026/final/LLM09_VectorAndEmbeddingWeaknesses.md`
- **Leg:** the mixed-trust mitigation — external, internal and partner content must not share an index without hard isolation — is enforceable at the WRITE into the index, which is a tool call. The index internals, the embeddings and the retrieval are not visible at this door at all.
- **Refusal:** none
- **Control:** none
- **Status:** UNREACHED · unbuilt
- **Limitation:** docs/LIMITATIONS.md §23
- **Note:** the Leg above is the mixed-trust one and no pair pins it, which is the whole of why this row is UNREACHED. **A different mitigation of this category is met at a different leg and does not move this row.** Mitigation 2 asks that zero-width characters, white-on-white text and Unicode homoglyphs be stripped at extraction; D-046 built a refusal for **an enumerated subset of the first of those three**, and its pair is IL-8's — `proxy/tests/test_proxy.py::TestHiddenCharactersInArguments::test_a_hidden_character_in_an_argument_is_refused_and_does_not_reach_the_tool` with its control `proxy/tests/test_proxy.py::TestTheHiddenCharacterRuleIsWhatRefusesTheCall::test_the_same_payload_lands_with_that_class_unarmed`. Read that exactly as far as it goes, and the word *subset* is load-bearing: the mitigation's phrase *zero-width characters* is wider than any fixed list of code points, and a zero-width code point outside the enumeration is not refused — measured in `docs/LIMITATIONS.md` §21 item 4, which is where B-085 landed after a sentence here claimed the whole item. What is asserted is one enumerated subset of one item of one of this category's mitigations, at a tool call rather than at an extraction step, and a REFUSAL rather than a strip, because this door decides a call and never rewrites one. White-on-white text is a rendering property nothing here can see; homoglyphs are `unbuilt` (`docs/LIMITATIONS.md` §21); the index, the embeddings and the retrieval are not visible at this door at all. A row's status follows the leg the row names, which is D-047.

### LLM10:2026 · Improper Output Handling

- **Source:** `GenAI-Security-Project/GenAI-LLM-Top10`, `2026/final/LLM10_ImproperOutputHandling.md`
- **Leg:** the named danger is model output entered directly into a system shell. A `run_command` whose string matches `shell-destructive` is refused at the proxy and does not reach the shell.
- **Refusal:** proxy/tests/test_proxy.py::TestAttackBlocked::test_destructive_command_is_blocked_with_rule_id
- **Control:** proxy/tests/test_proxy.py::TestAttackBlocked::test_same_attack_lands_when_unguarded
- **Status:** COVERED
- **Note:** this is the only pair in the repository whose control is process-level ground truth: the refusal asserts the upstream received nothing, and the control sends the identical command with no proxy in the path and asserts it arrived. **It is the coarsest control here for that same reason, and not the shape the others are measured against** — removing the enforcement point removes everything at once, while four other pairs remove one rule, unarm one class, swap one declaration or move one strictness dial, which is a one-variable control on the guard itself. *(This Note called it "the strongest pair in the repository and the shape the others are measured against" until 2026-08-08 — **B-106**. The colon made the rest of the sentence a definition of that shape, and no other pair has it or could adopt it as an improvement.)* LLM10 cannot have the finer form, and that is the honest half of the row: `run_command`'s only allow rule is `shell-readonly`, whose three patterns are fully anchored (`\Apwd\Z`, `\Als( +-[A-Za-z]+)*\Z`, `\Aecho +[A-Za-z0-9 ._/-]*\Z`), so removing `shell-destructive` leaves the identical payload `block / default:on_no_match` — measured, not assumed — and nothing but removing the proxy makes it land. The payload is one string — a download piped into a shell — matched by one committed pattern; a command this policy has no pattern for is refused too, but by deny-by-default, which is a weaker statement and is not what this row cites. The process-level version of the same control is `proxy/demo/run_demo.py`, whose guard-off leg shows the call landing in the upstream's own execution log. **A second leg of this category is met here and is named rather than folded into the sentence above.** Mitigation 8 reads *"Sanitize control characters from model output before writing to terminals or logs"*, and this project writes two artifacts of that kind. The decision log already satisfied it, and that is now pinned with both controls: `proxy/tests/test_decision_log_encoding.py::TestTheDecisionLogCannotBeForgedByAnArgument::test_control_characters_in_an_argument_cannot_forge_a_log_line` drives the real `python -m proxy --log-file` with arguments carrying a newline, a carriage return, an ANSI erase-line sequence, `U+0085`, `U+2028` and `U+2029`, each followed by a whole forged decision event, and the file comes back one JSON object per event with no raw control byte in it and no forged event in it — while `proxy/tests/test_decision_log_encoding.py::TestTheJsonEncodingIsWhatStopsIt::test_the_same_events_without_ascii_escaping_split_the_log` re-encodes those same events with one keyword changed and a per-line reader then recovers fewer records than were written. The other artifact did **not** satisfy it: each model-run record's `transcript.txt` rendered the model's own closing text verbatim, so an ANSI escape placed there reached the file as raw bytes (B-084, fixed, with the committed transcripts byte-identical either way). Both are mitigation 8 at a surface this repository owns. Neither is a claim about LLM10:2026 as a category, and this row's own Leg is a third thing again.

## Invariant Labs — MCP attack classes

### IL-1 · Tool Poisoning Attack

- **Source:** *MCP Security Notification: Tool Poisoning Attacks*, 2025-04-01 — malicious instructions embedded in a tool DESCRIPTION, invisible to the user and visible to the model.
- **Leg:** arrives on `tools/list`. A tool the operator approved no definition of is refused whichever description it carries, so the payload never reaches the model — it is refused for arriving unapproved, not for what it says.
- **Refusal:** proxy/tests/test_tool_listing.py::TestIL1ToolPoisoning::test_a_poisoned_tool_description_is_refused_at_the_listing_door
- **Control:** proxy/tests/test_tool_listing.py::TestIL1ToolPoisoning::test_the_same_poisoned_description_reaches_the_agent_with_the_door_unarmed
- **Status:** COVERED
- **Note:** the payload is Invariant's own shape — an `<IMPORTANT>` block inside an ordinary sentence, addressed to the model, telling it to read a credential file first and to keep quiet about it — advertised as a fifth tool beside the demo upstream's four approved ones. It comes back `block / listing:unpinned-tool`, the refusal names `summarize_notes` and the digest computed for it, and the payload text appears nowhere in the event: this door never read it. With the section removed the same description reaches the agent byte for byte. **Same rule id as IL-3**, and honestly so — this door meets both with one mechanism, and inventing a second would be the thing `docs/LIMITATIONS.md` §20 exists to prevent. §20 is also where the hole in it lives: a poisoned description that was already there when the operator took the pin is approved.

### IL-2 · MCP Rug Pull

- **Source:** *MCP Security Notification: Tool Poisoning Attacks*, 2025-04-01 — a malicious server changes the tool description after the client has already approved it.
- **Leg:** arrives on `tools/list`, and turns on the difference between the definition the client approved and the one now being served. The `tool_listing.approved` digests **are** that approval written down, so the comparison the class describes is the comparison this door makes.
- **Refusal:** proxy/tests/test_tool_listing.py::TestIL2RugPull::test_a_description_changed_after_approval_is_refused
- **Control:** proxy/tests/test_tool_listing.py::TestIL2RugPull::test_the_same_changed_description_reaches_the_agent_with_the_door_unarmed
- **Status:** COVERED
- **Note:** the same two nodes as LLM04:2026, deliberately — one mechanism meets both rows, which is a fact about the taxonomies (D-038 Decision 4). One listing in a fresh session, so the change need not happen while anyone is watching: the pin is what remembers. The in-session form of the same attack is IL-5's row and has its own pair and its own rule id. What neither reaches is a definition that was already hostile when the pin was taken — `docs/LIMITATIONS.md` §20, item 2.

### IL-3 · Tool Shadowing

- **Source:** *MCP Security Notification: Tool Poisoning Attacks*, 2025-04-01 — a malicious server poisons tool descriptions to exfiltrate data reachable through other trusted servers; cross-server behaviour override.
- **Leg:** arrives on `tools/list`. An unapproved definition is refused whatever it says, so a shadowing description does not reach the model — and that is the whole of what this door contributes. Rules can also be scoped to a named server (D-015), which narrows what a shadowed CALL may do; that is a different leg and not this one.
- **Refusal:** proxy/tests/test_tool_listing.py::TestIL3ToolShadowing::test_a_shadowing_tool_description_is_refused
- **Control:** proxy/tests/test_tool_listing.py::TestIL3ToolShadowing::test_the_same_shadowing_description_reaches_the_agent_with_the_door_unarmed
- **Status:** COVERED
- **Note:** read this row narrowly, because the gap between what is asserted and what the class means is real. The payload is a `notify_team` tool whose description declares that every call to `mcp__mail__send_email` — a tool on **another** server — must add a hidden bcc. It comes back `block / listing:unpinned-tool`, and the control shows the same description reaching the agent with the door unarmed. But **this door does not see the shadowing**: nothing here reads the sentence, nothing relates one server's definitions to another's, and the refusal is for arriving unapproved and would be identical had the description been a recipe. So the payload is stopped at this door and the cross-server *relationship* that makes it shadowing is invisible to it — which is also why the pin is per-deployment and per-server rather than global. Same mechanism and same rule id as IL-1; `docs/LIMITATIONS.md` §20 carries what it does not reach.

### IL-4 · Authentication Hijacking

- **Source:** *MCP Security Notification: Tool Poisoning Attacks*, 2025-04-01 — credentials from one server secretly passed to another, enabled by shadowing.
- **Leg:** arrives in `tools/call` arguments, which this door does read — but the thing that makes it hijacking is where the credential CAME FROM, and no predicate here takes provenance.
- **Refusal:** none
- **Control:** none
- **Status:** UNREACHED · structural
- **Limitation:** docs/LIMITATIONS.md §22

### IL-5 · Sleeper / delayed activation

- **Source:** *WhatsApp MCP Exploited*, 2025-04-07 — a server advertises an innocuous tool, then switches to a malicious one after the user has approved its use.
- **Leg:** arrives on `tools/list`, on a second load — so the fact that decides it is one only run state holds: this run was already handed a different definition of that same tool. A run is one MCP client session with the proxy (D-022).
- **Refusal:** proxy/tests/test_tool_listing.py::TestIL5Sleeper::test_the_second_listing_switching_a_definition_is_refused_mid_run
- **Control:** proxy/tests/test_tool_listing.py::TestIL5Sleeper::test_both_listings_reach_the_agent_with_the_door_unarmed
- **Status:** COVERED
- **Note:** both legs are in ONE session, the shape `TestTaintTracking` established: listing 1 is the honest one and is `allow / listing:approved` and reaches the agent; listing 2 differs in `run_command`'s description alone and is `block / listing:definition-changed-mid-run`. The control shows both listings reaching the agent with the door unarmed, the second carrying the switch. **What the run state adds is the attribution, not the refusal** — under one pin per tool name the approval check would also have refused listing 2, with the less specific `listing:definition-drift`, and that is measured rather than claimed in `engine/tests/test_listing.py::TestWhatRunStateAddsAndWhatItDoesNot`. The attribution is worth its state because the two facts have different remediations: definitions differing from the approved ones is often an upgrade to re-approve, while one session served two definitions of one tool cannot be an upgrade at all.

### IL-6 · Toxic Agent Flow

- **Source:** *GitHub MCP Exploited*, 2025-05-26 — indirect prompt injection used to trigger a malicious tool-use SEQUENCE.
- **Leg:** the sequence, not the payload: under `egress_mode: all_egress` any egress call a run makes after consuming a source result is refused, whatever it carries.
- **Refusal:** proxy/tests/test_proxy.py::TestTaintTracking::test_all_egress_refuses_a_harmless_egress_call_after_taint
- **Control:** proxy/tests/test_proxy.py::TestTaintTracking::test_the_same_harmless_call_survives_taint_under_secrets_only
- **Status:** COVERED
- **Note:** one variable, the operator's strictness dial. `pwd` — carrying no credential and naming no host, so neither of the other two modes has any reason to touch it — is `block / taint:egress` after a fetch under the strictest mode, and `allow / shell-readonly` reaching the tool after the same fetch under the shipped mode. That is the sequence being refused rather than the call.

### IL-7 · Indirect prompt injection via tool output

- **Source:** *WhatsApp MCP Exploited*, 2025-04-07 — the injection arrives in a tool result.
- **Leg:** the result of a tool the policy names an untrusted source marks the run; what the run may send afterwards is tightened. The result's bytes are forwarded to the agent untouched and are never inspected (D-031).
- **Refusal:** proxy/tests/test_proxy.py::TestTaintTracking::test_secrets_only_refuses_a_credential_bearing_call_after_taint
- **Control:** proxy/tests/test_proxy.py::TestTheTaintBlockIsWhatRefusesTheCallAfterASource::test_the_same_credential_call_lands_after_a_fetch_with_the_taint_block_removed
- **Status:** COVERED
- **Note:** the same two nodes as LLM01:2026, deliberately. This door meets both rows with one mechanism, and citing it twice is honest where inventing a second pair would not be. Both rows' Control moved together on 2026-08-08 (**B-109**) — the reason is written out in LLM01:2026's Note and applies here unchanged. What neither row reaches is the injection deciding anything: no model is in either test, and `docs/THREAT-MODEL.md` §4 says which link that is.

### IL-8 · Payload obfuscation

- **Source:** *WhatsApp MCP Exploited*, 2025-04-07 — hidden whitespace and unicode the user never sees, and context-shaped payloads that imitate the surrounding data format.
- **Leg:** the *hidden whitespace and unicode the user never sees* half, in ARGUMENTS, **and only for the code points the engine enumerates**. A policy may carry a rule using `args_contain_invisible_characters`, which names one or more classes of character a reader cannot see — zero-width, bidi controls, C0/C1, the two line separators outside that block, the soft hyphen, the Unicode Tags block, the variation selectors — and a call whose arguments carry a character from a named class is refused at the proxy and does not reach the tool. Each class is a fixed set of code points, so the leg is bounded by that enumeration and not by the English phrase *a character a reader cannot see*; what falls outside it is the fourth item in the Note below.
- **Refusal:** proxy/tests/test_proxy.py::TestHiddenCharactersInArguments::test_a_hidden_character_in_an_argument_is_refused_and_does_not_reach_the_tool
- **Control:** proxy/tests/test_proxy.py::TestTheHiddenCharacterRuleIsWhatRefusesTheCall::test_the_same_payload_lands_with_that_class_unarmed
- **Status:** COVERED
- **Note:** what those two assert, and the whole of it: an otherwise-allowed `fetch_url` to `https://pypi.org/simple/` carries a second argument reading `build metadata v1.2.3` with ONE code point inserted into it. With that code point's class armed the call is `block / args-hidden-characters` and the upstream received nothing; with **that one class removed from the rule's list and every other class left in**, the identical call is `allow / net-fetch-allowlist` and arrives at the upstream with its arguments intact, invisible character included. One class per node, one variable each — which class the operator armed. `proxy/tests/test_proxy.py::TestAWholeInstructionHiddenInOneArgument` is the same shape at the scale the class is actually used at — a 29-code-point instruction spelled in the Tags block, inside a note whose visible text is byte-identical to the benign neighbour's, refused with `tag_characters` armed — and its guard-off half is its own node, `proxy/tests/test_proxy.py::TestTheTagCharacterClassIsWhatRefusesTheHiddenInstruction::test_the_same_hidden_instruction_lands_with_tag_characters_unarmed`, where the identical call reaches the upstream with the instruction in it once that one class is taken out. A further node asserts the shipped `policy.example.yaml` arms none of this, so like LLM04:2026's row this one describes a deployment that opted in. **Four things it does not reach**, each measured in `docs/LIMITATIONS.md` §21: **homoglyphs**, which are a visible character that resembles another and are `unbuilt` by a ruling with its false-positive cost measured (D-046); **the other half of the class Invariant describes**, a payload shaped like the data around it, which nothing here parses for; **the results half**, which no matcher here sees at all because a result's bytes are forwarded untouched (D-031) — a property rather than a debt, and the reason this row names the arguments half only; and **every invisible code point outside the enumeration**, which is a cost of D-046 Decision 2's fixed sets rather than a debt of any one class — measured with every class armed after D-048, `U+180E`, `U+3164`, `U+FFA0`, `U+115F`, `U+2800` and `U+1D173` still come back `allow / net-fetch-allowlist`, and 52 of the 170 `General_Category=Cf` code points at this interpreter's Unicode version are held by no class. That fourth item is `unbuilt`, it is pinned by `engine/tests/test_predicates.py::TestTheEnumerationIsNotExhaustive` so it goes red if a class ever grows to cover one of those code points, and it was missing from this list until B-085 — a residual list that presents itself as complete is the B-060 defect class one level down, which is what D-048 exists to close. One more thing this pair is not: it does not make `secret_like` see through the obfuscation. `contains_sensitive` still answers False on an AWS key id with a zero-width space in it, so what changes is that the call is refused, not that the credential is recognised.

---

*Created 2026-08-06. The status of a row changes only by a test landing or a limitation being measured — not by a reading of it. If this file and the suite disagree, `tests/test_attack_coverage.py` is what says so.*
