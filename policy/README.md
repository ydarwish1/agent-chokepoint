# policy — the file the engine is told what to do by

`policy.example.yaml` is the LIVE policy: the proxy is run against it, the demos run against it, and `policy/tests/` asserts both directions of every rule straight out of that file rather than out of a fixture. `loader.py` turns it into an immutable `engine.Policy` and refuses anything it cannot enforce — an unknown key, an unknown predicate, a relative path prefix, an empty `when`, a rule claiming a reserved id namespace — at load time rather than at decide time.

## Editing `policy.example.yaml` — read this first

**It is pinned byte-for-byte by three committed model-run records.** Each one stores the SHA-256 of the exact file text the recorded run went against, and `tests/test_model_run_records.py::TestCommittedRecords::test_the_policy_is_the_shipped_file_or_one_scalar_off_it` re-derives it. **Any** edit breaks those three tests — including a comment, including whitespace — because the record's claim is about the file that ran, not about the behaviour it produced.

That is the guard working, and the failure message says so plainly (*"this record claims the shipped policy, unmodified, and the file has changed"*). It is written here because the constraint is invisible from inside the file, and it is the reason this README exists: documentation that would naturally have gone in a YAML comment goes here instead. Discovered 2026-08-06 while adding the `tool_listing:` documentation below; five tests went red on a comment block.

Editing it anyway means deciding what to do about those records, and that is a scope question rather than a code one — re-rendering a record so its hash matches a later file would be changing what the record says it ran against, which is falsification. See D-034 and D-035.

## `tool_listing:` — D-039, and it is deliberately NOT set in the shipped file

Four of Invariant Labs' eight published MCP attack classes arrive in a tool DESCRIPTION rather than in a tool call — a poisoned description, a description changed after the client approved it, a description that re-programs behaviour toward another server's tool, and a tool swapped in on a later load — and all four arrive on `tools/list`. OWASP LLM04:2026's one leg that reaches this gateway is the same surface.

With no `tool_listing:` section, `tools/list` crosses this gateway **unjudged**: the proxy forwards the upstream's answer and writes the `action: forwarded` event, exactly as it did before this section existed. Absent means the door is not armed, and there is no half-armed spelling — the loader refuses `tool_listing:` with an empty value rather than reading it as absent.

**Why the shipped file does not arm it.** A pin is a fact about ONE server's exact build. `policy.example.yaml` is written for a tool VOCABULARY — `read_file`, `write_file`, `fetch_url`, `run_command` — so any digest in it would be wrong for every real deployment, and a placeholder digest would read as protection and pin nothing, which is the shape this loader refuses everywhere else. Arming it is a deployment decision. `policy/tests/test_loader.py::TestTheToolListingSection::test_the_shipped_policy_leaves_the_door_unarmed` holds the file to that.

### What an operator writes

```yaml
tool_listing:
  approved:
    read_file:   "sha256:<64 lowercase hex>"
    write_file:  "sha256:<64 lowercase hex>"
    fetch_url:   "sha256:<64 lowercase hex>"
    run_command: "sha256:<64 lowercase hex>"
```

Every tool the upstream advertises must be in that map with a matching digest, or the **whole listing** is refused — deny by default, the same posture as the rules. `approved` is the only key: there is no verdict knob and no report-only mode, because at this door `ask` has no approver (D-005) and the hook door never sees a listing at all, so the setting would have exactly one honest value.

### Where the digests come from

The digest is `sha256` over the tool definition exactly as the upstream sent it, **whole**: name, description, input schema, and any field this SDK version does not model. Two ways to get them, both through the door's own parse rather than a second serialisation of the same objects:

1. **Read them out of a refusal.** Arm the section with any well-formed placeholder digest and run once. The refusal names every offending tool with the digest the gateway computed for it, in the order the upstream advertised them:

   ```
   tools/list refused: 1 of 5 tool definitions are not the ones this policy approved —
   summarize_notes is sha256:1bdcc0c714ca929e0db95af1b0addb286bce23d8bb6097741279053aef117d8b
   and this policy approves no definition of it
   ```

2. **Call `proxy/server.py:observed_tool_pins`** against a connected upstream client. It returns the map to paste in.

### What it does, and the three things it does not

- It **compares** definitions. It does not **read** them. No description is scored, pattern-matched or judged anywhere, and a harmless typo fix in a description is refused with the same verdict and the same rule id as an injected instruction — asserted, in `proxy/tests/test_tool_listing.py::TestThisDoorJudgesIntegrityAndNotIntent`. Integrity and provenance are decidable here; intent is not, and content filtering is out of scope (`README.md`).
- It does not stop the upstream being **asked**. The thing judged is the upstream's answer, so the answer is fetched and then withheld from the agent rather than prevented.
- It cannot help against a server that was already hostile when you took the pin. You approved that definition, and this door's whole question is whether the definition is the approved one.

The full list of what it does not reach is `docs/LIMITATIONS.md` §20, and the design is D-039.

## `hidden_context:` — D-049, and it is deliberately NOT set in the shipped file

OWASP **LLM08:2026 Hidden Context Exposure** is the unauthorized extraction of hidden, non-user-facing system instructions or operational context. **This gateway cannot stop the extraction** — that happens in the model's output, which it never sees. It can refuse the tool call that carries the recitation OUT, which is the only leg of that category that reaches a door mediating tool calls.

With no `hidden_context:` section nothing is declared and the predicate below cannot be used at all: a rule naming an undeclared set is refused at load, which is deliberate — a rule pointed at a set that does not exist would be a control the operator believes is armed and is not.

**Why the shipped file declares nothing.** Which material must not leave is a fact about ONE deployment — a support assistant's prompt, a tool-schema listing, an internal runbook. `policy.example.yaml` is written for a tool VOCABULARY, so it could only name a file that exists nowhere. `policy/tests/test_loader.py::TestTheHiddenContextSection::test_the_shipped_policy_declares_none` holds the file to that.

### What an operator writes

```yaml
hidden_context:
  system_prompt: /etc/chokepoint/hidden/system-prompt.txt
  tool_schemas:  /etc/chokepoint/hidden/tool-schemas.json

rules:
  - id: egress-hidden-context
    owasp: LLM08
    tool: fetch_url
    decision: block
    when:
      args_contain_hidden_context: [system_prompt, tool_schemas]
```

The value is an **absolute path and never the material itself** — the loader refuses a non-path value and says why. Pasting the prompt into the policy would put the hidden context into a file that is reviewed, diffed and committed, and, depending on where that file sits, into one a call can read (see the warning below). A `~` and a relative path are refused for the reasons path prefixes refuse them: both bind the declaration to whichever process loaded the file.

One rule per declaration if you want to know WHICH set matched — the rule id is the only attribution a decision event carries, and a rule naming two sets reports the same id for both.

### **Keep these files out of the agent's reach** — B-088

Three files decide whether this control means anything, and the shipped example policy knows about none of them:

| file | keep it outside |
|---|---|
| the policy itself | every `path_within` prefix, read **and** write |
| the decision log (`--log-file`) | the same |
| every file named under `hidden_context:` | the same |

Measured against the shipped `policy.example.yaml`: `read_file /workspace/policy.yaml` is `allow / fs-read-scoped`, and the whole policy text then rides out through an `allow / net-fetch-allowlist` fetch. `fs-read-scoped` allows the workspace and denies three credential-directory NAMES; it has no idea what a policy file is. **The shipped Helm chart already does this** — `/etc/chokepoint/policy.yaml` and `/sandbox` are both outside `/workspace/` and both come back `block / default:on_no_match`. Any other placement is the operator's to get right.

### What it matches, and the two things it does not

Each declared file is reduced at load time to **segments** — its lines and sentences, whitespace collapsed, ASCII case folded, anything under 32 characters dropped. A call is refused when any string anywhere in its arguments contains any segment of an armed declaration. So a recitation still matches when it is re-wrapped, quoted inside a longer sentence, only partly reproduced, or has a word changed.

- **Paraphrase is not matched.** A model that describes its instructions in its own words carries no declared segment and the call is allowed. That is a property of every literal matcher; closing it means comparing meaning, which is the content filtering this project rules out of scope.
- **A recitation split mid-sentence across two calls is not matched.** Nothing here relates one call's arguments to another's.

Both are measured in `docs/LIMITATIONS.md` §26, and the false-positive cost of the 32-character floor is false-positive class 15 in the same file. The design is D-049.

Two more things worth knowing before arming it. Declared material is **redacted from the decision log at both doors**, whatever the verdict and whether or not a rule arms it — a refusal that wrote the protected material into a file would be a control that leaks what it protects. And arming this changes nothing about what `secret_like` sees: `contains_sensitive` is still False on a system prompt, so the call is refused without the material being recognised as a credential, and the log says which of those happened.
