# hooks — the second enforcement point

A Claude Code `PreToolUse` hook that calls the same engine as the proxy. Its purpose is partly practical (one command, no MCP wiring, judges Claude Code's own built-in tools) and partly evidentiary: a second door on the same brain is what proves the engine/enforcement split is real rather than claimed.

`hooks/chokepoint_hook.py` imports `engine` unmodified. Adding this enforcement point required **zero** engine changes — that is the property under test, and `git diff` over `engine/` is how it is checked.

## How it works

Claude Code runs the hook once per tool call, before the tool executes. One JSON object arrives on stdin; one decision goes back on stdout:

```json
{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow|deny|ask", "permissionDecisionReason": "..."}}
```

`permissionDecision` is a literal 1:1 with `engine.Verdict` — `ALLOW → allow`, `BLOCK → deny`, `ASK → ask` — which is why the engine needed nothing added.

Exit codes follow the hook protocol: **0 with a decision on stdout** is a decision, **0 with empty stdout** defers to Claude Code's normal permission flow, and **2** blocks. Exit 1 means "non-blocking error, run the tool anyway", so every path that fails to reach a decision returns 2 instead — a security control that crashes must not thereby permit the call it failed to judge.

That covers two separate failures, guarded separately because one of them cannot see the other. An exception raised while judging is caught in `main()`. A first-party import that fails at **module scope** — `from engine import ...`, or the `import yaml` inside `policy/loader.py` — is caught by its own guard, because `main()`'s `except` is not yet on the stack when module-level code runs. Before that guard existed, pointing the hook at an interpreter without PyYAML gave **exit 1, empty stdout, and the tool ran anyway**. The trigger is mundane: an operator writes `python3` instead of the venv path in `settings.json`, or the venv is rebuilt after a Python upgrade.

One case stays outside any runtime guard: if `chokepoint_hook.py` will not compile at all — syntax error, truncated copy — the interpreter exits 1 before a single line of it runs, and no code inside the file can intervene. So **run the hook once by hand after installing, editing, or upgrading it**, with the exact interpreter path from your `settings.json`:

```
echo '{"tool_name":"Read","tool_input":{"file_path":"/tmp/x"}}' | \
  /ABSOLUTE/PATH/TO/.venv/bin/chokepoint-hook --policy /ABSOLUTE/PATH/TO/policy.yaml
```

Exit 0 (with a decision) or exit 2 means the install is sound. **Exit 1 means it is fail-open** — the interpreter cannot load the hook, and every call it was supposed to judge will proceed unjudged.

## Install

Prefer `chokepoint-init --project /absolute/path --install-settings ~/.claude/settings.json` after `pip install -e .`. That writes a deny-by-default policy for *your* directory and merges the two matcher groups with absolute paths. The rest of this section is the manual equivalent.

1. Copy `hooks/settings.example.json` into your Claude Code settings (`~/.claude/settings.json` or a project's `.claude/settings.json`), merging the `hooks` key if you already have one.
2. Replace every `/ABSOLUTE/PATH/TO/...` — hooks run with your project as the working directory, so relative paths do not work. After install, `chokepoint-hook` is the venv binary; a bare `python3` has no PyYAML and the hook exits **2** (fail-closed). A truncated hook file still exits **1** (fail-open).
3. Point `--policy` at your policy file. `$CHOKEPOINT_POLICY` does the same job if you would rather not repeat it on both matchers.

Two matcher groups, because they cover different things: `mcp__.*` for every MCP tool, and an anchored list for the built-ins this policy vocabulary can describe.

Flags: `--policy` (or `$CHOKEPOINT_POLICY`), `--log-file` (or `$CHOKEPOINT_LOG`, else decision events go to stderr), `--agent-id` (default `claude-code-hook`).

## Native tool mapping

Claude Code's built-ins are not the policy's vocabulary, so they are translated. The table is **measured**: a real headless Claude Code 2.1.220 was driven with a logging hook, and these columns are read off the payloads it sent (2026-08-02).

| Claude Code tool | engine tool | canonical key ← payload key |
|---|---|---|
| `Read` | `read_file` | `path` ← `file_path` |
| `Write` | `write_file` | `path` ← `file_path` |
| `Edit` | `write_file` | `path` ← `file_path` |
| `NotebookEdit` | `write_file` | `path` ← `notebook_path` |
| `Bash` | `run_command` | `command` ← `command` |
| `WebFetch` | `fetch_url` | `url` ← `url` |

The canonical key is **added** to a copy of the payload, never substituted for it: `args_match_any` scans every string anywhere in the arguments, so a private key pasted into `Write.content` still trips `private_key_block`. When a payload lacks its source key the canonical key is omitted, the predicate is unsatisfied, and the call falls to deny-by-default.

Omitted means *removed*, not merely left unset. A payload that carries the canonical key itself — a `Read` whose `tool_input` is `{"path": "..."}` with no `file_path` anywhere — would otherwise satisfy the path predicate on its own, letting a caller address the engine's vocabulary directly instead of the harness's. That key is dropped when the real source key is absent. It cannot turn a block into an allow: `decide()` ranks matching rules block > ask > allow, so dropping a string can only remove a match, never promote one. For `Bash` and `WebFetch` the canonical and payload keys are the same name, which makes the whole question a no-op.

MCP tools arrive as `mcp__<server>__<tool>`. The prefix is stripped, the rest is split once, and the engine is handed the bare tool name with the arguments object **unchanged** — byte-identical to the envelope the proxy builds for the same call arriving over MCP. Write policy rules against the bare tool name (`echo_note`, not `mcp__probe__echo_note`).

## Coverage gap: unmapped native tools

**The hook makes no decision at all about `Grep`, `Glob`, `Task`, `TodoWrite`, `WebSearch`, `ToolSearch` and every other built-in outside the table above.** It exits 0, prints nothing, and Claude Code's normal permission flow decides. There is no decision event for these calls either — they are not judged, so they are not in the audit trail.

This is a real gap and it is deliberate that it is a gap rather than an `allow`. A hook that answered `allow` for tools it cannot describe would be *widening* the permissions the user already configured; a security control must only ever narrow them. Closing the gap properly means growing the policy vocabulary to describe those tools (`Grep` reads files, `Task` spawns an agent), which is a policy-schema question, not a hook question.

Practical consequence: this hook does not stop a file read performed by `Grep`, and it does not see anything a subagent launched through `Task` does.

## What an `allow` does not do

An `allow` from this hook is this control declining to object. It is **not** a grant, and it does not hand the call a pass through Claude Code's own permission system. Measured on Claude Code 2.1.220, `--permission-mode default`, headless, one variable per pair (2026-08-02):

| the user's own setting | hook installed? | did the call run? |
|---|---|---|
| `permissions.deny` on the file | no — control | no: `File is in a directory that is denied by your permission settings.` |
| `permissions.deny` on the file | yes, and the policy says `allow` | **no**, byte-identical error — and the hook logged **no decision event at all** |
| `permissions.ask` on the command | no — control | no: `Claude requested permissions to use Bash, but you haven't granted it yet.` |
| `permissions.ask` on the command | yes, and the policy says `allow` | **no**, identical error — the hook logged `verdict=allow` and it changed nothing |

The `deny` row is the sharper one: the hook was never consulted at all. A third leg showed that is ordering rather than a dead hook — same hook, same deny rule, reading a *different* file in the same folder produced a decision event (`verdict=allow`, `rule_id=fs-read-scoped`) and returned the file, while the denied file produced no event. **Claude Code evaluates `permissions.deny` before it runs `PreToolUse` hooks.**

So the hook narrows and never widens: `deny` and `ask` map onto stricter outcomes than the user configured, and `allow` steps back and lets the user's own configuration decide. That is the property the coverage gap above is careful to protect, and it is now measured rather than assumed.

**Not measured**, so not claimed: whether an `allow` affects `permissions.allow` entries, sandbox settings, or the prompt a *human* sees in an interactive session. Both legs above ran headless, where an `ask` has nobody to ask.

## `ask` means ask

The proxy fails closed on `ask` (D-005): it has no approval channel wired to it, so an `ask` verdict becomes a blocked call with error `-32001`. **This hook does not.** Claude Code *is* an approval channel, so `ask` maps to Claude Code's `ask` and the verdict reaches the human it was written for.

That is not a relaxation of D-005. D-005's rule is that the *absence* of a human must never convert into an allow. `ask` here is not an allow — it is the human being asked. Same engine verdict, enforcement adapted to what the enforcement point can actually do: that is the PDP/PEP split doing its job.

## Other differences from the proxy

- **No `limits:` enforcement.** The hook is one process per tool call with no cross-call counters, so it sends `run_state=None` and `decide()` skips the limit block by its own documented contract. `max_tool_calls_per_run`, `max_wall_clock_seconds` and `max_repeated_identical_calls` are enforced by the proxy only. A counter file shared between hook processes is a separate piece of work with its own concurrency questions.
- **Logged arguments are truncated.** A `Write` payload carries the entire file body and an `Edit` payload carries whole `old_string`/`new_string` values, so logging them wholesale would write file contents into a security product's audit trail. Strings over 256 characters become `<str len=N truncated>` **in the log only** — `decide()` always receives the full untruncated arguments.
- **Redaction runs before truncation, and the order is load-bearing.** `engine.contains_sensitive` scans the full arguments first; only if that comes back clean is anything truncated. Truncating first would let a credential sitting past the cutoff escape the check and land in the log.

## Decision events

One JSON line per **judged** call, with the same key set as the proxy's — `ts`, `agent_id`, `method`, `tool`, `arguments`, `verdict`, `rule_id`, `owasp`, `reason`, `decision_ms` — so one consumer reads both doors. `method` is `PreToolUse`; `tool` is the name as it arrived (`Read`, `mcp__probe__echo_note`) rather than the engine name it mapped to, because that direction is deterministic and the reverse is not.

Two synthetic rule ids appear where no policy rule produced the decision, alongside the engine's own `default:on_no_match`:

- `hook:unparseable-input` — stdin was not a JSON object, carried no usable `tool_name`, or named an MCP tool that does not split into a server and a tool. Denied, never deferred: input that cannot be inspected is refused (the same call the proxy makes in B-005).
- `hook:policy-error` — no policy was configured, or the file would not load. Denied, carrying the loader's error text. A broken policy is a broken control; it fails closed rather than quietly enforcing nothing.

## Tests

```
.venv/bin/python -m pytest hooks/ -q
```

`hooks/tests/test_hook.py` drives real captured payloads through the hook, and the end-to-end tests run the file as a subprocess with JSON on stdin — a unit test of an internal function does not prove it works as a hook. The policy under test is `hooks/tests/policy.fixture.yaml`, not the shipped example: these tests assert the hook's plumbing, and the example has its own tests in `policy/tests/`.
