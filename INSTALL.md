# Install Agent-Chokepoint

Two ways to run it. Pick one, or run both.

- **The Claude Code hook.** Easiest. One JSON block in your Claude Code settings and every `Read`, `Write`, `Edit`, `Bash` and `WebFetch` your agent makes gets judged first. Start here.
- **The MCP proxy.** For any agent that speaks MCP. You put the proxy in front of your MCP server and the agent talks to the proxy instead.

Both call the same decision engine, so both give the same answer to the same call.

## Hand this to your agent

Paste this into Claude Code, or any agent that can run shell commands:

```
Clone https://github.com/ydarwish1/agent-chokepoint, read its INSTALL.md,
and install the Claude Code hook for me. Use the shipped example policy first,
run the verification step, and show me the output. Then help me edit the policy
so it fits the directories I actually work in.
```

That is the whole install for most people. The rest of this file is what the agent will be reading, and it is written so you can follow it yourself.

## Before you start

You need **Python 3.10 or newer** and git. Check first, because this is the one thing that reliably goes wrong:

```bash
python3 -V
```

If that prints 3.9 or lower, you have the system Python. macOS ships 3.9.6, and installing against it fails with `Package 'agent-chokepoint' requires a different Python: 3.9.6 not in '>=3.10'`. Install a newer one (`brew install python@3.12`) and use that interpreter by name in the next step.

## Step 1: get it and install it

```bash
git clone https://github.com/ydarwish1/agent-chokepoint
cd agent-chokepoint
python3 -m venv .venv                 # or: /opt/homebrew/bin/python3.12 -m venv .venv
.venv/bin/python -m pip install -e .
```

The project declares two dependencies, `mcp` and `PyYAML`. Pip pulls in whatever `mcp` needs on top of those. No daemon, no database, no account, and nothing outside that directory.

Want the tests too? `.venv/bin/python -m pip install "pytest>=9"` and then `.venv/bin/python -m pytest`.

## Step 2: check it actually works

Run the gateway by hand once, before wiring it into anything:

```bash
echo '{"tool_name":"Read","tool_input":{"file_path":"/workspace/notes.txt"}}' | \
  .venv/bin/python hooks/chokepoint_hook.py --policy policy/policy.example.yaml
```

You should see a decision on stdout:

```
{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow", "permissionDecisionReason": "agent-chokepoint: allowed by rule fs-read-scoped (LLM01)"}}
```

Now check that it refuses something. Same command, different path:

```bash
echo '{"tool_name":"Bash","tool_input":{"command":"rm -rf /workspace"}}' | \
  .venv/bin/python hooks/chokepoint_hook.py --policy policy/policy.example.yaml
```

```
{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": "agent-chokepoint: blocked by rule shell-destructive (LLM01): rule shell-destructive matched tool 'run_command'"}}
```

**Read the exit code, not just the text.** A verdict of any kind, refusals included, comes back as exit 0 with that JSON on stdout. Exit 2 is the fail-closed path: the hook could not reach a decision at all, so it blocks the call and prints why on stderr. Both of those are a healthy install.

**Exit 1 is the one that matters.** In this protocol exit 1 means "non-blocking error, run the tool anyway", so a hook that exits 1 is a hook that permits exactly the call it failed to judge. It happens when Python cannot run the file at all, from a truncated copy or a syntax error, because the interpreter quits before any of the hook's own guards get to run. Nothing inside the file can catch that, which is why you run it by hand.

Point the command at the venv you just made rather than a bare `python3`. An interpreter without PyYAML gives you exit 2 and `could not import its own engine`, which is safe but useless.

## Step 3: wire it into Claude Code

Copy the block from `hooks/settings.example.json` into `~/.claude/settings.json`, or into `.claude/settings.json` inside a single project. If you already have a `hooks` key, merge into it rather than replacing it.

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "mcp__.*",
        "hooks": [
          {
            "type": "command",
            "command": "/ABSOLUTE/PATH/TO/agent-chokepoint/.venv/bin/python /ABSOLUTE/PATH/TO/agent-chokepoint/hooks/chokepoint_hook.py --policy /ABSOLUTE/PATH/TO/agent-chokepoint/policy/policy.example.yaml --log-file /ABSOLUTE/PATH/TO/chokepoint-decisions.jsonl"
          }
        ]
      },
      {
        "matcher": "^(Read|Write|Edit|NotebookEdit|Bash|WebFetch)$",
        "hooks": [
          {
            "type": "command",
            "command": "/ABSOLUTE/PATH/TO/agent-chokepoint/.venv/bin/python /ABSOLUTE/PATH/TO/agent-chokepoint/hooks/chokepoint_hook.py --policy /ABSOLUTE/PATH/TO/agent-chokepoint/policy/policy.example.yaml --log-file /ABSOLUTE/PATH/TO/chokepoint-decisions.jsonl"
          }
        ]
      }
    ]
  }
}
```

Three things to get right:

1. **Replace every `/ABSOLUTE/PATH/TO/...`.** Hooks run with your project as the working directory, so relative paths do not work.
2. **The interpreter path is part of that.** It has to be the venv from step 1. A bare `python3` has no PyYAML and produces the exit 1 case above.
3. **There are two matcher groups on purpose.** `mcp__.*` covers every MCP tool your agent has. The anchored list covers the built-in tools this policy vocabulary can describe.

Restart Claude Code, then ask it to read a file. Decisions land in the `--log-file` you named, one JSON line each. If nothing appears there, the hook is not firing and the paths are the first thing to check.

## Step 4: make the policy yours

**Do this before you decide the tool is broken.** The shipped example is a demo policy. It allows file reads only under `/workspace/`, so on a normal machine almost everything your agent does gets refused:

```
Read /Users/alice/project/main.py    ->  deny   (default:on_no_match)
Read /workspace/main.py              ->  allow  (fs-read-scoped)
```

That is the deny-by-default design working as intended, not a bug. Copy the example somewhere outside the repo, point `--policy` at your copy, and change the paths to the directories you actually work in:

```bash
cp policy/policy.example.yaml ~/chokepoint-policy.yaml
```

Then edit the `path_within` list to name your project directories. The file is heavily commented and every rule is written out in full. Start by changing three things:

- `path_within` under the read rule: where your agent may read.
- `path_within` under the write rule: where it may write. It is set to `ask`, so writes surface as a permission prompt rather than going through silently.
- `domain_in` under the fetch rule: which hosts it may reach.

Paths must be absolute. The engine cannot know your tool's working directory, so it refuses to judge a relative path, which means a relative prefix protects nothing.

## Running the MCP proxy instead

If your agent speaks MCP, put the proxy between it and the server:

```bash
.venv/bin/python -m proxy --policy policy/policy.example.yaml -- <your MCP server command>
```

Flags: `--policy` is required, `--agent-id` labels the decisions, `--server-name` binds rules that name a server, and `--log-file` appends decision events somewhere instead of stderr.

In your agent's MCP config, the proxy command replaces the server command. The agent still thinks it is talking to the server.

Two differences from the hook, both deliberate:

- The proxy enforces the `limits:` block (call caps, wall clock, repeat caps) and taint tracking. The hook cannot, because it runs as one process per tool call and holds no session state.
- On an `ask` verdict the proxy **refuses the call** and returns MCP error `-32001`. No approval channel is wired to it, so it fails closed rather than letting silence become a yes. In Claude Code, `ask` reaches a real human instead.

If the policy will not load, the proxy refuses to start, exits 2, and writes one final decision event first so the outage shows up in your log stream rather than vanishing.

## What it does not judge

Worth knowing on day one, because the gap is deliberate and it is not advertised anywhere in the UI.

The hook judges `Read`, `Write`, `Edit`, `NotebookEdit`, `Bash`, `WebFetch`, and every `mcp__*` tool. It makes **no decision at all** about `Grep`, `Glob`, `Task`, `TodoWrite`, `WebSearch` and the rest. Those exit silently and Claude Code's normal permission flow decides. There is no decision event for them either, so they are not in your audit trail.

The reason it is a gap rather than an `allow`: a hook that answered `allow` for tools it cannot describe would be widening the permissions you already configured. A security control should only ever narrow them.

Practical consequence, stated plainly: this hook does not stop a file read performed by `Grep`, and it does not see anything a subagent launched through `Task` does.

An `allow` from the hook is also not a grant. It is this control declining to object. Your own `permissions.deny` entries in Claude Code are evaluated first and still win.

## When something is wrong

| What you see | What it means |
|---|---|
| Exit 1 from the hook | Python could not run the file at all, so calls go through unjudged. Restore or re-clone the hook file. |
| Exit 2 plus `could not import its own engine` | The interpreter has no PyYAML. You are pointing at the wrong Python. Calls are blocked, not permitted. |
| Everything gets denied | You are still on the example policy and its paths are not yours. See step 4. |
| `blocked by rule default:on_no_match` | Nothing matched, so deny-by-default fired. Add a rule for that call. |
| No lines in the log file | The hook is not firing. Check the paths and that you restarted Claude Code. |
| Proxy exits 2 at startup | The policy file will not load. The final event in your log says why. |

Run the hook by hand after every edit or upgrade. If the file will not compile at all, Python exits 1 before any of its own guards can run, and that is the one failure the code cannot catch for you.

## Uninstall

Delete the `hooks` block you added to your Claude Code settings and restart. For the proxy, put your original server command back in your MCP config. Then remove the clone. Nothing is installed outside the repo directory and your own settings file.

## Where to go next

- `README.md` explains what this is and when it helps.
- `policy/README.md` is the policy language.
- `docs/LIMITATIONS.md` is what it cannot stop, with the measurement behind each entry.
- `docs/THREAT-MODEL.md` is the threat model.
- `CONTRIBUTING.md` is for working on the code itself.
