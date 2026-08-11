# proxy — the primary enforcement point

An MCP middleman. The agent believes it is talking to its tools; every call traverses this first. Calls the engine, carries out the verdict, emits the decision event.

This is the door that makes Agent-Chokepoint agent-agnostic — anything speaking MCP works without knowing this exists.

**Done when:** a real agent runs through it end to end; a blocked call visibly fails; an allowed call is byte-identical to running unproxied.

*Proven end to end with a real agent.* Run it as:

```
python -m proxy --policy policy/policy.example.yaml -- <upstream server command...>
```

Two committed transcripts stand behind the claim above, both produced by the demo in `demo/`:

- `demo/transcript-2026-08-02.txt` — three real processes over real stdio, scripted MCP client. Reproduce with `python proxy/demo/run_demo.py`.
- `demo/transcript-real-agent-2026-08-02.txt` — **Claude Code itself** driving five tool calls through the proxy, then the same five with the proxy removed. Guarded, 2 of 5 reached the tool; unguarded, 5 of 5.

The guard-off half of each is not decoration. "Nothing bad happened" reads identically whether the control worked or the call path was broken; firing the same payload down the unguarded path and watching it land is the only thing that tells them apart.

A policy that will not load refuses to start the proxy — exit 2, and one final `proxy:policy-error` decision event written to `--log-file`/stderr first (D-029), so the outage is visible in the stream instead of silent. Any other startup failure (a bad flag, an upstream that cannot spawn) still writes nothing; the schema's WHO-WRITES-THE-FILE section states the boundary. The hook's equivalent is `hook:policy-error` (`hooks/README.md`).
