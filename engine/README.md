# engine — the decision point

Pure library. Takes a tool call, returns `allow | block | ask` plus the id of the rule that fired. No I/O, no network, no state.

Keeping it pure is what makes multiple enforcement points possible: the proxy and the Claude Code hook call the same function and cannot disagree.

**Done when:** unit tests cover every rule type; the library is importable standalone; adding a new enforcement point requires zero changes here.

`decide()` is in `decide.py`, the fixed predicate vocabulary (D-006) in `predicates.py`, the frozen data model in `model.py`. Purity is checked mechanically, not asserted: `tests/test_standalone.py` imports the engine in a fresh interpreter and diffs `sys.modules` — no non-stdlib module may appear.

*Added by D-039:* `listing.py` holds a **second** decision function, `decide_listing()`, for `tools/list` — the tool definitions an agent is handed, judged against the digests the operator approved. Same contract: pure, no I/O, a `Decision` with a rule id out. It is handed `(name, digest)` pairs rather than tool definitions, so no description reaches this package at all — which is what makes "this gateway does not read descriptions" a property of the type signature rather than a promise. The wire parse that produces those pairs is the enforcement point's job, the way building a `ToolCall` is.
