# dashboard

Grafana over Postgres, provisioned from the files in this directory. The repo contributes a table definition, a loader, a datasource, and a dashboard model — and **no UI code at all**. This project ships no web frontend of its own; the dashboard is the one carved-out exception, and using an off-the-shelf product is what keeps the carve-out narrow.

```
docker-compose.yml                     Grafana + Postgres, loopback-bound
schema.sql                             the events table: one column per schema field
load_events.py                         decision-event JSONL -> SQL INSERTs on stdout
grafana/provisioning/datasources/      the events table, as a datasource
grafana/provisioning/dashboards/       loads the model below from disk, UI edits disabled
grafana/dashboards/agent-chokepoint.json   the dashboard model
```

## Run it

```sh
cd telemetry/dashboard
export CHOKEPOINT_PG_PASSWORD="$(openssl rand -hex 16)"
docker compose up -d
python3 load_events.py ../samples/*.jsonl | docker compose exec -T postgres \
  psql -q -U chokepoint -d chokepoint
open http://127.0.0.1:3001/d/chokepoint-decisions
```

Point the loader at a real gateway's stream instead, and the same panels render production traffic:

```sh
kubectl -n chokepoint exec <pod> -- cat /sandbox/decisions.jsonl > decisions.jsonl
python3 load_events.py decisions.jsonl | docker compose exec -T postgres \
  psql -q -U chokepoint -d chokepoint
```

Tear down with `docker compose down -v`.

## Where the four numbers in the README's screenshot caption come from

`README.md`'s alt text for `telemetry/dashboard.png` states four figures. Each one is a panel's own query over the committed `../samples/*.jsonl`, and the query is in `grafana/dashboards/agent-chokepoint.json` — read them from there rather than trusting this list, which is a pointer, not a second source.

```
figure in the caption          panel                          the clause that produces it
170 decisions                  Decisions                      method IN ('tools/call', 'PreToolUse')
23 blocked                     Blocked                        verdict = 'block'
1 approval-required refusal    Approval required (refused)    verdict = 'ask'
engine decision p95 0.613 ms   Engine decision p95            percentile_cont(0.95) WITHIN GROUP
                                                                (ORDER BY decision_ms), WHERE
                                                                decision_ms > 0
```

*(The middle two rows named **Decisions over time** until 2026-08-08 — **B-124**. That is a real panel and it is a timeseries: its query is `$__timeGroupAlias(ts, $__interval), verdict AS metric, count(*) … GROUP BY 1,2` under `WHERE verdict IS NOT NULL`, so it produces a series and neither scalar, and it carries neither clause the table attributed to it. The two figures are correct and re-derive; what was wrong was the pointer, in the section written to be the pointer. The ledger had it right — B-117's script labels these `panel 'Blocked'` and `panel 'Approval required'` — so two documents written in one pass disagreed and the one a reader is sent to was the wrong one. This section's own caveat below, that it is "a pointer, not a second source", does not cover it: a pointer that points at the wrong panel is the defect and not something the disclaimer excuses.)*

**The p95 is the one a reader cannot check by eye, so its method is stated in full.** `percentile_cont` is PostgreSQL's continuous percentile — linear interpolation at rank `q*(n-1)` over the sorted values — and the panel's `WHERE decision_ms > 0` drops two zero-valued events from the 170. Over the remaining 168 it returns **0.6126**, which the panel renders **0.613** at its own `"decimals": 3`. Both halves are load-bearing: the same function over all 170 values returns 0.6022, and a general-purpose quantile over the unfiltered corpus returns something else again — which is how B-101 came to report that no quantile of the corpus reaches the published figure. It does; the panel's does. **B-117**, and the correction appended to **B-101**.

## Decisions worth knowing before you copy any of this

- **No credential is committed.** The Postgres password comes from `CHOKEPOINT_PG_PASSWORD` with no default, so `docker compose up` fails loudly rather than starting with a password published in a git repo.
- **Anonymous access is ON and the login form is off.** This stack renders a local file of sample events on a loopback-bound port; it is a viewer, not a deployment target. Do not copy that block into anything that leaves your machine.
- **The Postgres port is not published at all** — only Grafana's is, and only on `127.0.0.1`.
- **UI edits cannot become the artifact** (`allowUiUpdates: false`). The file in the repo is the dashboard.
- **`load_events.py` prints SQL rather than connecting.** A database driver would be a dependency this project does not otherwise need, and text on stdout can be read before it is executed.
