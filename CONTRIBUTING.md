# Contributing

Thanks for looking. This is a small project with one maintainer, so a short issue describing what you hit is more useful than a large surprise pull request.

## Set up

```sh
git clone https://github.com/ydarwish1/agent-chokepoint
cd agent-chokepoint
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -e .
.venv/bin/python -m pip install --group dev
.venv/bin/python -m pytest
```

Python 3.10 or newer. The `--group dev` install is [PEP 735](https://peps.python.org/pep-0735/) and needs pip 25.1 or newer, which the upgrade step supplies. That group is the single list of test-only tools; install it by reference rather than re-typing its members.

Without the dev group, `tests/test_telemetry_controls.py` skips instead of running, so the event-schema validation and the Sigma rule checks do not execute.

## Run the suite the way CI runs it

CI is `.github/workflows/ci.yml`: the suite on Python 3.10 and 3.14 on every push and pull request, plus a job that builds the container image and gates the Helm chart's hardening. Mirror the commands above rather than improvising.

Two things that trip people up:

- **Do not add another `-q`.** The pytest options in `pyproject.toml` already carry one, and a second suppresses the summary line entirely.
- **Do not assume a virtualenv.** The local convention is `.venv/`, but CI has none. A test harness spawns the interpreter that is running it; `tests/test_suite_is_portable.py` holds the suite to that.

## What a good change looks like

- **A policy rule change ships with both controls.** A case proving the rule refuses what it claims, and a case proving it leaves the nearest benign call alone. A rule with only the first is indistinguishable from a rule that refuses everything.
- **A claim in a document is measured.** This project publishes no effectiveness figures because none have been measured. If you add a number, name the command that produced it.
- **Engine changes stay pure.** `engine/` does no network, no disk and holds no state between calls. `engine/tests/test_standalone.py` imports it in a fresh interpreter and fails if a non-standard-library module appears.
- **Both doors keep agreeing.** The MCP proxy and the Claude Code hook call the same engine. `hooks/demo/side_by_side.py` is what checks they return the same verdict for the same call.

## Reporting a security defect

Please do not open a public issue for an exploitable bug. `SECURITY.md` has the private route.

## License

By contributing you agree that your contribution is licensed under Apache-2.0, the same terms as the rest of the project.
