"""D-029: a proxy whose policy fails to load writes ONE `proxy:policy-error`
event, then refuses to start — both controls, at the process boundary.

Before this, the proxy exited on a bad policy before its event sink existed, so
its outage produced zero events and was invisible in the stream where the
hook's identical failure emits `hook:policy-error`. The published schema's
WHO-WRITES-THE-FILE section stated that gap as fact; it was updated in the same
commit as this file.

Through the process, because the sink ordering inside ``main()`` is exactly
what is under test — a unit test that called the emission helper directly
would pass with the ordering still wrong. The bad policies are never
hand-written YAML: one scalar is changed via safe_load/safe_dump (B-039).

The negative space is pinned too: a startup failure BEFORE the sink exists
(an unparseable flag) still writes nothing, because ``--log-file`` itself may
be the broken flag. The schema documents that boundary in the same words.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import anyio
import pytest
import yaml

from mcp import Client, StdioServerParameters, stdio_client

REPO_ROOT = Path(__file__).resolve().parents[2]
POLICY = REPO_ROOT / "policy" / "policy.example.yaml"
SCHEMA_PATH = REPO_ROOT / "telemetry" / "event-schema.json"
UPSTREAM = REPO_ROOT / "proxy" / "demo" / "upstream_server.py"

RULE = "proxy:policy-error"


def _unloadable_policy(tmp_path: Path) -> Path:
    """The shipped policy with one rule id claiming a reserved prefix — a real
    `PolicyError` out of the real loader (D-026), not a YAML syntax error."""
    doc = yaml.safe_load(POLICY.read_text(encoding="utf-8"))
    doc["rules"][0]["id"] = "limit:claimed-by-a-policy-author"
    out = tmp_path / "unloadable.yaml"
    out.write_text(yaml.safe_dump(doc), encoding="utf-8")
    return out


def _run_proxy(argv: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "proxy", *argv],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=30,
    )


def _events(log: Path) -> list[dict]:
    return [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]


class TestThePolicyErrorEventIsWritten:
    def _assert_the_one_event(self, event: dict, *, agent_id: str, server: str | None):
        # The full key set of a decision event, exactly — the point of using
        # the decision shape is that every existing consumer already reads it.
        assert sorted(event) == [
            "agent_id", "arguments", "decision_ms", "method", "owasp",
            "reason", "rule_id", "run_id", "server", "tool", "ts",
            "verdict",
        ]
        assert event["rule_id"] == RULE
        assert event["verdict"] == "block"
        assert event["method"] == "tools/call"
        # Null tool and arguments: this refusal precedes any call. Null run_id:
        # the run it would identify was never created. 0.0: refused before the
        # engine ran (the schema tells latency consumers to exclude it).
        assert event["tool"] is None
        assert event["arguments"] is None
        assert event["run_id"] is None
        assert event["decision_ms"] == 0.0
        assert event["owasp"] is None
        assert event["agent_id"] == agent_id
        assert event["server"] == server
        assert "did not load" in event["reason"]

    def test_a_policy_the_loader_refuses_writes_the_event_and_refuses_to_start(self, tmp_path):
        log = tmp_path / "events.jsonl"
        proc = _run_proxy([
            "--policy", str(_unloadable_policy(tmp_path)),
            "--agent-id", "gateway-under-test", "--server-name", "docs-mcp",
            "--log-file", str(log), "--", "prog-never-spawned",
        ])
        assert proc.returncode == 2
        assert "did not load" in proc.stderr and "refusing to start" in proc.stderr
        assert "Traceback" not in proc.stderr
        events = _events(log)
        assert len(events) == 1
        self._assert_the_one_event(events[0], agent_id="gateway-under-test", server="docs-mcp")

    def test_a_missing_policy_file_writes_the_event_too(self, tmp_path):
        # The OSError half of the pair the hook refuses on — a path that names
        # no file is the commonest broken deployment (a ConfigMap that moved).
        log = tmp_path / "events.jsonl"
        proc = _run_proxy([
            "--policy", str(tmp_path / "no-such-policy.yaml"),
            "--log-file", str(log), "--", "prog-never-spawned",
        ])
        assert proc.returncode == 2
        events = _events(log)
        assert len(events) == 1
        self._assert_the_one_event(events[0], agent_id="default", server=None)

    def test_a_policy_file_with_invalid_utf8_writes_the_event_too(self, tmp_path):
        # B-044 / D-030. This is the case that showed D-029's signal was
        # reachable only for the exception types someone had thought to name:
        # `load_policy` read the file with `encoding="utf-8"`, so one bad byte
        # raised `UnicodeDecodeError`, which is neither `PolicyError` nor
        # `OSError`, so `main()`'s except clause did not catch it. Measured
        # pre-fix: exit 1, ZERO events, a raw traceback — the silent outage
        # D-029 exists to abolish. Not hand-written text: real bytes that are
        # not valid UTF-8, the way a truncated or mis-transcoded ConfigMap
        # arrives.
        policy = tmp_path / "bad-bytes.yaml"
        policy.write_bytes(b"version: 0\n# \xff\xfe\n")
        log = tmp_path / "events.jsonl"
        proc = _run_proxy([
            "--policy", str(policy), "--log-file", str(log), "--", "prog-never-spawned",
        ])
        assert proc.returncode == 2
        assert "Traceback" not in proc.stderr
        events = _events(log)
        assert len(events) == 1
        self._assert_the_one_event(events[0], agent_id="default", server=None)

    def test_without_a_log_file_the_event_goes_to_stderr(self, tmp_path):
        # The default deployment logs to stderr; the outage signal must not
        # depend on the optional flag.
        proc = _run_proxy([
            "--policy", str(_unloadable_policy(tmp_path)), "--", "prog-never-spawned",
        ])
        assert proc.returncode == 2
        json_lines = [
            json.loads(line) for line in proc.stderr.splitlines()
            if line.startswith("{")
        ]
        assert [e["rule_id"] for e in json_lines] == [RULE]

    def test_the_event_validates_against_the_published_schema(self, tmp_path):
        jsonschema = pytest.importorskip("jsonschema")
        log = tmp_path / "events.jsonl"
        _run_proxy([
            "--policy", str(_unloadable_policy(tmp_path)),
            "--log-file", str(log), "--", "prog-never-spawned",
        ])
        (event,) = _events(log)
        validator = jsonschema.Draft202012Validator(
            json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        )
        errors = [e.message for e in validator.iter_errors(event)]
        assert not errors, errors[0]


def _child_env() -> dict[str, str]:
    env = {k: os.environ[k] for k in ("HOME", "PATH", "LOGNAME", "SHELL", "TERM", "USER") if k in os.environ}
    env["PYTHONPATH"] = str(REPO_ROOT)
    return env


async def _one_allowed_call(log: Path, sandbox: Path) -> str:
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "proxy", "--policy", str(POLICY), "--log-file", str(log),
              "--", sys.executable, str(UPSTREAM), "--sandbox", str(sandbox)],
        cwd=str(REPO_ROOT), env=_child_env(),
    )
    async with Client(stdio_client(params)) as agent:
        await agent.call_tool("read_file", {"path": "/workspace/notes.txt"})
        return "ALLOWED"


class TestAGoodPolicyStillStartsClean:
    def test_the_shipped_policy_serves_and_emits_no_policy_error(self, tmp_path):
        """The control, end to end: the same entrypoint with the same sink
        reordering serves a real call, its decision events land in the same
        --log-file, and none of them is a policy-error. Without this leg the
        tests above would pass identically if the proxy now refused every
        start."""
        log = tmp_path / "events.jsonl"
        sandbox = tmp_path / "sandbox"
        sandbox.mkdir()
        (sandbox / "notes.txt").write_text("benign\n", encoding="utf-8")
        assert anyio.run(_one_allowed_call, log, sandbox) == "ALLOWED"
        events = _events(log)
        assert any(e.get("verdict") == "allow" for e in events)
        assert not any(e.get("rule_id") == RULE for e in events)
        # Serving events belong to a run; only the startup refusal has none.
        assert all(e["run_id"] for e in events)

    def test_a_flag_error_still_writes_nothing(self, tmp_path):
        # The boundary the schema states: argparse refusals happen before the
        # sink exists (--log-file itself may be the broken flag), so they still
        # produce no event — only the policy-load failure emits.
        log = tmp_path / "events.jsonl"
        proc = _run_proxy([
            "--policy", str(POLICY), "--server-name", "prod__west",
            "--log-file", str(log), "--", "prog-never-spawned",
        ])
        assert proc.returncode == 2
        assert not log.exists()
