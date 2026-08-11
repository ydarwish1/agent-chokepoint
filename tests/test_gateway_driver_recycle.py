"""D-022 / B-040: per-run caps versus a long-lived gateway, and the recycle fix.

A "run" is one MCP client session with the proxy — one proxy process, since the
stdio proxy serves exactly one session per process. The deployed driver held one
session open forever, so `max_wall_clock_seconds: 900` became a pod-uptime cap:
measured live, the gateway blocked 100% of traffic from 900s onward and the
kubelet restarted a healthy pod every ~16 minutes (B-040).

Three legs, D-021's both-controls discipline, every one driving the REAL chain —
this test's client -> a real `python -m proxy` process -> the real demo
upstream, over stdio, against the shipped policy with one scalar changed:

1. the CAP leg (the defect, distilled): one session held past
   `max_wall_clock_seconds` has every later call blocked — the control proving
   the limit can fire and that `beat` recognises it as a run-limit;
2. the FIX leg: sessions recycled under the cap keep serving well past it —
   every beat reaches the tool, counted from the upstream's own EXECUTED.log,
   never from this test's account of what it sent;
3. the BACKSTOP leg: with proactive recycling effectively off, a run-limit
   block ends the session early instead of holding a dark gateway, and the
   next session's first beat lands.

The probe policy is built by `yaml.safe_load` + one edit + `yaml.safe_dump`,
never hand-written (B-039: a hand-quoted YAML scalar changes the pattern the
loader sees, and the test then measures a different refusal than it means to).
"""

from __future__ import annotations

import importlib.util
import sys
import time
from pathlib import Path

import anyio
import pytest
import yaml

from mcp import Client, stdio_client

REPO_ROOT = Path(__file__).resolve().parents[1]
UPSTREAM_SERVER = REPO_ROOT / "proxy" / "demo" / "upstream_server.py"

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return "asyncio"


def _load_driver():
    # deploy/ is deliberately not a package (pyproject [tool.setuptools]), so
    # the driver is loaded from its path, exactly as the pod's command line does.
    spec = importlib.util.spec_from_file_location(
        "gateway_driver", REPO_ROOT / "deploy" / "demo" / "gateway_driver.py"
    )
    module = importlib.util.module_from_spec(spec)
    # Registered BEFORE exec: the driver defines dataclasses, and on 3.14 the
    # dataclass machinery resolves the defining module through sys.modules.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


gd = _load_driver()


def _capped_policy(tmp_path: Path, max_wall_clock_seconds: int) -> Path:
    doc = yaml.safe_load(
        (REPO_ROOT / "policy" / "policy.example.yaml").read_text(encoding="utf-8")
    )
    doc["limits"]["max_wall_clock_seconds"] = max_wall_clock_seconds
    out = tmp_path / "policy.yaml"
    out.write_text(yaml.safe_dump(doc), encoding="utf-8")
    return out


def _params(policy: Path, sandbox: Path):
    return gd.proxy_params(
        sys.executable,
        str(policy),
        [sys.executable, str(UPSTREAM_SERVER), "--sandbox", str(sandbox)],
    )


def _reached(sandbox: Path) -> int:
    executed = sandbox / "EXECUTED.log"
    if not executed.is_file():
        return 0
    return sum(
        1
        for line in executed.read_text(encoding="utf-8").splitlines()
        if line.startswith(gd.HEARTBEAT_LEG.tool + "\t")
    )


async def test_a_session_held_past_the_wall_clock_cap_blocks(tmp_path):
    """The defect leg: the cap fires inside ONE session, and `beat` sees it."""
    policy = _capped_policy(tmp_path, 2)
    heartbeat = tmp_path / "heartbeat"
    async with Client(stdio_client(_params(policy, tmp_path))) as client:
        assert await gd.beat(client, heartbeat, 1) == gd.BEAT_OK
        await anyio.sleep(2.2)  # the proxy's run clock starts at process start
        assert await gd.beat(client, heartbeat, 2) == gd.BEAT_RUN_LIMIT
    # The blocked beat never reached the tool: only the first one is in the log.
    assert _reached(tmp_path) == 1


async def test_recycled_sessions_keep_serving_past_the_cap(tmp_path, monkeypatch):
    """The fix leg: with sessions recycled under the cap, service is continuous
    well past the wall-clock that killed the deployed gateway."""
    policy = _capped_policy(tmp_path, 4)
    monkeypatch.setattr(gd, "RECYCLE_SECONDS", 1)
    monkeypatch.setattr(gd, "HEARTBEAT_SECONDS", 0.2)
    heartbeat = tmp_path / "heartbeat"
    params = _params(policy, tmp_path)

    sequence = 0
    sessions = 0
    start = time.monotonic()
    while time.monotonic() - start < 9:  # more than twice the 4s cap
        sessions += 1
        async with Client(stdio_client(params)) as client:
            sequence = await gd.hold_session(client, heartbeat, sequence)
    elapsed = time.monotonic() - start

    assert sessions >= 2, "the recycle cadence never recycled"
    assert elapsed >= 8, "the loop did not outlive the cap it claims to survive"
    assert sequence >= 10, f"only {sequence} beats in {elapsed:.1f}s"
    # Every beat reached the tool — the upstream's own log, not this test's
    # account. One refused beat would make these differ.
    assert _reached(tmp_path) == sequence, (
        "a beat was refused: recycling failed to keep every run under the caps"
    )


async def test_run_limit_backstop_recycles_early_and_service_resumes(tmp_path, monkeypatch):
    """The backstop leg: proactive recycling off, the run-limit block ends the
    session (no dark gateway), and a fresh session serves again."""
    policy = _capped_policy(tmp_path, 2)
    monkeypatch.setattr(gd, "RECYCLE_SECONDS", 3600)  # proactive recycle OFF
    monkeypatch.setattr(gd, "HEARTBEAT_SECONDS", 0.2)
    heartbeat = tmp_path / "heartbeat"
    params = _params(policy, tmp_path)

    start = time.monotonic()
    async with Client(stdio_client(params)) as client:
        sequence = await gd.hold_session(client, heartbeat, 0)
    elapsed = time.monotonic() - start

    assert elapsed < 20, "hold_session did not return early on the run-limit block"
    assert sequence >= 2, "the session never beat before the cap tripped"

    async with Client(stdio_client(params)) as client:
        assert await gd.beat(client, heartbeat, sequence + 1) == gd.BEAT_OK
