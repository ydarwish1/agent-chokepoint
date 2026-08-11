"""Acceptance artifact for **D-020** — command resolution is PINNED, shown with both controls.

D-020 makes B-035's precondition a deployment requirement: the chart must pin how the
upstream command is resolved, and the config-scan output must state the pinning mechanism
explicitly and show it, not assert it. This script is the showing.

THE MECHANISM (traced, not re-derived here; the header resolves every line number below
against the interpreter that is actually running, so the citations stay true in the
container as well as outside it):

  1. ``mcp/client/stdio.py`` ``_get_executable_command`` — on POSIX it returns the command
     **unchanged**. There is no ``shutil.which``; the SDK does not resolve anything.
  2. ``mcp/client/stdio.py`` — ``anyio.open_process([command, *args], env=…,
     start_new_session=True)``. The **list** form means ``subprocess_exec``: no shell, ever.
  3. ``subprocess.py`` — ``start_new_session=True`` is one of the conjuncts in the
     ``_USE_POSIX_SPAWN`` gate, so it **disqualifies the ``posix_spawn`` fast path** and
     execution always reaches ``_fork_exec``. (Measured at ``:1869`` on CPython 3.14.6 —
     the clause moves between point releases, which is why the header resolves it live
     rather than trusting any one number.)
  4. ``subprocess.py`` — ``if os.path.dirname(executable): executable_list =
     (executable,)``, **else** the list is built from ``os.get_exec_path(env)``, which the
     source itself annotates *"This matches the behavior of os._execvpe()"*. That single
     ``if`` is the entire pin: a command containing a ``/`` gets **no PATH search at all**.
     That is the MECHANISM and this artifact reports it as such — but it is not the
     harness's admission policy. A *relative* path contains a ``/`` too, and it resolves
     against the process's working directory, which a workload may be able to write. So
     ``--interpreter`` is refused unless ``os.path.isabs`` holds: "skips the PATH search"
     and "cannot be influenced" are different statements, and blurring them would let a
     run prove only that the string contained a slash.
  5. ``mcp/client/stdio.py`` — the child's env is a six-key scrub
     (``HOME LOGNAME PATH SHELL TERM USER``) of the **proxy's own** ``os.environ``, merged
     under any explicit ``env=``. So the PATH set on the proxy process is exactly the PATH
     the child's exec search uses.

THE EXPERIMENT — one variable, and that is the whole point.

Under the pinned PATH a bare ``python3`` was measured to resolve to
``/usr/local/bin/python3`` too. A control that merely changed absolute → bare would run the
**same real interpreter** in both legs and prove nothing — "nothing bad happened" reads the
same whether the pin worked or the probe was broken. So:

  * BOTH legs run with ``PATH=<shimdir>:/usr/local/bin:/usr/bin:/bin`` — the same string.
  * BOTH legs have one executable shim named ``python3`` in ``<shimdir>``. It (a) appends a
    line to a marker file and (b) execs the real interpreter with the same argv, so a leg
    whose lookup *is* interposed still works end to end. Breaking (b) would make the
    guard-off leg indistinguishable from a crash.
  * BOTH legs make the same allowed call through the same proxy at the same sandbox.
  * **Leg 1, guard ON** — upstream spelled ``<abs-interpreter> <abs-upstream.py> --sandbox``:
    marker absent, call still reaches the tool.
  * **Leg 2, guard OFF (the control)** — upstream spelled ``python3 <abs-upstream.py>
    --sandbox``: marker present, call still reaches the tool.

The only difference between the two legs is the spelling of ``argv[0]`` of the upstream
command, and that is asserted in the VERDICT block rather than promised here.

GROUND TRUTH, per claim, always written by a different program than this one:

  * "did the shim run"       -> the marker file **the shim itself wrote**, counted before
                                and after each leg. Never this script's account of itself.
  * "did the call reach it"  -> ``EXECUTED.log``, appended by
                                ``proxy/demo/upstream_server.py`` when a call arrives.
  * "was it judged"          -> the proxy's own decision events.

A leg that was not measured must **fail**, never read as "the shim did not run": every
counter starts at ``-1`` and ``shim_ran`` is ``None`` until both snapshots exist, so an
unmeasured leg satisfies neither ``expect_shim_ran=False`` nor ``expect_shim_ran=True``.
And if BOTH legs agree — shim in neither, or shim in both — the shim is broken and nothing
was proven; that is its own named check, not a pass.

    .venv/bin/python deploy/demo/path_pinning.py
    .venv/bin/python deploy/demo/path_pinning.py --out FILE
    # in the pod:
    python3 /app/deploy/demo/path_pinning.py --repo-root /app \\
        --interpreter /usr/local/bin/python3 --workdir /sandbox --out /sandbox/path-pinning.txt

Exit 0 only when every property the transcript asserts holds; exit 1 otherwise.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shlex
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

import anyio

import mcp.client.stdio as mcp_stdio
from mcp import Client, MCPError, StdioServerParameters, stdio_client

# deploy/demo/path_pinning.py -> parents[2] is the repo root (/app in the image).
DEFAULT_REPO_ROOT = Path(__file__).resolve().parents[2]

# The shim directory is prepended to this, identically in both legs.
PINNED_PATH = "/usr/local/bin:/usr/bin:/bin"

# The shim is named for the command leg 2 spells bare. Same file, both legs.
SHIM_NAME = "python3"

# allow / fs-read-scoped against the LIVE policy, so the call reaches the tool in both
# legs and `reached` is a real number rather than a blocked-by-design 0.
CALL_TOOL: str = "read_file"
CALL_ARGS: dict = {"path": "/workspace/notes.txt"}

# Written into the shim once and used by both legs. `$0` is the shim's own path (the
# kernel supplies it for a `#!` script), `$*` the argv it was handed.
SHIM_TEMPLATE = """\
#!/bin/sh
# Planted by deploy/demo/path_pinning.py. IDENTICAL in both legs -- it is the PATH
# entry that differs in whether anything looks it up, never the shim itself.
#   (a) record that a PATH search landed here, and
#   (b) chain to the real interpreter with the same argv, so the leg that IS
#       interposed still works end to end. A shim that broke the chain would make
#       the guard-off leg indistinguishable from a crash.
echo "shim ran: argv0=$0 args=$*" >> {marker}
exec {real} "$@"
"""

lines: list[str] = []


def say(text: str = "") -> None:
    lines.append(text)
    print(text, flush=True)


def rule(title: str, width: int = 78) -> None:
    say(f"--- {title} " + "-" * max(0, width - len(title) - 5))


def compact(obj: object) -> str:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True)


# ----------------------------------------------------------------------- the setup


@dataclass(frozen=True)
class Setup:
    """Every path and string the run needs, resolved once so both legs share them."""

    repo_root: Path
    interpreter: str
    run_dir: Path
    shim_dir: Path
    shim: Path
    marker: Path
    sandbox: Path
    decisions: Path
    path: str

    @property
    def policy(self) -> Path:
        return self.repo_root / "policy" / "policy.example.yaml"

    @property
    def upstream(self) -> Path:
        return self.repo_root / "proxy" / "demo" / "upstream_server.py"


def build_setup(repo_root: Path, interpreter: str, workdir: Path) -> Setup:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    run_dir = workdir / f"path-pinning-{stamp}-{os.getpid()}"
    shim_dir = run_dir / "shim"
    sandbox = run_dir / "sandbox"
    for directory in (run_dir, shim_dir, sandbox):
        directory.mkdir(parents=True)
    (sandbox / "notes.txt").write_text("benign sandbox file\n", encoding="utf-8")

    setup = Setup(
        repo_root=repo_root,
        interpreter=interpreter,
        run_dir=run_dir,
        shim_dir=shim_dir,
        shim=shim_dir / SHIM_NAME,
        marker=run_dir / "SHIM-RAN.log",
        sandbox=sandbox,
        decisions=run_dir / "decisions.jsonl",
        # The one PATH both legs use. The shim directory genuinely precedes the real
        # bin dirs: a shim that does not come first is a control that cannot fire.
        path=f"{shim_dir}:{PINNED_PATH}",
    )
    setup.shim.write_text(
        SHIM_TEMPLATE.format(marker=shlex.quote(str(setup.marker)), real=shlex.quote(interpreter)),
        encoding="utf-8",
    )
    setup.shim.chmod(0o755)
    return setup


def child_env(setup: Setup) -> dict[str, str]:
    """The environment the proxy runs in — and therefore, after the SDK's six-key scrub,
    the environment its exec search runs in.

    PATH is deliberately NOT inherited: it is the constant this experiment pins. The SDK
    merges an explicit ``env=`` OVER ``get_default_environment()``, so this value wins.
    ``PYTHONPATH`` is rebuilt because the scrub drops it and the proxy imports this repo
    (same reason as ``proxy/demo/run_demo.py``). ``PYTHONDONTWRITEBYTECODE`` is set so a
    read-only application root never needs a writable package directory; it is identical
    in both legs and so cannot be the variable.
    """
    env = {k: os.environ[k] for k in ("HOME", "LOGNAME", "SHELL", "TERM", "USER") if k in os.environ}
    env["PATH"] = setup.path
    env["PYTHONPATH"] = str(setup.repo_root)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


def upstream_argv(setup: Setup, argv0: str) -> list[str]:
    """The command the PROXY will exec. ``argv0`` is the only thing that ever differs."""
    return [argv0, str(setup.upstream), "--sandbox", str(setup.sandbox)]


def proxy_argv(setup: Setup, argv0: str) -> list[str]:
    return [
        "-m", "proxy",
        "--policy", str(setup.policy),
        "--agent-id", "path-pinning",
        "--log-file", str(setup.decisions),
        "--", *upstream_argv(setup, argv0),
    ]


def spawn_argv(setup: Setup, argv0: str) -> list[str]:
    return [setup.interpreter, *proxy_argv(setup, argv0)]


# ------------------------------------------------------------------ ground truth readers


def marker_lines(marker: Path) -> int:
    """How many lines the SHIM has written. 0 when the file does not exist yet."""
    if not marker.is_file():
        return 0
    return len([ln for ln in marker.read_text(encoding="utf-8").splitlines() if ln.strip()])


def executed(sandbox: Path) -> list[str]:
    """The upstream's own record of what reached it — one line per call that arrived."""
    log = sandbox / "EXECUTED.log"
    return log.read_text(encoding="utf-8").splitlines() if log.is_file() else []


def read_events(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    return [json.loads(ln) for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]


def sha256(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()[:16]
    except OSError as exc:
        return f"<unreadable: {exc}>"


def is_digest(value: str) -> bool:
    """A real reading, not the ``<not measured>`` / ``<unreadable>`` sentinel.

    Two sentinels compare equal, so an equality test alone would score "the shim was never
    readable" as "the shim never changed"."""
    return len(value) == 16 and all(c in "0123456789abcdef" for c in value)


# -------------------------------------------------------------------------- the legs


@dataclass(frozen=True)
class Leg:
    """One leg, and what it is EXPECTED to produce — data beside the call, not a comment.

    ``expect_shim_ran`` and ``expect_reach`` are what make this harness test the pin
    rather than merely report two numbers. Without them a run where the shim never fired
    at all reads exactly like a run where the pin worked.
    """

    number: int
    guard: str
    argv0: str
    expect_shim_ran: bool
    expect_reach: int
    why: str

    @property
    def label(self) -> str:
        return f"leg {self.number} · guard {self.guard}"


@dataclass
class LegResult:
    """Measurements for one leg. Every counter starts at a value that FAILS its check."""

    leg: Leg
    upstream: list[str] = field(default_factory=list)
    spawn: list[str] = field(default_factory=list)
    path: str = "<not measured>"
    marker_before: int = -1
    marker_after: int = -1
    marker_exists_after: bool | None = None
    reach_before: int = -1
    reach_after: int = -1
    outcome: str = "<not measured>"
    verdicts: list[str] = field(default_factory=list)
    error: str = ""

    @property
    def measured(self) -> bool:
        return not self.error and min(
            self.marker_before, self.marker_after, self.reach_before, self.reach_after
        ) >= 0

    @property
    def shim_ran(self) -> bool | None:
        """``None`` until both marker snapshots exist.

        Deliberately tri-state. A boolean would make an unmeasured leg report ``False``,
        i.e. "the shim did not run" — which is precisely the guard-ON claim this artifact
        exists to make, handed out for free to a leg that never ran.
        """
        if not self.measured:
            return None
        return self.marker_after > self.marker_before

    @property
    def reached(self) -> int:
        """Lines the upstream added to EXECUTED.log during THIS leg. ``-1`` if unmeasured."""
        if not self.measured:
            return -1
        return self.reach_after - self.reach_before

    @property
    def shim_text(self) -> str:
        return {None: "<not measured>", True: "YES", False: "no"}[self.shim_ran]


async def one_call(client: Client, tool: str, args: dict) -> str:
    try:
        result = await client.call_tool(tool, args)
        return "RESULT   " + result.content[0].text.replace("\n", " ")[:100].strip()
    except MCPError as exc:
        return f"REFUSED  code={exc.error.code} {exc.error.message}"


async def run_leg(setup: Setup, leg: Leg) -> LegResult:
    result = LegResult(leg=leg)
    result.upstream = upstream_argv(setup, leg.argv0)
    result.spawn = spawn_argv(setup, leg.argv0)
    result.path = setup.path
    result.marker_before = marker_lines(setup.marker)
    result.reach_before = len(executed(setup.sandbox))
    events_before = len(read_events(setup.decisions))

    params = StdioServerParameters(
        command=setup.interpreter,
        args=proxy_argv(setup, leg.argv0),
        cwd=str(setup.repo_root),
        env=child_env(setup),
    )
    try:
        async with Client(stdio_client(params)) as client:
            result.outcome = await one_call(client, CALL_TOOL, CALL_ARGS)
    except Exception as exc:  # noqa: BLE001 — a failed leg is a finding, not a traceback
        result.error = f"{type(exc).__name__}: {exc}"
        return result

    result.marker_after = marker_lines(setup.marker)
    result.marker_exists_after = setup.marker.is_file()
    result.reach_after = len(executed(setup.sandbox))
    # tools/call events only: the proxy also emits a `tools/list ... forwarded` event that
    # carries no verdict, and rendering it as "None / None" would print an empty column as
    # though it were a measurement.
    result.verdicts = [
        f"{e.get('verdict')} / {e.get('rule_id')}"
        for e in read_events(setup.decisions)[events_before:]
        if e.get("method") == "tools/call"
    ]
    return result


# ------------------------------------------------------------------------- comparison


def argv_diff(a: list[str], b: list[str]) -> list[int] | None:
    """Indices at which two argv lists differ, or ``None`` if the lengths differ.

    ``None`` rather than a shorter list: ``zip`` would silently compare the overlap and
    report "identical" for two commands of different length.
    """
    if len(a) != len(b):
        return None
    return [i for i, (x, y) in enumerate(zip(a, b)) if x != y]


@dataclass
class Results:
    legs: list[LegResult] = field(default_factory=list)
    shim_sha_before: str = "<not measured>"
    shim_sha_after: str = "<not measured>"

    def leg(self, number: int) -> LegResult | None:
        return next((r for r in self.legs if r.leg.number == number), None)

    @property
    def checks(self) -> list[tuple[str, bool, str]]:
        one, two = self.leg(1), self.leg(2)
        blank = LegResult(leg=Leg(0, "?", "?", False, -1, ""))
        a, b = one or blank, two or blank

        up_diff = argv_diff(a.upstream, b.upstream) if one and two else None
        spawn_diff = argv_diff(a.spawn, b.spawn) if one and two else None
        errors = "; ".join(f"{r.leg.label}: {r.error}" for r in self.legs if r.error)

        return [
            (
                "both legs ran and were measured (no counter left at its sentinel)",
                len(self.legs) == 2 and a.measured and b.measured,
                errors
                or f"{len(self.legs)} leg(s); measured: leg1={a.measured} leg2={b.measured}",
            ),
            (
                "leg 1 · guard ON  · the PATH shim did NOT run",
                a.shim_ran is False and a.marker_exists_after is False,
                f"shim_ran={a.shim_text}, marker file on disk after the leg="
                f"{a.marker_exists_after}, marker lines {a.marker_before}->{a.marker_after} "
                f"(expected {a.leg.expect_shim_ran})",
            ),
            (
                "leg 1 · guard ON  · the call still REACHED the upstream",
                a.reached == a.leg.expect_reach,
                f"EXECUTED.log grew by {a.reached} line(s), expected {a.leg.expect_reach}",
            ),
            (
                "leg 2 · guard OFF · the PATH shim DID run (the control)",
                b.shim_ran is True,
                f"shim_ran={b.shim_text}, marker lines {b.marker_before}->{b.marker_after} "
                f"(expected {b.leg.expect_shim_ran})",
            ),
            (
                "leg 2 · guard OFF · the call still REACHED the upstream",
                b.reached == b.leg.expect_reach,
                f"EXECUTED.log grew by {b.reached} line(s), expected {b.leg.expect_reach}",
            ),
            (
                "the two legs DIFFER — a shim that ran in both, or in neither, proves nothing",
                a.shim_ran is not None and b.shim_ran is not None and a.shim_ran != b.shim_ran,
                f"leg1 shim_ran={a.shim_text}, leg2 shim_ran={b.shim_text}"
                + (
                    ""
                    if (a.shim_ran is not None and b.shim_ran is not None and a.shim_ran != b.shim_ran)
                    else "  <- the shim is broken or was never consulted; NOTHING is demonstrated"
                ),
            ),
            (
                "the ONLY difference between the legs is the spelling of argv[0]",
                up_diff == [0] and spawn_diff is not None and len(spawn_diff) == 1 and a.path == b.path,
                f"upstream argv differs at {up_diff} (expected [0]), full spawn argv differs at "
                f"{spawn_diff} (expected exactly one index), PATH identical={a.path == b.path}",
            ),
            (
                "the resolution test subprocess.py applies: leg 1 has a directory component, leg 2 does not",
                bool(os.path.dirname(a.leg.argv0)) and not os.path.dirname(b.leg.argv0),
                f"os.path.dirname({a.leg.argv0!r})={os.path.dirname(a.leg.argv0)!r}, "
                f"os.path.dirname({b.leg.argv0!r})={os.path.dirname(b.leg.argv0)!r}",
            ),
            (
                "the shim was byte-identical throughout (nothing rewrote it between legs)",
                self.shim_sha_before == self.shim_sha_after and is_digest(self.shim_sha_before),
                f"sha256[:16] before={self.shim_sha_before} after={self.shim_sha_after}",
            ),
        ]

    @property
    def ok(self) -> bool:
        return all(passed for _name, passed, _detail in self.checks)


# ----------------------------------------------------------------------------- header


def cite(path: Path, needle: str, label: str) -> tuple[str, str]:
    """``(file:line, label)`` for a line of the LIVE source, resolved rather than remembered.

    Line numbers in the SDK and in the standard library move between point releases, and
    this artifact runs on at least two interpreters (this machine's and the image's). A
    number that cannot be found is reported as missing, never quietly omitted.
    """
    try:
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if needle in line:
                return (f"{path.name}:{number}", label)
    except OSError as exc:
        return (f"<could not read {path}: {exc}>", label)
    return (f"<{needle!r} NOT FOUND in {path}>", label)


def mechanism() -> list[tuple[str, str]]:
    sdk = Path(mcp_stdio.__file__)
    sub = Path(subprocess.__file__)
    return [
        cite(sdk, "def _get_executable_command", "POSIX branch returns the command UNCHANGED (no shutil.which)"),
        cite(sdk, "start_new_session=True", "anyio.open_process([command, *args]) — list form, so exec, never a shell"),
        cite(sdk, '"HOME", "LOGNAME", "PATH", "SHELL", "TERM", "USER"', "the six-key env scrub the child inherits"),
        cite(sdk, "env=get_default_environment() | (server.env or {})", "an explicit env= is merged OVER the scrub"),
        cite(sub, "and not start_new_session", "disqualifies the posix_spawn fast path -> always _fork_exec"),
        cite(sub, "executable_list = (executable,)", "a command containing '/' -> NO PATH search at all"),
        cite(sub, "This matches the behavior of os._execvpe()", "otherwise: os.get_exec_path(env), i.e. execvp semantics"),
    ]


def header(setup: Setup, legs: list[Leg]) -> None:
    say("Agent-Chokepoint — acceptance artifact: D-020, command resolution is PINNED")
    say("=" * 78)
    say()
    say("D-020: the Helm chart must pin command resolution — absolute paths, or a fixed")
    say(" PATH the agent cannot influence — and the config-scan artifact must record")
    say(" that it does, stating the pinning mechanism explicitly and SHOWING it rather")
    say(" than asserting it.")
    say()
    say(f"  date:        {datetime.now().astimezone().isoformat(timespec='seconds')}")
    say(f"  python:      {sys.version.split()[0]}  ({sys.executable})")
    say(f"  repo root:   {setup.repo_root}")
    say(f"  interpreter: {setup.interpreter}  (the spelling leg 1 uses; os.path.isabs -> "
        f"{'ABSOLUTE' if os.path.isabs(setup.interpreter) else 'RELATIVE, i.e. cwd-dependent and NOT pinned'})")
    say(f"  policy:      {setup.policy}  (the committed file, unmodified)")
    say(f"  run dir:     {setup.run_dir}")
    say()
    say("  this transcript was generated by:")
    say(f"    {sys.executable} {' '.join(sys.argv)}")
    say()
    say("MECHANISM — every citation below resolved against the source this run imported,")
    say("not copied from a note. A line that could not be found says so.")
    cites = mechanism()
    where = max(len(w) for w, _label in cites)
    for w, label in cites:
        say(f"  {w:<{where}}  {label}")
    say()
    say("GROUND TRUTH, per claim — each written by a different program than this one:")
    say("  - \"did the shim run\"      : the marker file THE SHIM wrote, counted before and")
    say(f"                              after each leg. {setup.marker}")
    say("  - \"did the call reach it\" : EXECUTED.log, appended by")
    say(f"                              proxy/demo/upstream_server.py. {setup.sandbox}/EXECUTED.log")
    say("  - \"was it judged\"         : the proxy's own decision events.")
    say(f"                              {setup.decisions}")
    say("  Nothing here is this harness's account of the request it sent.")
    say()
    say("THE ONE VARIABLE — identical in both legs:")
    say(f"  PATH   {setup.path}")
    say(f"  shim   {setup.shim}  (mode 0o755, sha256[:16] printed in the VERDICT block)")
    say(f"  policy {setup.policy}")
    say(f"  call   {CALL_TOOL} {compact(CALL_ARGS)}")
    say("  shim source (identical file, used by both legs):")
    for line in setup.shim.read_text(encoding="utf-8").splitlines():
        say(f"    | {line}")
    say()
    say("  differing in exactly one token — argv[0] of the upstream command:")
    for leg in legs:
        say(f"    leg {leg.number}  guard {leg.guard:<3}  argv[0] = {leg.argv0}")
        say(f"             expects: shim ran = {leg.expect_shim_ran}, reached the tool = {leg.expect_reach}")
        say(f"             why: {leg.why}")
    say()
    say("NOTE: the upstream RECORDS every call instead of executing it — the observable is")
    say("      reach, and proving it with a real command would be reckless. The shim is the")
    say("      same shape of substitution: it records an interposition instead of being one.")
    say()


# ------------------------------------------------------------------------------- run


async def run_all(setup: Setup) -> Results:
    lines.clear()
    results = Results()

    legs = [
        Leg(
            number=1,
            guard="ON",
            argv0=setup.interpreter,
            expect_shim_ran=False,
            expect_reach=1,
            why="the command contains '/', so executable_list = (executable,) and the PATH "
                "search never happens — the shim sitting first on PATH is never consulted",
        ),
        Leg(
            number=2,
            guard="OFF",
            argv0=SHIM_NAME,
            expect_shim_ran=True,
            expect_reach=1,
            why="the command has no '/', so the list comes from os.get_exec_path(env) and "
                "the search hits the shim directory first — execvp semantics, unpinned",
        ),
    ]

    header(setup, legs)
    results.shim_sha_before = sha256(setup.shim)

    for leg in legs:
        rule(f"LEG {leg.number} — guard {leg.guard}: upstream spelled `{leg.argv0}`")
        say()
        result = await run_leg(setup, leg)
        results.legs.append(result)

        say("  the process this leg spawned (the proxy; it then execs the upstream):")
        say(f"    {' '.join(shlex.quote(part) for part in result.spawn)}")
        say(f"  upstream command the proxy execs: {' '.join(shlex.quote(p) for p in result.upstream)}")
        say("  PATH handed to the proxy (and, after the six-key scrub, to the exec search):")
        say(f"    {result.path}")
        say(f"  os.path.dirname(argv[0]) = {os.path.dirname(leg.argv0)!r}  "
            f"-> {'no PATH search (pinned)' if os.path.dirname(leg.argv0) else 'PATH search (unpinned)'}")
        say()
        if result.error:
            say(f"  LEG ERROR — {result.error}")
            say()
            continue
        say(f"  client saw: {result.outcome}")
        say(f"  proxy decision event(s) this leg: {result.verdicts or '<none>'}")
        say()
        say(f"  marker file (written by the SHIM): {result.marker_before} -> {result.marker_after} line(s)"
            f"; exists on disk = {result.marker_exists_after}")
        marker_body = setup.marker.read_text(encoding="utf-8").splitlines() if setup.marker.is_file() else []
        for line in marker_body:
            say(f"    | {line}")
        if not marker_body:
            say("    | <no marker file — nothing looked the shim up>")
        say(f"  SHIM RAN THIS LEG: {result.shim_text}   (expected {leg.expect_shim_ran})")
        say()
        say(f"  upstream EXECUTED.log: {result.reach_before} -> {result.reach_after} line(s); "
            f"this leg added {result.reached}")
        for line in executed(setup.sandbox)[result.reach_before:result.reach_after]:
            say(f"    | {line}")
        if result.reached <= 0:
            say("    | <nothing reached the tool in this leg>")
        say()

    results.shim_sha_after = sha256(setup.shim)

    rule("VERDICT")
    say()
    say("  Every property this transcript asserts, each able to fail the run on its own.")
    say("  An unmeasured leg fails: `shim_ran` is None until both marker snapshots exist,")
    say("  so it satisfies neither expectation and can never read as \"the shim did not run\".")
    say()
    width = max(len(name) for name, _passed, _detail in results.checks)
    for name, passed, detail in results.checks:
        say(f"  {'PASS' if passed else 'FAIL'}  {name:<{width}}  {detail}")
    say()
    if results.ok:
        say("  PASS — command resolution is PINNED, and the control proves the probe was live:")
        say("         the same shim, first on the same PATH, in the same pod, was consulted")
        say("         when argv[0] was spelled bare and NOT consulted when it was spelled")
        say("         absolutely. One variable, both controls, and both legs still reached")
        say("         the tool — so the pin is not availability loss wearing a security hat.")
    else:
        say("  FAIL — read the FAIL line(s). A broken shim, an unmeasured leg, a leg that")
        say("         did not reach the tool and a second variable creeping into the")
        say("         comparison are four different findings, and this block names which.")
        say("         In particular: if the two legs agree, nothing was demonstrated — a")
        say("         guard-ON leg with a dead control is exactly the \"nothing bad")
        say("         happened\" result this project rejects.")
    return results


async def main_async(repo_root: Path, interpreter: str, workdir: Path | None, out: Path | None) -> None:
    if workdir is not None:
        results = await run_all(build_setup(repo_root, interpreter, workdir))
    else:
        with tempfile.TemporaryDirectory(prefix="chokepoint-path-pinning-") as tmp:
            results = await run_all(build_setup(repo_root, interpreter, Path(tmp)))
    if out is not None:
        out.write_text("\n".join(lines) + "\n", encoding="utf-8")
        print(f"\n[transcript written to {out}]", flush=True)
    if not results.ok:
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="D-020 acceptance artifact: command resolution is pinned, shown with both controls."
    )
    parser.add_argument("--repo-root", type=Path, default=DEFAULT_REPO_ROOT,
                        help="application root holding policy/ and proxy/ (default: derived from __file__; /app in the image)")
    parser.add_argument("--interpreter", default=sys.executable,
                        help="ABSOLUTE interpreter path leg 1 spells out (default: sys.executable)")
    parser.add_argument("--workdir", type=Path, default=None,
                        help="writable directory for the shim, marker and sandbox (default: a temporary directory; /sandbox in the pod)")
    parser.add_argument("--out", type=Path, default=None, help="also write the transcript here")
    args = parser.parse_args()

    # os.path.isabs, NOT `os.path.dirname(...)` truthiness. dirname is subprocess.py's
    # rule for "is a PATH search performed", and it is reported as such throughout this
    # artifact — but it is the wrong ADMISSION test, because a relative path satisfies it.
    # The two refusals below are different defects and say so separately.
    if not os.path.isabs(args.interpreter):
        if os.path.dirname(args.interpreter):
            why = (
                f"the relative path {args.interpreter!r}: it does contain a '/', so "
                "subprocess.py would skip the PATH search and leg 1 would 'pass' — but what "
                "leg 1 pinned to would then be resolved against the process's working "
                "directory, and against a directory the workload may be able to write. The "
                "run would demonstrate only that the string contains a slash, never the "
                "absolute, non-influenceable resolution D-020 requires"
            )
        else:
            why = (
                f"the bare name {args.interpreter!r}: leg 1's whole claim is that a command "
                "containing '/' skips the PATH search (subprocess.py), so a bare name would "
                "make both legs identical"
            )
        parser.error(f"--interpreter must be an absolute path, not {why}")
    for needed in (args.repo_root / "policy" / "policy.example.yaml",
                   args.repo_root / "proxy" / "demo" / "upstream_server.py"):
        if not needed.is_file():
            parser.error(f"--repo-root {args.repo_root} does not hold {needed} — wrong root?")
    if args.workdir is not None and not args.workdir.is_dir():
        parser.error(
            f"--workdir {args.workdir} is not an existing directory: it must be a WRITABLE "
            "one (in the pod, the /sandbox emptyDir — the application root is read-only)"
        )

    anyio.run(main_async, args.repo_root, args.interpreter, args.workdir, args.out)


if __name__ == "__main__":
    main()
