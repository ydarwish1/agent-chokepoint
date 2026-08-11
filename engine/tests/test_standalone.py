"""Two engine guarantees: "importable standalone" and "no I/O, no network".

Both are checked mechanically in a fresh interpreter rather than asserted in
prose. The engine is what the proxy and the Claude Code hook share; the day it
grows a dependency on either, the split stops being real.

Purity is checked by RUNNING ``decide()`` and watching what it touches (B-024).
The source grep below is kept as a cheap first line, but it is a lint, not the
guard: measured, the B-024 mutation — ``import time as _t, os as _o;
_t.time(); _o.path.exists('/etc/hosts')`` in ``decide()``'s body — leaves every
source-level test in this file green, because a lazy import inside a function
body has no import line to grep and no banned token on the call.
"""

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

# Snapshot sys.modules first, then diff: this attributes each module to the
# engine import itself, rather than to interpreter startup (site, sitecustomize,
# and friends are already loaded before any of our code runs).
PROBE = """
import sys
before = set(sys.modules)
import engine
added = set(sys.modules) - before

third_party = sorted(
    name for name in added
    if not name.startswith("_")
    and name.split(".")[0] not in sys.stdlib_module_names
    and name.split(".")[0] != "engine"
)
print("THIRD_PARTY:" + ",".join(third_party))
print("DECIDES:" + str(engine.decide(
    engine.Policy(
        version=0,
        defaults=engine.Defaults(),
        limits=engine.Limits(),
        rules=(),
    ),
    engine.ToolCall(tool="anything"),
).verdict))
"""


# The purity probe. Two instruments, because neither one alone covers the three
# things B-024 names — filesystem I/O, a clock read, and a lazy third-party
# import.
#
#   Leg 1, sentinels over the primitives. Measured on CPython 3.14.6: a clock
#   read raises NO audit event at all, and neither does os.stat(). An audit
#   hook is structurally blind to both. Wrapping the module attribute is not,
#   and it sees through the evasion that defeats the source grep: `import time
#   as _t` inside a function body binds the SAME module object out of
#   sys.modules, so `_t.time()` still goes through the wrapper.
#
#   Leg 2, sys.addaudithook. It sees what the sentinels cannot: the stdlib's
#   own C-level work (importlib reads the disk through the frozen posix module,
#   not through the `os` object patched in leg 1 — measured, a lazy `import
#   yaml` inside decide() reports audit events exec/import/marshal.loads/open/
#   os.listdir while the sentinels report nothing), and any route to open,
#   socket or subprocess that a hand-written list of primitives never named.
#
# The hook cannot be removed once added and fires for the whole interpreter,
# pytest's own I/O included, so this runs in a subprocess whose only job is to
# arm it and call decide(). Everything the probe needs — the engine, the
# policy, the calls, the modules it instruments — is imported and built BEFORE
# the sentinels go in and the hook is armed, and `armed` goes False the instant
# decide() returns, so the measurement is about decide() and nothing else.
PURITY_PROBE = """
import sys

import builtins, os, socket, time
import engine

POLICY = engine.Policy(
    version=0,
    defaults=engine.Defaults(),
    limits=engine.Limits(max_tool_calls_per_run=50, max_wall_clock_seconds=300,
                         max_repeated_identical_calls=5),
    rules=(
        engine.Rule(
            id='fs-read-scoped', owasp='LLM01', tool='read_file',
            decision=engine.Verdict.ALLOW,
            when={'path_within': ('/workspace/',), 'path_not_within': ('/workspace/.ssh/',)},
        ),
        engine.Rule(
            id='net-fetch-allowlist', owasp='LLM02', tool='fetch_url',
            decision=engine.Verdict.ALLOW, when={'domain_in': ('docs.python.org',)},
        ),
        engine.Rule(
            id='net-egress-sensitive', owasp='LLM02', tool='fetch_url',
            decision=engine.Verdict.BLOCK,
            when={'args_match_any': ('secret_like', 'private_key_block')},
        ),
        engine.Rule(
            id='shell-destructive', owasp='LLM01', tool='run_command',
            decision=engine.Verdict.BLOCK,
            when={'command_matches_any': (r'rm\\s+-rf',)},
        ),
    ),
)

# Every predicate in the vocabulary, both verdicts, the limits path and the
# None-arguments envelope: a probe that exercised one trivial call could report
# a clean engine while the impure branch never ran.
CALLS = (
    engine.ToolCall(tool='read_file', arguments={'path': '/workspace/README.md'}),
    engine.ToolCall(tool='read_file', arguments={'path': '/workspace/.ssh/id_rsa'}),
    engine.ToolCall(tool='fetch_url', arguments={'url': 'https://docs.python.org/3/'}),
    engine.ToolCall(tool='fetch_url',
                    arguments={'url': 'https://docs.python.org/?k=AKIA' + 'A' * 16}),
    engine.ToolCall(tool='run_command', arguments={'command': 'rm -rf /'}),
    engine.ToolCall(tool='read_file', arguments=None),
    engine.ToolCall(tool='unknown_tool', arguments={'nested': {'a': ['b', {'c': 'd'}]}},
                    run_state=engine.RunState(calls_made=1, elapsed_seconds=0.5,
                                              identical_calls=1)),
)

armed = False
impure = []
events = []


def _sentinel(label, real):
    def wrapper(*a, **k):
        if armed:
            impure.append(label)
        return real(*a, **k)
    return wrapper


WRAPPED = (
    (time, 'time'), (time, 'time_ns'), (time, 'monotonic'), (time, 'monotonic_ns'),
    (time, 'perf_counter'), (time, 'sleep'), (time, 'localtime'),
    (os, 'stat'), (os, 'lstat'), (os, 'listdir'), (os, 'scandir'),
    (os, 'getcwd'), (os, 'urandom'), (os, 'getenv'),
    (builtins, 'open'), (socket, 'socket'),
)
for _mod, _name in WRAPPED:
    setattr(_mod, _name, _sentinel(_mod.__name__ + '.' + _name, getattr(_mod, _name)))


def _hook(event, args):
    if armed:
        events.append(event)


sys.addaudithook(_hook)

armed = True
verdicts = [engine.decide(POLICY, c).verdict.value for c in CALLS]
armed = False

print('VERDICTS:' + ','.join(verdicts))
print('IMPURE:' + ','.join(sorted(set(impure))))
print('AUDIT:' + ','.join(sorted(set(events))))
"""

# One per call in the probe, in order: inside the allow prefix; inside the deny
# prefix; allowlisted host; allowlisted host carrying a secret (block wins on
# precedence); destructive command; no arguments; unknown tool, already over
# its identical-call limit.
EXPECTED_VERDICTS = "allow,block,allow,block,block,block,block"


def run_probe() -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-c", PROBE],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=60,
    )


def run_purity_probe() -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-c", PURITY_PROBE],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=60,
    )


def test_engine_imports_with_no_third_party_dependencies():
    proc = run_probe()
    assert proc.returncode == 0, proc.stderr
    line = next(l for l in proc.stdout.splitlines() if l.startswith("THIRD_PARTY:"))
    imported = [name for name in line.removeprefix("THIRD_PARTY:").split(",") if name]
    # mcp, pydantic and yaml are the dependencies the enforcement points and the
    # policy loader carry. None of them may reach the engine.
    assert imported == [], f"engine pulled in non-stdlib modules: {imported}"


def test_engine_decides_without_the_rest_of_the_project():
    proc = run_probe()
    assert "DECIDES:block" in proc.stdout, proc.stdout


def test_decide_reads_no_clock_and_touches_no_file_socket_or_lazy_import():
    """B-024 — purity asserted on BEHAVIOUR, by running decide() instrumented.

    What this catches: any call to the wrapped clock, filesystem and socket
    primitives, including through a lazy re-import of an already-loaded module;
    and any audit event at all, which covers open, socket, subprocess, and the
    disk reads a lazy third-party import performs.

    What it does NOT catch, named rather than implied away: a clock read that
    bypasses the `time` module at the C level (``datetime.datetime.now()``
    reads the system clock without going through any patchable attribute), and
    a read of ``os.environ`` as a mapping, which is an ordinary dict lookup.
    Both are impurities this probe would report clean on.

    The AUDIT assertion is "no events at all" rather than a list of banned
    names: measured, a clean decide() over these seven calls raises zero audit
    events on CPython 3.11, 3.12 and 3.14. CI's other leg is 3.10, which was
    not available locally to measure; if a future or older interpreter raises a
    benign event during pure computation, this test names it in the failure.
    """
    proc = run_purity_probe()
    assert proc.returncode == 0, proc.stderr
    out = dict(
        line.split(":", 1) for line in proc.stdout.splitlines() if ":" in line
    )
    # The control first. Without it, a probe that decided nothing — an engine
    # that failed to judge at all — would report perfectly clean.
    assert out.get("VERDICTS") == EXPECTED_VERDICTS, proc.stdout
    assert out.get("IMPURE") == "", f"decide() called impure primitives: {out.get('IMPURE')}"
    assert out.get("AUDIT") == "", f"decide() raised audit events: {out.get('AUDIT')}"


def test_engine_source_contains_no_io_calls():
    """A crude source lint, kept as a cheap first line and no more than that.

    It catches an I/O call written plainly at module scope. It does not catch
    the B-024 mutation, and cannot: a lazy import inside a function body has no
    import line to grep and no banned token on the call. The real guard is
    ``test_decide_reads_no_clock_and_touches_no_file_socket_or_lazy_import``
    above; if this lint ever has to be weakened to let a change through, that
    is a finding about the change.
    """
    banned = ("open(", "socket", "subprocess", "requests", "urlopen", "Path(")
    offenders = []
    for path in sorted((REPO_ROOT / "engine").glob("*.py")):
        source = path.read_text(encoding="utf-8")
        # Strip the module docstring's prose; only code lines matter here.
        for lineno, text in enumerate(source.splitlines(), 1):
            stripped = text.strip()
            if stripped.startswith("#") or stripped.startswith('"'):
                continue
            for token in banned:
                if token in text:
                    offenders.append(f"{path.name}:{lineno}: {stripped}")
    assert offenders == [], f"engine appears to do I/O: {offenders}"
