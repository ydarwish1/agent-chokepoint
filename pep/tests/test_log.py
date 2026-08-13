"""Shared decision-log helpers: one implementation, two door policies."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from pep.log import (
    MAX_LOGGED_STRING,
    REDACTION_MARKER,
    TOOL_NAME_REDACTION_MARKER,
    loggable_arguments,
    loggable_tool,
    truncated,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
AKIA = "AKIA" + "A" * 16


def test_importing_pep_still_does_not_import_the_engine():
    """canonicalize stays independent; ``import pep`` must not pull in pep.log."""
    probe = "import pep, sys; print(sorted(m for m in sys.modules if m in {'engine', 'policy', 'pep.log'}))"
    done = subprocess.run(
        [sys.executable, "-c", probe],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
    )
    assert done.returncode == 0, done.stderr
    assert done.stdout.strip() == "[]"


def test_pep_log_does_not_import_the_doors_or_the_loader():
    probe = (
        "import pep.log, sys; print(sorted("
        "m.split('.')[0] for m in sys.modules "
        "if m.split('.')[0] in {'hooks', 'proxy', 'policy'}))"
    )
    done = subprocess.run(
        [sys.executable, "-c", probe],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
    )
    assert done.returncode == 0, done.stderr
    assert done.stdout.strip() == "[]"


def test_proxy_server_does_not_import_hooks():
    """The cycle-break: log helpers live in pep.log, not in the hook module."""
    probe = (
        "import proxy.server, sys; print(sorted("
        "m for m in sys.modules if m == 'hooks' or m.startswith('hooks.')))"
    )
    done = subprocess.run(
        [sys.executable, "-c", probe],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
    )
    assert done.returncode == 0, done.stderr
    assert done.stdout.strip() == "[]"


def test_credential_in_arguments_redacts_before_any_truncate():
    command = "echo " + "x" * (MAX_LOGGED_STRING + 1) + " " + AKIA
    assert command.index(AKIA) > MAX_LOGGED_STRING
    assert loggable_arguments({"command": command}, (), truncate=True) == REDACTION_MARKER
    assert loggable_arguments({"command": command}, (), truncate=False) == REDACTION_MARKER


def test_truncate_flag_is_the_documented_door_split():
    note = "n" * (MAX_LOGGED_STRING + 1)
    hooked = loggable_arguments({"note": note}, (), truncate=True)
    proxied = loggable_arguments({"note": note}, (), truncate=False)
    assert hooked == {"note": f"<str len={len(note)} truncated>"}
    assert proxied == {"note": note}


def test_tool_name_length_cap_is_opt_in():
    long_name = "echo_note_" + "x" * (MAX_LOGGED_STRING + 1)
    assert loggable_tool(long_name, ()) == long_name
    capped = loggable_tool(long_name, (), max_len=MAX_LOGGED_STRING)
    assert capped == truncated(long_name)
    assert AKIA not in capped


def test_tool_name_credential_suffix_redacts():
    name = f"read_file_{AKIA}"
    assert loggable_tool(name, ()) == TOOL_NAME_REDACTION_MARKER
