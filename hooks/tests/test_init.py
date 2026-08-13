"""chokepoint-init: wiring only, deny-by-default preserved."""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

from engine import ToolCall, Verdict, decide
from hooks.init import (
    PLACEHOLDER,
    InitError,
    fill_pack,
    hook_command,
    merge_settings,
    resolve_project,
    run,
    settings_fragment,
)
from policy import load_policy

REPO_ROOT = Path(__file__).resolve().parents[2]
PACK = REPO_ROOT / "policy" / "packs" / "coding-agent.yaml"
EXAMPLE = REPO_ROOT / "policy" / "policy.example.yaml"


def test_pack_is_the_example_with_a_path_placeholder(tmp_path: Path):
    """A drift generator: the pack's rules must stay the live example's rules."""
    filled = fill_pack(PACK.read_text(encoding="utf-8"), Path("/workspace"))
    derived = tmp_path / "filled.yaml"
    derived.write_text(filled, encoding="utf-8")
    assert load_policy(derived) == load_policy(EXAMPLE)


def test_the_pack_itself_loads_with_the_placeholder():
    """The placeholder is an absolute prefix, so the file lints as it stands."""
    policy = load_policy(PACK)
    assert policy.defaults.on_no_match is Verdict.BLOCK
    assert policy.defaults.decision is Verdict.BLOCK
    assert any(PLACEHOLDER in prefix for rule in policy.rules for spec in [rule.when.get("path_within") or ()] for prefix in spec)


def test_relative_project_resolves_against_cwd(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    project = tmp_path / "app"
    project.mkdir()
    monkeypatch.chdir(tmp_path)
    assert resolve_project("app") == project.resolve()


def test_missing_project_is_refused(tmp_path: Path):
    with pytest.raises(InitError, match="not an existing directory"):
        resolve_project(str(tmp_path / "nope"))


def test_root_filesystem_as_project_is_refused():
    with pytest.raises(InitError, match="whole filesystem"):
        resolve_project("/")


def _run_init(tmp_path: Path, project: Path, extra: list[str] | None = None) -> tuple[int, str]:
    policy_out = tmp_path / "chokepoint-policy.yaml"
    log_file = tmp_path / "chokepoint-decisions.jsonl"
    argv = [
        "--project",
        str(project),
        "--policy-out",
        str(policy_out),
        "--log-file",
        str(log_file),
        *(extra or ()),
    ]
    return run(argv)


def test_init_writes_a_policy_that_allows_the_project_and_denies_the_rest(tmp_path: Path):
    project = tmp_path / "app"
    project.mkdir()
    (project / "main.py").write_text("x\n", encoding="utf-8")
    code, out = _run_init(tmp_path, project)
    assert code == 0, out
    policy_out = tmp_path / "chokepoint-policy.yaml"
    assert policy_out.is_file()
    assert PLACEHOLDER not in policy_out.read_text(encoding="utf-8")
    policy = load_policy(policy_out)
    assert policy.defaults.on_no_match is Verdict.BLOCK
    allowed = decide(
        policy,
        ToolCall(tool="read_file", arguments={"path": str(project / "main.py")}),
    )
    denied = decide(
        policy,
        ToolCall(tool="read_file", arguments={"path": "/etc/shadow"}),
    )
    assert allowed.verdict is Verdict.ALLOW
    assert allowed.rule_id == "fs-read-scoped"
    assert denied.verdict is Verdict.BLOCK
    assert denied.rule_id == "default:on_no_match"


def test_init_refuses_a_policy_inside_the_allow_prefix(tmp_path: Path):
    project = tmp_path / "app"
    project.mkdir()
    code, err = run(
        [
            "--project",
            str(project),
            "--policy-out",
            str(project / "policy.yaml"),
            "--log-file",
            str(tmp_path / "decisions.jsonl"),
        ]
    )
    assert code == 2
    assert "inside the allow prefix" in err


def test_init_refuses_a_log_inside_the_allow_prefix(tmp_path: Path):
    project = tmp_path / "app"
    project.mkdir()
    code, err = run(
        [
            "--project",
            str(project),
            "--policy-out",
            str(tmp_path / "policy.yaml"),
            "--log-file",
            str(project / "decisions.jsonl"),
        ]
    )
    assert code == 2
    assert "inside the allow prefix" in err


def test_settings_fragment_uses_absolute_paths_and_both_matchers(tmp_path: Path):
    project = tmp_path / "app"
    project.mkdir()
    policy = tmp_path / "policy.yaml"
    log = tmp_path / "log.jsonl"
    fragment = settings_fragment(policy, log)
    groups = fragment["hooks"]["PreToolUse"]
    matchers = {g["matcher"] for g in groups}
    assert "mcp__.*" in matchers
    assert "^(Read|Write|Edit|NotebookEdit|Bash|WebFetch)$" in matchers
    commands = {entry["command"] for g in groups for entry in g["hooks"]}
    assert len(commands) == 1
    command = next(iter(commands))
    argv = shlex.split(command)
    assert str(policy) in argv
    assert str(log) in argv
    assert not command.startswith("python")
    # Either the console script or this interpreter + the hook file.
    assert os.path.isabs(argv[0])


def test_hook_command_never_constructs_a_venv_path():
    command = hook_command(Path("/tmp/p.yaml"), Path("/tmp/l.jsonl"))
    assert ".venv" not in command


def test_hook_command_does_not_follow_the_venv_symlink_to_system_python():
    """A venv ``python`` resolves to ``/usr/bin/python3.x``. Wiring that
    interpreter drops PyYAML and the hook exits 2 on every call."""
    command = hook_command(Path("/tmp/p.yaml"), Path("/tmp/l.jsonl"))
    argv = shlex.split(command)
    sibling = Path(sys.executable).parent / "chokepoint-hook"
    if sibling.is_file() and os.access(sibling, os.X_OK):
        assert argv[0] == str(sibling)
    else:
        assert argv[0] == sys.executable
        assert argv[1].endswith("chokepoint_hook.py")
    resolved = str(Path(sys.executable).resolve())
    if resolved != sys.executable:
        assert argv[0] != resolved


def test_hook_command_quotes_paths_with_spaces(tmp_path: Path):
    policy = tmp_path / "my policy.yaml"
    log = tmp_path / "the log.jsonl"
    command = hook_command(policy, log)
    argv = shlex.split(command)
    assert str(policy) in argv
    assert str(log) in argv
    assert "--policy" in argv
    assert "--log-file" in argv


def test_project_path_with_a_newline_is_refused(tmp_path: Path):
    project = tmp_path / "app\nname"
    project.mkdir()
    with pytest.raises(InitError, match="cannot be written"):
        resolve_project(str(project))


def test_project_path_with_spaces_writes_a_loadable_policy(tmp_path: Path):
    project = tmp_path / "my app"
    project.mkdir()
    (project / "main.py").write_text("x\n", encoding="utf-8")
    code, out = _run_init(tmp_path, project)
    assert code == 0, out
    policy = load_policy(tmp_path / "chokepoint-policy.yaml")
    allowed = decide(
        policy,
        ToolCall(tool="read_file", arguments={"path": str(project / "main.py")}),
    )
    assert allowed.verdict is Verdict.ALLOW
    assert allowed.rule_id == "fs-read-scoped"


def test_default_outputs_inside_home_are_refused_when_project_is_home(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """The documented defaults live in $HOME; --project $HOME would put them
    inside the allow prefix (B-088). Init must refuse rather than write them."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    code, err = run(["--project", str(home)])
    assert code == 2
    assert "inside the allow prefix" in err


def test_merge_keeps_unrelated_hooks():
    existing = {
        "permissions": {"allow": ["Bash(pwd)"]},
        "hooks": {
            "PreToolUse": [
                {"matcher": "Other", "hooks": [{"type": "command", "command": "true"}]},
            ]
        },
    }
    fragment = {
        "hooks": {
            "PreToolUse": [
                {"matcher": "mcp__.*", "hooks": [{"type": "command", "command": "chokepoint"}]},
            ]
        }
    }
    merged = merge_settings(existing, fragment)
    assert merged["permissions"] == existing["permissions"]
    matchers = [g["matcher"] for g in merged["hooks"]["PreToolUse"]]
    assert matchers == ["Other", "mcp__.*"]


def test_install_settings_merges_into_an_existing_file(tmp_path: Path):
    project = tmp_path / "app"
    project.mkdir()
    dest = tmp_path / "settings.json"
    dest.write_text(json.dumps({"env": {"FOO": "1"}}), encoding="utf-8")
    code, out = _run_init(tmp_path, project, extra=["--install-settings", str(dest)])
    assert code == 0, out
    written = json.loads(dest.read_text(encoding="utf-8"))
    assert written["env"] == {"FOO": "1"}
    assert written["hooks"]["PreToolUse"]


def test_install_settings_refuses_broken_json(tmp_path: Path):
    project = tmp_path / "app"
    project.mkdir()
    dest = tmp_path / "settings.json"
    dest.write_text("{not json", encoding="utf-8")
    code, err = _run_init(tmp_path, project, extra=["--install-settings", str(dest)])
    assert code == 2
    assert "not JSON" in err


def test_subprocess_entrypoint_shape(tmp_path: Path):
    """Drive the module the way a console script will: a real process, real files."""
    project = tmp_path / "app"
    project.mkdir()
    done = subprocess.run(
        [
            sys.executable,
            "-m",
            "hooks.init",
            "--project",
            str(project),
            "--policy-out",
            str(tmp_path / "p.yaml"),
            "--log-file",
            str(tmp_path / "l.jsonl"),
            "--settings-out",
            str(tmp_path / "settings.json"),
        ],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
    )
    assert done.returncode == 0, done.stderr
    assert "wrote policy" in done.stdout
    settings = json.loads((tmp_path / "settings.json").read_text(encoding="utf-8"))
    assert settings["hooks"]["PreToolUse"]
