"""Write a deny-by-default coding-agent policy and Claude Code hook settings.

Does not widen the engine. It fills absolute paths into the shipped starter
pack and a settings fragment. ``defaults.on_no_match`` stays block.

    chokepoint-init --project /absolute/path/to/the/repo

Relative ``--project`` is resolved against this process's cwd (init has one;
the engine does not). The decision log and the written policy must sit
*outside* the allow prefix so the agent cannot rewrite the control (B-088).
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

PLACEHOLDER = "/ABSOLUTE/PATH/TO/PROJECT"
PACK_RELATIVE = Path("policy") / "packs" / "coding-agent.yaml"
SETTINGS_EXAMPLE = Path(__file__).resolve().parent / "settings.example.json"
HOOK_SCRIPT = Path(__file__).resolve().parent / "chokepoint_hook.py"
REPO_ROOT = Path(__file__).resolve().parent.parent


class InitError(ValueError):
    """An init request this tool refuses rather than guessing at."""


def _pack_text() -> str:
    """The starter pack, from the installed package or the source tree."""
    try:
        from importlib.resources import files

        return (files("policy") / "packs" / "coding-agent.yaml").read_text(encoding="utf-8")
    except (FileNotFoundError, ModuleNotFoundError, OSError):
        fallback = REPO_ROOT / PACK_RELATIVE
        return fallback.read_text(encoding="utf-8")


def resolve_project(raw: str) -> Path:
    """Absolute existing directory, or :class:`InitError`."""
    path = Path(raw).expanduser()
    if not path.is_absolute():
        path = Path.cwd() / path
    path = path.resolve()
    if path == Path("/"):
        raise InitError("refusing project '/': that allow-prefix is the whole filesystem")
    if not path.is_dir():
        raise InitError(f"project {path} is not an existing directory")
    # The pack interpolates this path into double-quoted YAML and the settings
    # command line. Newlines / quotes / backslashes are legal Unix names and
    # would break one of those two, so refuse rather than emit a file that
    # does not mean what the operator typed.
    if any(ch in str(path) for ch in ('"', "\\", "\n", "\r", "\0")):
        raise InitError(
            f"project {path} contains a character that cannot be written into "
            "the policy YAML or the hook command"
        )
    return path


def _is_inside(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def fill_pack(text: str, project: Path) -> str:
    if PLACEHOLDER not in text:
        raise InitError(f"starter pack does not contain {PLACEHOLDER}")
    # No trailing slash on the substitution: the pack writes `{placeholder}/`.
    return text.replace(PLACEHOLDER, str(project))


def hook_command(policy: Path, log_file: Path) -> str:
    """Absolute command line for Claude Code settings.

    Prefers the ``chokepoint-hook`` console script next to this interpreter.
    Falls back to ``{sys.executable} hooks/chokepoint_hook.py`` so a tree
    without entry points still wires. Never guesses ``.venv/bin/python``.

    Do not ``Path.resolve()`` the interpreter: a venv's ``python`` is a
    symlink to the system binary, and the console script lives next to the
    symlink, not next to ``/usr/bin/python3``.
    """
    python = Path(sys.executable)
    entry = python.parent / "chokepoint-hook"
    if entry.is_file() and os.access(entry, os.X_OK):
        argv = [str(entry)]
    else:
        argv = [str(python), str(HOOK_SCRIPT)]
    argv.extend(["--policy", str(policy), "--log-file", str(log_file)])
    return " ".join(shlex.quote(part) for part in argv)


def settings_fragment(policy: Path, log_file: Path) -> dict[str, Any]:
    """``hooks/settings.example.json`` with the command filled in both matchers."""
    raw = json.loads(SETTINGS_EXAMPLE.read_text(encoding="utf-8"))
    command = hook_command(policy, log_file)
    for group in raw["hooks"]["PreToolUse"]:
        for entry in group["hooks"]:
            entry["command"] = command
    return raw


def merge_settings(existing: Mapping[str, Any], fragment: Mapping[str, Any]) -> dict[str, Any]:
    """Keep unrelated settings; upsert PreToolUse groups by matcher."""
    merged = json.loads(json.dumps(existing))  # deep copy via JSON (settings are JSON)
    hooks = merged.setdefault("hooks", {})
    incoming = fragment["hooks"]["PreToolUse"]
    current = list(hooks.get("PreToolUse") or [])
    by_matcher = {group.get("matcher"): group for group in incoming}
    kept: list[Any] = []
    seen: set[Any] = set()
    for group in current:
        matcher = group.get("matcher")
        if matcher in by_matcher:
            kept.append(by_matcher[matcher])
            seen.add(matcher)
        else:
            kept.append(group)
    for matcher, group in by_matcher.items():
        if matcher not in seen:
            kept.append(group)
    hooks["PreToolUse"] = kept
    return merged


def _parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="chokepoint-init",
        description=(
            "Write a deny-by-default coding-agent policy and Claude Code hook "
            "settings with absolute paths."
        ),
    )
    parser.add_argument(
        "--project",
        required=True,
        help="directory the agent may read (and write, as ask). Resolved to an absolute path.",
    )
    parser.add_argument(
        "--policy-out",
        default=None,
        help="where to write the filled policy (default: ~/chokepoint-policy.yaml)",
    )
    parser.add_argument(
        "--log-file",
        default=None,
        help="decision log path stamped into settings (default: ~/chokepoint-decisions.jsonl)",
    )
    parser.add_argument(
        "--settings-out",
        default=None,
        help="write a settings fragment here (does not merge into Claude Code)",
    )
    parser.add_argument(
        "--install-settings",
        default=None,
        help="merge PreToolUse hook groups into this Claude Code settings.json",
    )
    return parser.parse_args(list(argv))


def run(argv: Sequence[str]) -> tuple[int, str]:
    """Returns ``(exit code, stdout text)``. Exit 2 is a refused init, not a crash."""
    args = _parse_args(argv)
    try:
        project = resolve_project(args.project)
        policy_out = Path(args.policy_out).expanduser() if args.policy_out else Path.home() / "chokepoint-policy.yaml"
        log_file = Path(args.log_file).expanduser() if args.log_file else Path.home() / "chokepoint-decisions.jsonl"
        policy_out = policy_out if policy_out.is_absolute() else (Path.cwd() / policy_out).resolve()
        log_file = log_file if log_file.is_absolute() else (Path.cwd() / log_file).resolve()
        if _is_inside(policy_out, project):
            raise InitError(
                f"policy-out {policy_out} sits inside the allow prefix {project}; "
                "the agent could rewrite it. Pass --policy-out outside that directory."
            )
        if _is_inside(log_file, project):
            raise InitError(
                f"log-file {log_file} sits inside the allow prefix {project}; "
                "the agent could read or rewrite it. Pass --log-file outside that directory."
            )
        filled = fill_pack(_pack_text(), project)
        policy_out.parent.mkdir(parents=True, exist_ok=True)
        policy_out.write_text(filled, encoding="utf-8")
        fragment = settings_fragment(policy_out, log_file)
        notes: list[str] = [
            f"wrote policy {policy_out}",
            f"allow prefix {project}/ (deny-by-default; writes are ask)",
            f"decision log {log_file} (created on the first judged call)",
            f"hook command: {hook_command(policy_out, log_file)}",
        ]
        if args.settings_out:
            settings_path = Path(args.settings_out).expanduser()
            settings_path = settings_path if settings_path.is_absolute() else (Path.cwd() / settings_path).resolve()
            settings_path.parent.mkdir(parents=True, exist_ok=True)
            settings_path.write_text(json.dumps(fragment, indent=2) + "\n", encoding="utf-8")
            notes.append(f"wrote settings fragment {settings_path}")
        if args.install_settings:
            dest = Path(args.install_settings).expanduser()
            dest = dest if dest.is_absolute() else (Path.cwd() / dest).resolve()
            if dest.is_file():
                try:
                    existing = json.loads(dest.read_text(encoding="utf-8"))
                except ValueError as exc:
                    raise InitError(f"settings {dest} is not JSON: {exc}") from exc
                if not isinstance(existing, dict):
                    raise InitError(f"settings {dest} is JSON but not an object")
                merged = merge_settings(existing, fragment)
            else:
                dest.parent.mkdir(parents=True, exist_ok=True)
                merged = fragment
            dest.write_text(json.dumps(merged, indent=2) + "\n", encoding="utf-8")
            notes.append(f"merged hooks into {dest}")
        sample = project / "notes.txt"
        command = hook_command(policy_out, log_file)
        notes.append("")
        notes.append("Verify (expect allow on a file under the project, deny on /etc/shadow):")
        notes.append(
            f"  echo '{{\"tool_name\":\"Read\",\"tool_input\":{{\"file_path\":\"{sample}\"}}}}' | {command}"
        )
        notes.append(
            f"  echo '{{\"tool_name\":\"Read\",\"tool_input\":{{\"file_path\":\"/etc/shadow\"}}}}' | {command}"
        )
        if not args.settings_out and not args.install_settings:
            notes.append("")
            notes.append("Settings fragment (merge into ~/.claude/settings.json or .claude/settings.json):")
            notes.append(json.dumps(fragment, indent=2))
        return 0, "\n".join(notes) + "\n"
    except InitError as exc:
        return 2, f"chokepoint-init: {exc}\n"


def main(argv: Sequence[str] | None = None) -> int:
    code, text = run(sys.argv[1:] if argv is None else argv)
    stream = sys.stdout if code == 0 else sys.stderr
    stream.write(text)
    return code


if __name__ == "__main__":
    sys.exit(main())
