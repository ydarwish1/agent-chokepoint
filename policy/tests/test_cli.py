"""``chokepoint-policy check``: one line per case, exit 0 / 1 / 2.

The shipped coding-agent cases run here against the shipped pack, and every
rule in the pack is held to a case it fires on and a near miss it leaves alone.
The rest is the command refusing a cases file it cannot read honestly — a file
that half-loads would report a pass for cases it never judged.
"""

from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from engine import DEFAULT_RULE_ID, TAINT_EGRESS_RULE_ID, RunState, ToolCall, decide
from pep import canonical_path
from pep.log import HIDDEN_CONTEXT_TOOL_NAME_REDACTION_MARKER, TOOL_NAME_REDACTION_MARKER
from policy import load_policy
from policy.cli import MAX_CASES_BYTES, MAX_CASES_DEPTH, load_cases, main, run

REPO_ROOT = Path(__file__).resolve().parents[2]
PACK = REPO_ROOT / "policy" / "packs" / "coding-agent.yaml"
PACK_CASES = REPO_ROOT / "policy" / "packs" / "coding-agent.cases.yaml"

AKIA = "AKIA" + "A" * 16  # well-formed AWS access key id, fake

ONE_CASE = """\
cases:
  - tool: run_command
    arguments: {command: "rm -rf /"}
    verdict: block
    rule_id: shell-destructive
"""


def _check(policy: Path, cases: Path) -> tuple[int, str]:
    return run(["check", str(policy), str(cases)])


def _cases_file(tmp_path: Path, text: str, name: str = "cases.yaml") -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


# ------------------------------------------------------------ the shipped pack


def test_the_shipped_cases_pass_against_the_shipped_pack():
    code, out = _check(PACK, PACK_CASES)
    lines = out.splitlines()
    total = len(load_cases(PACK_CASES))
    assert code == 0, out
    assert len(lines) == total + 1  # one line per case, then the summary
    assert all(line.startswith("PASS case ") for line in lines[:-1])
    assert lines[-1] == f"{total} of {total} cases match"


@pytest.mark.parametrize("rule", load_policy(PACK).rules, ids=lambda rule: rule.id)
def test_every_pack_rule_has_a_case_it_fires_on_and_a_near_miss(rule):
    """Both directions, measured against the rule alone rather than read off the file.

    A one-rule policy credits ``rule.id`` exactly when that rule matches, so a
    case counts as a near miss only if the rule really does not match it.
    """
    cases = load_cases(PACK_CASES)
    alone = replace(load_policy(PACK), rules=(rule,))
    fires = [case for case in cases if case.rule_id == rule.id]
    near_misses = [
        case
        for case in cases
        if case.call.tool == rule.tool and decide(alone, case.call).rule_id == DEFAULT_RULE_ID
    ]
    assert fires, f"no case expects {rule.id}"
    assert all(decide(alone, case.call).rule_id == rule.id for case in fires)
    assert near_misses, f"no case on {rule.tool} that {rule.id} leaves alone"


def test_the_command_runs_as_a_real_process():
    done = subprocess.run(
        [sys.executable, "-m", "policy.cli", "check", str(PACK), str(PACK_CASES)],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
    )
    assert done.returncode == 0, done.stderr
    assert done.stdout.splitlines()[-1].endswith("cases match")


def test_the_installed_console_script_runs_when_present():
    entry = Path(sys.executable).parent / "chokepoint-policy"
    if not (entry.is_file() and os.access(entry, os.X_OK)):
        pytest.skip("chokepoint-policy is not installed next to this interpreter")
    done = subprocess.run([str(entry), "check", str(PACK), str(PACK_CASES)], capture_output=True, text=True)
    assert done.returncode == 0, done.stderr


# ------------------------------------------------------------- exit 1: mismatch


def test_an_edited_rule_id_fails_and_names_the_case(tmp_path: Path):
    edited = PACK_CASES.read_text(encoding="utf-8").replace(
        "rule_id: shell-destructive", "rule_id: default:on_no_match", 1
    )
    code, out = _check(PACK, _cases_file(tmp_path, edited))
    failures = [line for line in out.splitlines() if line.startswith("FAIL")]
    assert code == 1
    assert len(failures) == 1
    assert failures[0].endswith(
        "run_command -> expected block default:on_no_match, got block shell-destructive"
    )
    total = len(load_cases(PACK_CASES))
    assert out.splitlines()[-1] == f"{total - 1} of {total} cases match"


def test_a_case_claiming_an_allow_the_policy_does_not_give_fails(tmp_path: Path):
    text = ONE_CASE.replace("verdict: block", "verdict: allow")
    code, out = _check(PACK, _cases_file(tmp_path, text))
    assert code == 1
    assert out.splitlines()[0] == (
        "FAIL case 1: run_command -> expected allow shell-destructive, got block shell-destructive"
    )


def test_reordered_cases_get_the_same_decisions(tmp_path: Path):
    head, body = PACK_CASES.read_text(encoding="utf-8").split("cases:\n", 1)
    blocks = body.split("\n\n")
    reordered = _cases_file(tmp_path, head + "cases:\n" + "\n\n".join(reversed(blocks)) + "\n")
    _, original = _check(PACK, PACK_CASES)
    code, out = _check(PACK, reordered)

    def results(text: str) -> list[str]:
        return sorted(line.split(": ", 1)[1] for line in text.splitlines()[:-1])

    assert code == 0, out
    assert results(out) == results(original)


# ------------------------------------------------------- exit 2: did not load


@pytest.mark.parametrize(
    "text, message",
    [
        ("", "must be a YAML mapping"),
        ("cases: []\n", "non-empty list"),
        ("- tool: x\n", "must be a YAML mapping"),
        ("cases:\n  - tool: x\n    verdict: block\n    rule_id: y\npolicy: p.yaml\n", "unknown top-level keys"),
        ("cases:\n  - tool: x\n    verdcit: block\n    rule_id: y\n", "unknown keys"),
        ("cases:\n  - tool: x\n    verdict: block\n", "missing required key 'rule_id'"),
        ("cases:\n  - tool: x\n    verdict: ALLOW\n    rule_id: y\n", "verdict must be one of"),
        ("cases:\n  - tool: x\n    verdict: allow\n    verdict: block\n    rule_id: y\n", "duplicate key"),
        ("cases:\n  - tool: ''\n    verdict: block\n    rule_id: y\n", "tool must be a non-empty string"),
        ("cases:\n  - tool: x\n    arguments: [a]\n    verdict: block\n    rule_id: y\n", "arguments must be a mapping"),
        ("cases:\n  - tool: x\n    server: ''\n    verdict: block\n    rule_id: y\n", "server must be"),
        ("cases:\n  - tool: x\n    server: a__b\n    verdict: block\n    rule_id: y\n", "not a usable MCP server"),
        ("cases:\n  - just a string\n", "must be a mapping"),
        ("cases: [\n", "not valid YAML"),
    ],
    ids=lambda value: value if len(value) < 30 else None,
)
def test_a_cases_file_that_does_not_load_exits_2(tmp_path: Path, text: str, message: str):
    code, err = _check(PACK, _cases_file(tmp_path, text))
    assert code == 2
    assert err.startswith("chokepoint-policy: cases did not load: ")
    assert message in err


def test_invalid_utf8_exits_2(tmp_path: Path):
    path = tmp_path / "cases.yaml"
    path.write_bytes(ONE_CASE.encode("utf-8") + b"# \xff\xfe\n")
    code, err = _check(PACK, path)
    assert code == 2
    assert "UnicodeDecodeError" in err


def test_a_file_over_the_size_cap_exits_2_before_parsing(tmp_path: Path):
    path = _cases_file(tmp_path, ONE_CASE + "#" * MAX_CASES_BYTES + "\n")
    code, err = _check(PACK, path)
    assert code == 2
    assert "larger than" in err


def test_deep_nesting_is_refused_without_parsing_all_of_it(tmp_path: Path):
    """100 000 levels took 164 s to parse in full; the cap stops at level 65."""
    depth = 100_000
    path = _cases_file(tmp_path, "cases: " + "[" * depth + "]" * depth + "\n")
    code, err = _check(PACK, path)
    assert code == 2
    assert f"nested deeper than {MAX_CASES_DEPTH} levels" in err


def _nested_arguments_case(levels: int) -> str:
    """One case whose arguments are ``levels`` mappings deep; the file adds 3 more."""
    nested = "{a: " * levels + "x" + "}" * levels
    return f"cases:\n  - tool: run_command\n    arguments: {nested}\n    verdict: block\n    rule_id: default:on_no_match\n"


def test_nesting_up_to_the_cap_loads_and_one_more_level_does_not(tmp_path: Path):
    at_cap = _cases_file(tmp_path, _nested_arguments_case(MAX_CASES_DEPTH - 3), "at.yaml")
    past_cap = _cases_file(tmp_path, _nested_arguments_case(MAX_CASES_DEPTH - 2), "past.yaml")
    assert _check(PACK, at_cap)[0] == 0
    code, err = _check(PACK, past_cap)
    assert code == 2
    assert "nested deeper than" in err


def test_yaml_aliases_are_refused(tmp_path: Path):
    """A few lines of anchors would otherwise expand into an argument tree the
    engine's scans walk billions of times."""
    bomb = "\n".join(
        [
            "a: &a [x, x, x, x, x, x, x, x, x, x]",
            *(f"{chr(98 + i)}: &{chr(98 + i)} [{', '.join(['*' + chr(97 + i)] * 10)}]" for i in range(8)),
        ]
    )
    text = ONE_CASE.replace('arguments: {command: "rm -rf /"}', "arguments:\n" + _indent(bomb, 6))
    code, err = _check(PACK, _cases_file(tmp_path, text))
    assert code == 2
    assert "aliases" in err


def _indent(text: str, spaces: int) -> str:
    return "\n".join(" " * spaces + line for line in text.splitlines())


def test_a_missing_cases_file_exits_2(tmp_path: Path):
    code, err = _check(PACK, tmp_path / "nope.yaml")
    assert code == 2
    assert "not a regular file" in err


def test_a_directory_as_cases_exits_2(tmp_path: Path):
    code, err = _check(PACK, tmp_path)
    assert code == 2
    assert "not a regular file" in err


def test_an_unreadable_cases_file_exits_2(tmp_path: Path):
    path = _cases_file(tmp_path, ONE_CASE)
    path.chmod(0)
    try:
        if os.access(path, os.R_OK):
            pytest.skip("running with privileges that ignore file modes")
        code, err = _check(PACK, path)
    finally:
        path.chmod(0o644)
    assert code == 2
    assert "PermissionError" in err


def test_a_dangling_symlink_exits_2_and_a_live_one_is_followed(tmp_path: Path):
    dangling = tmp_path / "dangling.yaml"
    dangling.symlink_to(tmp_path / "gone.yaml")
    live = tmp_path / "live.yaml"
    live.symlink_to(_cases_file(tmp_path, ONE_CASE))
    assert _check(PACK, dangling)[0] == 2
    assert _check(PACK, live)[0] == 0


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="no named pipes on this platform")
def test_a_named_pipe_exits_2_instead_of_waiting_for_a_writer(tmp_path: Path):
    fifo = tmp_path / "cases.yaml"
    os.mkfifo(fifo)
    code, err = _check(PACK, fifo)
    assert code == 2
    assert "not a regular file" in err


@pytest.mark.parametrize(
    "policy_text",
    [None, "version: 0\nrules: {}\n", "version: 0\nversion: 0\n", b"version: 0\n# \xff\n"],
    ids=["missing", "invalid", "duplicate-key", "bad-utf8"],
)
def test_a_policy_that_does_not_load_exits_2(tmp_path: Path, policy_text):
    policy = tmp_path / "policy.yaml"
    if isinstance(policy_text, bytes):
        policy.write_bytes(policy_text)
    elif policy_text is not None:
        policy.write_text(policy_text, encoding="utf-8")
    code, err = _check(policy, _cases_file(tmp_path, ONE_CASE))
    assert code == 2
    assert err.startswith("chokepoint-policy: policy did not load: ")


def test_no_command_is_a_usage_error_exit_2(capsys: pytest.CaptureFixture[str]):
    with pytest.raises(SystemExit) as raised:
        main([])
    assert raised.value.code == 2
    assert "check" in capsys.readouterr().err


# ------------------------------------------------------------------ the output


def test_main_writes_results_to_stdout_and_load_failures_to_stderr(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    assert main(["check", str(PACK), str(_cases_file(tmp_path, ONE_CASE))]) == 0
    captured = capsys.readouterr()
    assert captured.out.startswith("PASS case 1: run_command -> block shell-destructive")
    assert captured.err == ""

    assert main(["check", str(PACK), str(tmp_path / "nope.yaml")]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "cases did not load" in captured.err


def test_a_credential_in_a_tool_name_is_redacted(tmp_path: Path):
    text = ONE_CASE.replace("tool: run_command", f"tool: fetch_{AKIA}")
    code, out = _check(PACK, _cases_file(tmp_path, text))
    assert code == 1
    assert AKIA not in out
    assert TOOL_NAME_REDACTION_MARKER in out


def test_declared_hidden_context_in_a_tool_name_is_redacted(tmp_path: Path):
    secret = "the operator's private system prompt, never to leave"
    hidden = tmp_path / "system-prompt.txt"
    hidden.write_text(secret + "\n", encoding="utf-8")
    policy = tmp_path / "policy.yaml"
    policy.write_text(f"version: 0\nhidden_context:\n  system_prompt: {hidden}\n", encoding="utf-8")
    text = f"cases:\n  - tool: \"lookup {secret}\"\n    verdict: block\n    rule_id: default:on_no_match\n"
    code, out = _check(policy, _cases_file(tmp_path, text))
    assert code == 0, out
    assert secret not in out
    assert HIDDEN_CONTEXT_TOOL_NAME_REDACTION_MARKER in out


def test_a_newline_in_a_tool_or_rule_id_cannot_forge_a_line(tmp_path: Path):
    text = (
        "cases:\n"
        '  - tool: "x\\nPASS case 9: read_file"\n'
        "    verdict: allow\n"
        '    rule_id: "y\\nPASS"\n'
    )
    code, out = _check(PACK, _cases_file(tmp_path, text))
    lines = out.splitlines()
    assert code == 1
    assert len(lines) == 2
    assert lines[0].startswith("FAIL case 1: 'x\\nPASS case 9: read_file' -> expected allow 'y\\nPASS'")


def test_help_states_the_exit_codes_the_tests_above_hold_it_to(capsys: pytest.CaptureFixture[str]):
    with pytest.raises(SystemExit) as raised:
        main(["check", "--help"])
    assert raised.value.code == 0
    text = " ".join(capsys.readouterr().out.split())
    assert "print one line per case" in text
    assert "Exit 0 when every case gets its verdict and rule id, 1 when any case does not, 2 when POLICY or CASES does not load." in text


def test_a_case_names_its_server_in_the_envelope():
    cases = load_cases(PACK_CASES)
    with_server = [case for case in cases if case.call.server is not None]
    assert with_server
    assert with_server[0].call == ToolCall(
        tool="read_file", arguments={"path": "/ABSOLUTE/PATH/TO/PROJECT/src/main.py"}, server="filesystem"
    )


# ---------------------------------------------- what the check does NOT consult


def test_limits_and_taint_are_not_consulted(tmp_path: Path):
    """No run state, as at the hook: a one-call cap and all-egress taint stay silent."""
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        "version: 0\n"
        "limits: {max_tool_calls_per_run: 1}\n"
        "taint: {sources: [fetch_url], egress_tools: [run_command], egress_mode: all_egress}\n"
        "rules:\n"
        "  - {id: shell-pwd, owasp: LLM01, tool: run_command, decision: allow,"
        " when: {command_matches_any: ['\\Apwd\\Z']}}\n",
        encoding="utf-8",
    )
    text = "cases:\n" + "  - {tool: run_command, arguments: {command: pwd}, verdict: allow, rule_id: shell-pwd}\n" * 2
    cases = _cases_file(tmp_path, text)
    code, out = _check(policy, cases)
    assert code == 0, out
    # Control: the same call WITH run state is refused by each of them.
    call = load_cases(cases)[0].call
    loaded = load_policy(policy)
    assert decide(loaded, replace(call, run_state=RunState(calls_made=1))).rule_id == "limit:max_tool_calls_per_run"
    assert decide(loaded, replace(call, run_state=RunState(tainted=True))).rule_id == TAINT_EGRESS_RULE_ID


def test_a_path_is_judged_as_written_not_resolved(tmp_path: Path):
    """A door resolves this symlink to /etc/passwd and blocks; the check does not."""
    project = tmp_path / "project"
    project.mkdir()
    (project / "link").symlink_to("/etc")
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        "version: 0\nrules:\n"
        f"  - {{id: fs-read, owasp: LLM01, tool: read_file, decision: allow, when: {{path_within: ['{project}/']}}}}\n",
        encoding="utf-8",
    )
    text = f"cases:\n  - {{tool: read_file, arguments: {{path: '{project}/link/passwd'}}, verdict: allow, rule_id: fs-read}}\n"
    code, out = _check(policy, _cases_file(tmp_path, text))
    assert code == 0, out
    # Control: the doors' resolver places the same path outside the project.
    assert canonical_path(f"{project}/link/passwd") == str(Path("/etc").resolve() / "passwd")


def test_a_case_variant_of_a_denied_directory_passes_as_written(tmp_path: Path):
    """The README's `.SSH` limit: the engine compares components exactly."""
    text = (
        "cases:\n  - {tool: read_file, arguments: {path: /ABSOLUTE/PATH/TO/PROJECT/.SSH/id_rsa},"
        " verdict: allow, rule_id: fs-read-scoped}\n"
    )
    code, out = _check(PACK, _cases_file(tmp_path, text))
    assert code == 0, out


def test_the_readme_example_passes_against_the_pack(tmp_path: Path):
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    section = readme.split("## Check a policy before you trust it", 1)[1]
    example = section.split("```yaml\n", 1)[1].split("```", 1)[0]
    code, out = _check(PACK, _cases_file(tmp_path, example))
    assert code == 0, out
    assert out.splitlines()[-1] == "2 of 2 cases match"
