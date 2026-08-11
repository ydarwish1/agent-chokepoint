"""Entrypoint argv assembly: only the LEADING ``--`` is a separator (B-016).

``proxy/__main__.py`` used to build the upstream command with
``[a for a in args.upstream if a != "--"]``, which drops **every** ``--`` and
not just the separator that precedes the command. An upstream invocation that
legitimately carries its own ``--`` — ``npx -y server -- --verbose``, or any
wrapper that forwards flags to a child — reached the upstream mangled.

These tests drive the **real** parser via ``_build_parser()`` rather than a
reconstruction of it, because the defect lives in what ``argparse.REMAINDER``
actually hands back. Measured on this repo's interpreter (Python 3.14.6,
2026-08-02) and pinned by ``test_remainder_keeps_the_separator_it_stopped_at``
below: the separator is retained, it is absent when the caller omits it, and a
second one belongs to the upstream command rather than to argparse.

The empty-upstream case goes through the process boundary, because
``parser.error`` — exit 2, message on stderr — is only real as a process
result. It fires before ``load_policy``, so no upstream is ever spawned here
and no test in this file starts a subprocess server.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import anyio
import pytest

from mcp import Client, MCPError, StdioServerParameters, stdio_client

from policy import load_policy
from proxy.__main__ import _build_parser, _upstream_command

REPO_ROOT = Path(__file__).resolve().parents[2]


def _upstream_for(argv: list[str]) -> list[str]:
    """Full path under test: real parser, then the real separator logic."""
    return _upstream_command(_build_parser().parse_args(argv).upstream)


class TestRemainderShape:
    """What argparse hands us — pinned, so the fix rests on a measurement."""

    def test_remainder_keeps_the_separator_it_stopped_at(self):
        args = _build_parser().parse_args(["--policy", "P", "--", "prog", "--", "inner"])
        assert args.upstream == ["--", "prog", "--", "inner"]

    def test_remainder_omits_the_separator_when_the_caller_does(self):
        args = _build_parser().parse_args(["--policy", "P", "prog", "arg"])
        assert args.upstream == ["prog", "arg"]


class TestUpstreamCommand:
    def test_inner_separator_reaches_the_upstream_intact(self):
        assert _upstream_for(["--policy", "P", "--", "prog", "--", "inner"]) == [
            "prog",
            "--",
            "inner",
        ]

    def test_flags_forwarded_past_an_inner_separator_survive(self):
        assert _upstream_for(
            ["--policy", "P", "--", "npx", "-y", "server", "--", "--verbose"]
        ) == ["npx", "-y", "server", "--", "--verbose"]

    def test_second_leading_separator_belongs_to_the_command(self):
        assert _upstream_for(["--policy", "P", "--", "--", "prog"]) == ["--", "prog"]

    def test_ordinary_command_is_unchanged(self):
        assert _upstream_for(["--policy", "P", "--", "prog", "arg"]) == ["prog", "arg"]

    def test_command_without_a_separator_is_left_alone(self):
        assert _upstream_for(["--policy", "P", "prog", "arg"]) == ["prog", "arg"]

    def test_bare_separator_yields_no_command(self):
        assert _upstream_for(["--policy", "P", "--"]) == []


class TestServerNameFlag:
    """D-015 (B-011) — ``--server-name`` on the real parser.

    A flag rather than something read per call: this proxy fronts exactly one
    upstream and the MCP wire carries no server name, so there is nothing to
    read it from. Unset must stay ``None``, because ``None`` is what makes a
    rule carrying ``server:`` match nothing here — the omission fails closed.
    """

    def test_it_defaults_to_none(self):
        assert _build_parser().parse_args(["--policy", "P", "--", "prog"]).server_name is None

    def test_it_parses_the_value(self):
        args = _build_parser().parse_args(
            ["--policy", "P", "--server-name", "trusted", "--", "prog"]
        )
        assert args.server_name == "trusted"

    def test_it_does_not_disturb_the_upstream_command(self):
        # The flag sits before the `--`, so REMAINDER must still hand back the
        # upstream verbatim (B-016's property, re-checked with the new flag in
        # the argv rather than assumed to be independent of it).
        assert _upstream_for(
            ["--policy", "P", "--server-name", "trusted", "--", "npx", "-y", "s", "--", "-v"]
        ) == ["npx", "-y", "s", "--", "-v"]

    @pytest.mark.parametrize("server_name", ["prod__west", "__west", "west__", "a__b__c"])
    def test_a_name_carrying_the_hook_delimiter_errors_at_the_process_boundary(self, server_name):
        """B-034: the identity the other door cannot represent is refused here.

        ``mcp__prod__west__read_file`` is the name of both (server ``prod``,
        tool ``west__read_file``) and (server ``prod__west``, tool
        ``read_file``), so a proxy started with ``--server-name prod__west``
        judges a call the hook judges differently -- one deployment, two
        envelopes. ``policy/loader.py`` refuses the same string in a rule's
        ``server:`` key; this is the other place the identity gets in.

        Through the process, because ``parser.error`` -- exit 2, message on
        stderr -- is only real as a process result, the same reason
        ``TestEmptyUpstreamStillErrors`` runs one.
        """
        proc = subprocess.run(
            [
                sys.executable, "-m", "proxy",
                "--policy", "policy/policy.example.yaml",
                "--server-name", server_name,
                "--", "prog",
            ],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=30,
        )
        assert proc.returncode == 2
        assert "--server-name must not contain" in proc.stderr
        assert "B-034" in proc.stderr

    @pytest.mark.parametrize("server_name", ["prod_", "west_", "a_b_c_"])
    def test_a_name_ending_in_the_delimiters_char_errors_at_the_process_boundary(
        self, server_name
    ):
        """B-037: B-034's `__` rule was not the whole condition.

        `prod_` contains no `__`, so the B-034 guard accepted it -- and
        `mcp__prod___read_file`, the wire name it produces, splits readably in
        two places (`prod` + `_read_file` and `prod_` + `read_file`), so the
        hook denies it with `hook:unparseable-input`. Measured on the pre-fix
        export: this flag ACCEPTED, hook DENIED. Fail-closed, hence S3, but the
        same door-disagreement B-034's fix existed to eliminate.

        Through the process for the same reason the B-034 case above is.
        """
        proc = subprocess.run(
            [
                sys.executable, "-m", "proxy",
                "--policy", "policy/policy.example.yaml",
                "--server-name", server_name,
                "--", "prog",
            ],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=30,
        )
        assert proc.returncode == 2
        assert "--server-name must not contain '__' or end with '_'" in proc.stderr
        assert "B-037" in proc.stderr

    @pytest.mark.parametrize("server_name", ["plugin_my-plugin_db", "my-server", "prod_west"])
    def test_an_ordinary_server_name_still_starts_the_proxy(self, server_name):
        """The control. The refusal above would look identical if the flag were
        rejected outright, so this drives an ordinary name through the same
        entrypoint: it must get PAST argument parsing. It fails on the upstream
        instead (`prog` does not exist), which is proof it was accepted -- exit 2
        with the flag's own message is what a blanket refusal would print.
        ``TestServerNameReachesTheEngine`` covers the end-to-end allow."""
        proc = subprocess.run(
            [
                sys.executable, "-m", "proxy",
                "--policy", "policy/policy.example.yaml",
                "--server-name", server_name,
                "--", "prog-that-does-not-exist",
            ],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=30,
        )
        assert "--server-name must not contain" not in proc.stderr

    @pytest.mark.parametrize("flag_argv", [["--server-name", ""], ["--server-name="]])
    def test_an_empty_server_name_errors_at_the_process_boundary(self, flag_argv):
        """B-038: emptiness is not ambiguity, and the guard gated only on ambiguity.

        `ambiguous_server_identity('')` is False and correctly so -- `"" + "__"`
        carries the delimiter exactly once, so an empty identity is not
        ambiguous, it is absent. B-034's and B-037's guard therefore did not
        cover it, and `--server-name=` started the proxy with `server_name=''`
        while `policy/loader.py` refuses `server: ""` outright and the hook
        denies `mcp____read_file`. Measured on the pre-fix export: this flag
        ACCEPTED (exit 1, the upstream failing to spawn), the loader REFUSED.

        S3, not S2: an empty identity matches only unscoped rules, exactly as an
        unset one does (`engine/decide.py` short-circuits on `rule.server is
        None`), so nothing is wrongly allowed -- a configuration is merely
        writable at one door and unwritable at the other.

        Through the process, because `parser.error` -- exit 2, message on
        stderr -- is only real as a process result, the same reason the two
        cases above run one. Both argv spellings, because `--server-name=` and
        `--server-name ""` are one value to argparse and two to an operator.
        """
        proc = subprocess.run(
            [
                sys.executable, "-m", "proxy",
                "--policy", "policy/policy.example.yaml",
                *flag_argv,
                "--", "prog",
            ],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=30,
        )
        assert proc.returncode == 2
        assert "--server-name must be a non-empty string" in proc.stderr
        assert "B-038" in proc.stderr

    def test_a_whitespace_only_server_name_is_left_alone_at_both_doors(self, tmp_path):
        """B-038's boundary, pinned: empty is refused, whitespace is not.

        Not because `--server-name "   "` is a good identity, but because
        `policy/loader.py` LOADS `server: "   "` -- its check is `not server`,
        false for a space -- and the hook can read `mcp__   __read_file`.
        Refusing it at this door alone would open the same disagreement B-034,
        B-037 and B-038 all exist to close, pointing the other way. Both doors
        take it or neither does, and widening both is a policy-schema change.

        Driven against the REAL loader rather than a restatement of its
        condition, because a restatement would keep passing while the doors
        drifted apart, which is this whole family's shape.
        """
        policy = tmp_path / "whitespace.yaml"
        policy.write_text(
            server_scoped_policy_text('    server: "   "\n'), encoding="utf-8"
        )
        assert load_policy(str(policy)).rules[0].server == "   "

        proc = subprocess.run(
            [
                sys.executable, "-m", "proxy",
                "--policy", "policy/policy.example.yaml",
                "--server-name", "   ",
                "--", "prog-that-does-not-exist",
            ],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=30,
        )
        assert "--server-name must" not in proc.stderr

    def test_the_flag_is_documented_in_help(self):
        proc = subprocess.run(
            [sys.executable, "-m", "proxy", "--help"],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=30,
        )
        assert proc.returncode == 0
        assert "--server-name" in proc.stdout


def server_scoped_policy_text(server_line: str) -> str:
    """One allow rule for ``read_file``, with or without a ``server:`` line.

    Concatenated rather than ``str.format``-ed: the ``defaults:`` flow mapping
    carries literal braces, which ``format`` reads as fields.
    """
    return (
        "version: 0\n"
        "defaults: {decision: block, on_no_match: block}\n"
        "rules:\n"
        "  - id: trusted-read\n"
        "    owasp: LLM01\n"
        "    tool: read_file\n"
        "    decision: allow\n"
        + server_line
        + "    when:\n"
        '      path_within: ["/workspace/"]\n'
    )


def child_env() -> dict[str, str]:
    """A stdio child does not inherit the parent environment (the SDK passes an
    allow-list), so the proxy and the upstream both need this project on the
    path. Same helper, same reason, as ``hooks/demo/side_by_side.py``."""
    env = {
        k: os.environ[k]
        for k in ("HOME", "PATH", "LOGNAME", "SHELL", "TERM", "USER")
        if k in os.environ
    }
    env["PYTHONPATH"] = str(REPO_ROOT)
    return env


async def one_call_through(policy: Path, sandbox: Path, server_name: str | None) -> str:
    """Drive one real ``read_file`` through ``python -m proxy`` over real stdio.

    Three processes and a real wire, which is the only place ``--server-name``
    exists at all: ``build_proxy``'s keyword is covered by
    ``proxy/tests/test_proxy.py``, and what is unproven until here is that the
    flag on the command line reaches it. Returns "ALLOWED" or the refusal's
    rule id.
    """
    argv = [
        "-m", "proxy",
        "--policy", str(policy),
        *(("--server-name", server_name) if server_name is not None else ()),
        "--", sys.executable, str(REPO_ROOT / "proxy" / "demo" / "upstream_server.py"),
        "--sandbox", str(sandbox),
    ]
    params = StdioServerParameters(
        command=sys.executable, args=argv, cwd=str(REPO_ROOT), env=child_env()
    )
    async with Client(stdio_client(params)) as agent:
        try:
            await agent.call_tool("read_file", {"path": "/workspace/README.md"})
            return "ALLOWED"
        except MCPError as exc:
            return str(exc.error.data["rule_id"])


def outcome(tmp_path: Path, *, scoped: bool, server_name: str | None) -> str:
    policy = tmp_path / ("scoped.yaml" if scoped else "unscoped.yaml")
    policy.write_text(
        server_scoped_policy_text("    server: trusted\n" if scoped else ""),
        encoding="utf-8",
    )
    sandbox = tmp_path / f"sandbox-{policy.stem}-{server_name}"
    sandbox.mkdir()
    return anyio.run(one_call_through, policy, sandbox, server_name)


class TestServerNameReachesTheEngine:
    """D-015 end to end: the flag on the command line changes the verdict.

    A flag that parses and is then dropped on the floor is exactly B-011's own
    shape — the hook computed the server name on one line and discarded it on
    the next — so parsing is not the property worth asserting here. These drive
    the real entrypoint as a process, with the real upstream behind it.

    Costs seconds where the rest of this file costs microseconds, for the same
    reason ``proxy/tests/test_run_demo_gate.py`` does: it tests the harness
    instead of a re-implementation of it.
    """

    def test_the_named_server_is_allowed(self, tmp_path):
        assert outcome(tmp_path, scoped=True, server_name="trusted") == "ALLOWED"

    def test_a_different_server_name_is_refused(self, tmp_path):
        assert outcome(tmp_path, scoped=True, server_name="attacker") == "default:on_no_match"

    def test_omitting_the_flag_is_refused_by_a_scoped_rule(self, tmp_path):
        # The trap, at the process boundary: forgetting `--server-name` against
        # a policy that scopes its rules closes the door rather than opening it.
        assert outcome(tmp_path, scoped=True, server_name=None) == "default:on_no_match"

    def test_an_internal_underscore_identity_still_reaches_the_engine(self, tmp_path):
        """B-037's control at the far end, and the shape nearest the refusal.

        `prod_west` differs from the refused `prod_` by one trailing character,
        so a guard that over-widened would take it too -- and the four refusal
        tests would still all pass, because everything here blocks by default.
        This drives it through the real entrypoint, real stdio and the real
        upstream: it must come back ALLOWED, not merely get past argparse.
        """
        policy = tmp_path / "prod-west.yaml"
        policy.write_text(
            server_scoped_policy_text("    server: prod_west\n"), encoding="utf-8"
        )
        sandbox = tmp_path / "sandbox-prod-west"
        sandbox.mkdir()
        assert anyio.run(one_call_through, policy, sandbox, "prod_west") == "ALLOWED"

    @pytest.mark.parametrize("server_name", ["trusted", "attacker", None])
    def test_the_same_policy_without_server_allows_all_three(self, tmp_path, server_name):
        # Guard off. Without this leg the two refusals above prove only that
        # deny-by-default was reached, which a broken policy file also does.
        assert outcome(tmp_path, scoped=False, server_name=server_name) == "ALLOWED"


class TestEmptyUpstreamStillErrors:
    def test_bare_separator_errors_at_the_process_boundary(self):
        proc = subprocess.run(
            [sys.executable, "-m", "proxy", "--policy", "policy/policy.example.yaml", "--"],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=30,
        )
        assert proc.returncode == 2
        assert "upstream server command required" in proc.stderr
