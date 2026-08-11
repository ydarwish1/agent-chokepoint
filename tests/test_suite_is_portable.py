"""A harness spawns the interpreter that is RUNNING it, never one it guessed a
path to (CP-08).

Every other harness in this tree already did. `proxy/demo/tainted_run.py`,
`hooks/demo/side_by_side.py`, `pep/demo/two_doors_paths.py`, the `proxy/tests/`
subprocess tests — all of them write `sys.executable`. Two did not:
`proxy/demo/real_model_attacks.py` and `hooks/demo/real_agent_run.py` each
carried

    VENV_PYTHON = REPO_ROOT / ".venv" / "bin" / "python"

which names a directory that exists only on a machine where somebody ran
`python -m venv .venv` inside the checkout. CI does not: `.github/workflows/ci.yml`
does `pip install -e .` and then `pytest`, on 3.10 and on 3.14, and the README
quickstart says the same. So the constant resolved to a path with no file at the
end of it, every replay leg raised `FileNotFoundError` inside `subprocess`, and
eight tests in `tests/test_model_run_records.py` — five in `TestReplayMachinery`,
three in `TestTheReachMatcher` — died before reaching a single assertion. Both CI
legs were red. A local run, on the one machine that has the `.venv`, was green.

**That gap is the defect, and it is why this module scans rather than fixes.**
The two constants are one edit; what made them survive is that the only place
they fail is the place nobody was looking. A green laptop is not evidence about a
clean checkout, and no test that runs on the laptop can become evidence about one
by asserting harder. What CAN travel is a check on the SHAPE of the code:
assembling an interpreter path out of the repository root is wrong on every
machine, including the one where it happens to work.

WHAT IS FLAGGED is a path CONSTRUCTION that names a virtualenv directory and an
interpreter inside it — the `Path` division chain above, the same thing spelled
as one literal, as an f-string, or through `os.path.join`. Not the substring
`.venv`, which is innocent where it legitimately appears in code: a tree walk
filtered with `rel.startswith((".venv/", ...))` is a directory being EXCLUDED,
not an interpreter being located. Docstrings are exempt for the same reason from the
other end — `.venv/bin/python proxy/demo/real_model_attacks.py` is the correct
usage recipe and stays correct after the fix, because when a reader invokes the
file that way `sys.executable` IS that binary. Comments never reach the scan at
all; `ast` drops them.

The boundary, stated rather than implied: the scan reads path-shaped expressions,
so an interpreter path assembled at runtime out of pieces that are individually
innocent goes through. `VENV_DIR + "/bin/python"` below is exactly that, and it is
deliberate — this module has to hold its own fixtures without failing its own
scan. It is a guard against the accident that already happened twice, not against
an author working around it.

BOTH CONTROLS: a scan that flags nothing proves nothing unless the same scan
flags the construction it exists to catch. `TestTheScanSeesTheDefect`
feeds it the five shapes; `TestTheScanLeavesLegitimateMentionsAlone` feeds it the
four this repository actually contains and requires silence.
"""

from __future__ import annotations

import ast
import os
import re
import sys
from pathlib import Path

import pytest

from hooks.demo import real_agent_run as hook_harness
from proxy.demo import real_model_attacks as proxy_harness

REPO_ROOT = Path(__file__).resolve().parents[1]

#: A virtualenv directory (`.venv`, `venv`, `venv312`, `.virtualenv`) followed by
#: the interpreter inside it, in the POSIX layout or the Windows one. `pip` counts
#: alongside `python`: the failure is identical and `tests/test_telemetry_controls.py`
#: shows the recipe form it takes.
INTERPRETER_UNDER_A_VIRTUALENV = re.compile(
    r"(?:^|[/\\])\.?(?:venv|virtualenv)[\w.\-]*[/\\](?:bin|Scripts)[/\\](?:python|pip)",
    re.IGNORECASE,
)

#: Stands in for a piece of an expression that is not a string literal — the
#: `REPO_ROOT` in `REPO_ROOT / ".venv" / "bin" / "python"`. NUL cannot occur in a
#: path segment, so a placeholder can never complete a match the source did not
#: already spell out.
OPAQUE = "\x00"


def _docstring_constants(tree: ast.AST) -> set[int]:
    """The `Constant` nodes that are docstrings, by identity.

    Held by node id rather than by line so a one-line docstring and a code string
    on the same line stay distinguishable. `tree` outlives every use of the set,
    which is what makes the ids stable.
    """
    docstrings: set[int] = set()
    holders = (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
    for node in ast.walk(tree):
        if not isinstance(node, holders):
            continue
        body = node.body
        if (body and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)):
            docstrings.add(id(body[0].value))
    return docstrings


def _path_spelled_by(node: ast.AST, docstrings: set[int]) -> str | None:
    """The path a node spells, or None if it does not spell one.

    Four shapes, because those are the four ways this repository writes a path:
    a string literal, an f-string, a `Path` division chain, and a `.join()` of
    segments. Non-literal operands become `OPAQUE`, which is what lets the
    outermost node of `ROOT / ".venv" / "bin" / "python"` report the whole
    construction while its inner nodes (`ROOT / ".venv"`) report a fragment that
    matches nothing.
    """
    if isinstance(node, ast.Constant):
        if id(node) in docstrings or not isinstance(node.value, str):
            return None
        return node.value
    if isinstance(node, ast.JoinedStr):
        return "".join(
            piece.value if isinstance(piece, ast.Constant) and isinstance(piece.value, str)
            else OPAQUE
            for piece in node.values
        )
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
        left = _path_spelled_by(node.left, docstrings)
        right = _path_spelled_by(node.right, docstrings)
        return f"{left if left is not None else OPAQUE}/{right if right is not None else OPAQUE}"
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr == "join"
            and not isinstance(node.func.value, ast.Constant)):
        # `os.path.join(ROOT, ".venv", "bin", "python")`. The `isinstance` guard
        # excludes `"/".join(parts)`, which is str.join and says nothing about
        # what its argument holds.
        parts = [_path_spelled_by(arg, docstrings) for arg in node.args]
        return "/".join(part if part is not None else OPAQUE for part in parts)
    return None


def interpreter_constructions(source: str) -> list[tuple[int, str]]:
    """Every `(line, path)` in `source` that builds an interpreter inside a venv."""
    tree = ast.parse(source)
    docstrings = _docstring_constants(tree)
    found = set()
    for node in ast.walk(tree):
        spelled = _path_spelled_by(node, docstrings)
        if spelled and INTERPRETER_UNDER_A_VIRTUALENV.search(spelled):
            found.add((getattr(node, "lineno", 0), spelled))
    return sorted(found)


def _shipped_python() -> list[Path]:
    """Every `.py` file this repository ships. The environment is not one of them."""
    files = []
    for path in sorted(REPO_ROOT.rglob("*.py")):
        rel = path.relative_to(REPO_ROOT).as_posix()
        if rel.startswith((".venv/", ".git/")) or "__pycache__" in path.parts:
            continue
        files.append(path)
    assert len(files) > 40, "no shipped modules found - this scan would pass vacuously"
    return files


SHIPPED_PYTHON = _shipped_python()

#: The fixtures below need the defect's own string, and this module is itself
#: scanned by the test above. Kept in pieces so the file states the construction
#: without containing it - `.venv` on its own is a directory name, and the scan
#: correctly says nothing about one.
VENV_DIR = ".venv"
POSIX_INTERPRETER = VENV_DIR + "/bin/python"


class TestNoShippedModuleBuildsItsOwnInterpreterPath:
    """The scan, over the tree as it stands. This is the half that goes red when
    the defect comes back; the two control classes below are what make a green
    run here mean anything."""

    def test_no_module_constructs_an_interpreter_inside_a_virtualenv(self):
        findings = []
        for path in SHIPPED_PYTHON:
            source = path.read_text(encoding="utf-8")
            for lineno, spelled in interpreter_constructions(source):
                rel = path.relative_to(REPO_ROOT).as_posix()
                findings.append(f"{rel}:{lineno}: {spelled!r}")
        assert not findings, (
            "these lines build an interpreter path out of the checkout, which CI "
            "does not have (CP-08). Spawn sys.executable instead:\n  "
            + "\n  ".join(findings)
        )

    def test_the_two_harnesses_that_carried_it_spawn_this_interpreter(self):
        """The site-level half, asserted on the value each constant now holds.

        The scan above proves nothing was CONSTRUCTED; this proves the two files
        that used to construct one arrived at the running interpreter rather than
        at some other guess.
        """
        assert str(proxy_harness.PYTHON) == sys.executable
        assert str(hook_harness.PYTHON) == sys.executable


class TestEverySpawnSiteUsesIt:
    """Behaviour, not the constant: what actually lands in an argv.

    A constant with the right value and one call site still holding an old path
    is the same outage, and asserting on `PYTHON` alone cannot see it. These four
    are every place the two harnesses name an interpreter - three subprocess
    envelopes in the replay harness, one generated hook command line.
    """

    def test_the_upstream_is_spawned_with_it(self, tmp_path):
        argv = proxy_harness.upstream_argv(tmp_path, None)
        assert argv[0] == sys.executable

    def test_the_proxied_server_is_spawned_with_it(self, tmp_path):
        params = proxy_harness.proxied_params(
            tmp_path / "policy.yaml", tmp_path, tmp_path / "events.jsonl", None)
        assert params.command == sys.executable
        assert params.args[:2] == ["-m", "proxy"]

    def test_the_mcp_config_claude_code_reads_names_it(self, tmp_path):
        config = proxy_harness.mcp_config(
            tmp_path / "policy.yaml", tmp_path, tmp_path / "events.jsonl",
            tmp_path / "page.html")
        server = config["mcpServers"][proxy_harness.MCP_SERVER]
        assert server["command"] == sys.executable

    def test_the_generated_hook_command_runs_it(self, tmp_path):
        command = hook_harness.hook_command(tmp_path / "policy.yaml", tmp_path / "hook.jsonl")
        assert command.startswith(f"{sys.executable} ")


class TestTheScanSeesTheDefect:
    """The positive control. Five spellings of one mistake, each of which would
    fail on a clean checkout exactly as CP-08 did."""

    @pytest.mark.parametrize("source", [
        pytest.param(f'ROOT = Path(".")\nPY = ROOT / "{VENV_DIR}" / "bin" / "python"\n',
                     id="the-division-chain-CP-08-used"),
        pytest.param(f'PY = "/opt/project/{POSIX_INTERPRETER}"\n',
                     id="one-literal"),
        pytest.param(f'PY = f"{{ROOT}}/{POSIX_INTERPRETER}"\n',
                     id="an-f-string"),
        pytest.param(f'PY = os.path.join(ROOT, "{VENV_DIR}", "bin", "python")\n',
                     id="os-path-join"),
        pytest.param(f'PY = ROOT / "{VENV_DIR}" / "Scripts" / "python.exe"\n',
                     id="the-windows-layout"),
    ])
    def test_the_construction_is_flagged(self, source):
        assert interpreter_constructions(source), \
            f"the scan missed an interpreter path it exists to catch:\n{source}"

    def test_it_reports_where(self):
        source = f'X = 1\nY = 2\nPY = ROOT / "{VENV_DIR}" / "bin" / "python"\n'
        assert [line for line, _ in interpreter_constructions(source)] == [3]

    def test_a_file_on_disk_that_carries_it_is_flagged(self, tmp_path):
        """End to end over a real file, so the reader of the main test knows the
        path/read/parse half runs too and not only the regex."""
        module = tmp_path / "harness.py"
        module.write_text(f'from pathlib import Path\n'
                          f'ROOT = Path(__file__).resolve().parents[2]\n'
                          f'PY = ROOT / "{VENV_DIR}" / "bin" / "python"\n', encoding="utf-8")
        assert interpreter_constructions(module.read_text(encoding="utf-8"))


class TestTheScanLeavesLegitimateMentionsAlone:
    """The negative control. Every one of these is a real line in this tree; a
    scan that flags them is a scan somebody turns off."""

    def test_a_docstring_usage_recipe_is_not_a_construction(self):
        source = (f'"""Run it:\n\n    {POSIX_INTERPRETER} proxy/demo/real_model_attacks.py\n"""\n'
                  f'import sys\n')
        assert interpreter_constructions(source) == []

    def test_a_directory_filter_is_not_a_construction(self):
        source = f'rel = p.as_posix()\nif rel.startswith(("{VENV_DIR}/", ".git/")):\n    pass\n'
        assert interpreter_constructions(source) == []

    def test_the_fix_itself_is_not_a_construction(self):
        source = 'import sys\nfrom pathlib import Path\nPYTHON = Path(sys.executable)\n'
        assert interpreter_constructions(source) == []

    def test_an_ordinary_path_under_the_root_is_not_a_construction(self):
        source = 'UPSTREAM = REPO_ROOT / "proxy" / "demo" / "upstream_server.py"\n'
        assert interpreter_constructions(source) == []

    def test_a_comment_never_reaches_the_scan(self):
        source = f'# was: PY = ROOT / "{VENV_DIR}" / "bin" / "python"\nPY = sys.executable\n'
        assert interpreter_constructions(source) == []


class TestTheScanCanParseEveryShippedModule:
    """`ast.parse` failing is silent unless somebody checks: a module the scan
    cannot read is a module the scan does not cover, and the main test would go
    green on it either way. CI runs 3.10 and 3.14, so this also catches syntax
    that only one of them accepts.
    """

    def test_every_shipped_module_parses(self):
        unreadable = []
        for path in SHIPPED_PYTHON:
            try:
                ast.parse(path.read_text(encoding="utf-8"))
            except (SyntaxError, UnicodeDecodeError) as exc:
                unreadable.append(f"{path.relative_to(REPO_ROOT).as_posix()}: {exc}")
        assert not unreadable, "the scan cannot read:\n  " + "\n  ".join(unreadable)

    def test_the_two_harnesses_are_in_the_scanned_set(self):
        """Named on purpose. A `rglob` that stops matching them turns the main
        test into a check on the files that never had the defect, which passes."""
        scanned = {p.relative_to(REPO_ROOT).as_posix() for p in SHIPPED_PYTHON}
        assert "proxy/demo/real_model_attacks.py" in scanned
        assert "hooks/demo/real_agent_run.py" in scanned
        assert os.path.relpath(__file__, REPO_ROOT).replace(os.sep, "/") in scanned
