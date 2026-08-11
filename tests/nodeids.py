"""Ask pytest what it collects, and map every accepted spelling of a citation
onto the test functions it names.

One place in the repo asks pytest what exists, so no two checks can drift into
accepting different spellings of the same node id.
"""

from __future__ import annotations

import subprocess
import sys
from functools import lru_cache
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


@lru_cache(maxsize=1)
def _collected() -> tuple[str, ...]:
    """The raw node ids pytest collects, one subprocess per pytest run."""
    out = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-p", "no:cacheprovider"],
        capture_output=True, text=True, cwd=str(REPO_ROOT),
    )
    raw = [ln.strip() for ln in out.stdout.splitlines() if "::" in ln and not ln.startswith(" ")]
    # `addopts = "-q"` is already in pyproject; passing another -q makes it -qq,
    # which prints NO listing at all and would leave the callers asserting nothing.
    assert raw, (
        "pytest --collect-only produced no node ids; this check would be vacuous.\n"
        f"stdout tail:\n{out.stdout[-1500:]}\nstderr tail:\n{out.stderr[-1500:]}"
    )
    return tuple(raw)


def node_id_aliases() -> dict[str, frozenset[str]]:
    """Every accepted spelling of a citation -> the test FUNCTIONS it can name.

    A "test function" here is a collected node id with its parametrization
    bracket removed, so two parameters of one parametrized test are ONE function.
    That is deliberate and it is the point of this map: two ids that share a body
    are not two independently-failing nodes, and a coverage row citing one of
    them as the guard-off control for the other has no control at all.

    The same spelling can name more than one function -- a class prefix names all
    of its methods, and a method cited without its class names every class in
    that file defining it -- so the value is a SET and callers ask about
    intersection rather than about equality. Comparing two citation fields as raw
    strings let a coverage row set its Control to its own Refusal with the
    enclosing class stripped and stay green, because the two strings differ while
    the node does not.
    """
    families: dict[str, set[str]] = {}
    for node in _collected():
        segments = node.split("::")
        base = segments[:-1] + [segments[-1].split("[")[0]]
        canonical = "::".join(base)
        spellings = {node, canonical}
        for tail in ({tuple(segments), tuple(base)}):
            for i in range(2, len(tail) + 1):
                spellings.add("::".join(tail[:i]))
            # a method cited without its enclosing class still names it
            if len(tail) == 3:
                spellings.add(f"{tail[0]}::{tail[2]}")
        for spelling in spellings:
            families.setdefault(spelling, set()).add(canonical)
    return {spelling: frozenset(named) for spelling, named in families.items()}


def collect_node_ids() -> frozenset[str]:
    """Every node id pytest actually collects, plus every spelling of one that
    still names it unambiguously.

    Resolution only -- "does this citation name something". Whether two citations
    name the SAME something is `node_id_aliases()`, because this set cannot
    answer it: a method spelled with its enclosing class and the same method
    spelled without it are two members of this set and one node.
    """
    return frozenset(node_id_aliases())
