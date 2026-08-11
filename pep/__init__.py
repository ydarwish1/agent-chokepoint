"""PEP = Policy Enforcement Point, not Python Enhancement Proposal.

The shared half of the two enforcement points. ``proxy/server.py`` and
``hooks/chokepoint_hook.py`` are different doors onto the same engine; what
this package holds is the work a door can do that the engine cannot — touching
the filesystem to resolve a path before the engine judges it (D-011, closing
B-007 and B-008).

It depends on the standard library and on nothing else in this repo. In
particular it does NOT import ``engine``: the claim this project makes is that
the engine is a pure PDP with no enforcement in it, and a PDP that a PEP module
reaches into is no longer that. The dependency runs one way — both doors import
this, this imports nobody — and ``pep/tests/test_canonicalize.py`` asserts it in
a subprocess rather than trusting the import list to stay honest.
"""

from .canonicalize import (
    PATH_ARGUMENT,
    RULE_UNRESOLVABLE_PATH,
    UnresolvablePath,
    canonical_path,
    canonicalized_arguments,
)

__all__ = [
    "PATH_ARGUMENT",
    "RULE_UNRESOLVABLE_PATH",
    "UnresolvablePath",
    "canonical_path",
    "canonicalized_arguments",
]
