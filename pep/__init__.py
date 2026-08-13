"""PEP = Policy Enforcement Point, not Python Enhancement Proposal.

The shared half of the two enforcement points. ``proxy/server.py`` and
``hooks/chokepoint_hook.py`` are different doors onto the same engine; what
this package holds is the work a door can do that the engine cannot — touching
the filesystem to resolve a path before the engine judges it (D-011, closing
B-007 and B-008).

``import pep`` loads only :mod:`pep.canonicalize`, which depends on the
standard library and on nothing else in this repo — so the engine stays a
pure PDP that this package does not reach into. Both doors also import
:mod:`pep.log` **by name** for the shared decision-log helpers; that submodule
uses the engine's scanners and is asserted separately. Canonicalize still
imports nobody: ``pep/tests/test_canonicalize.py`` checks ``import pep`` in a
subprocess.
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
