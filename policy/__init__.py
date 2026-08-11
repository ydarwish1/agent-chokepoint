"""agent-chokepoint policy package — loading and validation.

``policy.example.yaml`` is the readable artifact; :func:`load_policy` is the
only code path from that file to the engine.
"""

from .loader import PolicyError, load_policy

__all__ = ["PolicyError", "load_policy"]
