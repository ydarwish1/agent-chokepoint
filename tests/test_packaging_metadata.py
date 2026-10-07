"""``pyproject.toml`` carries its licence as a PEP 639 SPDX string (B-027).

setuptools deprecated ``license = { text = "..." }`` and stops building it
after 2027-02-18, so the table form is a build with an expiry date on it. The
replacement is the bare SPDX expression ``license = "Apache-2.0"``, which
cannot coexist with a ``License ::`` trove classifier - setuptools errors out
when both are present.

Read as text rather than through a TOML parser on purpose: ``tomllib`` is
3.11+, ``requires-python`` is ``>=3.10``, and CI runs the 3.10 bound
(.github/workflows/ci.yml matrix). Importing tomllib here would make this file
an error on that leg, and adding ``tomli`` would put a dependency on the
project so it can test itself. String form versus table form is a textual
property anyway.
"""

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = REPO_ROOT / "pyproject.toml"

SPDX_LICENSE = re.compile(r'^license\s*=\s*"([^"]*)"\s*$', re.MULTILINE)
TABLE_LICENSE = re.compile(r"^license\s*=\s*\{", re.MULTILINE)
TROVE_LICENSE = re.compile(r'"License\s*::')


def _uncommented(text):
    """Drop whole-line ``#`` comments so no guard can fire on its own prose."""
    return "\n".join(
        line for line in text.splitlines() if not line.lstrip().startswith("#")
    )


def test_license_is_the_spdx_string_not_the_deprecated_table():
    body = _uncommented(PYPROJECT.read_text(encoding="utf-8"))

    assert not TABLE_LICENSE.search(body), (
        "pyproject.toml uses the deprecated `license = { text = ... }` table; "
        "setuptools stops building it after 2027-02-18 (B-027)"
    )

    assert SPDX_LICENSE.findall(body) == ["Apache-2.0"], (
        'expected exactly one `license = "Apache-2.0"` SPDX expression, found '
        f"{SPDX_LICENSE.findall(body)!r}"
    )

    assert not TROVE_LICENSE.search(body), (
        "a `License ::` trove classifier cannot coexist with a PEP 639 license "
        "expression - setuptools refuses to build with both"
    )


def test_console_scripts_are_declared():
    """Entry points are the install; without them init cannot name chokepoint-hook."""
    body = _uncommented(PYPROJECT.read_text(encoding="utf-8"))
    assert 'chokepoint-hook = "hooks.chokepoint_hook:main"' in body
    assert 'chokepoint-proxy = "proxy.__main__:main"' in body
    assert 'chokepoint-init = "hooks.init:main"' in body
    assert 'chokepoint-policy = "policy.cli:main"' in body


def test_policy_yaml_is_declared_package_data():
    """A wheel without the pack cannot run chokepoint-init (Dockerfile used to COPY instead)."""
    body = _uncommented(PYPROJECT.read_text(encoding="utf-8"))
    assert "[tool.setuptools.package-data]" in body
    assert 'policy = ["policy.example.yaml", "packs/*.yaml"]' in body


def test_the_installed_pack_is_readable_as_package_data():
    """The declaration above is load-bearing only if the files are actually there."""
    from importlib.resources import files

    pack = files("policy") / "packs" / "coding-agent.yaml"
    example = files("policy") / "policy.example.yaml"
    assert pack.is_file()
    assert example.is_file()
    assert "/ABSOLUTE/PATH/TO/PROJECT" in pack.read_text(encoding="utf-8")
