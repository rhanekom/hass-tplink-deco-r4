"""Smoke tests for the integration manifest."""

from __future__ import annotations

import json
from pathlib import Path

from custom_components.tplink_deco_r4.const import DOMAIN

MANIFEST = Path(__file__).parent.parent / "custom_components" / DOMAIN / "manifest.json"


def test_manifest_domain_matches_package() -> None:
    """The manifest domain matches the package directory and const.DOMAIN."""
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    assert manifest["domain"] == DOMAIN
    assert MANIFEST.parent.name == DOMAIN


def test_manifest_has_required_custom_integration_keys() -> None:
    """Keys hassfest requires of a custom integration are present."""
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    for key in ("name", "version", "documentation", "issue_tracker", "codeowners"):
        assert manifest[key], f"manifest.json is missing {key}"
