"""Shared pytest fixtures for the TP-Link Deco R4 test suite."""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def auto_enable_custom_integrations(enable_custom_integrations: None) -> None:
    """Enable loading the custom integration in every test."""
