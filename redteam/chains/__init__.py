"""Offline cross-server chain analysis."""

from pathlib import Path

import mcp_audit


class ShadowImportError(ImportError):
    """An absent or incompatible dependency for checkout-only discovery."""


def ensure_repo_import() -> None:
    """Check the package origin before importing any version-specific core API."""
    module_file = mcp_audit.__file__
    repo_src = Path(__file__).resolve().parents[2] / "src"
    if module_file is None or not Path(module_file).resolve().is_relative_to(repo_src):
        raise ShadowImportError("mcp_audit must be imported from this checkout's src/ directory")
