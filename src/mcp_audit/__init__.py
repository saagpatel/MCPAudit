"""MCP Permission Auditor — scan and risk-score locally configured MCP servers."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("mcp-audits")
except PackageNotFoundError:
    __version__ = "0.0.0"
