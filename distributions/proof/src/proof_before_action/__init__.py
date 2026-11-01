"""Proof Before Action — disposable observation and portable evidence."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("mcp-audits-proof")
except PackageNotFoundError:
    __version__ = "0.0.0"
