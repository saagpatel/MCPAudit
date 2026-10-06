"""Abstract base class for MCP config discoverers."""

import logging
import os
from abc import ABC, abstractmethod
from pathlib import Path

from mcp_audit.models import ClientType, ServerConfig
from mcp_audit.terminal_text import TerminalSafeLogFilter

logger = logging.getLogger(__name__)
logger.addFilter(TerminalSafeLogFilter())


def is_project_config(path: Path) -> bool:
    """Classify project config filenames without resolving symlinks into trusted paths."""
    path = Path(os.path.abspath(path))
    if path.name == ".mcp.json":
        return True
    return (
        path.name == "mcp.json"
        and path.parent.name == ".vscode"
        and path != Path.home() / ".vscode" / "mcp.json"
    )


class ConfigParseError(Exception):
    """A client config file exists but could not be read or parsed.

    Discovery treats this as per-file, not fatal: one corrupt config must not
    void a fleet sweep, but it also must not silently shrink the scan — callers
    surface collected errors as config-health findings.
    """

    def __init__(
        self,
        path: str,
        client: ClientType,
        reason: str,
        *,
        finding_type: str = "config_parse_failure",
        server_name: str | None = None,
    ) -> None:
        self.path = path
        self.client = client
        self.reason = reason
        self.finding_type = finding_type
        self.server_name = server_name
        super().__init__(f"could not parse {client.value} config {path}: {reason}")


class ConfigDiscoverer(ABC):
    """Base class for per-client MCP config discoverers."""

    @abstractmethod
    def config_paths(self) -> list[Path]:
        """Return candidate config file paths for this client."""
        ...

    @abstractmethod
    def parse(self, path: Path, parse_errors: list[ConfigParseError] | None = None) -> list[ServerConfig]:
        """Parse a config file and return all valid ServerConfig entries found.

        Raises :class:`ConfigParseError` when the file exists but cannot be
        read or parsed as this client's config format. Entry-level diagnostics
        are collected into ``parse_errors`` or logged as warnings.
        """
        ...

    def discover(
        self,
        parse_errors: list[ConfigParseError] | None = None,
        config_paths: list[Path] | None = None,
    ) -> list[ServerConfig]:
        """Run discovery: check each candidate path and parse those that exist.

        A file that exists but fails to parse is recorded into ``parse_errors``
        (or logged as a warning when no accumulator is given) and skipped, so
        one corrupt config cannot take down the rest of the sweep.
        """
        try:
            paths = self.config_paths()
        except (OSError, RuntimeError) as exc:
            # Path.cwd() raises OSError when the working directory was deleted;
            # Path.home() raises RuntimeError when no home resolves. Neither
            # may take down the other clients' discovery.
            logger.warning("%s: cannot resolve config paths (%s) — skipping", type(self).__name__, exc)
            return []
        results: list[ServerConfig] = []
        for path in paths:
            if path.exists():
                if config_paths is not None:
                    config_paths.append(path)
                try:
                    results.extend(self.parse(path, parse_errors))
                except ConfigParseError as exc:
                    if parse_errors is not None:
                        parse_errors.append(exc)
                    else:
                        logger.warning("%s", exc)
        return results
