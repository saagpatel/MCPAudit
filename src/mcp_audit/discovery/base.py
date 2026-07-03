"""Abstract base class for MCP config discoverers."""

import logging
from abc import ABC, abstractmethod
from pathlib import Path

from mcp_audit.models import ClientType, ServerConfig

logger = logging.getLogger(__name__)


class ConfigParseError(Exception):
    """A client config file exists but could not be read or parsed.

    Discovery treats this as per-file, not fatal: one corrupt config must not
    void a fleet sweep, but it also must not silently shrink the scan — callers
    surface collected errors as config-health findings.
    """

    def __init__(self, path: str, client: ClientType, reason: str) -> None:
        self.path = path
        self.client = client
        self.reason = reason
        super().__init__(f"could not parse {client.value} config {path}: {reason}")


class ConfigDiscoverer(ABC):
    """Base class for per-client MCP config discoverers."""

    @abstractmethod
    def config_paths(self) -> list[Path]:
        """Return candidate config file paths for this client."""
        ...

    @abstractmethod
    def parse(self, path: Path) -> list[ServerConfig]:
        """Parse a config file and return all ServerConfig entries found.

        Raises :class:`ConfigParseError` when the file exists but cannot be
        read or parsed as this client's config format.
        """
        ...

    def discover(self, parse_errors: list[ConfigParseError] | None = None) -> list[ServerConfig]:
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
                try:
                    results.extend(self.parse(path))
                except ConfigParseError as exc:
                    if parse_errors is not None:
                        parse_errors.append(exc)
                    else:
                        logger.warning("%s", exc)
        return results
