"""Abstract base class for MCP config discoverers."""

from abc import ABC, abstractmethod
from pathlib import Path

from mcp_audit.models import ServerConfig


class ConfigDiscoverer(ABC):
    """Base class for per-client MCP config discoverers."""

    @abstractmethod
    def config_paths(self) -> list[Path]:
        """Return candidate config file paths for this client."""
        ...

    @abstractmethod
    def parse(self, path: Path) -> list[ServerConfig]:
        """Parse a config file and return all ServerConfig entries found."""
        ...

    def discover(self) -> list[ServerConfig]:
        """Run discovery: check each candidate path and parse those that exist."""
        results: list[ServerConfig] = []
        for path in self.config_paths():
            if path.exists():
                results.extend(self.parse(path))
        return results
