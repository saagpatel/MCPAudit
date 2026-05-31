"""Launch-config / provenance drift detector.

Compares a server's current launch configuration against the snapshot captured in
its pin baseline and flags supply-chain-relevant changes that the tool-schema
drift check cannot see:

  MCP020 (COMMAND)      — command/binary or transport changed (HIGH).
  MCP021 (ARGS)         — launch arguments changed: version float, package swap,
                          or a new flag.  MEDIUM, or HIGH if a known-dangerous
                          flag was gained.
  MCP022 (URL)          — HTTP endpoint/URL changed (HIGH).
  MCP023 (CREDENTIALS)  — declared env/header KEY-NAME set changed (MEDIUM).

A server can keep byte-identical tool schemas while repointing ``npx pkg@1.2.3``
to ``@latest``, swapping its binary, gaining ``--no-sandbox``, or changing its
endpoint — each a classic rug-pull vector.  Findings are a pure delta against the
pinned config snapshot, so an unchanged launch config produces nothing.

Credential surface is compared by KEY NAME only (``env_keys`` / ``headers_keys``);
no value is ever read, stored, or displayed.  Opt-in behind ``--provenance-check``
(which implies a pin comparison).  Baselines pinned before config snapshots
existed return ``None`` and are skipped.
"""

from __future__ import annotations

from typing import Any

from mcp_audit.models import (
    ProvenanceFinding,
    ProvenanceKind,
    ProvenanceSeverity,
    ServerConfig,
)

# Flag prefixes that mark a launch argument as security-relevant. A newly gained
# arg whose token starts with any of these escalates an ARGS change to HIGH.
# INVARIANT: every entry MUST be lowercase (matching lowercases the arg, not the
# signal) and begin with "--" (prefix matching relies on it).
_DANGEROUS_FLAG_SIGNALS: frozenset[str] = frozenset(
    {
        "--no-sandbox",
        "--dangerously",  # e.g. --dangerously-skip-permissions
        "--allow-all",
        "--allow-root",
        "--disable-security",
        "--disable-sandbox",
        "--unsafe",
        "--no-verify",
        "--insecure",
        "--privileged",
        "--trust-all",
        "--skip-permissions",
    }
)


def _disp(value: object) -> str:
    """Render a config value for the finding's baseline/current fields.

    Maps ``None`` to ``"(unset)"`` so a stdio→http or no-url→url transition reads
    clearly instead of leaking the Python string ``"None"`` into JSON/SARIF.
    """
    return "(unset)" if value is None else str(value)


class ProvenanceAnalyzer:
    """Detects launch-config / provenance drift against a pin baseline snapshot."""

    def analyze_server(
        self,
        server_config: ServerConfig,
        baseline: dict[str, Any] | None,
    ) -> list[ProvenanceFinding]:
        """Return provenance findings for one server.

        ``baseline`` is the pinned config snapshot (from
        ``PinStore.baseline_config``); ``None`` means no comparison is possible
        (unpinned, or pinned before config snapshots existed) and yields ``[]``.
        """
        # None (unpinned / pre-feature) or an empty/malformed snapshot → nothing to
        # compare. A real _config_snapshot always has the six keys (transport is
        # never empty), so this only short-circuits the absent/degenerate cases.
        if not baseline:
            return []

        name = server_config.name
        findings: list[ProvenanceFinding] = []

        findings.extend(self._command_finding(name, server_config, baseline))
        findings.extend(self._args_finding(name, server_config, baseline))
        findings.extend(self._url_finding(name, server_config, baseline))
        findings.extend(self._credentials_finding(name, server_config, baseline))
        return findings

    # ------------------------------------------------------------------
    # Per-class comparisons
    # ------------------------------------------------------------------

    def _command_finding(
        self, name: str, cfg: ServerConfig, baseline: dict[str, Any]
    ) -> list[ProvenanceFinding]:
        base_cmd = baseline.get("command")
        base_transport = baseline.get("transport")
        cur_transport = cfg.transport.value
        if cfg.command == base_cmd and cur_transport == base_transport:
            return []
        return [
            ProvenanceFinding(
                kind=ProvenanceKind.COMMAND,
                severity=ProvenanceSeverity.HIGH,
                server_name=name,
                summary=(
                    f"Launch command/transport for '{name}' changed since pin: "
                    f"command {base_cmd!r}→{cfg.command!r}, "
                    f"transport {base_transport!r}→{cur_transport!r}."
                ),
                baseline=f"{_disp(base_cmd)} ({base_transport})",
                current=f"{_disp(cfg.command)} ({cur_transport})",
            )
        ]

    def _args_finding(
        self, name: str, cfg: ServerConfig, baseline: dict[str, Any]
    ) -> list[ProvenanceFinding]:
        base_args = [str(a) for a in baseline.get("args", [])]
        cur_args = list(cfg.args)
        if base_args == cur_args:
            return []

        gained_flags = sorted(self._dangerous_args(cur_args) - self._dangerous_args(base_args))
        severity = ProvenanceSeverity.HIGH if gained_flags else ProvenanceSeverity.MEDIUM
        flag_note = f" Dangerous flag(s) gained: {', '.join(gained_flags)}." if gained_flags else ""
        return [
            ProvenanceFinding(
                kind=ProvenanceKind.ARGS,
                severity=severity,
                server_name=name,
                summary=(
                    f"Launch arguments for '{name}' changed since pin: "
                    f"[{' '.join(base_args)}] → [{' '.join(cur_args)}].{flag_note}"
                ),
                baseline=" ".join(base_args),
                current=" ".join(cur_args),
                gained_flags=gained_flags,
            )
        ]

    def _url_finding(self, name: str, cfg: ServerConfig, baseline: dict[str, Any]) -> list[ProvenanceFinding]:
        base_url = baseline.get("url")
        if cfg.url == base_url:
            return []
        return [
            ProvenanceFinding(
                kind=ProvenanceKind.URL,
                severity=ProvenanceSeverity.HIGH,
                server_name=name,
                summary=(f"HTTP endpoint for '{name}' changed since pin: {base_url!r}→{cfg.url!r}."),
                baseline=_disp(base_url),
                current=_disp(cfg.url),
            )
        ]

    def _credentials_finding(
        self, name: str, cfg: ServerConfig, baseline: dict[str, Any]
    ) -> list[ProvenanceFinding]:
        base_keys = set(baseline.get("env_keys", [])) | set(baseline.get("headers_keys", []))
        cur_keys = set(cfg.env_keys) | set(cfg.headers_keys)
        if base_keys == cur_keys:
            return []

        added = sorted(cur_keys - base_keys)
        removed = sorted(base_keys - cur_keys)
        parts = []
        if added:
            parts.append(f"added [{', '.join(added)}]")
        if removed:
            parts.append(f"removed [{', '.join(removed)}]")
        return [
            ProvenanceFinding(
                kind=ProvenanceKind.CREDENTIALS,
                severity=ProvenanceSeverity.MEDIUM,
                server_name=name,
                summary=(
                    f"Declared credential key names for '{name}' changed since pin: "
                    f"{'; '.join(parts)}. (Key names only — values are never inspected.)"
                ),
                baseline=", ".join(sorted(base_keys)),
                current=", ".join(sorted(cur_keys)),
            )
        ]

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _dangerous_args(self, args: list[str]) -> set[str]:
        """Return the arg tokens that START WITH a known-dangerous flag signal.

        Prefix (not substring) matching: every signal begins with ``--``, so
        ``startswith`` matches the flag itself (incl. ``--flag=value`` forms) but
        ignores a benign value that merely contains a signal string (e.g.
        ``--output-dir=/x/no-sandbox-y``).
        """
        return {arg for arg in args if any(arg.lower().startswith(sig) for sig in _DANGEROUS_FLAG_SIGNALS)}
