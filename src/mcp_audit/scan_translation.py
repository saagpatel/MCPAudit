"""Frozen, option-only legacy scan translation shared with the 3.0 interceptor.

No discovery or execution belongs here. ``preserved`` and ``narrowed`` describe
option mapping only; review source limits can still reduce coverage. ``narrowed``
means the caller explicitly selected --config-only. Known implicit coverage loss
always takes precedence and withholds the command.
"""

from __future__ import annotations

import shlex
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Literal

from mcp_audit.redaction import redact_text
from mcp_audit.review_discovery import MAX_CONFIG_BYTES, MAX_CONTAINERS, MAX_DEPTH, MAX_SERVERS

Coverage = Literal["preserved", "narrowed", "would-silently-shrink"]
OptionKind = Literal["flag", "value", "repeat"]


@dataclass(frozen=True)
class OptionTranslation:
    parameter: str
    check_option: str
    kind: OptionKind = "flag"
    default: str | int | bool | tuple[str, ...] | None = False


# Keys are scan spellings, not check spellings. Keep this independent of Click
# registration so future options cannot accidentally become accepted aliases.
OPTION_TABLE: Mapping[str, OptionTranslation] = MappingProxyType(
    {
        "--json": OptionTranslation("json_output", "--output-json", "value", None),
        "--sarif": OptionTranslation("sarif_output", "--sarif", "value", None),
        "--sarif-profile": OptionTranslation("sarif_profile", "--sarif-profile", "value", "compatibility"),
        "--html": OptionTranslation("html_output", "--html", "value", None),
        "--show-host": OptionTranslation("show_host", "--show-host"),
        "--skip-connect": OptionTranslation("skip_connect", "--skip-connect"),
        "--connect-project-configs": OptionTranslation(
            "connect_project_configs", "--connect-project-configs"
        ),
        "--clients": OptionTranslation("clients", "--client", "value", None),
        "--timeout": OptionTranslation("timeout", "--timeout", "value", 10),
        "--max-concurrency": OptionTranslation("max_concurrency", "--max-concurrency", "value", 32),
        "--max-frame-bytes": OptionTranslation(
            "max_frame_bytes", "--max-frame-bytes", "value", 16 * 1024 * 1024
        ),
        "--max-surface-bytes": OptionTranslation(
            "max_surface_bytes", "--max-surface-bytes", "value", 64 * 1024 * 1024
        ),
        "--sdk-stdio-fallback": OptionTranslation("sdk_stdio_fallback", "--sdk-stdio-fallback"),
        "--verbose": OptionTranslation("verbose", "--verbose"),
        "--details": OptionTranslation("details", "--details"),
        "--color": OptionTranslation("color", "--color", "value", "auto"),
        "--config": OptionTranslation("extra_config", "--config", "value", None),
        "--config-only": OptionTranslation("config_only", "--config-only"),
        "--override-config": OptionTranslation("override_config_path", "--override-config", "value", None),
        "--policy": OptionTranslation("policy_path", "--policy", "value", None),
        "--ignore": OptionTranslation("ignore_rules", "--ignore", "repeat", ()),
        "--ignore-reason": OptionTranslation("ignore_reason", "--ignore-reason", "value", None),
        "--inject-check": OptionTranslation("inject_check", "--inject-check"),
        "--ssrf-check": OptionTranslation("ssrf_check", "--ssrf-check"),
        "--ssrf-allowlist": OptionTranslation("ssrf_allowlist", "--ssrf-allowlist", "value", None),
        "--egress-check": OptionTranslation("egress_check", "--egress-check"),
        "--egress-allowlist": OptionTranslation("egress_allowlist", "--egress-allowlist", "value", None),
        "--multi-tenant-hosts": OptionTranslation(
            "multi_tenant_hosts", "--multi-tenant-hosts", "value", None
        ),
        "--pin-check": OptionTranslation("pin_check", "--pin-check"),
        "--pin-file": OptionTranslation("pin_file", "--pin-file", "value", None),
        "--pin-min-sequence": OptionTranslation("pin_min_sequence", "--pin-min-sequence", "value", None),
        "--trifecta-check": OptionTranslation("trifecta_check", "--trifecta-check"),
        "--shadow-check": OptionTranslation("shadow_check", "--shadow-check"),
        "--escalation-check": OptionTranslation("escalation_check", "--escalation-check"),
        "--provenance-check": OptionTranslation("provenance_check", "--provenance-check"),
        "--integrity-check": OptionTranslation("integrity_check", "--integrity-check"),
        "--verify-artifacts": OptionTranslation("verify_artifacts", "--verify-artifacts"),
        "--download-artifacts": OptionTranslation("download_artifacts", "--download-artifacts"),
        "--llm-analysis": OptionTranslation("llm_analysis", "--llm-analysis"),
        "--redact": OptionTranslation("redact", "--redact"),
        "--canary-check": OptionTranslation("canary_check", "--canary-check"),
        "--canary-calls": OptionTranslation("canary_calls", "--canary-calls", "value", 5),
        "--canary-identities": OptionTranslation("canary_identities", "--canary-identities", "value", None),
        "--canary-safe-tool": OptionTranslation("canary_safe_tools", "--canary-safe-tool", "repeat", ()),
        "--card": OptionTranslation("card", "--card", "value", None),
        "--names": OptionTranslation("names", "--names"),
        "--previous": OptionTranslation("previous", "--previous", "value", None),
    }
)

_CLIENTS = ("claude_code", "claude_desktop", "cursor", "vscode", "windsurf")


@dataclass(frozen=True)
class ScanTranslation:
    coverage: Coverage
    check_argv: tuple[str, ...] | None
    reasons: tuple[str, ...] = ()

    def notice(self) -> str:
        """Render one stderr line; unsafe argument values never enter reasons."""
        if self.check_argv is None:
            return "scan: no exact check translation exists: " + "; ".join(self.reasons)
        return (
            "scan: options map exactly to check (source coverage is not guaranteed; "
            f"check enforces a {MAX_SERVERS}-server cap per source and across accepted sources, "
            f"{MAX_CONFIG_BYTES}-byte source limit, nesting depth {MAX_DEPTH}, "
            f"{MAX_CONTAINERS} containers, and symlink refusal for discovered sources): "
            + shlex.join(self.check_argv)
        )


def classify_scan_options(options: Mapping[str, object]) -> ScanTranslation:
    """Classify parsed scan parameters without consulting configs or server state.

    Unknown parameters, unsupported spellings and values that cannot be safely
    printed are refused, including otherwise harmless options. No guessed or
    partially translated command is offered as an exact replacement.
    """
    known = {rule.parameter for rule in OPTION_TABLE.values()}
    reasons: list[str] = []
    if options.keys() - known:
        reasons.append("an option is absent from the frozen scan table")
    values = {rule.parameter: options.get(rule.parameter, rule.default) for rule in OPTION_TABLE.values()}
    argv = ["mcp-audit", "check"]
    for spelling, rule in OPTION_TABLE.items():
        value = values[rule.parameter]
        if rule.kind == "flag":
            if not isinstance(value, bool):
                reasons.append(f"{spelling} is not a parsed boolean")
            elif value:
                argv.append(rule.check_option)
            continue
        if value is None:
            continue
        if rule.kind == "repeat":
            if not isinstance(value, tuple) or not all(isinstance(item, str) for item in value):
                reasons.append(f"{spelling} is not a parsed repeated option")
                continue
            arguments = value
        elif isinstance(value, (str, Path)) or (isinstance(value, int) and not isinstance(value, bool)):
            arguments = (str(value),) if value != rule.default else ()
        else:
            reasons.append(f"{spelling} is not a parsed option value")
            continue
        for argument in arguments:
            if not argument.isprintable() or redact_text(argument) != argument:
                reasons.append(f"{spelling} cannot be safely printed as an exact single-line command")
            else:
                argv.extend((rule.check_option, argument))

    config_only = values["config_only"] is True
    if config_only and not values["extra_config"]:
        reasons.append("--config-only requires --config")
    if values["skip_connect"] is not True:
        reasons.append("scan connects by default; static check would lose connected coverage")
    if values["json_output"] is not None:
        reasons.append("--json PATH is not an exact compatibility spelling (check uses --output-json PATH)")
    clients = values["clients"]
    if clients is not None and clients not in _CLIENTS:
        reasons.append(
            "--clients must name one supported client; comma-separated selections are untranslatable"
        )
    if not config_only:
        argv.append("--include-discovered")
        if values["extra_config"] is not None:
            reasons.append(
                "scan appends explicit sources; check deduplicates them, so overlapping sources can be lost"
            )
        if clients in (None, "claude_code"):
            reasons.append("Claude Code discovery can include other project scopes that check cannot select")
        if clients in (None, "cursor"):
            reasons.append("check adds Cursor project discovery, so the selected server set can differ")
    if values["connect_project_configs"] is True:
        reasons.append("--connect-project-configs requires an explicit check connection selection")
    if values["canary_check"] is True:
        reasons.append("--canary-check requires an explicit check connection selection")
    # scan reads the default override even in config-only mode, whereas check
    # does not. Without an explicit path, options alone cannot preserve that.
    if config_only and values["override_config_path"] is None:
        reasons.append(
            "config-only scan reads default overrides; supply --override-config for an exact translation"
        )
    if reasons:
        return ScanTranslation("would-silently-shrink", None, tuple(dict.fromkeys(reasons)))
    return ScanTranslation("narrowed" if config_only else "preserved", tuple(argv))
