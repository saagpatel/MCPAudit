"""Direct-detector harness over declared server surfaces; this is not an end-to-end CLI scan.

The adapter never connects to a server, fakes a connected status, or patches the
MCP connector. Detector outputs describe only the supplied inert metadata.
"""

from __future__ import annotations

import tempfile
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Literal

from mcp_audit.analyzer import PermissionAnalyzer
from mcp_audit.egress import EgressDetector
from mcp_audit.escalation import EscalationAnalyzer
from mcp_audit.injection import InjectionDetector
from mcp_audit.integrity import IntegrityAnalyzer
from mcp_audit.models import (
    DriftFinding,
    EscalationFinding,
    IntegrityFinding,
    PackageVerifyFinding,
    ProvenanceFinding,
    ServerAudit,
    ShadowingFinding,
    SsrfFinding,
    ToolInfo,
    TrifectaFinding,
)
from mcp_audit.pinning import PinStore
from mcp_audit.pkgverify import FetchHash, PackageVerifier
from mcp_audit.provenance import ProvenanceAnalyzer
from mcp_audit.schema_rules import scan_tool_schema
from mcp_audit.shadowing import ShadowingAnalyzer
from mcp_audit.ssrf import SsrfDetector
from mcp_audit.trifecta import TrifectaAnalyzer
from redteam.surface import ServerSurface

DetectorKey = Literal[
    "permissions",
    "injection",
    "ssrf",
    "egress",
    "schema",
    "trifecta",
    "shadowing",
    "drift",
    "escalation",
    "provenance",
    "integrity",
    "pkgverify",
]
DetectorState = Literal["completed", "not_run", "disabled"]

DETECTOR_KEYS: tuple[DetectorKey, ...] = (
    "permissions",
    "injection",
    "ssrf",
    "egress",
    "schema",
    "trifecta",
    "shadowing",
    "drift",
    "escalation",
    "provenance",
    "integrity",
    "pkgverify",
)


@dataclass(frozen=True)
class IntegrityInput:
    """Expected hashes and supplied bytes, keyed by synthetic relative POSIX paths."""

    artifacts: dict[str, str]
    current_files: dict[str, bytes] = field(default_factory=dict)


def _relative_artifact(name: str) -> PurePosixPath:
    components = name.split("/")
    path = PurePosixPath(name)
    if (
        not name
        or "\\" in name
        or ":" in name
        or path.is_absolute()
        or any(part in {"", ".", ".."} or part.startswith(".") for part in components)
    ):
        raise ValueError(f"integrity artifact path must be a safe relative POSIX path: {name!r}")
    return path


def _temp_root() -> Path:
    root = Path(__file__).resolve().parents[3] / "build" / "redteam"
    root.mkdir(parents=True, exist_ok=True)
    return root


@dataclass(frozen=True)
class DetectorStatus:
    state: DetectorState
    reason: str | None = None


@dataclass(frozen=True)
class AdapterFinding:
    check_id: str
    severity: str
    tool: str | None
    detector: DetectorKey
    evidence: str


@dataclass
class AdapterResult:
    findings: list[AdapterFinding] = field(default_factory=list)
    statuses: dict[DetectorKey, DetectorStatus] = field(default_factory=dict)
    provenance: set[Literal["MOCKED"]] = field(default_factory=set)


def _severity(finding: object) -> str:
    value = getattr(finding, "severity", "info")
    return str(getattr(value, "value", value))


def _tool_name(finding: object) -> str | None:
    for name in ("tool_name", "target_name", "artifact_path", "name"):
        value = getattr(finding, name, None)
        if isinstance(value, str):
            return value
    return None


def _evidence(finding: object) -> str:
    for name in ("evidence", "details", "matched_text", "summary", "description"):
        value = getattr(finding, name, None)
        if isinstance(value, list):
            return "; ".join(item for item in value if isinstance(item, str))[:500]
        if isinstance(value, str):
            return value[:500]
    return "Detector emitted a finding."


def _check_id(finding: object, detector: DetectorKey) -> str:
    value = getattr(finding, "rule_id", None)
    if isinstance(value, str):
        return value
    # All core findings currently have taxonomy rule IDs. This fallback is
    # deliberately stable for detector models that do not expose one.
    fallback_ids: dict[DetectorKey, str] = {"drift": "MCP009"}
    return fallback_ids.get(detector, detector.upper())


def _add(
    result: AdapterResult,
    detector: DetectorKey,
    findings: Sequence[object],
) -> None:
    for finding in findings:
        result.findings.append(
            AdapterFinding(
                check_id=_check_id(finding, detector),
                severity=_severity(finding),
                tool=_tool_name(finding),
                detector=detector,
                evidence=_evidence(finding),
            )
        )


def _set_status(
    result: AdapterResult,
    key: DetectorKey,
    state: DetectorState,
    reason: str | None = None,
) -> None:
    result.statuses[key] = DetectorStatus(state=state, reason=reason)


def _audit(surface: ServerSurface, *, tools: list[ToolInfo] | None = None) -> ServerAudit:
    return ServerAudit(
        server=surface.to_config(),
        connection_status="skipped",
        tools=surface.to_tools() if tools is None else tools,
        resources=surface.to_resources(),
    )


def run_detectors(
    surface: ServerSurface,
    *,
    baseline: ServerSurface | None,
    fleet: list[ServerSurface],
    integrity: IntegrityInput | None = None,
    package_fetch: FetchHash | None = None,
    disabled: set[str] | None = None,
) -> AdapterResult:
    """Run MCPAudit's existing detectors directly over supplied metadata."""
    if baseline is not None and baseline.server_name != surface.server_name:
        raise ValueError("baseline surface must have the same server_name as current surface")
    result = AdapterResult()
    disabled_keys = disabled or set()
    unknown_disabled = disabled_keys - set(DETECTOR_KEYS)
    if unknown_disabled:
        raise ValueError(f"unknown detector key(s): {', '.join(sorted(unknown_disabled))}")
    current_tools = surface.to_tools()
    resources = surface.to_resources()
    current_audit = _audit(surface, tools=current_tools)

    def enabled(key: DetectorKey) -> bool:
        if key in disabled_keys:
            _set_status(result, key, "disabled", "disabled by caller")
            return False
        return True

    if enabled("permissions"):
        permission_analyzer = PermissionAnalyzer()
        permission_findings: list[object] = list(permission_analyzer.analyze_server(current_tools))
        permission_findings.extend(permission_analyzer.analyze_capabilities([], resources))
        for tool in current_tools:
            permission_findings.extend(permission_analyzer.analyze_annotation_contradictions(tool))
        _add(result, "permissions", permission_findings)
        _set_status(result, "permissions", "completed")

    if enabled("injection"):
        detector = InjectionDetector()
        _add(result, "injection", detector.scan_server(current_tools, resources=resources))
        _set_status(result, "injection", "completed")

    if enabled("ssrf"):
        ssrf_detector = SsrfDetector()
        ssrf_findings: list[SsrfFinding] = [
            finding for tool in current_tools for finding in ssrf_detector.scan_tool(tool)
        ]
        ssrf_findings.extend(
            finding for resource in resources for finding in ssrf_detector.scan_resource(resource)
        )
        current_audit.ssrf_findings = ssrf_findings
        _add(result, "ssrf", ssrf_findings)
        _set_status(result, "ssrf", "completed")

    if enabled("egress"):
        # Egress is static: use an empty allowlist so declared destinations are
        # surfaced for the harness; no request is issued.
        egress_findings = EgressDetector(set()).scan_server(current_audit)
        current_audit.egress_findings = egress_findings
        _add(result, "egress", egress_findings)
        _set_status(result, "egress", "completed")

    if enabled("schema"):
        schema_findings = [finding for tool in current_tools for finding in scan_tool_schema(tool)]
        _add(result, "schema", schema_findings)
        _set_status(result, "schema", "completed")

    audits = [_audit(member) for member in fleet]
    if enabled("trifecta"):
        if not fleet:
            _set_status(result, "trifecta", "not_run", "fleet companion surfaces are required")
        else:
            trifecta_analyzer = TrifectaAnalyzer()
            fleet_audits = [current_audit, *audits]
            for audit in fleet_audits:
                audit.permissions = PermissionAnalyzer().analyze_server(audit.tools)
                audit.capability_findings = PermissionAnalyzer().analyze_capabilities([], audit.resources)
                audit.injection_findings = InjectionDetector().scan_server(
                    audit.tools, resources=audit.resources
                )
                ssrf_detector = SsrfDetector()
                audit.ssrf_findings = [
                    finding for tool in audit.tools for finding in ssrf_detector.scan_tool(tool)
                ] + [
                    finding
                    for resource in audit.resources
                    for finding in ssrf_detector.scan_resource(resource)
                ]
                audit.trifecta_findings = trifecta_analyzer.analyze_server(audit)
            trifecta_findings: list[TrifectaFinding] = [
                finding for audit in fleet_audits for finding in audit.trifecta_findings
            ]
            trifecta_findings.extend(trifecta_analyzer.analyze_fleet(fleet_audits))
            _add(result, "trifecta", trifecta_findings)
            _set_status(result, "trifecta", "completed")

    if enabled("shadowing"):
        if not fleet:
            _set_status(result, "shadowing", "not_run", "fleet companion surfaces are required")
        else:
            shadowing_findings: list[ShadowingFinding] = ShadowingAnalyzer().analyze_fleet(
                [current_audit, *audits]
            )
            _add(result, "shadowing", shadowing_findings)
            _set_status(result, "shadowing", "completed")

    if enabled("drift"):
        if baseline is None:
            _set_status(result, "drift", "not_run", "baseline surface is required")
        else:
            temp_root = _temp_root()
            with tempfile.TemporaryDirectory(prefix="pin-", dir=temp_root) as tmp:
                root = Path(tmp)
                store = PinStore(
                    root / "pins.yaml",
                    signing_key=root / "signing.key",
                    trusted_keys_path=root / "trusted-keys.json",
                    unsigned=True,
                )
                baseline_tools = baseline.to_tools()
                # Passing launch config would resolve and hash command/argument
                # paths. Drift only needs the tool snapshot, so omit it.
                store.pin_server(baseline.server_name, baseline_tools)
                drift_findings: list[DriftFinding] = store.check_drift(
                    surface.server_name, current_tools, review_unsigned_v2=True
                )
            _add(result, "drift", drift_findings)
            _set_status(result, "drift", "completed")

    if enabled("escalation"):
        if baseline is None:
            _set_status(result, "escalation", "not_run", "baseline surface is required")
        else:
            escalation_findings: list[EscalationFinding] = EscalationAnalyzer().analyze_server(
                surface.server_name, baseline.to_tools(), current_tools
            )
            _add(result, "escalation", escalation_findings)
            _set_status(result, "escalation", "completed")

    if enabled("provenance"):
        if baseline is None:
            _set_status(result, "provenance", "not_run", "baseline surface is required")
        else:
            base_config = baseline.to_config()
            snapshot = {
                "command": base_config.command,
                "args": list(base_config.args),
                "url": base_config.url,
                "transport": base_config.transport.value,
                "env_keys": sorted(base_config.env_keys),
                "headers_keys": sorted(base_config.headers_keys),
            }
            provenance_findings: list[ProvenanceFinding] = ProvenanceAnalyzer().analyze_server(
                surface.to_config(), snapshot
            )
            _add(result, "provenance", provenance_findings)
            _set_status(result, "provenance", "completed")

    if enabled("integrity"):
        if integrity is None:
            _set_status(result, "integrity", "not_run", "pinned artifact hashes are required")
        else:
            expected = {_relative_artifact(name): digest for name, digest in integrity.artifacts.items()}
            current = {_relative_artifact(name): content for name, content in integrity.current_files.items()}
            temp_root = _temp_root()
            with tempfile.TemporaryDirectory(prefix="integrity-", dir=temp_root) as tmp:
                root = Path(tmp).resolve()
                for relative, content in current.items():
                    target = (root / relative).resolve()
                    if root not in target.parents:
                        raise ValueError("integrity artifact path escapes its temporary directory")
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(content)
                artifact_hashes = {str(root / name): digest for name, digest in expected.items()}
                integrity_findings: list[IntegrityFinding] = IntegrityAnalyzer().analyze_server(
                    surface.server_name, artifact_hashes
                )
                for finding in integrity_findings:
                    relative_path = Path(finding.artifact_path).relative_to(root).as_posix()
                    result.findings.append(
                        AdapterFinding(
                            check_id=_check_id(finding, "integrity"),
                            severity=_severity(finding),
                            tool=relative_path,
                            detector="integrity",
                            evidence=_evidence(finding).replace(str(root), "<integrity>"),
                        )
                    )
            _set_status(result, "integrity", "completed")

    if enabled("pkgverify"):
        if package_fetch is None:
            _set_status(result, "pkgverify", "not_run", "injected package fetch is required")
        elif baseline is None:
            _set_status(result, "pkgverify", "not_run", "baseline surface is required")
        else:
            # PackageVerifier uses ``fetch or RegistryClient().fetch_hash``;
            # wrap the injected callable so a falsey callable cannot select the
            # live registry client.
            verifier = PackageVerifier(fetch=lambda reference: package_fetch(reference))
            baseline_hashes = verifier.capture(baseline.to_config())
            package_findings: list[PackageVerifyFinding] = verifier.analyze_server(
                surface.server_name, surface.to_config(), baseline_hashes
            )
            _add(result, "pkgverify", package_findings)
            result.provenance.add("MOCKED")
            _set_status(result, "pkgverify", "completed")

    # Keep serialized results reproducible, independent of detector internals.
    result.findings.sort(key=lambda item: (item.detector, item.check_id, item.tool or "", item.evidence))
    result.statuses = {key: result.statuses[key] for key in DETECTOR_KEYS if key in result.statuses}
    return result
