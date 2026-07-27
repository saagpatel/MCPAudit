"""Offline static analysis for program-owned Agent UI contract fixtures."""

from __future__ import annotations

import html
import ipaddress
import json
import os
import stat
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any, Never
from urllib.parse import urlsplit

from pydantic import ValidationError

from mcp_audit.agent_ui_models import (
    A2UI_CATALOG_ID,
    A2UIActionContract,
    A2UIFixtureEnvelope,
    A2UIFixtureManifest,
    A2UIMessage,
    AgentUIFinding,
    AgentUIReport,
    AgentUISeverity,
    DataProvenance,
    EvidenceState,
    HostProfile,
    MCPAppsFixture,
    RenderedControl,
    VisualState,
    canonical_json_bytes,
    sha256_bytes,
)

_MAX_INPUT_BYTES = 1_048_576
_MAX_JSONL_LINES = 256
_MAX_JSONL_LINE_BYTES = 65_536
_MAX_COMPONENTS = 2_048
_MAX_TREE_DEPTH = 64
_MAX_JSON_DEPTH = 64

_SUPPORTED_INPUTS = [
    "One strict program-owned MCP Apps metadata fixture using mcpaudit.agent-ui.mcp-apps-fixture.v1.",
    "One program-owned A2UI fixture manifest line followed by A2UI v0.9 JSONL messages.",
    f"A2UI components from the fixed synthetic catalog {A2UI_CATALOG_ID}.",
]

_UNSUPPORTED_INPUTS = [
    "Widget HTML, JavaScript, CSS, binaries, remote resources, MCP server connections, and authentication.",
    "Real MCP client/server configuration, real user data, transcripts, credentials, and host runtime state.",
    "A2UI v0.8, v0.9 catalogs other than the fixed synthetic catalog, v1.0, inline catalogs, "
    "client-to-server messages, transport metadata, and custom components.",
    "AG-UI, WebMCP, protocol translation, transport interoperability, and host-behavior equivalence.",
]

_CLAIM_CEILING = [
    "Findings describe contradictions in program-owned static fixtures only.",
    "A clean report does not prove a widget, renderer, host, MCP server, transport, approval flow, "
    "sandbox, CSP enforcement, or authentication implementation is safe.",
    "MCP Apps, OpenAI-specific metadata, and A2UI remain distinct input profiles; no interoperability "
    "between them is tested or claimed.",
    "Unsupported, ambiguous, malformed-but-parseable, or unbound constructs remain UNKNOWN.",
]

_RULES: dict[str, tuple[AgentUISeverity, str, str]] = {
    "MCPUI000": (
        AgentUISeverity.UNKNOWN,
        "Unsupported or ambiguous Agent UI construct",
        "Reduce the fixture to a supported program-owned profile or extend the scanner with an explicit "
        "schema, host assumption, and negative control.",
    ),
    "MCPUI001": (
        AgentUISeverity.HIGH,
        "Rendered authority understates invoked tool authority",
        "Make the rendered disclosure cover every invoked authority effect, or reduce the tool authority "
        "to the disclosed least-privilege boundary.",
    ),
    "MCPUI002": (
        AgentUISeverity.HIGH,
        "Approval or widget state is stale",
        "Bind the control to the current approval identifier and version, reject stale state, and require "
        "a fresh approval after authority-relevant changes.",
    ),
    "MCPUI003": (
        AgentUISeverity.HIGH,
        "Tool invocation is hidden or surprising",
        "Render an explicit, visible action disclosure naming the invoked tool and material effect before "
        "the user can trigger it.",
    ),
    "MCPUI004": (
        AgentUISeverity.HIGH,
        "Untrusted tool output influences an approval control",
        "Keep approval labels, enabled state, evidence state, and version bindings on host-owned or "
        "independently trusted data; render tool output as untrusted context only.",
    ),
    "MCPUI005": (
        AgentUISeverity.HIGH,
        "Unknown evidence is rendered as passing",
        "Render unknown or unverifiable evidence neutrally and block any pass/green presentation until "
        "the evidence becomes current and independently bound.",
    ),
    "MCPUI006": (
        AgentUISeverity.HIGH,
        "External link or data sink is undeclared",
        "Declare the exact external origin in the program contract and the host-specific CSP or redirect "
        "allowlist; otherwise remove the external action.",
    ),
}

_SEVERITY_ORDER = {
    AgentUISeverity.CRITICAL: 0,
    AgentUISeverity.HIGH: 1,
    AgentUISeverity.MEDIUM: 2,
    AgentUISeverity.LOW: 3,
    AgentUISeverity.UNKNOWN: 4,
}
_EVIDENCE_STATES = {item.value for item in EvidenceState}
_VISUAL_STATES = {item.value for item in VisualState}

_MCP_ASSUMPTIONS = [
    "Tool authority is taken only from the program-owned audit_contract sidecar.",
    "MCP Apps metadata is inspected statically; no UI resource is fetched or rendered.",
]
_A2UI_ASSUMPTIONS = [
    f"A2UI v0.9 is interpreted only with the fixed synthetic catalog {A2UI_CATALOG_ID}.",
    "JSONL ordering is inspected as file order; no transport delivery, renderer, or host behavior is tested.",
]

_A2UI_COMPONENT_FIELDS: dict[str, set[str]] = {
    "Column": {"id", "component", "children"},
    "Text": {"id", "component", "text", "variant"},
    "Button": {
        "id",
        "component",
        "text",
        "child",
        "variant",
        "action",
        "disclosedAuthority",
        "approvalVersion",
        "evidenceState",
        "visualState",
        "checks",
        "enabled",
    },
    "StatusBadge": {"id", "component", "label", "state", "tone"},
    "ExternalLink": {"id", "component", "label", "url", "sendsData"},
}


class AgentUIInputError(ValueError):
    """The input could not be safely read as a fixture."""


def _reject_json_constant(value: str) -> Never:
    raise ValueError(f"unsupported JSON constant: {value}")


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in pairs:
        if key in output:
            raise ValueError(f"duplicate JSON key: {key}")
        output[key] = value
    return output


def _load_json(value: bytes) -> Any:
    return json.loads(
        value,
        object_pairs_hook=_object_without_duplicates,
        parse_constant=_reject_json_constant,
    )


def _validate_json_nesting(value: bytes) -> None:
    depth = 0
    in_string = False
    escaped = False
    for byte in value:
        if in_string:
            if escaped:
                escaped = False
            elif byte == 0x5C:
                escaped = True
            elif byte == 0x22:
                in_string = False
            continue
        if byte == 0x22:
            in_string = True
        elif byte in {0x5B, 0x7B}:
            depth += 1
            if depth > _MAX_JSON_DEPTH:
                raise AgentUIInputError(f"JSON nesting exceeds {_MAX_JSON_DEPTH} levels")
        elif byte in {0x5D, 0x7D}:
            depth = max(0, depth - 1)


def _validation_evidence(exc: ValidationError) -> str:
    error = exc.errors(include_input=False, include_url=False)[0]
    location = "/".join(str(item) for item in error.get("loc", ())) or "<root>"
    return f"schema validation failed at {location}: {error.get('type', 'invalid')}"


def _finding(
    rule_id: str,
    *,
    target: str,
    evidence: Iterable[str],
    protocol: str,
    host_profile: str,
    assumptions: list[str],
) -> AgentUIFinding:
    severity, title, remediation = _RULES[rule_id]
    return AgentUIFinding(
        rule_id=rule_id,  # type: ignore[arg-type]
        severity=severity,
        title=title,
        target=target,
        evidence=sorted(set(evidence)),
        remediation=remediation,
        protocol=protocol,  # type: ignore[arg-type]
        host_profile=host_profile,
        assumptions=assumptions,
    )


def _unknown(
    *,
    target: str,
    evidence: str,
    protocol: str,
    host_profile: str,
    assumptions: list[str],
) -> AgentUIFinding:
    return _finding(
        "MCPUI000",
        target=target,
        evidence=[evidence],
        protocol=protocol,
        host_profile=host_profile,
        assumptions=assumptions,
    )


def _sort_findings(findings: list[AgentUIFinding]) -> list[AgentUIFinding]:
    unique: dict[tuple[str, str, tuple[str, ...]], AgentUIFinding] = {}
    for finding in findings:
        key = (finding.rule_id, finding.target, tuple(finding.evidence))
        unique[key] = finding
    return sorted(
        unique.values(),
        key=lambda item: (
            _SEVERITY_ORDER[item.severity],
            item.rule_id,
            item.target,
            item.evidence,
        ),
    )


def _verdict(findings: list[AgentUIFinding]) -> str:
    if any(finding.severity is not AgentUISeverity.UNKNOWN for finding in findings):
        return "fail"
    if findings:
        return "unknown"
    return "pass"


def _report(
    *,
    fixture_id: str,
    input_kind: str,
    protocol: str,
    protocol_version: str,
    host_profile: str,
    input_sha256: str,
    findings: list[AgentUIFinding],
    assumptions: list[str],
) -> AgentUIReport:
    ordered = _sort_findings(findings)
    return AgentUIReport(
        fixture_id=fixture_id,
        input_kind=input_kind,  # type: ignore[arg-type]
        protocol=protocol,  # type: ignore[arg-type]
        protocol_version=protocol_version,
        host_profile=host_profile,
        input_sha256=input_sha256,
        verdict=_verdict(ordered),  # type: ignore[arg-type]
        findings=ordered,
        assumptions=assumptions,
        supported_inputs=_SUPPORTED_INPUTS,
        unsupported_inputs=_UNSUPPORTED_INPUTS,
        claim_ceiling=_CLAIM_CEILING,
    )


def _unknown_report(
    digest: str,
    evidence: str,
    *,
    protocol: str = "unknown",
    input_kind: str = "unknown",
    fixture_id: str = "unknown",
    protocol_version: str = "unknown",
    host_profile: str = "unknown",
    assumptions: list[str] | None = None,
) -> AgentUIReport:
    active_assumptions = assumptions or [
        "The input profile could not be established from the supported program-owned contracts."
    ]
    return _report(
        fixture_id=fixture_id,
        input_kind=input_kind,
        protocol=protocol,
        protocol_version=protocol_version,
        host_profile=host_profile,
        input_sha256=digest,
        findings=[
            _unknown(
                target=fixture_id,
                evidence=evidence,
                protocol=protocol,
                host_profile=host_profile,
                assumptions=active_assumptions,
            )
        ],
        assumptions=active_assumptions,
    )


def scan_agent_ui_path(path: Path) -> AgentUIReport:
    """Scan one program-owned JSON or JSONL fixture without external effects."""
    raw = _read_fixture_bytes(path)
    digest = sha256_bytes(raw)
    if path.suffix == ".jsonl":
        return _scan_a2ui_jsonl(raw, digest)
    if path.suffix == ".json":
        return _scan_mcp_apps_json(raw, digest)
    return _unknown_report(digest, "only .json and .jsonl fixture inputs are supported")


def _read_fixture_bytes(path: Path) -> bytes:
    """Read one identity-bound regular file without exceeding the input budget."""
    try:
        before = path.lstat()
    except OSError as exc:
        raise AgentUIInputError(f"cannot inspect input fixture: {path}") from exc
    if not stat.S_ISREG(before.st_mode):
        raise AgentUIInputError("input fixture must be a regular non-symlink file")

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise AgentUIInputError("input fixture must be a regular non-symlink file") from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise AgentUIInputError("input fixture must be a regular non-symlink file")
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise AgentUIInputError("input fixture changed while it was being opened")
        if opened.st_size > _MAX_INPUT_BYTES:
            raise AgentUIInputError(f"input fixture exceeds {_MAX_INPUT_BYTES} bytes")

        chunks: list[bytes] = []
        remaining = _MAX_INPUT_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > _MAX_INPUT_BYTES:
            raise AgentUIInputError(f"input fixture exceeds {_MAX_INPUT_BYTES} bytes")
        return raw
    finally:
        os.close(descriptor)


def _scan_mcp_apps_json(raw: bytes, digest: str) -> AgentUIReport:
    try:
        _validate_json_nesting(raw)
        payload = _load_json(raw)
    except AgentUIInputError:
        raise
    except RecursionError as exc:
        raise AgentUIInputError("invalid JSON fixture: recursion limit exceeded") from exc
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise AgentUIInputError(f"invalid JSON fixture: {type(exc).__name__}") from exc
    if not isinstance(payload, dict):
        return _unknown_report(digest, "MCP Apps fixture root must be a JSON object")
    raw_fixture_id = payload.get("fixture_id")
    fixture_id: str = raw_fixture_id if isinstance(raw_fixture_id, str) else "unknown"
    try:
        fixture = MCPAppsFixture.model_validate(payload, strict=True)
    except ValidationError as exc:
        return _unknown_report(
            digest,
            _validation_evidence(exc),
            protocol="mcp-apps",
            input_kind="mcp-apps-metadata",
            fixture_id=fixture_id,
            protocol_version=str(payload.get("protocol_profile", "unknown")),
            host_profile=str(payload.get("host_profile", "unknown")),
            assumptions=_MCP_ASSUMPTIONS,
        )
    findings = _scan_mcp_apps_fixture(fixture)
    return _report(
        fixture_id=fixture.fixture_id,
        input_kind="mcp-apps-metadata",
        protocol="mcp-apps",
        protocol_version=fixture.protocol_profile,
        host_profile=str(fixture.host_profile),
        input_sha256=digest,
        findings=findings,
        assumptions=_MCP_ASSUMPTIONS,
    )


def _scan_mcp_apps_fixture(fixture: MCPAppsFixture) -> list[AgentUIFinding]:
    findings: list[AgentUIFinding] = []
    host = str(fixture.host_profile)
    tools = {tool.name: tool for tool in fixture.tools}
    resources = {resource.uri: resource for resource in fixture.resources}
    if len(tools) != len(fixture.tools):
        findings.append(
            _unknown(
                target=fixture.fixture_id,
                evidence="duplicate tool names make action binding ambiguous",
                protocol="mcp-apps",
                host_profile=host,
                assumptions=_MCP_ASSUMPTIONS,
            )
        )
    if len(resources) != len(fixture.resources):
        findings.append(
            _unknown(
                target=fixture.fixture_id,
                evidence="duplicate resource URIs make UI binding ambiguous",
                protocol="mcp-apps",
                host_profile=host,
                assumptions=_MCP_ASSUMPTIONS,
            )
        )

    for destination in fixture.declared_external_destinations:
        if _origin(destination) is None:
            findings.append(
                _unknown(
                    target=fixture.fixture_id,
                    evidence=f"declared external destination is not a supported HTTPS origin: {destination}",
                    protocol="mcp-apps",
                    host_profile=host,
                    assumptions=_MCP_ASSUMPTIONS,
                )
            )

    for tool in fixture.tools:
        standard = tool.meta.ui.resource_uri
        alias = tool.meta.openai_output_template
        if fixture.host_profile == HostProfile.GENERIC_MCP_APPS.value and any(
            value is not None
            for value in (
                alias,
                tool.meta.openai_widget_accessible,
                tool.meta.openai_visibility,
            )
        ):
            findings.append(
                _unknown(
                    target=tool.name,
                    evidence="generic MCP Apps profile cannot consume OpenAI-specific tool metadata",
                    protocol="mcp-apps",
                    host_profile=host,
                    assumptions=_MCP_ASSUMPTIONS,
                )
            )
        if (
            fixture.host_profile == HostProfile.OPENAI_CHATGPT.value
            and standard
            and alias
            and standard != alias
        ):
            findings.append(
                _unknown(
                    target=tool.name,
                    evidence="_meta.ui.resourceUri conflicts with openai/outputTemplate",
                    protocol="mcp-apps",
                    host_profile=host,
                    assumptions=_MCP_ASSUMPTIONS,
                )
            )
        if (
            fixture.host_profile == HostProfile.OPENAI_CHATGPT.value
            and tool.meta.openai_visibility is not None
        ):
            model_visible = "model" in tool.meta.ui.visibility
            openai_public = tool.meta.openai_visibility == "public"
            if model_visible != openai_public:
                findings.append(
                    _unknown(
                        target=tool.name,
                        evidence=("_meta.ui.visibility conflicts with openai/visibility for model access"),
                        protocol="mcp-apps",
                        host_profile=host,
                        assumptions=_MCP_ASSUMPTIONS,
                    )
                )

    if fixture.host_profile == HostProfile.GENERIC_MCP_APPS.value:
        for resource_descriptor in fixture.resources:
            openai_csp = resource_descriptor.meta.openai_widget_csp
            if any(
                (
                    resource_descriptor.meta.openai_widget_description is not None,
                    resource_descriptor.meta.openai_widget_domain is not None,
                    bool(openai_csp.connect_domains),
                    bool(openai_csp.resource_domains),
                    bool(openai_csp.frame_domains),
                    bool(openai_csp.redirect_domains),
                )
            ):
                findings.append(
                    _unknown(
                        target=resource_descriptor.uri,
                        evidence="generic MCP Apps profile cannot consume OpenAI-specific resource metadata",
                        protocol="mcp-apps",
                        host_profile=host,
                        assumptions=_MCP_ASSUMPTIONS,
                    )
                )

    for resource_descriptor in fixture.resources:
        findings.extend(_resource_metadata_findings(fixture, resource_descriptor))

    for control in fixture.rendered_controls:
        resource = resources.get(control.resource_uri)
        if resource is None:
            findings.append(
                _unknown(
                    target=control.component_id,
                    evidence="rendered control references an undeclared UI resource",
                    protocol="mcp-apps",
                    host_profile=host,
                    assumptions=_MCP_ASSUMPTIONS,
                )
            )
        bound_tool = tools.get(control.action.target) if control.action.kind == "tool_call" else None
        if control.action.kind == "tool_call" and bound_tool is None:
            findings.append(
                _unknown(
                    target=control.component_id,
                    evidence="rendered control invokes a tool absent from the fixture contract",
                    protocol="mcp-apps",
                    host_profile=host,
                    assumptions=_MCP_ASSUMPTIONS,
                )
            )
            continue
        if bound_tool is not None:
            linked_uri = bound_tool.meta.ui.resource_uri
            if fixture.host_profile == HostProfile.OPENAI_CHATGPT.value:
                linked_uri = linked_uri or bound_tool.meta.openai_output_template
            if linked_uri != control.resource_uri:
                findings.append(
                    _unknown(
                        target=control.component_id,
                        evidence="rendered control resource does not match the tool UI metadata binding",
                        protocol="mcp-apps",
                        host_profile=host,
                        assumptions=_MCP_ASSUMPTIONS,
                    )
                )
            accessibility_reasons: list[str] = []
            if "app" not in bound_tool.meta.ui.visibility:
                accessibility_reasons.append("_meta.ui.visibility excludes app access")
            if (
                fixture.host_profile == HostProfile.OPENAI_CHATGPT.value
                and bound_tool.meta.openai_widget_accessible is not True
            ):
                accessibility_reasons.append("openai/widgetAccessible is not true")
            if accessibility_reasons:
                findings.append(
                    _unknown(
                        target=control.component_id,
                        evidence="; ".join(accessibility_reasons),
                        protocol="mcp-apps",
                        host_profile=host,
                        assumptions=_MCP_ASSUMPTIONS,
                    )
                )
            missing = sorted(set(bound_tool.audit_contract.authority) - set(control.disclosed_authority))
            if missing:
                findings.append(
                    _finding(
                        "MCPUI001",
                        target=control.component_id,
                        evidence=[
                            f"invoked tool: {bound_tool.name}",
                            f"undisclosed authority: {', '.join(missing)}",
                        ],
                        protocol="mcp-apps",
                        host_profile=host,
                        assumptions=_MCP_ASSUMPTIONS,
                    )
                )
            if not control.visible or not control.disclosed:
                hidden_reasons = []
                if not control.visible:
                    hidden_reasons.append("control is not visible")
                if not control.disclosed:
                    hidden_reasons.append("tool invocation is not disclosed")
                findings.append(
                    _finding(
                        "MCPUI003",
                        target=control.component_id,
                        evidence=[f"invoked tool: {bound_tool.name}", *hidden_reasons],
                        protocol="mcp-apps",
                        host_profile=host,
                        assumptions=_MCP_ASSUMPTIONS,
                    )
                )
            findings.extend(
                _approval_findings(
                    control,
                    expected_version=bound_tool.audit_contract.approval_version,
                    required=bound_tool.audit_contract.requires_approval,
                    protocol="mcp-apps",
                    host_profile=host,
                    assumptions=_MCP_ASSUMPTIONS,
                )
            )
        if control.action.kind in {"external_link", "data_sink"} and resource is not None:
            findings.extend(_external_findings(fixture, control, resource))
    return findings


def _approval_findings(
    control: RenderedControl,
    *,
    expected_version: str | None,
    required: bool,
    protocol: str,
    host_profile: str,
    assumptions: list[str],
) -> list[AgentUIFinding]:
    findings: list[AgentUIFinding] = []
    approval = control.approval
    if not required:
        return findings
    if approval is None:
        return [
            _unknown(
                target=control.component_id,
                evidence="approval-required action has no approval presentation contract",
                protocol=protocol,
                host_profile=host_profile,
                assumptions=assumptions,
            )
        ]
    stale_reasons: list[str] = []
    if not approval.required:
        stale_reasons.append("approval presentation marks the required action as not requiring approval")
    if approval.evidence_state == EvidenceState.STALE.value:
        stale_reasons.append("approval evidence state is stale")
    if expected_version is None:
        findings.append(
            _unknown(
                target=control.component_id,
                evidence="approval-required tool contract has no authoritative expected version",
                protocol=protocol,
                host_profile=host_profile,
                assumptions=assumptions,
            )
        )
    elif approval.expected_version not in {None, expected_version}:
        stale_reasons.append(
            f"presentation expected version {approval.expected_version} "
            f"does not match tool contract {expected_version}"
        )
    if expected_version is not None and approval.displayed_version != expected_version:
        stale_reasons.append(
            f"displayed version {approval.displayed_version or '<missing>'} "
            f"does not match expected {expected_version}"
        )
    if stale_reasons:
        findings.append(
            _finding(
                "MCPUI002",
                target=control.component_id,
                evidence=stale_reasons,
                protocol=protocol,
                host_profile=host_profile,
                assumptions=assumptions,
            )
        )
    if DataProvenance.UNTRUSTED_TOOL_OUTPUT.value in approval.input_sources:
        findings.append(
            _finding(
                "MCPUI004",
                target=control.component_id,
                evidence=["approval presentation depends on untrusted_tool_output"],
                protocol=protocol,
                host_profile=host_profile,
                assumptions=assumptions,
            )
        )
    if DataProvenance.UNKNOWN.value in approval.input_sources:
        findings.append(
            _unknown(
                target=control.component_id,
                evidence="approval presentation has unknown input provenance",
                protocol=protocol,
                host_profile=host_profile,
                assumptions=assumptions,
            )
        )
    if (
        approval.evidence_state in {EvidenceState.UNKNOWN.value, EvidenceState.UNVERIFIABLE.value}
        and approval.visual_state == VisualState.PASS.value
    ):
        findings.append(
            _finding(
                "MCPUI005",
                target=control.component_id,
                evidence=[
                    f"evidence state is {approval.evidence_state}",
                    "visual state is pass",
                ],
                protocol=protocol,
                host_profile=host_profile,
                assumptions=assumptions,
            )
        )
    return findings


def _origin(value: str) -> str | None:
    if not value or "\\" in value or any(character.isspace() for character in value):
        return None
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        return None
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or not parsed.hostname
    ):
        return None
    hostname = parsed.hostname
    if not hostname.isascii() or "%" in hostname or hostname.endswith("."):
        return None
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        if len(hostname) > 253:
            return None
        labels = hostname.split(".")
        if any(
            not label
            or len(label) > 63
            or not label[0].isalnum()
            or not label[-1].isalnum()
            or any(not (character.isalnum() or character == "-") for character in label)
            for label in labels
        ):
            return None
        normalized_host = hostname.lower()
    else:
        normalized_host = f"[{address.compressed}]" if address.version == 6 else address.compressed
    effective_port = 443 if port is None else port
    if parsed.netloc.endswith(":") or not 1 <= effective_port <= 65_535:
        return None
    port_suffix = "" if port in {None, 443} else f":{port}"
    return f"https://{normalized_host}{port_suffix}"


def _normalized_origins(values: Iterable[str]) -> set[str]:
    return {origin for value in values if (origin := _origin(value)) is not None}


def _resource_metadata_findings(fixture: MCPAppsFixture, resource: Any) -> list[AgentUIFinding]:
    """Validate supported URL syntax and reconcile dual OpenAI metadata."""
    host = str(fixture.host_profile)
    findings: list[AgentUIFinding] = []
    standard = resource.meta.ui
    openai = resource.meta.openai_widget_csp
    url_fields: list[tuple[str, str]] = []
    for label, values in (
        ("_meta.ui.csp.connectDomains", standard.csp.connect_domains),
        ("_meta.ui.csp.resourceDomains", standard.csp.resource_domains),
        ("_meta.ui.csp.frameDomains", standard.csp.frame_domains),
        ("openai/widgetCSP.connect_domains", openai.connect_domains),
        ("openai/widgetCSP.resource_domains", openai.resource_domains),
        ("openai/widgetCSP.frame_domains", openai.frame_domains),
        ("openai/widgetCSP.redirect_domains", openai.redirect_domains),
    ):
        url_fields.extend((label, value) for value in values)
    for label, value in (
        ("_meta.ui.domain", standard.domain),
        ("openai/widgetDomain", resource.meta.openai_widget_domain),
    ):
        if value is not None:
            url_fields.append((label, value))
    for label, value in url_fields:
        if _origin(value) is None:
            findings.append(
                _unknown(
                    target=resource.uri,
                    evidence=f"{label} contains an unsupported HTTPS origin: {value}",
                    protocol="mcp-apps",
                    host_profile=host,
                    assumptions=_MCP_ASSUMPTIONS,
                )
            )

    if fixture.host_profile != HostProfile.OPENAI_CHATGPT.value:
        return findings

    if standard.domain is not None and resource.meta.openai_widget_domain is not None:
        standard_domain = _origin(standard.domain)
        openai_domain = _origin(resource.meta.openai_widget_domain)
        if standard_domain is not None and openai_domain is not None and standard_domain != openai_domain:
            findings.append(
                _unknown(
                    target=resource.uri,
                    evidence="_meta.ui.domain conflicts with openai/widgetDomain",
                    protocol="mcp-apps",
                    host_profile=host,
                    assumptions=_MCP_ASSUMPTIONS,
                )
            )

    for standard_name, standard_values, openai_name, openai_values in (
        (
            "_meta.ui.csp.connectDomains",
            standard.csp.connect_domains,
            "openai/widgetCSP.connect_domains",
            openai.connect_domains,
        ),
        (
            "_meta.ui.csp.resourceDomains",
            standard.csp.resource_domains,
            "openai/widgetCSP.resource_domains",
            openai.resource_domains,
        ),
        (
            "_meta.ui.csp.frameDomains",
            standard.csp.frame_domains,
            "openai/widgetCSP.frame_domains",
            openai.frame_domains,
        ),
    ):
        standard_origins = _normalized_origins(standard_values)
        openai_origins = _normalized_origins(openai_values)
        if standard_origins != openai_origins:
            findings.append(
                _unknown(
                    target=resource.uri,
                    evidence=f"{standard_name} conflicts with {openai_name}",
                    protocol="mcp-apps",
                    host_profile=host,
                    assumptions=_MCP_ASSUMPTIONS,
                )
            )
    return findings


def _external_findings(
    fixture: MCPAppsFixture,
    control: RenderedControl,
    resource: Any,
) -> list[AgentUIFinding]:
    destination = control.action.destination
    if destination is None:
        return []
    origin = _origin(destination)
    host = str(fixture.host_profile)
    if origin is None:
        return [
            _unknown(
                target=control.component_id,
                evidence="external destination is not an absolute credential-free HTTPS URL",
                protocol="mcp-apps",
                host_profile=host,
                assumptions=_MCP_ASSUMPTIONS,
            )
        ]
    declared = _normalized_origins(fixture.declared_external_destinations)
    if control.action.kind == "data_sink" or control.action.sends_data:
        host_allowlist = _normalized_origins(resource.meta.ui.csp.connect_domains)
        if fixture.host_profile == HostProfile.OPENAI_CHATGPT.value:
            host_allowlist |= _normalized_origins(resource.meta.openai_widget_csp.connect_domains)
        allowlist_name = "connect-domain allowlist"
    else:
        if fixture.host_profile == HostProfile.OPENAI_CHATGPT.value:
            host_allowlist = _normalized_origins(resource.meta.openai_widget_csp.redirect_domains)
            allowlist_name = "openai/widgetCSP.redirect_domains"
        else:
            if origin in declared:
                return [
                    _unknown(
                        target=control.component_id,
                        evidence=(
                            "generic MCP Apps profile has no tested host-specific external-link allowlist"
                        ),
                        protocol="mcp-apps",
                        host_profile=host,
                        assumptions=_MCP_ASSUMPTIONS,
                    )
                ]
            host_allowlist = set()
            allowlist_name = "program-owned external-link declaration"
    missing: list[str] = []
    if origin not in declared:
        missing.append("program contract")
    if origin not in host_allowlist:
        missing.append(allowlist_name)
    if not missing:
        return []
    return [
        _finding(
            "MCPUI006",
            target=control.component_id,
            evidence=[
                f"external origin: {origin}",
                f"missing declaration: {', '.join(missing)}",
            ],
            protocol="mcp-apps",
            host_profile=host,
            assumptions=_MCP_ASSUMPTIONS,
        )
    ]


def _scan_a2ui_jsonl(raw: bytes, digest: str) -> AgentUIReport:
    lines = raw.splitlines()
    if not lines:
        raise AgentUIInputError("A2UI JSONL fixture is empty")
    if len(lines) > _MAX_JSONL_LINES:
        raise AgentUIInputError(f"A2UI JSONL fixture exceeds {_MAX_JSONL_LINES} lines")
    if any(len(line) > _MAX_JSONL_LINE_BYTES for line in lines):
        raise AgentUIInputError(f"A2UI JSONL line exceeds {_MAX_JSONL_LINE_BYTES} bytes")
    if any(not line.strip() for line in lines):
        return _unknown_report(
            digest,
            "blank JSONL lines are outside the supported fixture profile",
            protocol="a2ui",
            input_kind="a2ui-jsonl",
            assumptions=_A2UI_ASSUMPTIONS,
        )
    try:
        _validate_json_nesting(lines[0])
        envelope_payload = _load_json(lines[0])
    except AgentUIInputError:
        raise
    except RecursionError as exc:
        raise AgentUIInputError("invalid A2UI manifest JSON: recursion limit exceeded") from exc
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise AgentUIInputError(f"invalid A2UI manifest JSON: {type(exc).__name__}") from exc
    fixture_id = "unknown"
    if isinstance(envelope_payload, dict):
        fixture_payload = envelope_payload.get("fixture")
        if isinstance(fixture_payload, dict) and isinstance(fixture_payload.get("fixture_id"), str):
            fixture_id = fixture_payload["fixture_id"]
    try:
        envelope = A2UIFixtureEnvelope.model_validate(envelope_payload, strict=True)
    except ValidationError as exc:
        return _unknown_report(
            digest,
            _validation_evidence(exc),
            protocol="a2ui",
            input_kind="a2ui-jsonl",
            fixture_id=fixture_id,
            protocol_version="v0.9",
            host_profile=HostProfile.PROGRAM_OWNED_A2UI.value,
            assumptions=_A2UI_ASSUMPTIONS,
        )

    messages: list[A2UIMessage] = []
    parse_findings: list[AgentUIFinding] = []
    for index, line in enumerate(lines[1:], start=2):
        try:
            _validate_json_nesting(line)
            payload = _load_json(line)
            messages.append(A2UIMessage.model_validate(payload, strict=True))
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError, ValidationError, RecursionError) as exc:
            evidence = (
                _validation_evidence(exc)
                if isinstance(exc, ValidationError)
                else (
                    f"line {index} exceeds the supported JSON nesting budget"
                    if isinstance(exc, (AgentUIInputError, RecursionError))
                    else f"line {index} is not supported: {type(exc).__name__}"
                )
            )
            parse_findings.append(
                _unknown(
                    target=f"line:{index}",
                    evidence=evidence,
                    protocol="a2ui",
                    host_profile=HostProfile.PROGRAM_OWNED_A2UI.value,
                    assumptions=_A2UI_ASSUMPTIONS,
                )
            )
    semantic_findings = _scan_a2ui_messages(envelope.fixture, messages)
    findings = [*parse_findings, *semantic_findings]
    return _report(
        fixture_id=envelope.fixture.fixture_id,
        input_kind="a2ui-jsonl",
        protocol="a2ui",
        protocol_version=envelope.fixture.protocol_version,
        host_profile=HostProfile.PROGRAM_OWNED_A2UI.value,
        input_sha256=digest,
        findings=findings,
        assumptions=_A2UI_ASSUMPTIONS,
    )


class _A2UISurface:
    def __init__(self, catalog_id: str) -> None:
        self.catalog_id = catalog_id
        self.components: dict[str, dict[str, Any]] = {}
        self.data: Any = {}


def _scan_a2ui_messages(
    manifest: A2UIFixtureManifest,
    messages: list[A2UIMessage],
) -> list[AgentUIFinding]:
    findings: list[AgentUIFinding] = []
    historical_findings: list[AgentUIFinding] = []
    surfaces: dict[str, _A2UISurface] = {}
    total_components = 0
    action_contracts = {item.action_name: item for item in manifest.action_contracts}
    evidence_contracts = {item.component_id: item for item in manifest.evidence_contracts}

    def capture_surface(
        surface_id: str,
        surface: _A2UISurface,
        *,
        retain_unknown: bool,
    ) -> None:
        snapshot_findings = _scan_a2ui_surface(
            manifest,
            surface_id,
            surface,
            action_contracts,
            evidence_contracts,
        )
        historical_findings.extend(
            finding
            for finding in snapshot_findings
            if retain_unknown or finding.severity is not AgentUISeverity.UNKNOWN
        )

    if not messages:
        findings.append(_a2ui_unknown(manifest.fixture_id, "fixture contains no A2UI messages"))
    for destination in manifest.declared_external_destinations:
        if _origin(destination) is None:
            findings.append(
                _a2ui_unknown(
                    manifest.fixture_id,
                    f"declared external destination is not a supported HTTPS origin: {destination}",
                )
            )

    for index, message in enumerate(messages, start=2):
        if message.create_surface is not None:
            create_item = message.create_surface
            if create_item.surface_id in surfaces:
                findings.append(_a2ui_unknown(f"line:{index}", "surface is created more than once"))
                continue
            if create_item.catalog_id != manifest.catalog_id:
                findings.append(
                    _a2ui_unknown(
                        f"surface:{create_item.surface_id}",
                        f"unsupported catalog ID: {create_item.catalog_id}",
                    )
                )
            surfaces[create_item.surface_id] = _A2UISurface(create_item.catalog_id)
            continue
        if message.update_components is not None:
            components_item = message.update_components
            surface = surfaces.get(components_item.surface_id)
            if surface is None:
                findings.append(_a2ui_unknown(f"line:{index}", "component update precedes createSurface"))
                continue
            if surface.components:
                capture_surface(components_item.surface_id, surface, retain_unknown=False)
            total_components += len(components_item.components)
            if total_components > _MAX_COMPONENTS:
                findings.append(
                    _a2ui_unknown(
                        f"surface:{components_item.surface_id}",
                        f"component budget exceeded ({_MAX_COMPONENTS})",
                    )
                )
                break
            for component_model in components_item.components:
                component = component_model.model_dump(
                    mode="python",
                    by_alias=True,
                    exclude_none=True,
                )
                component_id = component.get("id")
                component_type = component.get("component")
                if not isinstance(component_id, str) or not component_id:
                    findings.append(_a2ui_unknown(f"line:{index}", "component has no stable string id"))
                    continue
                if not isinstance(component_type, str) or component_type not in _A2UI_COMPONENT_FIELDS:
                    findings.append(
                        _a2ui_unknown(
                            f"component:{component_id}",
                            f"unsupported component type: {component_type!s}",
                        )
                    )
                    continue
                unexpected = sorted(set(component) - _A2UI_COMPONENT_FIELDS[component_type])
                if unexpected:
                    findings.append(
                        _a2ui_unknown(
                            f"component:{component_id}",
                            f"unsupported {component_type} fields: {', '.join(unexpected)}",
                        )
                    )
                    continue
                surface.components[component_id] = component
            continue
        if message.update_data_model is not None:
            data_item = message.update_data_model
            surface = surfaces.get(data_item.surface_id)
            if surface is None:
                findings.append(_a2ui_unknown(f"line:{index}", "data-model update precedes createSurface"))
                continue
            if surface.data != {}:
                capture_surface(data_item.surface_id, surface, retain_unknown=False)
            try:
                surface.data = _set_pointer(surface.data, data_item.path, data_item.value)
            except ValueError as exc:
                findings.append(_a2ui_unknown(f"line:{index}", str(exc)))
            continue
        if message.delete_surface is not None:
            delete_item = message.delete_surface
            surface = surfaces.get(delete_item.surface_id)
            if surface is None:
                findings.append(_a2ui_unknown(f"line:{index}", "deleteSurface targets no live surface"))
            else:
                capture_surface(delete_item.surface_id, surface, retain_unknown=True)
                surfaces.pop(delete_item.surface_id)

    if len(action_contracts) != len(manifest.action_contracts):
        findings.append(_a2ui_unknown(manifest.fixture_id, "duplicate action contract names"))
    if len(evidence_contracts) != len(manifest.evidence_contracts):
        findings.append(_a2ui_unknown(manifest.fixture_id, "duplicate evidence component contracts"))

    for surface_id, surface in sorted(surfaces.items()):
        findings.extend(
            _scan_a2ui_surface(
                manifest,
                surface_id,
                surface,
                action_contracts,
                evidence_contracts,
            )
        )
    return [*historical_findings, *findings]


def _scan_a2ui_surface(
    manifest: A2UIFixtureManifest,
    surface_id: str,
    surface: _A2UISurface,
    action_contracts: dict[str, A2UIActionContract],
    evidence_contracts: dict[str, Any],
) -> list[AgentUIFinding]:
    if surface.catalog_id != manifest.catalog_id:
        return []
    findings: list[AgentUIFinding] = []
    reachable, graph_findings = _reachable_components(surface_id, surface.components)
    findings.extend(graph_findings)
    for component_id in sorted(reachable):
        component = surface.components[component_id]
        component_type = component["component"]
        if component_type == "Button":
            findings.extend(
                _scan_a2ui_button(
                    manifest,
                    surface,
                    component,
                    action_contracts,
                )
            )
        elif component_type == "StatusBadge":
            findings.extend(
                _scan_a2ui_status_badge(
                    manifest,
                    surface,
                    component,
                    evidence_contracts.get(component_id),
                )
            )
        elif component_type == "ExternalLink":
            findings.extend(_scan_a2ui_external_link(manifest, component))
    return findings


def _a2ui_unknown(target: str, evidence: str) -> AgentUIFinding:
    return _unknown(
        target=target,
        evidence=evidence,
        protocol="a2ui",
        host_profile=HostProfile.PROGRAM_OWNED_A2UI.value,
        assumptions=_A2UI_ASSUMPTIONS,
    )


def _decode_pointer(pointer: str) -> list[str]:
    if pointer == "/":
        return []
    if not pointer.startswith("/"):
        raise ValueError("JSON Pointer must be absolute")
    for index, character in enumerate(pointer):
        if character == "~" and (index + 1 >= len(pointer) or pointer[index + 1] not in {"0", "1"}):
            raise ValueError("JSON Pointer contains an invalid tilde escape")
    return [token.replace("~1", "/").replace("~0", "~") for token in pointer[1:].split("/")]


def _set_pointer(document: Any, pointer: str, value: Any) -> Any:
    tokens = _decode_pointer(pointer)
    if not tokens:
        return value
    if not isinstance(document, dict):
        raise ValueError("data-model update cannot descend through a non-object root")
    current = document
    for token in tokens[:-1]:
        next_value = current.get(token)
        if next_value is None:
            next_value = {}
            current[token] = next_value
        if not isinstance(next_value, dict):
            raise ValueError("data-model update cannot descend through a non-object value")
        current = next_value
    current[tokens[-1]] = value
    return document


def _get_pointer(document: Any, pointer: str) -> tuple[bool, Any]:
    try:
        tokens = _decode_pointer(pointer)
    except ValueError:
        return False, None
    current = document
    for token in tokens:
        if isinstance(current, dict) and token in current:
            current = current[token]
        elif isinstance(current, list) and token.isdigit() and int(token) < len(current):
            current = current[int(token)]
        else:
            return False, None
    return True, current


def _provenance_for_path(
    provenance: Mapping[str, str],
    path: str,
) -> str | None:
    """Resolve exact or nearest-ancestor JSON Pointer provenance."""
    try:
        path_tokens = _decode_pointer(path)
    except ValueError:
        return None
    match: tuple[int, str] | None = None
    for candidate, value in provenance.items():
        try:
            candidate_tokens = _decode_pointer(candidate)
        except ValueError:
            continue
        if path_tokens[: len(candidate_tokens)] != candidate_tokens:
            continue
        if match is None or len(candidate_tokens) > match[0]:
            match = (len(candidate_tokens), value)
    return match[1] if match is not None else None


def _approval_provenance_findings(
    manifest: A2UIFixtureManifest,
    component_id: str,
    influence_paths: set[str],
) -> list[AgentUIFinding]:
    findings: list[AgentUIFinding] = []
    untrusted: list[str] = []
    for path in sorted(influence_paths):
        provenance = _provenance_for_path(manifest.data_provenance, path)
        if provenance is None:
            findings.append(
                _a2ui_unknown(
                    f"component:{component_id}",
                    f"approval binding has no declared provenance: {path}",
                )
            )
        elif provenance == DataProvenance.UNKNOWN.value:
            findings.append(
                _a2ui_unknown(
                    f"component:{component_id}",
                    f"approval binding provenance is unknown: {path}",
                )
            )
        elif provenance == DataProvenance.UNTRUSTED_TOOL_OUTPUT.value:
            untrusted.append(path)
    if untrusted:
        findings.append(
            _finding(
                "MCPUI004",
                target=f"component:{component_id}",
                evidence=[f"untrusted approval binding: {path}" for path in untrusted],
                protocol="a2ui",
                host_profile=HostProfile.PROGRAM_OWNED_A2UI.value,
                assumptions=_A2UI_ASSUMPTIONS,
            )
        )
    return findings


def _reachable_components(
    surface_id: str,
    components: dict[str, dict[str, Any]],
) -> tuple[set[str], list[AgentUIFinding]]:
    findings: list[AgentUIFinding] = []
    if "root" not in components:
        return set(), [_a2ui_unknown(f"surface:{surface_id}", "surface has no root component")]
    reachable: set[str] = set()
    stack: list[tuple[str, int, frozenset[str]]] = [("root", 0, frozenset())]
    while stack:
        component_id, depth, ancestors = stack.pop()
        if depth > _MAX_TREE_DEPTH:
            findings.append(
                _a2ui_unknown(
                    f"surface:{surface_id}",
                    f"component tree depth exceeds {_MAX_TREE_DEPTH}",
                )
            )
            continue
        if component_id in ancestors:
            findings.append(_a2ui_unknown(f"component:{component_id}", "component graph contains a cycle"))
            continue
        component = components.get(component_id)
        if component is None:
            findings.append(_a2ui_unknown(f"component:{component_id}", "referenced component is absent"))
            continue
        if component_id in reachable:
            continue
        reachable.add(component_id)
        child_ids: list[str] = []
        children = component.get("children")
        if isinstance(children, list):
            child_ids.extend(item for item in children if isinstance(item, str))
        child = component.get("child")
        if isinstance(child, str):
            child_ids.append(child)
        branch = ancestors | {component_id}
        stack.extend((child_id, depth + 1, branch) for child_id in reversed(child_ids))
    return reachable, findings


def _resolve_value(value: Any, data: Any) -> tuple[bool, Any, set[str]]:
    if isinstance(value, dict) and set(value) == {"path"} and isinstance(value["path"], str):
        path = value["path"]
        found, resolved = _get_pointer(data, path)
        return found, resolved, {path}
    if isinstance(value, (str, int, float, bool)) or value is None:
        return True, value, set()
    return False, None, _bound_paths(value)


def _bound_paths(value: Any) -> set[str]:
    paths: set[str] = set()
    if isinstance(value, dict):
        if set(value) == {"path"} and isinstance(value["path"], str):
            paths.add(value["path"])
        else:
            for nested in value.values():
                paths.update(_bound_paths(nested))
    elif isinstance(value, list):
        for nested in value:
            paths.update(_bound_paths(nested))
    return paths


def _button_label(
    surface: _A2UISurface,
    component: dict[str, Any],
) -> tuple[bool, str, set[str]]:
    if "text" in component:
        found, value, paths = _resolve_value(component["text"], surface.data)
        return found and isinstance(value, str), value if isinstance(value, str) else "", paths
    child_id = component.get("child")
    child = surface.components.get(child_id) if isinstance(child_id, str) else None
    if child and child.get("component") == "Text":
        found, value, paths = _resolve_value(child.get("text"), surface.data)
        return found and isinstance(value, str), value if isinstance(value, str) else "", paths
    return False, "", set()


def _scan_a2ui_button(
    manifest: A2UIFixtureManifest,
    surface: _A2UISurface,
    component: dict[str, Any],
    contracts: dict[str, A2UIActionContract],
) -> list[AgentUIFinding]:
    component_id = str(component["id"])
    action = component.get("action")
    if not isinstance(action, dict) or set(action) != {"event"}:
        return [_a2ui_unknown(f"component:{component_id}", "unsupported Button action shape")]
    event = action.get("event")
    if not isinstance(event, dict) or not isinstance(event.get("name"), str):
        return [_a2ui_unknown(f"component:{component_id}", "Button event has no stable name")]
    action_name = event["name"]
    contract = contracts.get(action_name)
    if contract is None:
        return [_a2ui_unknown(f"component:{component_id}", "Button event has no action contract")]
    findings: list[AgentUIFinding] = []
    label_found, label, label_paths = _button_label(surface, component)
    if not label_found:
        findings.append(
            _a2ui_unknown(f"component:{component_id}", "Button label cannot be resolved statically")
        )
    disclosed = component.get("disclosedAuthority", [])
    if not isinstance(disclosed, list) or not all(isinstance(item, str) for item in disclosed):
        findings.append(
            _a2ui_unknown(f"component:{component_id}", "Button authority disclosure is ambiguous")
        )
        disclosed = []
    missing = sorted(set(contract.authority) - set(disclosed))
    if missing:
        findings.append(
            _finding(
                "MCPUI001",
                target=f"component:{component_id}",
                evidence=[
                    f"action event: {action_name}",
                    f"undisclosed authority: {', '.join(missing)}",
                ],
                protocol="a2ui",
                host_profile=HostProfile.PROGRAM_OWNED_A2UI.value,
                assumptions=_A2UI_ASSUMPTIONS,
            )
        )
    if component.get("disclosedAuthority") is None or not label.strip():
        findings.append(
            _finding(
                "MCPUI003",
                target=f"component:{component_id}",
                evidence=[f"action event: {action_name}", "visible action disclosure is absent"],
                protocol="a2ui",
                host_profile=HostProfile.PROGRAM_OWNED_A2UI.value,
                assumptions=_A2UI_ASSUMPTIONS,
            )
        )
    if not contract.requires_approval:
        return findings
    if contract.expected_approval_version is None:
        findings.append(
            _a2ui_unknown(
                f"component:{component_id}",
                "approval-required action contract has no authoritative expected version",
            )
        )

    version_found, version, version_paths = _resolve_value(component.get("approvalVersion"), surface.data)
    state_found, state, state_paths = _resolve_value(component.get("evidenceState"), surface.data)
    visual_found, visual, visual_paths = _resolve_value(component.get("visualState"), surface.data)
    version_resolved = version_found and isinstance(version, str)
    state_resolved = state_found and isinstance(state, str)
    visual_resolved = visual_found and isinstance(visual, str)
    if not version_resolved or not state_resolved or not visual_resolved:
        findings.append(
            _a2ui_unknown(
                f"component:{component_id}",
                "approval version, evidence state, or visual state cannot be resolved",
            )
        )
    if state_resolved and state not in _EVIDENCE_STATES:
        findings.append(
            _a2ui_unknown(
                f"component:{component_id}",
                f"approval evidence state is outside the supported enum: {state}",
            )
        )
    if visual_resolved and visual not in _VISUAL_STATES:
        findings.append(
            _a2ui_unknown(
                f"component:{component_id}",
                f"approval visual state is outside the supported enum: {visual}",
            )
        )

    stale_reasons: list[str] = []
    if state_resolved and state == EvidenceState.STALE.value:
        stale_reasons.append("approval evidence state is stale")
    if (
        version_resolved
        and contract.expected_approval_version is not None
        and version != contract.expected_approval_version
    ):
        stale_reasons.append(
            f"displayed version {version} does not match expected {contract.expected_approval_version}"
        )
    if stale_reasons:
        findings.append(
            _finding(
                "MCPUI002",
                target=f"component:{component_id}",
                evidence=stale_reasons,
                protocol="a2ui",
                host_profile=HostProfile.PROGRAM_OWNED_A2UI.value,
                assumptions=_A2UI_ASSUMPTIONS,
            )
        )
    if (
        state_resolved
        and state in {EvidenceState.UNKNOWN.value, EvidenceState.UNVERIFIABLE.value}
        and visual_resolved
        and visual == VisualState.PASS.value
    ):
        findings.append(
            _finding(
                "MCPUI005",
                target=f"component:{component_id}",
                evidence=[f"evidence state is {state}", "visual state is pass"],
                protocol="a2ui",
                host_profile=HostProfile.PROGRAM_OWNED_A2UI.value,
                assumptions=_A2UI_ASSUMPTIONS,
            )
        )
    influence_paths = (
        label_paths
        | version_paths
        | state_paths
        | visual_paths
        | _bound_paths(component.get("enabled"))
        | _bound_paths(component.get("checks"))
    )
    findings.extend(_approval_provenance_findings(manifest, component_id, influence_paths))
    return findings


def _scan_a2ui_status_badge(
    manifest: A2UIFixtureManifest,
    surface: _A2UISurface,
    component: dict[str, Any],
    contract: Any,
) -> list[AgentUIFinding]:
    component_id = str(component["id"])
    if contract is None:
        return [_a2ui_unknown(f"component:{component_id}", "StatusBadge has no evidence contract")]
    found, evidence_state = _get_pointer(surface.data, contract.evidence_state_path)
    label_found, label, label_paths = _resolve_value(component.get("label"), surface.data)
    state_found, displayed_state, state_paths = _resolve_value(
        component.get("state"),
        surface.data,
    )
    tone = component.get("tone")
    pass_presentation = (
        tone == "green"
        or displayed_state == VisualState.PASS.value
        or (isinstance(label, str) and label.strip().lower() in {"pass", "passed", "safe"})
    )
    findings: list[AgentUIFinding] = []
    evidence_resolved = found and isinstance(evidence_state, str)
    presentation_resolved = label_found and state_found
    if not evidence_resolved or not presentation_resolved:
        findings.append(
            _a2ui_unknown(
                f"component:{component_id}",
                "StatusBadge evidence or presentation cannot be resolved",
            )
        )
    if evidence_resolved and evidence_state not in _EVIDENCE_STATES:
        findings.append(
            _a2ui_unknown(
                f"component:{component_id}",
                f"StatusBadge evidence state is outside the supported enum: {evidence_state}",
            )
        )
    if state_found and displayed_state not in _VISUAL_STATES:
        findings.append(
            _a2ui_unknown(
                f"component:{component_id}",
                f"StatusBadge visual state is outside the supported enum: {displayed_state!s}",
            )
        )
    badge_paths = {contract.evidence_state_path, *label_paths, *state_paths}
    missing_or_unknown: list[str] = []
    untrusted: list[str] = []
    for path in sorted(badge_paths):
        provenance = _provenance_for_path(manifest.data_provenance, path)
        if provenance is None:
            missing_or_unknown.append(f"missing provenance: {path}")
        elif provenance == DataProvenance.UNKNOWN.value:
            missing_or_unknown.append(f"unknown provenance: {path}")
        elif provenance == DataProvenance.UNTRUSTED_TOOL_OUTPUT.value:
            untrusted.append(path)
    if missing_or_unknown:
        findings.append(
            _a2ui_unknown(
                f"component:{component_id}",
                "; ".join(missing_or_unknown),
            )
        )
    if untrusted and not pass_presentation:
        findings.append(
            _a2ui_unknown(
                f"component:{component_id}",
                f"StatusBadge evidence is not independently trusted: {', '.join(untrusted)}",
            )
        )

    unestablished_reasons: list[str] = []
    if not evidence_resolved:
        unestablished_reasons.append("evidence state cannot be resolved")
    elif evidence_state not in _EVIDENCE_STATES:
        unestablished_reasons.append(f"evidence state is unsupported: {evidence_state}")
    elif evidence_state in {EvidenceState.UNKNOWN.value, EvidenceState.UNVERIFIABLE.value}:
        unestablished_reasons.append(f"evidence state is {evidence_state}")
    unestablished_reasons.extend(missing_or_unknown)
    unestablished_reasons.extend(f"untrusted evidence binding: {path}" for path in untrusted)
    if pass_presentation and unestablished_reasons:
        findings.append(
            _finding(
                "MCPUI005",
                target=f"component:{component_id}",
                evidence=[
                    *unestablished_reasons,
                    f"rendered label/tone is {label!s}/{tone!s}",
                ],
                protocol="a2ui",
                host_profile=HostProfile.PROGRAM_OWNED_A2UI.value,
                assumptions=_A2UI_ASSUMPTIONS,
            )
        )
    return findings


def _scan_a2ui_external_link(
    manifest: A2UIFixtureManifest,
    component: dict[str, Any],
) -> list[AgentUIFinding]:
    component_id = str(component["id"])
    url = component.get("url")
    if not isinstance(url, str):
        return [_a2ui_unknown(f"component:{component_id}", "external URL is not static")]
    origin = _origin(url)
    if origin is None:
        return [
            _a2ui_unknown(
                f"component:{component_id}",
                "external URL is not an absolute credential-free HTTPS URL",
            )
        ]
    if origin in _normalized_origins(manifest.declared_external_destinations):
        return []
    return [
        _finding(
            "MCPUI006",
            target=f"component:{component_id}",
            evidence=[f"external origin {origin} is absent from the fixture declaration"],
            protocol="a2ui",
            host_profile=HostProfile.PROGRAM_OWNED_A2UI.value,
            assumptions=_A2UI_ASSUMPTIONS,
        )
    ]


def render_agent_ui_html(report: AgentUIReport) -> str:
    """Render a deterministic, inert HTML projection of the canonical JSON report."""
    verdict_color = {"pass": "#4ade80", "fail": "#fb7185", "unknown": "#facc15"}[report.verdict]
    findings = (
        "".join(
            "<li>"
            f"<strong>{html.escape(item.severity.value.upper())}</strong> "
            f"<code>{html.escape(item.rule_id)}</code> "
            f"{html.escape(item.title)} — {html.escape(item.target)}"
            "<ul>"
            + "".join(f"<li>{html.escape(evidence)}</li>" for evidence in item.evidence)
            + f"<li>Remediation: {html.escape(item.remediation)}</li>"
            + "</ul></li>"
            for item in report.findings
        )
        or "<li>No supported contract contradiction was found.</li>"
    )
    limitations = "".join(f"<li>{html.escape(item)}</li>" for item in report.claim_ceiling)
    assumptions = "".join(f"<li>{html.escape(item)}</li>" for item in report.assumptions)
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Agent UI Contract Audit</title>
<style>
body{{font:16px/1.5 system-ui,sans-serif;max-width:960px;margin:40px auto;padding:0 20px;
background:#10141b;color:#e5e7eb}}h1,h2{{line-height:1.2}}code{{color:#93c5fd}}
.verdict{{color:{verdict_color};font-size:1.4rem;font-weight:700}}.muted{{color:#9ca3af}}
</style></head><body>
<h1>Agent UI Contract Audit</h1>
<p><strong>Fixture:</strong> {html.escape(report.fixture_id)}</p>
<p><strong>Protocol profile:</strong> {html.escape(report.protocol)} /
{html.escape(report.protocol_version)} / {html.escape(report.host_profile)}</p>
<p class="verdict">Verdict: {html.escape(report.verdict.upper())}</p>
<p class="muted">Offline projection. The canonical evidence is the JSON report.</p>
<h2>Findings</h2><ol>{findings}</ol>
<h2>Protocol and host assumptions</h2><ul>{assumptions}</ul>
<h2>Claim ceiling</h2><ul>{limitations}</ul>
</body></html>
"""


def report_json_bytes(report: AgentUIReport) -> bytes:
    return canonical_json_bytes(report)
