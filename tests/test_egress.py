"""Tests for the egress (outbound-destination) detector."""

from __future__ import annotations

import socket

import pytest

from mcp_audit.egress import EgressDetector, _is_credential_token_set
from mcp_audit.models import (
    CapabilityTarget,
    ClientType,
    EgressKind,
    EgressSeverity,
    ResourceInfo,
    ServerAudit,
    ServerConfig,
    ToolInfo,
)
from mcp_audit.ssrf import SsrfDetector, _key_tokens
from mcp_audit.taxonomy import egress_metadata


def _tool(name: str, description: str, properties: dict[str, object]) -> ToolInfo:
    return ToolInfo(
        name=name,
        description=description,
        input_schema={"type": "object", "properties": properties},
    )


def _audit(
    tools: list[ToolInfo] | None = None,
    resources: list[ResourceInfo] | None = None,
) -> ServerAudit:
    """Build a ServerAudit with SSRF findings populated, as the pipeline does."""
    audit = ServerAudit(
        server=ServerConfig(
            name="srv",
            client=ClientType.CLAUDE_CODE,
            config_path="/tmp/config.json",
        ),
        connection_status="connected",
        tools=tools or [],
        resources=resources or [],
    )
    audit.ssrf_findings = SsrfDetector().scan_server(audit.tools, audit.resources)
    return audit


# --- Defaults --------------------------------------------------------------


def test_server_audit_egress_findings_defaults_empty() -> None:
    assert _audit().egress_findings == []


def test_clean_server_has_no_egress_findings() -> None:
    audit = _audit(tools=[_tool("add", "Add two numbers.", {"a": {"type": "number"}})])
    assert EgressDetector(allowlist={"github.com"}).scan_server(audit) == []


# --- Fixed destination outside the allowlist (MEDIUM) ----------------------


def test_fixed_host_outside_allowlist_is_medium() -> None:
    audit = _audit(resources=[ResourceInfo(uri="https://api.anthropic.com/data")])
    findings = EgressDetector(allowlist={"github.com"}).scan_server(audit)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.kind is EgressKind.DESTINATION_OUTSIDE_ALLOWLIST
    assert finding.severity is EgressSeverity.MEDIUM
    assert finding.destination_host == "api.anthropic.com"
    assert finding.target_type is CapabilityTarget.RESOURCE
    assert finding.rule_id == "MCP040"


def test_fixed_host_inside_allowlist_is_clean() -> None:
    # A plain (non-multi-tenant) allowlisted host with no credential signal is clean.
    audit = _audit(resources=[ResourceInfo(uri="https://docs.internal.example/data")])
    assert EgressDetector(allowlist={"internal.example"}).scan_server(audit) == []


def test_empty_allowlist_flags_every_fixed_destination() -> None:
    # No allowlist trusts nothing, so every fixed external destination is reported.
    audit = _audit(resources=[ResourceInfo(uri="https://api.anthropic.com/data")])
    findings = EgressDetector(allowlist=set()).scan_server(audit)
    assert len(findings) == 1
    assert findings[0].kind is EgressKind.DESTINATION_OUTSIDE_ALLOWLIST


def test_local_scheme_resource_is_not_egress() -> None:
    audit = _audit(resources=[ResourceInfo(uri="file:///etc/passwd")])
    assert EgressDetector(allowlist=set()).scan_server(audit) == []


# --- Unbounded / caller-controlled egress (HIGH) ---------------------------


def test_caller_controlled_tool_is_high_unbounded() -> None:
    audit = _audit(tools=[_tool("fetch_url", "Fetch the contents of a URL.", {"url": {"type": "string"}})])
    findings = EgressDetector(allowlist={"github.com"}).scan_server(audit)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.kind is EgressKind.UNBOUNDED_EGRESS
    assert finding.severity is EgressSeverity.HIGH
    assert finding.destination_host is None
    assert finding.target_type is CapabilityTarget.TOOL
    assert finding.target_name == "fetch_url"
    assert finding.rule_id == "MCP041"


def test_templated_host_resource_is_high_unbounded() -> None:
    audit = _audit(resources=[ResourceInfo(uri="https://{host}/api/data")])
    findings = EgressDetector(allowlist=set()).scan_server(audit)
    assert len(findings) == 1
    assert findings[0].kind is EgressKind.UNBOUNDED_EGRESS
    assert findings[0].severity is EgressSeverity.HIGH
    assert findings[0].destination_host is None


def test_caller_controlled_target_is_flagged_regardless_of_allowlist() -> None:
    # An unbounded target cannot be allowlisted away — allowlisting any host is irrelevant.
    audit = _audit(tools=[_tool("fetch_url", "Fetch the contents of a URL.", {"url": {"type": "string"}})])
    findings = EgressDetector(allowlist={"anything.com"}).scan_server(audit)
    assert len(findings) == 1
    assert findings[0].kind is EgressKind.UNBOUNDED_EGRESS


# --- Dedup -----------------------------------------------------------------


def test_path_templated_fixed_host_emits_one_finding() -> None:
    # A path-templated remote URI fires an SSRF finding (fixed host) AND is walked as a
    # resource — egress must emit exactly one outside-allowlist finding, not two.
    audit = _audit(resources=[ResourceInfo(uri="https://api.example.com/{path}")])
    findings = EgressDetector(allowlist={"github.com"}).scan_server(audit)
    assert len(findings) == 1
    assert findings[0].kind is EgressKind.DESTINATION_OUTSIDE_ALLOWLIST
    assert findings[0].destination_host == "api.example.com"


def test_mixed_unbounded_and_fixed_destinations() -> None:
    audit = _audit(
        tools=[_tool("fetch_url", "Fetch a URL.", {"url": {"type": "string"}})],
        resources=[ResourceInfo(uri="https://api.anthropic.com/data")],
    )
    findings = EgressDetector(allowlist=set()).scan_server(audit)
    kinds = sorted(f.kind.value for f in findings)
    assert kinds == ["destination_outside_allowlist", "unbounded_egress"]


# --- Metadata + construction contract --------------------------------------


def test_egress_metadata_present_for_all_kinds() -> None:
    for kind in EgressKind:
        meta = egress_metadata(kind)
        assert meta.description
        assert meta.rule_id.startswith("MCP04")


# --- Phase 1: trusted-destination residual (the Cowork lesson) -------------


def test_allowlisted_multi_tenant_host_is_low_residual() -> None:
    # api.anthropic.com is in the curated MULTI_TENANT_API_HOSTS default; allowlisting it
    # does not make it automatically safe — it stays a LOW advisory residual.
    audit = _audit(resources=[ResourceInfo(uri="https://api.anthropic.com/data")])
    findings = EgressDetector(allowlist={"anthropic.com"}).scan_server(audit)
    assert len(findings) == 1
    f = findings[0]
    assert f.kind is EgressKind.TRUSTED_DESTINATION_RESIDUAL
    assert f.severity is EgressSeverity.LOW
    assert f.destination_host == "api.anthropic.com"
    assert f.rule_id == "MCP042"


def test_cowork_credential_plus_trusted_host_is_medium_residual() -> None:
    # The Cowork pattern: an allowlisted multi-tenant API + a tool that takes an api_key.
    audit = _audit(
        tools=[_tool("send", "Send a message.", {"api_key": {"type": "string"}})],
        resources=[ResourceInfo(uri="https://api.anthropic.com/data")],
    )
    findings = EgressDetector(allowlist={"anthropic.com"}).scan_server(audit)
    assert len(findings) == 1
    f = findings[0]
    assert f.kind is EgressKind.TRUSTED_DESTINATION_RESIDUAL
    assert f.severity is EgressSeverity.MEDIUM  # credential vector elevates LOW -> MEDIUM


def test_credential_param_elevates_plain_trusted_host_to_residual() -> None:
    # Even a non-multi-tenant allowlisted host gets a residual when the server is
    # credential-bearing — the credential could redirect data off the trusted path.
    audit = _audit(
        tools=[_tool("call", "Call an API.", {"accessToken": {"type": "string"}})],
        resources=[ResourceInfo(uri="https://docs.internal.example/data")],
    )
    findings = EgressDetector(allowlist={"internal.example"}).scan_server(audit)
    assert len(findings) == 1
    assert findings[0].kind is EgressKind.TRUSTED_DESTINATION_RESIDUAL
    assert findings[0].severity is EgressSeverity.MEDIUM


def test_non_credential_param_does_not_trigger_residual() -> None:
    # Exact-token match, not substring: 'query' is not a credential token.
    audit = _audit(
        tools=[_tool("search", "Search docs.", {"query": {"type": "string"}})],
        resources=[ResourceInfo(uri="https://docs.internal.example/data")],
    )
    assert EgressDetector(allowlist={"internal.example"}).scan_server(audit) == []


@pytest.mark.parametrize(
    "param",
    ["api_key", "apiKey", "accessKey", "secret_key", "authToken", "bearer", "credential", "apikey", "auth"],
)
def test_credential_param_names_are_detected(param: str) -> None:
    assert _is_credential_token_set(_key_tokens(param))


@pytest.mark.parametrize(
    "param",
    ["primary_key", "sort_key", "cache_key", "foreign_key", "registry_key", "partition_key", "query", "url"],
)
def test_identifier_key_params_are_not_credentials(param: str) -> None:
    # A bare 'key' token is a credential only with a credential qualifier — '*_key' identifier
    # params must not over-promote the trusted-destination residual from LOW to MEDIUM.
    assert not _is_credential_token_set(_key_tokens(param))


def test_identifier_key_param_keeps_residual_low() -> None:
    # End-to-end: a 'primary_key' param on a multi-tenant allowlisted host stays LOW, not MEDIUM.
    audit = _audit(
        tools=[_tool("lookup", "Look up a row.", {"primary_key": {"type": "string"}})],
        resources=[ResourceInfo(uri="https://api.anthropic.com/data")],
    )
    findings = EgressDetector(allowlist={"anthropic.com"}).scan_server(audit)
    assert len(findings) == 1
    assert findings[0].kind is EgressKind.TRUSTED_DESTINATION_RESIDUAL
    assert findings[0].severity is EgressSeverity.LOW  # not elevated: primary_key is not a credential


def test_userinfo_templated_resource_is_credential_bearing() -> None:
    # A resource URI that templates its userinfo attaches a caller-supplied credential to a
    # fixed (allowlisted) host — credential-bearing, so a MEDIUM residual.
    audit = _audit(resources=[ResourceInfo(uri="https://user:{token}@docs.internal.example/x")])
    findings = EgressDetector(allowlist={"internal.example"}).scan_server(audit)
    assert len(findings) == 1
    assert findings[0].kind is EgressKind.TRUSTED_DESTINATION_RESIDUAL
    assert findings[0].severity is EgressSeverity.MEDIUM


def test_residual_is_never_high() -> None:
    audit = _audit(
        tools=[_tool("send", "Send.", {"secret": {"type": "string"}})],
        resources=[ResourceInfo(uri="https://api.openai.com/v1/data")],
    )
    findings = EgressDetector(allowlist={"openai.com"}).scan_server(audit)
    assert findings
    assert all(f.severity is not EgressSeverity.HIGH for f in findings)


def test_multi_tenant_hosts_arg_extends_the_curated_default() -> None:
    # An operator-supplied host joins (does not replace) the curated default.
    audit = _audit(resources=[ResourceInfo(uri="https://data.partner.example/x")])
    findings = EgressDetector(
        allowlist={"partner.example"}, multi_tenant_hosts={"data.partner.example"}
    ).scan_server(audit)
    assert len(findings) == 1
    assert findings[0].kind is EgressKind.TRUSTED_DESTINATION_RESIDUAL
    assert findings[0].severity is EgressSeverity.LOW


def test_non_remote_userinfo_resource_does_not_set_credential_bearing() -> None:
    # An ftp resource is not an egress destination (non-remote scheme); its templated
    # userinfo must NOT inflate an unrelated allowlisted destination's residual to MEDIUM.
    audit = _audit(
        resources=[
            ResourceInfo(uri="ftp://user:{token}@files.internal.example/x"),
            ResourceInfo(uri="https://api.anthropic.com/data"),
        ]
    )
    findings = EgressDetector(allowlist={"anthropic.com"}).scan_server(audit)
    assert len(findings) == 1
    f = findings[0]
    assert f.destination_host == "api.anthropic.com"
    assert f.kind is EgressKind.TRUSTED_DESTINATION_RESIDUAL
    assert f.severity is EgressSeverity.LOW  # not elevated by the non-remote ftp credential


def test_non_allowlisted_multi_tenant_host_is_outside_not_residual() -> None:
    # The residual only applies to allowlisted hosts; a multi-tenant host that is NOT
    # allowlisted is still a plain DESTINATION_OUTSIDE_ALLOWLIST finding.
    audit = _audit(resources=[ResourceInfo(uri="https://api.anthropic.com/data")])
    findings = EgressDetector(allowlist={"github.com"}).scan_server(audit)
    assert len(findings) == 1
    assert findings[0].kind is EgressKind.DESTINATION_OUTSIDE_ALLOWLIST


# --- Static-only invariant -------------------------------------------------


def test_scan_makes_no_network_call(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(*args: object, **kwargs: object) -> object:
        raise AssertionError("egress detector must not open a socket")

    monkeypatch.setattr(socket, "socket", _boom)
    audit = _audit(
        tools=[_tool("fetch_url", "Fetch a URL.", {"url": {"type": "string"}})],
        resources=[ResourceInfo(uri="https://api.anthropic.com/data")],
    )
    findings = EgressDetector(allowlist=set()).scan_server(audit)
    assert findings  # work happened, with zero network access
