"""Coverage contracts exercised through isolated repository-owned servers."""

import sys
from pathlib import Path

import pytest
from click.testing import CliRunner

from mcp_audit.cli import main
from mcp_audit.connector import ServerConnector
from mcp_audit.engine import ScanOptions, run_scan
from mcp_audit.htmlreport import HtmlReportGenerator
from mcp_audit.models import (
    AuditReport,
    CanarySummary,
    CheckCoverage,
    ClientType,
    CoverageState,
    IntegrityFinding,
    IntegrityKind,
    IntegritySeverity,
    LLMAnalysisReasonCode,
    LLMAnalysisStatus,
    LLMAnalysisSummary,
    PermissionCategory,
    PromptInfo,
    ResourceInfo,
    ScanWarning,
    ServerAudit,
    ServerConfig,
)
from mcp_audit.policy import PolicyConfig, evaluate_policy, load_policy
from mcp_audit.sarif import SarifGenerator
from mcp_audit.text_limits import MAX_FIELD_BYTES
from tests.conftest import make_server_config, make_tool

FIXTURES = Path(__file__).parent / "fixtures"

# Expected affected inputs are explicit so the matrix does not mirror the
# aggregator's private dependency sets. Each row exercises every check.
ALL_CHECKS = {
    "config_health",
    "metadata",
    "permissions",
    "capabilities",
    "inject_check",
    "ssrf_check",
    "egress_check",
    "pin_check",
    "trifecta_check",
    "shadow_check",
    "escalation_check",
    "provenance_check",
    "integrity_check",
    "verify_artifacts",
    "download_artifacts",
    "llm_analysis",
    "runtime_security",
}
CONFIG_CHECKS = {"provenance_check", "integrity_check", "verify_artifacts", "download_artifacts"}
BASELINE_CHECKS = CONFIG_CHECKS | {"pin_check", "escalation_check"}
PACKAGES = {"verify_artifacts", "download_artifacts"}
METADATA_CHECKS = ALL_CHECKS - CONFIG_CHECKS - {"config_health"}
DEGRADED_CASES = [
    ("clean", set(), set()),
    ("parse_failure", ALL_CHECKS, set()),
    ("no_servers", set(), ALL_CHECKS - {"config_health"}),
    ("unexecuted", set(), ALL_CHECKS),
    ("analysis_failure", set(), ALL_CHECKS - {"config_health"}),
    ("failed", set(), METADATA_CHECKS),
    ("timeout", set(), METADATA_CHECKS),
    ("skipped", {"permissions"}, METADATA_CHECKS - {"permissions"}),
    ("config_only", {"permissions"}, METADATA_CHECKS - {"permissions"}),
    ("partial_listing", METADATA_CHECKS, set()),
    ("mixed_skipped", METADATA_CHECKS, set()),
    ("mixed_failed", METADATA_CHECKS, set()),
    ("mixed_missing_baseline", BASELINE_CHECKS, set()),
    (
        "description_truncated",
        {"permissions", "capabilities", "ssrf_check", "egress_check", "trifecta_check", "escalation_check"},
        set(),
    ),
    ("agent_text_incomplete", {"permissions", "inject_check", "trifecta_check", "escalation_check"}, set()),
    ("permission_schema_incomplete", {"permissions", "trifecta_check", "escalation_check"}, set()),
    ("targeted_warning", ALL_CHECKS - {"config_health"}, set()),
    ("missing_baseline", set(), BASELINE_CHECKS),
    ("empty_baseline", set(), BASELINE_CHECKS),
    ("inapplicable_baseline", set(), PACKAGES),
    ("unverified_package", PACKAGES, set()),
    ("missing_llm", set(), {"llm_analysis"}),
    ("unknown_llm", set(), {"llm_analysis"}),
    ("partial_llm", {"llm_analysis"}, set()),
    ("missing_runtime", set(), {"runtime_security"}),
    ("no_safe_runtime", set(), {"runtime_security"}),
    ("partial_runtime", {"runtime_security"}, set()),
    ("short_runtime", {"runtime_security"}, set()),
    ("warning_runtime", {"runtime_security"}, set()),
    ("integrity_unavailable", {"integrity_check"}, set()),
]


@pytest.mark.parametrize("check", sorted(ALL_CHECKS))
@pytest.mark.parametrize("condition,partial,not_run", DEGRADED_CASES, ids=[row[0] for row in DEGRADED_CASES])
def test_every_check_requires_all_its_inputs(
    check: str, condition: str, partial: set[str], not_run: set[str]
) -> None:
    from mcp_audit.coverage import OPTIONAL_CHECKS, build_coverage

    assert ALL_CHECKS == {"config_health", "metadata", "permissions", "capabilities", *OPTIONAL_CHECKS}
    audit = ServerAudit(
        server=make_server_config(),
        connection_status="connected",
        canary=CanarySummary(requested_calls=1, completed_calls=1, status="complete"),
        llm_analysis=LLMAnalysisSummary(
            status=LLMAnalysisStatus.COMPLETE,
            reason_code=LLMAnalysisReasonCode.COMPLETE,
            model="fixture",
            candidate_tools=1,
            analyzed_tools=1,
        ),
    )
    audits = [] if condition == "no_servers" else [audit]
    completed = [set(ALL_CHECKS) for _ in audits]
    baseline = condition not in {"missing_baseline", "empty_baseline"}
    baselines = {name: [baseline for _ in audits] for name in BASELINE_CHECKS}
    if condition == "missing_baseline":
        baselines = {}
    package_state: CoverageState = (
        "not_run"
        if condition in {"missing_baseline", "empty_baseline", "inapplicable_baseline"}
        else "partial"
        if condition == "unverified_package"
        else "complete"
    )
    packages = {
        name: [CheckCoverage(state=package_state, reason="fixture package evidence") for _ in audits]
        for name in PACKAGES
    }
    if condition in {"mixed_skipped", "mixed_failed", "mixed_missing_baseline"}:
        sibling = audit.model_copy(deep=True)
        if condition != "mixed_missing_baseline":
            sibling.connection_status = "skipped" if condition == "mixed_skipped" else "failed"
        audits.append(sibling)
        completed.append(set(ALL_CHECKS))
        for entries in baselines.values():
            entries.append(condition != "mixed_missing_baseline")
        for package_entries in packages.values():
            package_entries.append(
                CheckCoverage(
                    state="not_run" if condition == "mixed_missing_baseline" else "complete",
                    reason="fixture sibling evidence",
                )
            )
    warnings = []
    if condition in {"failed", "timeout", "skipped"}:
        audit.connection_status = condition
    elif condition == "partial_listing":
        audit.connection_status = "partial"
    elif condition in {"unexecuted", "analysis_failure"}:
        completed = [set()]
        audit.connection_status = "failed"
    elif condition in {
        "description_truncated",
        "agent_text_incomplete",
        "permission_schema_incomplete",
        "targeted_warning",
    }:
        warnings = [
            ScanWarning(
                code=condition,
                message="fixture warning",
                check=check
                if condition == "targeted_warning"
                else "permission_analysis"
                if condition == "permission_schema_incomplete"
                else None,
                servers=[audit.server.name],
            )
        ]
    elif condition == "missing_llm":
        audit.llm_analysis = None
    elif condition in {"unknown_llm", "partial_llm"}:
        assert audit.llm_analysis is not None
        audit.llm_analysis.analyzed_tools = 0
        if condition == "unknown_llm":
            audit.llm_analysis.status = LLMAnalysisStatus.UNKNOWN
            audit.llm_analysis.reason_code = LLMAnalysisReasonCode.PROVIDER_INCOMPLETE
    elif condition == "missing_runtime":
        audit.canary = None
    elif condition in {"no_safe_runtime", "partial_runtime", "short_runtime", "warning_runtime"}:
        assert audit.canary is not None
        if condition == "no_safe_runtime":
            audit.canary.status = "no_safe_tools"
        elif condition == "partial_runtime":
            audit.canary.status = "partial"
        elif condition == "short_runtime":
            audit.canary.completed_calls = 0
        else:
            audit.canary.warnings = ["fixture truncation"]
    elif condition == "integrity_unavailable":
        audit.integrity_findings = [
            IntegrityFinding(
                kind=IntegrityKind.ARTIFACT_DRIFT,
                severity=IntegritySeverity.MEDIUM,
                server_name=audit.server.name,
                artifact_path="fixture.bin",
                baseline_hash="fixture",
                current_hash=None,
                summary="fixture unavailable",
            )
        ]
    coverage = build_coverage(
        audits,
        requested=set(OPTIONAL_CHECKS),
        skip_connect=condition == "config_only",
        warnings=warnings,
        baselines=baselines,
        completed=completed,
        package_coverage=packages,
        discovery_incomplete=condition == "parse_failure",
        config_health_inspected=condition != "unexecuted",
    )
    assert coverage[check].state == (
        "partial" if check in partial else "not_run" if check in not_run else "complete"
    )
    assert coverage[check].reason


@pytest.mark.parametrize(
    "check", sorted(ALL_CHECKS - {"config_health", "metadata", "permissions", "capabilities"})
)
def test_unrequested_checks_stay_unrequested_even_when_discovery_failed(check: str) -> None:
    from mcp_audit.coverage import build_coverage

    coverage = build_coverage(
        [],
        requested=set(),
        skip_connect=False,
        warnings=[],
        baselines={},
        completed=[],
        package_coverage={},
        discovery_incomplete=True,
        config_health_inspected=True,
    )
    assert coverage[check].state == "not_requested"


@pytest.mark.anyio
@pytest.mark.parametrize("surface", ["resource", "prompt", "tool"])
@pytest.mark.parametrize("optional_checks", [False, True])
async def test_description_truncation_reduces_detector_coverage_but_not_metadata(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, surface: str, optional_checks: bool
) -> None:
    from mcp_audit import pinning

    tool = make_tool("status", "Status")
    prompt = PromptInfo(name="summary", description="Status")
    resource = ResourceInfo(uri="fixture:status", description="Status")
    oversized = "x" * MAX_FIELD_BYTES + " read file"
    if surface == "resource":
        resource.description = oversized
    elif surface == "prompt":
        prompt.description = oversized
    else:
        tool.description = oversized
    config = make_server_config()
    store = pinning.PinStore(path=tmp_path / "pins.yaml")
    store.pin_server(config.name, [make_tool("status", "Status")])
    monkeypatch.setattr(pinning, "PinStore", lambda: store)

    async def connect(self: ServerConnector, server: ServerConfig) -> ServerAudit:
        return ServerAudit(
            server=server,
            connection_status="connected",
            tools=[tool],
            prompts=[prompt],
            resources=[resource],
        )

    monkeypatch.setattr(ServerConnector, "connect", connect)
    report = await run_scan(
        ScanOptions(
            ssrf_check=optional_checks,
            egress_check=optional_checks,
            trifecta_check=optional_checks,
            escalation_check=optional_checks,
            pin_check=optional_checks,
            shadow_check=optional_checks,
        ),
        servers=[config],
    )
    [warning] = [w for w in report.warnings if w.code == "description_truncated"]
    assert warning.check == "permission_analysis"
    assert warning.servers == [config.name]
    assert report.audits[0].connection_status == "connected"
    assert all(f.category != PermissionCategory.FILE_READ for f in report.audits[0].permissions)
    assert report.audits[0].capability_findings == []
    for check in ("config_health", "metadata"):
        assert report.coverage[check].state == "complete"
    for check in ("permissions", "capabilities"):
        assert report.coverage[check].state == "partial"
        assert "description_truncated" in report.coverage[check].reason
    for check in ("ssrf_check", "egress_check", "trifecta_check", "escalation_check"):
        assert report.coverage[check].state == ("partial" if optional_checks else "not_requested")
        if optional_checks:
            assert "description_truncated" in report.coverage[check].reason
    for check in ("pin_check", "shadow_check"):
        assert report.coverage[check].state == ("complete" if optional_checks else "not_requested")
    assert report.coverage["inject_check"].state == "not_requested"
    assert not evaluate_policy(report, PolicyConfig(fail_on_coverage=True)).passed
    assert evaluate_policy(report, PolicyConfig()).passed


@pytest.mark.anyio
async def test_config_only_reports_unchecked_metadata_and_gate() -> None:
    report = await run_scan(ScanOptions(skip_connect=True, inject_check=True), servers=[make_server_config()])
    assert report.schema_version == 1
    assert report.coverage["config_health"].state == "complete"
    assert report.coverage["metadata"] == CheckCoverage(state="not_run", reason="connections disabled")
    assert report.coverage["inject_check"].state == "not_run"
    assert report.coverage["runtime_security"].state == "not_requested"
    assert not evaluate_policy(report, PolicyConfig(fail_on_coverage=True)).passed
    assert evaluate_policy(report, PolicyConfig()).passed


@pytest.mark.anyio
async def test_mixed_valid_and_unparseable_discovery_fails_coverage_only_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from mcp_audit.discovery import CursorDiscoverer

    paths = [
        FIXTURES / "config_health/local_shadowing_config.json",
        FIXTURES / "config_health/invalid/unparseable_config.json",
    ]
    monkeypatch.setattr(CursorDiscoverer, "config_paths", lambda self: paths)

    async def connect(self: ServerConnector, server: ServerConfig) -> ServerAudit:
        return ServerAudit(server=server, connection_status="connected")

    monkeypatch.setattr(ServerConnector, "connect", connect)
    report = await run_scan(ScanOptions(clients=[ClientType.CURSOR], connect_project_configs=True))
    assert report.servers_connected > 0
    assert any(f.finding_type == "config_parse_failure" for f in report.config_health_findings)
    for check in ("config_health", "metadata", "permissions", "capabilities"):
        assert report.coverage[check].state == "partial"
        assert "config_parse_failure" in report.coverage[check].reason
    assert not evaluate_policy(report, PolicyConfig(fail_on_coverage=True)).passed
    assert evaluate_policy(report, PolicyConfig()).passed
    run = SarifGenerator().generate(report, profile="extended")["runs"][0]
    for result in run["results"]:
        if result["ruleId"].startswith("MCP-CH-"):
            uris = [
                location["physicalLocation"]["artifactLocation"]["uri"] for location in result["locations"]
            ]
            path = paths[1] if result["ruleId"] == "MCP-CH-CONFIG-PARSE-FAILURE" else paths[0]
            assert uris == [path.resolve().as_uri()]


@pytest.mark.anyio
@pytest.mark.parametrize("current", ["fixture-pkg@2.0.0", "fixture-pkg", "fixture-pkg@latest"])
@pytest.mark.parametrize("mixed", [False, True])
async def test_package_baseline_must_apply_to_current_config(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, current: str, mixed: bool
) -> None:
    from mcp_audit import pinning
    from mcp_audit.pkgverify import ArtifactResult, PackageRef, RegistryClient

    configs = [make_server_config(name="changed", args=[current])]
    if mixed:
        configs.append(make_server_config(name="unchanged", args=["fixture-pkg@1.0.0"]))
    store = pinning.PinStore(path=tmp_path / "pins.yaml")
    for config in configs:
        store.pin_server(
            config.name,
            [],
            server_config=config,
            package_hashes={"npm:fixture-pkg:1.0.0": "sha512-fixture"},
            artifact_hashes={"npm:fixture-pkg:1.0.0": "fixture.tgz=fixture-digest"},
        )
    monkeypatch.setattr(pinning, "PinStore", lambda: store)
    calls: list[str] = []

    def fetch_hash(self: RegistryClient, ref: PackageRef) -> str:
        calls.append("hash:" + ref.key())
        return "sha512-fixture"

    def fetch_artifact(self: RegistryClient, ref: PackageRef) -> ArtifactResult:
        calls.append("bytes:" + ref.key())
        return ArtifactResult({"fixture.tgz": "fixture-digest"}, True)

    async def connect(self: ServerConnector, server: ServerConfig) -> ServerAudit:
        return ServerAudit(server=server, connection_status="connected")

    monkeypatch.setattr(RegistryClient, "fetch_hash", fetch_hash)
    monkeypatch.setattr(RegistryClient, "fetch_artifact", fetch_artifact)
    monkeypatch.setattr(ServerConnector, "connect", connect)
    report = await run_scan(ScanOptions(verify_artifacts=True, download_artifacts=True), servers=configs)
    assert calls == (["hash:npm:fixture-pkg:1.0.0", "bytes:npm:fixture-pkg:1.0.0"] if mixed else [])
    for check in ("verify_artifacts", "download_artifacts"):
        assert report.coverage[check].state == ("partial" if mixed else "not_run")
        assert "usable baseline" in report.coverage[check].reason
    assert not evaluate_policy(report, PolicyConfig(fail_on_coverage=True)).passed


@pytest.mark.parametrize("artifact", [False, True])
@pytest.mark.parametrize(
    "condition", ["verified", "mixed", "failed", "empty", "unusable", "unexecuted", "floated"]
)
def test_package_coverage_counts_applicable_and_successfully_verified_references(
    monkeypatch: pytest.MonkeyPatch, artifact: bool, condition: str
) -> None:
    from mcp_audit import pkgverify

    refs = [pkgverify.PackageRef("npm", "fixture-pkg", "1.0.0")]
    if condition == "floated":
        refs = [pkgverify.PackageRef("npm", "fixture-pkg", "latest")]
    if condition == "mixed":
        refs.append(pkgverify.PackageRef("npm", "unbaselined-pkg", "1.0.0"))
    monkeypatch.setattr(pkgverify, "resolve_package_refs", lambda config: refs)
    baseline = {refs[0].key(): "fixture.tgz=digest" if artifact else "sha512-fixture"}
    if condition == "empty":
        baseline = {}
    elif condition == "unusable":
        baseline = {refs[0].key(): "no-file-hashes" if artifact else ""}
    calls: list[str] = []

    def fetch_hash(ref: pkgverify.PackageRef) -> str | None:
        calls.append(ref.key())
        return None if condition == "failed" else "sha512-fixture"

    def fetch_artifact(ref: pkgverify.PackageRef) -> pkgverify.ArtifactResult | None:
        calls.append(ref.key())
        return None if condition == "failed" else pkgverify.ArtifactResult({"fixture.tgz": "digest"}, True)

    verified: set[str] = set()
    config = make_server_config()
    if condition != "unexecuted":
        if artifact:
            pkgverify.ArtifactVerifier(fetch=fetch_artifact).analyze_server(
                config.name, config, baseline, verified
            )
        else:
            pkgverify.PackageVerifier(fetch=fetch_hash).analyze_server(
                config.name, config, baseline, verified
            )
    entry = pkgverify.verification_coverage(config, baseline, verified, artifact=artifact)
    expected = (
        "not_run"
        if condition in {"empty", "unusable", "floated"}
        else "complete"
        if condition == "verified"
        else "partial"
    )
    assert entry.state == expected
    assert calls == ([] if condition in {"empty", "unusable", "unexecuted", "floated"} else [refs[0].key()])
    assert verified == ({refs[0].key()} if condition in {"verified", "mixed"} else set())


def test_duplicate_config_health_locations_include_each_fixture_source() -> None:
    from mcp_audit.confighealth import config_health_findings
    from mcp_audit.discovery import CursorDiscoverer

    paths = [
        FIXTURES / "config_health/shell_remote_arg_config.json",
        FIXTURES / "config_health/remote_credentials_config.json",
    ]
    servers = [CursorDiscoverer().parse(path)[0] for path in paths]
    for server in servers:
        server.name = "duplicate-fixture"
    findings = config_health_findings(servers)
    report = AuditReport.model_validate_json((FIXTURES / "reports/config_only_report.json").read_text())
    report.config_health_findings = findings
    results = SarifGenerator().generate(report, profile="extended")["runs"][0]["results"]
    duplicate = next(result for result in results if result["ruleId"] == "MCP-CH-DUPLICATE-SERVER-NAME")
    assert {
        location["physicalLocation"]["artifactLocation"]["uri"] for location in duplicate["locations"]
    } == {path.resolve().as_uri() for path in paths}


@pytest.mark.anyio
async def test_no_eligible_tools_is_incomplete_in_html_sarif_and_policy() -> None:
    config = make_server_config(command=sys.executable, args=[str(FIXTURES / "deadbugz_server.py"), "unsafe"])
    report = await run_scan(ScanOptions(canary_check=True, timeout=15), servers=[config])
    assert report.coverage["metadata"].state == "complete"
    assert report.coverage["runtime_security"].state == "not_run"
    assert "No eligible" in report.coverage["runtime_security"].reason
    assert "Audit coverage is incomplete" in HtmlReportGenerator().generate(report)
    run = SarifGenerator().generate(report)["runs"][0]
    assert run["properties"]["mcpAuditCoverage"]["runtime_security"]["state"] == "not_run"
    assert run["invocations"][0]["toolExecutionNotifications"]
    assert not evaluate_policy(report, PolicyConfig(fail_on_coverage=True)).passed


@pytest.mark.anyio
@pytest.mark.parametrize("canary", [False, True])
async def test_pagination_flood_is_partial_and_gateable(canary: bool) -> None:
    config = make_server_config(
        command=sys.executable, args=[str(FIXTURES / "evasion_server.py"), "page_flood", "current"]
    )
    report = await run_scan(ScanOptions(canary_check=canary, timeout=15), servers=[config])
    assert report.audits[0].connection_status == "partial"
    assert not report.audits[0].tools
    assert report.servers_connected == 1 and report.servers_failed == 0
    assert report.coverage["metadata"].state == "partial"
    if canary:
        assert report.coverage["runtime_security"].state == "partial"
    assert not evaluate_policy(report, PolicyConfig(fail_on_coverage=True)).passed


@pytest.mark.anyio
async def test_bounded_clean_canary_and_unrequested_checks_pass_coverage_gate() -> None:
    config = make_server_config(command=sys.executable, args=[str(FIXTURES / "deadbugz_server.py"), "clean"])
    report = await run_scan(ScanOptions(canary_check=True, timeout=15), servers=[config])
    assert report.coverage["runtime_security"].state == "complete"
    assert report.coverage["inject_check"].state == "not_requested"
    assert evaluate_policy(report, PolicyConfig(fail_on_coverage=True)).passed


@pytest.mark.anyio
async def test_advertised_metadata_failure_is_partial_without_pagination_claim(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from mcp import Client

    async def fail(self: Client, *args: object, **kwargs: object) -> None:
        raise ValueError("fixture failure")

    monkeypatch.setattr(Client, "list_prompts", fail)
    config = make_server_config(command=sys.executable, args=[str(FIXTURES / "mock_server.py")])
    report = await run_scan(ScanOptions(timeout=15), servers=[config])
    assert report.audits[0].connection_status == "partial"
    assert report.coverage["metadata"].state == "partial"
    warning = next(warning for warning in report.warnings if warning.code == "surface_listing_incomplete")
    assert "Advertised metadata could not be listed" in warning.message
    assert "large" not in warning.message


@pytest.mark.anyio
async def test_mixed_fleet_and_missing_per_server_baseline_are_partial(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from mcp_audit import pinning

    store = pinning.PinStore(path=tmp_path / "pins.yaml")
    servers = [make_server_config(name=name) for name in ("pinned", "unpinned")]
    store.pin_server("pinned", [], server_config=servers[0])
    monkeypatch.setattr(pinning, "PinStore", lambda: store)
    report = await run_scan(ScanOptions(skip_connect=True, provenance_check=True), servers=servers)
    assert report.coverage["provenance_check"].state == "partial"
    assert "baseline unavailable" in report.coverage["provenance_check"].reason


@pytest.mark.anyio
@pytest.mark.parametrize("pinned", [False, True])
async def test_empty_tool_pin_baseline_presence(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, pinned: bool
) -> None:
    from mcp_audit import pinning
    from mcp_audit.connector import ServerConnector

    store = pinning.PinStore(path=tmp_path / "pins.yaml")
    config = make_server_config()
    if pinned:
        store.pin_server(config.name, [])
    monkeypatch.setattr(pinning, "PinStore", lambda: store)

    async def connect(self: ServerConnector, server: ServerConfig) -> ServerAudit:
        return ServerAudit(server=server, connection_status="connected")

    monkeypatch.setattr(ServerConnector, "connect", connect)
    report = await run_scan(ScanOptions(pin_check=True), servers=[config])
    assert report.audits[0].drift_findings == []
    assert report.coverage["pin_check"].state == ("complete" if pinned else "not_run")
    assert evaluate_policy(report, PolicyConfig(fail_on_coverage=True)).passed is pinned


def test_legacy_unknown_coverage_is_gateable() -> None:
    report = AuditReport.model_validate_json((FIXTURES / "reports/config_only_report.json").read_text())
    result = evaluate_policy(report, PolicyConfig(fail_on_coverage=True))
    assert not result.passed
    assert result.violations[0].rule == "fail_on.coverage"
    assert "unknown" in result.violations[0].message


def test_sparse_coverage_does_not_pass_gate() -> None:
    report = AuditReport.model_validate_json((FIXTURES / "reports/config_only_report.json").read_text())
    report.coverage = {"metadata": CheckCoverage(state="complete", reason="metadata listed")}
    assert not evaluate_policy(report, PolicyConfig(fail_on_coverage=True)).passed


def test_coverage_policy_and_extended_sarif_cli(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text("fail_on:\n  coverage: true\n")
    assert load_policy(policy_path).fail_on_coverage
    output = tmp_path / "audit.sarif"
    result = CliRunner().invoke(
        main,
        [
            "scan",
            "--config",
            "examples/sandbox/fixtures/synthetic-mcp-config.json",
            "--config-only",
            "--skip-connect",
            "--override-config",
            "/dev/null",
            "--policy",
            str(policy_path),
            "--sarif",
            str(output),
            "--sarif-profile",
            "extended",
        ],
    )
    assert result.exit_code == 2, result.output
    assert output.exists()
    assert "MCP-CH-" in output.read_text()


@pytest.mark.parametrize("value", ["partial", "yes please", 1, None])
def test_coverage_policy_rejects_ambiguous_values(tmp_path: Path, value: object) -> None:
    import yaml

    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(yaml.safe_dump({"fail_on": {"coverage": value}}))
    with pytest.raises(ValueError, match="must be a boolean"):
        load_policy(policy_path)
