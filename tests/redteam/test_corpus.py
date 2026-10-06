"""In-process scan regression suite for the synthetic evasion corpus."""

from __future__ import annotations

import json
import sys
from collections.abc import Callable, Iterator, Mapping
from pathlib import Path
from typing import cast

import pytest

from mcp_audit.engine import ScanOptions, run_scan
from mcp_audit.models import ClientType, ServerAudit, ServerConfig
from mcp_audit.pinning import PinStore

HERE = Path(__file__).resolve().parent
FIXTURE = HERE.parent / "fixtures" / "evasion_server.py"
CORPUS_PATH = HERE / "corpus.json"
CORPUS = cast(list[dict[str, object]], json.loads(CORPUS_PATH.read_text())["cases"])

_GAP_REASONS = {
    "lying-annotations": "gap 9: fixed by P1-3",
    "schema-text-injection": "gap 1: fixed by P1-4",
    "annotation-title-injection": "gap 2: fixed by P1-4",
    "prompt-argument-text": "gap 7: fixed by P1-4",
    "unicode-tag-block": "gap 4: fixed by P1-5",
    "homoglyph-instructions": "gap 5: fixed by P1-5",
    "shadow-fullwidth-zerowidth": "gap 11: fixed by P1-5",
    "result-unicode-tags": "gap 18: fixed by P1-5",
    "result-homoglyph": "gap 19: fixed by P1-5",
    "escalation-homoglyph-desc": "gap 23: fixed by P1-5",
    "base64-encoded-payload": "gap 6: fixed by P1-6",
    "escalation-nested-schema": "gap 22: fixed by P1-12",
    "gate-on-client-name": "gap 12: fixed by P2-7",
    "split-across-tools-fields": "gap 3: unplanned cross-field detection",
}


def _parametrize_cases() -> list[object]:
    parameters: list[object] = []
    for case in CORPUS:
        case_id = str(case["id"])
        reason = _GAP_REASONS.get(case_id)
        marks = pytest.mark.xfail(strict=True, raises=AssertionError, reason=reason) if reason else ()
        parameters.append(pytest.param(case, id=case_id, marks=marks))
    return parameters


def _server(case: Mapping[str, object], name: str | None = None, stage: str = "current") -> ServerConfig:
    return ServerConfig(
        name=name or str(case["id"]),
        client=ClientType.CLAUDE_DESKTOP,
        config_path="synthetic://redteam-corpus",
        command=sys.executable,
        args=["-I", str(FIXTURE), str(case["mode"]), stage],
    )


def _finding_labels(audit: ServerAudit, fields: set[str]) -> Iterator[str]:
    for name, findings in audit.model_dump(mode="json").items():
        if name not in {"permissions", "capability_findings"} and not name.endswith("_findings"):
            continue
        if not isinstance(findings, list):
            continue
        for finding in findings:
            if isinstance(finding, dict):
                for field in fields:
                    value = finding.get(field)
                    if isinstance(value, str):
                        yield value.casefold()


@pytest.fixture
def isolated_pin_store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Callable[..., PinStore]:
    from mcp_audit import pinning

    pin_path = tmp_path / ".mcp-audit-pins.yaml"
    real_pin_store = pinning.PinStore
    monkeypatch.setattr(pinning, "DEFAULT_PIN_PATH", pin_path)
    monkeypatch.setattr(pinning, "PinStore", lambda *a, **k: real_pin_store(path=pin_path))
    return pinning.PinStore


async def _scan_pinned_case(case: Mapping[str, object], pin_store: Callable[..., PinStore]) -> ServerAudit:
    baseline = await run_scan(
        ScanOptions(config_only=True, timeout=60), servers=[_server(case, stage="baseline")]
    )
    baseline_audit = baseline.audits[0]
    if baseline_audit.connection_status != "connected" or not baseline_audit.tools:
        raise RuntimeError("Pin baseline fixture did not connect and list tools")
    store = pin_store()
    store.pin_server(str(case["id"]), baseline_audit.tools)
    if not store.path.exists() or str(case["id"]) not in pin_store().pinned_servers():
        raise RuntimeError("Pin baseline was not written")
    report = await run_scan(
        ScanOptions(config_only=True, inject_check=True, pin_check=True, escalation_check=True, timeout=60),
        servers=[_server(case, stage="current")],
    )
    audit = report.audits[0]
    if audit.connection_status != "connected" or not audit.tools:
        raise RuntimeError("Current pin fixture did not connect and list tools")
    return audit


@pytest.mark.redteam
@pytest.mark.anyio
@pytest.mark.parametrize("case", _parametrize_cases())
async def test_detector_gap_corpus(
    case: dict[str, object], isolated_pin_store: Callable[..., PinStore]
) -> None:
    """Exercise each corpus mode through run_scan and assert its detector contract."""
    phase = str(case["phase"])
    detector = case["detector"]
    if not isinstance(detector, dict):
        raise TypeError("Corpus detector contract must be an object")
    kind = str(detector["kind"])
    if phase == "static":
        servers = [_server(case)]
        if kind == "shadowing":
            peer_case = {**case, "mode": "shadow_plain"}
            servers.append(_server(peer_case, name="shadow-plain-peer", stage="current"))
        report = await run_scan(
            ScanOptions(
                config_only=True,
                inject_check=True,
                ssrf_check=True,
                egress_check=True,
                trifecta_check=True,
                shadow_check=True,
                timeout=60,
            ),
            servers=servers,
        )
        audit = next(audit for audit in report.audits if audit.server.name == str(case["id"]))
        if audit.connection_status != "connected":
            raise RuntimeError("Static corpus fixture did not connect")
        if kind == "injection":
            assert any(f.tool_name == detector["tool"] for f in audit.injection_findings)
        elif kind == "prompt_injection":
            assert any(
                f.target_type == "prompt" and f.target_name == detector["prompt"]
                for f in audit.injection_findings
            )
        elif kind == "resource_injection":
            patterns = {
                f.pattern_name
                for f in audit.injection_findings
                if f.target_type == "resource" and f.target_name == detector["resource"]
            }
            assert len(patterns) >= 2
        elif kind == "injection_or_coverage":
            assert any(f.tool_name in detector["tools"] for f in audit.injection_findings) or any(
                "cross_field" in warning.code for warning in report.warnings
            )
        elif kind == "annotation_contradiction":
            categories = {finding.category.value for finding in audit.permissions}
            assert "destructive" in categories or "file_write" in categories
            # P1-3 should tighten this to the exact annotation-contradiction field.
            assert "annotation_contradiction" in set(
                _finding_labels(audit, {"category", "kind", "rule", "rule_name", "pattern_name"})
            )
        elif kind == "ssrf_and_egress":
            assert any(f.target_name == detector["tool"] for f in audit.ssrf_findings)
            assert any(f.target_name == detector["tool"] for f in audit.egress_findings)
        elif kind == "shadowing":
            assert any(
                detector["peer"] in {tool_name for _, tool_name in finding.collisions}
                for finding in report.shadowing_findings
            )
        else:
            raise RuntimeError(f"Unknown static detector contract: {kind}")
        return

    if phase == "canary":
        report = await run_scan(
            ScanOptions(config_only=True, inject_check=True, canary_check=True, canary_calls=5, timeout=60),
            servers=[_server(case)],
        )
        audit = report.audits[0]
        if audit.connection_status != "connected":
            raise RuntimeError("Canary corpus fixture did not connect")
        if kind == "canary_not_excluded":
            if audit.canary is None:
                raise RuntimeError("Canary corpus fixture did not produce a summary")
            summary = audit.canary.model_dump()
            assert detector["limit"] in (summary.get("not_excluded") or [])
        elif kind == "drift_or_identity":
            # The fixture gates on literal "mcp". When F-1 sends "mcp-audit",
            # update it to gate on that identity (or on "not mcp-audit").
            assert any(f.source == "session" for f in audit.drift_findings) or any(
                "identity" in label for label in _finding_labels(audit, {"code", "kind"})
            )
        elif kind == "runtime_injection":
            patterns = {
                f.pattern_name
                for f in audit.injection_findings
                if f.after_call is not None and f.tool_name == detector["tool"]
            }
            assert len(patterns) >= (2 if case["id"] == "result-plain-control" else 1)
        elif kind == "canary_warning":
            # As of 2.8.0 the page-limit failure is surfaced as a coverage warning;
            # assert its stable code, not the implementation-specific warning text.
            assert any(warning.code == detector["code"] for warning in report.warnings)
        else:
            raise RuntimeError(f"Unknown canary detector contract: {kind}")
        return

    if phase == "pin":
        audit = await _scan_pinned_case(case, isolated_pin_store)
        if kind == "drift_or_escalation":
            assert any(
                f.status.value == "changed" and f.tool_name == detector["tool"] for f in audit.drift_findings
            ) or any(f.tool_name == detector["tool"] for f in audit.escalation_findings)
        elif kind == "escalation":
            assert any(
                f.tool_name == detector["tool"]
                and f.kind.value == "capability"
                and detector["category"] in {category.value for category in f.gained_categories}
                for f in audit.escalation_findings
            )
        elif kind == "escalation_injection":
            assert any(
                f.tool_name == detector["tool"] and f.kind.value == "description_injection"
                for f in audit.escalation_findings
            )
        else:
            raise RuntimeError(f"Unknown pin detector contract: {kind}")
        return

    raise RuntimeError(f"Unknown corpus phase: {phase}")


@pytest.mark.redteam
@pytest.mark.anyio
async def test_pin_drift_control(isolated_pin_store: Callable[..., PinStore]) -> None:
    """A schema change proves the isolated pin comparison is active."""
    from mcp_audit import pinning

    case = {"id": "pin-drift-control", "mode": "esc_nested_schema"}
    audit = await _scan_pinned_case(case, isolated_pin_store)
    pin_path = isolated_pin_store().path
    assert pin_path.exists()
    assert any(f.status.value == "changed" and f.tool_name == "status" for f in audit.drift_findings)
    # Both the default and explicit-path constructors stay on the isolated store.
    assert pinning.DEFAULT_PIN_PATH == pin_path
    assert pinning.PinStore().path == pin_path
    assert pinning.PinStore(path=pin_path).path == pin_path


@pytest.mark.redteam
@pytest.mark.anyio
async def test_annotation_flip_is_drift_and_escalation(
    isolated_pin_store: Callable[..., PinStore],
) -> None:
    """Pin v2 must retain annotations and report both drift and capability gain."""
    case = {"id": "annotation-flip-acceptance", "mode": "esc_annotations"}
    audit = await _scan_pinned_case(case, isolated_pin_store)
    assert any(f.status.value == "changed" for f in audit.drift_findings)
    assert any(f.kind.value == "capability" for f in audit.escalation_findings)
    assert any(
        f.kind.value == "annotation_delta" and f.severity.value == "high" for f in audit.escalation_findings
    )
