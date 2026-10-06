"""In-process scan regression suite for the synthetic evasion corpus."""

from __future__ import annotations

import json
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import cast

import pytest

from mcp_audit.engine import ScanOptions, run_scan
from mcp_audit.models import ClientType, ServerConfig

HERE = Path(__file__).resolve().parent
FIXTURE = HERE.parent / "fixtures" / "evasion_server.py"
CORPUS_PATH = HERE / "corpus.json"
CORPUS = cast(list[dict[str, object]], json.loads(CORPUS_PATH.read_text())["cases"])

_GAP_REASONS = {
    "escalation-annotations-only": "gap 21: fixed by P1-2",
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
    "gate-on-elapsed-time": "gap 13: fixed by F-1 (not_excluded)",
    "gate-on-randomness": "gap 14: fixed by F-1 (not_excluded)",
    "flip-after-more-than-k": "gap 15: fixed by F-1 (not_excluded)",
    "flip-after-final-listing": "gap 16: fixed by F-1 (not_excluded)",
    "split-across-tools-fields": "gap 3: unplanned cross-field detection",
}


def _parametrize_cases() -> list[object]:
    parameters: list[object] = []
    for case in CORPUS:
        case_id = str(case["id"])
        reason = _GAP_REASONS.get(case_id)
        marks = pytest.mark.xfail(strict=True, reason=reason) if reason else ()
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


@pytest.mark.redteam
@pytest.mark.anyio
@pytest.mark.parametrize("case", _parametrize_cases())
async def test_detector_gap_corpus(
    case: dict[str, object], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Exercise each corpus mode through run_scan and assert its detector contract."""
    phase = str(case["phase"])
    detector = case["detector"]
    assert isinstance(detector, dict)
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
        if kind == "injection":
            assert any(f.tool_name == detector["tool"] for f in audit.injection_findings)
        elif kind == "prompt_injection":
            assert any(
                f.target_type == "prompt" and f.target_name == detector["prompt"]
                for f in audit.injection_findings
            )
        elif kind == "resource_injection":
            assert any(
                f.target_type == "resource" and f.target_name == detector["resource"]
                for f in audit.injection_findings
            )
        elif kind == "injection_or_coverage":
            assert any(f.tool_name in detector["tools"] for f in audit.injection_findings) or any(
                "cross_field" in warning.code for warning in report.warnings
            )
        elif kind == "annotation_contradiction":
            categories = {finding.category.value for finding in audit.permissions}
            assert "destructive" in categories or "file_write" in categories
            assert any("annotation" in warning.code for warning in report.warnings)
        elif kind == "ssrf_and_egress":
            assert any(f.target_name == detector["tool"] for f in audit.ssrf_findings)
            assert any(f.target_name == detector["tool"] for f in audit.egress_findings)
        elif kind == "shadowing":
            assert any(
                detector["peer"] in {tool_name for _, tool_name in finding.collisions}
                for finding in report.shadowing_findings
            )
        else:
            raise AssertionError(f"Unknown static detector contract: {kind}")
        return

    if phase == "canary":
        report = await run_scan(
            ScanOptions(config_only=True, inject_check=True, canary_check=True, canary_calls=5, timeout=60),
            servers=[_server(case)],
        )
        audit = report.audits[0]
        if kind == "canary_not_excluded":
            assert audit.canary is not None
            summary = audit.canary.model_dump()
            assert summary.get("not_excluded")
        elif kind == "runtime_injection":
            assert any(
                f.after_call is not None and f.tool_name == detector["tool"] for f in audit.injection_findings
            )
        elif kind == "canary_warning":
            # Since 2.8.0 the page-limit failure is surfaced as a coverage warning;
            # assert its stable code, not the implementation-specific warning text.
            assert any(warning.code == detector["code"] for warning in report.warnings)
        else:
            raise AssertionError(f"Unknown canary detector contract: {kind}")
        return

    if phase == "pin":
        from mcp_audit import pinning

        monkeypatch.setenv("HOME", str(tmp_path))
        pin_path = tmp_path / ".mcp-audit-pins.yaml"
        real_pin_store = pinning.PinStore
        monkeypatch.setattr(pinning, "PinStore", lambda: real_pin_store(path=pin_path))

        baseline = await run_scan(
            ScanOptions(config_only=True, timeout=60), servers=[_server(case, stage="baseline")]
        )
        real_pin_store(path=pin_path).pin_server(str(case["id"]), baseline.audits[0].tools)
        report = await run_scan(
            ScanOptions(
                config_only=True,
                inject_check=True,
                pin_check=True,
                escalation_check=True,
                timeout=60,
            ),
            servers=[_server(case, stage="current")],
        )
        audit = report.audits[0]
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
            raise AssertionError(f"Unknown pin detector contract: {kind}")
        return

    raise AssertionError(f"Unknown corpus phase: {phase}")


@pytest.mark.redteam
@pytest.mark.anyio
@pytest.mark.xfail(strict=True, reason="gap 21: fixed by P1-2")
async def test_annotation_flip_is_drift_and_escalation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Pin v2 must retain annotations and report both drift and capability gain."""
    from mcp_audit import pinning

    case = {"id": "annotation-flip-acceptance", "mode": "esc_annotations"}
    monkeypatch.setenv("HOME", str(tmp_path))
    pin_path = tmp_path / ".mcp-audit-pins.yaml"
    real_pin_store = pinning.PinStore
    monkeypatch.setattr(pinning, "PinStore", lambda: real_pin_store(path=pin_path))

    baseline = await run_scan(ScanOptions(config_only=True), servers=[_server(case, stage="baseline")])
    real_pin_store(path=pin_path).pin_server(str(case["id"]), baseline.audits[0].tools)
    current = await run_scan(
        ScanOptions(config_only=True, pin_check=True, escalation_check=True),
        servers=[_server(case, stage="current")],
    )
    audit = current.audits[0]
    assert any(f.status.value == "changed" for f in audit.drift_findings)
    assert any(f.kind.value == "capability" for f in audit.escalation_findings)
