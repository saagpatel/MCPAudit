"""Keep the 3.0 migration guide linked, complete, and true to the interceptor."""

from __future__ import annotations

from pathlib import Path

import pytest

from mcp_audit import _core_cli
from mcp_audit.scan_translation import ScanTranslation, classify_scan_options

GUIDE = Path("docs/3.0-MIGRATION.md")
# Docs and examples whose commands must use check grammar. Pinned historical
# commands (for example `mcp-audits==2.2.0` in the trust packet) are excluded.
SWEPT = [
    Path("docs/ADOPTION-GUIDE.md"),
    Path("docs/EGRESS-DETECTION.md"),
    Path("docs/ESCALATION-DETECTION.md"),
    Path("docs/INTEGRITY-DETECTION.md"),
    Path("docs/PACKAGE-VERIFICATION.md"),
    Path("docs/PROVENANCE-DETECTION.md"),
    Path("docs/SHADOWING-DETECTION.md"),
    Path("docs/SSRF-DETECTION.md"),
    Path("docs/TRIFECTA-DETECTION.md"),
    Path("docs/guides/pinning.md"),
    Path("docs/guides/suppressing.md"),
    Path("docs/assets/hero.tape"),
    Path("docs/assets/policy-gate-demo.sh"),
    Path("examples/consumers/README.md"),
    Path("examples/sandbox/README.md"),
    Path("maintainers/GOLDEN-ROLLOUT.md"),
    Path("maintainers/LAUNCH-RESPONSE-PLAYBOOK.md"),
    Path("maintainers/MAINTAINER-WORKFLOWS.md"),
    *sorted(Path("examples/policies").glob("*")),
]


def _flat(path: Path) -> str:
    return " ".join(path.read_text(encoding="utf-8").split())


def _classify(argv: list[str]) -> ScanTranslation:
    with _core_cli.scan.make_context("scan", argv) as context:
        return classify_scan_options(context.params)


def test_guide_is_linked_from_entry_points() -> None:
    assert GUIDE.is_file()
    assert "docs/3.0-MIGRATION.md" in Path("README.md").read_text(encoding="utf-8")
    assert "(3.0-MIGRATION.md)" in Path("docs/README.md").read_text(encoding="utf-8")
    assert "3.0-MIGRATION.md" in Path("docs/guides/scan-migration.md").read_text(encoding="utf-8")


@pytest.mark.parametrize(
    "phrase",
    [
        "--scan-compatible-sources",
        "supported for all of 3.x",
        "`--json PATH`",
        "comma-separated `--clients a,b`",
        "Unaffected until you bump",
        "Do not rewrite a 2.11 hook",
        "`mcp-audit check --include-discovered --inject-check`",
        "review the selected project",
        "The Action installs only `mcp-audits`",
        "`lab` commands through Action `args` are not supported",
        "uv tool install mcp-audits-proof",
        "uv tool install 'mcp-audits[labs]'",
        "`proof_before_action.proof_cli`",
        "`mcp_audit_labs.safeforge*`",
        "`mcp_audit.client_filter._parse_clients`",
        "`scan: no exact check translation exists:`",
        "even without `--policy`",
        "`fail_on.pin_baseline_withheld: false` is accepted but ignored",
        "`watch` never exits for this",
        "`no_sources_reviewed`",
        "`MCP-CH-CONFIG-PARSE-FAILURE`",
        "1,048,576 bytes",
        "`connect=true`",
        "`get_artifact_verify_findings`",
        "`pin` stays as a permanent, visible alias",
    ],
)
def test_guide_names_each_documented_break(phrase: str) -> None:
    assert phrase in _flat(GUIDE)


def test_guide_makes_no_release_date_claim() -> None:
    text = GUIDE.read_text(encoding="utf-8")
    assert "3.0.0 -" not in text
    assert "released on" not in text.lower()


@pytest.mark.parametrize(
    ("argv", "coverage", "command"),
    [
        ([], "would-silently-shrink", "mcp-audit check --include-discovered --connect-all"),
        (
            ["--skip-connect"],
            "preserved",
            "mcp-audit check --skip-connect --include-discovered --scan-compatible-sources",
        ),
        (
            ["--skip-connect", "--inject-check"],
            "preserved",
            "mcp-audit check --skip-connect --inject-check --include-discovered --scan-compatible-sources",
        ),
        (
            ["--skip-connect", "--clients", "cursor"],
            "preserved",
            "mcp-audit check --skip-connect --client cursor --include-discovered --scan-compatible-sources",
        ),
        (
            ["--skip-connect", "--json", "out.json"],
            "would-silently-shrink",
            "mcp-audit check --output-json out.json --skip-connect --include-discovered "
            "--scan-compatible-sources",
        ),
        (
            ["--skip-connect", "--clients", "claude_code,cursor"],
            "would-silently-shrink",
            "mcp-audit check --skip-connect --client claude_code --client cursor --include-discovered "
            "--scan-compatible-sources",
        ),
        (
            ["--config", "mcp.json", "--config-only", "--skip-connect", "--override-config", "o.yaml"],
            "narrowed",
            "mcp-audit check --skip-connect --config mcp.json --config-only --override-config o.yaml",
        ),
        (
            ["--config", "mcp.json", "--config-only", "--skip-connect"],
            "would-silently-shrink",
            "mcp-audit check --skip-connect --config mcp.json --config-only",
        ),
        (
            ["--config", "mcp.json", "--skip-connect"],
            "would-silently-shrink",
            "mcp-audit check --skip-connect --config mcp.json --include-discovered",
        ),
        (
            ["--connect-project-configs"],
            "would-silently-shrink",
            "mcp-audit check --connect-project-configs --include-discovered --connect-all",
        ),
        (
            ["--pin-check"],
            "would-silently-shrink",
            "mcp-audit check --pin-check --include-discovered --connect-all",
        ),
    ],
)
def test_flag_mapping_matches_the_interceptor(argv: list[str], coverage: str, command: str) -> None:
    translation = _classify(argv)
    assert translation.coverage == coverage
    printed = translation.check_argv if translation.check_argv is not None else translation.replacement_argv
    assert " ".join(printed) == command


@pytest.mark.parametrize("path", SWEPT, ids=str)
def test_swept_docs_use_check_grammar(path: Path) -> None:
    assert "mcp-audit scan" not in path.read_text(encoding="utf-8")
