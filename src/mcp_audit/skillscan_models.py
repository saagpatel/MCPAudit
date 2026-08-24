"""Strict models for the skillscan-report/v1 interchange contract."""

from __future__ import annotations

import json
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class StrictModel(BaseModel):
    """Forbid fields outside the scanner-to-sealer contract."""

    model_config = ConfigDict(extra="forbid", strict=True)


class SkillscanSubject(StrictModel):
    kind: Literal["skill_bundle", "mcp_server"]
    name: str = Field(min_length=1)
    digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    media_type: Literal[
        "application/vnd.checkseal.bundle-manifest+json",
        "application/vnd.mcpb+zip",
    ]


class SkillscanRuleset(StrictModel):
    config_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    rules: list[str]


class SkillscanDetail(StrictModel):
    rule_id: str = Field(pattern=r"^SKILL[0-9]{3}$")
    path: str
    line: int = Field(ge=0)
    excerpt: str


class SkillscanCheck(StrictModel):
    id: Literal[
        "scan/injection-patterns",
        "scan/obfuscated-egress",
        "scan/dynamic-fetch-presence",
        "scan/permission-surface",
    ]
    result: Literal["pass", "fail", "error"]
    findings: int = Field(ge=0)
    rule_ids: list[str]
    detail: list[SkillscanDetail]


class SkillscanReport(StrictModel):
    schema_version: Literal["skillscan-report/v1"] = Field(
        default="skillscan-report/v1",
        alias="schema",
        serialization_alias="schema",
    )
    scanner: Literal["mcp-audit"] = "mcp-audit"
    scanner_version: str = Field(min_length=1)
    ran_at: str
    subject: SkillscanSubject
    ruleset: SkillscanRuleset
    checks: list[SkillscanCheck]


def report_json_bytes(report: SkillscanReport) -> bytes:
    """Serialize a stable UTF-8 report with the required trailing newline."""
    payload = report.model_dump(mode="json", by_alias=True)
    return (json.dumps(payload, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
