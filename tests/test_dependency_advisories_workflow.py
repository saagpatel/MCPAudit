"""Acceptance checks for the restored OSV advisory workflow."""

from __future__ import annotations

import re
from pathlib import Path

import yaml


WORKFLOW = Path(".github/workflows/dependency-advisories.yml")


def test_dependency_advisory_workflow_contract() -> None:
    source = WORKFLOW.read_text(encoding="utf-8")
    workflow = yaml.load(source, Loader=yaml.BaseLoader)

    assert workflow["name"] == "Dependency advisories"
    assert workflow["on"] == {
        "pull_request": {"branches": ["main"]},
        "schedule": [{"cron": "17 12 * * 1"}],
        "workflow_dispatch": None,
    }
    assert workflow["permissions"] == {"contents": "read"}

    job = workflow["jobs"]["osv"]
    assert job["permissions"] == {"contents": "read"}
    assert job["steps"] == [
        {
            "name": "Check out repository",
            "uses": "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
        },
        {
            "name": "Check locked dependencies against OSV",
            "run": "python3 scripts/check_advisories.py",
        },
    ]

    action_references = re.findall(r"^\s+uses:\s+(\S+)", source, re.MULTILINE)
    assert action_references
    assert all(re.fullmatch(r"[^@]+@[0-9a-f]{40}(?:\s+#.*)?", ref) for ref in action_references)
