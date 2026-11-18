"""The signed provenance must name the approved release commit, not only the controls commit."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts import release_provenance as provenance

RELEASE = "1" * 40
CONTROLS = "2" * 40
ENV = {
    "GITHUB_SERVER_URL": "https://github.com",
    "GITHUB_REPOSITORY": "saagpatel/MCPAudit",
    "GITHUB_WORKFLOW_REF": "saagpatel/MCPAudit/.github/workflows/publish.yml@refs/heads/main",
    "GITHUB_RUN_ID": "200",
    "GITHUB_RUN_ATTEMPT": "1",
    "GITHUB_EVENT_NAME": "workflow_dispatch",
    "RELEASE_VERSION": "3.1.0",
    "RELEASE_COMMIT": RELEASE,
    "CONTROL_SHA": CONTROLS,
    "MANIFEST_SHA256": "a" * 64,
    "BUILD_RUN_ID": "100",
    "RESUME": "true",
}


def test_predicate_records_source_and_controls_separately() -> None:
    predicate = provenance.build_predicate(ENV)
    assert provenance.predicate_commit(predicate, "release-source") == RELEASE
    assert provenance.predicate_commit(predicate, "release-controls") == CONTROLS
    definition = predicate["buildDefinition"]
    assert isinstance(definition, dict)
    assert definition["externalParameters"]["inputs"] == {
        "version": "3.1.0",
        "commit": RELEASE,
        "resume": True,
    }
    assert definition["externalParameters"]["workflow"]["path"] == ".github/workflows/publish.yml"
    assert definition["internalParameters"]["build_run"].endswith("/actions/runs/100")
    run = predicate["runDetails"]
    assert isinstance(run, dict)
    assert run["metadata"]["invocationId"].endswith("/actions/runs/200/attempts/1")
    assert run["byproducts"] == [{"name": "release-manifest.json", "digest": {"sha256": "a" * 64}}]


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("RELEASE_COMMIT", "abc"),
        ("CONTROL_SHA", ""),
        ("MANIFEST_SHA256", "z" * 64),
        ("RELEASE_VERSION", "3.1.0; rm"),
        ("BUILD_RUN_ID", "1a"),
        ("GITHUB_WORKFLOW_REF", "other/repo/.github/workflows/publish.yml@refs/heads/main"),
    ],
)
def test_malformed_input_is_refused(name: str, value: str) -> None:
    with pytest.raises(provenance.ProvenanceError):
        provenance.build_predicate({**ENV, name: value})


def test_cli_writes_json_and_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    for key, value in ENV.items():
        monkeypatch.setenv(key, value)
    out = tmp_path / "predicate.json"
    assert provenance.main(["--output", str(out)]) == 0
    assert provenance.predicate_commit(json.loads(out.read_text()), "release-source") == RELEASE
    monkeypatch.setenv("RELEASE_COMMIT", "not-a-commit")
    bad = tmp_path / "bad.json"
    assert provenance.main(["--output", str(bad)]) == 1
    assert not bad.exists()
