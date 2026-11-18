#!/usr/bin/env python3
"""Write the SLSA v1 provenance predicate the publish job signs for the six release files.

The default ``actions/attest`` provenance records only the workflow commit (``github.sha``),
which for this main-dispatched train is the release-controls revision. The files themselves
are built from the approved ``inputs.commit``, which can be older. This predicate records both
as separate resolved dependencies so a verifier can tell the source from the controls, and
binds the approved manifest digest and the run that built the bytes. Standard library only;
every value comes from the environment and is validated before it is written.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
BUILD_TYPE = "https://actions.github.io/buildtypes/workflow/v1"
COMMIT = re.compile(r"[0-9a-f]{40}")
SHA256 = re.compile(r"[0-9a-f]{64}")
VERSION = re.compile(r"[0-9]+(?:\.[0-9]+)*(?:(?:a|b|rc)[0-9]+)?")
RUN_ID = re.compile(r"[0-9]+")
WORKFLOW_REF = re.compile(r"(?P<repo>[^/@]+/[^/@]+)/(?P<path>\.github/workflows/[^@]+)@(?P<ref>refs/\S+)")


class ProvenanceError(ValueError):
    """An input needed for the predicate is missing or malformed."""


def _require(env: dict[str, str], name: str, pattern: re.Pattern[str] | None = None) -> str:
    value = env.get(name, "")
    if not value or (pattern is not None and pattern.fullmatch(value) is None):
        raise ProvenanceError(f"{name} is missing or malformed: {value!r}")
    return value


def build_predicate(env: dict[str, str]) -> dict[str, object]:
    server = _require(env, "GITHUB_SERVER_URL").rstrip("/")
    repository = _require(env, "GITHUB_REPOSITORY")
    workflow = WORKFLOW_REF.fullmatch(_require(env, "GITHUB_WORKFLOW_REF"))
    if workflow is None or workflow["repo"] != repository:
        raise ProvenanceError(f"GITHUB_WORKFLOW_REF does not name {repository}")
    version = _require(env, "RELEASE_VERSION", VERSION)
    release_commit = _require(env, "RELEASE_COMMIT", COMMIT)
    control_sha = _require(env, "CONTROL_SHA", COMMIT)
    manifest_sha256 = _require(env, "MANIFEST_SHA256", SHA256)
    build_run_id = _require(env, "BUILD_RUN_ID", RUN_ID)
    run_id = _require(env, "GITHUB_RUN_ID", RUN_ID)
    attempt = _require(env, "GITHUB_RUN_ATTEMPT", RUN_ID)
    resume = env.get("RESUME", "false") == "true"
    repo_url = f"{server}/{repository}"

    return {
        "buildDefinition": {
            "buildType": BUILD_TYPE,
            "externalParameters": {
                "workflow": {"ref": workflow["ref"], "repository": repo_url, "path": workflow["path"]},
                "inputs": {"version": version, "commit": release_commit, "resume": resume},
            },
            "internalParameters": {
                "github": {
                    "event_name": env.get("GITHUB_EVENT_NAME", ""),
                    "repository_id": env.get("GITHUB_REPOSITORY_ID", ""),
                    "repository_owner_id": env.get("GITHUB_REPOSITORY_OWNER_ID", ""),
                    "runner_environment": env.get("RUNNER_ENVIRONMENT", ""),
                },
                "build_run": f"{repo_url}/actions/runs/{build_run_id}",
            },
            "resolvedDependencies": [
                {
                    "uri": f"git+{repo_url}",
                    "name": "release-source",
                    "digest": {"gitCommit": release_commit},
                    "annotations": {"role": "approved commit the six files were built from"},
                },
                {
                    "uri": f"git+{repo_url}@{workflow['ref']}",
                    "name": "release-controls",
                    "digest": {"gitCommit": control_sha},
                    "annotations": {"role": "workflow and verifier scripts that built and checked the files"},
                },
            ],
        },
        "runDetails": {
            "builder": {"id": "https://github.com/actions/runner/github-hosted"},
            "metadata": {"invocationId": f"{repo_url}/actions/runs/{run_id}/attempts/{attempt}"},
            "byproducts": [{"name": "release-manifest.json", "digest": {"sha256": manifest_sha256}}],
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        predicate = build_predicate(dict(os.environ))
    except ProvenanceError as exc:
        print(f"::error::{exc}", file=sys.stderr)
        return 1
    args.output.write_text(json.dumps(predicate, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"provenance predicate: release-source {predicate_commit(predicate, 'release-source')}")
    print(f"provenance predicate: release-controls {predicate_commit(predicate, 'release-controls')}")
    return 0


def predicate_commit(predicate: dict[str, object], name: str) -> str:
    definition = predicate["buildDefinition"]
    assert isinstance(definition, dict)
    for dependency in definition["resolvedDependencies"]:
        if dependency["name"] == name:
            return str(dependency["digest"]["gitCommit"])
    raise KeyError(name)


if __name__ == "__main__":
    sys.exit(main())
