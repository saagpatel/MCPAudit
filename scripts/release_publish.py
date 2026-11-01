#!/usr/bin/env python3
"""Bounded publication staging and recovery; never uploads or creates a tag."""

from __future__ import annotations

import argparse
import email.message
import hashlib
import json
import os
import re
import shutil
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from pathlib import Path

if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts import verify_release as release

JsonFetch = Callable[[str], object]

# PyPI's JSON API can trail an upload by a minute or more; the workflow readback waits this long.
READBACK_ATTEMPTS = 13
READBACK_DELAY_SECONDS = 10.0


def fetch_json(url: str) -> object:
    headers = {"Accept": "application/json"}
    if url.startswith("https://api.github.com/"):
        headers["Authorization"] = f"Bearer {os.environ['GH_TOKEN']}"
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.load(response)


def validate_dispatch(
    commit: str, version: str, resume: bool, run_id: str, digest: str, control: str
) -> None:
    if release.COMMIT_RE.fullmatch(commit) is None or release.VERSION_RE.fullmatch(version) is None:
        raise release.VerificationError("dispatch requires an exact commit and numeric X.Y.Z version")
    if version.startswith("2."):
        raise release.VerificationError("main publication requires the split release contract")
    if resume:
        if (
            re.fullmatch(r"[1-9][0-9]*", run_id) is None
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            or release.COMMIT_RE.fullmatch(control) is None
        ):
            raise release.VerificationError(
                "resume requires original run_id, manifest SHA-256 and control SHA"
            )
    elif run_id or digest or control:
        raise release.VerificationError("recovery approvals are only valid with resume=true")


def artifact_name(version: str) -> str:
    return f"mcp-audits-{version}"


def verify_run(
    run_id: str, control: str, repository: str, version: str, *, fetch: JsonFetch = fetch_json
) -> None:
    """The approved manifest binds source commit; GitHub binds original run and controls."""
    base = f"https://api.github.com/repos/{repository}/actions/runs/{run_id}"
    run = fetch(base)
    if not isinstance(run, dict) or any(
        run.get(key) != value
        for key, value in {
            "id": int(run_id),
            "path": ".github/workflows/publish.yml",
            "head_sha": control,
            "head_branch": "main",
            "event": "workflow_dispatch",
            "status": "completed",
        }.items()
    ):
        raise release.VerificationError("original run is not this main workflow at the approved control SHA")
    repo = run.get("repository")
    if not isinstance(repo, dict) or repo.get("full_name") != repository:
        raise release.VerificationError("original run repository does not match")
    # A publication failure is recoverable; a failed/skipped original smoke is not.
    jobs: dict[str, str] = {}
    for page in range(1, 101):
        raw = fetch(f"{base}/jobs?per_page=100&page={page}")
        if not isinstance(raw, dict) or not isinstance(raw.get("jobs"), list):
            raise release.VerificationError("original run jobs are unreadable")
        for job in raw["jobs"]:
            if not isinstance(job, dict):
                raise release.VerificationError("original run job is invalid")
            jobs[str(job.get("name"))] = str(job.get("conclusion"))
        if len(raw["jobs"]) < 100:
            break
    else:
        raise release.VerificationError("original run job pagination exceeded limit")
    if any(
        jobs.get(name) != "success" for name in ("Verify and build exact release", "Smoke disposable copies")
    ):
        raise release.VerificationError("original build and consumer smoke must have succeeded")
    raw = fetch(f"{base}/artifacts?per_page=100")
    if not isinstance(raw, dict) or not isinstance(raw.get("artifacts"), list):
        raise release.VerificationError("original run artifacts are unreadable")
    matches = [a for a in raw["artifacts"] if isinstance(a, dict) and a.get("name") == artifact_name(version)]
    if len(matches) != 1 or matches[0].get("expired") is not False:
        raise release.VerificationError("retained artifacts unavailable or expired; cut a new patch version")


def approved_files(candidate: Path, version: str, commit: str, control: str, digest: str) -> dict[str, str]:
    manifest = candidate / "release-manifest.json"
    if (
        re.fullmatch(r"[0-9a-f]{64}", digest) is None
        or hashlib.sha256(manifest.read_bytes()).hexdigest() != digest
    ):
        raise release.VerificationError("manifest SHA-256 does not match approval")
    files = release.verify_manifest(
        json.loads(manifest.read_text()), version=version, commit=commit, workflow_sha=control
    )
    if dict(release.distribution_hashes(candidate / "dist", version)) != files:
        raise release.VerificationError("retained artifact digests do not match approval")
    return files


def pypi_response(name: str, version: str, *, fetch: JsonFetch = fetch_json) -> object:
    try:
        return fetch(f"https://pypi.org/pypi/{name}/{version}/json")
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise


def file_entry(name: str, digest: str) -> dict[str, object]:
    return {
        "filename": name,
        "digests": {"sha256": digest},
        "yanked": False,
        "packagetype": "bdist_wheel" if name.endswith(".whl") else "sdist",
    }


def missing_files(raw: object, name: str, version: str, files: dict[str, str]) -> set[str]:
    expected = {filename: files[filename] for filename in release.distribution_names(version, name)}
    if raw is None:
        return set(expected)
    if not isinstance(raw, dict) or not isinstance(raw.get("urls"), list):
        raise release.VerificationError("invalid PyPI response")
    # Validate even a one-file partial upload with the verifier's full response rules.
    urls = raw["urls"]
    seen: set[str] = set()
    for entry in urls:
        if not isinstance(entry, dict):
            raise release.VerificationError("invalid PyPI file entry")
        filename = entry.get("filename")
        if not isinstance(filename, str) or filename not in expected:
            raise release.VerificationError("unexpected PyPI filename")
        if filename in seen:
            raise release.VerificationError("duplicate PyPI filename")
        seen.add(filename)
    completed = dict(raw)
    completed["urls"] = urls + [
        file_entry(filename, expected[filename]) for filename in expected.keys() - seen
    ]
    release.verify_pypi(completed, version=version, hashes=expected, distribution=name)
    return expected.keys() - seen


def stage(
    candidate: Path,
    destination: Path,
    version: str,
    files: dict[str, str],
    *,
    resume: bool = False,
    fetch: JsonFetch = fetch_json,
) -> dict[str, bool]:
    # Validate every response before copying anything or enabling the first upload.
    missing = {
        item.name: missing_files(pypi_response(item.name, version, fetch=fetch), item.name, version, files)
        for item in release.DISTRIBUTIONS
    }
    if not resume and any(len(names) != 2 for names in missing.values()):
        raise release.VerificationError("version already exists on PyPI; use resume with original approvals")
    destination.mkdir(parents=True, exist_ok=False)
    for name, filenames in missing.items():
        folder = destination / name
        folder.mkdir()
        for filename in sorted(filenames):
            source = candidate / "dist" / filename
            if hashlib.sha256(source.read_bytes()).hexdigest() != files[filename]:
                raise release.VerificationError("candidate changed before staging")
            shutil.copyfile(source, folder / filename)
    return {name: bool(filenames) for name, filenames in missing.items()}


def _not_yet_visible(raw: object, hashes: dict[str, str]) -> bool:
    """True only for a missing release or a correct strict subset of its files (propagation lag)."""
    if raw is None:
        return True
    urls = raw.get("urls") if isinstance(raw, dict) else None
    if not isinstance(urls, list) or len(urls) >= len(hashes):
        return False
    for entry in urls:
        digests = entry.get("digests") if isinstance(entry, dict) else None
        name = entry.get("filename") if isinstance(entry, dict) else None
        if (
            not isinstance(digests, dict)
            or not isinstance(name, str)
            or name not in hashes
            or digests.get("sha256") != hashes[name]
        ):
            return False
    return True


def readback(
    version: str,
    through: str | None,
    files: dict[str, str],
    *,
    fetch: JsonFetch = fetch_json,
    attempts: int = 1,
    delay: float = 0.0,
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, object]:
    responses: dict[str, object] = {}
    for item in release._published_prefix(through):
        hashes = {name: files[name] for name in release.distribution_names(version, item.name)}
        raw = pypi_response(item.name, version, fetch=fetch)
        for _ in range(attempts - 1):
            if not _not_yet_visible(raw, hashes):
                break
            sleep(delay)
            raw = pypi_response(item.name, version, fetch=fetch)
        release.verify_pypi(raw, version=version, hashes=hashes, distribution=item.name)
        responses[item.name] = raw
    return responses


def rehearse(candidate: Path, destination: Path, version: str, files: dict[str, str]) -> None:
    """Simulate a first-file upload then failure; recover using the production stager."""
    registry: dict[str, dict[str, object]] = {}

    def fetch(url: str) -> object:
        name = url.split("/")[-3]
        if name not in registry:
            raise urllib.error.HTTPError(url, 404, "not uploaded", email.message.Message(), None)
        return registry[name]

    initial = destination / "initial"
    stage(candidate, initial, version, files, fetch=fetch)
    core = release.DISTRIBUTIONS[0].name
    first = next(iter(sorted((initial / core).iterdir())))

    def upload(name: str, path: Path) -> None:
        raw = registry.setdefault(name, {"info": {"name": name, "version": version}, "urls": []})
        urls = raw["urls"]
        assert isinstance(urls, list)
        if any(entry["filename"] == path.name for entry in urls):
            raise release.VerificationError("rehearsal tried to upload an existing filename")
        urls.append(file_entry(path.name, hashlib.sha256(path.read_bytes()).hexdigest()))

    upload(core, first)
    try:
        readback(version, core, files, fetch=fetch)
    except release.VerificationError as exc:
        print(f"simulated partial upload stopped before Labs/Proof: {exc}")
    else:
        raise release.VerificationError("rehearsal failed to detect partial publication")
    # Model a new runner downloading the original retained candidate, not a rebuild.
    retained = destination / "retained"
    shutil.copytree(candidate, retained)
    if (retained / "release-manifest.json").read_bytes() != (
        candidate / "release-manifest.json"
    ).read_bytes() or dict(release.distribution_hashes(retained / "dist", version)) != files:
        raise release.VerificationError("retained rehearsal bytes changed")
    recovered = destination / "resumed"
    stage(retained, recovered, version, files, resume=True, fetch=fetch)
    if (recovered / core / first.name).exists():
        raise release.VerificationError("resume restaged an already published file")
    for item in release.DISTRIBUTIONS:
        for path in sorted((recovered / item.name).iterdir()):
            upload(item.name, path)
        readback(version, item.name, files, fetch=fetch)
    readback(version, None, files, fetch=fetch)
    print(
        "dry-run rehearsal: partial upload rejected; retained missing files resumed; all six files verified"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("dispatch", "run", "stage", "readback", "rehearse"))
    parser.add_argument("--distributions", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--control-sha", default="")
    parser.add_argument("--manifest-sha256", default="")
    parser.add_argument("--run-id", default="")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--candidate", type=Path, default=Path("release"))
    parser.add_argument("--destination", type=Path, default=Path("staged"))
    parser.add_argument("--through", choices=tuple(release.KNOWN_DISTRIBUTIONS))
    parser.add_argument("--response-json", type=Path)
    args = parser.parse_args()
    try:
        release.DISTRIBUTIONS = release.load_distributions(args.distributions)
        release._require_split_contract(args.version)
        if args.command == "dispatch":
            validate_dispatch(
                args.commit, args.version, args.resume, args.run_id, args.manifest_sha256, args.control_sha
            )
        elif args.command == "run":
            validate_dispatch(
                args.commit, args.version, True, args.run_id, args.manifest_sha256, args.control_sha
            )
            verify_run(args.run_id, args.control_sha, os.environ["GITHUB_REPOSITORY"], args.version)
        else:
            files = approved_files(
                args.candidate, args.version, args.commit, args.control_sha, args.manifest_sha256
            )
            if args.command == "stage":
                result = stage(args.candidate, args.destination, args.version, files, resume=args.resume)
                with Path(os.environ["GITHUB_OUTPUT"]).open("a") as output:
                    for name, needed in result.items():
                        output.write(f"{name}={str(needed).lower()}\n")
            elif args.command == "readback":
                if args.response_json is None:
                    raise release.VerificationError("readback requires --response-json")
                responses = readback(
                    args.version,
                    args.through,
                    files,
                    attempts=READBACK_ATTEMPTS,
                    delay=READBACK_DELAY_SECONDS,
                )
                args.response_json.write_text(json.dumps(responses))
            else:
                rehearse(args.candidate, args.destination, args.version, files)
    except (OSError, ValueError, KeyError, release.VerificationError) as exc:
        print(f"publication preparation failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
