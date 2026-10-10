"""Offline tests for the lockfile advisory gate."""

from __future__ import annotations

import io
import json
import sys
import urllib.error
from pathlib import Path
from typing import Any
from urllib import request

import pytest

from scripts import check_advisories


def write_lock(path: Path) -> None:
    path.write_text(
        """version = 1

[[package]]
name = "click"
version = "8.3.3"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "optional-extra"
version = "1.2.3"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "private-package"
version = "9.9.9"
source = { registry = "https://packages.example.invalid/simple" }
""",
        encoding="utf-8",
    )


def test_load_queries_covers_registry_lock_entries_and_build_pin(tmp_path: Path) -> None:
    lock_path = tmp_path / "uv.lock"
    constraints_path = tmp_path / "build-constraints.txt"
    write_lock(lock_path)
    constraints_path.write_text("uv-build==0.12.24 --hash=sha256:" + "a" * 64 + "\n", encoding="utf-8")

    queries = check_advisories.load_queries(lock_path, constraints_path)

    assert queries == [
        {"package": {"name": "click", "ecosystem": "PyPI"}, "version": "8.3.3"},
        {"package": {"name": "optional-extra", "ecosystem": "PyPI"}, "version": "1.2.3"},
        {"package": {"name": "uv-build", "ecosystem": "PyPI"}, "version": "0.12.24"},
    ]


def test_load_queries_keeps_multiple_locked_versions(tmp_path: Path) -> None:
    lock_path = tmp_path / "uv.lock"
    write_lock(lock_path)
    with lock_path.open("a", encoding="utf-8") as lock_file:
        lock_file.write(
            '\n[[package]]\nname = "click"\nversion = "8.4.0"\n'
            'source = { registry = "https://pypi.org/simple" }\n'
        )

    queries = check_advisories.load_queries(lock_path, None)

    click_versions: list[str] = []
    for query in queries:
        package = query.get("package")
        if isinstance(package, dict) and package.get("name") == "click":
            version = query.get("version")
            assert isinstance(version, str)
            click_versions.append(version)
    assert click_versions == ["8.3.3", "8.4.0"]


def test_build_constraints_must_be_exactly_pinned(tmp_path: Path) -> None:
    lock_path = tmp_path / "uv.lock"
    constraints_path = tmp_path / "build-constraints.txt"
    write_lock(lock_path)
    constraints_path.write_text("uv-build>=0.12,<0.13\n", encoding="utf-8")

    with pytest.raises(check_advisories.AdvisoryCheckError, match="exact name==version pin"):
        check_advisories.load_queries(lock_path, constraints_path)


def test_osv_batch_request_is_bounded_and_uses_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    response = io.BytesIO(b'{"results":[{"vulns":[]}]}')
    captured: dict[str, Any] = {}

    def fake_urlopen(request: object, *, timeout: float) -> io.BytesIO:
        captured["request"] = request
        captured["timeout"] = timeout
        return response

    monkeypatch.setattr(request, "urlopen", fake_urlopen)
    queries: list[dict[str, object]] = [
        {"package": {"name": "click", "ecosystem": "PyPI"}, "version": "8.3.3"}
    ]

    result = check_advisories.request_osv(queries)

    assert result == {"results": [{"vulns": []}]}
    assert captured["timeout"] == check_advisories.REQUEST_TIMEOUT_SECONDS
    captured_request = captured["request"]
    assert isinstance(captured_request, request.Request)
    assert isinstance(captured_request.data, bytes)
    assert json.loads(captured_request.data) == {"queries": queries}


def test_oversized_osv_response_is_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        request,
        "urlopen",
        lambda request, *, timeout: io.BytesIO(b"x" * (check_advisories.MAX_RESPONSE_BYTES + 1)),
    )
    queries: list[dict[str, object]] = [
        {"package": {"name": "click", "ecosystem": "PyPI"}, "version": "8.3.3"}
    ]

    with pytest.raises(check_advisories.AdvisoryCheckError, match="size limit"):
        check_advisories.request_osv(queries)


def test_saved_response_fixture_read_is_bounded(tmp_path: Path) -> None:
    fixture_path = tmp_path / "response.json"
    fixture_path.write_bytes(b"x" * (check_advisories.MAX_RESPONSE_BYTES + 1))

    with pytest.raises(check_advisories.AdvisoryCheckError, match="size limit"):
        check_advisories.load_fixture(fixture_path)


def test_unavailable_feed_is_explicit(monkeypatch: pytest.MonkeyPatch) -> None:
    def unavailable(request: object, *, timeout: float) -> None:
        raise urllib.error.URLError("offline")

    monkeypatch.setattr(request, "urlopen", unavailable)
    queries: list[dict[str, object]] = [
        {"package": {"name": "click", "ecosystem": "PyPI"}, "version": "8.3.3"}
    ]

    with pytest.raises(check_advisories.AdvisoryCheckError, match="OSV advisory feed unavailable"):
        check_advisories.request_osv(queries)


def test_unavailable_feed_fails_cli_with_status_two(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    lock_path = tmp_path / "uv.lock"
    write_lock(lock_path)

    def unavailable(request: object, *, timeout: float) -> None:
        raise OSError("offline")

    monkeypatch.setattr(request, "urlopen", unavailable)
    monkeypatch.setattr(sys, "argv", ["check_advisories.py", "--lock", str(lock_path)])

    assert check_advisories.main() == 2
    assert "advisory check unavailable: OSV advisory feed unavailable" in capsys.readouterr().err


def test_response_requires_one_result_per_query() -> None:
    with pytest.raises(check_advisories.AdvisoryCheckError, match="result count"):
        check_advisories.vulnerable_packages({"results": []}, [{"name": "click"}])


@pytest.mark.parametrize(
    "result",
    [{"error": "temporarily unavailable"}, {"status": "ERROR"}],
)
def test_osv_result_errors_fail_closed(result: dict[str, str]) -> None:
    with pytest.raises(check_advisories.AdvisoryCheckError, match="indicates an error"):
        check_advisories.vulnerable_packages({"results": [result]}, [{"name": "click"}])


def test_vulnerabilities_are_reported_against_locked_package() -> None:
    queries: list[dict[str, object]] = [
        {"package": {"name": "click", "ecosystem": "PyPI"}, "version": "8.3.3"}
    ]

    findings = check_advisories.vulnerable_packages(
        {"results": [{"vulns": [{"id": "GHSA-example"}]}]}, queries
    )

    assert findings == [("click", ["GHSA-example"])]


def test_response_json_is_explicit_offline_fixture_mode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    lock_path = tmp_path / "uv.lock"
    fixture_path = tmp_path / "response.json"
    write_lock(lock_path)
    fixture_path.write_text(json.dumps({"results": [{"vulns": []}, {"vulns": []}]}), encoding="utf-8")
    monkeypatch.setattr(
        sys,
        "argv",
        ["check_advisories.py", "--lock", str(lock_path), "--response-json", str(fixture_path)],
    )

    assert check_advisories.main() == 0
    captured = capsys.readouterr()
    assert "fixture mode" in captured.out
    assert "checked 2 locked public PyPI package versions" in captured.out
    assert "build-input coverage unavailable: build-constraints.txt missing" in captured.err
