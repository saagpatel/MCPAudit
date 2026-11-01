"""Acceptance checks for the uv workspace and three-distribution package layout."""

from __future__ import annotations

import configparser
import email.parser
import re
import subprocess
import sys
import tarfile
import tomllib
import zipfile
from pathlib import Path

import pytest
from packaging.requirements import Requirement

ROOT = Path(__file__).resolve().parents[1]
MEMBERS = {"labs": "mcp_audit_labs", "proof": "proof_before_action"}
LAB_MODULES = """
_artifacts lab_primitives conformance_probe enforcement_cli evidence_enforcement fixture_gateway
agent_ui_cli agent_ui_models agent_ui_scanner
authorization_posture_cli authorization_posture_models authorization_posture_scanner
cache_contract_cli cache_contract_models cache_contract_scanner
oauth_transcript_cli oauth_transcript_models oauth_transcript_sarif oauth_transcript_scanner
result_parcel_cli result_parcel_models result_parcel_scanner
session_resume_cli session_resume_lab session_resume_models
task_time_machine task_time_machine_cli task_time_machine_models
safeforge safeforge_cli safeforge_consumer safeforge_contract_linter safeforge_coordinator safeforge_runtime
""".split()
# The 2.12 requirement strings; only cross-distribution requirements are exact pins (Q3).
OPTIONAL_EXTRAS = {
    "watch": ["watchfiles>=1.1.1"],
    "llm": ["anthropic>=0.40"],
    "otel": ["opentelemetry-api>=1.45.1,<2"],
}


def test_workspace_members_and_dependency_direction() -> None:
    root = tomllib.loads((ROOT / "pyproject.toml").read_text())
    version = root["project"]["version"]
    assert root["tool"]["uv"]["workspace"]["members"] == [f"distributions/{member}" for member in MEMBERS]
    for member, module in MEMBERS.items():
        base = ROOT / "distributions" / member
        data = tomllib.loads((base / "pyproject.toml").read_text())
        assert data["project"]["name"] == f"mcp-audits-{member}"
        assert data["project"]["version"] == version
        assert data["build-system"] == root["build-system"]
        assert data["tool"]["uv"]["build-backend"]["module-name"] == module
        assert (base / "src" / module / "__init__.py").is_file()
        for filename in ("mcp_audit_build_backend.py", "LICENSE"):
            assert (base / filename).read_bytes() == (ROOT / filename).read_bytes()
        assert data["project"]["readme"] == "README.md"
        readme = (base / "README.md").read_text()
        assert readme.startswith(f"# mcp-audits-{member}\n")
        links = re.findall(r"\]\(([^)]*)\)", readme)
        assert links and all(link.startswith("https://github.com/saagpatel/MCPAudit/") for link in links)
        assert data["project"]["license-files"] == ["LICENSE"]
        dependencies = [Requirement(value) for value in data["project"]["dependencies"]]
        if member == "labs":
            assert [str(value) for value in dependencies] == [f"mcp-audits=={version}"]
            assert data["tool"]["uv"]["sources"]["mcp-audits"] == {"workspace": True}
        else:
            assert {value.name for value in dependencies} == {"click", "pydantic", "pyyaml"}
            assert len(dependencies) == 3
            assert data["project"]["scripts"] == {"proof-before-action": "proof_before_action.proof_cli:main"}
        assert root["tool"]["uv"]["sources"][f"mcp-audits-{member}"] == {"workspace": True}


def test_core_extras_pin_satellites_and_all_is_the_union() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    extras = project["optional-dependencies"]
    for member in MEMBERS:
        assert extras[member] == [f"mcp-audits-{member}=={project['version']}"]
    for extra, values in OPTIONAL_EXTRAS.items():
        assert extras[extra] == values
    parts = ("labs", "proof", *OPTIONAL_EXTRAS)
    assert extras["all"] == [value for part in parts for value in extras[part]]


def test_ci_and_make_install_sync_every_package() -> None:
    assert "uv sync --all-packages --locked --dev" in (ROOT / "Makefile").read_text()
    assert "uv sync --all-packages --locked --dev" in (ROOT / ".github/workflows/ci.yml").read_text()


@pytest.fixture(scope="module")
def workspace_artifacts(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Path]:
    artifacts: dict[str, Path] = {}
    for member in ("core", *MEMBERS):
        project = ROOT if member == "core" else ROOT / "distributions" / member
        name = "mcp-audits" if member == "core" else f"mcp-audits-{member}"
        output = tmp_path_factory.mktemp(f"workspace-{member}")
        subprocess.run(
            [
                "uv",
                "build",
                "--offline",
                "--package",
                name,
                "--no-create-gitignore",
                "--build-constraints",
                str(ROOT / "build-constraints.txt"),
                "--out-dir",
                str(output),
            ],
            cwd=project,
            check=True,
            capture_output=True,
        )
        assert len(list(output.glob("*.whl"))) == len(list(output.glob("*.tar.gz"))) == 1
        artifacts[member] = output
    return artifacts


@pytest.mark.parametrize("member", ["core", *MEMBERS])
def test_built_artifacts_have_portable_metadata_and_only_their_package(
    workspace_artifacts: dict[str, Path], member: str
) -> None:
    output = workspace_artifacts[member]
    (wheel,) = output.glob("*.whl")
    (sdist,) = output.glob("*.tar.gz")
    module = "mcp_audit" if member == "core" else MEMBERS[member]
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        assert all(name.startswith(f"{module}/") or ".dist-info/" in name for name in names)
        (metadata,) = [name for name in names if name.endswith(".dist-info/METADATA")]
        wheel_metadata = archive.read(metadata)
        entry_points = [name for name in names if name.endswith(".dist-info/entry_points.txt")]
        scripts = configparser.ConfigParser()
        if entry_points:
            assert len(entry_points) == 1
            scripts.read_string(archive.read(entry_points[0]).decode())
        expected_scripts = (
            {"mcp-audit": "mcp_audit.cli:main", "mcp-audits": "mcp_audit.cli:main"}
            if member == "core"
            else {"proof-before-action": "proof_before_action.proof_cli:main"}
            if member == "proof"
            else {}
        )
        observed_scripts = (
            dict(scripts.items("console_scripts")) if scripts.has_section("console_scripts") else {}
        )
        assert observed_scripts == expected_scripts
        if member in {"core", "proof"}:
            proof_files = {
                "proof_capsule.py",
                "proof_cli.py",
                "proof_models.py",
                "proof_observer.py",
                "proof_trust.py",
            }
            observed = {Path(name).name for name in names if name.startswith(f"{module}/proof_")}
            assert observed == (proof_files if member == "proof" else set())
    with tarfile.open(sdist) as archive:
        assert all("distributions" not in Path(info.name).parts for info in archive.getmembers())
        (pkg_info,) = [info for info in archive.getmembers() if Path(info.name).name == "PKG-INFO"]
        stream = archive.extractfile(pkg_info)
        assert stream is not None
        with stream:
            sdist_metadata = stream.read()
    for raw in (wheel_metadata, sdist_metadata):
        parsed = email.parser.BytesParser().parsebytes(raw)
        requirements = [Requirement(value) for value in parsed.get_all("Requires-Dist", [])]
        assert all(value.url is None for value in requirements)
        if member == "core":
            for extra in ("labs", "proof", "all"):
                selected = {
                    value.name
                    for value in requirements
                    if value.marker and value.marker.evaluate({"extra": extra})
                }
                expected = (
                    {"mcp-audits-labs", "mcp-audits-proof", "watchfiles", "anthropic", "opentelemetry-api"}
                    if extra == "all"
                    else {f"mcp-audits-{extra}"}
                )
                assert selected == expected
        elif member == "proof":
            assert {value.name for value in requirements} == {"click", "pydantic", "pyyaml"}


def test_lock_contains_editable_members_and_exact_extra_requirements() -> None:
    lock = tomllib.loads((ROOT / "uv.lock").read_text())
    packages = {item["name"]: item for item in lock["package"]}
    for member in MEMBERS:
        package = packages[f"mcp-audits-{member}"]
        assert package["source"] == {"editable": f"distributions/{member}"}
        assert package["version"] == packages["mcp-audits"]["version"]
    assert {item["name"] for item in packages["mcp-audits-proof"]["dependencies"]} == {
        "click",
        "pydantic",
        "pyyaml",
    }
    assert {item["name"] for item in packages["mcp-audits"]["optional-dependencies"]["all"]} == {
        "mcp-audits-labs",
        "mcp-audits-proof",
        "watchfiles",
        "anthropic",
        "opentelemetry-api",
    }


def test_labs_artifacts_contain_all_moved_modules_and_load_bundled_scenarios(
    workspace_artifacts: dict[str, Path],
) -> None:
    assert len(LAB_MODULES) == len(set(LAB_MODULES)) == 34
    expected = {f"mcp_audit_labs/{name}.py" for name in LAB_MODULES} | {
        "mcp_audit_labs/__init__.py",
        "mcp_audit_labs/_build_provenance.json",
        "mcp_audit_labs/session_resume_scenarios_v1.json",
    }
    output = workspace_artifacts["labs"]
    (wheel,) = output.glob("*.whl")
    with zipfile.ZipFile(wheel) as archive:
        assert {
            name
            for name in archive.namelist()
            if name.startswith("mcp_audit_labs/") and not name.endswith("/")
        } == expected
    (sdist,) = output.glob("*.tar.gz")
    with tarfile.open(sdist) as archive:
        assert {
            info.name.split("/src/", 1)[1]
            for info in archive.getmembers()
            if "/src/" in info.name and info.isfile()
        } == expected
    for name in LAB_MODULES:
        assert not (ROOT / "src" / "mcp_audit" / f"{name}.py").exists()
    assert not (ROOT / "src/mcp_audit/session_resume_scenarios_v1.json").exists()
    script = (
        "import sys; sys.path.insert(0, sys.argv[1]); "
        "import mcp_audit_labs; "
        "assert sys.argv[1] in mcp_audit_labs.__file__; "
        "from mcp_audit_labs.session_resume_lab import load_builtin_scenarios, run_builtin_suite; "
        "assert load_builtin_scenarios(); assert run_builtin_suite()"
    )
    result = subprocess.run(
        [sys.executable, "-c", script, str(wheel)], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stderr
