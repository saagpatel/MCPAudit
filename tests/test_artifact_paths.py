"""Fixture-only regressions for destructive CLI artifact path aliases."""

import itertools
import json
from pathlib import Path

import click
import pytest
from click.testing import CliRunner

from mcp_audit.artifact_paths import validate_artifact_paths
from mcp_audit.cli import main
from mcp_audit.discovery import _DISCOVERERS
from mcp_audit.discovery.cursor import CursorDiscoverer

SANDBOX = Path(__file__).resolve().parents[1] / "examples/sandbox/fixtures/synthetic-mcp-config.json"
FLAGS = {"check": ("--output-json", "--sarif", "--html"), "scan": ("--json", "--sarif", "--html")}
OUTPUT_CASES = [(command, flag) for command, flags in FLAGS.items() for flag in flags]
PAIR_CASES = [
    (command, first, second)
    for command, flags in FLAGS.items()
    for first, second in itertools.combinations(flags, 2)
]


@pytest.fixture(autouse=True)
def isolated_sources(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.chdir(tmp_path)
    for discoverer in _DISCOVERERS.values():
        monkeypatch.setattr(discoverer, "config_paths", lambda self: [])


def _inputs(tmp_path: Path) -> tuple[Path, Path, Path]:
    config = tmp_path / "synthetic.json"
    config.write_bytes(SANDBOX.read_bytes())
    policy = tmp_path / "policy.yaml"
    policy.write_text("max_risk: 10\n", encoding="utf-8")
    override = tmp_path / "override.yaml"
    override.write_text("{}\n", encoding="utf-8")
    return config, policy, override


def _args(command: str, config: Path, policy: Path, override: Path) -> list[str]:
    args = [command, "--config", str(config), "--policy", str(policy)]
    if command == "scan":
        args.extend(["--config-only", "--skip-connect", "--override-config", str(override)])
    return args


def _alias(source: Path, destination: Path, kind: str) -> Path:
    if kind == "direct":
        return source
    if kind == "symlink":
        destination.symlink_to(source)
    elif kind == "hardlink":
        destination.hardlink_to(source)
    else:
        directory = destination.parent / "linked-directory"
        directory.symlink_to(source.parent, target_is_directory=True)
        return directory / source.name
    return destination


@pytest.mark.parametrize(("command", "flag"), OUTPUT_CASES)
@pytest.mark.parametrize("kind", ["direct", "symlink", "hardlink", "directory-symlink"])
@pytest.mark.parametrize("target", ["config", "policy"])
def test_artifacts_cannot_overwrite_inputs(
    tmp_path: Path, command: str, flag: str, kind: str, target: str
) -> None:
    config, policy, override = _inputs(tmp_path)
    snapshots = {path: path.read_bytes() for path in (config, policy, override)}
    source = config if target == "config" else policy
    collision = _alias(source, tmp_path / "alias", kind)
    outputs = {option: tmp_path / f"artifact-{index}" for index, option in enumerate(FLAGS[command])}
    outputs[flag] = collision
    safe_paths = [path for option, path in outputs.items() if option != flag]
    safe_paths[0].write_bytes(b"existing artifact")
    args = _args(command, config, policy, override)
    for option, path in outputs.items():
        args.extend([option, str(path)])

    result = CliRunner().invoke(main, args)

    assert result.exit_code == 2, result.output
    assert flag in result.stderr
    assert "aliases an input file" in result.stderr
    assert "no artifacts written" in result.stderr
    assert {path: path.read_bytes() for path in snapshots} == snapshots
    assert safe_paths[0].read_bytes() == b"existing artifact"
    assert not safe_paths[1].exists()


@pytest.mark.parametrize("flag", FLAGS["scan"])
@pytest.mark.parametrize("kind", ["direct", "symlink", "hardlink"])
def test_scan_artifacts_cannot_overwrite_override(tmp_path: Path, flag: str, kind: str) -> None:
    config, policy, override = _inputs(tmp_path)
    before = override.read_bytes()
    output = _alias(override, tmp_path / "alias", kind)
    result = CliRunner().invoke(main, [*_args("scan", config, policy, override), flag, str(output)])
    assert result.exit_code == 2, result.output
    assert flag in result.stderr
    assert "aliases an input file" in result.stderr
    assert override.read_bytes() == before


@pytest.mark.parametrize(("command", "flag"), OUTPUT_CASES)
@pytest.mark.parametrize("contents", ['{"mcpServers": {}}', '{"mcpServers":', '{"theme": "dark"}'])
@pytest.mark.parametrize("kind", ["direct", "symlink", "hardlink"])
def test_discovered_configs_without_servers_are_protected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    command: str,
    flag: str,
    contents: str,
    kind: str,
) -> None:
    config, policy, override = _inputs(tmp_path)
    discovered = tmp_path / "discovered.json"
    discovered.write_text(contents, encoding="utf-8")
    before = discovered.read_bytes()
    monkeypatch.setattr(CursorDiscoverer, "config_paths", lambda self: [discovered])
    output = _alias(discovered, tmp_path / "alias", kind)
    if command == "check":
        args = [*_args(command, config, policy, override), "--include-discovered"]
    else:
        args = [command, "--config", str(config), "--skip-connect", "--override-config", str(override)]
    other = tmp_path / "other-artifact"
    other_flag = next(option for option in FLAGS[command] if option != flag)
    result = CliRunner().invoke(main, [*args, other_flag, str(other), flag, str(output)])

    assert result.exit_code == 2, result.output
    assert flag in result.stderr
    assert "aliases an input file" in result.stderr
    assert discovered.read_bytes() == before
    assert not other.exists()


@pytest.mark.parametrize(("command", "first", "second"), PAIR_CASES)
@pytest.mark.parametrize("kind", ["direct", "symlink", "hardlink"])
def test_artifact_destinations_cannot_alias_each_other(
    tmp_path: Path, command: str, first: str, second: str, kind: str
) -> None:
    config, policy, override = _inputs(tmp_path)
    destination = tmp_path / "existing-artifact"
    destination.write_bytes(b"keep this artifact")
    alias = _alias(destination, tmp_path / "alias", kind)
    untouched = tmp_path / "untouched"
    third = next(flag for flag in FLAGS[command] if flag not in (first, second))
    result = CliRunner().invoke(
        main,
        [
            *_args(command, config, policy, override),
            first,
            str(destination),
            second,
            str(alias),
            third,
            str(untouched),
        ],
    )

    assert result.exit_code == 2, result.output
    assert first in result.stderr and second in result.stderr
    assert "aliases artifact destination" in result.stderr
    assert destination.read_bytes() == b"keep this artifact"
    assert alias.read_bytes() == b"keep this artifact"
    assert not untouched.exists()


@pytest.mark.parametrize("command", FLAGS)
def test_duplicate_new_artifact_destinations_are_rejected(tmp_path: Path, command: str) -> None:
    config, policy, override = _inputs(tmp_path)
    destination = tmp_path / "new-artifact"
    alias = tmp_path / "alias"
    alias.symlink_to(destination)
    first, second, _ = FLAGS[command]
    result = CliRunner().invoke(
        main, [*_args(command, config, policy, override), first, str(destination), second, str(alias)]
    )
    assert result.exit_code == 2, result.output
    assert first in result.stderr and second in result.stderr
    assert not destination.exists()


@pytest.mark.parametrize("command", FLAGS)
def test_distinct_artifacts_are_written_without_changing_inputs(tmp_path: Path, command: str) -> None:
    config, policy, override = _inputs(tmp_path)
    snapshots = {path: path.read_bytes() for path in (config, policy, override)}
    paths = [tmp_path / f"report.{extension}" for extension in ("json", "sarif", "html")]
    paths[0].write_text("old report", encoding="utf-8")
    args = _args(command, config, policy, override)
    for flag, path in zip(FLAGS[command], paths, strict=True):
        args.extend([flag, str(path)])
    result = CliRunner().invoke(main, args)

    assert result.exit_code == 0, result.output
    assert json.loads(paths[0].read_text())["servers_discovered"] == 5
    assert json.loads(paths[1].read_text())["version"] == "2.1.0"
    assert "<html" in paths[2].read_text()
    assert {path: path.read_bytes() for path in snapshots} == snapshots


def test_identity_errors_fail_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    output = tmp_path / "artifact"

    def denied(path: Path, *args: object, **kwargs: object) -> Path:
        raise PermissionError("path inspection unavailable")

    monkeypatch.setattr(Path, "resolve", denied)
    with pytest.raises(click.BadParameter, match="Cannot verify output path") as error:
        validate_artifact_paths([("--html", output)], [])
    assert error.value.param_hint == "--html"
    with pytest.raises(click.BadParameter, match="Cannot verify input paths"):
        validate_artifact_paths([("--html", output)], [tmp_path / "config"])
