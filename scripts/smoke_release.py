#!/usr/bin/env python3
"""Install each release artifact and pinned extra with only prepared local wheels."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts import verify_release as release

LAB_NOTICE = "uv tool install 'mcp-audits[labs]'"


def run(command: list[str], *, expected: int = 0, stderr_contains: str = "") -> str:
    result = subprocess.run(command, capture_output=True, text=True, check=False, timeout=180)
    if result.returncode != expected:
        raise RuntimeError(f"smoke command {command!r} exited {result.returncode}: {result.stderr}")
    if stderr_contains not in result.stderr:
        raise RuntimeError(f"smoke command {command!r} stderr lacks {stderr_contains!r}: {result.stderr}")
    return result.stdout.strip()


def smoke(dist: Path, dependencies: Path, destination: Path, version: str, constraints: Path) -> None:
    core = release.DISTRIBUTIONS[0]
    cases = [
        (item, artifact, "")
        for item in release.DISTRIBUTIONS
        for artifact in release.distribution_names(version, item.name)
    ]
    cases += [
        (core, artifact, extra)
        for artifact in release.distribution_names(version)
        for extra in (*release.SATELLITE_EXTRAS, *release.OPTIONAL_EXTRAS)
    ]
    for index, (item, artifact, extra) in enumerate(cases):
        environment = destination / str(index)
        run(["uv", "venv", str(environment)])
        python = str(environment / "bin/python")
        package = str((dist / artifact).resolve()) + (f"[{extra}]" if extra else "")
        run(
            [
                "uv",
                "--no-cache",
                "pip",
                "install",
                "--python",
                python,
                "--no-index",
                "--find-links",
                str(dist.resolve()),
                "--find-links",
                str(dependencies.resolve()),
                "--build-constraints",
                str(constraints.resolve()),
                package,
            ]
        )
        modules = {item.module: item.name}
        if item.name == "mcp-audits-labs":
            modules[core.module] = core.name
        for satellite in release.DISTRIBUTIONS[1:]:
            if satellite.name in release.SATELLITE_EXTRAS.get(extra, ()):
                modules[satellite.module] = satellite.name
        for module, name in modules.items():
            actual = run(
                [
                    python,
                    "-I",
                    "-c",
                    f"import {module}; from importlib.metadata import version; print(version({name!r}))",
                ]
            )
            if actual != version:
                raise RuntimeError(f"installed {name} is not the exact release version")
        proof = environment / "bin/proof-before-action"
        if "proof_before_action" in modules:
            if run([str(proof), "--version"]) != f"proof-before-action, version {version}":
                raise RuntimeError("Proof command version mismatch")
            run([str(proof), "--help"])
        elif proof.exists():
            raise RuntimeError("core/Labs unexpectedly installed proof-before-action")
        if core.module in modules:
            for command in core.scripts:
                if run([str(environment / "bin" / command), "--version"]) != f"mcp-audit, version {version}":
                    raise RuntimeError("core command version mismatch")
            if "mcp_audit_labs" not in modules:
                # Bare `lab` is a core group that prints help and exits 0, so probe a real topic.
                # This exits 2 with the install notice only once lab modules move to
                # mcp_audit_labs (item S-2).
                run(
                    [str(environment / "bin/mcp-audit"), "lab", "agent-ui", "--help"],
                    expected=2,
                    stderr_contains=LAB_NOTICE,
                )
            run([python, "-I", str(Path(__file__).with_name("smoke_installed_artifact.py").resolve())])
        elif (environment / "bin/mcp-audit").exists():
            # Only the Proof artifacts reach here; Labs depends on core.
            raise RuntimeError("Proof unexpectedly installed the core mcp-audit command")
        # Optional extras must really be importable, even when their release pins are indirect.
        for extra_name, module in {
            "watch": "watchfiles",
            "llm": "anthropic",
            "otel": "opentelemetry.trace",
        }.items():
            if extra in (extra_name, "all"):
                run([python, "-I", "-c", f"import {module}"])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--distributions", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--dist-dir", type=Path, required=True)
    parser.add_argument("--dependencies", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--build-constraints", type=Path, required=True)
    args = parser.parse_args()
    release.DISTRIBUTIONS = release.load_distributions(args.distributions)
    release._require_split_contract(args.version)
    smoke(args.dist_dir, args.dependencies, args.destination, args.version, args.build_constraints)
    return 0


if __name__ == "__main__":
    sys.exit(main())
