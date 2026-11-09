"""Checkout-only, static chain exploration with an opt-in sandboxed canary."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from redteam.chains import ShadowImportError, ensure_repo_import


class OutputConflict(ValueError):
    """A report destination would overwrite an input or another report."""


def _validate_outputs(
    outputs: list[Path | None],
    inputs: list[Path | None],
    pins_dir: Path | None,
    directories: list[Path] | None = None,
) -> None:
    selected = [path for path in outputs if path is not None]
    protected = [path for path in inputs if path is not None]
    for index, path in enumerate(selected):
        for other in [*protected, *selected[:index]]:
            if path.resolve() == other.resolve() or (
                path.exists() and other.exists() and path.samefile(other)
            ):
                raise OutputConflict("report destinations must be distinct from each other and their inputs")
        if pins_dir is not None and path.resolve().is_relative_to(pins_dir.resolve()):
            raise OutputConflict("report destination must be outside the selected pin directory")
        if any(path.resolve().is_relative_to(root.resolve()) for root in directories or []):
            raise OutputConflict("report destination must be outside discovery metadata directories")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)
    run = subcommands.add_parser("run", help="rank declared cross-server chains without connecting")
    source = run.add_mutually_exclusive_group(required=True)
    source.add_argument("--config", type=Path)
    source.add_argument("--discover", action="store_true")
    run.add_argument("--surfaces", type=Path, help="adjacent explicit name-to-surface filename JSON mapping")
    run.add_argument("--pins", type=Path, help="explicit pin directory (never read by default)")
    run.add_argument("--dxt-dir", type=Path, help="Claude Extensions directory; reads metadata only")
    run.add_argument(
        "--include-claude-code", action="store_true", help="opt into the ClaudeCode config collector"
    )
    run.add_argument(
        "--reproduce", action="store_true", help="run the top supported canary under sandbox-exec"
    )
    run.add_argument(
        "--allow-skip", action="store_true", help="return success when a requested canary is skipped"
    )
    run.add_argument(
        "--allow-incomplete", action="store_true", help="allow success with parse or collector errors"
    )
    run.add_argument("--json", type=Path, dest="json_path")
    run.add_argument("--md", type=Path, dest="md_path")
    options = parser.parse_args(argv)
    if options.include_claude_code and not options.discover:
        parser.error("--include-claude-code requires --discover")
    if options.surfaces and options.discover:
        parser.error("--surfaces requires --config")
    try:
        ensure_repo_import()
    except ShadowImportError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    from redteam.chains.discovery import discover_servers
    from redteam.chains.pairs import AmbiguousInput, load_config
    from redteam.chains.report import build_report, to_json, to_markdown

    try:
        directories = (
            [options.dxt_dir, options.dxt_dir.parent / "Claude Extensions Settings"]
            if options.dxt_dir is not None
            else []
        )
        _validate_outputs(
            [options.json_path, options.md_path],
            [options.config, options.surfaces],
            options.pins,
            directories,
        )
        input_paths = [options.config, options.surfaces]
        additional_inputs: list[Path] = []
        if options.discover:
            servers = discover_servers(
                include_claude_code=options.include_claude_code,
                pins_dir=options.pins,
                dxt_dir=options.dxt_dir,
                input_paths=additional_inputs,
                input_directories=directories,
                validate_inputs=lambda: _validate_outputs(
                    [options.json_path, options.md_path],
                    [*input_paths, *additional_inputs],
                    options.pins,
                    directories,
                ),
            )
        else:
            servers = load_config(
                options.config,
                options.surfaces,
                pins_dir=options.pins,
                input_paths=additional_inputs,
                dxt_dir=options.dxt_dir,
            )
        _validate_outputs(
            [options.json_path, options.md_path],
            [*input_paths, *additional_inputs],
            options.pins,
            directories,
        )
        report = build_report(servers, reproduce=options.reproduce)
        markdown = to_markdown(report)
        for path, content in ((options.json_path, to_json(report)), (options.md_path, markdown)):
            if path is not None:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
        print(markdown, end="")
        if report["analysis_incomplete"] and not options.allow_incomplete:
            return 1
        reproduction = report["reproduction"]
        if isinstance(reproduction, dict):
            if reproduction.get("status") == "NOT_REPRODUCED":
                return 1
            if reproduction.get("status") == "SKIPPED" and not options.allow_skip:
                return 3
    except ShadowImportError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except AmbiguousInput as exc:
        print(f"chains failed: {exc}", file=sys.stderr)
        return 2
    except OutputConflict:
        print(
            "chains failed (ValueError); report destinations must be distinct from inputs and each other "
            "and outside pin/discovery metadata directories",
            file=sys.stderr,
        )
        return 2
    except (ValueError, OSError) as exc:
        # Parsing exceptions can contain credentials or snippets. Emit the class only.
        print(
            f"chains failed ({type(exc).__name__}); check the selected input and output paths",
            file=sys.stderr,
        )
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
