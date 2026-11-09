"""Checkout-only, static chain exploration with an opt-in sandboxed canary."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from redteam.chains.pairs import load_config
from redteam.chains.report import build_report, to_json, to_markdown


def _validate_outputs(outputs: list[Path | None], inputs: list[Path | None], pins_dir: Path | None) -> None:
    selected = [path for path in outputs if path is not None]
    protected = [path for path in inputs if path is not None]
    for index, path in enumerate(selected):
        for other in [*protected, *selected[:index]]:
            if path.resolve() == other.resolve() or (
                path.exists() and other.exists() and path.samefile(other)
            ):
                raise ValueError("report destinations must be distinct from each other and their inputs")
        if pins_dir is not None and path.resolve().is_relative_to(pins_dir.resolve()):
            raise ValueError("report destination must be outside the selected pin directory")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)
    run = subcommands.add_parser("run", help="rank declared cross-server chains without connecting")
    source = run.add_mutually_exclusive_group(required=True)
    source.add_argument("--config", type=Path)
    source.add_argument("--discover", action="store_true")
    run.add_argument("--surfaces", type=Path, help="adjacent explicit name-to-surface filename JSON mapping")
    run.add_argument("--pins", type=Path, help="explicit pin directory (never read by default)")
    run.add_argument("--dxt-dir", type=Path, help="Claude Extensions directory; reads manifests only")
    run.add_argument(
        "--include-claude-code", action="store_true", help="opt into credential-bearing config read"
    )
    run.add_argument(
        "--reproduce", action="store_true", help="run the top supported canary under sandbox-exec"
    )
    run.add_argument("--json", type=Path, dest="json_path")
    run.add_argument("--md", type=Path, dest="md_path")
    options = parser.parse_args(argv)
    if options.include_claude_code and not options.discover:
        parser.error("--include-claude-code requires --discover")
    if options.surfaces and options.discover:
        parser.error("--surfaces requires --config")
    try:
        _validate_outputs(
            [options.json_path, options.md_path], [options.config, options.surfaces], options.pins
        )
        if options.dxt_dir is not None:
            for output in (options.json_path, options.md_path):
                if output is not None and (
                    output.resolve().is_relative_to(options.dxt_dir.resolve())
                    or output.resolve().is_relative_to(
                        (options.dxt_dir.parent / "Claude Extensions Settings").resolve()
                    )
                ):
                    raise ValueError("report destination must be outside DXT metadata directories")
        if options.discover:
            from redteam.chains.discovery import discover_servers

            servers = discover_servers(
                include_claude_code=options.include_claude_code,
                pins_dir=options.pins,
                dxt_dir=options.dxt_dir,
            )
        else:
            servers = load_config(
                options.config, options.surfaces, pins_dir=options.pins, dxt_dir=options.dxt_dir
            )
        report = build_report(servers, reproduce=options.reproduce)
        markdown = to_markdown(report)
        for path, content in ((options.json_path, to_json(report)), (options.md_path, markdown)):
            if path is not None:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
        print(markdown, end="")
        reproduction = report["reproduction"]
        if isinstance(reproduction, dict) and reproduction.get("status") == "NOT_REPRODUCED":
            return 1
    except ImportError as exc:
        from redteam.chains.discovery import ShadowImportError

        if isinstance(exc, ShadowImportError):
            print(str(exc), file=sys.stderr)
        else:
            raise
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
