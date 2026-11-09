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
    run.add_argument("--config", type=Path, required=True)
    run.add_argument("--surfaces", type=Path, help="adjacent explicit name-to-surface filename JSON mapping")
    run.add_argument("--pins", type=Path, help="explicit pin directory (never read by default)")
    run.add_argument(
        "--reproduce", action="store_true", help="run the top supported canary under sandbox-exec"
    )
    run.add_argument(
        "--allow-skip", action="store_true", help="return success when a requested canary is skipped"
    )
    run.add_argument("--json", type=Path, dest="json_path")
    run.add_argument("--md", type=Path, dest="md_path")
    options = parser.parse_args(argv)
    try:
        _validate_outputs(
            [options.json_path, options.md_path], [options.config, options.surfaces], options.pins
        )
        servers = load_config(options.config, options.surfaces, pins_dir=options.pins)
        report = build_report(servers, reproduce=options.reproduce)
        markdown = to_markdown(report)
        for path, content in ((options.json_path, to_json(report)), (options.md_path, markdown)):
            if path is not None:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
        print(markdown, end="")
        reproduction = report["reproduction"]
        if isinstance(reproduction, dict):
            if reproduction.get("status") == "NOT_REPRODUCED":
                return 1
            if reproduction.get("status") == "SKIPPED" and not options.allow_skip:
                return 3
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
