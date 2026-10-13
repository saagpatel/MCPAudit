"""Composite Action command adapter, independent of the installed core version."""

from __future__ import annotations

import os
import re
import shlex
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path

_VALUE_OPTIONS = frozenset(
    {
        "--config",
        "--project",
        "--client",
        "--server",
        "--output-json",
        "--sarif",
        "--html",
        "--card",
        "--previous",
        "--color",
        "--override-config",
        "--policy",
        "--ignore",
        "--ignore-reason",
        "--ssrf-allowlist",
        "--egress-allowlist",
        "--multi-tenant-hosts",
        "--pin-file",
        "--pin-min-sequence",
        "--timeout",
        "--max-concurrency",
        "--max-frame-bytes",
        "--max-surface-bytes",
        "--canary-calls",
        "--canary-identities",
        "--canary-safe-tool",
        "--sarif-profile",
    }
)


def supports_check() -> bool:
    """Probe help only: early 2.x has check, but not the expanded grammar."""
    result = subprocess.run(["mcp-audit", "check", "--help"], capture_output=True, text=True)
    options = set(re.findall(r"--[a-z][a-z-]*", result.stdout))
    return (
        result.returncode == 0
        and {
            "--include-discovered",
            "--output-json",
            "--inject-check",
            "--connect-all",
        }
        <= options
    )


def translate_check_args(args: list[str]) -> tuple[list[str], set[str]]:
    """Translate only known legacy spellings; leave native check args intact."""
    translated: list[str] = []
    options: set[str] = set()
    index = 0
    while index < len(args):
        token = args[index]
        option, equals, value = token.partition("=")
        options.add(option)
        if option == "--clients":
            if not equals:
                index += 1
                if index == len(args) or args[index].startswith("-"):
                    raise ValueError("--clients requires a name; use --client NAME instead.")
                value = args[index]
            if not value or "," in value:
                raise ValueError(
                    "--clients has no exact comma-separated translation; "
                    "use repeated --client NAME options instead."
                )
            translated.extend(("--client", value))
        elif option == "--json" and equals:
            if not value:
                raise ValueError("--json PATH requires a path; use --output-json PATH instead.")
            translated.extend(("--output-json", value))
        elif token == "--json" and index + 1 < len(args) and not args[index + 1].startswith("-"):
            index += 1
            translated.extend(("--output-json", args[index]))
        else:
            translated.append(token)
            if token == "--":
                translated.extend(args[index + 1 :])
                break
            if option in _VALUE_OPTIONS and not equals and index + 1 < len(args):
                index += 1
                translated.append(args[index])
        index += 1
    return translated, options


def build_command(env: Mapping[str, str], *, check: bool) -> list[str]:
    extra = shlex.split(env.get("EXTRA_ARGS", ""))
    options: set[str] = set()
    if check:
        extra, options = translate_check_args(extra)
    command = ["mcp-audit", "check" if check else "scan"]
    if env.get("SKIP_CONNECT", "true") == "true":
        # Keep the compatibility safety constraint even if args asks to connect.
        command.append("--skip-connect")
    elif check and not options & {"--connect", "--connect-all"}:
        command.append("--connect-all")
    clients = env.get("CLIENTS", "")
    if clients:
        if check:
            for client in clients.split(","):
                command.extend(("--client", client.strip()))
        else:
            command.extend(("--clients", clients))
    config = env.get("CONFIG", "")
    if config:
        command.extend(("--config", config))
        if not check:
            command.append("--config-only")
    elif check and "--config-only" not in options:
        command.append("--include-discovered")
    for key, option in (
        ("SARIF", "--sarif"),
        ("JSON", "--output-json" if check else "--json"),
        ("POLICY", "--policy"),
    ):
        if value := env.get(key, ""):
            command.extend((option, value))
    return [*command, *extra]


def main() -> None:
    check = supports_check()
    try:
        command = build_command(os.environ, check=check)
    except ValueError as exc:
        print(f"::error title=MCPAudit::{exc}", file=sys.stderr)
        code = 2
    else:
        notice = shlex.join(command).replace("\r", "\\r").replace("\n", "\\n")
        if os.environ.get("EXTRA_ARGS"):
            print(
                f"MCPAudit Action: args use {'check' if check else 'scan'} grammar; "
                f"translated command: {notice}",
                file=sys.stderr,
            )
        else:
            print(f"+ {notice}", file=sys.stderr)
        code = subprocess.run(command).returncode
        if code < 0:
            code = 128 - code
    with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as output:
        output.write(f"exit-code={code}\n")
        output.write(f"sarif-file={os.environ.get('SARIF', '')}\n")
        output.write(f"json-file={os.environ.get('JSON', '')}\n")
    # Leave the Action's existing upload-then-enforce ordering intact.


if __name__ == "__main__":
    main()
