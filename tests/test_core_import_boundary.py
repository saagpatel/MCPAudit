"""Keep core independent of lab/proof code except explicit command dispatch."""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "src"
NON_CORE_PREFIXES = (
    "mcp_audit._artifacts",
    "mcp_audit.agent_ui",
    "mcp_audit.authorization_posture",
    "mcp_audit.cache_contract",
    "mcp_audit.conformance_probe",
    "mcp_audit.enforcement_cli",
    "mcp_audit.evidence_enforcement",
    "mcp_audit.fixture_gateway",
    "mcp_audit.lab_primitives",
    "mcp_audit.oauth_transcript",
    "mcp_audit.proof_",
    "mcp_audit.result_parcel",
    "mcp_audit.safeforge",
    "mcp_audit.session_resume",
    "mcp_audit.task_time_machine",
    "mcp_audit_labs",
    "proof_before_action",
)


def test_core_import_graph_excludes_labs_and_proof() -> None:
    violations: list[str] = []
    for path in sorted((ROOT / "mcp_audit").rglob("*.py")):
        module = ".".join(path.relative_to(ROOT).with_suffix("").parts).removesuffix(".__init__")
        if module.startswith(NON_CORE_PREFIXES):
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
        for node in ast.walk(tree):
            if not isinstance(node, (ast.Import, ast.ImportFrom, ast.Call)):
                continue
            imports: list[str] = []
            if isinstance(node, ast.Import):
                imports = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                package = module if path.name == "__init__.py" else module.rpartition(".")[0]
                prefix = node.module or ""
                if node.level:
                    base = package.split(".")[: len(package.split(".")) - node.level + 1]
                    prefix = ".".join([*base, *([prefix] if prefix else [])])
                imports = [prefix, *(f"{prefix}.{alias.name}" for alias in node.names)]
            elif (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id in {"import_module", "__import__", "_import_command_module"}
                and node.args
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)
            ):
                imports = [node.args[0].value]
            for target in imports:
                if not target.startswith(NON_CORE_PREFIXES):
                    continue
                # Q8 permits lab code only at explicit command invocation. Keep
                # this exception specific to the existing conformance dispatch.
                parent: ast.AST | None = parents.get(node)
                while parent is not None and not isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    parent = parents.get(parent)
                if (
                    module == "mcp_audit._command_registry"
                    and isinstance(parent, ast.FunctionDef)
                    and parent.name == "lab"
                    and isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id == "_import_command_module"
                    and target == "mcp_audit_labs.conformance_probe"
                ):
                    continue
                violations.append(f"{module}:{node.lineno} -> {target}")
    assert not violations, "Core imports lab/proof code:\n" + "\n".join(violations)


def test_authorization_probe_import_does_not_load_labs_or_proof() -> None:
    code = (
        "import sys; import mcp_audit.probe; "
        f"assert not [name for name in sys.modules if name.startswith({NON_CORE_PREFIXES!r})]"
    )
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr


def test_labs_do_not_import_deleted_legacy_cli_symbols() -> None:
    labs = ROOT.parent / "distributions" / "labs" / "src" / "mcp_audit_labs"
    # X-2 removes monitor, the legacy scan engine, and the cli compatibility
    # exports. Labs use the engine/api and public probe helpers instead.
    deleted_modules = {"mcp_audit.monitor", "mcp_audit.scan_cli", "mcp_audit._core_cli"}
    deleted_symbols = {"_run_scan_core", "_run_scan", "_parse_clients"}
    violations: list[str] = []
    for path in sorted(labs.rglob("*.py")):
        relative = path.relative_to(labs).as_posix()
        tree = ast.parse(path.read_text(encoding="utf-8"))
        # Names bound to the mcp_audit.cli module, so `cli._run_scan` is caught too.
        cli_aliases = {"mcp_audit.cli"}
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module == "mcp_audit" and not node.level:
                cli_aliases.update(alias.asname or alias.name for alias in node.names if alias.name == "cli")
            elif isinstance(node, ast.Import):
                cli_aliases.update(
                    alias.asname for alias in node.names if alias.name == "mcp_audit.cli" and alias.asname
                )
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                targets = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                prefix = node.module or ""
                targets = [prefix, *(f"{prefix}.{alias.name}" for alias in node.names)]
            elif (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id in {"import_module", "__import__"}
                and node.args
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)
            ):
                targets = [node.args[0].value]
            elif isinstance(node, ast.Attribute) and node.attr in deleted_symbols:
                owner = _dotted_name(node.value)
                targets = [f"mcp_audit.cli.{node.attr}"] if owner in cli_aliases else []
            else:
                continue
            for target in targets:
                if any(target == name or target.startswith(name + ".") for name in deleted_modules) or (
                    target.startswith("mcp_audit.cli.") and target.rsplit(".", 1)[-1] in deleted_symbols
                ):
                    violations.append(f"{relative}:{node.lineno} -> {target}")
    assert not violations, "Labs import deleted legacy CLI symbols:\n" + "\n".join(violations)


def _dotted_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        owner = _dotted_name(node.value)
        return f"{owner}.{node.attr}" if owner is not None else None
    return None
