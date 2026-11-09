"""Deterministic metadata-only chain reports (never config or tool contents)."""

from __future__ import annotations

import json
import unicodedata
from dataclasses import asdict

from redteam.chains.labeler import label_server
from redteam.chains.pairs import ConfiguredServer, pair_servers
from redteam.chains.rank import RankedChain, rank_chains


def _source(server: ConfiguredServer) -> str:
    if server.surface is None:
        return "UNKNOWN"
    source = server.surface.source
    if server.source == "explicit":
        return f"explicit {source} (declared metadata)"
    if source == "pin":
        return "pin (historical/unverified)"
    if source == "catalog":
        if server.surface.config.command is not None:
            return "catalog (versioned or local declared metadata; unverified)"
        return "catalog (unversioned/unverified)"
    return f"{source} (declared metadata)"


def _chain(row: RankedChain, rank: int) -> dict[str, object]:
    chain = row.chain
    pairs = sorted({(member.writer_label.tool, member.executor_label.tool) for member in row.alternatives})
    return {
        "rank": rank,
        "writer": chain.writer.name,
        "executor": chain.executor.name,
        "template": chain.template.name,
        "score": row.score,
        "explanation": list(row.explanation),
        "overlap": row.overlap,
        "preconditions": list(
            dict.fromkeys(
                (*chain.preconditions,)
                + tuple(
                    label.condition
                    for member in row.alternatives
                    for label in (member.writer_label, member.executor_label)
                    if label.condition is not None
                )
            )
        ),
        "surface_sources": {"writer": _source(chain.writer), "executor": _source(chain.executor)},
        "steps": [asdict(step) for step in chain.steps],
        "alternative_tool_pairs": [
            {"writer_tool": writer, "executor_tool": executor} for writer, executor in pairs
        ],
    }


def build_report(servers: list[ConfiguredServer]) -> dict[str, object]:
    ranked, dropped = rank_chains(pair_servers(servers))
    rows = [_chain(row, number) for number, row in enumerate(ranked, 1)]
    report: dict[str, object] = {
        "schema": "mcpaudit.chains.v1",
        "mode": "static/offline; no MCP server connections",
        "limitations": (
            "Declared, catalog, and historical surfaces do not verify current server behavior. "
            "Ranking describes conditional capability composition, not exploitability."
        ),
        "analysis_incomplete": any(server.parse_error for server in servers),
        "servers": [
            {
                "name": server.name,
                "tool_surface": server.tool_surface,
                "surface_source": _source(server),
                "env_keys": sorted(set(server.env_keys)),
                "reason": server.reason,
                **(
                    {
                        "provenance": (
                            "user-selected explicit metadata; current surface unverified"
                            if server.source == "explicit"
                            else server.surface.provenance
                        ),
                        "unverified": True,
                    }
                    if server.surface is not None and server.surface.source == "catalog"
                    else {}
                ),
            }
            for server in sorted(servers, key=lambda item: item.name)
        ],
        "ranked": rows,
        "unknown_surfaces": sorted(server.name for server in servers if server.surface is None),
        "unknown_labels": [
            {"server": server.name, "tool": label.tool}
            for server in sorted(servers, key=lambda item: item.name)
            if server.surface is not None
            for label in label_server(server.surface)
            if label.tag == "unknown"
        ],
        "dropped": [
            {
                "template": row.chain.template.name,
                "writer": row.chain.writer.name,
                "executor": row.chain.executor.name,
                "reason": row.reason,
            }
            for row in dropped
        ],
        "discovery_notes": [],
    }
    return report


def to_json(report: dict[str, object]) -> str:
    return json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def _cell(value: object) -> str:
    # Configured names and tool names may be untrusted terminal/Markdown text.
    text = "".join(char if not unicodedata.category(char).startswith("C") else " " for char in str(value))
    return text.replace("|", r"\|")


def _items(value: object) -> list[object]:
    return list(value) if isinstance(value, list) else []


def _steps(row: dict[str, object]) -> str:
    by_executor: dict[str, set[str]] = {}
    for pair in _items(row["alternative_tool_pairs"]):
        if isinstance(pair, dict):
            writer, executor = pair.get("writer_tool"), pair.get("executor_tool")
            if isinstance(writer, str) and isinstance(executor, str):
                by_executor.setdefault(executor, set()).add(writer)
    return "; ".join(
        f"{row['writer']}.{'|'.join(sorted(writers))} → {row['executor']}.{executor}"
        for executor, writers in sorted(by_executor.items())
    )


def to_markdown(report: dict[str, object]) -> str:
    lines = [
        "# Two-server chains",
        "",
        _cell(report["mode"]),
        "",
        _cell(report["limitations"]),
        "",
        "| Rank | Writer → executor | Template | Steps | Score + explanation | "
        "Preconditions | Surface sources |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for row in _items(report["ranked"]):
        if not isinstance(row, dict):
            continue
        sources = row["surface_sources"]
        source_text = (
            "; ".join(f"{_cell(key)}: {_cell(value)}" for key, value in sorted(sources.items()))
            if isinstance(sources, dict)
            else _cell(sources)
        )
        explanation = "; ".join(_cell(item) for item in _items(row["explanation"]))
        conditions = "; ".join(_cell(item) for item in _items(row["preconditions"]))
        lines.append(
            f"| {_cell(row['rank'])} | {_cell(row['writer'])} → {_cell(row['executor'])} | "
            f"{_cell(row['template'])} | {_cell(_steps(row))} | "
            f"{_cell(row['score'])}: {explanation} | {conditions} | "
            f"{source_text} |"
        )
    if report["analysis_incomplete"]:
        lines.extend(["", "Analysis incomplete: one or more server entries could not be parsed."])
    unknown = ", ".join(_cell(name) for name in _items(report["unknown_surfaces"]))
    lines.extend(["", f"UNKNOWN surfaces: {unknown or 'none'}."])
    unknown_labels = _items(report.get("unknown_labels"))
    if unknown_labels:
        lines.extend(["", "UNKNOWN tool labels; possible chains were not ranked:"])
        for item in unknown_labels:
            if isinstance(item, dict):
                lines.append(f"- {_cell(item.get('server'))}.{_cell(item.get('tool'))}")
    for server in _items(report["servers"]):
        if not isinstance(server, dict):
            continue
        if server.get("reason"):
            lines.append(
                f"Surface {_cell(server['name'])}: {_cell(server['tool_surface'])} — "
                f"{_cell(server['reason'])}."
            )
        if server.get("provenance"):
            lines.append(
                f"Surface {_cell(server['name'])}: {_cell(server['surface_source'])}; "
                f"{_cell(server['provenance'])}."
            )
    return "\n".join(lines) + "\n"
