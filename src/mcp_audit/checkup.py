"""Local counts-only checkup cards, independent of report evidence rendering."""

from __future__ import annotations

import html
import os
import re
import stat
from pathlib import Path

from pydantic import ValidationError

from mcp_audit import __version__
from mcp_audit.models import AuditReport
from mcp_audit.pkgverify import resolve_package_refs
from mcp_audit.redaction import redacted_excerpt

_STYLE = """
*{box-sizing:border-box}
body{margin:0;background:#eceae4;color:#1d1b16;
font:16px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
.card{width:1200px;height:630px;background:#fffdf8;border-radius:28px;position:relative;
overflow:hidden;display:grid;grid-template-columns:400px 1fr;color:#1d1b16}
.card::after{content:"";position:absolute;inset:0;pointer-events:none;
background:repeating-linear-gradient(0deg,transparent 0 33px,rgba(52,70,196,.05) 33px 34px)}
.left{padding:54px 0 48px 60px;display:flex;flex-direction:column;justify-content:space-between;z-index:1}
.kicker{font:700 15px/1 ui-monospace,Menlo,monospace;letter-spacing:.14em;color:#6b665b}
.big{font:800 250px/.85 ui-rounded,system-ui,sans-serif;letter-spacing:-.06em;margin:0;color:#1d7a3e}
.big.B{color:#4d7c0f}.big.C{color:#8a5a00}.big.D,.big.F{color:#b42318}
.big.preview{font-size:70px;letter-spacing:-.03em;color:#6b665b}
.verdict{font-size:28px;font-weight:750;line-height:1.15;margin:16px 0 0;max-width:310px}
.right{padding:54px 60px 48px 20px;display:flex;flex-direction:column;justify-content:space-between;z-index:1}
.title{font-size:40px;font-weight:800;letter-spacing:-.025em;line-height:1.1;margin:0}
.title span{color:#6b665b;font-weight:600}
.vitals{list-style:none;margin:0;padding:0;display:grid;gap:12px}
.vitals li{display:grid;grid-template-columns:40px 1fr auto;align-items:center;gap:14px;
font-size:23px;font-weight:600;padding:10px 0;border-bottom:2px dashed #e7e1d4}
.vitals li:last-child{border:0}
.dot{width:40px;height:40px;border-radius:12px;display:grid;place-items:center;
font-size:22px;background:#fdf3dc;color:#8a5a00}
.ok .dot{background:#e5f4ea;color:#1d7a3e}
.val{font:700 20px/1 ui-monospace,Menlo,monospace;color:#6b665b}
.foot{font-size:17px;color:#6b665b}.foot p{margin:4px 0}
.foot code{font:600 18px/1 ui-monospace,Menlo,monospace;color:#1d1b16}
.caveat{font-weight:700}.names{margin:4px 0;max-width:1200px;overflow-wrap:anywhere}
"""


def load_previous(path: Path | None) -> AuditReport | None:
    """Read only an explicitly selected, bounded local report; no history discovery."""
    if path is None:
        return None
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError("Previous report must be a regular file.")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            payload = stream.read(16 * 1024 * 1024 + 1)
    finally:
        os.close(descriptor)
    if len(payload) > 16 * 1024 * 1024:
        raise ValueError("Previous report exceeds the 16 MiB limit.")
    try:
        return AuditReport.model_validate_json(payload)
    except ValidationError:
        raise ValueError("Previous report is not valid AuditReport JSON.") from None


def vitals(report: AuditReport) -> list[tuple[str, int, bool]]:
    """Return observed counts with completion; an unrun check never means zero risk."""

    def complete(check: str) -> bool:
        entry = report.coverage.get(check)
        return entry is not None and entry.state == "complete"

    floating = sum(
        any(
            ref.version is None
            or (
                ref.ecosystem == "npm"
                and re.fullmatch(r"v?\d+\.\d+\.\d+(?:-[\w.-]+)?(?:\+[\w.-]+)?", ref.version) is None
            )
            or (ref.ecosystem == "pypi" and "*" in ref.version)
            for ref in resolve_package_refs(audit.server)
        )
        for audit in report.audits
    )
    return [
        (
            "Hidden instruction signals",
            sum(len(a.injection_findings) for a in report.audits),
            complete("inject_check"),
        ),
        (
            "Read, fetch & send chains",
            len(report.fleet_trifecta_findings) + sum(len(a.trifecta_findings) for a in report.audits),
            complete("trifecta_check"),
        ),
        ("Lookalike tool names", len(report.shadowing_findings), complete("shadow_check")),
        ("Auto-updating launches", floating, complete("config_health")),
    ]


def _comparison(report: AuditReport, previous: AuditReport | None) -> str:
    if (
        previous is None
        or (previous.scan_timestamp.tzinfo is None) != (report.scan_timestamp.tzinfo is None)
        or previous.scan_timestamp >= report.scan_timestamp
    ):
        return ""

    def identities(r: AuditReport) -> list[tuple[str, str, str, str]]:
        return sorted(
            (a.server.client.value, a.server.scope, a.server.name, a.server.config_path) for a in r.audits
        )

    if identities(report) != identities(previous) or report.coverage != previous.coverage:
        return ""
    current, before = report.ensure_review_summary(), previous.ensure_review_summary()
    if current.grade is None or before.grade is None:
        return ""
    fewer = before.action_count - current.action_count
    if fewer <= 0 or "ABCDF".index(current.grade) > "ABCDF".index(before.grade):
        return ""
    return f"{fewer} fewer review actions · was {before.grade} in previous run"


def sticker(report: AuditReport) -> str:
    """A counts-only Markdown line with no remote badge, URL or identifier."""
    grade = report.ux_summary.grade
    mode = "deep scan" if grade else "preview"
    return (
        f"**MCPAudit checkup · {grade or 'Preview'} · {_inventory(report)} · "
        f"{mode} · {report.scan_timestamp:%Y-%m-%d}** — " + report.ux_summary.caveat
    )


def _inventory(report: AuditReport) -> str:
    servers = f"{report.servers_discovered} server{'s' if report.servers_discovered != 1 else ''}"
    tools = f"{report.total_tools} tool{'s' if report.total_tools != 1 else ''}"
    return f"{servers}, {tools}"


def generate_card(report: AuditReport, *, names: bool = False, previous: AuditReport | None = None) -> str:
    """Render a self-contained 1200×630 crop. Raw evidence is never interpolated."""
    grade = report.ux_summary.grade
    label = grade or "Preview"
    mode = "deep scan" if grade else "preview"
    verdict = "Review the findings." if grade in {"C", "D", "F"} else "Review of reach and hygiene."
    if grade is None:
        verdict = "Incomplete tool checks. No letter grade."
    rows = []
    for title, count, completed in vitals(report):
        value = str(count) if completed else (f"{count} · partial" if count else "not checked")
        ok = completed and count == 0
        rows.append(
            f'<li class="{"ok" if ok else "warn"}"><span class="dot">{"✓" if ok else "◆"}</span>'
            f'{html.escape(title)}<span class="val">{value}</span></li>'
        )
    comparison = _comparison(report, previous)
    name_block = ""
    if names:
        safe_names = [
            html.escape(redacted_excerpt(a.server.name, 0, len(a.server.name), max_length=120))
            for a in report.audits
        ]
        name_block = '<p class="names">Server names (opt-in): ' + ", ".join(safe_names) + "</p>"
    return (
        '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        '<meta http-equiv="Content-Security-Policy" '
        "content=\"default-src 'none'; style-src 'unsafe-inline'\">"
        f"<title>MCP setup checkup</title><style>{_STYLE}</style></head><body>"
        '<main class="card" aria-label="MCP setup checkup">'
        '<div class="left"><div class="kicker">MCP SETUP CHECKUP</div><div>'
        f'<p class="big {grade or "preview"}">{label}</p><p class="verdict">{verdict}</p>'
        '</div></div><div class="right">'
        f'<h1 class="title">{_inventory(report)} '
        f'<span>· {mode}</span></h1><ul class="vitals">{"".join(rows)}</ul>'
        '<footer class="foot">'
        f"<p>{html.escape(comparison)}</p>"
        f"<p>MCPAudit {__version__} · {report.scan_timestamp:%d %b %Y} · ran locally</p>"
        f'<p class="caveat">{report.ux_summary.caveat}</p><p><code>mcp-audit checkup</code></p>'
        f"</footer></div></main>{name_block}</body></html>"
    )
