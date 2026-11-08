"""Render a verdict card for the terminal and as a small self-contained HTML page."""

from __future__ import annotations

import json
from collections import Counter
from html import escape

from mcp_audit.terminal_text import strip_controls
from mcp_audit.trust.models import Phase, VerdictCard
from mcp_audit.trust.verdict import hosts

_VERDICT_LABEL = {
    "no_mismatches_observed": "NO MISMATCHES OBSERVED",
    "review": "REVIEW",
    "do_not_install": "DO NOT INSTALL",
    "incomplete": "INCOMPLETE",
}
_MODE_LABEL = {
    "container": "sandboxed container run",
    "outside": "outside view only (remote server)",
    "none": "not observed",
}


def _t(value: object) -> str:
    return strip_controls(str(value))


def _phase_line(phase: Phase) -> str:
    bits: list[str] = []
    if phase.file_changes:
        bits.append(f"{len(phase.file_changes) + phase.file_changes_truncated} file change(s)")
    reached = hosts(phase.network)
    if reached:
        bits.append("network: " + ", ".join(reached[:6]))
    if phase.error:
        bits.append(f"error: {phase.error}")
    elif phase.is_error:
        bits.append("tool returned an error result")
    return f"{phase.name}: " + ("; ".join(bits) if bits else "no writes, no network")


def terminal(card: VerdictCard) -> str:
    target, obs = card.target, card.observation
    lines = [
        f"Trust Before Connect: {_t(target.server_name or target.input)}",
        f"  verdict  {_VERDICT_LABEL[card.verdict]}  {_t(card.headline)}",
        f"  observed {_MODE_LABEL[obs.mode]}"
        + (f", {obs.status}" if obs.status != "complete" else "")
        + (f", MCP {obs.protocol_version}" if obs.protocol_version else ""),
    ]
    if target.package:
        package = target.package
        lines.append(
            f"  package  {package.registry_type}:{_t(package.identifier)} {_t(package.version or '?')}"
        )
    if target.remote:
        lines.append(f"  remote   {_t(target.remote.url)}")
    if obs.error:
        lines.append(f"  error    {_t(obs.error)}")
    lines += ["", "Claims"]
    if target.description:
        lines.append(f"  description: {_t(target.description)}")
    for check in target.checks:
        lines.append(f"  [{check.status:<7}] {_t(check.summary)}")
    if obs.tools:
        read_only = sum(1 for t in obs.tools if t.read_only_hint is True)
        lines.append(f"  tools: {len(obs.tools)} listed, {read_only} declared read-only")
    lines += ["", "Touched"]
    if not obs.phases:
        unseen = (
            "not observable from outside (remote server)" if obs.mode == "outside" else "nothing observed"
        )
        lines.append("  " + unseen)
    for phase in obs.phases:
        lines.append("  " + _t(_phase_line(phase)))
        for change in phase.file_changes[:5]:
            kind = "entries" if change.entries_only else change.change
            lines.append(f"      {kind:<8} {_t(change.path)}")
    exercised = [t.name for t in obs.tools if t.exercised]
    if obs.tools:
        lines.append(f"  exercised: {', '.join(map(_t, exercised)) if exercised else 'none'}")
    lines += ["", "Mismatches"]
    if not card.mismatches:
        lines.append("  none")
    for mismatch in card.mismatches:
        tool = f" [{_t(mismatch.tool)}]" if mismatch.tool else ""
        lines.append(f"  {mismatch.severity.upper():<6} {mismatch.rule}{tool} {_t(mismatch.summary)}")
    lines += ["", "Suggested lines"]
    for suggestion in card.suggestions:
        lines.append(f"  {suggestion.title}")
        lines.extend("    " + _t(line) for line in suggestion.body.splitlines())
    if obs.limits:
        lines += ["", "Limits"]
        lines.extend(f"  - {_t(limit)}" for limit in obs.limits)
    return "\n".join(lines)


_CSS = """
:root{--bg:#fbfaf7;--fg:#1d1d1b;--muted:#6b6a65;--line:#e4e1d8;--card:#fff;
--ok:#1f7a4d;--warn:#9a6200;--bad:#b42318;--info:#3d5a99;--code:#f3f1ea}
@media (prefers-color-scheme:dark){:root{--bg:#161614;--fg:#ecebe6;--muted:#a3a19a;--line:#2e2d29;
--card:#1e1d1a;--ok:#5cc28f;--warn:#e0a948;--bad:#f07a6e;--info:#8fa8e6;--code:#26251f}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.55 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:920px;margin:0 auto;padding:32px 16px 64px}
h1{font-size:22px;margin:0 0 4px;overflow-wrap:break-word}h2{font-size:15px;text-transform:uppercase;
letter-spacing:.06em;color:var(--muted);margin:32px 0 10px}
.sub{color:var(--muted);margin:0 0 20px;overflow-wrap:break-word}
.verdict{border:1px solid var(--line);border-left:6px solid var(--c);background:var(--card);
padding:14px 18px;border-radius:8px}.verdict b{color:var(--c);letter-spacing:.04em}
.v-no_mismatches_observed{--c:var(--ok)}.v-review{--c:var(--warn)}.v-do_not_install{--c:var(--bad)}
.v-incomplete{--c:var(--muted)}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);
border-radius:8px;overflow:hidden}td,th{text-align:left;vertical-align:top;padding:8px 12px;
border-top:1px solid var(--line);overflow-wrap:break-word}tr:first-child td,tr:first-child th{border-top:0}
th{font-weight:600;color:var(--muted);font-size:13px}
.s{font-size:12px;font-weight:700;text-transform:uppercase;white-space:nowrap}
.s-pass,.s-low{color:var(--ok)}.s-warn,.s-medium{color:var(--warn)}.s-fail,.s-high{color:var(--bad)}
.s-unknown,.s-info{color:var(--info)}
code,pre{font:13px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace}code{overflow-wrap:anywhere}
pre{background:var(--code);border:1px solid var(--line);border-radius:8px;padding:12px;
overflow:auto;margin:6px 0}
.note{color:var(--muted);font-size:13px;margin:4px 0 16px}ul{margin:0;padding-left:20px}
.wrap{overflow-x:auto}
"""


def _row(*cells: str, head: bool = False) -> str:
    tag = "th" if head else "td"
    return "<tr>" + "".join(f"<{tag}>{cell}</{tag}>" for cell in cells) + "</tr>"


def _badge(value: str) -> str:
    return f'<span class="s s-{escape(value)}">{escape(value)}</span>'


def html(card: VerdictCard) -> str:
    target, obs = card.target, card.observation
    name = escape(target.server_name or target.input)
    facts = [
        (
            "Observed",
            escape(_MODE_LABEL[obs.mode] + (f" ({obs.status})" if obs.status != "complete" else "")),
        ),
    ]
    if target.package:
        package = target.package
        facts.append(
            (
                "Package",
                f"<code>{escape(package.registry_type)}:{escape(package.identifier)}</code> "
                f"{escape(package.version or '?')}",
            )
        )
    if target.remote:
        facts.append(("Remote", f"<code>{escape(target.remote.url)}</code>"))
    if obs.protocol_version:
        facts.append(("MCP protocol", escape(f"{obs.protocol_version} ({obs.protocol_era})")))
    if obs.runtime:
        facts.append(("Runtime", escape(obs.runtime)))
    if obs.image:
        facts.append(("Base image", f"<code>{escape(obs.image)}</code>"))
    if obs.network_policy:
        facts.append(("Network", escape(obs.network_policy)))
    if obs.synthetic_env:
        facts.append(("Synthetic env", escape(", ".join(obs.synthetic_env))))
    if obs.error:
        facts.append(("Error", escape(obs.error)))
    parts = [
        "<!doctype html><html lang=en><head><meta charset=utf-8>",
        '<meta name=viewport content="width=device-width,initial-scale=1">',
        f"<title>Trust card: {name}</title><style>{_CSS}</style></head><body><main>",
        f"<h1>{name}</h1>",
        f"<p class=sub>{escape(target.title or '')}{' · ' if target.title else ''}"
        f"{escape(target.description or 'No description published.')}</p>",
        f'<div class="verdict v-{card.verdict}"><b>{_VERDICT_LABEL[card.verdict]}</b><br>'
        f"{escape(card.headline)}</div>",
        "<h2>Run</h2><div class=wrap><table>",
        *(_row(f"<b>{label}</b>", value) for label, value in facts),
        "</table></div>",
        "<h2>What it claims</h2><div class=wrap><table>",
        _row("Result", "Check", head=True),
        *(_row(_badge(c.status), escape(c.summary)) for c in target.checks),
        "</table></div>",
    ]
    if obs.tools:
        parts += [
            "<h2>Tools</h2><div class=wrap><table>",
            _row("Tool", "Declared", "Inferred", "Exercised", head=True),
        ]
        for tool in obs.tools:
            declared = ", ".join(
                label
                for label, value in (
                    ("read-only", tool.read_only_hint),
                    ("destructive", tool.destructive_hint),
                    ("open-world", tool.open_world_hint),
                )
                if value is True
            )
            parts.append(
                _row(
                    f"<code>{escape(tool.name)}</code><div class=note>{escape(tool.description or '')}</div>",
                    escape(declared or "no hints"),
                    escape(", ".join(tool.inferred) or "none"),
                    "yes" if tool.exercised else escape(tool.skip_reason or "no"),
                )
            )
        parts.append("</table></div>")
    parts += ["<h2>What it touched</h2>"]
    if obs.sandbox:
        parts.append("<ul class=note>" + "".join(f"<li>{escape(f)}</li>" for f in obs.sandbox) + "</ul>")
    parts += ["<div class=wrap><table>", _row("Phase", "File writes", "Network attempts", head=True)]
    for phase in obs.phases:
        files = "<br>".join(
            f"{'temporary entries in' if c.entries_only else escape(c.change)} <code>{escape(c.path)}</code>"
            for c in phase.file_changes[:30]
        )
        if phase.file_changes_truncated or len(phase.file_changes) > 30:
            files += f"<br>… {len(phase.file_changes) - 30 + phase.file_changes_truncated} more"
        counts = Counter(e.label() for e in phase.network)
        net = "<br>".join(
            escape(label + (f" ×{n}" if n > 1 else "")) for label, n in list(counts.items())[:30]
        )
        label = escape(phase.name)
        if phase.arguments is not None:
            shown = json.dumps(phase.arguments, sort_keys=True, default=str)
            label += f"<div class=note>synthetic input <code>{escape(shown)}</code></div>"
        if phase.error or phase.is_error:
            label += f"<div class=note>{escape(phase.error or 'returned an error result')}</div>"
        parts.append(_row(label, files or "none", net or "none"))
    if not obs.phases:
        unseen = "not observable from outside" if obs.mode == "outside" else "not observed"
        parts.append(_row("—", unseen, unseen))
    parts += ["</table></div>", "<h2>Mismatches</h2>"]
    if card.mismatches:
        parts += ["<div class=wrap><table>", _row("Severity", "Rule", "Detail", head=True)]
        parts += [
            _row(
                _badge(m.severity),
                f"<code>{escape(m.rule)}</code>",
                (f"<code>{escape(m.tool)}</code> " if m.tool else "") + escape(m.summary),
            )
            for m in card.mismatches
        ]
        parts.append("</table></div>")
    else:
        parts.append("<p>None found between what it claims and what it did.</p>")
    parts.append("<h2>Suggested lines</h2>")
    for suggestion in card.suggestions:
        parts.append(f"<b>{escape(suggestion.title)}</b><pre>{escape(suggestion.body)}</pre>")
        if suggestion.note:
            parts.append(f"<p class=note>{escape(suggestion.note)}</p>")
    if obs.limits:
        parts += ["<h2>Limits of this run</h2><ul>", *(f"<li>{escape(x)}</li>" for x in obs.limits), "</ul>"]
    parts.append(
        f"<p class=note>Generated {escape(card.generated_at)} by mcp-audit {escape(card.mcp_audit_version)}. "
        "Server-provided text is shown escaped and redacted.</p></main></body></html>"
    )
    return "\n".join(parts)
