"""Turn a resolution and an observation into mismatches, a verdict, suggested lines, and a pin."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from hashlib import sha256
from urllib.parse import urlsplit

from mcp_audit import __version__
from mcp_audit.models import ToolInfo
from mcp_audit.redaction import redact_text
from mcp_audit.trust.models import (
    Mismatch,
    NetworkEvent,
    Observation,
    Phase,
    PinnedTool,
    Resolution,
    Severity,
    Suggestion,
    ToolSummary,
    TrustPin,
    Verdict,
    VerdictCard,
)
from mcp_audit.trust.sandbox import HOME

_LOCAL_CLAIM = re.compile(
    r"\b(local(?:ly)?|offline|no network|on-device|never (?:sends|leaves)|private)\b", re.I
)
_NAMESPACE_CHECKS = {"namespace.repository", "namespace.remote_host", "namespace.package_ownership"}
_KEY = re.compile(r"[^A-Za-z0-9_-]+")


def utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def hosts(events: list[NetworkEvent]) -> list[str]:
    """Distinct destinations; a lookup is folded into a later connect to the same host."""
    seen: dict[str, None] = {}
    connected = {e.host for e in events if e.kind == "tcp" and e.host} | {
        e.sni or e.http_host for e in events if e.kind == "tcp" and (e.sni or e.http_host)
    }
    for event in events:
        if event.kind == "udp":
            seen["udp (destination not recorded)"] = None
            continue
        if event.kind == "dns" and event.host in connected:
            continue
        host = event.sni or event.http_host or event.host or event.ip
        if host:
            seen[f"{host}:{event.port}" if event.kind == "tcp" and event.port else f"{host} (lookup)"] = None
    return list(seen)


def _home(path: str) -> str:
    return "$HOME" + path.removeprefix(HOME) if path == HOME or path.startswith(HOME + "/") else path


def mismatches(resolution: Resolution, observation: Observation, drift: list[Mismatch]) -> list[Mismatch]:
    found: list[Mismatch] = []
    for check in resolution.checks:
        if check.status == "fail":
            found.append(Mismatch(severity="high", rule="TBC-RESOLVE", summary=check.summary))
        elif check.status == "warn":
            severity: Severity = (
                "medium" if check.id in _NAMESPACE_CHECKS or check.id == "registry.listed" else "low"
            )
            found.append(Mismatch(severity=severity, rule="TBC-RESOLVE", summary=check.summary))
    if resolution.package and resolution.package.install_scripts:
        found.append(
            Mismatch(
                severity="low",
                rule="TBC-INSTALL-SCRIPTS",
                summary="Declares npm install scripts ("
                + ", ".join(resolution.package.install_scripts)
                + "); they were not run here, so their effects are unobserved.",
            )
        )
    tools = {t.name: t for t in observation.tools}
    for tool in observation.tools:
        if tool.injection:
            found.append(
                Mismatch(
                    severity="high",
                    rule="TBC-INJECTION",
                    tool=tool.name,
                    summary=f"Tool text matches prompt-injection patterns: {', '.join(tool.injection)}.",
                )
            )
    all_events: list[NetworkEvent] = []
    for phase in observation.phases:
        all_events.extend(phase.network)
        found.extend(_phase_mismatches(phase, tools.get(phase.tool or "")))
    if all_events and resolution.description and _LOCAL_CLAIM.search(resolution.description):
        found.append(
            Mismatch(
                severity="medium",
                rule="TBC-LOCAL-CLAIM-NET",
                summary="Its description reads as local or offline, yet it tried to reach "
                + ", ".join(hosts(all_events)[:5])
                + ".",
            )
        )
    found.extend(drift)
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    return sorted(found, key=lambda m: (order[m.severity], m.rule, m.tool or ""))


def _phase_mismatches(phase: Phase, tool: ToolSummary | None) -> list[Mismatch]:
    found: list[Mismatch] = []
    writes = list(phase.file_changes)
    outside = [c for c in writes if not c.in_home]
    reached = hosts(phase.network)
    if tool is not None and tool.read_only_hint is True:
        if writes:
            found.append(
                Mismatch(
                    severity="high",
                    rule="TBC-READONLY-WRITE",
                    tool=tool.name,
                    summary=f"Declared read-only, but {len(writes)} file change(s) appeared during its call: "
                    + ", ".join(_home(c.path) for c in writes[:4])
                    + ".",
                )
            )
        if reached:
            closed = tool.open_world_hint is False
            found.append(
                Mismatch(
                    severity="high" if closed else "low",
                    rule="TBC-READONLY-NET",
                    tool=tool.name,
                    summary=(
                        "Declared closed-world (openWorldHint false), but reached "
                        if closed
                        else "Read-only tool reached the network during its call: "
                    )
                    + ", ".join(reached[:5])
                    + ".",
                )
            )
        return found
    when = "at startup" if phase.name == "startup" else "at shutdown" if phase.name == "shutdown" else None
    if when and reached:
        found.append(
            Mismatch(
                severity="medium",
                rule="TBC-UNPROMPTED-NET",
                summary=f"Tried to reach the network {when}, before any tool was called: "
                + ", ".join(reached[:6])
                + ".",
            )
        )
    if outside:
        found.append(
            Mismatch(
                severity="medium",
                rule="TBC-WRITE-OUTSIDE-HOME",
                tool=phase.tool,
                summary=f"Wrote outside its home directory {when or 'during ' + phase.name}: "
                + ", ".join(c.path for c in outside[:4])
                + ".",
            )
        )
    inside = [c for c in writes if c.in_home]
    if when and inside:
        found.append(
            Mismatch(
                severity="info",
                rule="TBC-STARTUP-WRITE",
                summary=f"Created files in its home directory {when}: "
                + ", ".join(_home(c.path) for c in inside[:4])
                + ".",
            )
        )
    return found


def decide(observation: Observation, found: list[Mismatch]) -> tuple[Verdict, str]:
    severities = {m.severity for m in found}
    if "high" in severities:
        return (
            "do_not_install",
            "Do not install: at least one high-severity mismatch between claims and behaviour.",
        )
    if observation.status == "failed":
        return "incomplete", "Incomplete: the server could not be observed, so behaviour is unknown."
    if "medium" in severities:
        return "review", "Review before installing: what it did differs from what it claims."
    if observation.status == "partial":
        return "incomplete", "Incomplete: observation stopped early; review the gaps below."
    if observation.mode == "outside":
        return (
            "no_mismatches_observed",
            "No mismatches observed from outside; its server-side behaviour is unseen.",
        )
    return (
        "no_mismatches_observed",
        "No mismatches observed in the sandbox. That is evidence, not a guarantee.",
    )


def server_key(resolution: Resolution) -> str:
    base = resolution.server_name or (resolution.package.identifier if resolution.package else "") or "server"
    key = _KEY.sub("-", base.rsplit("/", 1)[-1]).strip("-")
    return key or "server"


def suggestions(
    resolution: Resolution, observation: Observation, found: list[Mismatch], command: list[str] | None
) -> list[Suggestion]:
    key = server_key(resolution)
    result = [_launch(resolution, key, command)]
    if observation.tools:
        result.append(_permissions(key, observation, found))
    result.append(_egress(resolution, observation))
    if observation.mode == "container":
        result.append(_filesystem(observation))
    return [s for s in result if s is not None]


def _launch(resolution: Resolution, key: str, command: list[str] | None) -> Suggestion:
    entry: dict[str, object]
    package = resolution.package
    if package is not None and package.registry_type in {"npm", "pypi"}:
        if package.registry_type == "npm":
            spec = f"{package.identifier}@{package.version}" if package.version else package.identifier
            entry = {"command": "npx", "args": ["-y", spec, *package.arguments]}
        else:
            spec = f"{package.identifier}=={package.version}" if package.version else package.identifier
            script = command[0].rsplit("/", 1)[-1] if command else None
            args = ["--from", spec, script] if script else [spec]
            entry = {"command": "uvx", "args": [*args, *package.arguments]}
        if package.env:
            entry["env"] = {var.name: "<set-me>" for var in package.env if var.required or var.secret}
            if not entry["env"]:
                del entry["env"]
    elif resolution.remote is not None:
        entry = {"type": "http", "url": resolution.remote.url}
    else:
        entry = {"note": "nothing runnable was resolved"}
    return Suggestion(
        title="Pinned launch entry",
        format="json",
        body=json.dumps({"mcpServers": {key: entry}}, indent=2),
        note="Generated from published metadata with the exact version. MCPAudit never reads or edits "
        "your client configuration; paste it yourself after review.",
    )


def _permissions(key: str, observation: Observation, found: list[Mismatch]) -> Suggestion:
    flagged = {m.tool for m in found if m.tool and m.severity == "high"}
    effects = {
        phase.tool for phase in observation.phases if phase.tool and (phase.file_changes or phase.network)
    }
    allow, ask, deny = [], [], []
    for tool in observation.tools:
        rule = f"mcp__{key}__{tool.name}"
        if tool.name in flagged or tool.destructive_hint is True or tool.injection:
            deny.append(rule)
        elif tool.exercised and tool.read_only_hint is True and tool.name not in effects:
            allow.append(rule)
        else:
            ask.append(rule)
    body = json.dumps({"permissions": {"allow": allow, "ask": ask, "deny": deny}}, indent=2)
    return Suggestion(
        title="Tool permissions (Claude Code settings)",
        format="json",
        body=body,
        note="allow: declared read-only, exercised, and no effects seen. deny: declared destructive, "
        "injection-matching, or a high-severity mismatch. ask: everything not proven either way.",
    )


def _egress(resolution: Resolution, observation: Observation) -> Suggestion:
    lines: list[str] = []
    if observation.mode == "outside" and resolution.remote is not None:
        host = urlsplit(resolution.remote.url).hostname
        lines.append(f"allow {host}:443  # the remote endpoint itself")
        lines.append("# Server-side egress cannot be seen from outside.")
    else:
        seen: dict[str, list[str]] = {}
        for phase in observation.phases:
            for host in hosts(phase.network):
                seen.setdefault(host, []).append(phase.name)
        for host, phases in seen.items():
            lines.append(f"review {host}  # attempted during {', '.join(dict.fromkeys(phases))}")
        lines.append(
            "deny *  # nothing else was attempted" if seen else "deny *  # no egress attempts observed"
        )
    return Suggestion(
        title="Network egress",
        format="text",
        body="\n".join(lines),
        note="Hosts are attempts recorded by the sinkhole; none were reached. "
        "Allow only what the tools you use need.",
    )


def _filesystem(observation: Observation) -> Suggestion:
    roots: dict[str, None] = {}
    for phase in observation.phases:
        for change in phase.file_changes:
            if change.in_home:
                parts = change.path.removeprefix(HOME + "/").split("/", 1)
                roots[f"$HOME/{parts[0]}" if parts[0] else "$HOME"] = None
            else:
                roots[change.path] = None
    lines = [f"allow-write {root}" for root in roots]
    lines.append(
        "deny-write *  # nothing else was written" if roots else "deny-write *  # no writes observed"
    )
    return Suggestion(
        title="Filesystem writes",
        format="text",
        body="\n".join(lines),
        note="Paths are where it wrote during the observed session; reads were not recorded.",
    )


def _schema_hash(schema: object) -> str:
    return sha256(json.dumps(schema, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


def build_pin(resolution: Resolution, observation: Observation, tools: list[ToolInfo]) -> TrustPin:
    pinned = [
        PinnedTool(
            name=tool.name,
            description=redact_text(tool.description or "") or None,
            description_sha256=sha256((tool.description or "").encode()).hexdigest(),
            input_schema_sha256=_schema_hash(tool.input_schema or {}),
            annotations={
                "readOnlyHint": tool.annotations.read_only_hint if tool.annotations else None,
                "destructiveHint": tool.annotations.destructive_hint if tool.annotations else None,
                "openWorldHint": tool.annotations.open_world_hint if tool.annotations else None,
            },
        )
        for tool in sorted(tools, key=lambda t: t.name)
    ]
    surface = sha256(
        json.dumps(
            [[t.name, t.description_sha256, t.input_schema_sha256, t.annotations] for t in pinned],
            sort_keys=True,
        ).encode()
    ).hexdigest()
    package = resolution.package
    return TrustPin(
        created_at=utc_now(),
        target=resolution.input,
        server_name=resolution.server_name,
        package=f"{package.registry_type}:{package.identifier}" if package else None,
        version=package.version if package else resolution.server_version,
        protocol_version=observation.protocol_version,
        surface_sha256=surface,
        tools=pinned,
    )


def compare_pin(previous: TrustPin, current: TrustPin) -> list[Mismatch]:
    """Drift between an earlier pin and this run's surface."""
    if previous.surface_sha256 == current.surface_sha256:
        return []
    before = {t.name: t for t in previous.tools}
    after = {t.name: t for t in current.tools}
    found: list[Mismatch] = []
    for name in sorted(after.keys() - before.keys()):
        found.append(
            Mismatch(severity="medium", rule="TBC-DRIFT", tool=name, summary="Tool added since the pin.")
        )
    for name in sorted(before.keys() - after.keys()):
        found.append(
            Mismatch(severity="low", rule="TBC-DRIFT", tool=name, summary="Tool removed since the pin.")
        )
    for name in sorted(before.keys() & after.keys()):
        old, new = before[name], after[name]
        changed = [
            label
            for label, differs in (
                ("description", old.description_sha256 != new.description_sha256),
                ("input schema", old.input_schema_sha256 != new.input_schema_sha256),
                ("annotations", old.annotations != new.annotations),
            )
            if differs
        ]
        if changed:
            found.append(
                Mismatch(
                    severity="medium",
                    rule="TBC-DRIFT",
                    tool=name,
                    summary=f"{', '.join(changed).capitalize()} changed since the pin.",
                )
            )
    return found


def build_card(
    resolution: Resolution,
    observation: Observation,
    drift: list[Mismatch],
    command: list[str] | None,
) -> VerdictCard:
    found = mismatches(resolution, observation, drift)
    verdict, headline = decide(observation, found)
    return VerdictCard(
        generated_at=utc_now(),
        mcp_audit_version=__version__,
        target=resolution,
        observation=observation,
        mismatches=found,
        verdict=verdict,
        headline=headline,
        suggestions=suggestions(resolution, observation, found, command),
    )
