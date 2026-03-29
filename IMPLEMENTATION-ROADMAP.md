# MCP Permission Auditor (mcp-audit) — Implementation Roadmap

## Architecture

### System Overview
```
[Config Discoverer] → [Config Parser] → [Server Connector] → [Tool Enumerator]
                                                                      ↓
                                                              [Permission Analyzer]
                                                                      ↓
                                                              [Risk Scorer]
                                                                      ↓
                                                    [Report Generator (Terminal + JSON)]
```

Data flows left-to-right:
1. **Config Discoverer** scans known paths for each MCP client, returns list of config files found
2. **Config Parser** reads JSON/JSONC configs, extracts `mcpServers` entries into `ServerConfig` models
3. **Server Connector** spawns stdio servers (or connects via HTTP), performs MCP JSON-RPC `initialize` + `tools/list`
4. **Tool Enumerator** extracts tool names, descriptions, input schemas, and annotations from each server
5. **Permission Analyzer** applies keyword pattern rules + annotation data to infer permission categories per tool
6. **Risk Scorer** computes weighted multi-dimensional risk scores per server
7. **Report Generator** renders Rich terminal tables (default) or JSON file (--json flag)

### File Structure
```
mcp-audit/
├── src/
│   └── mcp_audit/
│       ├── __init__.py             # Package version
│       ├── cli.py                  # Click CLI entrypoint, subcommands: discover, scan
│       ├── discovery/
│       │   ├── __init__.py         # Exports discover_all_configs()
│       │   ├── base.py            # ConfigDiscoverer ABC
│       │   ├── claude_desktop.py  # Claude Desktop config parser
│       │   ├── claude_code.py     # Claude Code config parser (~/.claude.json)
│       │   ├── cursor.py          # Cursor config parser
│       │   ├── vscode.py          # VS Code config parser
│       │   └── windsurf.py        # Windsurf config parser
│       ├── connector.py           # MCP server connection via stdio/HTTP + tool listing
│       ├── analyzer.py            # Permission inference engine
│       ├── scorer.py              # Risk scoring with weighted dimensions
│       ├── models.py              # All Pydantic models
│       ├── rules/
│       │   ├── __init__.py
│       │   ├── patterns.py        # Permission inference keyword patterns
│       │   └── weights.py         # Risk score category weights + confidence multipliers
│       └── report.py              # Rich terminal table + JSON output generators
├── tests/
│   ├── conftest.py                # Shared fixtures, mock server factory
│   ├── test_discovery.py          # Config discovery unit tests
│   ├── test_analyzer.py           # Permission analyzer unit tests
│   ├── test_scorer.py             # Risk scoring unit tests
│   ├── test_connector.py          # Server connection integration tests
│   ├── test_report.py             # Report output tests
│   └── fixtures/                  # Sample config files for each client
│       ├── claude_desktop_config.json
│       ├── claude_code_config.json
│       ├── cursor_mcp.json
│       └── vscode_mcp.json
├── pyproject.toml
├── README.md
├── CLAUDE.md
├── IMPLEMENTATION-ROADMAP.md
└── LICENSE                        # MIT
```

### Data Model

All models in `src/mcp_audit/models.py`:

```python
from pydantic import BaseModel, Field
from enum import Enum
from datetime import datetime


class TransportType(str, Enum):
    STDIO = "stdio"
    HTTP = "http"
    SSE = "sse"  # legacy — detect and warn


class ClientType(str, Enum):
    CLAUDE_DESKTOP = "claude_desktop"
    CLAUDE_CODE = "claude_code"
    CURSOR = "cursor"
    VSCODE = "vscode"
    WINDSURF = "windsurf"


class PermissionCategory(str, Enum):
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    NETWORK = "network"
    SHELL_EXEC = "shell_execution"
    DESTRUCTIVE = "destructive"
    EXFILTRATION = "exfiltration"


class Confidence(str, Enum):
    DECLARED = "declared"   # From MCP tool annotations
    HIGH = "high"           # Multiple strong keyword matches
    MEDIUM = "medium"       # Single strong or multiple moderate
    LOW = "low"             # Weak/inferred
    MANUAL = "manual"       # From user override config


class ServerConfig(BaseModel):
    """Represents a single MCP server entry from a client config file."""
    name: str
    client: ClientType
    config_path: str
    command: str | None = None
    args: list[str] = Field(default_factory=list)
    env_keys: list[str] = Field(default_factory=list)  # Key names only, NEVER values
    transport: TransportType = TransportType.STDIO
    url: str | None = None  # For HTTP/SSE transport


class ToolAnnotations(BaseModel):
    """MCP tool annotations (hints about behavior)."""
    title: str | None = None
    read_only_hint: bool | None = None       # MCP default: false
    destructive_hint: bool | None = None     # MCP default: true
    idempotent_hint: bool | None = None      # MCP default: false
    open_world_hint: bool | None = None      # MCP default: true


class ToolInfo(BaseModel):
    """A single tool exposed by an MCP server."""
    name: str
    description: str | None = None
    input_schema: dict | None = None
    annotations: ToolAnnotations | None = None


class PermissionFinding(BaseModel):
    """A single permission inference for a tool."""
    category: PermissionCategory
    confidence: Confidence
    evidence: list[str]  # What triggered this finding (pattern matches, annotation values)
    tool_name: str


class RiskScore(BaseModel):
    """Multi-dimensional risk score for a server."""
    composite: float = Field(ge=0, le=10)
    file_access: float = Field(ge=0, le=10)
    network_access: float = Field(ge=0, le=10)
    shell_execution: float = Field(ge=0, le=10)
    destructive: float = Field(ge=0, le=10)
    exfiltration: float = Field(ge=0, le=10)


class ServerAudit(BaseModel):
    """Complete audit result for a single MCP server."""
    server: ServerConfig
    connection_status: str  # "connected", "failed", "timeout", "skipped"
    connection_error: str | None = None
    tools: list[ToolInfo] = Field(default_factory=list)
    permissions: list[PermissionFinding] = Field(default_factory=list)
    risk_score: RiskScore | None = None
    has_annotations: bool = False
    annotation_coverage: float = 0.0  # Percentage of tools with annotations


class AuditReport(BaseModel):
    """Top-level audit report containing all server audits."""
    scan_timestamp: datetime
    hostname: str
    os_platform: str
    servers_discovered: int
    servers_connected: int
    servers_failed: int
    total_tools: int
    high_risk_servers: int  # composite >= 7.0
    audits: list[ServerAudit]
    scan_duration_seconds: float
```

### Permission Inference Patterns

In `src/mcp_audit/rules/patterns.py`:

```python
from mcp_audit.models import PermissionCategory

# Patterns organized by signal strength.
# Matching logic: scan tool name, description, and param names/descriptions.
# Tool name matches weighted 3x. Description matches weighted 2x. Param matches weighted 1x.

PERMISSION_PATTERNS: dict[PermissionCategory, dict[str, list[str]]] = {
    PermissionCategory.FILE_READ: {
        "strong": [
            "read_file", "get_file", "list_directory", "list_files",
            "search_files", "read_resource", "file_content", "get_directory",
            "tree", "find_files", "stat_file", "file_info",
        ],
        "moderate": [
            "path", "filepath", "filename", "directory", "folder",
            "glob", "file_pattern", "working_directory",
        ],
        "weak": ["open", "load", "import", "source", "inspect"],
    },
    PermissionCategory.FILE_WRITE: {
        "strong": [
            "write_file", "create_file", "save_file", "edit_file",
            "modify_file", "append_file", "replace_in_file", "patch_file",
            "move_file", "copy_file", "rename_file", "mkdir",
        ],
        "moderate": [
            "write", "save", "output_path", "destination",
            "overwrite", "upsert",
        ],
        "weak": ["create", "update", "set", "put"],
    },
    PermissionCategory.NETWORK: {
        "strong": [
            "fetch", "http_request", "curl", "wget", "api_call",
            "web_search", "send_request", "download", "web_fetch",
            "scrape", "crawl",
        ],
        "moderate": [
            "url", "endpoint", "host", "port", "webhook",
            "api_key", "base_url", "headers",
        ],
        "weak": ["remote", "external", "online", "cloud"],
    },
    PermissionCategory.SHELL_EXEC: {
        "strong": [
            "execute_command", "run_command", "shell", "bash",
            "terminal", "exec", "subprocess", "system_command",
            "run_script", "eval", "spawn_process",
        ],
        "moderate": ["command", "script", "process", "spawn", "cmd"],
        "weak": ["run", "execute"],
    },
    PermissionCategory.DESTRUCTIVE: {
        "strong": [
            "delete_file", "remove_file", "drop_table", "destroy",
            "purge", "truncate", "wipe", "uninstall", "rm",
            "rmdir", "drop_database",
        ],
        "moderate": ["delete", "remove", "drop", "clear", "reset"],
        "weak": ["clean", "flush", "prune"],
    },
    PermissionCategory.EXFILTRATION: {
        "strong": [
            "send_email", "post_message", "upload", "publish",
            "push", "send_notification", "webhook", "send_slack",
            "post_to", "tweet", "broadcast",
        ],
        "moderate": ["send", "post", "share", "export", "transmit"],
        "weak": ["output", "emit", "forward", "relay"],
    },
}
```

### Risk Scoring Weights

In `src/mcp_audit/rules/weights.py`:

```python
from mcp_audit.models import PermissionCategory, Confidence

# Higher weight = more dangerous capability
CATEGORY_WEIGHTS: dict[PermissionCategory, float] = {
    PermissionCategory.SHELL_EXEC: 3.0,      # Arbitrary code execution
    PermissionCategory.EXFILTRATION: 2.5,     # Data leaves the machine
    PermissionCategory.FILE_WRITE: 2.0,       # Can modify system state
    PermissionCategory.DESTRUCTIVE: 2.0,      # Can destroy data
    PermissionCategory.NETWORK: 1.5,          # External communication
    PermissionCategory.FILE_READ: 1.0,        # Least risky, still notable
}

# Confidence affects how much a finding contributes to the score
CONFIDENCE_MULTIPLIERS: dict[Confidence, float] = {
    Confidence.DECLARED: 1.0,    # From annotations — most reliable
    Confidence.MANUAL: 1.0,      # User explicitly classified
    Confidence.HIGH: 0.9,        # Multiple strong keyword matches
    Confidence.MEDIUM: 0.6,      # Single strong or multiple moderate
    Confidence.LOW: 0.3,         # Weak/inferred
}

# Composite score formula:
# For each permission category found on a server:
#   category_score = CATEGORY_WEIGHTS[category] * max(CONFIDENCE_MULTIPLIERS[finding.confidence] for findings in category)
# composite = min(10, sum(category_scores))
```

### CLI Interface

```
mcp-audit discover                    # List all discovered MCP configs
mcp-audit discover --client claude_code  # Filter by client
mcp-audit scan                        # Full audit: discover + connect + analyze + report
mcp-audit scan --json report.json     # Output JSON report
mcp-audit scan --skip-connect         # Config-only analysis (no server probing)
mcp-audit scan --clients claude_desktop,claude_code  # Filter clients
mcp-audit scan --timeout 15           # Custom connection timeout (default: 10s)
mcp-audit scan --config /path/to/custom/config.json  # Scan specific config file
mcp-audit scan --verbose              # Show per-tool permission details
```

### Dependencies

```bash
# Create project
uv init mcp-audit --python 3.11
cd mcp-audit

# Production dependencies
uv add click rich anyio json5 mcp pydantic pyyaml

# Dev dependencies
uv add --dev pytest pytest-anyio ruff mypy
```

## Scope Boundaries

**In scope:**
- Config discovery for Claude Desktop, Claude Code, Cursor, VS Code, Windsurf
- Stdio and StreamableHTTP transport for server connections
- Tool enumeration via MCP `tools/list`
- Permission inference from tool annotations + heuristic pattern matching
- Multi-dimensional risk scoring
- Rich terminal table output and JSON report output
- User override config (~/.mcp-audit.yaml) for manual tool classifications
- --skip-connect mode for config-only analysis
- macOS and Linux support (primary)

**Out of scope:**
- Windows support (can be added later but not MVP)
- LLM-based analysis of tool descriptions
- Runtime monitoring of MCP tool calls
- Modifying or fixing MCP configs
- Tool pinning or hash verification (Invariant mcp-scan does this)
- Prompt injection detection (Cisco/Snyk scanners do this)
- Source code analysis of MCP server implementations
- SARIF output (Phase 2 optional stretch goal)

**Deferred:**
- `--watch` mode for continuous monitoring (Phase 2)
- SARIF output for GitHub Security tab (Phase 2)
- Windows path support (post-MVP)
- Remote MCP server scanning via HTTP (Phase 2)
- Web-based HTML report (post-MVP)

## Security & Credentials

- **This tool stores NO credentials.** It reads existing config files but never stores, logs, or transmits secret values.
- **Env var key names only:** When reporting env vars from configs (e.g., `GITHUB_TOKEN`), report only the key name. The value is NEVER read, logged, or included in reports.
- **Data boundaries:** Zero data leaves the machine. No telemetry, no analytics, no API calls, no cloud services.
- **Config file access:** Read-only. The tool never writes to any MCP config file.
- **Spawned server processes:** Servers spawned for tool enumeration are terminated after the scan. Use anyio cancellation scopes and process cleanup to prevent orphaned processes. Kill any server process that exceeds the timeout.
- **Report files:** JSON reports are written to the user-specified path only. They contain no credential values.

---

## Phase 0: Foundation — Config Discovery & Parsing (Days 1–2)

**Objective:** Discover and parse MCP server configs from all supported clients. No server connections yet. CLI skeleton with `discover` subcommand.

**Tasks:**
1. Scaffold project with `uv init`, configure `pyproject.toml` with `[project.scripts]` entry point `mcp-audit = "mcp_audit.cli:main"` — **Acceptance:** `uv run mcp-audit --help` prints help text with `discover` and `scan` subcommands
2. Implement all Pydantic models in `models.py` — **Acceptance:** `mypy src/mcp_audit/models.py` passes with zero errors; models serialize/deserialize correctly
3. Implement `ConfigDiscoverer` ABC in `discovery/base.py` with abstract methods `config_paths() -> list[Path]` and `parse(path: Path) -> list[ServerConfig]` — **Acceptance:** ABC defined, cannot be instantiated directly
4. Implement Claude Desktop discoverer — **Acceptance:** Parses fixture `claude_desktop_config.json`, extracts all `mcpServers` entries with correct command, args, env key names
5. Implement Claude Code discoverer — **Acceptance:** Parses fixture `claude_code_config.json` from `~/.claude.json`, correctly handles the nested structure with `mcpServers` key
6. Implement Cursor discoverer — **Acceptance:** Parses `~/.cursor/mcp.json` (JSONC format with comments/trailing commas) using `json5`
7. Implement VS Code discoverer — **Acceptance:** Discovers `.vscode/mcp.json` in CWD and user-level settings
8. Implement Windsurf discoverer — **Acceptance:** Parses `~/.codeium/windsurf/mcp_config.json`
9. Implement `discover_all_configs()` aggregator that runs all discoverers and deduplicates servers — **Acceptance:** Returns unified list of `ServerConfig` across all clients
10. Implement `discover` CLI subcommand with `--client` filter and `--verbose` flag — **Acceptance:** `uv run mcp-audit discover` prints a Rich table listing all found servers with name, client, transport, command, and config path
11. Write unit tests for all discoverers with fixture config files — **Acceptance:** `uv run pytest tests/test_discovery.py -v` passes all tests

**Verification checklist:**
- [ ] `uv run mcp-audit discover` → Rich table listing servers from your Claude Desktop and Claude Code configs
- [ ] `uv run mcp-audit discover --client claude_code` → filtered output
- [ ] `uv run mcp-audit discover --verbose` → shows args and env key names
- [ ] `uv run pytest tests/test_discovery.py -v` → all green
- [ ] `uv run mypy src/` → zero errors
- [ ] `uv run ruff check src/` → zero violations

**Risks:**
- Config file not found for a client: Mitigation — skip silently with debug log, only show clients with configs. Fallback — `--config` flag for manual path.
- JSONC parsing edge cases: Mitigation — use `json5` library which handles comments and trailing commas. Test with real Cursor config.

---

## Phase 1: Server Probing + Permission Analysis + Report (Days 3–5)

**Objective:** Connect to discovered servers, enumerate tools, analyze permissions, score risk, produce terminal + JSON report.

**Tasks:**
1. Implement `ServerConnector` class in `connector.py`:
   - `async connect_stdio(config: ServerConfig, timeout: float) -> list[ToolInfo]` — spawn process, JSON-RPC handshake, `tools/list`
   - `async connect_http(config: ServerConfig, timeout: float) -> list[ToolInfo]` — HTTP POST to server URL
   - Handle: timeout, connection refused, invalid response, missing tools capability
   - Extract tool annotations from response into `ToolAnnotations` model
   — **Acceptance:** Successfully connects to ≥3 real servers on your machine; returns `ToolInfo` list with annotations when available

2. Implement `PermissionAnalyzer` in `analyzer.py`:
   - `analyze_tool(tool: ToolInfo) -> list[PermissionFinding]`
   - For each tool: check annotations first (declared confidence), then apply keyword patterns against tool name (3x weight), description (2x weight), param names (1x weight)
   - Confidence assignment: ≥2 strong matches = HIGH, 1 strong or ≥2 moderate = MEDIUM, otherwise LOW
   - Handle annotation defaults per MCP spec: if `read_only_hint` is None, treat as `false` (not read-only); if `destructive_hint` is None, treat as `true` (assume destructive)
   — **Acceptance:** filesystem server → FILE_READ + FILE_WRITE (HIGH); github server → NETWORK + FILE_READ (HIGH); sequential-thinking → no permissions (risk 0)

3. Implement `RiskScorer` in `scorer.py`:
   - `score_server(permissions: list[PermissionFinding]) -> RiskScore`
   - Per-dimension score: for each category, take the highest-confidence finding, multiply by category weight
   - Composite: sum of dimension scores, capped at 10.0
   - Per-dimension scores also capped at 10.0
   — **Acceptance:** Server with shell execution tools → composite ≥ 7.0; read-only server → composite ≤ 3.0; server with no tools → composite 0.0

4. Implement `ReportGenerator` in `report.py`:
   - `render_terminal(report: AuditReport)` — Rich table with columns: Server Name, Client, Tools, Risk Score (color-coded: green ≤3, yellow 3-6, red >6), Top Permissions
   - `render_json(report: AuditReport, path: Path)` — Full AuditReport serialized to JSON
   - Summary banner at top: "Scanned N servers across M clients. X high-risk. Y failed to connect."
   - Verbose mode: expand each server to show per-tool permission breakdown
   — **Acceptance:** Terminal output renders cleanly with colors; JSON output validates against Pydantic model

5. Implement `scan` CLI subcommand:
   - Orchestrates: discover → connect → analyze → score → report
   - Flags: `--json PATH`, `--skip-connect`, `--clients`, `--timeout`, `--verbose`, `--config`
   - Progress bar during server connections (Rich Progress)
   - Concurrent server connections using `anyio.create_task_group()`
   — **Acceptance:** `uv run mcp-audit scan` produces full colored terminal report

6. Handle annotation-based inference:
   - If tool has `readOnlyHint: true` → suppress FILE_WRITE, DESTRUCTIVE findings for that tool
   - If tool has `destructiveHint: false` → suppress DESTRUCTIVE findings
   - If tool has `openWorldHint: false` → suppress NETWORK, EXFILTRATION findings
   - Report `annotation_coverage` per server: % of tools that have any annotations
   — **Acceptance:** Annotated tools show DECLARED confidence; annotation coverage calculated correctly

7. Implement `--skip-connect` mode:
   - Skip server connections entirely
   - Infer what you can from config: command name (e.g., `npx @modelcontextprotocol/server-filesystem` → FILE_READ + FILE_WRITE), env var key names (e.g., `GITHUB_PERSONAL_ACCESS_TOKEN` → NETWORK)
   - Known command patterns for popular servers
   — **Acceptance:** Runs in <1 second, produces partial risk assessment

8. Write tests:
   - Mock MCP server fixture (responds to initialize + tools/list over stdio)
   - Unit tests for PermissionAnalyzer with various tool configurations
   - Unit tests for RiskScorer with known inputs and expected outputs
   - Integration test: fixture configs → scan → validate JSON report structure
   — **Acceptance:** `uv run pytest tests/ -v` all green

**Verification checklist:**
- [ ] `uv run mcp-audit scan` → full audit with risk scores, runs in <30s for your servers
- [ ] `uv run mcp-audit scan --json report.json` → valid JSON, can be parsed back into AuditReport
- [ ] `uv run mcp-audit scan --skip-connect` → fast output with config-inferred permissions
- [ ] `uv run mcp-audit scan --verbose` → per-tool permission breakdown visible
- [ ] Risk scores pass manual validation: filesystem=low, github=medium, bash-tool=high
- [ ] `uv run pytest tests/ -v` → all green
- [ ] `uv run mypy src/` → zero errors

**Risks:**
- Server hangs on connection: Mitigation — anyio `move_on_after(timeout)` per server. Report as "timeout" and continue.
- `mcp` SDK breaking changes: Mitigation — pin exact version in pyproject.toml. Fallback — raw JSON-RPC over subprocess stdin/stdout.
- Process orphaning: Mitigation — use `anyio` process management with cleanup in finally blocks. Kill signal on timeout.

---

## Phase 2: Polish & Distribution (Days 6–7)

**Objective:** README, packaging, CI, and quality-of-life features.

**Tasks:**
1. Write README.md:
   - Badges: PyPI version, Python version, CI status, license
   - One-line install: `pipx install mcp-audit` or `uvx mcp-audit`
   - Quick start: `mcp-audit scan`
   - Full usage with all flags
   - Sample terminal output (screenshot or Rich-exported text)
   - Sample JSON report snippet
   - Architecture overview (text diagram from this roadmap)
   - Comparison with existing tools (what mcp-audit does that others don't)
   - Contributing guide
   — **Acceptance:** README renders correctly on GitHub; clear enough that a stranger can install and run in <2 minutes

2. Configure pyproject.toml for PyPI:
   - `[build-system]` with hatchling or setuptools
   - `[project]` metadata: name, version, description, authors, license, classifiers, python_requires
   - `[project.scripts]` entry point
   - `[project.urls]` homepage, repository, issues
   — **Acceptance:** `uv build` produces wheel; `pipx install ./dist/mcp_audit-*.whl` installs cleanly; `mcp-audit --help` works

3. Add user override config (`~/.mcp-audit.yaml`):
   ```yaml
   overrides:
     # Override permission classification for specific tools
     - server: "my-custom-server"
       tool: "safe_read_tool"
       permissions:
         file_read: true
         file_write: false
       notes: "Manually verified — read-only despite ambiguous description"
   ```
   — **Acceptance:** Override appears in report with MANUAL confidence

4. Add GitHub Actions CI (`.github/workflows/ci.yml`):
   - Matrix: Python 3.11, 3.12, 3.13
   - Steps: checkout, uv install, ruff check, mypy, pytest
   — **Acceptance:** CI passes on push to main

5. (Stretch) Add `--format sarif` output:
   - Map risk findings to SARIF format
   — **Acceptance:** SARIF file uploads to GitHub Security tab

6. (Stretch) Add `--watch` mode:
   - Use `watchfiles` to monitor config file changes
   - Re-run scan on change
   — **Acceptance:** Detects config edit and re-scans within 2 seconds

**Verification checklist:**
- [ ] `pipx install mcp-audit` → installs and `mcp-audit scan` works
- [ ] README renders on GitHub with correct formatting
- [ ] GitHub Actions CI passes
- [ ] Override config modifies report output correctly
- [ ] `uv run ruff check src/ tests/` → clean
- [ ] `uv run mypy src/` → clean

**Risks:**
- PyPI name collision: Mitigation — check `pip index versions mcp-audit` before publishing. Fallback — `mcp-permission-auditor`.
- CI flakiness from server connection tests: Mitigation — mock servers in CI, real server tests only run locally.
