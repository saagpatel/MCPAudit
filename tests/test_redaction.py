"""Tests for centralized output redaction."""

from time import perf_counter

import pytest

from mcp_audit.redaction import redact_data, redact_identifiers, redact_text


def test_redacts_secret_assignments() -> None:
    text = "failed with token=abc123 and api_key: sk-test"
    redacted = redact_text(text)
    assert "abc123" not in redacted
    assert "sk-test" not in redacted
    assert "token=<redacted>" in redacted


def test_redacts_bearer_tokens() -> None:
    redacted = redact_text("Authorization: Bearer abc.def.ghi")
    assert redacted == "Authorization: Bearer <redacted>"


def test_redacts_basic_auth_and_preserves_scheme() -> None:
    redacted = redact_text("Authorization: Basic YWJjOnNlY3JldA==")
    assert redacted == "Authorization: Basic <redacted>"
    assert redact_text(redacted) == redacted


def test_redacts_url_userinfo() -> None:
    redacted = redact_text("https://user:password@example.com/mcp")
    assert redacted == "https://<redacted>@example.com/mcp"


def test_redacts_nested_data() -> None:
    data = {"tools": [{"description": "password=super-secret"}]}
    redacted = redact_data(data)
    assert redacted["tools"][0]["description"] == "password=<redacted>"


@pytest.mark.parametrize(
    "name",
    [
        "FOO_TOKEN",
        "token",
        "api-key",
        "apikey",
        "client_secret",
        "PASSWORD",
        "passwd",
        "pwd",
        "credential",
        "auth",
        "AUTH",
        "x_auth_token",
        "sig",
        "signature",
        "private_key",
        "access-key",
        "session",
        "github-token",
        "authorization",
        "authentication",
        "sessionid",
        "USERSESSION",
        "session_id",
        "session-name-token",
    ],
)
def test_secret_names_in_assignments_and_flags(name: str) -> None:
    assert redact_text(f"{name}=fixture-secret") == f"{name}=<redacted>"
    assert redact_text(f"--{name} fixture-secret") == f"--{name} <redacted>"
    assert redact_data([f"--{name}", "fixture-secret"]) == [f"--{name}", "<redacted>"]


@pytest.mark.parametrize(
    "secret",
    [
        *[prefix + "a1B2" * 5 for prefix in ("ghp_", "gho_", "ghu_", "ghs_", "ghr_")],
        "github_pat_" + "a_1B" * 5,
        "sk-" + "a1B_" * 4,
        "sk-proj-" + "a1B_" * 4,
        "sk-ant-" + "a1B_" * 4,
        *[prefix + "a1B2-" * 2 for prefix in ("xoxa-", "xoxb-", "xoxp-", "xoxo-", "xoxs-", "xoxr-")],
        "AKIAABCDEFGHIJKLMNOP",
        "ASIAABCDEFGHIJKLMNOP",
        "eyJabcdefgh.abcdefgh.abcdefgh",
        "glpat-" + "a1B_" * 5,
        "npm_" + "a1B2" * 9,
    ],
)
def test_bare_secret_shapes_anywhere(secret: str) -> None:
    assert redact_text(f"before {secret} after") == "before <redacted> after"


def test_jwt_is_redacted_before_overlapping_secret_shapes() -> None:
    assert redact_text("eyJabcdefgh.sk-abcdefghijklmnop.abcdefgh") == "<redacted>"


@pytest.mark.parametrize(
    "url, expected",
    [
        (
            "https://example.test/mcp?a=one&mode=x&sig=two",
            "https://example.test/mcp?a=<redacted>&mode=<redacted>&sig=<redacted>",
        ),
        (
            "http://user:pass@example.test/?x=a=b#fragment-secret",
            "http://<redacted>@example.test/?x=<redacted>#<redacted>",
        ),
        ("https://example.test/mcp#access_token=fragment-secret", "https://example.test/mcp#<redacted>"),
        ("https://example.test/mcp?x=&flag&x=two", "https://example.test/mcp?x=<redacted>&flag&x=<redacted>"),
        ("https://example.test?email=user@example.test", "https://example.test?email=<redacted>"),
        ("https://user@example.test?mode=x", "https://<redacted>@example.test?mode=<redacted>"),
    ],
)
def test_url_values_and_fragments(url: str, expected: str) -> None:
    assert redact_text(url) == expected
    assert redact_text(expected) == expected


def test_benign_argument_contract() -> None:
    # Plural tokens denote a count; session-name is a display label. auth must
    # be a whole name component rather than the prefix in author/authority/oauth.
    args = [
        "--port",
        "8080",
        "--model",
        "gpt-4o",
        "--author=jane",
        "--host",
        "127.0.0.1",
        "--root",
        "/data",
        "--log-level",
        "debug",
        "--read-only",
        "--authority",
        "https://login.example.test",
        "--max-tokens",
        "4096",
        "--session-name",
        "demo",
        "--session_name",
        "demo",
        "--client-session_name",
        "demo",
        "--tokenizer",
        "gpt-4o",
        "@modelcontextprotocol/server-filesystem@2026.6.1",
        "/data/file.txt",
        "https://example.test/mcp",
        "--timeout",
        "30",
        "--verbose",
        "--cache-dir=/cache",
        "authority=https://login.example.test",
        "oauth_callback_port=3000",
    ]
    assert len(args) >= 20
    assert redact_data(args) == args
    assert redact_text(" ".join(args)) == " ".join(args)


def test_flag_value_and_quoted_assignments_are_idempotent() -> None:
    text = "token=\"two word secret\" --password 'another secret' --api-key=sk-test"
    expected = "token=<redacted> --password <redacted> --api-key=<redacted>"
    assert redact_text(text) == expected
    assert redact_text(expected) == expected
    args = ["--token", "fixture-secret", "--port", "8080", "--api-key=fixture-secret"]
    assert redact_data(redact_data(args)) == redact_data(args)


@pytest.mark.parametrize(
    "text, expected",
    [
        ('{"password":"hunter2-SECRET"}', '{"password":<redacted>}'),
        ('{"password": "hunter2-SECRET"}', '{"password": <redacted>}'),
        ("{'password': 'hunter2'}", "{'password': <redacted>}"),
        ('{"password":"first\\"second"}', '{"password":<redacted>}'),
    ],
)
def test_quoted_secret_keys_in_text(text: str, expected: str) -> None:
    assert redact_text(text) == expected
    assert redact_data(["--config", text]) == ["--config", expected]
    assert redact_text(expected) == expected


def test_redaction_marker_prefix_does_not_preserve_secret_suffix() -> None:
    assert redact_text("password=<redacted>fixture-secret") == "password=<redacted>"


def test_secret_dict_values_and_schema_literals_keep_structure() -> None:
    data = {
        "password": "hunter2-SECRET",
        "token": 42,
        "session": False,
        "secret": {"port": 8080},
        "properties": {
            "password": {
                "type": "string",
                "default": "hunter2-SECRET",
                "examples": ["hunter2-SECRET", {"nested": "another-secret"}, 42, None],
                "const": "hunter2-SECRET",
            },
            "session_id": {"default": "session-secret"},
            "port": {"type": "integer", "default": 8080, "examples": [9000]},
            "tokenizer": {"default": "gpt-4o"},
            "session_name": {"default": "demo"},
        },
    }
    properties = data["properties"]
    assert isinstance(properties, dict)
    expected = {
        **data,
        "password": "<redacted>",
        "properties": {
            **properties,
            "password": {
                "type": "string",
                "default": "<redacted>",
                "examples": ["<redacted>", {"nested": "<redacted>"}, 42, None],
                "const": "<redacted>",
            },
            "session_id": {"default": "<redacted>"},
        },
    }
    assert redact_data(data) == expected
    assert redact_data(expected) == expected
    assert data["password"] == "hunter2-SECRET"


@pytest.mark.parametrize(
    "scheme", ["postgresql", "mysql", "redis", "mongodb+srv", "wss", "custom+v1", "token"]
)
def test_non_http_url_credentials_and_endpoint_context(scheme: str) -> None:
    url = f"{scheme}://app:fixture-secret@token.example.test:5432/app?mode=admin&x=two#fragment"
    expected = f"{scheme}://<redacted>@token.example.test:5432/app?mode=<redacted>&x=<redacted>#<redacted>"
    assert redact_text(url) == expected
    assert redact_text(expected) == expected
    assert redact_data([url]) == [expected]


@pytest.mark.parametrize("host", ["token", "secret", "auth", "session", "key"])
def test_url_host_port_and_path_survive_named_assignment_pass(host: str) -> None:
    url = f"https://{host}.example.test:8443/password=value"
    expected = f"https://{host}.example.test:8443/password=<redacted>"
    text = f"token=fixture-secret endpoint={url} password=another-secret"
    assert redact_text(url) == expected
    assert redact_text(text) == f"token=<redacted> endpoint={expected} password=<redacted>"


@pytest.mark.parametrize(
    "prefix, chunk",
    [
        ("", "a+.-"),  # long scheme-like text without ://
        ("postgresql://", "a"),  # long authority without userinfo separator
        ("mongodb+srv://user:", "a"),  # missing @ after a long userinfo candidate
        ("wss://host/mcp?x=", "a"),
        ("redis://host/#", "a"),
        ('{"password":"', "\\x"),  # unterminated escaped quoted value
        ("postgresql://app:", "p@"),  # many userinfo separators
        ("postgresql://app:", "p@ss?"),  # @ after the authority delimiter is not userinfo
        ("https://token.example.test:8443/", "password=x/"),
        ("--password https://example.test/", "a"),
        ("https://proxy.example/", "https://host/"),  # repeated nested scheme boundaries
        ("https://proxy.example/", "a+.-/"),  # long scheme-like path runs without ://
        ("https://proxy.example/", "1https://"),  # invalid nested schemes stay in the path
    ],
)
def test_megabyte_url_and_quoted_value_inputs_are_linear(prefix: str, chunk: str) -> None:
    def elapsed(size: int) -> float:
        text = prefix + (chunk * (size // len(chunk) + 1))[: size - len(prefix)]
        start = perf_counter()
        redact_text(text)
        return perf_counter() - start

    # Scaling, not wall clock: CI with coverage tracing is ~10x slower than local.
    # Linear input growth of 4x stays near 4x; quadratic would be near 16x.
    small, large = elapsed(262_144), elapsed(1_048_576)
    assert large < 10 * small + 0.05


@pytest.mark.parametrize("chunk", ["a", "token", "eyJabcdefgh", "token "])
def test_megabyte_adversarial_input_is_linear(chunk: str) -> None:
    text = (chunk * (1_048_576 // len(chunk) + 1))[:1_048_576]
    start = perf_counter()
    redact_text(text)
    assert perf_counter() - start < 2.0  # linear is far faster; quadratic takes minutes


def test_redact_identifiers_scrubs_hostname() -> None:
    data = {"hostname": "Ds-MacBook.local", "note": "scanned on Ds-MacBook.local"}
    out = redact_identifiers(data, hostname="Ds-MacBook.local")
    assert out["hostname"] == "<redacted-host>"
    assert out["note"] == "scanned on <redacted-host>"
    assert "Ds-MacBook.local" not in str(out)


def test_redact_identifiers_scrubs_unix_home_usernames() -> None:
    data = {
        "config_path": "/Users/alice/.claude.json",
        "command": "/home/bob/.local/bin/server",
    }
    out = redact_identifiers(data, hostname=None)
    assert out["config_path"] == "/Users/<redacted>/.claude.json"
    assert out["command"] == "/home/<redacted>/.local/bin/server"


def test_redact_identifiers_scrubs_windows_home_username() -> None:
    data = {"config_path": r"C:\Users\carol\AppData\mcp.json"}
    out = redact_identifiers(data, hostname=None)
    assert out["config_path"] == r"C:\Users\<redacted>\AppData\mcp.json"


def test_redact_identifiers_preserves_non_identifying_values() -> None:
    data = {
        "os_platform": "Darwin",
        "servers_discovered": 24,
        "finding_type": "package_runner_source_review",
    }
    out = redact_identifiers(data, hostname="some-host")
    assert out == data


def test_redact_identifiers_recurses_lists_and_dicts() -> None:
    data = {"audits": [{"server": {"config_path": "/Users/dave/x.json"}}]}
    out = redact_identifiers(data, hostname=None)
    assert out["audits"][0]["server"]["config_path"] == "/Users/<redacted>/x.json"


@pytest.mark.parametrize("name", ["synthetic/private", "synthetic~private/name", "~synthetic/private~"])
def test_redact_identifiers_decodes_pointer_tokens_once(name: str) -> None:
    escaped_name = name.replace("~", "~0").replace("/", "~1")
    pointer = f"/projects/~1Users~1synthetic~0person~1work~01/mcpServers/{escaped_name}"
    server = {"config_pointer": pointer}
    data = {"audits": [{"server": server}], "legacy": {"config_pointer": None}}
    out = redact_identifiers(data, name_aliases={name: "server-01"})
    assert out["audits"][0]["server"]["config_pointer"] == (
        "/projects/~1Users~1<redacted>~1work~01/mcpServers/server-01"
    )
    assert out["legacy"]["config_pointer"] is None
    assert server["config_pointer"] == pointer


@pytest.mark.parametrize(
    "map_pointer", ["/mcpServers", "/servers", "/mcp/servers", "/projects/work/mcpServers"]
)
@pytest.mark.parametrize("name", ["mcpServers", "projects", "mcp", "servers"])
def test_redact_identifiers_preserves_structural_pointer_tokens(map_pointer: str, name: str) -> None:
    out = redact_identifiers({"config_pointer": f"{map_pointer}/{name}"}, name_aliases={name: "server-01"})
    assert out["config_pointer"] == f"{map_pointer}/server-01"


def test_redact_identifiers_aliases_server_names() -> None:
    data = {
        "name": "personal-ops",
        "summary": "'personal-ops' appears 2 times",
        "command": "/Users/alice/.claude/bin/personal-ops-mcp",
    }
    out = redact_identifiers(data, hostname=None, name_aliases={"personal-ops": "server-01"})
    assert out["name"] == "server-01"
    assert out["summary"] == "'server-01' appears 2 times"
    assert out["command"] == "/Users/<redacted>/.claude/bin/server-01-mcp"
    assert "personal-ops" not in str(out)


def test_redact_identifiers_alias_prefers_longest_name() -> None:
    aliases = {"git": "server-01", "github-mcp": "server-02"}
    out = redact_identifiers({"a": "git", "b": "github-mcp"}, name_aliases=aliases)
    assert out["a"] == "server-01"
    assert out["b"] == "server-02"


def test_redact_identifiers_alias_respects_word_boundaries() -> None:
    # a server literally named "git" must not corrupt the unrelated word "github"
    out = redact_identifiers({"t": "see github docs"}, name_aliases={"git": "server-01"})
    assert out["t"] == "see github docs"
