from pathlib import Path

from redteam.catalog import load_catalog
from redteam.chains.labeler import label_server
from redteam.chains.pairs import ConfiguredServer, load_config, pair_servers
from redteam.chains.rank import rank_chains
from redteam.chains.templates import TEMPLATES
from redteam.surface import ServerSurface, SurfaceTool

FIXTURES = Path("redteam/fixtures/servers/configs")


def test_labels_and_pairs() -> None:
    servers = load_config(FIXTURES / "git-plus-filesystem.json")
    fs = next(s for s in servers if s.name == "filesystem")
    git = next(s for s in servers if s.name == "git")
    assert fs.surface is not None and git.surface is not None
    labels = label_server(fs.surface)
    assert any(x.tool == "write_file" and x.tag == "writes_file" for x in labels)
    assert any(x.tool == "write_file" and x.tag == "writes_git_config" and x.condition for x in labels)
    assert any(
        x.tool == "git_add" and x.tag == "triggers_git_filter" and x.capability == "execute" and x.condition
        for x in label_server(git.surface)
    )
    chains = pair_servers(servers)
    assert any(c.template.name == "git-clean-filter" and c.steps[0].tool == "write_file" for c in chains)
    assert all(c.writer.name != c.executor.name for c in chains)
    assert next(s for s in servers if s.name == "harmless").tool_surface == "UNKNOWN"


def test_ranking_and_registered_extension() -> None:
    servers = load_config(FIXTURES / "mixed.json", FIXTURES / "mixed-surfaces.json")
    chains = pair_servers(servers)
    ranked, dropped = rank_chains(chains)
    assert ranked[0].chain.template.name == "git-clean-filter"
    assert ranked[0].overlap == "confirmed"
    assert any(c.chain.template.name == "git-hook" for c in ranked)
    assert {t.name for t in TEMPLATES} == {
        "git-clean-filter",
        "git-hook",
        "write-then-run",
        "write-then-build",
    }
    assert any(
        chain.template.name == "write-then-build"
        for chain in pair_servers(
            [
                ConfiguredServer(
                    "filesystem",
                    ServerSurface(
                        server_name="filesystem",
                        source="fixture",
                        tools=[SurfaceTool(name="write_file")],
                    ),
                    ("/synthetic/project",),
                ),
                ConfiguredServer(
                    "xcodebuildmcp",
                    ServerSurface(
                        server_name="xcodebuildmcp",
                        source="catalog",
                        tools=[SurfaceTool(name="build_project")],
                    ),
                    ("/synthetic/project",),
                ),
            ]
        )
    )
    assert any(
        c.chain.writer.name == "isolated-filesystem"
        and c.reason == "lexically disjoint configured roots (symlinks not resolved)"
        for c in dropped
    )
    assert all(c.chain not in [r.chain for r in ranked] for c in dropped)


def test_write_then_run_ranks_below_clean_filter() -> None:
    servers = load_config(FIXTURES / "git-plus-filesystem.json")
    shell = ServerSurface(
        server_name="shell",
        source="fixture",
        tools=[
            SurfaceTool(
                name="bash",
                input_schema={
                    "type": "object",
                    "properties": {"command": {"type": "string"}},
                    "required": ["command"],
                },
            )
        ],
    )
    servers.append(ConfiguredServer("shell", shell, ("/synthetic/repo",)))
    ranked, _ = rank_chains(pair_servers(servers))
    clean = next(c for c in ranked if c.chain.template.name == "git-clean-filter")
    write_run = next(c for c in ranked if c.chain.template.name == "write-then-run")
    assert [(s.server, s.tool) for s in write_run.chain.steps] == [
        ("filesystem", "edit_file"),
        ("shell", "bash"),
    ]
    assert {member.writer_label.tool for member in write_run.alternatives} == {
        "edit_file",
        "move_file",
        "write_file",
    }
    assert write_run.overlap == "confirmed"
    assert clean.score > write_run.score
    assert ranked.index(clean) < ranked.index(write_run)


def test_template_extension_and_unknown_label() -> None:
    from redteam.chains.templates import Template

    servers = load_config(FIXTURES / "git-plus-filesystem.json")
    extension = Template(
        name="new-hook-template",
        writer_tag="writes_file",
        executor_tag="triggers_hook",
        artifact="synthetic artifact",
        trigger="synthetic trigger",
        preconditions=("repository exists",),
        automaticity="unknown",
    )
    assert any(chain.template == extension for chain in pair_servers(servers, (*TEMPLATES, extension)))
    surface = ServerSurface(server_name="unknown", source="fixture", tools=[SurfaceTool(name="mystery")])
    assert label_server(surface)[0].tag == "unknown"
    surface.tools[0].name = "git_commit"
    assert label_server(surface)[0].tag == "triggers_hook"


def test_explicit_surfaces_and_unknown_scope() -> None:
    servers = load_config(FIXTURES / "mixed.json", FIXTURES / "mixed-surfaces.json")
    fetch = next(server for server in servers if server.name == "fetch")
    assert fetch.surface is not None
    assert label_server(fetch.surface)[0].tag == "fetches_url"
    hook = next(server for server in servers if server.name == "hook-only")
    assert hook.surface is not None
    assert "triggers_hook" in {label.tag for label in label_server(hook.surface)}


def test_directory_only_server_does_not_form_file_writing_chains() -> None:
    directory = ServerSurface(
        server_name="directory",
        source="fixture",
        tools=[
            SurfaceTool(name="create_directory", input_schema={"properties": {"path": {"type": "string"}}}),
            SurfaceTool(name="create_dir", input_schema={"properties": {"path": {"type": "string"}}}),
        ],
    )
    git = ServerSurface(server_name="git", source="fixture", tools=[SurfaceTool(name="git_add")])
    assert pair_servers([ConfiguredServer("directory", directory), ConfiguredServer("git", git)]) == []


def test_git_log_and_other_servers_git_add_do_not_form_a_chain() -> None:
    git = load_catalog()["pypi:mcp-server-git"]
    servers = [
        ConfiguredServer(
            name,
            git.model_copy(update={"tools": [tool for tool in git.tools if tool.name == tool_name]}),
        )
        for name, tool_name in (("reader", "git_log"), ("indexer", "git_add"))
    ]
    assert pair_servers(servers) == []


def test_two_catalog_git_servers_do_not_supply_a_file_writer() -> None:
    git = load_catalog()["pypi:mcp-server-git"]
    servers = [ConfiguredServer("git-a", git), ConfiguredServer("git-b", git)]
    assert pair_servers(servers) == []


def test_chain_roles_are_revalidated_against_current_surface() -> None:
    from dataclasses import replace

    servers = load_config(FIXTURES / "git-plus-filesystem.json")
    chain = next(chain for chain in pair_servers(servers) if chain.template.name == "git-clean-filter")
    assert chain.satisfies_template()
    assert not replace(chain, writer=replace(chain.writer, surface=None)).satisfies_template()
    assert not replace(chain, executor=replace(chain.executor, surface=None)).satisfies_template()
    assert not replace(chain, writer_label=replace(chain.writer_label, tool="read_file")).satisfies_template()
    assert not replace(
        chain, executor_label=replace(chain.executor_label, tool="git_log")
    ).satisfies_template()
    assert not replace(chain, template=replace(chain.template, writer_tag="reads_file")).satisfies_template()
    assert chain.writer.surface is not None
    chain.writer.surface.tools.clear()
    assert not chain.satisfies_template()
