from pathlib import Path

from redteam.chains.labeler import label_server
from redteam.chains.pairs import load_config, pair_servers
from redteam.chains.rank import rank_chains
from redteam.chains.templates import TEMPLATES

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
    assert {t.name for t in TEMPLATES} == {"git-clean-filter", "git-hook"}
    assert any(c.chain.writer.name == "isolated-filesystem" and c.overlap == "unknown" for c in ranked)
    assert not dropped


def test_template_extension_and_unknown_label() -> None:
    from redteam.chains.templates import Template
    from redteam.surface import ServerSurface, SurfaceTool

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
    assert [label.tag for label in label_server(hook.surface)] == ["triggers_hook"]
