from dataclasses import replace
from pathlib import Path

from redteam.chains.pairs import load_config, pair_servers
from redteam.chains.rank import rank_chains, scope_overlap


def test_scope_overlap() -> None:
    assert scope_overlap(("/repo/",), ("/repo/sub",)) == "confirmed"
    assert scope_overlap(("/repo/./sub",), ("/repo",)) == "confirmed"
    assert scope_overlap(("/repo",), ("/repository",)) == "disjoint"
    assert scope_overlap(("/repo",), ()) == "possible"
    assert scope_overlap((), ()) == "unknown"
    assert scope_overlap(("/repo/../other",), ("/repo",)) == "unknown"
    assert scope_overlap(("/repo/~user",), ("/repo",)) == "unknown"
    assert scope_overlap(("relative",), ()) == "unknown"


def test_drop_disjoint_and_rank_mixed() -> None:
    fixtures = Path("redteam/fixtures/servers/configs")
    chains = pair_servers(load_config(fixtures / "mixed.json", fixtures / "mixed-surfaces.json"))
    ranked, dropped = rank_chains(chains)
    assert ranked[0].chain.template.name == "git-clean-filter"
    assert ranked[0].overlap == "confirmed"
    assert dropped
    assert all(
        item.reason == "lexically disjoint configured roots (symlinks not resolved)" for item in dropped
    )
    assert all("scope " in " ".join(item.explanation) for item in ranked)


def test_groups_tool_alternatives_by_server_pair_and_template() -> None:
    chains = pair_servers(load_config(Path("redteam/fixtures/servers/configs/git-plus-filesystem.json")))
    ranked, dropped = rank_chains(chains)
    assert not dropped
    assert [row.chain.template.name for row in ranked] == ["git-clean-filter", "git-hook"]
    for row, executor in zip(ranked, ("git_add", "git_commit"), strict=True):
        assert {(chain.writer_label.tool, chain.executor_label.tool) for chain in row.alternatives} == {
            ("create_directory", executor),
            ("write_file", executor),
            ("edit_file", executor),
            ("move_file", executor),
        }
    assert rank_chains(list(reversed(chains))) == (ranked, dropped)


def test_group_uses_best_members_score_and_explanation() -> None:
    chains = pair_servers(load_config(Path("redteam/fixtures/servers/configs/git-plus-filesystem.json")))
    members = [chain for chain in chains if chain.template.name == "git-clean-filter"]
    best = next(chain for chain in members if chain.writer_label.tool == "write_file")
    best = replace(best, writer_label=replace(best.writer_label, confidence="definite", condition=None))
    others = [chain for chain in members if chain.writer_label.tool != "write_file"]
    (best_row,), _ = rank_chains([best])
    (group,), _ = rank_chains([*others, best])
    assert group.chain == best
    assert group.score == best_row.score
    assert group.explanation == best_row.explanation
    assert group.alternatives == (best, *others)
