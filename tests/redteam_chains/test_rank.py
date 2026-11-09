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
