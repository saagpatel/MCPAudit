"""Rank roots lexically, without resolving symlinks.

Absolute roots without '..' or '~' are normalized. Equal or nested roots
overlap; all other valid pairs are disjoint. Missing roots on one side mean
possible overlap, while missing roots on both or invalid roots mean unknown.
"""

import posixpath
from dataclasses import dataclass
from typing import Literal

from redteam.chains.pairs import CandidateChain

Overlap = Literal["confirmed", "possible", "unknown", "disjoint"]


@dataclass(frozen=True)
class RankedChain:
    chain: CandidateChain
    score: int
    overlap: Overlap
    explanation: tuple[str, ...]


@dataclass(frozen=True)
class DroppedChain:
    chain: CandidateChain
    reason: str


def scope_overlap(writer: tuple[str, ...], executor: tuple[str, ...]) -> Overlap:
    paths = (*writer, *executor)
    if any(not p.startswith("/") or ".." in p.split("/") or "~" in p for p in paths):
        return "unknown"
    if not writer or not executor:
        return "possible" if writer or executor else "unknown"
    for a in map(posixpath.normpath, writer):
        for b in map(posixpath.normpath, executor):
            if a == b or a.startswith(b.rstrip("/") + "/") or b.startswith(a.rstrip("/") + "/"):
                return "confirmed"
    return "disjoint"


def rank_chains(chains: list[CandidateChain]) -> tuple[list[RankedChain], list[DroppedChain]]:
    ranked: list[RankedChain] = []
    dropped: list[DroppedChain] = []
    for chain in chains:
        overlap = scope_overlap(chain.writer.roots, chain.executor.roots)
        if overlap == "disjoint":
            dropped.append(DroppedChain(chain, "lexically disjoint configured roots (symlinks not resolved)"))
            continue
        automaticity = {"automatic": 30, "user_action": 20, "unknown": 0}[chain.template.automaticity]
        scope = {"confirmed": 20, "possible": 10, "unknown": 0, "disjoint": 0}[overlap]
        conditions = sum(
            label.confidence == "conditional" for label in (chain.writer_label, chain.executor_label)
        )
        setup = len(chain.preconditions) + conditions
        score = automaticity + scope - len(chain.steps) - setup
        detail = {
            "confirmed": "equal or nested configured roots (lexical; symlinks not resolved)",
            "possible": "one server has no configured roots",
            "unknown": "missing or invalid configured roots",
        }[overlap]
        ranked.append(
            RankedChain(
                chain,
                score,
                overlap,
                (
                    f"automaticity {chain.template.automaticity}: +{automaticity}",
                    f"scope {overlap}: +{scope}; {detail}",
                    f"steps: -{len(chain.steps)}",
                    f"preconditions and conditional labels: -{setup}",
                ),
            )
        )
    ranked.sort(
        key=lambda r: (-r.score, r.chain.template.name, tuple((s.server, s.tool) for s in r.chain.steps))
    )
    dropped.sort(key=lambda d: (d.chain.template.name, tuple((s.server, s.tool) for s in d.chain.steps)))
    return ranked, dropped
