"""Rank plausible chains without inspecting the filesystem."""

from dataclasses import dataclass
from pathlib import PurePosixPath
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
    if not writer or not executor:
        return "unknown"
    paths = [PurePosixPath(p) for p in (*writer, *executor)]
    if any(not p.is_absolute() or ".." in p.parts for p in paths):
        return "unknown"
    for a in map(PurePosixPath, writer):
        for b in map(PurePosixPath, executor):
            if a == b:
                return "confirmed"
            if a in b.parents or b in a.parents:
                return "possible"
    return "unknown"


def rank_chains(chains: list[CandidateChain]) -> tuple[list[RankedChain], list[DroppedChain]]:
    ranked: list[RankedChain] = []
    dropped: list[DroppedChain] = []
    for chain in chains:
        overlap = scope_overlap(chain.writer.roots, chain.executor.roots)
        if overlap == "disjoint":
            dropped.append(DroppedChain(chain, "proven disjoint path scopes"))
            continue
        automaticity = {"automatic": 30, "user_action": 20, "unknown": 0}[chain.template.automaticity]
        scope = {"confirmed": 20, "possible": 10, "unknown": 0, "disjoint": 0}[overlap]
        conditions = sum(
            label.confidence == "conditional" for label in (chain.writer_label, chain.executor_label)
        )
        setup = len(chain.preconditions) + conditions
        score = automaticity + scope - len(chain.steps) - setup
        ranked.append(
            RankedChain(
                chain,
                score,
                overlap,
                (
                    f"automaticity {chain.template.automaticity}: +{automaticity}",
                    f"scope {overlap}: +{scope}",
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
