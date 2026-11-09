"""Declarative chain definitions and explicit registry."""

from dataclasses import dataclass
from typing import Literal

from redteam.chains.labeler import Tag


@dataclass(frozen=True)
class Template:
    name: str
    writer_tag: Tag
    executor_tag: Tag
    artifact: str
    trigger: str
    preconditions: tuple[str, ...]
    automaticity: Literal["automatic", "user_action", "unknown"]
    writer_actions: tuple[str, ...] = ()


from redteam.chains.templates.git_clean_filter import TEMPLATE as CLEAN_FILTER  # noqa: E402
from redteam.chains.templates.git_hook import TEMPLATE as HOOK  # noqa: E402
from redteam.chains.templates.write_then_run import TEMPLATE as WRITE_THEN_RUN  # noqa: E402

TEMPLATES = (CLEAN_FILTER, HOOK, WRITE_THEN_RUN)
