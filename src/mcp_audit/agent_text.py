"""Bounded, field-addressed text visible to an MCP agent."""

from collections.abc import Iterator
from dataclasses import dataclass, field

from mcp_audit.models import PromptInfo, ToolInfo

MAX_TEXT_FIELDS = 256
MAX_FIELD_CHARS = 16_384
MAX_TOTAL_CHARS = 65_536
MAX_SCHEMA_NODES = 2_048
MAX_SCHEMA_DEPTH = 64
MAX_FIELD_PATH_CHARS = 2_048


@dataclass(frozen=True)
class TextField:
    path: str
    text: str


@dataclass
class AgentText:
    fields: list[TextField] = field(default_factory=list)
    incomplete: list[str] = field(default_factory=list)
    _chars: int = 0

    def warn(self, reason: str) -> None:
        if reason not in self.incomplete:
            self.incomplete.append(reason)

    def add(self, path: str, text: str) -> bool:
        """Return false when no more fields can be admitted."""
        if len(self.fields) >= MAX_TEXT_FIELDS:
            self.warn("field count budget exceeded")
            return False
        if self._chars >= MAX_TOTAL_CHARS:
            self.warn("total text budget exceeded")
            return False
        if len(path) > MAX_FIELD_PATH_CHARS:
            self.warn("field path budget exceeded")
            return True
        length = min(len(text), MAX_FIELD_CHARS, MAX_TOTAL_CHARS - self._chars)
        if length < len(text):
            self.warn("field text truncated")
        self.fields.append(TextField(path, text[:length]))
        self._chars += length
        return True


def _children(value: object) -> Iterator[tuple[object, object]]:
    if isinstance(value, dict):
        for key, child in value.items():
            yield key, child
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield str(index), child


def agent_visible_text(tool: ToolInfo) -> AgentText:
    """Extract tool fields and every schema string leaf, without resolving refs.

    Lazy child iterators bound wide schemas as well as deep ones. Paths are JSON
    Pointers into ToolInfo's JSON representation; top-level property names retain
    their existing keyword coverage, addressed by the property's pointer.
    """
    result = AgentText()
    result.add("/name", tool.name)
    result.add("/description", tool.description or "")
    if tool.annotations and tool.annotations.title is not None:
        result.add("/annotations/title", tool.annotations.title)
    if tool.input_schema is None:
        return result

    stack = [(_children(tool.input_schema), "/input_schema", frozenset({id(tool.input_schema)}))]
    nodes = 1
    while stack:
        children, prefix, ancestors = stack[-1]
        child = next(children, None)
        if child is None:
            stack.pop()
            continue
        if nodes >= MAX_SCHEMA_NODES:
            result.warn("schema node budget exceeded")
            break
        nodes += 1
        key, value = child
        if not isinstance(key, str):
            result.warn("non-string schema key skipped")
            continue
        if len(key) > MAX_FIELD_PATH_CHARS:
            result.warn("field path budget exceeded")
            continue
        path = f"{prefix}/{key.replace('~', '~0').replace('/', '~1')}"
        if len(path) > MAX_FIELD_PATH_CHARS:
            result.warn("field path budget exceeded")
            continue
        if prefix == "/input_schema/properties" and not result.add(path, key):
            break
        if isinstance(value, str):
            if not result.add(path, value):
                break
        elif isinstance(value, (dict, list)):
            if id(value) in ancestors:
                result.warn("cyclic schema branch skipped")
            elif len(stack) >= MAX_SCHEMA_DEPTH:
                result.warn("schema depth budget exceeded")
            else:
                stack.append((_children(value), path, ancestors | {id(value)}))
    return result


def prompt_visible_text(prompt: PromptInfo) -> AgentText:
    """Extract bounded prompt names, descriptions, and argument metadata."""
    result = AgentText()
    result.add("/name", prompt.name)
    result.add("/description", prompt.description or "")
    if not prompt.argument_details:
        for index, argument in enumerate(prompt.arguments):
            if not result.add(f"/arguments/{index}", argument):
                return result
    for index, argument_info in enumerate(prompt.argument_details):
        for key, text in (("name", argument_info.name), ("description", argument_info.description or "")):
            if not result.add(f"/argument_details/{index}/{key}", text):
                return result
    return result
