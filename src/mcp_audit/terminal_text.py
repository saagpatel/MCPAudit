"""Literal, control-free text for human-facing output."""

from __future__ import annotations

import logging
import re
import traceback

from rich.text import Text

from mcp_audit.normalize import render_invisibles

_CONTROLS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
_INTRODUCER = re.compile("[\x1b\x9b\x9d]")


def strip_controls(value: str) -> str:
    """Remove escape sequences and C0/C1 controls, preserving tabs and newlines.

    Each escape sequence is consumed once, including unterminated CSI/OSC
    sequences, so adversarial input cannot cause regex backtracking.
    """
    parts: list[str] = []
    start = 0
    length = len(value)
    # 7-bit (ESC [ / ESC ]) and 8-bit C1 (CSI U+009B / OSC U+009D) introducers.
    while (match := _INTRODUCER.search(value, start)) is not None:
        escape = match.start()
        parts.append(value[start:escape])
        end = escape + 1
        kind = value[escape]
        if kind == "\x1b" and end < length:
            kind = {"[": "\x9b", "]": "\x9d"}.get(value[end], "")
            end += 1
        if kind == "\x9b":
            while end < length and "\x20" <= value[end] <= "\x3f":
                end += 1
            if end < length and "\x40" <= value[end] <= "\x7e":
                end += 1
        elif kind == "\x9d":
            while end < length:
                if value[end] in "\x07\x9c":
                    end += 1
                    break
                if value.startswith("\x1b\\", end):
                    end += 2
                    break
                end += 1
        start = end
    parts.append(value[start:])
    return _CONTROLS.sub("", "".join(parts))


def terminal_safe(value: str) -> Text:
    """Return text that Rich will display literally, never as markup."""
    return Text(render_invisibles(strip_controls(value)))


class TerminalSafeLogFilter(logging.Filter):
    """Sanitize diagnostic records before any terminal handler formats them."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = strip_controls(record.getMessage())
        record.args = ()
        if record.exc_info is not None:
            record.exc_text = strip_controls("".join(traceback.format_exception(*record.exc_info)))
            record.exc_info = None
        elif record.exc_text is not None:
            record.exc_text = strip_controls(record.exc_text)
        if record.stack_info is not None:
            record.stack_info = strip_controls(record.stack_info)
        return True
