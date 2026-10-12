"""Shared synthetic mixed CSI/OSC/bare-ESC field for redaction guardrails."""

MIB = 1024 * 1024


def escape_dense_field(size: int = MIB, *, separated: bool = True) -> str:
    prefix, suffix = "context ", " password=fixture-credential"
    pattern = "x\x1b[31m\x1b]note\x07\x1b:" + (" " if separated else "")
    length = size - len(prefix) - len(suffix)
    if length < 0:
        raise ValueError("Field must fit its synthetic context and credential.")
    return prefix + (pattern * (length // len(pattern) + 1))[:length] + suffix
