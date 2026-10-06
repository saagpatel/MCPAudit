"""Bound untrusted detector text without processing an unbounded suffix."""

MAX_FIELD_BYTES = 256 * 1024


def bounded_text(text: str) -> str:
    """Return at most 256 KiB of UTF-8 text, ending at a character boundary."""
    if len(text) <= MAX_FIELD_BYTES // 4:
        return text
    prefix = text[:MAX_FIELD_BYTES]
    encoded = prefix.encode("utf-8", errors="surrogatepass")
    if len(encoded) <= MAX_FIELD_BYTES:
        return prefix
    capped = encoded[:MAX_FIELD_BYTES]
    try:
        return capped.decode("utf-8", errors="surrogatepass")
    except UnicodeDecodeError as exc:
        # Encoding above is valid; only the final character can be incomplete.
        return capped[: exc.start].decode("utf-8", errors="surrogatepass")
