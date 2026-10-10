"""Bound untrusted detector text without processing an unbounded suffix."""

MAX_FIELD_BYTES = 256 * 1024


def bounded_text(text: str, max_bytes: int = MAX_FIELD_BYTES) -> str:
    """Return a bounded UTF-8 prefix, ending at a character boundary."""
    if max_bytes < 0:
        raise ValueError("max_bytes must be nonnegative")
    if len(text) <= max_bytes // 4:
        return text
    prefix = text[:max_bytes]
    encoded = prefix.encode("utf-8", errors="surrogatepass")
    if len(encoded) <= max_bytes:
        return prefix
    capped = encoded[:max_bytes]
    try:
        return capped.decode("utf-8", errors="surrogatepass")
    except UnicodeDecodeError as exc:
        # Encoding above is valid; only the final character can be incomplete.
        return capped[: exc.start].decode("utf-8", errors="surrogatepass")
