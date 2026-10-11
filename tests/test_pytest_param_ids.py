"""Generated pytest IDs stay bounded for large string parameters."""

import pytest


@pytest.mark.parametrize("payload", ["x" * 1_000_000])
def test_megabyte_string_parameter_has_compact_node_id(payload: str, request: pytest.FixtureRequest) -> None:
    assert len(payload) == 1_000_000
    assert request.node.nodeid.endswith("[payload-str-1000000]")


@pytest.mark.parametrize("payload", [b"\x01" * 1_000])
def test_long_bytes_parameter_has_compact_node_id(payload: bytes, request: pytest.FixtureRequest) -> None:
    assert request.node.nodeid.endswith("[payload-bytes-1000]")
