"""Generated pytest IDs stay bounded for large string parameters."""

import pytest


@pytest.mark.parametrize("payload", ["x" * 1_000_000])
def test_megabyte_string_parameter_has_compact_node_id(
    payload: str, request: pytest.FixtureRequest
) -> None:
    assert len(payload) == 1_000_000
    assert request.node.nodeid.endswith("[payload-string-1000000]")
