"""An HTTP transport that only connects to public addresses, checked at connect time.

Checking a host name once and letting the client resolve it again leaves a DNS
rebinding gap: the second answer can point somewhere private. This backend
resolves, vets, and connects to the same address in one step, for every
connection the client opens. TLS still verifies the original host name.
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Iterable
from typing import Any

import anyio
import httpcore2
import httpx2


class NonPublicAddressError(httpcore2.ConnectError):
    """The host resolved to a loopback, private, link-local, or otherwise non-public address."""


def public_addresses(infos: Iterable[tuple[object, ...]]) -> list[str]:
    """Return resolved addresses only if every one of them is globally routable."""
    addresses: list[str] = []
    for info in infos:
        sockaddr = info[4]
        raw = str(sockaddr[0]) if isinstance(sockaddr, tuple) else str(sockaddr)
        address = ipaddress.ip_address(raw.split("%", 1)[0])
        if not address.is_global:
            raise NonPublicAddressError(f"refusing non-public address {address}")
        addresses.append(str(address))
    if not addresses:
        raise NonPublicAddressError("host did not resolve")
    return addresses


class PublicOnlyBackend(httpcore2.AnyIOBackend):
    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[Any] | None = None,
    ) -> httpcore2.AsyncNetworkStream:
        try:
            infos = await anyio.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except OSError as exc:
            raise httpcore2.ConnectError(f"could not resolve {host}") from exc
        addresses = public_addresses(infos)
        return await super().connect_tcp(
            addresses[0], port, timeout=timeout, local_address=local_address, socket_options=socket_options
        )


class PublicOnlyTransport(httpx2.AsyncHTTPTransport):
    """httpx transport whose pool uses PublicOnlyBackend and ignores proxy environment."""

    def __init__(self) -> None:
        super().__init__(trust_env=False)
        self._pool = httpcore2.AsyncConnectionPool(
            ssl_context=httpx2.create_ssl_context(trust_env=False),
            network_backend=PublicOnlyBackend(),
        )
