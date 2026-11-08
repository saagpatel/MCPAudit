"""Network sinkhole that runs as PID 1 of the sandbox's network-namespace container.

This file is copied into a container image and executed there with only the
standard library. It is never imported by MCPAudit at runtime. The server
under review joins this container's network namespace, which has no route to
any real network: a dummy interface carries a default route, and iptables
redirects every outbound DNS query and TCP connection to local listeners.
The listeners record what the server tried to reach and answer nothing useful.

Every record is one JSON line on stdout. Records carry host names, ports,
TLS SNI and HTTP Host only: never request paths, headers or bodies, which can
hold credentials.
"""

from __future__ import annotations

import ipaddress
import json
import socket
import socketserver
import struct
import subprocess
import sys
import threading
import time

DNS_PORT = 15053
TCP_PORT = 15001
UDP_PORT = 15002
SO_ORIGINAL_DST = 80
FAKE_NET = ipaddress.IPv4Network("198.18.0.0/15")
MAX_PEEK = 4096

_lock = threading.Lock()
_names: dict[str, str] = {}
_addresses: dict[str, str] = {}
_seq = 0


def emit(record: dict[str, object]) -> None:
    global _seq
    with _lock:
        _seq += 1
        record = {"seq": _seq, "t": round(time.monotonic(), 3), **record}
        sys.stdout.write(json.dumps(record, sort_keys=True) + "\n")
        sys.stdout.flush()


def fake_address(name: str) -> str:
    with _lock:
        if name not in _names:
            address = str(FAKE_NET[len(_names) + 1])
            _names[name] = address
            _addresses[address] = name
        return _names[name]


def run(*command: str) -> None:
    subprocess.run(command, check=True, capture_output=True, timeout=10)


def setup_network() -> bool:
    """Route everything into the sinkhole. Returns whether IPv6 is also captured."""
    run("ip", "link", "add", "sink0", "type", "dummy")
    run("ip", "addr", "add", "10.203.0.1/24", "dev", "sink0")
    run("ip", "link", "set", "sink0", "up")
    run("ip", "route", "add", "default", "dev", "sink0")
    nat = ("iptables", "-t", "nat", "-A", "OUTPUT")
    run(*nat, "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", str(DNS_PORT))
    run(*nat, "-p", "tcp", "--dport", "53", "-j", "REDIRECT", "--to-ports", str(TCP_PORT))
    run(*nat, "-d", "127.0.0.0/8", "-j", "RETURN")
    run(*nat, "-p", "tcp", "-j", "REDIRECT", "--to-ports", str(TCP_PORT))
    run(*nat, "-p", "udp", "-j", "REDIRECT", "--to-ports", str(UDP_PORT))
    try:
        run("ip", "-6", "addr", "add", "fd00:203::1/64", "dev", "sink0")
        run("ip", "-6", "route", "add", "default", "dev", "sink0")
        nat6 = ("ip6tables", "-t", "nat", "-A", "OUTPUT")
        run(*nat6, "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", str(DNS_PORT))
        run(*nat6, "-d", "::1/128", "-j", "RETURN")
        run(*nat6, "-p", "tcp", "-j", "REDIRECT", "--to-ports", str(TCP_PORT))
        run(*nat6, "-p", "udp", "-j", "REDIRECT", "--to-ports", str(UDP_PORT))
    except (subprocess.CalledProcessError, OSError, subprocess.TimeoutExpired):
        return False
    return True


def parse_question(packet: bytes) -> tuple[str, int, int] | None:
    """Return (name, qtype, end offset) for the first question, or None."""
    if len(packet) < 12 or struct.unpack("!H", packet[4:6])[0] < 1:
        return None
    labels: list[str] = []
    offset = 12
    while offset < len(packet):
        length = packet[offset]
        offset += 1
        if length == 0:
            break
        if length & 0xC0 or offset + length > len(packet):
            return None
        labels.append(packet[offset : offset + length].decode("ascii", "replace"))
        offset += length
    else:
        return None
    if offset + 4 > len(packet):
        return None
    qtype = struct.unpack("!H", packet[offset : offset + 2])[0]
    return ".".join(labels).lower()[:253], qtype, offset + 4


def dns_answer(packet: bytes) -> bytes | None:
    question = parse_question(packet)
    if question is None:
        return None
    name, qtype, end = question
    emit({"kind": "dns", "name": name, "qtype": qtype})
    flags = 0x8180  # response, recursion desired + available, NOERROR
    answers = b""
    count = 0
    if qtype == 1 and name:
        address = socket.inet_aton(fake_address(name))
        answers = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 5, 4) + address
        count = 1
    header = packet[:2] + struct.pack("!HHHHH", flags, 1, count, 0, 0)
    return header + packet[12:end] + answers


def tls_sni(data: bytes) -> str | None:
    """Extract the server_name from a TLS ClientHello, if present and complete."""
    try:
        if len(data) < 43 or data[0] != 0x16 or data[5] != 0x01:
            return None
        offset = 43
        offset += 1 + data[offset]  # session id
        offset += 2 + struct.unpack("!H", data[offset : offset + 2])[0]  # cipher suites
        offset += 1 + data[offset]  # compression methods
        end = offset + 2 + struct.unpack("!H", data[offset : offset + 2])[0]
        offset += 2
        while offset + 4 <= end and offset + 4 <= len(data):
            kind, length = struct.unpack("!HH", data[offset : offset + 4])
            offset += 4
            if kind == 0 and offset + 5 <= len(data):
                name_length = struct.unpack("!H", data[offset + 3 : offset + 5])[0]
                return data[offset + 5 : offset + 5 + name_length].decode("ascii", "replace").lower()[:253]
            offset += length
    except (IndexError, struct.error):
        return None
    return None


def http_request(data: bytes) -> tuple[str, str | None] | None:
    """Return (method, Host header) for a plaintext HTTP request; never the path."""
    head = data.split(b"\r\n\r\n", 1)[0].decode("latin-1", "replace")
    lines = head.split("\r\n")
    parts = lines[0].split(" ")
    if len(parts) != 3 or not parts[2].startswith("HTTP/") or not parts[0].isalpha():
        return None
    host = None
    for line in lines[1:]:
        key, _, value = line.partition(":")
        if key.strip().lower() == "host":
            host = value.strip().lower()[:253]
    return parts[0].upper()[:16], host


def original_destination(sock: socket.socket) -> tuple[str, int]:
    if sock.family == socket.AF_INET6:
        raw = sock.getsockopt(socket.IPPROTO_IPV6, SO_ORIGINAL_DST, 28)
        port = struct.unpack("!H", raw[2:4])[0]
        return str(ipaddress.IPv6Address(raw[8:24])), port
    raw = sock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
    port = struct.unpack("!H", raw[2:4])[0]
    return socket.inet_ntoa(raw[4:8]), port


class TcpSink(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        sock: socket.socket = self.request
        try:
            address, port = original_destination(sock)
        except OSError:
            address, port = "unknown", 0
        record: dict[str, object] = {"kind": "tcp", "dst_ip": address, "dst_port": port}
        with _lock:
            if address in _addresses:
                record["name"] = _addresses[address]
        sock.settimeout(1.5)
        data = b""
        try:
            while len(data) < MAX_PEEK:
                chunk = sock.recv(MAX_PEEK - len(data))
                if not chunk:
                    break
                data += chunk
                if tls_sni(data) or b"\r\n\r\n" in data:
                    break
        except OSError:
            pass
        record["bytes"] = len(data)
        if sni := tls_sni(data):
            record["sni"] = sni
        elif request := http_request(data):
            record["http_method"], record["http_host"] = request
            try:
                sock.sendall(
                    b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                )
            except OSError:
                pass
        emit(record)


class DnsSink(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        packet, sock = self.request
        reply = dns_answer(packet)
        if reply is not None:
            sock.sendto(reply, self.client_address)


class UdpSink(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        packet, _sock = self.request
        emit({"kind": "udp", "bytes": len(packet)})


class Tcp4(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class Tcp6(Tcp4):
    address_family = socket.AF_INET6

    def server_bind(self) -> None:
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        super().server_bind()


class Udp4(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True


class Udp6(Udp4):
    address_family = socket.AF_INET6

    def server_bind(self) -> None:
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        super().server_bind()


def serve(server: socketserver.BaseServer) -> None:
    threading.Thread(target=server.serve_forever, daemon=True).start()


def main() -> int:
    try:
        ipv6 = setup_network()
    except (subprocess.CalledProcessError, OSError, subprocess.TimeoutExpired) as exc:
        emit({"kind": "setup_error", "error": type(exc).__name__})
        return 1
    servers: list[socketserver.BaseServer] = [
        Udp4(("127.0.0.1", DNS_PORT), DnsSink),
        Tcp4(("127.0.0.1", TCP_PORT), TcpSink),
        Udp4(("127.0.0.1", UDP_PORT), UdpSink),
    ]
    if ipv6:
        try:
            servers += [
                Udp6(("::1", DNS_PORT), DnsSink),
                Tcp6(("::1", TCP_PORT), TcpSink),
                Udp6(("::1", UDP_PORT), UdpSink),
            ]
        except OSError:
            ipv6 = False
    for server in servers:
        serve(server)
    emit({"kind": "ready", "ipv6": ipv6})
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    raise SystemExit(main())
