"""Regenerate the program-owned MCP subscription stream fixture corpus."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

REVISION = "2026-07-28"
ROOT = Path(__file__).resolve().parent


def listen(
    stream: str,
    subscription_id: str,
    notifications: dict[str, Any],
    *,
    lifecycle: str = "open",
    replaces: str | None = None,
    protocol: str = REVISION,
) -> dict[str, Any]:
    event: dict[str, Any] = {
        "stream_id": stream,
        "stream_kind": "subscription",
        "request_id": subscription_id,
        "subscription_id": subscription_id,
        "direction": "client_to_server",
        "lifecycle": lifecycle,
        "protocol_version": protocol,
        "message": {
            "jsonrpc": "2.0",
            "id": subscription_id,
            "method": "subscriptions/listen",
            "params": {
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": protocol,
                    "io.modelcontextprotocol/clientCapabilities": {},
                },
                "notifications": notifications,
            },
        },
    }
    if replaces is not None:
        event["replaces_stream_id"] = replaces
    return event


def ack(
    stream: str,
    subscription_id: str,
    notifications: dict[str, Any],
    *,
    metadata_id: str | None = None,
    protocol: str = REVISION,
) -> dict[str, Any]:
    return {
        "stream_id": stream,
        "stream_kind": "subscription",
        "request_id": subscription_id,
        "subscription_id": subscription_id,
        "direction": "server_to_client",
        "lifecycle": "message",
        "protocol_version": protocol,
        "message": {
            "jsonrpc": "2.0",
            "method": "notifications/subscriptions/acknowledged",
            "params": {
                "_meta": {
                    "io.modelcontextprotocol/subscriptionId": (
                        subscription_id if metadata_id is None else metadata_id
                    )
                },
                "notifications": notifications,
            },
        },
    }


def notification(
    stream: str,
    subscription_id: str,
    method: str,
    *,
    metadata_id: str | None = None,
    uri: str | None = None,
    binding: str | None = None,
    protocol: str = REVISION,
) -> dict[str, Any]:
    params: dict[str, Any] = {
        "_meta": {
            "io.modelcontextprotocol/subscriptionId": (
                subscription_id if metadata_id is None else metadata_id
            )
        }
    }
    if uri is not None:
        params["uri"] = uri
    if method == "notifications/progress":
        params.update({"progressToken": "progress-1", "progress": 1})
    if method == "notifications/message":
        params.update({"level": "info", "data": "synthetic"})
    event: dict[str, Any] = {
        "stream_id": stream,
        "stream_kind": "subscription",
        "request_id": subscription_id,
        "subscription_id": subscription_id,
        "direction": "server_to_client",
        "lifecycle": "message",
        "protocol_version": protocol,
        "message": {"jsonrpc": "2.0", "method": method, "params": params},
    }
    if binding is not None:
        event["declared_resource_subscription"] = binding
    return event


def close(
    stream: str,
    subscription_id: str,
    *,
    protocol: str = REVISION,
) -> dict[str, Any]:
    return {
        "stream_id": stream,
        "stream_kind": "subscription",
        "request_id": subscription_id,
        "subscription_id": subscription_id,
        "direction": "server_to_client",
        "lifecycle": "close",
        "protocol_version": protocol,
        "message": {
            "jsonrpc": "2.0",
            "id": subscription_id,
            "result": {
                "_meta": {
                    "io.modelcontextprotocol/subscriptionId": subscription_id,
                }
            },
        },
    }


def disconnect(stream: str, subscription_id: str) -> dict[str, Any]:
    return {
        "stream_id": stream,
        "stream_kind": "subscription",
        "request_id": subscription_id,
        "subscription_id": subscription_id,
        "direction": "server_to_client",
        "lifecycle": "disconnect",
        "protocol_version": REVISION,
        "message": None,
    }


def request_open(stream: str, request_id: str) -> dict[str, Any]:
    return {
        "stream_id": stream,
        "stream_kind": "request",
        "request_id": request_id,
        "subscription_id": None,
        "direction": "client_to_server",
        "lifecycle": "open",
        "protocol_version": REVISION,
        "message": {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "tools/call",
            "params": {
                "_meta": {
                    "progressToken": "progress-1",
                    "io.modelcontextprotocol/protocolVersion": REVISION,
                    "io.modelcontextprotocol/clientCapabilities": {},
                },
                "name": "synthetic",
                "arguments": {},
            },
        },
    }


def request_progress(stream: str, request_id: str) -> dict[str, Any]:
    return {
        "stream_id": stream,
        "stream_kind": "request",
        "request_id": request_id,
        "subscription_id": None,
        "direction": "server_to_client",
        "lifecycle": "message",
        "protocol_version": REVISION,
        "message": {
            "jsonrpc": "2.0",
            "method": "notifications/progress",
            "params": {"progressToken": "progress-1", "progress": 1},
        },
    }


def legacy_notification() -> dict[str, Any]:
    return {
        "stream_id": "legacy-channel",
        "stream_kind": "subscription",
        "request_id": "legacy-listener",
        "subscription_id": "legacy-listener",
        "direction": "server_to_client",
        "lifecycle": "message",
        "protocol_version": "2025-11-25",
        "message": {
            "jsonrpc": "2.0",
            "method": "notifications/tools/list_changed",
            "params": {},
        },
    }


def write_trace(
    name: str,
    control_kind: str,
    events: list[dict[str, Any]],
    *,
    complete: bool = True,
) -> None:
    ordered = [{**event, "offset_ms": index} for index, event in enumerate(events)]
    payload = {
        "schema_version": "mcpaudit.mcp-subscription-trace.v1",
        "program_owned": True,
        "fixture_id": name,
        "control_kind": control_kind,
        "trace_complete": complete,
        "observed_duration_ms": max(0, len(ordered) - 1),
        "events": ordered,
    }
    target = ROOT / f"{name}.json"
    target.write_text(
        json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )


def current_tools(stream: str = "tools-listener", sub_id: str = "listen-tools") -> list[dict[str, Any]]:
    filters = {"toolsListChanged": True}
    return [
        listen(stream, sub_id, filters),
        ack(stream, sub_id, filters),
        notification(stream, sub_id, "notifications/tools/list_changed"),
        close(stream, sub_id),
    ]


def generate() -> None:
    tools = {"toolsListChanged": True}
    prompts = {"promptsListChanged": True}
    both = {"toolsListChanged": True, "promptsListChanged": True}

    write_trace(
        "wrong-type-vulnerable",
        "vulnerable",
        [
            listen("tools-listener", "listen-tools", tools),
            ack("tools-listener", "listen-tools", tools),
            notification(
                "tools-listener",
                "listen-tools",
                "notifications/prompts/list_changed",
            ),
            close("tools-listener", "listen-tools"),
        ],
    )
    write_trace("wrong-type-negative", "negative", current_tools())
    write_trace(
        "wrong-type-near-miss",
        "near_miss",
        [
            listen("catalog-listener", "listen-catalogs", both),
            ack("catalog-listener", "listen-catalogs", both),
            notification(
                "catalog-listener",
                "listen-catalogs",
                "notifications/prompts/list_changed",
            ),
            close("catalog-listener", "listen-catalogs"),
        ],
    )

    write_trace(
        "wrong-id-vulnerable",
        "vulnerable",
        [
            listen("tools-listener", "listen-tools", tools),
            ack("tools-listener", "listen-tools", tools),
            notification(
                "tools-listener",
                "listen-tools",
                "notifications/tools/list_changed",
                metadata_id="listen-other",
            ),
            close("tools-listener", "listen-tools"),
        ],
    )
    write_trace("wrong-id-negative", "negative", current_tools())
    write_trace(
        "wrong-id-near-miss",
        "near_miss",
        [
            listen("tools-listener", "listen-tools", tools),
            listen("prompts-listener", "listen-prompts", prompts),
            ack("prompts-listener", "listen-prompts", prompts),
            ack("tools-listener", "listen-tools", tools),
            notification(
                "prompts-listener",
                "listen-prompts",
                "notifications/prompts/list_changed",
            ),
            notification(
                "tools-listener",
                "listen-tools",
                "notifications/tools/list_changed",
            ),
            close("tools-listener", "listen-tools"),
            close("prompts-listener", "listen-prompts"),
        ],
    )

    write_trace(
        "request-leak-vulnerable",
        "vulnerable",
        [
            listen("tools-listener", "listen-tools", tools),
            ack("tools-listener", "listen-tools", tools),
            notification(
                "tools-listener",
                "listen-tools",
                "notifications/progress",
            ),
            close("tools-listener", "listen-tools"),
        ],
    )
    write_trace(
        "request-leak-negative",
        "negative",
        [
            request_open("tool-request", "call-1"),
            request_progress("tool-request", "call-1"),
            *current_tools(),
        ],
    )
    write_trace(
        "request-leak-near-miss",
        "near_miss",
        [
            listen("tools-listener", "listen-tools", tools),
            request_open("tool-request", "call-1"),
            ack("tools-listener", "listen-tools", tools),
            request_progress("tool-request", "call-1"),
            notification(
                "tools-listener",
                "listen-tools",
                "notifications/tools/list_changed",
            ),
            close("tools-listener", "listen-tools"),
        ],
    )

    alpha = {"resourceSubscriptions": ["file:///alpha"]}
    beta = {"resourceSubscriptions": ["file:///beta"]}
    write_trace(
        "wrong-resource-listener-vulnerable",
        "vulnerable",
        [
            listen("alpha-listener", "listen-alpha", alpha),
            listen("beta-listener", "listen-beta", beta),
            ack("alpha-listener", "listen-alpha", alpha),
            ack("beta-listener", "listen-beta", beta),
            notification(
                "alpha-listener",
                "listen-alpha",
                "notifications/resources/updated",
                uri="file:///beta/item.txt",
                binding="file:///beta",
            ),
            close("alpha-listener", "listen-alpha"),
            close("beta-listener", "listen-beta"),
        ],
    )
    write_trace(
        "wrong-resource-listener-negative",
        "negative",
        [
            listen("alpha-listener", "listen-alpha", alpha),
            ack("alpha-listener", "listen-alpha", alpha),
            notification(
                "alpha-listener",
                "listen-alpha",
                "notifications/resources/updated",
                uri="file:///alpha",
            ),
            close("alpha-listener", "listen-alpha"),
        ],
    )
    write_trace(
        "wrong-resource-listener-near-miss",
        "near_miss",
        [
            listen("alpha-listener", "listen-alpha", alpha),
            ack("alpha-listener", "listen-alpha", alpha),
            notification(
                "alpha-listener",
                "listen-alpha",
                "notifications/resources/updated",
                uri="file:///alpha/item.txt",
                binding="file:///alpha",
            ),
            close("alpha-listener", "listen-alpha"),
        ],
    )

    write_trace(
        "post-close-vulnerable",
        "vulnerable",
        [
            listen("tools-listener", "listen-tools", tools),
            ack("tools-listener", "listen-tools", tools),
            close("tools-listener", "listen-tools"),
            notification(
                "tools-listener",
                "listen-tools",
                "notifications/tools/list_changed",
            ),
        ],
    )
    write_trace("post-close-negative", "negative", current_tools())
    write_trace(
        "post-close-near-miss",
        "near_miss",
        [
            listen("old-listener", "listen-old", tools),
            ack("old-listener", "listen-old", tools),
            close("old-listener", "listen-old"),
            listen(
                "new-listener",
                "listen-new",
                tools,
                lifecycle="replace",
                replaces="old-listener",
            ),
            ack("new-listener", "listen-new", tools),
            notification(
                "new-listener",
                "listen-new",
                "notifications/tools/list_changed",
            ),
            close("new-listener", "listen-new"),
        ],
    )

    write_trace(
        "valid-interleaving-vulnerable",
        "vulnerable",
        [
            listen("tools-listener", "listen-tools", tools),
            listen("prompts-listener", "listen-prompts", prompts),
            ack("tools-listener", "listen-tools", tools),
            ack("prompts-listener", "listen-prompts", prompts),
            notification(
                "tools-listener",
                "listen-tools",
                "notifications/tools/list_changed",
                metadata_id="listen-prompts",
            ),
            close("tools-listener", "listen-tools"),
            close("prompts-listener", "listen-prompts"),
        ],
    )
    write_trace(
        "valid-interleaving-negative",
        "negative",
        [
            *current_tools("tools-listener", "listen-tools"),
            listen("prompts-listener", "listen-prompts", prompts),
            ack("prompts-listener", "listen-prompts", prompts),
            notification(
                "prompts-listener",
                "listen-prompts",
                "notifications/prompts/list_changed",
            ),
            close("prompts-listener", "listen-prompts"),
        ],
    )
    write_trace(
        "valid-interleaving-near-miss",
        "near_miss",
        [
            listen("tools-listener", "listen-tools", tools),
            listen("prompts-listener", "listen-prompts", prompts),
            ack("prompts-listener", "listen-prompts", prompts),
            ack("tools-listener", "listen-tools", tools),
            notification(
                "tools-listener",
                "listen-tools",
                "notifications/tools/list_changed",
            ),
            notification(
                "prompts-listener",
                "listen-prompts",
                "notifications/prompts/list_changed",
            ),
            close("prompts-listener", "listen-prompts"),
            close("tools-listener", "listen-tools"),
        ],
    )

    write_trace(
        "reconnect-vulnerable",
        "vulnerable",
        [
            listen("old-listener", "listen-old", tools),
            ack("old-listener", "listen-old", tools),
            disconnect("old-listener", "listen-old"),
            listen(
                "new-listener",
                "listen-new",
                tools,
                lifecycle="replace",
                replaces="old-listener",
            ),
            ack("new-listener", "listen-new", tools),
            notification(
                "old-listener",
                "listen-old",
                "notifications/tools/list_changed",
            ),
            close("new-listener", "listen-new"),
        ],
    )
    write_trace(
        "reconnect-negative",
        "negative",
        [
            listen("old-listener", "listen-old", tools),
            ack("old-listener", "listen-old", tools),
            disconnect("old-listener", "listen-old"),
        ],
    )
    write_trace(
        "reconnect-near-miss",
        "near_miss",
        [
            listen("old-listener", "listen-old", tools),
            ack("old-listener", "listen-old", tools),
            disconnect("old-listener", "listen-old"),
            listen(
                "new-listener",
                "listen-new",
                tools,
                lifecycle="replace",
                replaces="old-listener",
            ),
            ack("new-listener", "listen-new", tools),
            notification(
                "new-listener",
                "listen-new",
                "notifications/tools/list_changed",
            ),
            close("new-listener", "listen-new"),
        ],
    )

    write_trace(
        "old-protocol-vulnerable",
        "vulnerable",
        [legacy_notification(), *current_tools()],
    )
    write_trace("old-protocol-negative", "negative", current_tools())
    write_trace(
        "old-protocol-near-miss",
        "near_miss",
        [legacy_notification()],
    )

    write_trace(
        "truncated-vulnerable",
        "vulnerable",
        [
            listen("tools-listener", "listen-tools", tools),
            ack("tools-listener", "listen-tools", tools),
        ],
        complete=False,
    )
    write_trace("truncated-negative", "negative", current_tools())
    write_trace(
        "truncated-near-miss",
        "near_miss",
        [listen("tools-listener", "listen-tools", tools)],
        complete=False,
    )

    write_trace(
        "missing-ack-vulnerable",
        "vulnerable",
        [
            listen("tools-listener", "listen-tools", tools),
            notification(
                "tools-listener",
                "listen-tools",
                "notifications/tools/list_changed",
            ),
            close("tools-listener", "listen-tools"),
        ],
    )
    write_trace("missing-ack-negative", "negative", current_tools())
    write_trace(
        "missing-ack-near-miss",
        "near_miss",
        [
            listen("tools-listener", "listen-tools", tools),
            close("tools-listener", "listen-tools"),
        ],
    )


if __name__ == "__main__":
    generate()
