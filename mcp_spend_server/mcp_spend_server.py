import asyncio
import json
from typing import Any, Dict, List

import mcp.types as types
from mcp.server import NotificationOptions, Server
from mcp.server.models import InitializationOptions
from mcp.server.stdio import stdio_server

from approvals import (
    MAX_AUTO_SPEND_CENTS,
    MAX_HUMAN_CEILING_CENTS,
    TASK_ID_PATTERN,
    get_ledger,
    issue_card_for_task,
    public_view,
    request_human_approval,
)
from card_issuer import get_issuer

ECOSYSTEMS = ["gemini", "claude", "openai", "grok", "unknown"]

server = Server("cross-platform-agent-spend")


def _text(payload: Dict[str, Any]) -> List[types.TextContent]:
    return [types.TextContent(type="text", text=json.dumps(payload, indent=2))]


def _error(message: str) -> List[types.TextContent]:
    return _text({"error": message})


@server.list_tools()
async def handle_list_tools() -> List[types.Tool]:
    return [
        types.Tool(
            name="provision_agent_card",
            description=(
                "Request a single-use virtual card for a task. Requests up to "
                f"{MAX_AUTO_SPEND_CENTS} cents are issued immediately; larger ones up to "
                f"{MAX_HUMAN_CEILING_CENTS} cents wait for human approval in Slack. "
                "Returns the card token and last four digits, never the full card number."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "task_id": {"type": "string", "pattern": TASK_ID_PATTERN.pattern},
                    "max_spend_cents": {"type": "integer", "minimum": 1, "maximum": MAX_HUMAN_CEILING_CENTS},
                    "agent_ecosystem": {"type": "string", "enum": ECOSYSTEMS, "default": "unknown"},
                },
                "required": ["task_id", "max_spend_cents"],
            },
        ),
        types.Tool(
            name="get_agent_card_status",
            description="Check whether a card request is PENDING, ISSUING, APPROVED, DENIED or FAILED.",
            inputSchema={
                "type": "object",
                "properties": {"task_id": {"type": "string"}},
                "required": ["task_id"],
            },
        ),
    ]


@server.call_tool()
async def handle_call_tool(name: str, arguments: Dict[str, Any]) -> List[types.TextContent]:
    ledger = get_ledger()
    task_id = arguments.get("task_id")
    if not isinstance(task_id, str) or not TASK_ID_PATTERN.match(task_id):
        return _error("task_id must be 1-64 characters of letters, digits, '_', '.', ':' or '-'.")

    if name == "get_agent_card_status":
        row = ledger.get(task_id)
        return _text(public_view(row)) if row else _error(f"No card request for task {task_id}.")

    if name != "provision_agent_card":
        raise ValueError(f"Unsupported tool: {name}")

    max_spend_cents = arguments.get("max_spend_cents")
    # bool is a subclass of int; reject it explicitly.
    if not isinstance(max_spend_cents, int) or isinstance(max_spend_cents, bool) or max_spend_cents < 1:
        return _error("max_spend_cents must be a positive integer.")
    if max_spend_cents > MAX_HUMAN_CEILING_CENTS:
        return _error(f"max_spend_cents exceeds the hard limit of {MAX_HUMAN_CEILING_CENTS}.")
    agent_ecosystem = str(arguments.get("agent_ecosystem", "unknown")).lower()
    if agent_ecosystem not in ECOSYSTEMS:
        agent_ecosystem = "unknown"

    if not ledger.create(task_id, max_spend_cents, agent_ecosystem):
        return _error(f"A card request for task {task_id} already exists; use get_agent_card_status.")

    if max_spend_cents <= MAX_AUTO_SPEND_CENTS:
        row = await issue_card_for_task(ledger, get_issuer(), task_id, decided_by="auto-policy")
        return _text(public_view(row))

    sent = await request_human_approval(task_id, max_spend_cents, agent_ecosystem)
    view = public_view(ledger.get(task_id))
    view["approval_request_sent"] = sent
    return _text(view)


async def main():
    get_issuer()  # fail fast on a missing API key or unconfirmed production setting
    get_ledger()
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="spend-server",
                server_version="3.0.0",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(), experimental_capabilities={}
                ),
            ),
        )


if __name__ == "__main__":
    asyncio.run(main())
