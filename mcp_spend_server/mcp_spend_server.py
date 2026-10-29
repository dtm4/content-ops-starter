import asyncio
import json
import sys
import time
from typing import Any, Dict, List, Optional

import mcp.types as types
from mcp.server import NotificationOptions, Server
from mcp.server.models import InitializationOptions
from mcp.server.stdio import stdio_server

from approvals import (
    MAX_AUTO_SPEND_CENTS,
    MAX_HUMAN_CEILING_CENTS,
    TASK_ID_PATTERN,
    alert_cap_reached,
    get_ledger,
    issue_card_for_task,
    public_view,
    request_human_approval,
)
from card_issuer import get_issuer
from employees import current_employee_id, get_employee
from ledger import APPROVED, CREATED, EXISTS

ECOSYSTEMS = ["gemini", "claude", "openai", "grok", "unknown"]
CAP_ALERT_INTERVAL_SECONDS = 600
ID_RULE = "1-64 characters of letters, digits, '_', '.', ':' or '-'"

server = Server("cross-platform-agent-spend")
_last_cap_alert: Optional[float] = None


def _text(payload: Dict[str, Any]) -> List[types.TextContent]:
    return [types.TextContent(type="text", text=json.dumps(payload, indent=2))]


def _error(message: str) -> List[types.TextContent]:
    return _text({"error": message})


@server.list_tools()
async def handle_list_tools() -> List[types.Tool]:
    id_schema = {"type": "string", "pattern": TASK_ID_PATTERN.pattern}
    return [
        types.Tool(
            name="provision_agent_card",
            description=(
                "Request a single-use virtual card for a task. Requests up to "
                f"{MAX_AUTO_SPEND_CENTS} cents are issued immediately; larger ones up to "
                f"{MAX_HUMAN_CEILING_CENTS} cents wait for human approval in Slack. All requests "
                "count against the employee's rolling 24-hour cap. Returns the card token and "
                "last four digits, never the full card number."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "task_id": id_schema,
                    "max_spend_cents": {"type": "integer", "minimum": 1, "maximum": MAX_HUMAN_CEILING_CENTS},
                    "agent_instance_id": {**id_schema, "description": "Which agent run is asking, for the audit log."},
                    "agent_ecosystem": {"type": "string", "enum": ECOSYSTEMS, "default": "unknown"},
                },
                "required": ["task_id", "max_spend_cents", "agent_instance_id"],
            },
        ),
        types.Tool(
            name="get_agent_card_status",
            description="Check whether a card request is PENDING, ISSUING, APPROVED, CLOSED, DENIED or FAILED.",
            inputSchema={"type": "object", "properties": {"task_id": id_schema}, "required": ["task_id"]},
        ),
        types.Tool(
            name="terminate_agent_card",
            description="Permanently close a task's card once the purchase is done, so it can never be charged again.",
            inputSchema={"type": "object", "properties": {"task_id": id_schema}, "required": ["task_id"]},
        ),
    ]


async def _maybe_alert_cap(employee_id: str, agent_instance_id: str, task_id: str,
                           requested_cents: int, remaining_cents: int, daily_cap_cents: int) -> None:
    # A looping agent hits the cap over and over; alert at most once per interval.
    global _last_cap_alert
    now = time.monotonic()
    if _last_cap_alert is not None and now - _last_cap_alert < CAP_ALERT_INTERVAL_SECONDS:
        return
    _last_cap_alert = now
    await alert_cap_reached(employee_id, agent_instance_id, task_id, requested_cents,
                            remaining_cents, daily_cap_cents)


async def _provision(task_id: str, arguments: Dict[str, Any], employee_id: str) -> List[types.TextContent]:
    max_spend_cents = arguments.get("max_spend_cents")
    # bool is a subclass of int; reject it explicitly.
    if not isinstance(max_spend_cents, int) or isinstance(max_spend_cents, bool) or max_spend_cents < 1:
        return _error("max_spend_cents must be a positive integer.")
    if max_spend_cents > MAX_HUMAN_CEILING_CENTS:
        return _error(f"max_spend_cents exceeds the hard limit of {MAX_HUMAN_CEILING_CENTS}.")
    agent_instance_id = arguments.get("agent_instance_id")
    if not isinstance(agent_instance_id, str) or not TASK_ID_PATTERN.match(agent_instance_id):
        return _error(f"agent_instance_id must be {ID_RULE}.")
    agent_ecosystem = str(arguments.get("agent_ecosystem", "unknown")).lower()
    if agent_ecosystem not in ECOSYSTEMS:
        agent_ecosystem = "unknown"

    employee = get_employee(employee_id)
    if employee is None or not employee.active:
        return _error(f"Employee {employee_id} is not active, so no cards can be issued.")

    ledger = get_ledger()
    outcome, remaining = ledger.create(task_id, max_spend_cents, employee_id, agent_instance_id,
                                       agent_ecosystem, employee.daily_cap_cents)
    if outcome == EXISTS:
        return _error(f"A card request for task {task_id} already exists; use get_agent_card_status.")
    if outcome != CREATED:
        await _maybe_alert_cap(employee_id, agent_instance_id, task_id, max_spend_cents,
                               remaining, employee.daily_cap_cents)
        return _error(
            f"Blocked: this would exceed {employee_id}'s 24-hour cap of {employee.daily_cap_cents} cents "
            f"({remaining} cents left). A human has been alerted; do not retry."
        )

    if max_spend_cents <= MAX_AUTO_SPEND_CENTS:
        row = await issue_card_for_task(ledger, get_issuer(), task_id, decided_by="auto-policy")
        view = public_view(row)
    else:
        row = ledger.get(task_id)
        view = public_view(row)
        view["approval_request_sent"] = await request_human_approval(row)
    view["daily_cap_remaining_cents"] = remaining
    return _text(view)


async def _terminate(task_id: str, row: Dict[str, Any]) -> List[types.TextContent]:
    if row["status"] != APPROVED:
        return _error(f"Task {task_id} has no open card to close (status {row['status']}).")
    try:
        await get_issuer().close_card(row["card_token"])
    except Exception as e:
        sys.stderr.write(f"[ERROR] Closing card for task {task_id} failed: {e}\n")
        return _error(f"Closing the card failed ({type(e).__name__}); it is still open. Try again.")
    # Another call may have closed it at the same moment; either way it is closed now.
    closed = get_ledger().mark_closed(task_id) or get_ledger().get(task_id)
    return _text(public_view(closed))


@server.call_tool()
async def handle_call_tool(name: str, arguments: Dict[str, Any]) -> List[types.TextContent]:
    employee_id = current_employee_id()
    task_id = arguments.get("task_id")
    if not isinstance(task_id, str) or not TASK_ID_PATTERN.match(task_id):
        return _error(f"task_id must be {ID_RULE}.")

    if name == "provision_agent_card":
        return await _provision(task_id, arguments, employee_id)
    if name not in ("get_agent_card_status", "terminate_agent_card"):
        raise ValueError(f"Unsupported tool: {name}")

    row = get_ledger().get(task_id)
    # Agents only see their own employee's tasks.
    if row is None or row["employee_id"] != employee_id:
        return _error(f"No card request for task {task_id}.")
    if name == "get_agent_card_status":
        return _text(public_view(row))
    return await _terminate(task_id, row)


async def main():
    # Fail fast on missing identity, directory, API key or an unconfirmed production setting.
    employee_id = current_employee_id()
    if get_employee(employee_id) is None:
        raise RuntimeError(f"SPEND_EMPLOYEE_ID {employee_id!r} is not in the employee directory")
    get_issuer()
    get_ledger()
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="spend-server",
                server_version="3.1.0",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(), experimental_capabilities={}
                ),
            ),
        )


if __name__ == "__main__":
    asyncio.run(main())
