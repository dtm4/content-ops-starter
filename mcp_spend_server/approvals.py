"""Approval flow shared by the MCP server and the Slack listener."""

import os
import re
import sys
from typing import Any, Dict, Optional

import httpx

from ledger import Ledger

MAX_AUTO_SPEND_CENTS = 1000
MAX_HUMAN_CEILING_CENTS = 5000
TASK_ID_PATTERN = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")

DB_PATH = os.environ.get("AGENT_SPEND_DB", "/data/agent_spend.db")

_ledger: Optional[Ledger] = None


def get_ledger() -> Ledger:
    global _ledger
    if _ledger is None:
        _ledger = Ledger(DB_PATH)
    return _ledger


def public_view(row: Dict[str, Any]) -> Dict[str, Any]:
    """The fields safe to show an agent or a Slack channel. Never card numbers or CVVs."""
    return {
        "task_id": row["task_id"],
        "status": row["status"],
        "spend_limit_cents": row["max_budget_cents"],
        "card_token": row["card_token"],
        "last_four": row["last_four"],
    }


async def issue_card_for_task(ledger: Ledger, issuer, task_id: str, decided_by: str) -> Optional[Dict[str, Any]]:
    """Claim a PENDING task and issue its card.

    Returns the final row, or None when the task was not PENDING (already decided,
    being issued, or unknown), in which case nothing is issued.
    """
    claimed = ledger.claim_for_issuing(task_id, decided_by)
    if claimed is None:
        return None
    try:
        card = await issuer.issue_single_use_card(task_id, claimed["max_budget_cents"])
    except Exception as e:
        sys.stderr.write(f"[ERROR] Card issuing failed for task {task_id}: {e}\n")
        return ledger.mark_failed(task_id, f"{type(e).__name__}: {e}")
    return ledger.mark_approved(task_id, card.token, card.last_four)


async def request_human_approval(task_id: str, amount_cents: int, agent_ecosystem: str) -> bool:
    """Post an approve/deny message to Slack. Clicks go to the Slack listener."""
    webhook_url = os.environ.get("SPEND_APPROVAL_WEBHOOK", "")
    if not webhook_url:
        sys.stderr.write(f"[WARN] Human approval required for task {task_id}, but SPEND_APPROVAL_WEBHOOK is not set.\n")
        return False
    summary = (
        f"*AI agent spend request*\n*Task ID:* `{task_id}`\n"
        f"*Limit:* `${amount_cents / 100:.2f}` (single-use card)\n*Agent:* `{agent_ecosystem}`"
    )
    message = {
        "text": f"AI agent spend request for task {task_id}",
        "blocks": [
            {"type": "section", "text": {"type": "mrkdwn", "text": summary}},
            {
                "type": "actions",
                "elements": [
                    {"type": "button", "style": "primary", "action_id": "approve_spend",
                     "text": {"type": "plain_text", "text": "Approve"}, "value": task_id},
                    {"type": "button", "style": "danger", "action_id": "deny_spend",
                     "text": {"type": "plain_text", "text": "Deny"}, "value": task_id},
                ],
            },
        ],
    }
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            response = await client.post(webhook_url, json=message)
            response.raise_for_status()
        return True
    except Exception as e:
        sys.stderr.write(f"[ERROR] Slack approval webhook failed: {e}\n")
        return False
