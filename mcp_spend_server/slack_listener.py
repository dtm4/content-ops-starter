"""Receives Approve/Deny clicks from Slack and issues or denies the card.

Every request must carry a valid Slack signature, and only Slack user IDs listed
in SLACK_APPROVER_IDS can decide. Slack is answered immediately; the Lithic call
runs afterwards and the result is posted back to the message's response_url.
"""

import hashlib
import hmac
import json
import os
import sys
import time
from contextlib import asynccontextmanager
from typing import Optional
from urllib.parse import parse_qs

import httpx
from fastapi import BackgroundTasks, FastAPI, Request, Response

from approvals import get_ledger, issue_card_for_task
from card_issuer import get_issuer
from ledger import APPROVED

SIGNATURE_TOLERANCE_SECONDS = 300
SLACK_RESPONSE_URL_PREFIX = "https://hooks.slack.com/"


def verify_slack_signature(signing_secret: str, timestamp: Optional[str], signature: Optional[str],
                           body: bytes, now: Optional[float] = None) -> bool:
    if not signing_secret or not timestamp or not signature:
        return False
    try:
        sent_at = int(timestamp)
    except ValueError:
        return False
    if abs((now if now is not None else time.time()) - sent_at) > SIGNATURE_TOLERANCE_SECONDS:
        return False
    base = b"v0:" + timestamp.encode() + b":" + body
    expected = "v0=" + hmac.new(signing_secret.encode(), base, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def approver_ids() -> set:
    return {uid.strip() for uid in os.environ.get("SLACK_APPROVER_IDS", "").split(",") if uid.strip()}


@asynccontextmanager
async def lifespan(app: FastAPI):
    if not os.environ.get("SLACK_SIGNING_SECRET"):
        raise RuntimeError("SLACK_SIGNING_SECRET is not set")
    if not approver_ids():
        raise RuntimeError("SLACK_APPROVER_IDS is empty, so nobody could approve a request")
    get_issuer()
    get_ledger()
    yield


app = FastAPI(lifespan=lifespan)


async def post_to_slack(response_url: str, text: str) -> None:
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            await client.post(response_url, json={"text": text, "replace_original": True})
    except Exception as e:
        sys.stderr.write(f"[ERROR] Posting to Slack response_url failed: {e}\n")


async def approve_and_report(task_id: str, user_id: str, response_url: str) -> None:
    row = await issue_card_for_task(get_ledger(), get_issuer(), task_id, decided_by=f"slack:{user_id}")
    if row is None:
        text = f"Task `{task_id}` was already decided or does not exist. No card was issued."
    elif row["status"] == APPROVED:
        text = (f"Approved by <@{user_id}>. Single-use card ending {row['last_four']} issued for task "
                f"`{task_id}` with a ${row['max_budget_cents'] / 100:.2f} limit.")
    else:
        text = f"Approved by <@{user_id}>, but issuing the card for task `{task_id}` failed. Check the server logs."
    await post_to_slack(response_url, text)


async def deny_and_report(task_id: str, user_id: str, response_url: str) -> None:
    row = get_ledger().deny(task_id, decided_by=f"slack:{user_id}")
    if row is None:
        text = f"Task `{task_id}` was already decided or does not exist."
    else:
        text = f"Denied by <@{user_id}>. No card was issued for task `{task_id}`."
    await post_to_slack(response_url, text)


@app.post("/slack/interactivity")
async def handle_slack_interaction(request: Request, background: BackgroundTasks):
    body = await request.body()
    if not verify_slack_signature(
        os.environ.get("SLACK_SIGNING_SECRET", ""),
        request.headers.get("X-Slack-Request-Timestamp"),
        request.headers.get("X-Slack-Signature"),
        body,
    ):
        return Response(status_code=401)

    try:
        payload = json.loads(parse_qs(body.decode())["payload"][0])
        user_id = payload["user"]["id"]
        response_url = payload["response_url"]
        action = payload["actions"][0]
        action_id = action["action_id"]
        task_id = action["value"]
    except (KeyError, IndexError, ValueError, TypeError):
        return Response(status_code=400)
    if not response_url.startswith(SLACK_RESPONSE_URL_PREFIX):
        return Response(status_code=400)

    if user_id not in approver_ids():
        return {"response_type": "ephemeral", "replace_original": False,
                "text": "You are not on the approver list for agent spend requests."}

    if action_id == "approve_spend":
        background.add_task(approve_and_report, task_id, user_id, response_url)
    elif action_id == "deny_spend":
        background.add_task(deny_and_report, task_id, user_id, response_url)
    else:
        return Response(status_code=400)
    return Response(status_code=200)
