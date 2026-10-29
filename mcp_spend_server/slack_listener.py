"""Receives Approve/Deny clicks from Slack and issues or denies the card.

Every request must carry a valid Slack signature, and only Slack user IDs listed
in SLACK_APPROVER_IDS can decide. Slack is answered immediately; the Lithic call
runs afterwards and the result is posted back to the message's response_url.

Also serves /cards/view, the page behind the signed "View card details" links,
which frames Lithic's embedded card UI so a person can pay by hand.
"""

import hashlib
import hmac
import html
import json
import os
import sys
import time
from contextlib import asynccontextmanager
from typing import Optional
from urllib.parse import parse_qs

import httpx
from fastapi import BackgroundTasks, FastAPI, Request, Response
from fastapi.responses import HTMLResponse

from approvals import get_ledger, issue_card_for_task, view_link_line
from card_issuer import get_issuer
from card_view import MAX_HUMAN_VIEWS, verify_view_link
from employees import load_employees
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
    load_employees()
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
        text = (f"Approved by <@{user_id}>. Single-use card ending {row['last_four']} issued to "
                f"`{row['employee_id']}` for task `{task_id}` with a ${row['max_budget_cents'] / 100:.2f} limit."
                f"{view_link_line(task_id)}")
    else:
        text = (f"Approved by <@{user_id}>, but issuing the card for task `{task_id}` failed: "
                f"{row['error']}")
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


_NO_STORE_HEADERS = {
    "Cache-Control": "no-store",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": (
        "default-src 'none'; style-src 'unsafe-inline'; "
        "frame-src https://sandbox.lithic.com https://api.lithic.com; frame-ancestors 'none'"
    ),
}


def _view_page(title: str, body: str, status_code: int = 200) -> HTMLResponse:
    page = (
        "<!doctype html><html><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        f"<title>{html.escape(title)}</title>"
        "<style>body{font-family:system-ui,sans-serif;max-width:480px;margin:24px auto;padding:0 16px;color:#222}"
        "iframe{border:0;width:100%;height:260px}p{line-height:1.5}</style></head>"
        f"<body><h1 style='font-size:1.3em'>{html.escape(title)}</h1>{body}</body></html>"
    )
    return HTMLResponse(page, status_code=status_code, headers=_NO_STORE_HEADERS)


@app.get("/cards/view")
async def view_card(task_id: str = "", expires: str = "", sig: str = ""):
    if not verify_view_link(task_id, expires, sig):
        return _view_page("Link not valid", "<p>This link is invalid or has expired. "
                          "Ask for a new card if you still need to pay.</p>", status_code=403)
    row = get_ledger().record_human_view(task_id, MAX_HUMAN_VIEWS)
    if row is None:
        return _view_page("Card not available", "<p>This card is no longer open, or it has already been "
                          f"viewed {MAX_HUMAN_VIEWS} times.</p>", status_code=410)
    embed_url = get_issuer().get_embed_url(row["card_token"])
    details = (
        f"<p>Task <code>{html.escape(task_id)}</code> &middot; employee <code>{html.escape(row['employee_id'])}</code>"
        f"<br>Single-use card ending <b>{html.escape(row['last_four'])}</b>, "
        f"limit <b>${row['max_budget_cents'] / 100:.2f}</b>.</p>"
        f"<iframe src='{html.escape(embed_url, quote=True)}' allow='clipboard-write'></iframe>"
        "<p>The card details load straight from Lithic. If they don't appear, reload this page "
        f"(up to {MAX_HUMAN_VIEWS} views). Use the billing address registered on the card's "
        "Lithic account. The card works for one purchase only.</p>"
    )
    return _view_page("Card for checkout", details)
