import asyncio
import hashlib
import hmac
import json
import time
from urllib.parse import urlencode

import pytest
from fastapi.testclient import TestClient

import approvals
import card_issuer
import mcp_spend_server
import slack_listener
from card_issuer import IssuedCard
from ledger import APPROVED, DENIED, FAILED, PENDING, Ledger

SECRET = "test-signing-secret"
APPROVER = "UAPPROVER"


class FakeIssuer:
    def __init__(self, fail=False):
        self.fail = fail
        self.calls = []

    async def issue_single_use_card(self, task_id, spend_limit_cents):
        self.calls.append((task_id, spend_limit_cents))
        if self.fail:
            raise RuntimeError("lithic unavailable")
        return IssuedCard(token=f"tok-{task_id}", last_four="4242", state="OPEN")


@pytest.fixture
def env(tmp_path, monkeypatch):
    ledger = Ledger(str(tmp_path / "ledger.db"))
    issuer = FakeIssuer()
    slack_messages = []

    async def fake_approval(task_id, amount_cents, agent_ecosystem):
        slack_messages.append(task_id)
        return True

    async def fake_post(response_url, text):
        slack_messages.append(text)

    monkeypatch.setattr(approvals, "_ledger", ledger)
    monkeypatch.setattr(card_issuer, "_issuer", issuer)
    monkeypatch.setattr(mcp_spend_server, "request_human_approval", fake_approval)
    monkeypatch.setattr(slack_listener, "post_to_slack", fake_post)
    monkeypatch.setenv("SLACK_SIGNING_SECRET", SECRET)
    monkeypatch.setenv("SLACK_APPROVER_IDS", APPROVER)
    monkeypatch.delenv("LITHIC_ENVIRONMENT", raising=False)
    return ledger, issuer, slack_messages


def call_tool(name, **arguments):
    result = asyncio.run(mcp_spend_server.handle_call_tool(name, arguments))
    return json.loads(result[0].text)


# --- Lithic environment guard ---

def test_defaults_to_sandbox(monkeypatch):
    monkeypatch.delenv("LITHIC_ENVIRONMENT", raising=False)
    assert card_issuer.lithic_environment() == "sandbox"


def test_production_requires_explicit_opt_in(monkeypatch):
    monkeypatch.setenv("LITHIC_ENVIRONMENT", "production")
    monkeypatch.delenv("ALLOW_PRODUCTION_CARDS", raising=False)
    with pytest.raises(RuntimeError, match="ALLOW_PRODUCTION_CARDS"):
        card_issuer.lithic_environment()
    monkeypatch.setenv("ALLOW_PRODUCTION_CARDS", "yes")
    assert card_issuer.lithic_environment() == "production"


def test_unknown_environment_rejected(monkeypatch):
    monkeypatch.setenv("LITHIC_ENVIRONMENT", "prod")
    with pytest.raises(RuntimeError):
        card_issuer.lithic_environment()


# --- Ledger state machine ---

def test_task_is_claimed_only_once(tmp_path):
    ledger = Ledger(str(tmp_path / "l.db"))
    assert ledger.create("t1", 500, "claude")
    assert not ledger.create("t1", 500, "claude")
    assert ledger.claim_for_issuing("t1", "a")["status"] == "ISSUING"
    assert ledger.claim_for_issuing("t1", "b") is None
    assert ledger.deny("t1", "b") is None


def test_denied_task_cannot_be_claimed(tmp_path):
    ledger = Ledger(str(tmp_path / "l.db"))
    ledger.create("t1", 2000, "claude")
    assert ledger.deny("t1", "u")["status"] == DENIED
    assert ledger.claim_for_issuing("t1", "u") is None


def test_ledger_has_no_card_number_or_cvv_columns(tmp_path):
    ledger = Ledger(str(tmp_path / "l.db"))
    ledger.create("t1", 500, "claude")
    assert not {"card_number", "pan", "cvv", "expiry"} & set(ledger.get("t1"))


# --- MCP tools ---

def test_small_request_is_issued_without_card_secrets(env):
    ledger, issuer, _ = env
    result = call_tool("provision_agent_card", task_id="t1", max_spend_cents=700, agent_ecosystem="claude")
    assert result["status"] == APPROVED
    assert result["card_token"] == "tok-t1" and result["last_four"] == "4242"
    assert not {"pan", "cvv", "card_number", "expiry"} & set(result)
    assert issuer.calls == [("t1", 700)]


def test_large_request_waits_for_approval(env):
    ledger, issuer, slack_messages = env
    result = call_tool("provision_agent_card", task_id="t2", max_spend_cents=2000)
    assert result["status"] == PENDING and result["approval_request_sent"] is True
    assert issuer.calls == [] and slack_messages == ["t2"]


@pytest.mark.parametrize("amount", [5001, 0, -5, True, 10.5, "700"])
def test_bad_amounts_rejected(env, amount):
    _, issuer, _ = env
    assert "error" in call_tool("provision_agent_card", task_id="t3", max_spend_cents=amount)
    assert issuer.calls == []


@pytest.mark.parametrize("task_id", ["", "a" * 65, "bad id", "x`<!channel>`", None])
def test_bad_task_ids_rejected(env, task_id):
    assert "error" in call_tool("provision_agent_card", task_id=task_id, max_spend_cents=100)


def test_duplicate_task_id_does_not_issue_twice(env):
    _, issuer, _ = env
    call_tool("provision_agent_card", task_id="t4", max_spend_cents=100)
    assert "error" in call_tool("provision_agent_card", task_id="t4", max_spend_cents=100)
    assert len(issuer.calls) == 1


def test_issuer_failure_marks_task_failed(env):
    _, issuer, _ = env
    issuer.fail = True
    assert call_tool("provision_agent_card", task_id="t5", max_spend_cents=100)["status"] == FAILED


def test_status_tool(env):
    call_tool("provision_agent_card", task_id="t6", max_spend_cents=3000)
    assert call_tool("get_agent_card_status", task_id="t6")["status"] == PENDING
    assert "error" in call_tool("get_agent_card_status", task_id="missing")


# --- Slack signature ---

def sign(body: bytes, timestamp=None, secret=SECRET):
    timestamp = str(int(time.time())) if timestamp is None else str(timestamp)
    digest = hmac.new(secret.encode(), b"v0:" + timestamp.encode() + b":" + body, hashlib.sha256).hexdigest()
    return {"X-Slack-Request-Timestamp": timestamp, "X-Slack-Signature": f"v0={digest}",
            "Content-Type": "application/x-www-form-urlencoded"}


def test_signature_checks():
    body = b"payload=x"
    good = sign(body)
    ts, sig = good["X-Slack-Request-Timestamp"], good["X-Slack-Signature"]
    assert slack_listener.verify_slack_signature(SECRET, ts, sig, body)
    assert not slack_listener.verify_slack_signature("other", ts, sig, body)
    assert not slack_listener.verify_slack_signature(SECRET, ts, sig, body + b"tampered")
    assert not slack_listener.verify_slack_signature(SECRET, ts, sig, body, now=int(ts) + 301)
    assert not slack_listener.verify_slack_signature(SECRET, None, sig, body)
    assert not slack_listener.verify_slack_signature("", ts, sig, body)


# --- Slack listener ---

def interaction(action_id, task_id, user=APPROVER, response_url="https://hooks.slack.com/actions/T/1/x"):
    payload = {"user": {"id": user}, "response_url": response_url,
               "actions": [{"action_id": action_id, "value": task_id}]}
    return urlencode({"payload": json.dumps(payload)}).encode()


@pytest.fixture
def client(env):
    with TestClient(slack_listener.app) as c:
        yield c


def test_unsigned_request_rejected(env, client):
    ledger, issuer, _ = env
    ledger.create("t7", 2000, "claude")
    body = interaction("approve_spend", "t7")
    assert client.post("/slack/interactivity", content=body,
                       headers={"Content-Type": "application/x-www-form-urlencoded"}).status_code == 401
    assert client.post("/slack/interactivity", content=body, headers=sign(body, secret="wrong")).status_code == 401
    assert issuer.calls == [] and ledger.get("t7")["status"] == PENDING


def test_non_approver_cannot_approve(env, client):
    ledger, issuer, _ = env
    ledger.create("t8", 2000, "claude")
    body = interaction("approve_spend", "t8", user="URANDOM")
    response = client.post("/slack/interactivity", content=body, headers=sign(body))
    assert response.status_code == 200 and "not on the approver list" in response.json()["text"]
    assert issuer.calls == [] and ledger.get("t8")["status"] == PENDING


def test_approval_issues_exactly_once(env, client):
    ledger, issuer, slack_messages = env
    ledger.create("t9", 2000, "claude")
    body = interaction("approve_spend", "t9")
    for _ in range(2):
        assert client.post("/slack/interactivity", content=body, headers=sign(body)).status_code == 200
    assert issuer.calls == [("t9", 2000)]
    row = ledger.get("t9")
    assert row["status"] == APPROVED and row["decided_by"] == f"slack:{APPROVER}"
    assert "ending 4242" in slack_messages[0] and "already decided" in slack_messages[1]


def test_deny_then_approve_issues_nothing(env, client):
    ledger, issuer, _ = env
    ledger.create("t10", 2000, "claude")
    for action in ("deny_spend", "approve_spend"):
        body = interaction(action, "t10")
        client.post("/slack/interactivity", content=body, headers=sign(body))
    assert issuer.calls == [] and ledger.get("t10")["status"] == DENIED


def test_unknown_task_issues_nothing(env, client):
    _, issuer, _ = env
    body = interaction("approve_spend", "nope")
    assert client.post("/slack/interactivity", content=body, headers=sign(body)).status_code == 200
    assert issuer.calls == []


def test_non_slack_response_url_rejected(env, client):
    ledger, issuer, _ = env
    ledger.create("t11", 2000, "claude")
    body = interaction("approve_spend", "t11", response_url="https://attacker.example/x")
    assert client.post("/slack/interactivity", content=body, headers=sign(body)).status_code == 400
    assert issuer.calls == []


def test_listener_refuses_to_start_without_approvers(env, monkeypatch):
    monkeypatch.setenv("SLACK_APPROVER_IDS", "")
    with pytest.raises(RuntimeError, match="SLACK_APPROVER_IDS"):
        with TestClient(slack_listener.app):
            pass
