import asyncio
import hashlib
import hmac
import json
import sqlite3
import time
from urllib.parse import urlencode

import pytest
from fastapi.testclient import TestClient

import approvals
import card_issuer
import employees
import mcp_spend_server
import slack_listener
from card_issuer import CardDetails, CardDetailsUnavailable, IssuedCard
from ledger import APPROVED, CLOSED, CREATED, DENIED, EXISTS, FAILED, OVER_CAP, PENDING, Ledger

SECRET = "test-signing-secret"
APPROVER = "UAPPROVER"
EMPLOYEE = "EMP_A"
DIRECTORY = {
    "employees": [
        {"employee_id": "EMP_A", "display_name": "A", "lithic_account_token": "acct-a",
         "status": "ACTIVE", "daily_cap_cents": 5000},
        {"employee_id": "EMP_B", "display_name": "B", "status": "ACTIVE", "daily_cap_cents": 1500},
        {"employee_id": "EMP_OFF", "display_name": "Off", "status": "INACTIVE"},
    ]
}


class FakeIssuer:
    def __init__(self, fail=False):
        self.fail = fail
        self.calls = []
        self.closed = []
        self.revealed = []
        self.no_details = False

    async def issue_single_use_card(self, task_id, spend_limit_cents, account_token=None):
        self.calls.append((task_id, spend_limit_cents, account_token))
        if self.fail:
            raise RuntimeError("lithic unavailable")
        return IssuedCard(token=f"tok-{task_id}", last_four="4242", state="OPEN")

    async def close_card(self, card_token):
        if self.fail:
            raise RuntimeError("lithic unavailable")
        self.closed.append(card_token)

    async def get_card_details(self, card_token):
        if self.fail:
            raise RuntimeError("lithic unavailable")
        if self.no_details:
            raise CardDetailsUnavailable("Lithic did not return the full card details.")
        self.revealed.append(card_token)
        return CardDetails(card_number="4111111111114242", cvv="123", exp_month="11", exp_year="2029")


@pytest.fixture
def directory(tmp_path, monkeypatch):
    path = tmp_path / "employees.json"
    path.write_text(json.dumps(DIRECTORY))
    monkeypatch.setattr(employees, "CONFIG_PATH", str(path))
    return path


@pytest.fixture
def env(tmp_path, monkeypatch, directory):
    ledger = Ledger(str(tmp_path / "ledger.db"))
    issuer = FakeIssuer()
    slack_messages = []

    async def fake_channel_post(message):
        slack_messages.append(message["text"])
        return True

    async def fake_post(response_url, text):
        slack_messages.append(text)

    monkeypatch.setattr(approvals, "_ledger", ledger)
    monkeypatch.setattr(card_issuer, "_issuer", issuer)
    monkeypatch.setattr(approvals, "post_to_approval_channel", fake_channel_post)
    monkeypatch.setattr(slack_listener, "post_to_slack", fake_post)
    monkeypatch.setattr(mcp_spend_server, "_last_cap_alert", None)
    monkeypatch.setattr(mcp_spend_server, "CAP_ALERT_INTERVAL_SECONDS", 0)
    monkeypatch.setenv("SPEND_EMPLOYEE_ID", EMPLOYEE)
    monkeypatch.setenv("SLACK_SIGNING_SECRET", SECRET)
    monkeypatch.setenv("SLACK_APPROVER_IDS", APPROVER)
    monkeypatch.delenv("LITHIC_ENVIRONMENT", raising=False)
    return ledger, issuer, slack_messages


def call_tool(name, **arguments):
    result = asyncio.run(mcp_spend_server.handle_call_tool(name, arguments))
    return json.loads(result[0].text)


def provision(task_id, cents, agent="agent-1", **extra):
    return call_tool("provision_agent_card", task_id=task_id, max_spend_cents=cents,
                     agent_instance_id=agent, **extra)


def new_request(ledger, task_id, cents, employee=EMPLOYEE, cap=5000):
    return ledger.create(task_id, cents, employee, "agent-1", "claude", cap)


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


# --- Employee directory ---

def test_directory_loads(directory):
    loaded = employees.load_employees()
    assert loaded["EMP_A"].lithic_account_token == "acct-a" and loaded["EMP_A"].active
    assert loaded["EMP_B"].lithic_account_token is None
    assert loaded["EMP_OFF"].daily_cap_cents == employees.DEFAULT_DAILY_CAP_CENTS and not loaded["EMP_OFF"].active


def test_directory_rejects_bad_cap(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text(json.dumps({"employees": [{"employee_id": "X", "status": "ACTIVE", "daily_cap_cents": "lots"}]}))
    with pytest.raises(ValueError):
        employees.load_employees(str(path))


def test_employee_id_required(monkeypatch):
    monkeypatch.delenv("SPEND_EMPLOYEE_ID", raising=False)
    with pytest.raises(RuntimeError, match="SPEND_EMPLOYEE_ID"):
        employees.current_employee_id()


# --- Ledger state machine and daily cap ---

def test_task_is_claimed_only_once(tmp_path):
    ledger = Ledger(str(tmp_path / "l.db"))
    assert new_request(ledger, "t1", 500)[0] == CREATED
    assert new_request(ledger, "t1", 500)[0] == EXISTS
    assert ledger.claim_for_issuing("t1", "a")["status"] == "ISSUING"
    assert ledger.claim_for_issuing("t1", "b") is None
    assert ledger.deny("t1", "b") is None


def test_denied_task_cannot_be_claimed(tmp_path):
    ledger = Ledger(str(tmp_path / "l.db"))
    new_request(ledger, "t1", 2000)
    assert ledger.deny("t1", "u")["status"] == DENIED
    assert ledger.claim_for_issuing("t1", "u") is None


def test_only_approved_cards_can_be_closed(tmp_path):
    ledger = Ledger(str(tmp_path / "l.db"))
    new_request(ledger, "t1", 500)
    assert ledger.mark_closed("t1") is None
    ledger.claim_for_issuing("t1", "a")
    ledger.mark_approved("t1", "tok", "4242")
    assert ledger.mark_closed("t1")["status"] == CLOSED
    assert ledger.mark_closed("t1") is None


def test_daily_cap_counts_reserved_requests(tmp_path):
    ledger = Ledger(str(tmp_path / "l.db"))
    assert new_request(ledger, "t1", 3000) == (CREATED, 2000)
    assert new_request(ledger, "t2", 2000) == (CREATED, 0)
    assert new_request(ledger, "t3", 1) == (OVER_CAP, 0)
    # Another employee has their own cap.
    assert new_request(ledger, "t4", 1000, employee="EMP_B") == (CREATED, 4000)


def test_denied_and_failed_requests_release_the_cap(tmp_path):
    ledger = Ledger(str(tmp_path / "l.db"))
    new_request(ledger, "t1", 3000)
    new_request(ledger, "t2", 2000)
    ledger.deny("t1", "u")
    ledger.claim_for_issuing("t2", "u")
    ledger.mark_failed("t2", "boom")
    assert ledger.reserved_last_24h(EMPLOYEE) == 0
    assert new_request(ledger, "t3", 5000)[0] == CREATED


def test_closed_cards_still_count_against_the_cap(tmp_path):
    ledger = Ledger(str(tmp_path / "l.db"))
    new_request(ledger, "t1", 4000)
    ledger.claim_for_issuing("t1", "a")
    ledger.mark_approved("t1", "tok", "4242")
    ledger.mark_closed("t1")
    assert new_request(ledger, "t2", 1001)[0] == OVER_CAP


def test_cap_window_is_rolling_24_hours(tmp_path):
    ledger = Ledger(str(tmp_path / "l.db"))
    new_request(ledger, "old", 5000)
    with sqlite3.connect(ledger.path) as conn:
        conn.execute("UPDATE agent_card_requests SET created_at = datetime('now', '-25 hours')")
    assert new_request(ledger, "new", 5000)[0] == CREATED


def test_old_ledger_gains_new_columns(tmp_path):
    path = str(tmp_path / "old.db")
    with sqlite3.connect(path) as conn:
        conn.execute("CREATE TABLE agent_card_requests (task_id TEXT PRIMARY KEY, max_budget_cents INTEGER NOT NULL, "
                     "agent_ecosystem TEXT NOT NULL, status TEXT NOT NULL, card_token TEXT, last_four TEXT, "
                     "decided_by TEXT, error TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, "
                     "updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)")
    ledger = Ledger(path)
    assert new_request(ledger, "t1", 100)[0] == CREATED
    assert ledger.get("t1")["employee_id"] == EMPLOYEE


def test_ledger_has_no_card_number_or_cvv_columns(tmp_path):
    ledger = Ledger(str(tmp_path / "l.db"))
    new_request(ledger, "t1", 500)
    assert not {"card_number", "pan", "cvv", "expiry"} & set(ledger.get("t1"))


# --- MCP tools ---

def test_small_request_is_issued_under_employee_account(env):
    _, issuer, _ = env
    result = provision("t1", 700, agent_ecosystem="claude")
    assert result["status"] == APPROVED
    assert result["card_token"] == "tok-t1" and result["last_four"] == "4242"
    assert result["employee_id"] == EMPLOYEE and result["agent_instance_id"] == "agent-1"
    assert result["daily_cap_remaining_cents"] == 4300
    assert not {"pan", "cvv", "card_number", "expiry"} & set(result)
    assert issuer.calls == [("t1", 700, "acct-a")]


def test_agent_cannot_choose_its_employee(env):
    _, issuer, _ = env
    result = provision("t1", 700, employee_id="EMP_B")
    assert result["employee_id"] == EMPLOYEE and issuer.calls[0][2] == "acct-a"


def test_large_request_waits_for_approval(env):
    _, issuer, slack_messages = env
    result = provision("t2", 2000)
    assert result["status"] == PENDING and result["approval_request_sent"] is True
    assert issuer.calls == [] and slack_messages == ["AI agent spend request for task t2"]


def test_looping_agent_is_cut_off_by_daily_cap(env):
    _, issuer, slack_messages = env
    results = [provision(f"loop-{i}", 900) for i in range(7)]
    assert [r.get("status") for r in results[:5]] == [APPROVED] * 5
    assert all("24-hour cap" in r["error"] for r in results[5:])
    assert len(issuer.calls) == 5
    assert any("Daily agent spend cap reached" in m for m in slack_messages)


def test_pending_requests_count_toward_the_cap(env):
    provision("big-1", 3000)
    provision("big-2", 2000)
    assert "24-hour cap" in provision("small", 100)["error"]


def test_cap_alerts_are_throttled(env, monkeypatch):
    _, _, slack_messages = env
    monkeypatch.setattr(mcp_spend_server, "CAP_ALERT_INTERVAL_SECONDS", 600)
    provision("fill", 5000)
    for i in range(3):
        provision(f"over-{i}", 100)
    assert sum("cap reached" in m for m in slack_messages) == 1


def test_inactive_employee_cannot_request(env, monkeypatch):
    _, issuer, _ = env
    monkeypatch.setenv("SPEND_EMPLOYEE_ID", "EMP_OFF")
    assert "not active" in provision("t1", 100)["error"]
    monkeypatch.setenv("SPEND_EMPLOYEE_ID", "EMP_NOBODY")
    assert "not active" in provision("t2", 100)["error"]
    assert issuer.calls == []


@pytest.mark.parametrize("amount", [5001, 0, -5, True, 10.5, "700"])
def test_bad_amounts_rejected(env, amount):
    _, issuer, _ = env
    assert "error" in provision("t3", amount)
    assert issuer.calls == []


@pytest.mark.parametrize("task_id", ["", "a" * 65, "bad id", "x`<!channel>`", None])
def test_bad_task_ids_rejected(env, task_id):
    assert "error" in provision(task_id, 100)


@pytest.mark.parametrize("agent", ["", "bad agent", None, "<!channel>"])
def test_bad_agent_instance_ids_rejected(env, agent):
    assert "agent_instance_id" in provision("t1", 100, agent=agent)["error"]


def test_duplicate_task_id_does_not_issue_twice(env):
    _, issuer, _ = env
    provision("t4", 100)
    assert "already exists" in provision("t4", 100)["error"]
    assert len(issuer.calls) == 1


def test_issuer_failure_marks_task_failed(env):
    _, issuer, _ = env
    issuer.fail = True
    assert provision("t5", 100)["status"] == FAILED


def test_status_tool_is_scoped_to_employee(env, monkeypatch):
    provision("t6", 3000)
    assert call_tool("get_agent_card_status", task_id="t6")["status"] == PENDING
    assert "error" in call_tool("get_agent_card_status", task_id="missing")
    monkeypatch.setenv("SPEND_EMPLOYEE_ID", "EMP_B")
    assert "error" in call_tool("get_agent_card_status", task_id="t6")


def test_terminate_closes_card(env):
    ledger, issuer, _ = env
    provision("t7", 500)
    result = call_tool("terminate_agent_card", task_id="t7")
    assert result["status"] == CLOSED and issuer.closed == ["tok-t7"]
    assert "no open card" in call_tool("terminate_agent_card", task_id="t7")["error"]


def test_terminate_failure_leaves_card_open(env):
    ledger, issuer, _ = env
    provision("t8", 500)
    issuer.fail = True
    assert "still open" in call_tool("terminate_agent_card", task_id="t8")["error"]
    assert ledger.get("t8")["status"] == APPROVED


def test_terminate_pending_or_other_employees_card_refused(env, monkeypatch):
    _, issuer, _ = env
    provision("t9", 3000)
    assert "no open card" in call_tool("terminate_agent_card", task_id="t9")["error"]
    provision("t10", 500)
    monkeypatch.setenv("SPEND_EMPLOYEE_ID", "EMP_B")
    assert "No card request" in call_tool("terminate_agent_card", task_id="t10")["error"]
    assert issuer.closed == []


# --- Card details for checkout ---

def test_card_details_for_approved_card(env):
    ledger, issuer, _ = env
    provision("c1", 500)
    details = call_tool("get_card_details_for_checkout", task_id="c1")
    assert details["card_number"] == "4111111111114242" and details["cvv"] == "123"
    assert details["exp_month"] == "11" and details["exp_year"] == "2029" and details["spend_limit_cents"] == 500
    assert issuer.revealed == ["tok-c1"]
    row = ledger.get("c1")
    assert row["details_reveal_count"] == 1 and row["last_revealed_at"]
    # Never written to the ledger.
    with sqlite3.connect(ledger.path) as conn:
        dump = "\n".join(conn.iterdump())
    assert "4111111111114242" not in dump and "'123'" not in dump


def test_card_details_limited_per_card(env):
    _, issuer, _ = env
    provision("c2", 500)
    for _ in range(mcp_spend_server.MAX_DETAIL_REVEALS):
        assert "card_number" in call_tool("get_card_details_for_checkout", task_id="c2")
    assert "already been handed out" in call_tool("get_card_details_for_checkout", task_id="c2")["error"]
    assert len(issuer.revealed) == mcp_spend_server.MAX_DETAIL_REVEALS


def test_card_details_only_for_open_card(env):
    _, issuer, _ = env
    provision("c3", 3000)  # pending approval
    assert "no open card" in call_tool("get_card_details_for_checkout", task_id="c3")["error"]
    provision("c4", 500)
    call_tool("terminate_agent_card", task_id="c4")
    assert "no open card" in call_tool("get_card_details_for_checkout", task_id="c4")["error"]
    assert issuer.revealed == []


def test_card_details_scoped_to_employee(env, monkeypatch):
    _, issuer, _ = env
    provision("c5", 500)
    monkeypatch.setenv("SPEND_EMPLOYEE_ID", "EMP_B")
    assert "No card request" in call_tool("get_card_details_for_checkout", task_id="c5")["error"]
    assert issuer.revealed == []


def test_card_details_need_opt_in_for_production(env, monkeypatch):
    _, issuer, _ = env
    provision("c6", 500)
    monkeypatch.setenv("LITHIC_ENVIRONMENT", "production")
    monkeypatch.setenv("ALLOW_PRODUCTION_CARDS", "yes")
    monkeypatch.delenv("ALLOW_PRODUCTION_CARD_DETAILS", raising=False)
    assert "disabled in production" in call_tool("get_card_details_for_checkout", task_id="c6")["error"]
    assert issuer.revealed == []
    monkeypatch.setenv("ALLOW_PRODUCTION_CARD_DETAILS", "yes")
    assert "card_number" in call_tool("get_card_details_for_checkout", task_id="c6")


def test_card_details_unavailable_from_lithic(env):
    _, issuer, _ = env
    provision("c7", 500)
    issuer.no_details = True
    assert "did not return" in call_tool("get_card_details_for_checkout", task_id="c7")["error"]


def test_card_details_kept_out_of_repr():
    details = CardDetails(card_number="4111111111114242", cvv="123", exp_month="11", exp_year="2029")
    assert "4111111111114242" not in repr(details) and "123" not in repr(details)


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


def click(client, *args, **kwargs):
    body = interaction(*args, **kwargs)
    return client.post("/slack/interactivity", content=body, headers=sign(body))


def test_unsigned_request_rejected(env, client):
    ledger, issuer, _ = env
    new_request(ledger, "t7", 2000)
    body = interaction("approve_spend", "t7")
    assert client.post("/slack/interactivity", content=body,
                       headers={"Content-Type": "application/x-www-form-urlencoded"}).status_code == 401
    assert client.post("/slack/interactivity", content=body, headers=sign(body, secret="wrong")).status_code == 401
    assert issuer.calls == [] and ledger.get("t7")["status"] == PENDING


def test_non_approver_cannot_approve(env, client):
    ledger, issuer, _ = env
    new_request(ledger, "t8", 2000)
    response = click(client, "approve_spend", "t8", user="URANDOM")
    assert response.status_code == 200 and "not on the approver list" in response.json()["text"]
    assert issuer.calls == [] and ledger.get("t8")["status"] == PENDING


def test_approval_issues_exactly_once_under_employee_account(env, client):
    ledger, issuer, slack_messages = env
    new_request(ledger, "t9", 2000)
    for _ in range(2):
        assert click(client, "approve_spend", "t9").status_code == 200
    assert issuer.calls == [("t9", 2000, "acct-a")]
    row = ledger.get("t9")
    assert row["status"] == APPROVED and row["decided_by"] == f"slack:{APPROVER}"
    assert "ending 4242 issued to `EMP_A`" in slack_messages[0] and "already decided" in slack_messages[1]


def test_approval_for_deactivated_employee_issues_nothing(env, client, directory):
    ledger, issuer, slack_messages = env
    new_request(ledger, "t12", 2000)
    directory.write_text(json.dumps({"employees": [{**DIRECTORY["employees"][0], "status": "INACTIVE"}]}))
    click(client, "approve_spend", "t12")
    assert issuer.calls == [] and ledger.get("t12")["status"] == FAILED
    assert "is not active" in slack_messages[0]


def test_deny_then_approve_issues_nothing(env, client):
    ledger, issuer, _ = env
    new_request(ledger, "t10", 2000)
    for action in ("deny_spend", "approve_spend"):
        click(client, action, "t10")
    assert issuer.calls == [] and ledger.get("t10")["status"] == DENIED


def test_unknown_task_issues_nothing(env, client):
    _, issuer, _ = env
    assert click(client, "approve_spend", "nope").status_code == 200
    assert issuer.calls == []


def test_non_slack_response_url_rejected(env, client):
    ledger, issuer, _ = env
    new_request(ledger, "t11", 2000)
    assert click(client, "approve_spend", "t11", response_url="https://attacker.example/x").status_code == 400
    assert issuer.calls == []


def test_listener_refuses_to_start_without_approvers(env, monkeypatch):
    monkeypatch.setenv("SLACK_APPROVER_IDS", "")
    with pytest.raises(RuntimeError, match="SLACK_APPROVER_IDS"):
        with TestClient(slack_listener.app):
            pass
