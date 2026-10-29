"""SQLite ledger for agent card requests.

Each task moves through one state machine:

    PENDING -> ISSUING -> APPROVED -> CLOSED
            |          -> FAILED
            -> DENIED

Every transition is a single conditional UPDATE, so a request can be claimed for
issuing exactly once no matter how many times an approval arrives. Card numbers
and CVVs are never stored: only Lithic's card token, the last four digits and a
count of how many times the full details were handed to the agent.

Each request reserves its limit against the employee's rolling 24-hour cap when
it is created, so a looping agent is cut off by the total, not just per request.
"""

import os
import sqlite3
from contextlib import closing
from typing import Any, Dict, Optional, Tuple

PENDING = "PENDING"
ISSUING = "ISSUING"
APPROVED = "APPROVED"
CLOSED = "CLOSED"
DENIED = "DENIED"
FAILED = "FAILED"

# Requests that hold part of the daily cap. Closed cards still count: the cap is
# on what was authorised, not on what was actually spent.
RESERVING_STATUSES = (PENDING, ISSUING, APPROVED, CLOSED)

CREATED = "created"
EXISTS = "exists"
OVER_CAP = "over_cap"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS agent_card_requests (
    task_id TEXT PRIMARY KEY,
    max_budget_cents INTEGER NOT NULL,
    agent_ecosystem TEXT NOT NULL,
    status TEXT NOT NULL,
    card_token TEXT,
    last_four TEXT,
    decided_by TEXT,
    error TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    employee_id TEXT NOT NULL DEFAULT '',
    agent_instance_id TEXT NOT NULL DEFAULT '',
    details_reveal_count INTEGER NOT NULL DEFAULT 0,
    last_revealed_at TIMESTAMP
)
"""

_COLUMNS = ("task_id", "max_budget_cents", "agent_ecosystem", "status", "card_token",
            "last_four", "decided_by", "error", "created_at", "updated_at",
            "employee_id", "agent_instance_id", "details_reveal_count", "last_revealed_at")

_ADDED_COLUMNS = {
    "employee_id": "TEXT NOT NULL DEFAULT ''",
    "agent_instance_id": "TEXT NOT NULL DEFAULT ''",
    "details_reveal_count": "INTEGER NOT NULL DEFAULT 0",
    "last_revealed_at": "TIMESTAMP",
}


class Ledger:
    def __init__(self, path: str):
        self.path = path
        directory = os.path.dirname(path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        with closing(self._connect()) as conn, conn:
            # WAL lets the MCP server and the Slack listener share the file.
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute(_SCHEMA)
            existing = {row[1] for row in conn.execute("PRAGMA table_info(agent_card_requests)")}
            for name, definition in _ADDED_COLUMNS.items():
                if name not in existing:
                    conn.execute(f"ALTER TABLE agent_card_requests ADD COLUMN {name} {definition}")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_requests_employee_created "
                         "ON agent_card_requests (employee_id, created_at)")

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path, timeout=10)

    def _row(self, row: Optional[tuple]) -> Optional[Dict[str, Any]]:
        return dict(zip(_COLUMNS, row)) if row else None

    def _reserved_last_24h(self, conn: sqlite3.Connection, employee_id: str) -> int:
        placeholders = ", ".join("?" for _ in RESERVING_STATUSES)
        (total,) = conn.execute(
            "SELECT COALESCE(SUM(max_budget_cents), 0) FROM agent_card_requests "
            f"WHERE employee_id = ? AND created_at >= datetime('now', '-1 day') AND status IN ({placeholders})",
            (employee_id, *RESERVING_STATUSES),
        ).fetchone()
        return total

    def reserved_last_24h(self, employee_id: str) -> int:
        with closing(self._connect()) as conn:
            return self._reserved_last_24h(conn, employee_id)

    def create(self, task_id: str, max_budget_cents: int, employee_id: str, agent_instance_id: str,
               agent_ecosystem: str, daily_cap_cents: int) -> Tuple[str, int]:
        """Record a new PENDING request if it fits the employee's 24-hour cap.

        Returns (CREATED | EXISTS | OVER_CAP, cents of the cap still unreserved).
        The check and the insert run in one write transaction, so concurrent
        requests can't both squeeze under the cap.
        """
        with closing(self._connect()) as conn:
            conn.isolation_level = None
            conn.execute("BEGIN IMMEDIATE")
            try:
                if conn.execute("SELECT 1 FROM agent_card_requests WHERE task_id = ?", (task_id,)).fetchone():
                    outcome = EXISTS
                    reserved = self._reserved_last_24h(conn, employee_id)
                else:
                    reserved = self._reserved_last_24h(conn, employee_id)
                    if reserved + max_budget_cents > daily_cap_cents:
                        outcome = OVER_CAP
                    else:
                        conn.execute(
                            "INSERT INTO agent_card_requests (task_id, max_budget_cents, employee_id, "
                            "agent_instance_id, agent_ecosystem, status) VALUES (?, ?, ?, ?, ?, ?)",
                            (task_id, max_budget_cents, employee_id, agent_instance_id, agent_ecosystem, PENDING),
                        )
                        reserved += max_budget_cents
                        outcome = CREATED
                conn.execute("COMMIT")
            except BaseException:
                conn.execute("ROLLBACK")
                raise
        return outcome, max(daily_cap_cents - reserved, 0)

    def get(self, task_id: str) -> Optional[Dict[str, Any]]:
        with closing(self._connect()) as conn:
            row = conn.execute(
                f"SELECT {', '.join(_COLUMNS)} FROM agent_card_requests WHERE task_id = ?", (task_id,)
            ).fetchone()
        return self._row(row)

    def _transition(self, task_id: str, from_status: str, to_status: str, **fields: Any) -> Optional[Dict[str, Any]]:
        assignments = ", ".join(f"{name} = ?" for name in fields)
        sql = (
            f"UPDATE agent_card_requests SET status = ?, updated_at = CURRENT_TIMESTAMP"
            f"{', ' + assignments if assignments else ''} "
            f"WHERE task_id = ? AND status = ? RETURNING {', '.join(_COLUMNS)}"
        )
        with closing(self._connect()) as conn, conn:
            row = conn.execute(sql, (to_status, *fields.values(), task_id, from_status)).fetchone()
        return self._row(row)

    def claim_for_issuing(self, task_id: str, decided_by: str) -> Optional[Dict[str, Any]]:
        """Move PENDING -> ISSUING. Returns the row, or None if it was not PENDING."""
        return self._transition(task_id, PENDING, ISSUING, decided_by=decided_by)

    def mark_approved(self, task_id: str, card_token: str, last_four: str) -> Optional[Dict[str, Any]]:
        return self._transition(task_id, ISSUING, APPROVED, card_token=card_token, last_four=last_four)

    def mark_failed(self, task_id: str, error: str) -> Optional[Dict[str, Any]]:
        return self._transition(task_id, ISSUING, FAILED, error=error[:500])

    def mark_closed(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Move APPROVED -> CLOSED after the card has been closed at Lithic."""
        return self._transition(task_id, APPROVED, CLOSED)

    def record_details_reveal(self, task_id: str, max_reveals: int) -> Optional[Dict[str, Any]]:
        """Count a hand-out of the card's details to the agent, for the audit log.

        Only allowed while the card is APPROVED and under max_reveals; returns None
        otherwise. The details themselves are never stored.
        """
        with closing(self._connect()) as conn, conn:
            row = conn.execute(
                "UPDATE agent_card_requests SET details_reveal_count = details_reveal_count + 1, "
                "last_revealed_at = CURRENT_TIMESTAMP "
                f"WHERE task_id = ? AND status = ? AND details_reveal_count < ? RETURNING {', '.join(_COLUMNS)}",
                (task_id, APPROVED, max_reveals),
            ).fetchone()
        return self._row(row)

    def deny(self, task_id: str, decided_by: str) -> Optional[Dict[str, Any]]:
        """Move PENDING -> DENIED. Returns the row, or None if it was not PENDING."""
        return self._transition(task_id, PENDING, DENIED, decided_by=decided_by)
