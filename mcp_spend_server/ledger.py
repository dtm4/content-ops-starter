"""SQLite ledger for agent card requests.

Each task moves through one state machine:

    PENDING -> ISSUING -> APPROVED
            |          -> FAILED
            -> DENIED

Every transition is a single conditional UPDATE, so a request can be claimed for
issuing exactly once no matter how many times an approval arrives. Card numbers
and CVVs are never stored: only Lithic's card token and the last four digits.
"""

import os
import sqlite3
from contextlib import closing
from typing import Any, Dict, Optional

PENDING = "PENDING"
ISSUING = "ISSUING"
APPROVED = "APPROVED"
DENIED = "DENIED"
FAILED = "FAILED"

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
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
"""

_COLUMNS = ("task_id", "max_budget_cents", "agent_ecosystem", "status", "card_token",
            "last_four", "decided_by", "error", "created_at", "updated_at")


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

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path, timeout=10)

    def _row(self, row: Optional[tuple]) -> Optional[Dict[str, Any]]:
        return dict(zip(_COLUMNS, row)) if row else None

    def create(self, task_id: str, max_budget_cents: int, agent_ecosystem: str) -> bool:
        """Record a new PENDING request. Returns False if the task_id already exists."""
        try:
            with closing(self._connect()) as conn, conn:
                conn.execute(
                    "INSERT INTO agent_card_requests (task_id, max_budget_cents, agent_ecosystem, status) "
                    "VALUES (?, ?, ?, ?)",
                    (task_id, max_budget_cents, agent_ecosystem, PENDING),
                )
            return True
        except sqlite3.IntegrityError:
            return False

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

    def deny(self, task_id: str, decided_by: str) -> Optional[Dict[str, Any]]:
        """Move PENDING -> DENIED. Returns the row, or None if it was not PENDING."""
        return self._transition(task_id, PENDING, DENIED, decided_by=decided_by)
