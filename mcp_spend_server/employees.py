"""Employee directory: who can spend, under which Lithic account, and how much per day.

Read from EMPLOYEES_CONFIG on every lookup, so setting an employee to INACTIVE
takes effect without a restart. The MCP server's own employee comes from the
SPEND_EMPLOYEE_ID environment variable, never from the agent's tool call.
"""

import json
import os
from dataclasses import dataclass
from typing import Optional

DEFAULT_DAILY_CAP_CENTS = 5000
CONFIG_PATH = os.environ.get("EMPLOYEES_CONFIG", "/config/employees.json")


@dataclass(frozen=True)
class Employee:
    employee_id: str
    display_name: str
    lithic_account_token: Optional[str]
    daily_cap_cents: int
    active: bool


def load_employees(path: Optional[str] = None) -> dict:
    with open(path or CONFIG_PATH) as f:
        config = json.load(f)
    employees = {}
    for entry in config.get("employees", []):
        employee_id = entry["employee_id"]
        daily_cap = entry.get("daily_cap_cents", DEFAULT_DAILY_CAP_CENTS)
        if not isinstance(daily_cap, int) or isinstance(daily_cap, bool) or daily_cap < 0:
            raise ValueError(f"daily_cap_cents for {employee_id} must be a non-negative integer")
        employees[employee_id] = Employee(
            employee_id=employee_id,
            display_name=entry.get("display_name", employee_id),
            lithic_account_token=entry.get("lithic_account_token") or None,
            daily_cap_cents=daily_cap,
            active=entry.get("status") == "ACTIVE",
        )
    return employees


def get_employee(employee_id: str) -> Optional[Employee]:
    return load_employees().get(employee_id)


def current_employee_id() -> str:
    employee_id = os.environ.get("SPEND_EMPLOYEE_ID", "")
    if not employee_id:
        raise RuntimeError("SPEND_EMPLOYEE_ID is not set; each MCP server runs on behalf of one employee")
    return employee_id
