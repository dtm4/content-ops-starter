#!/usr/bin/env bash
set -euo pipefail

# Define Target Distribution Directory
DIST_DIR="./mcp_dist"
ZIP_NAME="mcp_spend_server_production.zip"

echo "🚀 Starting high-performance workspace compilation..."
mkdir -p "$DIST_DIR"

# 1. Output Python Requirements Profile
cat << 'EOF' > "$DIST_DIR/requirements.txt"
mcp>=1.0.0,<2
fastapi>=0.115.0
uvicorn>=0.30.0
pydantic>=2.9.0
requests>=2.32.0
EOF

# 2. Output Optimized Multi-Stage Dockerfile
cat << 'EOF' > "$DIST_DIR/Dockerfile"
FROM python:3.11-slim AS builder
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

FROM python:3.11-slim AS runner
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
    sqlite3 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /root/.local /root/.local
COPY mcp_spend_server.py .
ENV PATH=/root/.local/bin:$PATH
ENV PYTHONUNBUFFERED=1
ENV AGENT_SPEND_DB=/data/agent_spend.db
VOLUME ["/data"]
ENTRYPOINT ["python", "mcp_spend_server.py"]
EOF

# 3. Output Multi-Model Functional MCP Server Code
cat << 'EOF' > "$DIST_DIR/mcp_spend_server.py"
import os
import sys
import json
import random
import asyncio
import sqlite3
from typing import Dict, Any, List
import urllib.request
import urllib.error

from mcp.server.models import InitializationOptions
from mcp.server import NotificationOptions, Server
from mcp.server.stdio import stdio_server
import mcp.types as types

server = Server("cross-platform-agent-spend")
DB_PATH = os.environ.get("AGENT_SPEND_DB", "/data/agent_spend.db")
WEBHOOK_URL = os.environ.get("SPEND_APPROVAL_WEBHOOK", "")
MAX_AUTO_SPEND_CENTS = 1000      
MAX_HUMAN_CEILING_CENTS = 5000   

def init_database():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS task_spend_ledger (
            task_id TEXT PRIMARY KEY, card_id TEXT, card_number TEXT,
            cvv TEXT, expiry TEXT, max_budget_cents INTEGER,
            spent_cents INTEGER DEFAULT 0, status TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

def generate_mock_card_details() -> Dict[str, str]:
    bin_prefix = "411111"
    remainder = "".join(str(random.randint(0, 9)) for _ in range(9))
    digits = [int(d) for d in bin_prefix + remainder]
    checksum = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9: d -= 9
        checksum += d
    last_digit = (10 - (checksum % 10)) % 10
    return {
        "card_number": f"{bin_prefix}{remainder}{last_digit}",
        "cvv": f"{random.randint(100, 999)}",
        "expiry": f"{random.randint(1, 12):02d}/{random.randint(28, 35)}"
    }

async def send_human_approval_webhook(task_id: str, amount_cents: int, platform_hint: str) -> bool:
    if not WEBHOOK_URL:
        sys.stderr.write(f"[WARN] Human approval required for Task {task_id}, webhook offline.\n")
        return False
    payload = {
        "text": f"🚨 *AI Agent Spend Authorization Request* 🚨\n*Task ID:* `{task_id}`\n*Amount:* `${float(amount_cents)/100:.2f}`\n*Ecosystem:* `{platform_hint}`"
    }
    try:
        req = urllib.request.Request(WEBHOOK_URL, data=json.dumps(payload).encode("utf-8"), headers={"Content-Type": "application/json"}, method="POST")
        await asyncio.to_thread(urllib.request.urlopen, req, timeout=5)
        return True
    except Exception as e:
        sys.stderr.write(f"[ERROR] Webhook failed: {str(e)}\n")
        return False

@server.list_tools()
async def handle_list_tools() -> List[types.Tool]:
    return [
        types.Tool(
            name="provision_agent_card",
            description="Securely initiates a virtual card allocation bounded by strict ledger guardrails.",
            inputSchema={
                "type": "object",
                "properties": {
                    "task_id": {"type": "string"},
                    "max_spend_cents": {"type": "integer"},
                    "agent_ecosystem": {"type": "string", "enum": ["gemini", "claude", "openai", "grok", "unknown"], "default": "unknown"}
                },
                "required": ["task_id", "max_spend_cents"]
            }
        )
    ]

@server.call_tool()
async def handle_call_tool(name: str, arguments: Dict[str, Any]) -> List[types.TextContent]:
    if name != "provision_agent_card":
        raise ValueError(f"Unsupported tool: {name}")
    task_id = str(arguments.get("task_id", ""))
    max_spend_cents = int(arguments.get("max_spend_cents", 0))
    agent_ecosystem = str(arguments.get("agent_ecosystem", "unknown")).lower()
    if max_spend_cents > MAX_HUMAN_CEILING_CENTS:
        return [types.TextContent(type="text", text="Error: Absolute hard limit exceeded.")]
    approval_status = "APPROVED" if max_spend_cents <= MAX_AUTO_SPEND_CENTS else "PENDING"
    if approval_status == "PENDING":
        await send_human_approval_webhook(task_id, max_spend_cents, agent_ecosystem)
    mock_card = generate_mock_card_details() if approval_status == "APPROVED" else {"card_number": "SUSPENDED", "cvv": "000", "expiry": "00/00"}
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO task_spend_ledger (task_id, card_id, card_number, cvv, expiry, max_budget_cents, status) VALUES (?, ?, ?, ?, ?, ?, ?)",
                       (task_id, f"VCC_{task_id[:8].upper()}", mock_card["card_number"], mock_card["cvv"], mock_card["expiry"], max_spend_cents, approval_status))
        conn.commit()
        conn.close()
    except sqlite3.IntegrityError:
        return [types.TextContent(type="text", text="Ledger Conflict: Active session found.")]
    return [types.TextContent(type="text", text=json.dumps({"status": approval_status, "pan": mock_card["card_number"], "cvv": mock_card["cvv"], "expiry": mock_card["expiry"]}, indent=2))]

async def main():
    init_database()
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, InitializationOptions(server_name="spend-server", server_version="2.2.0", capabilities=server.get_capabilities(notification_options=NotificationOptions(), experimental_capabilities={})))

if __name__ == "__main__":
    asyncio.run(main())
EOF

# 4. Output Local docker-compose Profile
cat << 'EOF' > "$DIST_DIR/docker-compose.yml"
services:
  mcp-spend-server:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: production_mcp_spend_server
    restart: always
    # stdio MCP server: keep stdin open or it exits on EOF and restart-loops
    stdin_open: true
    environment:
      - AGENT_SPEND_DB=/data/agent_spend.db
      - SPEND_APPROVAL_WEBHOOK=${SPEND_APPROVAL_WEBHOOK:-}
      - PYTHONUNBUFFERED=1
    volumes:
      - mcp_ledger_data:/data
    # Performance Optimization Guardrails
    deploy:
      resources:
        limits:
          cpus: '1.0'
          memory: 512M
        reservations:
          memory: 128M
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"

volumes:
  mcp_ledger_data:
    driver: local
EOF

# 5. Compile Architecture Assets into standard Distribution Archive
echo "📦 Compression matrix processing..."
cd "$DIST_DIR"
zip -r "../$ZIP_NAME" ./* > /dev/null
cd ..

# 6. Clean Workspace Trace Variables
rm -rf "$DIST_DIR"

echo "✨ Production ZIP created successfully: $ZIP_NAME"
