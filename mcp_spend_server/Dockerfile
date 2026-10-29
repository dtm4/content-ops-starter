FROM python:3.11-slim AS builder
COPY requirements.txt .
RUN python -m venv /opt/venv && /opt/venv/bin/pip install --no-cache-dir -r requirements.txt

FROM python:3.11-slim AS runner
RUN useradd --system --no-create-home app && mkdir /data && chown app /data
COPY --from=builder /opt/venv /opt/venv
WORKDIR /app
COPY approvals.py card_issuer.py card_view.py employees.py ledger.py mcp_spend_server.py slack_listener.py ./
ENV PATH=/opt/venv/bin:$PATH
ENV PYTHONUNBUFFERED=1
ENV AGENT_SPEND_DB=/data/agent_spend.db
USER app
VOLUME ["/data"]
# Default process is the stdio MCP server; the Slack listener overrides this command.
CMD ["python", "mcp_spend_server.py"]
