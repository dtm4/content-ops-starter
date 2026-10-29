# Agent spend server (Lithic sandbox)

Two processes share one SQLite ledger:

- **`mcp_spend_server.py`**: stdio MCP server. Tools: `provision_agent_card` and `get_agent_card_status`.
- **`slack_listener.py`**: receives Approve/Deny clicks from Slack.

Requests up to $10 get a single-use Lithic card immediately. Requests up to $50 post an Approve/Deny message to Slack, and anything above $50 is rejected. Each card's spend limit is the requested amount.

Agents only ever see the card token and last four digits. Full card numbers and CVVs are never returned or stored.

## Safety defaults

- Cards come from **Lithic's sandbox** unless `LITHIC_ENVIRONMENT=production` *and* `ALLOW_PRODUCTION_CARDS=yes` are both set.
- The listener rejects any request without a valid Slack signature.
- Only Slack user IDs in `SLACK_APPROVER_IDS` can approve or deny.
- A request is claimed for issuing at most once, so repeated or late clicks never create a second card.
- A failed Lithic call leaves the request `FAILED`. Submit a new `task_id` to try again.

## Setup

1. `cp .env.example .env` and fill it in with your Lithic **sandbox** API key.
2. Create a Slack app:
   - Enable **Incoming Webhooks** for the approval channel → `SPEND_APPROVAL_WEBHOOK`.
   - Copy **Basic Information → Signing Secret** → `SLACK_SIGNING_SECRET`.
   - Enable **Interactivity** with the Request URL `https://<your-host>/slack/interactivity`.
3. Run `docker compose up -d --build`. The listener binds to `127.0.0.1:8080`, so put an HTTPS reverse proxy or tunnel in front of it for Slack.
4. Point your MCP client at the server, e.g. `docker run -i --rm -v <project>_mcp_ledger_data:/data --env-file .env mcp-spend-server:latest`.

## Tests

```
pip install -r requirements-dev.txt
pytest
```
