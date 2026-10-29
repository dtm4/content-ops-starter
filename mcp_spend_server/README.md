# Agent spend server (Lithic sandbox)

Two processes share one SQLite ledger:

- **`mcp_spend_server.py`**: stdio MCP server, run once per employee. Tools: `provision_agent_card`, `get_agent_card_status`, `get_card_details_for_checkout` and `terminate_agent_card`.
- **`slack_listener.py`**: receives Approve/Deny clicks from Slack, and serves the "View card details" page.

Requests up to $10 get a single-use Lithic card immediately. Requests up to $50 post an Approve/Deny message to Slack, and anything above $50 is rejected. Each card's spend limit is the requested amount, and the card is created under the employee's own Lithic account.

## Paying by hand

When `CARD_VIEW_LINK_SECRET` and `PUBLIC_BASE_URL` are set, every issued card gets a **View card details** link in the approval channel. This covers both cards issued automatically and cards approved in Slack.

The link opens a page showing Lithic's embedded card UI. The card number, CVV and expiry load in your browser straight from Lithic and never pass through this server, so you can pay by hand. This doesn't need Lithic's PCI approval for agent access.

Each link:
- works for 30 minutes;
- works only while the card is open;
- can be opened at most 5 times;
- is never shown to the agent.

Anyone in the approval channel can open it during that time, so keep the channel private.

## How an agent pays

1. `provision_agent_card` gets a card approved, automatically or in Slack. It returns only the card token and last four digits.
2. At the merchant's payment form, `get_card_details_for_checkout` returns the card number, CVV and expiry. They are fetched from Lithic at that moment, never stored, and the tool can be called at most 3 times per card.
3. The agent enters them together with the cardholder name and billing address, which you supply in the agent's instructions.
4. `terminate_agent_card` closes the card. Single-use cards also close themselves after the first purchase.

The card number passes through your AI provider's conversation with the agent. What limits the damage is the card itself: it works once, only up to its spend limit, and counts against the daily cap.

## Safety defaults

- Cards come from **Lithic's sandbox** unless `LITHIC_ENVIRONMENT=production` *and* `ALLOW_PRODUCTION_CARDS=yes` are both set.
- **Card details in production:** agents only get real card numbers if `ALLOW_PRODUCTION_CARD_DETAILS=yes` is also set. Lithic only returns full card numbers in production to PCI-compliant programs, so this needs Lithic's approval first.
- **Daily cap:** every request reserves its limit against the employee's rolling 24-hour cap (`daily_cap_cents`, default $50). Pending, issued and closed cards all count; denied and failed requests don't. Once the cap is reached, further requests are refused and Slack gets an alert, at most once every 10 minutes. This is what stops an agent stuck in a loop.
- **Employee identity:** the employee comes from the server's `SPEND_EMPLOYEE_ID`, never from the agent's tool call. Agents can only see and close their own employee's cards.
- **Deactivation:** setting an employee's `status` to anything but `ACTIVE` in `config/employees.json` blocks new requests and pending approvals immediately, with no restart.
- **Slack security:** the listener rejects any request without a valid Slack signature. Only Slack user IDs in `SLACK_APPROVER_IDS` can approve or deny.
- **No duplicate cards:** a request is claimed for issuing at most once, so repeated or late clicks never create a second card.
- **Retries:** a failed Lithic call leaves the request `FAILED`. Submit a new `task_id` to try again.
- **Closing cards:** `terminate_agent_card` closes the card at Lithic permanently. Single-use cards also close themselves after their first purchase.

The cap is on what was *authorised*, not on what was actually charged: a $9 card used for $2 still uses $9 of the cap.

## Setup

1. `cp .env.example .env` and fill it in with your Lithic **sandbox** API key.
2. `mkdir config && cp employees.example.json config/employees.json` and list your employees. `lithic_account_token` is the employee's Lithic account; leave it empty to use your program's default account (fine for sandbox testing).
3. Create a Slack app:
   - Enable **Incoming Webhooks** for the approval channel → `SPEND_APPROVAL_WEBHOOK`.
   - Copy **Basic Information → Signing Secret** → `SLACK_SIGNING_SECRET`.
   - Enable **Interactivity** with the Request URL `https://<your-host>/slack/interactivity`.
4. Run `docker compose up -d --build`. The listener binds to `127.0.0.1:8080`, so put an HTTPS reverse proxy or tunnel in front of it for Slack.
5. Point each MCP client at a server for its employee:

   ```
   docker run -i --rm --env-file .env -e SPEND_EMPLOYEE_ID=EMP_DEV_B \
     -v <project>_mcp_ledger_data:/data -v "$PWD/config:/config:ro" \
     mcp-spend-server:latest
   ```

## Tests

```
pip install -r requirements-dev.txt
pytest
```
