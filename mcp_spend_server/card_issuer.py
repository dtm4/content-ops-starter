"""Issues single-use virtual cards through Lithic.

Defaults to Lithic's sandbox. Production needs both LITHIC_ENVIRONMENT=production
and ALLOW_PRODUCTION_CARDS=yes, so a stray env var can't start issuing real cards.
The full card number and CVV that Lithic may return are discarded here.
"""

import os
from dataclasses import dataclass
from typing import Optional

from lithic import AsyncLithic

SANDBOX = "sandbox"
PRODUCTION = "production"


@dataclass(frozen=True)
class IssuedCard:
    token: str
    last_four: str
    state: str


def lithic_environment() -> str:
    environment = os.environ.get("LITHIC_ENVIRONMENT", SANDBOX)
    if environment not in (SANDBOX, PRODUCTION):
        raise RuntimeError(f"LITHIC_ENVIRONMENT must be '{SANDBOX}' or '{PRODUCTION}', got {environment!r}")
    if environment == PRODUCTION and os.environ.get("ALLOW_PRODUCTION_CARDS") != "yes":
        raise RuntimeError("Refusing to issue real cards: set ALLOW_PRODUCTION_CARDS=yes to use production")
    return environment


class LithicCardIssuer:
    def __init__(self) -> None:
        self.environment = lithic_environment()
        api_key = os.environ.get("LITHIC_API_KEY")
        if not api_key:
            raise RuntimeError("LITHIC_API_KEY is not set")
        # The SDK defaults to production, so always pass the environment explicitly.
        self._client = AsyncLithic(api_key=api_key, environment=self.environment, max_retries=0)

    async def issue_single_use_card(self, task_id: str, spend_limit_cents: int,
                                    account_token: Optional[str] = None) -> IssuedCard:
        options = {"account_token": account_token} if account_token else {}
        card = await self._client.cards.create(
            type="SINGLE_USE",
            memo=f"agent-task:{task_id}",
            spend_limit=spend_limit_cents,
            spend_limit_duration="TRANSACTION",
            state="OPEN",
            **options,
        )
        return IssuedCard(token=card.token, last_four=card.last_four, state=card.state)

    async def close_card(self, card_token: str) -> None:
        # CLOSED is permanent at Lithic; the card can never be used again.
        await self._client.cards.update(card_token, state="CLOSED")


_issuer = None


def get_issuer():
    global _issuer
    if _issuer is None:
        _issuer = LithicCardIssuer()
    return _issuer
