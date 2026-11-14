"""One-command check that your Lithic sandbox key works with this server.

Issues a $5 single-use sandbox card, reads it back, makes a card-view link, and
closes the card again. Prints only the last four digits, never the full number.

    LITHIC_API_KEY=... python sandbox_check.py
"""

import asyncio
import os
import sys

from card_issuer import CardDetailsUnavailable, LithicCardIssuer, SANDBOX, lithic_environment


async def main() -> int:
    if lithic_environment() != SANDBOX:
        print("This check only runs against the Lithic sandbox.")
        return 1
    if not os.environ.get("LITHIC_API_KEY"):
        print("Set LITHIC_API_KEY to your Lithic sandbox API key first.")
        return 1
    issuer = LithicCardIssuer()

    print("1/4 Creating a $5 single-use sandbox card...")
    card = await issuer.issue_single_use_card("sandbox-check", 500)
    print(f"    OK: card ending {card.last_four} ({card.state})")
    try:
        print("2/4 Reading the card details back...")
        try:
            details = await issuer.get_card_details(card.token)
            match = "match" if details.card_number.endswith(card.last_four) else "DO NOT match"
            print(f"    OK: details returned, last four {match}, expires {details.exp_month}/{details.exp_year}")
        except CardDetailsUnavailable as e:
            print(f"    Not available: {e}")

        print("3/4 Making a card-view link...")
        url = issuer.get_embed_url(card.token)
        print(f"    OK: {url.split('?')[0]} (link valid for one minute, not printed)")
    finally:
        print("4/4 Closing the card...")
        await issuer.close_card(card.token)
        print("    OK: card closed")
    print("\nAll good: your sandbox key works with the spend server.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(asyncio.run(main()))
    except Exception as e:
        print(f"\nFAILED: {type(e).__name__}: {e}")
        sys.exit(1)
