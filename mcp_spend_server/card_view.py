"""Short-lived signed links that let a person view an approved card in Lithic's embedded card UI.

The link points at the Slack listener, which checks the signature and expiry and
then serves a page framing Lithic's card UI. The card number and CVV load in the
viewer's browser straight from Lithic and never pass through this server.

Enabled only when both CARD_VIEW_LINK_SECRET and PUBLIC_BASE_URL are set.
"""

import hashlib
import hmac
import os
import time
from typing import Optional
from urllib.parse import urlencode

LINK_TTL_SECONDS = 30 * 60
MAX_HUMAN_VIEWS = 5


def _secret() -> str:
    return os.environ.get("CARD_VIEW_LINK_SECRET", "")


def _base_url() -> str:
    return os.environ.get("PUBLIC_BASE_URL", "").rstrip("/")


def links_enabled() -> bool:
    return bool(_secret() and _base_url())


def _signature(task_id: str, expires: int) -> str:
    message = f"card-view:{task_id}:{expires}".encode()
    return hmac.new(_secret().encode(), message, hashlib.sha256).hexdigest()


def make_view_link(task_id: str, now: Optional[float] = None) -> Optional[str]:
    if not links_enabled():
        return None
    expires = int(now if now is not None else time.time()) + LINK_TTL_SECONDS
    query = urlencode({"task_id": task_id, "expires": expires, "sig": _signature(task_id, expires)})
    return f"{_base_url()}/cards/view?{query}"


def verify_view_link(task_id: str, expires: str, sig: str, now: Optional[float] = None) -> bool:
    if not links_enabled() or not task_id or not sig:
        return False
    try:
        expires_at = int(expires)
    except (TypeError, ValueError):
        return False
    if (now if now is not None else time.time()) > expires_at:
        return False
    return hmac.compare_digest(_signature(task_id, expires_at), sig)
