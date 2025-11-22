# app/auth/redis.py

import time
from typing import Optional, Dict

# Simple in-memory blacklist: jti -> expires_at (unix timestamp or None)
_BLACKLIST: Dict[str, Optional[float]] = {}


async def add_to_blacklist(
    jti: str,
    expires_in: Optional[int] = None,
    expires_in_seconds: Optional[int] = None,
) -> None:
    """
    Add a token JTI to the blacklist with optional expiration.

    - If both expires_in and expires_in_seconds are provided,
      expires_in takes precedence.
    - If the chosen value is None, the token never expires.
    - If it is 0, the token expires immediately.
    """
    # Choose which TTL to use (tests call both styles)
    if expires_in is not None:
        ttl = expires_in
    else:
        ttl = expires_in_seconds

    if ttl is None:
        # Never expires
        expires_at: Optional[float] = None
    else:
        # Expire after ttl seconds (can be 0 → immediate)
        expires_at = time.time() + ttl

    _BLACKLIST[jti] = expires_at
    # No asyncio / trio calls here: works in both backends


async def is_blacklisted(jti: str) -> bool:
    """
    Check whether a JTI is blacklisted and not expired.
    Expired JTIs are removed.
    """
    sentinel = object()
    expires_at = _BLACKLIST.get(jti, sentinel)

    # Not present at all
    if expires_at is sentinel:
        return False

    # Present and no expiry → always blacklisted
    if expires_at is None:
        return True

    # Has expiry timestamp
    now = time.time()
    if now >= expires_at:
        # Expired → clean up
        del _BLACKLIST[jti]
        return False

    return True
