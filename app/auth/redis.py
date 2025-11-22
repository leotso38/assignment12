# app/auth/redis.py

from datetime import datetime, timedelta
from typing import Dict, Optional

# Simple in-memory blacklist for JWT IDs (jti)
# Key: jti (str)
# Value: expiry datetime (or None for no expiry)
_blacklist: Dict[str, Optional[datetime]] = {}


async def add_to_blacklist(jti: str, expires_in: Optional[int] = None) -> None:
    """
    Add a token's JTI to the blacklist.

    :param jti: The JWT ID to blacklist
    :param expires_in: Optional TTL in seconds (if provided by your JWT logic)
    """
    if expires_in is not None:
        expiry = datetime.utcnow() + timedelta(seconds=expires_in)
    else:
        expiry = None

    _blacklist[jti] = expiry


async def is_blacklisted(jti: str) -> bool:
    """
    Check if a JTI is blacklisted, respecting expiry if set.
    Expired entries are cleaned up on access.
    """
    if jti not in _blacklist:
        return False

    expiry = _blacklist[jti]

    # No expiry: always blacklisted
    if expiry is None:
        return True

    # If expired, remove and treat as not blacklisted
    if expiry < datetime.utcnow():
        _blacklist.pop(jti, None)
        return False

    return True
