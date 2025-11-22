# tests/integration/test_jwt.py

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from fastapi import HTTPException
from jose import jwt as jose_jwt

from app.auth.jwt import (
    verify_password,
    get_password_hash,
    create_token,
    decode_token,
    get_current_user,
)
from app.auth.redis import add_to_blacklist
from app.schemas.token import TokenType
from app.models.user import User
from app.core.config import get_settings

settings = get_settings()


def test_password_hash_and_verify():
    plain = "SuperSecure123!"
    hashed = get_password_hash(plain)

    assert hashed != plain
    assert verify_password(plain, hashed) is True
    assert verify_password("wrong-password", hashed) is False


def test_create_token_default_expiry_access():
    """Covers create_token() default expiry branch for ACCESS tokens."""
    user_id = str(uuid4())
    token = create_token(user_id=user_id, token_type=TokenType.ACCESS)
    assert isinstance(token, str)


def test_create_token_default_expiry_refresh():
    """Covers create_token() default expiry branch for REFRESH tokens."""
    user_id = str(uuid4())
    token = create_token(user_id=user_id, token_type=TokenType.REFRESH)
    assert isinstance(token, str)


def test_create_token_error_path(monkeypatch):
    """Force jwt.encode to raise, to hit the HTTP 500 path in create_token()."""

    def fake_encode(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr("app.auth.jwt.jwt.encode", fake_encode)

    with pytest.raises(HTTPException) as excinfo:
        create_token(user_id=str(uuid4()), token_type=TokenType.ACCESS)

    assert excinfo.value.status_code == 500
    assert "Could not create token" in excinfo.value.detail


@pytest.mark.anyio("asyncio")
async def test_create_and_decode_access_token(db_session):
    """Happy path: create and decode a valid ACCESS token."""
    user = User(
        first_name="JWT",
        last_name="User",
        email=f"jwt_user_{uuid4()}@example.com",
        username=f"jwt_user_{uuid4()}",
        hashed_password=get_password_hash("Password123!"),
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    token = create_token(
        user_id=user.id,
        token_type=TokenType.ACCESS,
        expires_delta=timedelta(minutes=5),
    )

    payload = await decode_token(token, TokenType.ACCESS)
    assert payload["sub"] == str(user.id)
    assert payload["type"] == TokenType.ACCESS.value
    assert "jti" in payload


@pytest.mark.anyio("asyncio")
async def test_decode_token_invalid_type_raises_http_401():
    """
    Create a token with a mismatched 'type' but valid signature so we hit
    the 'Invalid token type' branch.
    """
    user_id = str(uuid4())
    # encode with ACCESS secret but mark type as REFRESH
    payload = {
        "sub": user_id,
        "type": TokenType.REFRESH.value,  # wrong type
        "exp": datetime.now(timezone.utc) + timedelta(minutes=5),
        "iat": datetime.now(timezone.utc),
        "jti": "jti-invalid-type",
    }
    token = jose_jwt.encode(
        payload,
        settings.JWT_SECRET_KEY,  # same secret used for ACCESS in decode_token
        algorithm=settings.ALGORITHM,
    )

    with pytest.raises(HTTPException) as excinfo:
        await decode_token(token, TokenType.ACCESS)

    assert excinfo.value.status_code == 401
    assert "Invalid token type" in excinfo.value.detail


@pytest.mark.anyio("asyncio")
async def test_decode_token_expired_token_raises_http_401():
    """Create an already-expired token to hit the ExpiredSignatureError branch."""
    user_id = str(uuid4())
    payload = {
        "sub": user_id,
        "type": TokenType.ACCESS.value,
        "exp": datetime.now(timezone.utc) - timedelta(seconds=1),  # already expired
        "iat": datetime.now(timezone.utc) - timedelta(minutes=1),
        "jti": "jti-expired",
    }
    token = jose_jwt.encode(
        payload,
        settings.JWT_SECRET_KEY,
        algorithm=settings.ALGORITHM,
    )

    with pytest.raises(HTTPException) as excinfo:
        await decode_token(token, TokenType.ACCESS, verify_exp=True)

    assert excinfo.value.status_code == 401
    assert "expired" in excinfo.value.detail.lower()


@pytest.mark.anyio("asyncio")
async def test_blacklisted_token_is_rejected(db_session):
    """Covers the blacklist check branch in decode_token()."""
    user = User(
        first_name="Blacklisted",
        last_name="User",
        email=f"blacklist_{uuid4()}@example.com",
        username=f"blacklist_{uuid4()}",
        hashed_password=get_password_hash("Password123!"),
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    token = create_token(
        user.id,
        TokenType.ACCESS,
        expires_delta=timedelta(minutes=5),
    )

    payload = await decode_token(token, TokenType.ACCESS)
    jti = payload["jti"]

    await add_to_blacklist(jti, expires_in=60)

    with pytest.raises(HTTPException) as excinfo:
        await decode_token(token, TokenType.ACCESS)

    assert excinfo.value.status_code == 401
    assert "revoked" in excinfo.value.detail.lower()


@pytest.mark.anyio("asyncio")
async def test_get_current_user_returns_user(db_session):
    """Happy path for get_current_user()."""
    user = User(
        first_name="Current",
        last_name="User",
        email=f"current_{uuid4()}@example.com",
        username=f"current_{uuid4()}",
        hashed_password=get_password_hash("Password123!"),
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    token = create_token(
        user.id,
        TokenType.ACCESS,
        expires_delta=timedelta(minutes=5),
    )

    current_user = await get_current_user(token=token, db=db_session)

    assert current_user.id == user.id
    assert current_user.username == user.username
    assert current_user.is_active is True


@pytest.mark.anyio("asyncio")
async def test_get_current_user_inactive_user_raises_400(db_session):
    """Covers the 'Inactive user' branch."""
    user = User(
        first_name="Inactive",
        last_name="User",
        email=f"inactive_{uuid4()}@example.com",
        username=f"inactive_{uuid4()}",
        hashed_password=get_password_hash("Password123!"),
        is_active=False,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    token = create_token(
        user.id,
        TokenType.ACCESS,
        expires_delta=timedelta(minutes=5),
    )

    with pytest.raises(HTTPException) as excinfo:
        await get_current_user(token=token, db=db_session)

    assert excinfo.value.status_code == 400
    assert "Inactive user" in excinfo.value.detail


@pytest.mark.anyio("asyncio")
async def test_get_current_user_user_not_found_raises_404(db_session):
    """Covers the 'User not found' branch."""
    # use a random UUID that is NOT in the DB
    missing_user_id = str(uuid4())

    token = create_token(
        missing_user_id,
        TokenType.ACCESS,
        expires_delta=timedelta(minutes=5),
    )

    with pytest.raises(HTTPException) as excinfo:
        await get_current_user(token=token, db=db_session)

    assert excinfo.value.status_code == 404
    assert "User not found" in excinfo.value.detail


@pytest.mark.anyio("asyncio")
async def test_get_current_user_invalid_token_triggers_outer_exception(db_session):
    """
    Pass a completely invalid token so decode_token raises HTTPException,
    which is then wrapped by the outer 'except Exception as e' branch.
    """
    invalid_token = "this.is.not.a.jwt"

    with pytest.raises(HTTPException) as excinfo:
        await get_current_user(token=invalid_token, db=db_session)

    assert excinfo.value.status_code == 401
    # we don't assert the exact message, just that it's unauthorized
