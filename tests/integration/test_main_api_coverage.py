from uuid import uuid4
from datetime import datetime

import pytest
from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.main import (
    register,
    login_json,
    create_calculation,
    list_calculations,
    get_calculation,
    update_calculation,
    delete_calculation,
)
from app.schemas.user import UserCreate, UserLogin
from app.schemas.calculation import CalculationBase, CalculationUpdate
from app.models.user import User


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_random_user_payload() -> dict:
    """
    Build a unique payload that matches UserCreate (including confirm_password).
    Using uuids keeps us from tripping uniqueness constraints between tests.
    """
    uid = uuid4().hex
    password = "Password123!"
    return {
        "first_name": "Cov",
        "last_name": "User",
        "email": f"cov_{uid}@example.com",
        "username": f"cov_user_{uid}",
        "password": password,
        "confirm_password": password,
    }


def _make_persisted_user(db: Session) -> User:
    """
    Create a simple active / verified user directly in the DB.
    This bypasses the API and avoids depending on register() behaviour.
    """
    uid = uuid4().hex
    user = User(
        first_name="Direct",
        last_name="User",
        email=f"direct_{uid}@example.com",
        username=f"direct_{uid}",
        hashed_password="dummy-hash",  # not used in these direct tests
        is_active=True,
        is_verified=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


# ---------------------------------------------------------------------------
# Coverage for register() and login_json()
# ---------------------------------------------------------------------------

def test_register_function_success_and_duplicate(db_session: Session) -> None:
    """
    Call register() directly to exercise the happy path and the duplicate-user path.
    This hits the error-handling branch in main.register.
    """
    payload = _make_random_user_payload()
    user_create = UserCreate(**payload)

    # First registration should succeed.
    user = register(user_create, db=db_session)
    assert isinstance(user, User)
    assert user.email == payload["email"]

    # Second registration with same data should raise HTTP 400 via ValueError.
    with pytest.raises(HTTPException) as excinfo:
        register(user_create, db=db_session)

    assert excinfo.value.status_code == 400
    assert "already" in str(excinfo.value.detail).lower()


def test_login_json_naive_expires_at_monkeypatched(db_session: Session, monkeypatch) -> None:
    """
    Hit the branch in login_json where expires_at is naive (no tzinfo),
    so main.py adjusts it to timezone-aware.
    """
    # Persist a real user in the DB
    user = _make_persisted_user(db_session)

    # Monkeypatch User.authenticate to return a naive expires_at
    def fake_authenticate(db, username, password):
        assert db is db_session
        return {
            "user": user,
            "access_token": "fake_access",
            "refresh_token": "fake_refresh",
            # naive datetime on purpose
            "expires_at": datetime.utcnow(),
        }

    monkeypatch.setattr(
        User,
        "authenticate",
        classmethod(lambda cls, db, username, password: fake_authenticate(db, username, password)),
    )

    login_data = UserLogin(username=user.username, password="does_not_matter")
    token_response = login_json(login_data, db=db_session)

    assert token_response.access_token == "fake_access"
    assert token_response.refresh_token == "fake_refresh"
    # After the branch runs, expires_at should have tzinfo
    assert token_response.expires_at.tzinfo is not None
    assert token_response.user_id == user.id
    assert token_response.username == user.username


# ---------------------------------------------------------------------------
# Direct function tests for CRUD calculation endpoints
# ---------------------------------------------------------------------------

def test_calculation_crud_direct_functions(db_session: Session) -> None:
    """
    Call the calculation endpoint functions directly rather than through HTTP.

    This covers:
      * create_calculation success path
      * list_calculations for a user
      * get_calculation success
      * update_calculation success
      * delete_calculation success
    """
    user = _make_persisted_user(db_session)

    # --- Create ---
    create_payload = CalculationBase(
        type="addition",          # must be a valid enum value
        inputs=[2, 5],            # inputs must be a list
    )
    created = create_calculation(
        calculation_data=create_payload,
        current_user=user,
        db=db_session,
    )

    assert created.user_id == user.id
    assert created.result == 7
    calc_id_str = str(created.id)

    # --- List ---
    listed = list_calculations(
        current_user=user,
        db=db_session,
    )
    assert any(c.id == created.id for c in listed)

    # --- Get (success) ---
    fetched = get_calculation(
        calc_id=calc_id_str,
        current_user=user,
        db=db_session,
    )
    assert fetched.id == created.id

    # --- Update ---
    update_payload = CalculationUpdate(
        inputs=[10, 5],          # list again
    )
    updated = update_calculation(
        calc_id=calc_id_str,
        calculation_update=update_payload,
        current_user=user,
        db=db_session,
    )
    assert updated.result == 15

    # --- Delete ---
    delete_calculation(
        calc_id=calc_id_str,
        current_user=user,
        db=db_session,
    )

    # After deletion, trying to get it again should raise 404
    with pytest.raises(HTTPException) as excinfo:
        get_calculation(
            calc_id=calc_id_str,
            current_user=user,
            db=db_session,
        )
    assert excinfo.value.status_code == 404
    assert "not found" in str(excinfo.value.detail).lower()


def test_get_update_delete_invalid_uuid_and_not_found(db_session: Session) -> None:
    """
    Cover the invalid-UUID (400) and not-found (404) branches of:
      * get_calculation
      * update_calculation
      * delete_calculation
    """
    user = _make_persisted_user(db_session)

    # --- Invalid UUID for get_calculation ---
    with pytest.raises(HTTPException) as excinfo:
        get_calculation(
            calc_id="this-is-not-a-uuid",
            current_user=user,
            db=db_session,
        )
    assert excinfo.value.status_code == 400

    # --- Invalid UUID for update_calculation ---
    with pytest.raises(HTTPException) as excinfo:
        update_calculation(
            calc_id="this-is-not-a-uuid",
            calculation_update=CalculationUpdate(inputs=[1, 2]),
            current_user=user,
            db=db_session,
        )
    assert excinfo.value.status_code == 400

    # --- Invalid UUID for delete_calculation ---
    with pytest.raises(HTTPException) as excinfo:
        delete_calculation(
            calc_id="this-is-not-a-uuid",
            current_user=user,
            db=db_session,
        )
    assert excinfo.value.status_code == 400

    # --- Well-formed UUID that does not exist should yield 404 for get/update/delete ---
    missing_id = str(uuid4())

    with pytest.raises(HTTPException) as excinfo:
        get_calculation(
            calc_id=missing_id,
            current_user=user,
            db=db_session,
        )
    assert excinfo.value.status_code == 404

    with pytest.raises(HTTPException) as excinfo:
        update_calculation(
            calc_id=missing_id,
            calculation_update=CalculationUpdate(inputs=[1, 2]),
            current_user=user,
            db=db_session,
        )
    assert excinfo.value.status_code == 404

    with pytest.raises(HTTPException) as excinfo:
        delete_calculation(
            calc_id=missing_id,
            current_user=user,
            db=db_session,
        )
    assert excinfo.value.status_code == 404
