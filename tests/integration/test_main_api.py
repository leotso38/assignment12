# tests/integration/test_main_api.py

import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health_endpoint_returns_ok():
    """
    Basic smoke test for the /health endpoint.
    Ensures the app is up and responding with the expected payload.
    """
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_register_validation_error_returns_422():
    """
    POST /auth/register with an invalid body should trigger FastAPI validation
    and return HTTP 422.
    """
    response = client.post("/auth/register", json={"foo": "bar"})
    assert response.status_code == 422


def test_register_success_and_duplicate():
    """
    Register a valid user → expect 201.
    Register the same user again → expect 400 from ValueError inside main.py.
    """
    payload = {
        "username": "johnsmith",
        "password": "Password123!",
        "confirm_password": "Password123!",
        "email": "john@example.com",
        "first_name": "John",
        "last_name": "Smith",
    }

    # First registration should succeed
    r1 = client.post("/auth/register", json=payload)
    assert r1.status_code == 201

    # Duplicate should trigger ValueError → 400
    r2 = client.post("/auth/register", json=payload)
    assert r2.status_code == 400
    assert "already" in r2.json()["detail"].lower() or "exists" in r2.json()["detail"].lower()


def test_login_json_invalid_credentials_returns_401():
    """
    POST /auth/login with non-existent credentials → 401.
    """
    payload = {"username": "nouser", "password": "WrongPass"}

    response = client.post("/auth/login", json=payload)

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid username or password"


def test_login_json_success():
    """
    Create a user, then log in with correct credentials.
    Expect HTTP 200 and a valid TokenResponse payload.
    """
    reg_payload = {
        "username": "loginuser",
        "password": "StrongPass123!",
        "confirm_password": "StrongPass123!",
        "email": "login@example.com",
        "first_name": "Log",
        "last_name": "In",
    }

    # Register user
    r = client.post("/auth/register", json=reg_payload)
    assert r.status_code == 201

    # Login
    login_payload = {
        "username": "loginuser",
        "password": "StrongPass123!",
    }

    res = client.post("/auth/login", json=login_payload)
    assert res.status_code == 200

    data = res.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["username"] == "loginuser"


def test_login_form_invalid_credentials_returns_401():
    """
    Form-based login (/auth/token) with wrong credentials should return 401.
    """
    res = client.post(
        "/auth/token",
        data={"username": "nouser", "password": "WrongPass"},
    )
    assert res.status_code == 401
    assert res.json()["detail"] == "Invalid username or password"


def test_login_form_success():
    """
    Register → login using OAuth2PasswordRequestForm (form-data).
    """
    payload = {
        "username": "formuser",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!",
        "email": "form@example.com",
        "first_name": "Form",
        "last_name": "User",
    }

    # Register user
    r = client.post("/auth/register", json=payload)
    assert r.status_code == 201

    # Login (form)
    res = client.post(
        "/auth/token",
        data={"username": "formuser", "password": "TestPass123!"},
    )
    assert res.status_code == 200
    assert "access_token" in res.json()
    assert res.json()["token_type"] == "bearer"
