from __future__ import annotations

from app.extensions import db, limiter
from app.models import User
from conftest import _restore_test_app_state
from conftest import pytest_xdist_auto_num_workers


def test_shared_worker_app_reset_clears_rows_limiter_and_config(app):
    baseline_config = dict(app.config)
    original_cookie_name = app.config["SESSION_COOKIE_NAME"]
    with app.app_context():
        db.session.add(
            User(
                username="fixture-reset-customer",
                email="fixture.reset@example.test",
                password_hash="clearly-fake-not-a-real-password-hash",
                full_name="Fixture Reset Customer",
                phone_number="81234567",
                account_number="012345678901",
            )
        )
        db.session.commit()

    client = app.test_client()
    for _attempt in range(5):
        client.post(
            "/auth/login",
            json={"identifier": "unknown-before-reset", "password": "clearly-fake-password"},
        )
    app.config["SESSION_COOKIE_NAME"] = "__Host-mutated-test-cookie"
    app.extensions["password_reset_outbox"] = [{"body": "fake delivery"}]

    _restore_test_app_state(app, baseline_config)

    with app.app_context():
        assert db.session.query(User).count() == 0
    assert app.config["SESSION_COOKIE_NAME"] == original_cookie_name
    assert app.extensions["password_reset_outbox"] == []
    limiter.reset()
    response = app.test_client().post(
        "/auth/login",
        json={"identifier": "unknown-after-reset", "password": "clearly-fake-password"},
    )
    assert response.status_code == 401


def test_shared_worker_app_uses_per_process_memory_database(app):
    assert app.config["SQLALCHEMY_DATABASE_URI"] == "sqlite:///:memory:"
    assert app.config["TESTING"] is True


def test_xdist_auto_worker_count_is_bounded_for_sqlite_isolation(monkeypatch):
    monkeypatch.setattr("conftest.os.cpu_count", lambda: 32)
    assert pytest_xdist_auto_num_workers(None) == 4
    monkeypatch.setattr("conftest.os.cpu_count", lambda: 1)
    assert pytest_xdist_auto_num_workers(None) == 1
