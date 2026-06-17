import os
import pytest
from app.models import User, SecurityAuditEvent
from app.extensions import db
from app.security.passwords import hash_password
from app import create_app

def test_customer_app_configuration_bounds():
    """
    Proves the Customer application uses customer-specific namespaces,
    loads customer blueprints, and excludes admin routes.
    """
    os.environ["SITBANK_COMPONENT"] = "customer"
    app = create_app("testing")
    
    assert app.config["SESSION_COOKIE_NAME"] == "__Host-sitbank_session"
    assert app.config["SESSION_KEY_PREFIX"] == "session:"
    assert app.config["RATELIMIT_KEY_PREFIX"] == "ospbank:ratelimit:"
    assert app.config["PERMANENT_SESSION_LIFETIME"].total_seconds() == 900  # 15 mins
    
    # Customer routes are loaded, but admin is isolated
    assert "auth" in app.blueprints
    assert "web" in app.blueprints
    assert "admin" not in app.blueprints

def test_admin_app_configuration_bounds():
    """
    Proves the Admin application runs in a stricter namespace,
    uses different secret configs, and excludes public registration routes.
    """
    os.environ["SITBANK_COMPONENT"] = "admin"
    app = create_app("testing")
    
    assert app.config["SESSION_COOKIE_NAME"] == "__Host-sitbank_admin_session"
    assert app.config["SESSION_KEY_PREFIX"] == "admin_session:"
    assert app.config["RATELIMIT_KEY_PREFIX"] == "ospbank:admin_ratelimit:"
    assert app.config["PERMANENT_SESSION_LIFETIME"].total_seconds() == 600  # 10 mins
    
    # Admin routes are loaded, but customer endpoints (like self-registration) are excluded
    assert "admin" in app.blueprints
    assert "auth" not in app.blueprints
    assert "web" not in app.blueprints

def test_database_and_secret_isolation():
    """
    Proves the two applications parse different secret variables.
    """
    os.environ["SITBANK_COMPONENT"] = "customer"
    customer_app = create_app("testing")
    
    os.environ["SITBANK_COMPONENT"] = "admin"
    admin_app = create_app("testing")
    
    assert customer_app.config["SECRET_KEY"] != admin_app.config["SECRET_KEY"]
    assert customer_app.config["SQLALCHEMY_DATABASE_URI"] != admin_app.config["SQLALCHEMY_DATABASE_URI"]

def test_admin_route_requires_admin_auth_and_webauthn():
    """
    Proves admin route requires admin auth + WebAuthn/passkey, 
    and customer session cannot access admin.
    """
    os.environ["SITBANK_COMPONENT"] = "admin"
    app = create_app("testing")
    client = app.test_client()
    
    with app.app_context():
        db.create_all()
        admin = User(username="admin", email="admin@bank", password_hash=hash_password("test"), role="admin")
        customer = User(username="cust", email="cust@bank", password_hash=hash_password("test"), role="customer")
        db.session.add_all([admin, customer])
        db.session.commit()
        
        # 1. Unauthenticated -> 401
        assert client.get("/").status_code == 401
        
        # 2. Customer session cannot access admin -> 403
        with client.session_transaction() as sess:
            sess["user_id"] = customer.id
            sess["auth_context"] = "webauthn"
        assert client.get("/").status_code == 403

        # 3. Authenticated admin without WebAuthn -> 403
        with client.session_transaction() as sess:
            sess["user_id"] = admin.id
            sess["auth_context"] = "password"
        assert client.get("/").status_code == 403
        
        # 4. Authenticated admin with WebAuthn -> 200
        with client.session_transaction() as sess:
            sess["user_id"] = admin.id
            sess["auth_context"] = "webauthn"
        assert client.get("/").status_code == 200

def test_admin_login_success_failure_is_audited():
    """Proves admin login success/failure is audited correctly without leaking credentials."""
    os.environ["SITBANK_COMPONENT"] = "admin"
    app = create_app("testing")
    client = app.test_client()
    
    with app.app_context():
        db.create_all()
        admin = User(username="admin_logger", email="admin2@bank", password_hash=hash_password("test"), role="admin")
        db.session.add(admin)
        db.session.commit()
        
        client.post("/login", json={"username": "wrong_admin"})
        fail_event = db.session.query(SecurityAuditEvent).filter_by(event_type="admin_login", outcome="failure").first()
        assert fail_event is not None
        assert fail_event.event_metadata["reason"] == "invalid_user_or_role"
        
        client.post("/login", json={"username": "admin_logger"})
        success_event = db.session.query(SecurityAuditEvent).filter_by(event_type="admin_login", outcome="success").first()
        assert success_event is not None
        assert success_event.user_id == admin.id
        assert "ip_address" in success_event.event_metadata
        assert "user_agent" in success_event.event_metadata
        assert "password" not in success_event.event_metadata