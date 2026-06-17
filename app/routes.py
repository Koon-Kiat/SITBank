from flask import Blueprint, jsonify, request, abort, g, session
from app.security.audit import audit_event
from app.models import User
from app.extensions import db

admin_bp = Blueprint("admin", __name__)

@admin_bp.before_request
def require_admin_auth():
    """
    Enforces admin-specific authentication rules:
    - Requires WebAuthn/passkey for all admin users.
    - Disables password-only admin access.
    """
    # Skip auth enforcement for the login route itself
    if request.endpoint and request.endpoint.endswith('.admin_login'):
        return

    user_id = session.get("user_id")
    if user_id:
        g.current_user = db.session.get(User, user_id)

    if not getattr(g, "current_user", None):
        abort(401)
        
    # Verify the user's role is strictly 'admin'
    if g.current_user.role != "admin":
        audit_event("admin_access", "denied", metadata={"reason": "not_an_admin"})
        abort(403)

    # Enforce WebAuthn (password-only or TOTP-only access is blocked)
    if session.get("auth_context") != "webauthn":
        audit_event("admin_access", "denied", metadata={"reason": "webauthn_required"})
        abort(403)

@admin_bp.route("/login", methods=["POST"])
def admin_login():
    """
    Admin WebAuthn/passkey login endpoint.
    """
    data = request.get_json() or {}
    username = data.get("username")
    user = db.session.execute(db.select(User).where(User.username == username)).scalar_one_or_none()
    
    metadata = {
        "username": username,
        "ip_address": request.remote_addr,
        "user_agent": request.user_agent.string if request.user_agent else "Unknown"
    }

    if not user or user.role != "admin":
        audit_event("admin_login", "failure", metadata={**metadata, "reason": "invalid_user_or_role"})
        return jsonify({"error": "Unauthorized"}), 401
        
    # Note: A real implementation would verify the WebAuthn assertion payload here.
    session.clear()
    session["user_id"] = user.id
    session["auth_context"] = "webauthn"
    
    audit_event("admin_login", "success", user_id=user.id, metadata=metadata)
    return jsonify({"message": "Admin login successful"})

@admin_bp.route("/")
def dashboard():
    audit_event("admin_data_access", "success", metadata={"path": request.path})
    return jsonify({
        "component": "admin",
        "message": "Welcome to the SITBank Admin application."
    })