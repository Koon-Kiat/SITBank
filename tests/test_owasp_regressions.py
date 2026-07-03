from __future__ import annotations

from _auth_flow_helpers import verify_registration_email

VALID_PASSWORD = "Correct-Horse-Battery-Staple-2026!"


def test_security_headers_are_present(client):
    response = client.get("/")

    assert response.status_code == 200
    assert response.headers["X-Frame-Options"] == "SAMEORIGIN"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
    assert "default-src 'self'" in response.headers["Content-Security-Policy"]
    assert response.headers["Cross-Origin-Resource-Policy"] == "same-origin"


def test_public_homepage_exposes_verification_and_student_disclaimer(client):
    response = client.get("/")
    html = response.get_data(as_text=True)
    verification_tag = (
        '<meta name="google-site-verification" '
        'content="TdWqsa4Ln9t_GIYl4Devi4rrU48Z7XNSue_PiImREJs">'
    )
    disclaimer = (
        "SITBank is a student cybersecurity project and demonstration site. "
        "Do not enter real banking credentials, card numbers, phone numbers, "
        "or personal financial information."
    )

    assert response.status_code == 200
    assert verification_tag in html
    assert html.index(verification_tag) < html.index("</head>")
    assert html.count(disclaimer) == 1


def test_external_next_parameter_cannot_create_an_open_redirect(client):
    verify_registration_email(client, "redirect@example.com")
    register = client.post(
        "/register",
        data={
            "username": "redirect01",
            "email": "redirect@example.com",
            "full_name": "Redirect User",
            "phone_number": "91234567",
            "password": VALID_PASSWORD,
            "confirm_password": VALID_PASSWORD,
        },
    )
    response = client.post(
        "/login?next=https://attacker.example/steal",
        data={"identifier": "redirect01", "password": VALID_PASSWORD},
        follow_redirects=False,
    )

    assert register.status_code == 302
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/mfa/setup")
    assert "attacker.example" not in response.headers["Location"]


def test_url_like_mass_assignment_field_is_rejected(client):
    response = client.post(
        "/auth/register",
        json={
            "username": "ssrfguard01",
            "email": "ssrfguard@example.com",
            "password": VALID_PASSWORD,
            "callback_url": "http://169.254.169.254/latest/meta-data/",
        },
    )

    assert response.status_code == 400
    assert response.get_json() == {"error": "Invalid request"}


def test_server_errors_do_not_disclose_tracebacks(mutable_app):
    original = mutable_app.config.get("PROPAGATE_EXCEPTIONS")
    mutable_app.config["PROPAGATE_EXCEPTIONS"] = False

    @mutable_app.get("/_owasp-error-disclosure-test")
    def raise_for_error_disclosure_test():
        raise RuntimeError("sensitive-internal-marker")

    try:
        response = mutable_app.test_client().get(
            "/_owasp-error-disclosure-test",
            headers={"Accept": "application/json"},
        )
    finally:
        mutable_app.config["PROPAGATE_EXCEPTIONS"] = original

    assert response.status_code == 500
    assert response.get_json() == {
        "error": "Server error. Please try again later."
    }
    assert b"sensitive-internal-marker" not in response.data
    assert b"Traceback" not in response.data
