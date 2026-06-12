from __future__ import annotations


VALID_PASSWORD = "Correct-Horse-Battery-Staple-2026!"


def test_security_headers_are_present(client):
    response = client.get("/")

    assert response.status_code == 200
    assert response.headers["X-Frame-Options"] == "SAMEORIGIN"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
    assert "default-src 'self'" in response.headers["Content-Security-Policy"]


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
    register = client.post(
        "/register",
        data={
            "username": "redirect01",
            "email": "redirect@example.com",
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


def test_server_errors_do_not_disclose_tracebacks(app):
    original = app.config.get("PROPAGATE_EXCEPTIONS")
    app.config["PROPAGATE_EXCEPTIONS"] = False

    @app.get("/_owasp-error-disclosure-test")
    def raise_for_error_disclosure_test():
        raise RuntimeError("sensitive-internal-marker")

    try:
        response = app.test_client().get(
            "/_owasp-error-disclosure-test",
            headers={"Accept": "application/json"},
        )
    finally:
        app.config["PROPAGATE_EXCEPTIONS"] = original

    assert response.status_code == 500
    assert response.get_json() == {
        "error": "Server error. Please try again later."
    }
    assert b"sensitive-internal-marker" not in response.data
    assert b"Traceback" not in response.data
