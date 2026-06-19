from __future__ import annotations

import smtplib
from dataclasses import dataclass
from email.message import EmailMessage
from typing import Any

from flask import current_app


@dataclass(frozen=True)
class EmailDelivery:
    to_address: str
    subject: str
    body: str


def send_security_email(to_address: str, subject: str, body: str) -> None:
    delivery = EmailDelivery(to_address=to_address, subject=subject, body=body)
    backend = str(current_app.config.get("PASSWORD_RESET_EMAIL_BACKEND", "console")).casefold()
    if backend == "console":
        _deliver_to_outbox(delivery)
        return
    if backend == "smtp":
        _deliver_smtp(delivery)
        return
    raise RuntimeError("Unsupported password reset email backend")


def password_reset_outbox() -> list[dict[str, Any]]:
    outbox = current_app.extensions.setdefault("password_reset_outbox", [])
    if not isinstance(outbox, list):
        current_app.extensions["password_reset_outbox"] = []
    return current_app.extensions["password_reset_outbox"]


def _deliver_to_outbox(delivery: EmailDelivery) -> None:
    if current_app.config.get("APP_ENV") == "production":
        raise RuntimeError("Console email backend is not allowed in production")
    password_reset_outbox().append(
        {
            "to": delivery.to_address,
            "subject": delivery.subject,
            "body": delivery.body,
        }
    )


def _deliver_smtp(delivery: EmailDelivery) -> None:
    sender = str(current_app.config["PASSWORD_RESET_EMAIL_FROM"])
    message = EmailMessage()
    message["From"] = sender
    message["To"] = delivery.to_address
    message["Subject"] = delivery.subject
    message.set_content(delivery.body)

    host = str(current_app.config["SMTP_HOST"])
    port = int(current_app.config["SMTP_PORT"])
    username = current_app.config.get("SMTP_USERNAME")
    password = current_app.config.get("SMTP_PASSWORD")
    use_tls = bool(current_app.config.get("SMTP_USE_TLS", True))

    with smtplib.SMTP(host, port, timeout=10) as smtp:
        if use_tls:
            smtp.starttls()
        if username and password:
            smtp.login(str(username), str(password))
        smtp.send_message(message)
