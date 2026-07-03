"""Harden customer identity and MFA lifecycle state.

Revision ID: 20260703_0023
Revises: 20260703_0022
Create Date: 2026-07-03 12:00:00
"""

from alembic import op
import sqlalchemy as sa


revision = "20260703_0023"
down_revision = "20260703_0022"
branch_labels = None
depends_on = None


def _canonical_customer_email(value: str) -> str:
    normalized = str(value or "").strip().casefold()
    local, separator, domain = normalized.rpartition("@")
    if separator != "@" or not local or not domain:
        raise RuntimeError("Cannot canonicalize an invalid existing customer email")
    if domain in {"gmail.com", "googlemail.com"}:
        local = local.partition("+")[0].replace(".", "")
        domain = "gmail.com"
    if not local:
        raise RuntimeError("Cannot canonicalize an invalid existing customer email")
    return f"{local}@{domain}"


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("registration_email_canonical", sa.String(length=255), nullable=True),
    )
    op.add_column(
        "users",
        sa.Column("mfa_pending_started_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "users",
        sa.Column("mfa_pending_session_hash", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "recovery_codes",
        sa.Column(
            "hmac_version",
            sa.Integer(),
            nullable=False,
            server_default="2",
        ),
    )
    op.execute(sa.text("UPDATE recovery_codes SET hmac_version = 1"))

    if op.get_context().as_sql:
        op.execute(
            sa.text(
                "-- Online migration canonicalizes customer registration emails "
                "and rejects collisions before adding the unique index."
            )
        )
    else:
        connection = op.get_bind()
        users = sa.table(
            "users",
            sa.column("id", sa.Integer()),
            sa.column("email", sa.String()),
            sa.column("account_type", sa.String()),
            sa.column("registration_email_canonical", sa.String()),
        )
        seen: dict[str, int] = {}
        customer_rows = connection.execute(
            sa.select(users.c.id, users.c.email).where(
                users.c.account_type == "customer"
            )
        )
        for user_id, email in customer_rows:
            canonical = _canonical_customer_email(email)
            existing_id = seen.get(canonical)
            if existing_id is not None:
                raise RuntimeError(
                    "Canonical customer email collision detected; resolve duplicate "
                    f"customer records {existing_id} and {user_id} before migration"
                )
            seen[canonical] = int(user_id)
            connection.execute(
                users.update()
                .where(users.c.id == user_id)
                .values(registration_email_canonical=canonical)
            )

    op.create_index(
        "ix_users_registration_email_canonical",
        "users",
        ["registration_email_canonical"],
        unique=True,
        postgresql_where=sa.text("registration_email_canonical IS NOT NULL"),
        sqlite_where=sa.text("registration_email_canonical IS NOT NULL"),
    )


def downgrade() -> None:
    op.drop_index("ix_users_registration_email_canonical", table_name="users")
    with op.batch_alter_table("recovery_codes") as batch_op:
        batch_op.drop_column("hmac_version")
    with op.batch_alter_table("users") as batch_op:
        batch_op.drop_column("mfa_pending_session_hash")
        batch_op.drop_column("mfa_pending_started_at")
        batch_op.drop_column("registration_email_canonical")
