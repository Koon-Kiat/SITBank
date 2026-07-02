"""Add admin maker-checker action requests.

Revision ID: 20260702_0021
Revises: 20260702_0020
Create Date: 2026-07-02 00:21:00
"""

from alembic import op
import sqlalchemy as sa


revision = "20260702_0021"
down_revision = "20260702_0020"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "admin_action_requests",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("operation_type", sa.String(length=80), nullable=False),
        sa.Column("target_type", sa.String(length=80), nullable=False),
        sa.Column("target_id", sa.String(length=64), nullable=False),
        sa.Column("operation_payload", sa.JSON(), nullable=False),
        sa.Column("requester_id", sa.Integer(), nullable=False),
        sa.Column("requester_role", sa.String(length=32), nullable=False),
        sa.Column("approver_id", sa.Integer(), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("reason_present", sa.Boolean(), nullable=False),
        sa.Column("reason_length", sa.Integer(), nullable=False),
        sa.Column("metadata_hmac", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("executed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            (
                "operation_type IN ("
                "'staff_deactivate', 'staff_reactivate', 'staff_reset_activation', "
                "'manual_recovery_approve', 'manual_recovery_deny', 'manual_recovery_complete'"
                ")"
            ),
            name="ck_admin_action_requests_operation_type",
        ),
        sa.CheckConstraint(
            "target_type IN ('staff_user', 'manual_recovery_request')",
            name="ck_admin_action_requests_target_type",
        ),
        sa.CheckConstraint(
            "requester_role IN ('root_admin')",
            name="ck_admin_action_requests_requester_role",
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'rejected', 'cancelled', 'expired', 'executed', 'execution_failed')",
            name="ck_admin_action_requests_status",
        ),
        sa.ForeignKeyConstraint(["approver_id"], ["users.id"]),
        sa.ForeignKeyConstraint(["requester_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_admin_action_requests_operation_type", "admin_action_requests", ["operation_type"])
    op.create_index("ix_admin_action_requests_target_type", "admin_action_requests", ["target_type"])
    op.create_index("ix_admin_action_requests_target_id", "admin_action_requests", ["target_id"])
    op.create_index("ix_admin_action_requests_requester_id", "admin_action_requests", ["requester_id"])
    op.create_index("ix_admin_action_requests_approver_id", "admin_action_requests", ["approver_id"])
    op.create_index("ix_admin_action_requests_status", "admin_action_requests", ["status"])
    op.create_index("ix_admin_action_requests_created_at", "admin_action_requests", ["created_at"])
    op.create_index("ix_admin_action_requests_expires_at", "admin_action_requests", ["expires_at"])
    op.create_index(
        "ix_admin_action_requests_status_expires_at",
        "admin_action_requests",
        ["status", "expires_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_admin_action_requests_status_expires_at", table_name="admin_action_requests")
    op.drop_index("ix_admin_action_requests_expires_at", table_name="admin_action_requests")
    op.drop_index("ix_admin_action_requests_created_at", table_name="admin_action_requests")
    op.drop_index("ix_admin_action_requests_status", table_name="admin_action_requests")
    op.drop_index("ix_admin_action_requests_approver_id", table_name="admin_action_requests")
    op.drop_index("ix_admin_action_requests_requester_id", table_name="admin_action_requests")
    op.drop_index("ix_admin_action_requests_target_id", table_name="admin_action_requests")
    op.drop_index("ix_admin_action_requests_target_type", table_name="admin_action_requests")
    op.drop_index("ix_admin_action_requests_operation_type", table_name="admin_action_requests")
    op.drop_table("admin_action_requests")
