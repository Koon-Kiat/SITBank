from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from sqlalchemy.exc import DBAPIError

from app.ops import db_privileges


class Result:
    def __init__(self, value=None):
        self.value = value

    def scalar_one(self):
        return self.value

    def scalar_one_or_none(self):
        return self.value

    def all(self):
        return list(self.value or [])

    def scalars(self):
        return iter(self.value or [])


class SequentialConnection:
    def __init__(self, values, *, dialect="postgresql", in_transaction=False):
        self.values = iter(values)
        self.statements = []
        self.dialect = SimpleNamespace(name=dialect)
        self._in_transaction = in_transaction
        self.rollbacks = 0

    def execute(self, statement, params=None):
        self.statements.append((statement, params))
        value = next(self.values)
        if isinstance(value, BaseException):
            raise value
        return Result(value)

    def in_transaction(self):
        return self._in_transaction

    def rollback(self):
        self.rollbacks += 1
        self._in_transaction = False

    def begin(self):
        return Transaction()


class Transaction:
    def __init__(self):
        self.rollbacks = 0

    def rollback(self):
        self.rollbacks += 1


@pytest.mark.parametrize(
    ("admin_url", "migration_url", "schema", "message"),
    [
        ("", "postgresql://owner:fake@db.local/sitbank", "public", "ADMIN_DATABASE_URL is required"),
        ("postgresql://admin:fake@db.local/sitbank", "", "public", "DATABASE_MIGRATION_URL is required"),
        (
            "postgresql://admin:fake@db.local/sitbank",
            "postgresql://admin:fake@db.local/sitbank",
            "public",
            "must use different roles",
        ),
        (
            "postgresql://admin:fake@db.local/sitbank",
            "postgresql://owner:fake@db.local/sitbank",
            "unsafe-schema",
            "Schema name is not",
        ),
        (
            "postgresql://bad-role:fake@db.local/sitbank",
            "postgresql://owner:fake@db.local/sitbank",
            "public",
            "username must be",
        ),
        (
            "postgresql://admin@db.local/sitbank",
            "postgresql://owner:fake@db.local/sitbank",
            "public",
            "must include a password",
        ),
        (
            "postgresql://admin:fake@db.local/sitbank",
            "postgresql://admin:other@db.local/sitbank",
            "public",
            "must use different roles",
        ),
        (
            "postgresql://admin:fake@db.local/bad-name",
            "postgresql://owner:fake@db.local/bad-name",
            "public",
            "database name",
        ),
        (
            "postgresql://admin:fake@db.local/sitbank",
            "postgresql://owner:fake@db.local/other",
            "public",
            "must target the migration database",
        ),
    ],
)
def test_admin_privilege_input_validation_rejects_unsafe_boundaries(
    admin_url,
    migration_url,
    schema,
    message,
):
    with pytest.raises(RuntimeError, match=message):
        db_privileges._validate_admin_privilege_inputs(
            admin_url=admin_url,
            migration_url=migration_url,
            schema=schema,
        )


def test_admin_privilege_input_validation_returns_safe_role_and_database():
    assert db_privileges._validate_admin_privilege_inputs(
        admin_url="postgresql://admin_runtime:fake@db.local/sitbank",
        migration_url="postgresql://schema_owner:fake@db.local/sitbank",
        schema="public",
    ) == ("admin_runtime", "sitbank")


def test_identifier_and_table_helpers_fail_closed():
    assert db_privileges._is_identifier("safe_name")
    assert not db_privileges._is_identifier("")
    assert not db_privileges._is_identifier("1name")
    assert not db_privileges._is_identifier("bad-name")
    assert db_privileges._quote_identifier("safe_name") == '"safe_name"'
    assert db_privileges._qualified_table_name("public", "events") == '"public"."events"'
    assert db_privileges._create_probe_table_name("probe") == "probe_create"
    assert str(db_privileges._trusted_identifier_sql('DROP TABLE "public"."probe"'))
    with pytest.raises(RuntimeError, match="Unsafe PostgreSQL identifier"):
        db_privileges._quote_identifier("unsafe;drop")


def test_canonical_json_and_utc_helpers_are_deterministic():
    value = {
        "z": [True, b"bytes"],
        2: {"nested": 1},
        "a": None,
    }
    canonical = db_privileges._canonical_json_value(value)

    assert list(canonical) == ["2", "a", "z"]
    assert canonical["z"] == [True, "b'bytes'"]
    assert db_privileges._utc_iso("not-a-date") == "not-a-date"
    assert db_privileges._utc_iso(datetime(2026, 1, 2, 3, 4, 5)) == "2026-01-02T03:04:05Z"
    offset = datetime(2026, 1, 2, 11, 4, 5, tzinfo=timezone(timedelta(hours=8)))
    assert db_privileges._utc_iso(offset) == "2026-01-02T03:04:05Z"


def test_audit_probe_hash_supports_legacy_and_hmac_and_rejects_short_key():
    values = {
        "event_type": "probe",
        "outcome": "success",
        "ip_address": "local",
        "user_agent": "test",
        "correlation_id": "fake-correlation",
        "session_ref": None,
        "event_metadata": {"b": 2, "a": 1},
        "created_at": datetime(2026, 1, 2, tzinfo=timezone.utc),
        "previous_event_hash": "0" * 64,
        "hash_algorithm": db_privileges.LEGACY_AUDIT_HASH_ALGORITHM,
    }
    legacy = db_privileges._compute_audit_probe_hash(values, audit_hmac_key=None)
    hmac_values = {**values, "hash_algorithm": db_privileges.AUDIT_HASH_ALGORITHM}
    keyed = db_privileges._compute_audit_probe_hash(
        hmac_values,
        audit_hmac_key="fake-audit-key-" + ("x" * 32),
    )

    assert len(legacy) == len(keyed) == 64
    assert legacy != keyed
    with pytest.raises(RuntimeError, match="at least 32 characters"):
        db_privileges._compute_audit_probe_hash(hmac_values, audit_hmac_key="short")


def test_runtime_role_ownership_checks_accept_least_privilege_role():
    connection = SequentialConnection(
        [
            "schema_owner",
            False,
            "schema_owner",
            [],
            False,
            [],
        ]
    )

    db_privileges._assert_runtime_role_owns_no_schema_objects(
        connection,
        "runtime_role",
        "public",
    )
    assert len(connection.statements) == 6


@pytest.mark.parametrize(
    ("values", "message"),
    [
        (["runtime_role"], "owns the current database"),
        (["owner", True], "CREATE privilege on the current database"),
        (["owner", False, "runtime_role"], "owns schema public"),
        (
            ["owner", False, "schema_owner", [SimpleNamespace(relname="users")]],
            "owns schema objects: users",
        ),
        (["owner", False, "schema_owner", [], True], "CREATE privilege on schema public"),
        (
            ["owner", False, "schema_owner", [], False, [SimpleNamespace(extname="pgcrypto")]],
            "owns PostgreSQL extensions: pgcrypto",
        ),
    ],
)
def test_runtime_role_ownership_checks_reject_excess_privilege(values, message):
    with pytest.raises(RuntimeError, match=message):
        db_privileges._assert_runtime_role_owns_no_schema_objects(
            SequentialConnection(values),
            "runtime_role",
            "public",
        )


def test_probe_owner_and_trigger_contracts_fail_closed():
    db_privileges._assert_probe_table_owner(
        SequentialConnection(["schema_owner"]),
        schema="public",
        probe_table="probe",
        expected_owner="schema_owner",
    )
    with pytest.raises(RuntimeError, match="does not own"):
        db_privileges._assert_probe_table_owner(
            SequentialConnection(["other"]),
            schema="public",
            probe_table="probe",
            expected_owner="schema_owner",
        )

    trigger_names = {
        "security_audit_events_reject_update",
        "security_audit_events_reject_delete",
        "security_audit_events_reject_truncate",
    }
    db_privileges._assert_audit_append_only_triggers_installed(
        SequentialConnection([trigger_names, True]),
        schema="public",
    )
    with pytest.raises(RuntimeError, match="triggers are not installed"):
        db_privileges._assert_audit_append_only_triggers_installed(
            SequentialConnection([{"security_audit_events_reject_update"}]),
            schema="public",
        )
    with pytest.raises(RuntimeError, match="trigger function is not installed"):
        db_privileges._assert_audit_append_only_triggers_installed(
            SequentialConnection([trigger_names, False]),
            schema="public",
        )


def test_lock_audit_chain_is_postgres_only():
    sqlite = SequentialConnection([], dialect="sqlite")
    db_privileges._lock_audit_chain(sqlite)
    assert sqlite.statements == []

    postgres = SequentialConnection([None], dialect="postgresql")
    db_privileges._lock_audit_chain(postgres)
    assert len(postgres.statements) == 1


def test_extension_probe_prefers_known_order_and_rejects_missing_probe():
    connection = SequentialConnection([["citext", "pgcrypto"]])
    assert db_privileges._select_extension_probe(connection) == "citext"
    with pytest.raises(RuntimeError, match="No uninstalled known"):
        db_privileges._select_extension_probe(SequentialConnection([[]]))


def _denied_error(sqlstate):
    return DBAPIError(
        "statement",
        {},
        SimpleNamespace(pgcode=sqlstate, sqlstate=None),
        False,
    )


def test_privilege_denial_helpers_accept_only_expected_sqlstate():
    denied = SequentialConnection([_denied_error(db_privileges.PRIVILEGE_DENIED_SQLSTATE)])
    db_privileges._expect_privilege_denied(denied, "DROP TABLE x", "DROP TABLE")

    unexpected = SequentialConnection([_denied_error("99999")])
    with pytest.raises(RuntimeError, match="unexpected SQLSTATE 99999"):
        db_privileges._expect_privilege_denied(unexpected, "DROP TABLE x", "DROP TABLE")

    allowed = SequentialConnection([None])
    with pytest.raises(RuntimeError, match="unexpectedly succeeded"):
        db_privileges._expect_privilege_denied(allowed, "DROP TABLE x", "DROP TABLE")

    operation_connection = SequentialConnection([])
    db_privileges._expect_privilege_denied_operation(
        operation_connection,
        lambda: (_ for _ in ()).throw(
            _denied_error(db_privileges.PRIVILEGE_DENIED_SQLSTATE)
        ),
        "DELETE audit",
    )
    with pytest.raises(RuntimeError, match="unexpectedly succeeded"):
        db_privileges._expect_privilege_denied_operation(
            operation_connection,
            lambda: None,
            "DELETE audit",
        )


def test_sqlstate_supports_driver_attributes():
    assert db_privileges._sqlstate(_denied_error("42501")) == "42501"
    error = DBAPIError(
        "statement",
        {},
        SimpleNamespace(pgcode=None, sqlstate="42502"),
        False,
    )
    assert db_privileges._sqlstate(error) == "42502"
