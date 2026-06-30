from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from collections.abc import Mapping, Sequence

from sqlalchemy import Column, DateTime, Integer, JSON, MetaData, String, Table, bindparam, create_engine, select, text
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.exc import DBAPIError


PRIVILEGE_DENIED_SQLSTATE = "42501"
CURRENT_USER_QUERY = "SELECT current_user"
KNOWN_EXTENSION_PROBES = ("pg_trgm", "hstore", "citext", "pgcrypto")
AUDIT_HASH_ALGORITHM = "hmac-sha256-v1"
LEGACY_AUDIT_HASH_ALGORITHM = "sha256-v1"
AUDIT_CHAIN_START_HASH = "0" * 64
AUDIT_CHAIN_ADVISORY_LOCK_ID = 6151467082736394621


@dataclass(frozen=True)
class RuntimePrivilegeVerification:
    runtime_role: str
    migration_role: str
    probe_table: str
    extension_probe: str
    audit_table: str


@dataclass(frozen=True)
class AuditPrivilegeApplication:
    runtime_role: str
    migration_role: str
    audit_table: str


@dataclass(frozen=True)
class AdminRuntimePrivilegeApplication:
    admin_role: str
    migration_role: str
    database: str
    schema: str


def apply_admin_runtime_database_privileges(
    *,
    admin_url: str,
    migration_url: str,
    schema: str = "public",
) -> AdminRuntimePrivilegeApplication:
    admin_role, database = _validate_admin_privilege_inputs(
        admin_url=admin_url,
        migration_url=migration_url,
        schema=schema,
    )
    migration_role = _apply_admin_runtime_grants(
        migration_url=migration_url,
        admin_role=admin_role,
        database=database,
        schema=schema,
    )
    _verify_admin_runtime_connection(
        admin_url=admin_url,
        admin_role=admin_role,
        database=database,
        schema=schema,
    )
    return AdminRuntimePrivilegeApplication(
        admin_role=admin_role,
        migration_role=migration_role,
        database=database,
        schema=schema,
    )


def _validate_admin_privilege_inputs(
    *,
    admin_url: str,
    migration_url: str,
    schema: str,
) -> tuple[str, str]:
    if not admin_url:
        raise RuntimeError("ADMIN_DATABASE_URL is required for admin privilege application")
    if not migration_url:
        raise RuntimeError("DATABASE_MIGRATION_URL is required for admin privilege application")
    if admin_url == migration_url:
        raise RuntimeError("ADMIN_DATABASE_URL and DATABASE_MIGRATION_URL must use different roles")
    if not _is_identifier(schema):
        raise RuntimeError("Schema name is not a safe PostgreSQL identifier")

    admin_config = make_url(admin_url)
    migration_config = make_url(migration_url)
    admin_role = str(admin_config.username or "")
    admin_password = str(admin_config.password or "")
    migration_config_role = str(migration_config.username or "")
    database = str(admin_config.database or "")
    if not _is_identifier(admin_role):
        raise RuntimeError("ADMIN_DATABASE_URL username must be a safe PostgreSQL role")
    if not admin_password:
        raise RuntimeError("ADMIN_DATABASE_URL must include a password")
    if admin_role == migration_config_role:
        raise RuntimeError("Admin runtime and migration connections must use different roles")
    if not _is_identifier(database):
        raise RuntimeError("ADMIN_DATABASE_URL database name is not a safe PostgreSQL identifier")
    if database != str(migration_config.database or ""):
        raise RuntimeError("ADMIN_DATABASE_URL must target the migration database")
    return admin_role, database


def _apply_admin_runtime_grants(
    *,
    migration_url: str,
    admin_role: str,
    database: str,
    schema: str,
) -> str:
    migration_engine = create_engine(migration_url)
    try:
        with migration_engine.begin() as connection:
            migration_role = str(connection.execute(text(CURRENT_USER_QUERY)).scalar_one())
            if admin_role == migration_role:
                raise RuntimeError("Admin runtime and migration connections are using the same role")
            current_database = str(connection.execute(text("SELECT current_database()")).scalar_one())
            if current_database != database:
                raise RuntimeError("Migration connection is not using the admin runtime database")

            quoted_admin_role = _quote_identifier(admin_role)
            quoted_migration_role = _quote_identifier(migration_role)
            quoted_database = _quote_identifier(database)
            qualified_schema = _quote_identifier(schema)
            role_exists = bool(
                connection.execute(
                    text("SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :role)"),
                    {"role": admin_role},
                ).scalar_one()
            )
            if not role_exists:
                raise RuntimeError(
                    "ADMIN_DATABASE_URL role must already exist; create or rotate it "
                    "with a PostgreSQL administrator before deployment"
                )

            connection.execute(
                _trusted_identifier_sql(
                    f"GRANT CONNECT ON DATABASE {quoted_database} TO {quoted_admin_role}"
                )
            )
            connection.execute(
                _trusted_identifier_sql(
                    f"GRANT USAGE ON SCHEMA {qualified_schema} TO {quoted_admin_role}"
                )
            )
            qualified_audit_table = _qualified_table_name(schema, "security_audit_events")
            connection.execute(
                _trusted_identifier_sql(
                    f"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA {qualified_schema} "
                    f"TO {quoted_admin_role}"
                )
            )
            connection.execute(
                _trusted_identifier_sql(
                    f"GRANT SELECT, INSERT ON TABLE {qualified_audit_table} TO {quoted_admin_role}"
                )
            )
            connection.execute(
                _trusted_identifier_sql(
                    f"REVOKE UPDATE, DELETE, TRUNCATE ON TABLE {qualified_audit_table} "
                    f"FROM {quoted_admin_role}"
                )
            )
            connection.execute(
                _trusted_identifier_sql(
                    f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA {qualified_schema} "
                    f"TO {quoted_admin_role}"
                )
            )
            connection.execute(
                _trusted_identifier_sql(
                    f"ALTER DEFAULT PRIVILEGES FOR ROLE {quoted_migration_role} "
                    f"IN SCHEMA {qualified_schema} GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES "
                    f"TO {quoted_admin_role}"
                )
            )
            connection.execute(
                _trusted_identifier_sql(
                    f"ALTER DEFAULT PRIVILEGES FOR ROLE {quoted_migration_role} "
                    f"IN SCHEMA {qualified_schema} GRANT USAGE, SELECT ON SEQUENCES "
                    f"TO {quoted_admin_role}"
                )
            )
    finally:
        migration_engine.dispose()
    return migration_role


def _verify_admin_runtime_connection(
    *,
    admin_url: str,
    admin_role: str,
    database: str,
    schema: str,
) -> None:
    admin_engine = create_engine(admin_url)
    try:
        with admin_engine.connect() as admin_connection:
            connected_admin_role = str(
                admin_connection.execute(text(CURRENT_USER_QUERY)).scalar_one()
            )
            if connected_admin_role != admin_role:
                raise RuntimeError(
                    "ADMIN_DATABASE_URL did not authenticate as the configured role"
                )
            connected_database = str(
                admin_connection.execute(text("SELECT current_database()")).scalar_one()
            )
            if connected_database != database:
                raise RuntimeError(
                    "ADMIN_DATABASE_URL did not authenticate to the configured database"
                )
            _assert_admin_runtime_database_privileges(
                admin_connection,
                schema=schema,
            )
    finally:
        admin_engine.dispose()


def _assert_admin_runtime_database_privileges(connection, *, schema: str) -> None:
    required_table_privileges = {
        "users": ("SELECT", "INSERT", "UPDATE"),
        "staff_invites": ("SELECT", "INSERT", "UPDATE"),
        "manual_recovery_requests": ("SELECT", "UPDATE"),
        "auth_attempt_counters": ("SELECT", "INSERT", "UPDATE", "DELETE"),
        "totp_replay_records": ("SELECT", "INSERT"),
        "server_side_sessions": ("SELECT", "INSERT", "UPDATE", "DELETE"),
        "security_audit_events": ("SELECT", "INSERT"),
    }
    for table_name, privileges in required_table_privileges.items():
        qualified_table = f"{schema}.{table_name}"
        for privilege in privileges:
            has_privilege = bool(
                connection.execute(
                    text(
                        "SELECT has_table_privilege("
                        "current_user, :table_name, :privilege"
                        ")"
                    ),
                    {"table_name": qualified_table, "privilege": privilege},
                ).scalar_one()
            )
            if not has_privilege:
                raise RuntimeError(
                    f"ADMIN_DATABASE_URL role is missing {privilege} on {qualified_table}"
                )

    audit_table = f"{schema}.security_audit_events"
    for privilege in ("UPDATE", "DELETE", "TRUNCATE"):
        has_privilege = bool(
            connection.execute(
                text(
                    "SELECT has_table_privilege("
                    "current_user, :table_name, :privilege"
                    ")"
                ),
                {"table_name": audit_table, "privilege": privilege},
            ).scalar_one()
        )
        if has_privilege:
            raise RuntimeError(
                f"ADMIN_DATABASE_URL role must not have {privilege} on {audit_table}"
            )

    for sequence_name in ("users_id_seq", "security_audit_events_id_seq"):
        qualified_sequence = f"{schema}.{sequence_name}"
        has_usage = bool(
            connection.execute(
                text(
                    "SELECT has_sequence_privilege("
                    "current_user, :sequence_name, 'USAGE'"
                    ")"
                ),
                {"sequence_name": qualified_sequence},
            ).scalar_one()
        )
        if not has_usage:
            raise RuntimeError(
                f"ADMIN_DATABASE_URL role is missing USAGE on {qualified_sequence}"
            )


def apply_runtime_audit_table_privileges(
    *,
    runtime_url: str,
    migration_url: str,
    schema: str = "public",
    audit_table: str = "security_audit_events",
) -> AuditPrivilegeApplication:
    if not migration_url:
        raise RuntimeError("DATABASE_MIGRATION_URL is required for audit privilege application")
    if runtime_url == migration_url:
        raise RuntimeError("DATABASE_URL and DATABASE_MIGRATION_URL must use different roles")
    if not _is_identifier(schema) or not _is_identifier(audit_table):
        raise RuntimeError("Audit privilege target is not a safe PostgreSQL identifier")

    runtime_engine = create_engine(runtime_url)
    migration_engine = create_engine(migration_url)
    try:
        with runtime_engine.connect() as runtime_connection:
            runtime_role = str(runtime_connection.execute(text(CURRENT_USER_QUERY)).scalar_one())
        with migration_engine.begin() as migration_connection:
            migration_role = str(migration_connection.execute(text(CURRENT_USER_QUERY)).scalar_one())
            if runtime_role == migration_role:
                raise RuntimeError("Runtime and migration connections are using the same role")
            qualified_table = _qualified_table_name(schema, audit_table)
            quoted_runtime_role = _quote_identifier(runtime_role)
            migration_connection.execute(
                _trusted_identifier_sql(
                    f"GRANT SELECT, INSERT ON TABLE {qualified_table} TO {quoted_runtime_role}"
                )
            )
            migration_connection.execute(
                _trusted_identifier_sql(
                    f"REVOKE UPDATE, DELETE, TRUNCATE ON TABLE {qualified_table} "
                    f"FROM {quoted_runtime_role}"
                )
            )
            migration_connection.execute(
                _trusted_identifier_sql(
                    f"REVOKE UPDATE, DELETE, TRUNCATE ON TABLE {qualified_table} FROM PUBLIC"
                )
            )
    finally:
        runtime_engine.dispose()
        migration_engine.dispose()

    return AuditPrivilegeApplication(
        runtime_role=runtime_role,
        migration_role=migration_role,
        audit_table=f"{schema}.{audit_table}",
    )


def verify_runtime_database_privileges(
    *,
    runtime_url: str,
    migration_url: str,
    schema: str = "public",
    audit_hmac_key: str | None = None,
) -> RuntimePrivilegeVerification:
    if not migration_url:
        raise RuntimeError("DATABASE_MIGRATION_URL is required for runtime privilege verification")
    if runtime_url == migration_url:
        raise RuntimeError("DATABASE_URL and DATABASE_MIGRATION_URL must use different roles")
    if not _is_identifier(schema):
        raise RuntimeError("Schema name is not a safe PostgreSQL identifier")

    runtime_engine = create_engine(runtime_url)
    migration_engine = create_engine(migration_url)
    probe_table = f"sitbank_privilege_probe_{uuid.uuid4().hex}"
    create_probe_table_name = _create_probe_table_name(probe_table)
    create_probe_table = (
        f"CREATE TABLE {_qualified_table_name(schema, probe_table)} "
        "(id integer GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY, marker text NOT NULL)"
    )

    try:
        with migration_engine.begin() as migration_connection:
            migration_role = str(
                migration_connection.execute(text(CURRENT_USER_QUERY)).scalar_one()
            )
            _assert_audit_append_only_triggers_installed(migration_connection, schema=schema)
            migration_connection.execute(_trusted_identifier_sql(create_probe_table))

        try:
            with runtime_engine.connect() as runtime_connection:
                runtime_role = str(runtime_connection.execute(text(CURRENT_USER_QUERY)).scalar_one())
                if runtime_role == migration_role:
                    raise RuntimeError("Runtime and migration connections are using the same role")
                _assert_runtime_role_owns_no_schema_objects(runtime_connection, runtime_role, schema)
                _assert_probe_table_owner(
                    runtime_connection,
                    schema=schema,
                    probe_table=probe_table,
                    expected_owner=migration_role,
                )
                _assert_runtime_dml_allowed(runtime_connection, schema=schema, probe_table=probe_table)
                _assert_audit_table_append_only(
                    runtime_connection,
                    schema=schema,
                    audit_hmac_key=audit_hmac_key,
                )
                _expect_privilege_denied(
                    runtime_connection,
                    f"ALTER TABLE {_qualified_table_name(schema, probe_table)} "
                    "ADD COLUMN should_not_exist integer",
                    "ALTER TABLE",
                )
                _expect_privilege_denied(
                    runtime_connection,
                    f"DROP TABLE {_qualified_table_name(schema, probe_table)}",
                    "DROP TABLE",
                )
                _expect_privilege_denied(
                    runtime_connection,
                    f"CREATE TABLE {_qualified_table_name(schema, create_probe_table_name)} "
                    "(id integer)",
                    "CREATE TABLE",
                )
                extension_probe = _select_extension_probe(runtime_connection)
                _expect_privilege_denied(
                    runtime_connection,
                    f"CREATE EXTENSION {_quote_identifier(extension_probe)}",
                    "CREATE EXTENSION",
                )
        finally:
            _drop_probe_table(migration_engine, schema=schema, probe_table=probe_table)
    finally:
        runtime_engine.dispose()
        migration_engine.dispose()

    return RuntimePrivilegeVerification(
        runtime_role=runtime_role,
        migration_role=migration_role,
        probe_table=probe_table,
        extension_probe=extension_probe,
        audit_table=f"{schema}.security_audit_events",
    )


def _assert_runtime_role_owns_no_schema_objects(connection, runtime_role: str, schema: str) -> None:
    database_owner = connection.execute(
        text("SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname = current_database()")
    ).scalar_one()
    if database_owner == runtime_role:
        raise RuntimeError("Runtime role owns the current database")

    can_create_database_objects = connection.execute(
        text("SELECT has_database_privilege(current_user, current_database(), 'CREATE')")
    ).scalar_one()
    if can_create_database_objects:
        raise RuntimeError("Runtime role has CREATE privilege on the current database")

    schema_owner = connection.execute(
        text(
            """
            SELECT pg_get_userbyid(nspowner)
            FROM pg_namespace
            WHERE nspname = :schema
            """
        ),
        {"schema": schema},
    ).scalar_one()
    if schema_owner == runtime_role:
        raise RuntimeError(f"Runtime role owns schema {schema}")

    rows = connection.execute(
        text(
            """
            SELECT c.relname
            FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            JOIN pg_roles r ON r.oid = c.relowner
            WHERE n.nspname = :schema
              AND r.rolname = :runtime_role
              AND c.relkind IN ('r', 'p', 'S', 'v', 'm')
              AND c.relpersistence <> 't'
            ORDER BY c.relname
            """
        ),
        {"schema": schema, "runtime_role": runtime_role},
    ).all()
    if rows:
        owned = ", ".join(row.relname for row in rows[:5])
        raise RuntimeError(f"Runtime role owns schema objects: {owned}")

    can_create_schema = connection.execute(
        text("SELECT has_schema_privilege(current_user, :schema, 'CREATE')"),
        {"schema": schema},
    ).scalar_one()
    if can_create_schema:
        raise RuntimeError(f"Runtime role has CREATE privilege on schema {schema}")

    extensions = connection.execute(
        text(
            """
            SELECT e.extname
            FROM pg_extension e
            JOIN pg_roles r ON r.oid = e.extowner
            WHERE r.rolname = :runtime_role
            ORDER BY e.extname
            """
        ),
        {"runtime_role": runtime_role},
    ).all()
    if extensions:
        owned = ", ".join(row.extname for row in extensions[:5])
        raise RuntimeError(f"Runtime role owns PostgreSQL extensions: {owned}")


def _assert_probe_table_owner(connection, *, schema: str, probe_table: str, expected_owner: str) -> None:
    owner = connection.execute(
        text(
            """
            SELECT pg_get_userbyid(c.relowner)
            FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = :schema AND c.relname = :probe_table
            """
        ),
        {"schema": schema, "probe_table": probe_table},
    ).scalar_one()
    if owner != expected_owner:
        raise RuntimeError("Migration role does not own the privilege probe table")


def _assert_runtime_dml_allowed(connection, *, schema: str, probe_table: str) -> None:
    table = Table(
        probe_table,
        MetaData(),
        Column("id", Integer),
        Column("marker", String),
        schema=schema,
    )
    if connection.in_transaction():
        connection.rollback()
    with connection.begin():
        inserted_id = connection.execute(
            table.insert().values(marker="initial").returning(table.c.id)
        ).scalar_one()
        selected_marker = connection.execute(
            select(table.c.marker).where(table.c.id == inserted_id)
        ).scalar_one()
        if selected_marker != "initial":
            raise RuntimeError("Runtime role could not read back inserted probe data")
        connection.execute(table.update().where(table.c.id == inserted_id).values(marker="updated"))
        connection.execute(table.delete().where(table.c.id == inserted_id))


def _assert_audit_table_append_only(
    connection,
    *,
    schema: str,
    audit_hmac_key: str | None,
) -> int:
    table = Table(
        "security_audit_events",
        MetaData(),
        Column("id", Integer),
        Column("event_type", String),
        Column("outcome", String),
        Column("ip_address", String),
        Column("user_agent", String),
        Column("correlation_id", String),
        Column("session_ref", String),
        Column("event_metadata", JSON),
        Column("previous_event_hash", String),
        Column("event_hash", String),
        Column("hash_algorithm", String),
        Column("created_at", DateTime(timezone=True)),
        schema=schema,
    )
    if connection.in_transaction():
        connection.rollback()
    with connection.begin():
        _lock_audit_chain(connection)
        previous_event_hash = connection.execute(
            select(table.c.event_hash)
            .where(table.c.event_hash.is_not(None))
            .order_by(table.c.id.desc())
            .limit(1)
        ).scalar_one_or_none()
        hash_algorithm = AUDIT_HASH_ALGORITHM if audit_hmac_key else LEGACY_AUDIT_HASH_ALGORITHM
        event_values = {
            "event_type": "privilege_probe",
            "outcome": "success",
            "ip_address": "privilege-check",
            "user_agent": "privilege-check",
            "correlation_id": str(uuid.uuid4()),
            "session_ref": None,
            "event_metadata": {"probe": "runtime_append_only"},
            "previous_event_hash": str(previous_event_hash or AUDIT_CHAIN_START_HASH),
            "hash_algorithm": hash_algorithm,
            "created_at": datetime.now(timezone.utc),
        }
        event_values["event_hash"] = _compute_audit_probe_hash(
            event_values,
            audit_hmac_key=audit_hmac_key,
        )
        inserted_id = connection.execute(
            table.insert()
            .values(**event_values)
            .returning(table.c.id)
        ).scalar_one()
        selected_event_type = connection.execute(
            select(table.c.event_type).where(table.c.id == inserted_id)
        ).scalar_one()
        if selected_event_type != "privilege_probe":
            raise RuntimeError("Runtime role could not read back inserted audit probe data")
    _expect_privilege_denied_operation(
        connection,
        lambda: connection.execute(
            table.update().where(table.c.id == inserted_id).values(outcome="tampered")
        ),
        "UPDATE security_audit_events",
    )
    _expect_privilege_denied_operation(
        connection,
        lambda: connection.execute(table.delete().where(table.c.id == inserted_id)),
        "DELETE security_audit_events",
    )
    _expect_privilege_denied(
        connection,
        f"TRUNCATE TABLE {_qualified_table_name(schema, 'security_audit_events')}",
        "TRUNCATE security_audit_events",
    )
    return int(inserted_id)


def _assert_audit_append_only_triggers_installed(connection, *, schema: str) -> None:
    trigger_names = set(
        connection.execute(
            text(
                """
                SELECT t.tgname
                FROM pg_trigger t
                JOIN pg_class c ON c.oid = t.tgrelid
                JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE n.nspname = :schema
                  AND c.relname = 'security_audit_events'
                  AND NOT t.tgisinternal
                  AND t.tgname IN (
                    'security_audit_events_reject_update',
                    'security_audit_events_reject_delete',
                    'security_audit_events_reject_truncate'
                  )
                """
            ),
            {"schema": schema},
        ).scalars()
    )
    if trigger_names != {
        "security_audit_events_reject_update",
        "security_audit_events_reject_delete",
        "security_audit_events_reject_truncate",
    }:
        raise RuntimeError("security_audit_events append-only triggers are not installed")

    function_exists = connection.execute(
        text(
            """
            SELECT EXISTS (
                SELECT 1
                FROM pg_proc p
                JOIN pg_namespace n ON n.oid = p.pronamespace
                WHERE n.nspname = :schema
                  AND p.proname = 'security_audit_events_reject_mutation'
            )
            """
        ),
        {"schema": schema},
    ).scalar_one()
    if not function_exists:
        raise RuntimeError("security_audit_events append-only trigger function is not installed")


def _lock_audit_chain(connection) -> None:
    if connection.dialect.name != "postgresql":
        return
    connection.execute(
        text("SELECT pg_advisory_xact_lock(:lock_id)"),
        {"lock_id": AUDIT_CHAIN_ADVISORY_LOCK_ID},
    )


def _compute_audit_probe_hash(
    values: dict[str, object],
    *,
    audit_hmac_key: str | None,
) -> str:
    payload = {
        "event_type": values["event_type"],
        "outcome": values["outcome"],
        "user_id": None,
        "ip_address": values["ip_address"],
        "user_agent": values["user_agent"],
        "correlation_id": values["correlation_id"],
        "session_ref": values["session_ref"],
        "event_metadata": _canonical_json_value(values["event_metadata"]),
        "created_at": _utc_iso(values["created_at"]),
        "previous_event_hash": values["previous_event_hash"],
    }
    canonical_payload = json.dumps(payload, separators=(",", ":"), sort_keys=True, ensure_ascii=True)
    encoded_payload = canonical_payload.encode("utf-8")
    if values.get("hash_algorithm") == AUDIT_HASH_ALGORITHM:
        if not audit_hmac_key or len(audit_hmac_key) < 32:
            raise RuntimeError("SECURITY_AUDIT_HMAC_KEY must be at least 32 characters")
        return hmac.new(audit_hmac_key.encode("utf-8"), encoded_payload, hashlib.sha256).hexdigest()
    return hashlib.sha256(encoded_payload).hexdigest()


def _canonical_json_value(value: object) -> object:
    if isinstance(value, bool | int | float | str) or value is None:
        return value
    if isinstance(value, Mapping):
        return {
            str(key): _canonical_json_value(value[key])
            for key in sorted(value, key=lambda item: str(item))
        }
    if isinstance(value, Sequence) and not isinstance(value, bytes | bytearray | str):
        return [_canonical_json_value(item) for item in value]
    return str(value)


def _utc_iso(value: object) -> str:
    if not isinstance(value, datetime):
        return str(value)
    timestamp = value
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    return timestamp.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _expect_privilege_denied(connection, statement: str, label: str) -> None:
    if connection.in_transaction():
        connection.rollback()
    transaction = connection.begin()
    try:
        connection.execute(text(statement))
    except DBAPIError as exc:
        transaction.rollback()
        if _sqlstate(exc) != PRIVILEGE_DENIED_SQLSTATE:
            raise RuntimeError(f"{label} failed with unexpected SQLSTATE {_sqlstate(exc)}") from exc
        return
    else:
        transaction.rollback()
        raise RuntimeError(f"Runtime role unexpectedly succeeded at {label}")


def _expect_privilege_denied_operation(connection, operation, label: str) -> None:
    if connection.in_transaction():
        connection.rollback()
    transaction = connection.begin()
    try:
        operation()
    except DBAPIError as exc:
        transaction.rollback()
        if _sqlstate(exc) != PRIVILEGE_DENIED_SQLSTATE:
            raise RuntimeError(f"{label} failed with unexpected SQLSTATE {_sqlstate(exc)}") from exc
        return
    else:
        transaction.rollback()
        raise RuntimeError(f"Runtime role unexpectedly succeeded at {label}")


def _select_extension_probe(connection) -> str:
    rows = connection.execute(
        text(
            """
            SELECT name
            FROM pg_available_extensions
            WHERE installed_version IS NULL AND name IN :extension_names
            """
        ).bindparams(bindparam("extension_names", expanding=True)),
        {"extension_names": KNOWN_EXTENSION_PROBES},
    ).scalars()
    available = set(rows)
    for extension in KNOWN_EXTENSION_PROBES:
        if extension in available:
            return extension
    raise RuntimeError("No uninstalled known PostgreSQL extension is available to test")


def _drop_probe_table(engine: Engine, *, schema: str, probe_table: str) -> None:
    create_probe_table_name = _create_probe_table_name(probe_table)
    with engine.begin() as connection:
        connection.execute(
            _trusted_identifier_sql(
                f"DROP TABLE IF EXISTS {_qualified_table_name(schema, probe_table)}"
            )
        )
        connection.execute(
            _trusted_identifier_sql(
                f"DROP TABLE IF EXISTS "
                f"{_qualified_table_name(schema, create_probe_table_name)}"
            )
        )


def _sqlstate(exc: DBAPIError) -> str:
    return str(getattr(exc.orig, "pgcode", "") or getattr(exc.orig, "sqlstate", "") or "")


def _quote_identifier(identifier: str) -> str:
    if not _is_identifier(identifier):
        raise RuntimeError("Unsafe PostgreSQL identifier")
    return f'"{identifier}"'


def _trusted_identifier_sql(statement: str):
    # Dynamic DDL cannot bind PostgreSQL identifiers. Every caller constructs
    # this statement only from _quote_identifier/_qualified_table_name output.
    return text(statement)  # nosemgrep: python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text


def _qualified_table_name(schema: str, table_name: str) -> str:
    return f"{_quote_identifier(schema)}.{_quote_identifier(table_name)}"


def _create_probe_table_name(probe_table: str) -> str:
    return f"{probe_table}_create"


def _is_identifier(value: str) -> bool:
    return bool(value) and value.replace("_", "a").isalnum() and value[0].isalpha()
