from __future__ import annotations

from logging.config import fileConfig

from alembic import context
from flask import current_app
from sqlalchemy import create_engine
from sqlalchemy.engine import make_url


config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

db = current_app.extensions["migrate"].db
target_metadata = db.metadata


def get_engine_url() -> str:
    return _migration_database_url().replace("%", "%%")


def _migration_database_url() -> str:
    runtime_url = str(db.engine.url)
    migration_url = current_app.config.get("SQLALCHEMY_MIGRATION_DATABASE_URI")
    app_env = str(current_app.config.get("APP_ENV") or "").lower()

    if migration_url:
        migration_url = str(migration_url)
        _validate_migration_url(runtime_url, migration_url, app_env=app_env)
        return migration_url

    if app_env == "production":
        raise RuntimeError(
            "DATABASE_MIGRATION_URL or DATABASE_MIGRATION_URL_FILE is required "
            "for production migrations"
        )
    return runtime_url


def _validate_migration_url(runtime_url: str, migration_url: str, *, app_env: str) -> None:
    if app_env != "production":
        return

    runtime = make_url(runtime_url)
    migration = make_url(migration_url)
    if migration.username == runtime.username:
        raise RuntimeError("DATABASE_MIGRATION_URL must not use the runtime database role")
    if migration.database != runtime.database:
        raise RuntimeError("DATABASE_MIGRATION_URL must target the same database as DATABASE_URL")
    if migration.host != runtime.host or migration.port != runtime.port:
        raise RuntimeError("DATABASE_MIGRATION_URL must target the same PostgreSQL service as DATABASE_URL")


def run_migrations_offline() -> None:
    context.configure(
        url=get_engine_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    migration_url = _migration_database_url()
    if migration_url == str(db.engine.url):
        engine = db.engine
        dispose_engine = False
    else:
        engine = create_engine(migration_url)
        dispose_engine = True

    try:
        with engine.connect() as connection:
            context.configure(
                connection=connection,
                target_metadata=target_metadata,
                compare_type=True,
            )
            with context.begin_transaction():
                context.run_migrations()
    finally:
        if dispose_engine:
            engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
