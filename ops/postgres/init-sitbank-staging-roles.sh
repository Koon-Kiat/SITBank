#!/usr/bin/env sh
set -eu

if [ "${POSTGRES_USER:-}" != "sitbank_owner" ]; then
    echo "POSTGRES_USER must be sitbank_owner for SITBank staging role bootstrap" >&2
    exit 1
fi
if [ "${POSTGRES_DB:-}" != "sitbank_staging" ]; then
    echo "POSTGRES_DB must be sitbank_staging for SITBank staging role bootstrap" >&2
    exit 1
fi

app_password="$(cat /run/secrets/postgres_app_password)"

psql --no-psqlrc --set ON_ERROR_STOP=1 \
    --username "${POSTGRES_USER}" \
    --dbname "${POSTGRES_DB}" \
    --set app_password="${app_password}" <<'SQL'
CREATE ROLE sitbank_app LOGIN PASSWORD :'app_password';

REVOKE ALL ON DATABASE sitbank_staging FROM PUBLIC;
GRANT CONNECT ON DATABASE sitbank_staging TO sitbank_app;

REVOKE ALL ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON SCHEMA public FROM sitbank_app;
ALTER SCHEMA public OWNER TO sitbank_owner;
GRANT USAGE ON SCHEMA public TO sitbank_app;

GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO sitbank_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO sitbank_app;

ALTER DEFAULT PRIVILEGES FOR ROLE sitbank_owner IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO sitbank_app;
ALTER DEFAULT PRIVILEGES FOR ROLE sitbank_owner IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO sitbank_app;
SQL
