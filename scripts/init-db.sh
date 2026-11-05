#!/bin/sh
# Runs only on a new, project-owned PostgreSQL volume. No passwords in shell argv;
# psql quotes the role name, database name and password safely.
set -eu
: "${DB_PASSWORD:?DB_PASSWORD is required}"
export PGPASSWORD="$DB_PASSWORD"
# The official entrypoint uses a trusted local socket during initialization.
# The application role is not a superuser and does not receive CREATEDB.
psql --username "$POSTGRES_USER" --dbname postgres --set=ON_ERROR_STOP=1 \
    --set=app_user="$DB_USER" --set=app_db="$DB_NAME" <<'SQL'
\getenv app_password PGPASSWORD
CREATE ROLE :"app_user" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD :'app_password';
CREATE DATABASE :"app_db" OWNER :"app_user";
SQL
unset PGPASSWORD
