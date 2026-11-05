#!/bin/sh
# Creates development-only TLS files outside the repository; does not create .env.
set -eu
command -v openssl >/dev/null 2>&1 || { echo 'OpenSSL is required.' >&2; exit 1; }
directory=${1:-"$HOME/.local/share/kaspersky-backend-internship"}
umask 077
mkdir -p "$directory"
chmod 700 "$directory"
for file in server.key server.crt; do
    if [ -e "$directory/$file" ]; then
        echo 'Refusing to overwrite existing TLS files. Reuse them or choose a new directory.' >&2
        exit 1
    fi
done
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -noenc \
    -days 30 -subj '/CN=localhost' \
    -addext 'subjectAltName=DNS:localhost,DNS:app,IP:127.0.0.1' \
    -keyout "$directory/server.key" -out "$directory/server.crt"
# Compose file-backed secrets preserve host permissions. Allow UID 65532 to read
# mounted files; the host directory remains owner-only (0700).
chmod 444 "$directory/server.key" "$directory/server.crt"
printf 'Development TLS files created in %s\n' "$directory"
