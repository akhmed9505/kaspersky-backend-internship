#!/bin/sh
# Exercises a running HTTPS API with a new random identifier. No existing row is updated.
# Requires exported API_KEY and TLS_CERT_FILE; does not load .env or print credentials.
set -eu
: "${API_KEY:?Export API_KEY first}"
: "${TLS_CERT_FILE:?Export TLS_CERT_FILE first}"
base_url=${1:-https://localhost:8443}
case "$base_url" in https://*) ;; *) echo 'HTTPS URL required.' >&2; exit 1 ;; esac
command -v curl >/dev/null 2>&1 || { echo 'curl is required.' >&2; exit 1; }
command -v openssl >/dev/null 2>&1 || { echo 'OpenSSL is required.' >&2; exit 1; }
id=$(openssl rand -hex 16)
missing=$(openssl rand -hex 16)
while [ "$missing" = "$id" ]; do missing=$(openssl rand -hex 16); done

expect() {
    expected=$1
    method=$2
    resource=$3
    body=${4-}
    set -- --disable --silent --show-error --connect-timeout 5 --max-time 15 \
        --cacert "$TLS_CERT_FILE" --header @- --request "$method" \
        --output /dev/null --write-out '%{http_code}'
    if [ "$method" != GET ]; then
        set -- "$@" --header 'Content-Type: application/json' --data-binary "$body"
    fi
    status=$(printf 'X-API-Key: %s\n' "$API_KEY" | curl "$@" "$base_url$resource")
    if [ "$status" != "$expected" ]; then
        printf '%s %s: expected %s, received %s; stopping.\n' "$method" "$resource" "$expected" "$status" >&2
        exit 1
    fi
    printf '%s %s -> %s\n' "$method" "$resource" "$status"
}

# Stop on collision, authentication/transport failures or a concurrent creator.
# PUT is reached only after this invocation has successfully created the row.
expect 404 GET "/info/$id"
created=$(printf '{"md5":"%s","name":"Smoke.Initial","description":"HTTPS smoke test","severity":"high","file_type":"pe"}' "$id")
expect 201 POST /info "$created"
expect 200 GET "/info/$id"
expect 200 PUT "/info/$id" '{"name":"Smoke.Updated"}'
expect 200 GET "/info/$id"
expect 409 POST /info "$created"
expect 404 GET "/info/$missing"
printf 'HTTPS scenario passed. Created test MD5: %s (retained; API has no DELETE).\n' "$id"
