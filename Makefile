# The explicit version makes generation independent of globally installed tools.
OAPI_CODEGEN := go run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.8.1
API_SPEC := openapi.yaml
API_CONFIG := internal/api/oapi-codegen.yaml
API_OUTPUT := internal/delivery/http/generated/api.gen.go
COMPOSE := docker compose -p kaspersky-information-exchange

.PHONY: generate check-generated check-generated-build compose-config docker-build up down test-docker

# Generate atomically: a failed generator must not replace an existing artifact.
generate:
	mkdir -p $(dir $(API_OUTPUT))
	@set -eu; \
	generated_tmp=$$(mktemp "$(API_OUTPUT).XXXXXX"); \
	trap 'rm -f "$$generated_tmp"' EXIT HUP INT TERM; \
	$(OAPI_CODEGEN) -config $(API_CONFIG) -o "$$generated_tmp" $(API_SPEC); \
	test -s "$$generated_tmp"; \
	chmod 644 "$$generated_tmp"; \
	mv "$$generated_tmp" $(API_OUTPUT)

# Compare to a temporary file; no Git repository or working-tree writes required.
check-generated:
	@test -f $(API_OUTPUT) || { echo 'Generated file missing; run make generate first.' >&2; exit 1; }
	@set -eu; \
	generated_tmp=$$(mktemp); \
	trap 'rm -f "$$generated_tmp"' EXIT HUP INT TERM; \
	$(OAPI_CODEGEN) -config $(API_CONFIG) -o "$$generated_tmp" $(API_SPEC); \
	test -s "$$generated_tmp"; \
	diff -u $(API_OUTPUT) "$$generated_tmp"

check-generated-build:
	go build ./internal/delivery/http/generated

compose-config:
	$(COMPOSE) --profile integration config --quiet

docker-build:
	$(COMPOSE) build app

up:
	$(COMPOSE) up -d --build app

# Preserve the database volume. This operates only on our named Compose project.
down:
	$(COMPOSE) down

test-docker:
	$(COMPOSE) --profile integration run --build --rm integration-tests
