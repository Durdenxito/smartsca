#!/usr/bin/env bash
set -euo pipefail
mkdir -p build/docs
java scripts/docs/JavaInventory.java backend/src/main/java build/docs/java.xml

# Use the same migration engine as the proposed application, in an ephemeral database.
if find backend/src/main/resources/db/migration -type f -name '*.sql' | grep -q .; then
  docker run --rm --network host \
    -v "$PWD/backend/src/main/resources/db/migration:/flyway/sql:ro" \
    -e FLYWAY_URL=jdbc:postgresql://localhost:5432/smartsca_docs \
    -e FLYWAY_USER -e FLYWAY_PASSWORD \
    redgate/flyway:13.9.0 migrate
fi
psql --no-psqlrc --set ON_ERROR_STOP=1 --tuples-only --no-align \
  --file scripts/docs/schema.sql > build/docs/schema.json
# Compose expands the required password, but only non-secret deployment metadata is documented.
POSTGRES_PASSWORD=docs-placeholder docker compose -f infra/compose.yml config --format json > build/docs/compose.json
