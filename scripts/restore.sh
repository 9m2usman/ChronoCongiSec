#!/bin/bash
set -euo pipefail

# ChronoCogniSec PostgreSQL Restore Script
# Usage: ./scripts/restore.sh <backup_file>
# WARNING: This DROPS and recreates the 'amsc' database. Never run on production without confirmation.

BACKUP_FILE="${1:?Usage: restore.sh <backup_file>}"

if [ ! -f "${BACKUP_FILE}" ]; then
    echo "[RESTORE] ERROR: File not found: ${BACKUP_FILE}"
    exit 1
fi

echo "[RESTORE] WARNING: This will replace all data in the 'amsc' database."
read -p "Continue? (y/N): " confirm
if [ "${confirm}" != "y" ] && [ "${confirm}" != "Y" ]; then
    echo "[RESTORE] Aborted."
    exit 0
fi

echo "[RESTORE] Dropping and recreating database..."
docker compose exec -T postgres psql -U amsc -d postgres -c "DROP DATABASE IF EXISTS amsc;" -c "CREATE DATABASE amsc;"

echo "[RESTORE] Restoring from ${BACKUP_FILE}..."
gunzip -c "${BACKUP_FILE}" | docker compose exec -T postgres psql -U amsc -d amsc

echo "[RESTORE] Done."