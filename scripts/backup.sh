#!/bin/bash
set -euo pipefail

# ChronoCogniSec PostgreSQL Backup Script
# Usage: ./scripts/backup.sh [output_dir]
# Creates a timestamped pg_dump backup

OUTPUT_DIR="${1:-./backups}"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_FILE="${OUTPUT_DIR}/amsc_backup_${TIMESTAMP}.sql.gz"

mkdir -p "${OUTPUT_DIR}"

echo "[BACKUP] Starting PostgreSQL backup..."
docker compose exec -T postgres pg_dump -U amsc -d amsc | gzip > "${BACKUP_FILE}"

echo "[BACKUP] Created: ${BACKUP_FILE}"
echo "[BACKUP] Size: $(du -h "${BACKUP_FILE}" | cut -f1)"
echo "[BACKUP] Done."