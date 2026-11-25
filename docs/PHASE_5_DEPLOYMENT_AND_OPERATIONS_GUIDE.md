# Phase 5 — Deployment and Operations Guide

**Branch:** `feature/phase-5-enterprise-integration`
**Date:** 2026-11-25 (local)

## 1. Overview

This guide provides instructions for deploying and operating the Phase 5 containment system in a production environment.

## 2. Prerequisites

- **PostgreSQL 16** with appropriate permissions and database setup.
- **Redis 7** for distributed locking, rate-limiting, and ephemeral state.
- **Python 3.11+** with all required dependencies installed.
- **Docker** for containerized deployment.

## 3. Deployment Steps

### 3.1 Environment Setup

1. **Configure Environment Variables:**
   Ensure `.env` file contains the correct database and Redis URLs:
   ```
   DATABASE_URL=postgresql+asyncpg://<user>:<password>@<host>:<port>/<database>
   REDIS_URL=redis://<host>:<port>/<db>
   ```

2. **Database Migration:**
   Run the database migrations to set up the required tables and schemas:
   ```bash
   python -m backend.app.db.migrations.upgrade
   ```

### 3.2 Application Deployment

1. **Start Services:**
   Use Docker Compose to start the necessary services:
   ```bash
   docker-compose up -d
   ```

2. **Verify Services:**
   Ensure all services are running and healthy:
   ```bash
   docker ps
   ```

### 3.3 Post-Deployment Checks

1. **Run Security Tests:**
   Ensure all security tests pass:
   ```bash
   pytest backend/tests/security
   ```

2. **Run Unit Tests:**
   Ensure all unit tests pass:
   ```bash
   pytest backend/tests/unit
   ```

## 4. Operations Guide

### 4.1 Monitoring

- Monitor the application logs for any errors or warnings.
- Use the provided API endpoints to check the status of containment operations.

### 4.2 Incident Response

1. **Quarantine a Record:**
   Use the containment API to quarantine suspicious records:
   ```bash
   POST /api/v1/security/containment/apply
   {
     "record_id": "<record_id>",
     "reason": "<reason_for_quarantine>",
     "reason_code": "<reason_code>",
     "incident_id": "<incident_id>",
     "evidence_refs": ["<evidence_ref1>", "<evidence_ref2>"]
   }
   ```

2. **Forensic Access:**
   Use forensic access to investigate quarantined records:
   ```bash
   POST /api/v1/security/containment/forensic
   {
     "record_id": "<record_id>",
     "reason": "<reason_for_access>",
     "incident_id": "<incident_id>"
   }
   ```

### 4.3 Backup and Restore

- **Backup:**
  Regularly back up the database and Redis data:
  ```bash
  docker exec chronocongisec-postgres-1 pg_dump -U amsc -d amsc > backup.sql
  docker exec chronocongisec-redis-1 redis-cli --rdb /tmp/redis_backup.rdb
  ```

- **Restore:**
  Restore from backups in case of data loss:
  ```bash
  docker exec -i chronocongisec-postgres-1 psql -U amsc -d amsc < backup.sql
  docker exec chronocongisec-redis-1 redis-cli --rdb /tmp/redis_backup.rdb
  ```

## 5. Known Issues and Limitations

- **In-Memory Containment Outcomes:** Containment outcomes for `_suspend_agent`/`_block_actions`/`_isolate_resource` are synthesized in-memory.
- **ML Integration:** Phase 4 ML security intelligence is not yet integrated.

## 6. Next Steps

- Coordinate with the Phase 4 team to integrate ML security intelligence.
- Ensure Postgres and Redis are properly configured for production use.
- Monitor performance and adjust configurations as needed.