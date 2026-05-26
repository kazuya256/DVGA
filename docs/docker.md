# Docker Setup Guide

This document describes how the Docker environment isolates the **DVGA-Node** environment.

## Container Layout

The environment defines two networked services:
1. **`db` (Postgres 15-alpine):**
   * Persists database files to a local Docker volume named `pgdata`.
   * Only exposes port `5432` locally to allow client exploration.
   * Includes a health check query (`pg_isready`) ensuring the DB is active before application startup.
2. **`app` (Node.js application):**
   * Pulls dependencies via `npm ci` matching production locks.
   * Maps application port `5013` to host machine interface.
   * Depends on `db` service completing its health check successfully.

## Command Reference

```bash
# Build and start services
docker compose up --build

# Stop running containers
docker compose down

# Wipe database volume files
docker compose down -v
```

## Isolation Principles

To secure host environments, Docker forces the application and database container processes to run inside a sandboxed bridge network (`dvga-network`). Even if Command Injection is executed, access is confined to the Alpine container filesystem.
