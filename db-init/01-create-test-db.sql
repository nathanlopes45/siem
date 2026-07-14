-- Runs automatically on first-ever Postgres startup (fresh volume only).
-- Creates the throwaway database used by the pytest suite (see tests/conftest.py)
-- alongside the main POSTGRES_DB, so `docker compose down -v` + `up` leaves
-- both databases ready without a manual `createdb` step.
CREATE DATABASE siem_test_db;