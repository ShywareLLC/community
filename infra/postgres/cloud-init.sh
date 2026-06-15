#!/bin/bash
set -euo pipefail

apt-get update && apt-get upgrade -y
apt-get install -y postgresql-16 postgresql-client-16

# Move data dir to the attached volume (mounted at /mnt/HC_Volume_*)
PG_DATA="/mnt/postgres-data/postgresql/16/main"
mkdir -p "$PG_DATA"
chown -R postgres:postgres /mnt/postgres-data

cat > /etc/postgresql/16/main/postgresql.conf <<PGEOF
data_directory = '$PG_DATA'
listen_addresses = '${private_ip}'   # Private IP only — never public
port = 5432
max_connections = 100
shared_buffers = 2GB
effective_cache_size = 6GB
work_mem = 20MB
maintenance_work_mem = 512MB
wal_level = replica
archive_mode = off
log_line_prefix = '%t [%p]: [%l-1] '
log_min_duration_statement = 1000
PGEOF

cat >> /etc/postgresql/16/main/pg_hba.conf <<HBAEOF
# Allow API reader from private network
host    ${project}    api_reader    10.0.0.0/8    scram-sha-256
# Allow indexer from private network
host    ${project}    indexer       10.0.0.0/8    scram-sha-256
# Allow admin from private network
host    ${project}    postgres      10.0.0.0/8    scram-sha-256
HBAEOF

systemctl enable postgresql@16-main
systemctl start postgresql@16-main

sudo -u postgres psql <<SQLEOF
CREATE DATABASE ${project};
\c ${project}

CREATE USER api_reader WITH PASSWORD '${api_reader_password}';
GRANT CONNECT ON DATABASE ${project} TO api_reader;
GRANT USAGE ON SCHEMA public TO api_reader;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO api_reader;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO api_reader;

CREATE USER indexer WITH PASSWORD '${postgres_password}';
GRANT CONNECT ON DATABASE ${project} TO indexer;
GRANT USAGE, CREATE ON SCHEMA public TO indexer;
GRANT ALL ON ALL TABLES IN SCHEMA public TO indexer;
SQLEOF

echo "${project} PostgreSQL bootstrap complete."
