#!/usr/bin/env bash
# Backup automático dos bancos do home-server (Postgres + MySQL via docker)
# Retenção: 7 dias. Log: $BACKUP_ROOT/backup.log
# Criado em 17/09/2026 — rodar via cron (@daily).
set -uo pipefail

COMPOSE_DIR="/home/decsv/.gemini/antigravity/scratch/home-server"
BACKUP_ROOT="$COMPOSE_DIR/data/backups/db"
KEEP_DAYS=7
STAMP="$(date +%Y%m%d_%H%M%S)"
TODAY_DIR="$BACKUP_ROOT/$STAMP"
mkdir -p "$TODAY_DIR"

# fonte das senhas (mesmo .env do compose, sem expor nas chamadas)
if [ -f "$COMPOSE_DIR/.env" ]; then set -a; . "$COMPOSE_DIR/.env"; set +a; fi

log() { echo "[$(date '+%F %T')] $*" >> "$BACKUP_ROOT/backup.log"; }

# --- Postgres principal (homeserver-postgres): homedb, ridecheck, etc.
PG_DBS="$(docker exec homeserver-postgres psql -U homeserver -d postgres -tAc "SELECT datname FROM pg_database WHERE datistemplate=false AND datname<>'postgres'" 2>/dev/null)"
for db in $PG_DBS; do
  out="$TODAY_DIR/pg_${db}_$(date +%y%m%d).dump"
  if docker exec homeserver-postgres pg_dump -U homeserver -Fc -d "$db" > "$out" 2>/tmp/bk_pg.err; then
    log "pg:$db ok $(stat -c%s "$out")b"
  else
    log "pg:$db FALHOU ($(tail -1 /tmp/bk_pg.err))"
  fi
done

# --- Postgres Book do Motorista (book_motorista_postgres_dev) — ativo/não
if docker ps --format '{{.Names}}' | grep -q '^book_motorista_postgres_dev$'; then
  for db in book_motorista_dev; do
    out="$TODAY_DIR/pgb_${db}_$(date +%y%m%d).dump"
    if docker exec book_motorista_postgres_dev pg_dump -U postgres -Fc -d "$db" > "$out" 2>/tmp/bk_pgb.err; then
      log "pgb:$db ok $(stat -c%s "$out")b"
    else
      log "pgb:$db FALHOU ($(tail -1 /tmp/bk_pgb.err))"
    fi
  done
fi

# --- MySQL principal (homeserver-mysql) — db homedb
if docker ps --format '{{.Names}}' | grep -q '^homeserver-mysql$'; then
  out="$TODAY_DIR/mysql_homedb_$(date +%y%m%d).sql"
  if docker exec -e MYSQL_PWD="${MYSQL_PASSWORD:-}" homeserver-mysql mysqldump -u homeserver --single-transaction homedb > "$out" 2>/tmp/bk_mysql.err; then
    log "mysql:homedb ok $(stat -c%s "$out")b"
  else
    log "mysql:homedb FALHOU ($(tail -1 /tmp/bk_mysql.err))"
  fi
fi

# --- Retenção: remove backups com mais de KEEP_DAYS dias
OLD=$(find "$BACKUP_ROOT" -mindepth 1 -maxdepth 1 -type d -mtime +"$KEEP_DAYS" 2>/dev/null | wc -l)
[ "$OLD" -gt 0 ] && find "$BACKUP_ROOT" -mindepth 1 -maxdepth 1 -type d -mtime +"$KEEP_DAYS" -exec rm -rf {} +
log "finalizado. hoje: $(du -sh "$TODAY_DIR" 2>/dev/null | cut -f1), removidos: $OLD (retenção ${KEEP_DAYS}d)"
