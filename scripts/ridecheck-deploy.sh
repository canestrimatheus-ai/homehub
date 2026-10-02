#!/usr/bin/env bash
# Redeploy do RideCheck Web neste servidor.
# Uso: bash scripts/ridecheck-deploy.sh
set -euo pipefail

CLONE=/home/decsv/ridecheck-web
COMPOSE_DIR=/home/decsv/.gemini/antigravity/scratch/home-server

echo "==> Atualizando repositório ($CLONE)"
git -C "$CLONE" pull

echo "==> Sincronizando schema no banco"
cd "$CLONE"
set -a
# shellcheck disable=SC1091
source "$COMPOSE_DIR/.env"
set +a
export DATABASE_URL="postgresql://ridecheck:${RIDECHECK_DB_PASSWORD}@127.0.0.1:5432/ridecheck?schema=public"
npx prisma db push --skip-generate

echo "==> Build da imagem ridecheck-web"
cd "$COMPOSE_DIR"
docker compose build ridecheck-web
docker compose up -d ridecheck-web

echo "==> Aguardando healthcheck..."
# shellcheck disable=SC2015
for i in $(seq 1 24); do
  code=$(curl -s -o /dev/null -w '%{http_code}' http://localhost:3001/ridecheck/login || true)
  if [ "$code" = "200" ]; then
    echo "==> OK — RideCheck disponível em:"
    echo "    http://localhost:3001/ridecheck/login"
    echo "    https://interapophysal-demetria-secondly.ngrok-free.dev/ridecheck/login"
    exit 0
  fi
  sleep 5
done
echo "==> Atenção: o serviço demorou a responder. Veja: docker logs ridecheck-web" >&2
exit 1