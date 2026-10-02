#!/bin/bash
set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
SERVER_DIR="$(dirname "$SCRIPT_DIR")"

cd "$SERVER_DIR"

echo "=========================================================="
echo "🚀 Iniciando Servidor Caseiro Linux (Bancos & Hospedagem)"
echo "=========================================================="

# Ensure data directories exist
mkdir -p data/postgres data/mysql data/redis data/portainer

# Subir containers com Docker Compose
docker compose up -d --build

HOST_IP=$(hostname -I | awk '{print $1}')
TAILSCALE_IP=$(tailscale ip -4 2>/dev/null || echo "100.92.242.64")

echo ""
echo "=========================================================="
echo "✅ SERVIDOR ONLINE E PRONTO PARA USO!"
echo "=========================================================="
echo ""
echo "🖥️  HomeHub Dashboard:      http://${HOST_IP}:3000"
echo "📦 Portainer CE (Apps):    http://${HOST_IP}:9000"
echo "🗄️  Adminer (Bancos):       http://${HOST_IP}:8080"
echo ""
echo "🌍 Acesso de fora de casa (Tailscale VPN):"
echo "   http://${TAILSCALE_IP}:3000"
echo ""
echo "🔒 Conexão SSH:"
echo "   ssh decsv@${HOST_IP}"
echo "   ssh decsv@${TAILSCALE_IP}"
echo "=========================================================="
