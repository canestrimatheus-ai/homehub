#!/bin/bash
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
SERVER_DIR="$(dirname "$SCRIPT_DIR")"

cd "$SERVER_DIR"

echo "=========================================================="
echo "📊 STATUS DOS SERVIÇOS DO SERVIDOR CASEIRO"
echo "=========================================================="
docker compose ps
echo ""
echo "=========================================================="
echo "⚡ CONSUMO DE RECURSOS (CPU & RAM)"
echo "=========================================================="
docker stats --no-stream
