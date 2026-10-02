#!/bin/bash
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
SERVER_DIR="$(dirname "$SCRIPT_DIR")"

cd "$SERVER_DIR"

echo "🛑 Parando serviços do servidor caseiro..."
docker compose down
echo "✅ Servidor pausado com sucesso."
