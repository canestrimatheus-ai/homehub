#!/usr/bin/env bash
# ==============================================================================
# auto-cleanup.sh - Rotina Automática de Limpeza de Lixo e Cache do Sistema
# Mantém o SSD leve, liberando dezenas de GBs sem riscos aos dados ou serviços.
# ==============================================================================

set -euo pipefail

LOG_FILE="/home/decsv/.gemini/antigravity/scratch/home-server/logs/cleanup.log"
mkdir -p "$(dirname "$LOG_FILE")"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

log "=== Iniciando rotina de limpeza do servidor ==="

# 1. Liberar Cache de Compilação do Docker (Build Cache)
# Remove camadas intermediárias antigas que acumulam após builds de imagens.
# Mantém imagens em uso e volumes 100% intocados.
if command -v docker >/dev/null 2>&1; then
    log "Limpando Docker build cache antigo..."
    docker builder prune -af --keep-storage 2GB >> "$LOG_FILE" 2>&1 || true

    log "Limpando imagens dangling (<none>:<none>)..."
    docker image prune -f >> "$LOG_FILE" 2>&1 || true

    log "Limpando containers órfãos encerrados..."
    docker container prune -f >> "$LOG_FILE" 2>&1 || true
fi

# 2. Limpar logs do sistema (Systemd Journal)
# Limita o histórico de logs do Linux a no máximo 3 dias ou 200MB
if command -v journalctl >/dev/null 2>&1; then
    log "Compactando logs do systemd journal..."
    journalctl --vacuum-time=3d --vacuum-size=200M >> "$LOG_FILE" 2>&1 || true
fi

# 3. Limpar cache de pacotes APT
if [ -d "/var/cache/apt/archives" ]; then
    log "Limpando arquivos .deb temporários do APT..."
    find /var/cache/apt/archives -type f -name '*.deb' -delete 2>/dev/null || true
fi

# 4. Limpar arquivos temporários antigos em /tmp (> 3 dias)
log "Limpando arquivos temporários antigos em /tmp..."
find /tmp -type f -atime +3 -delete 2>/dev/null || true

# 5. Limpar caches de desenvolvimento (npm, pip)
if [ -d "/home/decsv/.cache/pip" ]; then
    rm -rf /home/decsv/.cache/pip 2>/dev/null || true
fi
if [ -d "/home/decsv/.npm/_cacache" ]; then
    rm -rf /home/decsv/.npm/_cacache 2>/dev/null || true
fi

# 6. Status final de disco
USO_DISCO=$(df -h / | awk 'NR==2 {print $3 " usados de " $2 " (" $5 ")"}')
log "=== Limpeza concluída com sucesso! Uso atual do SSD: $USO_DISCO ==="
