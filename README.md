# 🏠 HomeHub - Enterprise Self-Hosted Infrastructure & Orchestration Server

<div align="center">

![Docker](https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white)
![Nginx](https://img.shields.io/badge/Nginx-009639?style=for-the-badge&logo=nginx&logoColor=white)
![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-316192?style=for-the-badge&logo=postgresql&logoColor=white)
![Redis](https://img.shields.io/badge/Redis-DC382D?style=for-the-badge&logo=redis&logoColor=white)
![Cloudflare](https://img.shields.io/badge/Cloudflare_Tunnels-F38020?style=for-the-badge&logo=cloudflare&logoColor=white)

**Uma plataforma de infraestrutura privada e orquestração de servidores dedicada a eliminar custos recorrentes de nuvem (AWS, GCP, Vercel, Supabase Cloud) através de hardware dedicado on-premise com alta disponibilidade, segurança Zero-Trust e automação completa.**

[Visão Geral](#-visão-geral) • [Arquitetura](#-arquitetura-do-sistema) • [Redução de Custos](#-economia-e-comparativo-de-custos) • [Serviços](#-serviços-orquestrados) • [Instalação](#-como-rodar-o-servidor) • [Segurança](#-segurança-e-backups)

</div>

---

## 💡 Visão Geral

O **HomeHub** nasceu de uma necessidade estratégica corporativa: rodar aplicações críticas de gestão de frotas, auditoria, telemetria e checklists em tempo real com **custo operacional próximo a zero** em SaaS e infraestrutura de nuvem externa.

Ao invés de despender milhares de reais todos os meses em plataformas de nuvem pública (onde cada banco de dados gerenciado, gigabyte de tráfego, build no Vercel ou instância EC2 infla a fatura), o HomeHub transforma um servidor corporativo dedicado (estação Dell Vostro / Linux) em uma **central de dados privada, resiliente e segura**.

### 🎯 Principais Benefícios
- **Custo Fixo e Previsível**: Zero faturas surpresa de nuvem (sem cobrança por requisições, transferências de dados ou conexões simultâneas).
- **Controle Total dos Dados**: Todas as informações de telemetria, rotas de motoristas, checklists e vistorias residem dentro da própria infraestrutura.
- **Acesso Externo Seguro via Cloudflare Tunnels**: Nenhuma porta de roteador precisa ser aberta (Zero-Port-Forwarding). Conexão segura HTTPS/WSS com criptografia ponta a ponta.
- **Painel de Gestão e Deploy Engine**: Dashboard visual para monitorar métricas de hardware, status dos containers Docker, logs em tempo real e deploys automatizados.
- **Rotina de Backup Inteligente**: Snapshots automáticos de todos os bancos de dados (PostgreSQL, MySQL, SQLite) e volumes de arquivos com retenção histórica e recuperação em 1 clique.

---

## 🏛️ Arquitetura do Sistema

```
                  ┌──────────────────────────────────────────────┐
                  │              INTERNET / USUÁRIOS             │
                  │   (Mobile Apps, Painéis Web, Webhooks APIs)  │
                  └──────────────────────┬───────────────────────┘
                                         │  HTTPS / WSS Seguro
                                         ▼
                  ┌──────────────────────────────────────────────┐
                  │          CLOUDFLARE ZERO-TRUST TUNNEL        │
                  │   (decamservice.com - Túnel Criptografado)   │
                  └──────────────────────┬───────────────────────┘
                                         │
                                         ▼
                  ┌──────────────────────────────────────────────┐
                  │             NGINX GATEWAY PROXY              │
                  │         (homeserver-decam : Porta 8000)      │
                  └──────┬───────────────┼───────────────┬───────┘
                         │               │               │
         ┌───────────────┘               │               └───────────────┐
         ▼                               ▼                               ▼
┌──────────────────┐           ┌──────────────────┐           ┌──────────────────┐
│   HomeHub Core   │           │   RideCheck Web  │           │   Vistorias Web  │
│ Dashboard/Deploy │           │  Gestão & Frotas │           │ Inspeção/Modelos │
│   (:3000/Flask)  │           │  (:3001/Next.js) │           │   (:3020/Vite)   │
└────────┬─────────┘           └────────┬─────────┘           └────────┬─────────┘
         │                              │                              │
         └───────────────────────┬──────┴──────────────────────────────┘
                                 │
                                 ▼
┌────────────────────────────────────────────────────────────────────────────────┐
│                           SUITE DE DADOS & SERVIÇOS                            │
├─────────────────────┬────────────────────┬───────────────────┬─────────────────┤
│    PostgreSQL 16    │     MySQL 8.4      │      Redis 7      │   Supabase Self │
│  (Bancos Primários) │ (Sistemas Legados) │ (Filas & Caching) │ (Auth, Storage) │
├─────────────────────┼────────────────────┼───────────────────┼─────────────────┤
│    Portainer CE     │      Adminer       │ Docker Sock Proxy │ Backup Engine   │
│  (Gestão Containers)│  (Gestão de DBs)   │ (Segurança Docker)│ (Snapshots Auto)│
└─────────────────────┴────────────────────┴───────────────────┴─────────────────┘
```

---

## 💰 Economia e Comparativo de Custos

| Componente | Custo Médio em Nuvem Pública (Mensal) | Custo no HomeHub Dedicado |
| :--- | :--- | :--- |
| **Bancos de Dados Gerenciados** (PostgreSQL + MySQL + Redis) | R$ 1.200 - R$ 2.400 / mês (RDS/ElastiCache) | **R$ 0,00** (Docker Nativo) |
| **Hospedagem Web & APIs** (Vercel Pro + Render/Fly.io) | R$ 450 - R$ 900 / mês | **R$ 0,00** (Servidor Dedicado) |
| **Backend as a Service & Auth** (Supabase Cloud Pro) | R$ 350 - R$ 800 / mês | **R$ 0,00** (Supabase Self-Hosted) |
| **Armazenamento de Fotos/Anexos** (AWS S3 + CloudFront) | R$ 200 - R$ 600 / mês | **R$ 0,00** (Storage em Disco Local) |
| **Túnel Seguro & CDN** (Cloudflare Enterprise/Addons) | R$ 150 / mês | **R$ 0,00** (Cloudflare Free Tunnels) |
| **TOTAL ESTIMADO** | **R$ 2.350 - R$ 4.850 / mês** | **R$ 0,00 / mês recorrente** |

> **Economia anual projetada**: entre **R$ 28.000 e R$ 58.000 por ano** em licenças e servidores.

---

## 📦 Serviços Orquestrados

| Container | Serviço / Função | Tecnologia | Porta Interna | Rota Externa |
| :--- | :--- | :--- | :--- | :--- |
| `homehub-dashboard` | Painel Central & Deploy Engine | Python / Flask | `3000` | `decamservice.com/` |
| `homeserver-decam` | Reverse Proxy & SSL Gateway | Nginx Alpine | `8000` | Gateway Geral |
| `homeserver-cloudflare`| Túnel Seguro Zero-Trust | Cloudflare Daemon | - | Túnel de Conexão |
| `homeserver-postgres` | Banco Relacional Primário | PostgreSQL 16 Alpine | `5432` | `db.internal` |
| `homeserver-mysql` | Banco de Dados Complementar | MySQL 8.4 | `3306` | `mysql.internal` |
| `homeserver-redis` | Cache de Sessão & Filas | Redis 7 Alpine | `6379` | `redis.internal` |
| `homeserver-portainer`| Gestão Visual de Containers | Portainer CE | `9000` / `9443`| Painel Portainer |
| `homeserver-adminer` | Gerenciador de Banco de Dados | Adminer | `8080` | `/adminer` |
| `homeserver-socket-proxy`| Proxy Seguro para Docker API | Tecnativa Docker Proxy | `2375` | Comunicação Segura |
| `ridecheck-web` | Portal de Acompanhamentos & Telemetria | Next.js 16 / TypeScript | `3001` | `/ridecheck` |
| `pgcsc-telemetria` | Programa Comportamento Seguro | Python / Flask / Gunicorn| `5000` | `/pgsc` |
| `vistorias-web` | Painel Web de Vistorias e Relatórios PDF | React / Vite / Node.js | `3020` | `/vistorias` |

---

## 🚀 Como Rodar o Servidor

### 1. Pré-requisitos
- Sistema Operacional Linux (Ubuntu 22.04 LTS / Debian recomendado)
- Docker instalado (v24+) e Docker Compose (v2.20+)
- Python 3.10+ (para scripts de orquestração local)
- Conta no Cloudflare (para criação do Tunnel)

### 2. Clonagem e Configuração
```bash
git clone https://github.com/canestrimatheus-ai/homehub.git
cd homehub

# Copie as variáveis de exemplo
cp .env.example .env
```

Edite o arquivo `.env` com senhas fortes:
```env
POSTGRES_PASSWORD=sua_senha_postgres_segura
MYSQL_ROOT_PASSWORD=sua_senha_mysql_segura
RIDECHECK_DB_PASSWORD=sua_senha_ridecheck
AUTH_SECRET=sua_chave_secreta_jwt
CLOUDFLARE_TUNNEL_TOKEN=seu_token_cloudflare
```

### 3. Inicialização dos Containers
```bash
# Iniciar toda a infraestrutura em modo daemon
docker compose up -d

# Verificar se todos os serviços estão saudáveis
docker compose ps
```

### 4. Acesso aos Painéis
- **HomeHub Dashboard**: `http://localhost:3000`
- **Portainer**: `http://localhost:9000`
- **Adminer**: `http://localhost:8080`
- **Gateway Nginx**: `http://localhost:8000`

---

## 🔒 Segurança e Backups

1. **Docker Socket Proxy**: O Docker daemon (`docker.sock`) **não** fica exposto diretamente aos containers web; as chamadas são filtradas pelo `docker-socket-proxy`, impedindo ataques de elevação de privilégios.
2. **Backups Diários Automatizados**:
   - Rotina diária que extrai dumps com compressão de todos os bancos (`pg_dump`, `mysqldump`).
   - Armazenamento com rotação de snapshots (últimos 7 dias, 4 semanas, 6 meses).
   - Script de restauração automatizado em caso de falha de hardware (`restore_ctl.py`).
3. **Criptografia e SSL**: Todo o tráfego que transita externamente é criptografado com certificados SSL/TLS gerenciados automaticamente pela Cloudflare.

---

<div align="center">
Desenvolvido por <strong>Matheus Canestri</strong> para governança, alta disponibilidade e autonomia tecnológica.
</div>
