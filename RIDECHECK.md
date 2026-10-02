# RideCheck Web — Deploy neste servidor (Home Server)

Documentação operacional do deployment do **RideCheck Web** neste servidor.

---

## 1. Arquitetura

```
                            ┌────────────────────────────────────────────┐
 INTERNET                   │                 NGROK (conta free)          │
 https://interapophysal-    │  domínio fixo gratuito da conta            │
 demetria-secondly.         │  ratoverde10@gmail.com                     │
 ngrok-free.dev             └──────────────────┬─────────────────────────┘
        │                                     │ (HTTPS)
        ▼                                     ▼
┌─────────────────┐   http://localhost:8000  ┌──────────────────────────────┐
│   navegador     │ ────────────────────────► │  decam = nginx:alpine        │
│ / painel web    │                           │  (gateway / reverse proxy)   │
│ / mobile (API)  │                           │  - /             → HomeHub   │
└─────────────────┘                           │  - /ridecheck    → RideCheck │
                                              │  - /terminal     → terminal │
                                              │  - /api/*        → roteado   │
                                              └──────┬───────────────────────┘
                                                     │ rede docker home-server_default
                            ┌────────────────────────┼────────────────────────┐
                            ▼                        ▼                        ▼
                  ┌──────────────────┐     ┌──────────────────┐     ┌──────────────┐
                  │ ridecheck-web    │     │ homehub-dashboard│     │  postgres    │
                  │ Next.js 16       │     │ (HomeHub painel) │     │ :5432        │
                  │ porta 3001       │     │ porta 3000       │     │ db ridecheck │
                  │ basePath=/ridecheck                   │     │              │
                  └──────────────────┘     └──────────────────┘     └──────────────┘
```

### Como as URLs funcionam

| URL pública (via ngrok)                              | Destino                      |
| ---------------------------------------------------- | ---------------------------- |
| `https://interapophysal-demetria-secondly.ngrok-free.dev/`          | HomeHub (painel do servidor) |
| `https://interapophysal-demetria-secondly.ngrok-free.dev/ridecheck` | **RideCheck Web (login)**    |
| `https://interapophysal-demetria-secondly.ngrok-free.dev/ridecheck/api/...` | API RideCheck (inclusive mobile) |
| `http://localhost:3001/ridecheck`                    | RideCheck (direto, no host)  |

O RideCheck roda com `basePath=/ridecheck` (variável `NEXT_PUBLIC_BASE_PATH`).
O gateway `decam` (nginx) traduz as chamadas:

- `/ridecheck/*` → `ridecheck-web:3001` (páginas/estáticos/API com prefixo);
- `/api/auth/*`, `/api/operations`, `/api/tasks`, `/api/checkpoints`, ...,
  `/api/mobile-login` (chamadas "nuas" do frontend) → reescritas para
  `/ridecheck/api/*`. A lista completa (whitelist) fica no `location ~
  ^/api/(...)` do `decam/nginx.conf` — **toda rota nova criada em
  `src/app/api/<nome>/` precisa ser adicionada nela**, senão o
  `fetch('/api/<nome>')` do painel cai no HomeHub (401/404);
- demais `/api/*` (status do servidor, backup, deploy...) → HomeHub.

Isso foi necessário porque o painel chama `fetch('/api/...')` na raiz e o
HomeHub também usa `/api/...`.

---

## 2. Credenciais e segredos

Tudo fica em **`.env`** (não versionado):

```
/home/decsv/.gemini/antigravity/scratch/home-server/.env
```

| Chave                        | Uso                                                           |
| ---------------------------- | ------------------------------------------------------------- |
| `RIDECHECK_DB_PASSWORD`      | Senha do usuário `ridecheck` no PostgreSQL (banco `ridecheck`)|
| `AUTH_SECRET` / `NEXTAUTH_SECRET` | Assinatura das sessões do NextAuth                        |
| `MOBILE_API_SECRET`          | Assina os tokens Bearer do app mobile                         |
| `CRON_SECRET`                | `Authorization: Bearer <valor>` nas rotas `/api/cron/*`       |
| `SEED_ADMIN_EMAIL`           | E-mail do admin inicial (padrão: `admin@ridecheck.com`)       |
| `SEED_ADMIN_PASSWORD`        | Senha do admin inicial                                        |
| `APP_URL` / `NEXTAUTH_URL`   | URL pública usada em e-mails/links do painel                   |
| `ALLOWED_ORIGINS`            | Origens aceitas em CORS (separadas por vírgula)                |
| `SMTP_*` / `EMAIL_PROVIDER`  | (opcional) envio de e-mails — ver §5                          |
| `GEMINI_API_KEY`             | (opcional) análise de B.I. / OCR com IA                        |
| `IMGUR_CLIENT_ID`            | (opcional) upload externo; sem ele, fallback inline            |

> ⚠️ Nunca versionar este arquivo. Já existem backups `.env.bak-*`.

### Admin inicial
- E-mail: **admin@ridecheck.com**
- Senha: valor de `SEED_ADMIN_PASSWORD` no `.env` (troque após o primeiro login).

---

## 3. Banco de dados

PostgreSQL roda no container `homeserver-postgres` (stack do `docker-compose.yml`).
O RideCheck usa um banco dedicado:

```
host: postgres (rede docker) / 127.0.0.1:5432 (host)
db:   ridecheck
user: ridecheck
```

- Criação (já feita; apenas referência):
  ```bash
  docker exec homeserver-postgres psql -U homeserver -d postgres \
    -c "CREATE ROLE ridecheck LOGIN PASSWORD '<RIDECHECK_DB_PASSWORD>';" \
    -c "CREATE DATABASE ridecheck OWNER ridecheck;"
  ```
- Aplicar mudanças de schema recebidas de `git pull`:
  ```bash
  cd /home/decsv/ridecheck-web
  git pull
  set -a; source /home/decsv/.gemini/antigravity/scratch/home-server/.env; set +a
  export DATABASE_URL="postgresql://ridecheck:$RIDECHECK_DB_PASSWORD@127.0.0.1:5432/ridecheck?schema=public"
  npx prisma db push
---

## 4. Build / redeploy do app

O contexto de build é um **symlink**: `home-server/ridecheck-web -> /home/decsv/ridecheck-web`
(clone do repositório). Para atualizar:

```bash
git -C /home/decsv/ridecheck-web pull

cd /home/decsv/.gemini/antigravity/scratch/home-server
docker compose build ridecheck-web
docker compose up -d ridecheck-web
docker logs -f ridecheck-web        # opcional
```

Ou use o script pronto: `bash scripts/ridecheck-deploy.sh`

Verificação rápida:
```bash
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:3001/ridecheck/login   # 200
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:8000/ridecheck/login   # 200 (gateway)
curl -s -o /dev/null -w '%{http_code}\n' https://interapophysal-demetria-secondly.ngrok-free.dev/ridecheck/login  # 200 (público)
```

---

## 5. E-mail (convites, avisos, recuperação)

O envio de e-mail respeita o `EMAIL_PROVIDER`; sem credenciais ele apenas
loga e não envia. Preencha no `.env`:

```env
EMAIL_PROVIDER=smtp
SMTP_HOST=smtp-relay.brevo.com
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER=seu-usuario-smtp
SMTP_PASS=sua-senha
SMTP_FROM=RideCheck <no-reply@seudominio.com>
```

Depois de preencher: `docker compose up -d ridecheck-web` (recreate p/ aplicar).
Rota de teste: `http://localhost:3001/ridecheck/api/test-email`.

---

## 6. Rotinas agendadas (cron)

Não há agendador no servidor; as rotas são chamadas externamente:

```bash
curl -s -H "Authorization: Bearer $CRON_SECRET" \
  http://localhost:3001/ridecheck/api/cron/check-delays
curl -s -H "Authorization: Bearer $CRON_SECRET" \
  http://localhost:3001/ridecheck/api/cron/reminders
curl -s -H "Authorization: Bearer $CRON_SECRET" \
  http://localhost:3001/ridecheck/api/cron/checkpoints
```

`/api/cron/checkpoints` notifica **somente o responsável** (supervisor do
instrutor) dos retornos 7/15/30 vencidos. Ele é complementar: mesmo sem
agendador, o painel gera esses avisos quando o usuário consulta as
notificações (fallback idempotente).

($CRON_SECRET vem do `.env`.)

---

## 7. App mobile (RideCheck Mobile)

O app (repositório separado) consome a API em:

`https://interapophysal-demetria-secondly.ngrok-free.dev/ridecheck`

Ex.: `POST .../ridecheck/api/auth/mobile-login`

- Tokens assinados com `MOBILE_API_SECRET`.
- `MOBILE_APP_URL` no `.env` carrega essa URL para o web.

---

## 8. Migração para Cloudflare (quando tiver domínio)

O caminho está preparado: trocar o túnel **sem** alterar o app.

### 8.1 Opção A — Cloudflare Tunnel apontando direto para o RideCheck

1. Crie um **Tunnel** no painel **Cloudflare Zero Trust**.
2. Rode o agente no servidor (`cloudflared` já existe em `/home/decsv/bin/`):
   ```bash
   cloudflared tunnel run --token <TOKEN_DO_TUNNEL>
   ```
3. Em **Public Hostnames** aponte:
   - hostname `ridecheck.seudominio.com` → service `http://localhost:3001`
4. Mude o app para rodar na raiz e atualize o `.env`/compose:
   ```env
   APP_URL=https://ridecheck.seudominio.com
   MOBILE_APP_URL=https://ridecheck.seudominio.com
   ALLOWED_ORIGINS=https://ridecheck.seudominio.com,<origem-mobile>
   ```
   Rebuild com `NEXT_PUBLIC_BASE_PATH` vazio:
   ```bash
   cd /home/decsv/.gemini/antigravity/scratch/home-server
   sed -i 's#NEXT_PUBLIC_BASE_PATH=/ridecheck#NEXT_PUBLIC_BASE_PATH=#' docker-compose.yml
   docker compose build ridecheck-web && docker compose up -d ridecheck-web
   ```
   > Com esse caminho, o app fica na raiz e não precisa do gateway decam.

### 8.2 Opção B — Manter o gateway decam e apontar o domínio p/ o gateway

1. Tunnel Cloudflare → `http://localhost:8000`.
2. `ridecheck.seudominio.com/ridecheck` funciona exatamente como hoje.
3. Só atualizar `APP_URL`, `ALLOWED_ORIGINS` e desligar o ngrok quando quiser.

### 8.3 ngrok x Cloudflare — resumo

| Item          | ngrok (atual)                                     | Cloudflare Tunnel        |
| ------------- | ------------------------------------------------- | ------------------------ |
| Domínio fixo  | `interapophysal-demetria-secondly.ngrok-free.dev` | seu domínio (CNAME)      |
| Limite free   | 3 endpoints simultâneos; limite de requests       | sem limite de requests   |
| Estabilidade  | túneis efêmeros mudam a cada restart              | hostname estável         |
| Config        | `ngrok.yml` (+ backup em `ngrok.yml.*`)           | painel ZT + `cloudflared`|

---

## 9. Solução de problemas

| Sintoma                          | Causa / Verificação                                       |
| -------------------------------- | --------------------------------------------------------- |
| `502` em `/ridecheck`            | Container parado: `docker ps`; suba com §4.               |
| `502` no gateway (decam) inteiro | O nginx usa `resolver` dinâmico; se insistir: `docker restart homeserver-decam`. |
| `401` ao abrir `/` (HomeHub)     | Login do HomeHub é independente do RideCheck.             |
| Login do painel não funciona     | Confira `AUTH_SECRET` estável; recrie o container.        |
| Convites não chegam por e-mail   | SMTP vazio — veja §5.                                     |
| Túneis efêmeros mudaram          | Normal no free; o domínio fixo do gateway é estável.      |
  ```
---

## 10. Deploy 08/09/2026 — container online + correções de routing/auth

### Estado
- `ridecheck-web`: **Up (healthy)** — imagem `home-server-ridecheck-web:latest` (Next.js 16.2.4, porta 3001).
- Banco `ridecheck` ok (schema via `prisma db push`, admin seedado: `admin@ridecheck.com` / `Admin123!`).
- Card público **RideCheck** registrado no portal do HomeHub (`dashboard/projects.json`, id `ridecheck-web`, `/ridecheck/`).

### Fix 1 — nginx do decam: 500 em `/api/*` nus
Bug: `rewrite ... break` aborta os directives do módulo rewrite restantes — o `set $rc_upstream`
que vinha DEPOIS do rewrite nunca rodava → `invalid URL prefix in ""` → 500 em
`/api/auth/mobile-login` etc. Corrigido em `decam/nginx.conf` (set ANTES do rewrite).

### Fix 2 — NextAuth: 400 em `/api/auth/csrf` (login quebrado)
O Next.js remove o `basePath=/ridecheck` do `req.url` antes do Route Handler, mas o NextAuth
derivava `basePath=/ridecheck` do `NEXTAUTH_URL` → `UnknownAction: Cannot parse action at
/api/auth/csrf` → 400 no login. Fix em `src/lib/auth.ts`: `basePath: '/api/auth'` explícito
(parse dos actions volta a funcionar; cookies usam Path=/ e o gateway traduz `/api/auth/*`).
Validação E2E via URL pública: csrf → callback/credentials (200 + cookie) → session (JSON) →
dashboard (200).

### Gates públicos (08/09)
- **Ativo agora (sem limite de requests):** Cloudflare quick tunnel — ver `scripts/cloudflare-url`.
  Ex.: `https://outer-doors-colleges-nat.trycloudflare.com/ridecheck/login` (URL muda a cada restart).
- **Canônico/estável:** ngrok fixo `https://interapophysal-demetria-secondly.ngrok-free.dev/ridecheck`
  — 08/09 a 20:46 o domínio voltou **ERR_NGROK_727 (cota mensal HTTP esgotada)**; renova
  automaticamente. O dashboard HomeHub consome cota os polls de /api/status — se quiser
  economizar, aumentar o intervalo de polling do admin.js.

### Ajustes sugeridos p/ começar o mobile
- `MOBILE_APP_URL`/`APP_URL` no `.env` apontam p/ o ngrok fixo (estável, renova mês a mês).
  Se quiser a URL ativa do CF (troca a cada restart), atualizar `.env` + `docker compose up -d ridecheck-web`.
- Endpoint mobile: `POST <base>/api/auth/mobile-login` (retorna user + token assinado c/ MOBILE_API_SECRET).

---

## 11. Fix 14/09/2026 — página "Retornos 7/15/30 dias" + Service Worker órfão

Sintomas relatados no painel (`/ridecheck/dashboard/checkpoints`):

```
GET /api/checkpoints?scope=mine&status=PENDING → 404
sw.js?v=2:69 Uncaught TypeError: Failed to execute 'put' on 'Cache':
Request method 'POST'/'DELETE' is unsupported
The FetchEvent for ".../ridecheck/dashboard/checkpoints" resulted in a
network error response: the promise was resolved with an error response object.
```

### Causa 1 — rota `checkpoints` fora da whitelist do nginx
A página faz `fetch('/api/checkpoints?...')` (convenção "nua" do painel), mas o
gateway só reescrevia para `/ridecheck/api/*` os prefixos listados no
`location ~ ^/api/(...)`. `checkpoints` não estava na lista → a chamada caía no
HomeHub (`location /api/`) e voltava 404/401.

**Fix:** `checkpoints` adicionado à whitelist em `decam/nginx.conf`
(+ comentário lembrando de manter a lista sincronizada com `src/app/api/`).

Validação (via gateway):

| Requisição | Antes | Depois |
| --- | --- | --- |
| `GET /api/checkpoints?scope=mine&status=PENDING` | 401/404 do HomeHub (Werkzeug) | 401 do RideCheck (Next, `{"error":"Não autorizado"}`) |
| `POST /api/checkpoints/<id>` | 404 do HomeHub | 401 do RideCheck (rota existe) |

Com sessão válida a rota responde a lista (`items`/`summary`) — tabela
`DriverCheckpoint` confirmada no banco.

### Causa 2 — Service Worker órfão do DECAM 3D controlando o domínio
Quando o domínio ngrok apontava para o app DECAM 3D (container `hh-app-*`,
porta 4000), o kiosk registrava `navigator.serviceWorker.register('/sw.js?v=2')`
→ **escopo `/`** (raiz do domínio). Depois que o túnel voltou para o gateway
(porta 8000), o registro permaneceu ativo no browser e continuou interceptando
TODO o domínio, inclusive `/ridecheck/*`:

- `sw.js` linha 69: `caches.open(CACHE_NAME).then((cache) => cache.put(event.request, responseToCache))`
  sem checar `event.request.method === 'GET'` → erro em todo POST/DELETE
  (o Cache API não aceita esses métodos);
- fallback `respondWith` podia resolver com `undefined`/`Response.error()` →
  "network error response" na navegação.

**Fix (1) — gateway:** `location = /sw.js` no `decam/nginx.conf` passa a servir
um worker que se **auto-desregistra** e apaga os caches `decam-cache*`. O browser
faz soft-update do worker na próxima navegação de página controlada, então o
problema se resolve para todos os clientes sem ação manual.

**Fix (2) — app:** o `dashboard/layout.tsx` ganhou um efeito de limpeza
defensiva: desregistra qualquer Service Worker órfão em `/sw.js` e limpa os
caches `decam-cache*`, recarregando a página uma única vez por sessão
(`sessionStorage` evita loop). Corrige imediatamente a aba já aberta, sem
depender da janela de soft-update do browser.

> Observação: o app DECAM (imagem do Deploy Center) continua registrando o
> worker em `/sw.js` (raiz). Como ele agora vive sob `/apps/<slug>/`, um worker
> com escopo na raiz é incorreto (interceptaria HomeHub e RideCheck); ao mexer
> nesse app, trocar o registro para caminho relativo ao seu próprio prefixo.
