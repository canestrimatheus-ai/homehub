#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HomeHub — Enterprise Dashboard & Deploy Center
Flask application replacing server.py
"""
import os, sys, json, time, hmac, hashlib, secrets, threading, subprocess, re, io, uuid
import struct
import base64
from pathlib import Path
from functools import wraps
from flask import Flask, request, jsonify, send_file, Response, stream_with_context, abort
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix
import ipaddress
import requests as http_requests
from urllib.parse import quote as _urlquote

# ── Constants ────────────────────────────────────────────────────────────────
APP_DIR     = Path(__file__).parent
PROJECTS_F  = APP_DIR / "projects.json"
AUTH_F      = APP_DIR / "auth.json"
UPLOADS_DIR = APP_DIR / "uploads"
DB_PATH     = APP_DIR / "deploy.db"
SESSION_SECRET = os.environ.get("SESSION_SECRET", secrets.token_hex(32))
MAX_UPLOAD_MB  = 500
ALLOWED_EXTS   = {".zip", ".tar.gz", ".tgz"}
DEPLOY_PORT_RANGE = (4000, 4999)
GH_KEYS_FILE   = APP_DIR / "github_keys.json"

# ── File Manager ───────────────────────────────────────────────────────────────
# Raiz a partir da qual o Gerenciador de Arquivos navega. Dentro do container o
# bind-mount /hosthome aponta para a home do usuário no host (ver docker-compose).
FILES_ROOT = Path(os.environ.get("FILES_ROOT", str(Path.home()))).resolve()

# Nunca expor dotfiles/segredos no Gerenciador de Arquivos nem no portal, mesmo
# autenticado. Proteção em camadas com o FILES_ROOT dedicado (/hosthome/Documentos).
FM_DENY_NAMES = frozenset({
    ".ssh", ".gnupg", ".gnome", ".config", ".gnome2", ".pki",
    ".aws", ".azure", ".kube", ".docker", ".npm", ".cache",
    ".bash_history", ".bashrc", ".bash_profile", ".profile", ".zshrc",
    ".gitconfig", ".git-credentials", ".netrc",
    ".npmrc", ".pypirc", ".claude.json", ".claude", ".gemini", ".codex",
    ".wget-hsts", ".mysql_history", ".psql_history",
    ".hh_sessions.json", "auth.json", "github_keys.json",
    "deploy.db", "deploy.db-journal", ".ttyd-credentials",
    "id_ed25519", "id_rsa", "id_ecdsa", "id_ed448",
})

def _fm_is_sensitive(rel):
    """True se o caminho (relativo a FILES_ROOT) contém parte privada na raiz."""
    parts = [p for p in Path(rel).parts if p not in ("", ".", "..")]
    if not parts:
        return False
    return parts[0] in FM_DENY_NAMES

# ── GitHub keys (tokens salvos reutilizáveis) ─────────────────────────────────
def _load_gh_keys():
    """Return dict {key_name: token}. Arquivo tem permissão restritiva (0600) e
    a extensão .json é bloqueada de ser servida por HTTP (BLOCKED_STATIC_EXTS."""
    try:
        if GH_KEYS_FILE.exists():
            data = json.loads(GH_KEYS_FILE.read_text())
            return data if isinstance(data, dict) else {}
    except Exception as e:
        print(f"[GhKeys load error] {e}", flush=True)
    return {}

def _save_gh_keys(keys):
    try:
        GH_KEYS_FILE.write_text(json.dumps({k: v for k, v in keys.items() if v}, ensure_ascii=False, indent=2))
        try: os.chmod(GH_KEYS_FILE, 0o600)
        except Exception: pass
        return True
    except Exception as e:
        print(f"[GhKeys save error] {e}", flush=True)
        return False

def _resolve_gh_token(saved_key, token=""):
    """Resolve o token efetivo: prioridade para token informado, depois a chave salva."""
    token = (token or "").strip()
    if token:
        return token
    saved_key = (saved_key or "").strip()
    if saved_key:
        keys = _load_gh_keys()
        if saved_key in keys:
            return keys[saved_key]
    return ""

# ── Flask Setup ──────────────────────────────────────────────────────────────
app = Flask(__name__, static_folder=None)
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024
app.secret_key = SESSION_SECRET
# O ngrok roda em network_mode: host e o gRPC de túneis chega pelo gateway da
# bridge Docker (172.17/172.18.0.1) ou loopback. Sem ProxyFix, remote_addr é
# SEMPRE esse gateway — rate-limit vira global e auditoria perde o IP real.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

# Gateways Docker (172.16.0.0/12) = infraestrutura local confiável p/ X-Forwarded-For.
_DOCKER_NET = ipaddress.ip_network("172.16.0.0/12")

def _client_ip():
    """IP real do cliente.
    - Via túnel (ngrok/cloudflared/SSH): remote_addr é o gateway/loopback — então
      confiamos no X-Forwarded-For (não-forjável de fora, o túnel sobrescreve).
    - Acesso direto (LAN 10.11.2.0/22): remote_addr é o IP real; XFF é ignorado
      (evita spoof por quem já tem acesso à rede)."""
    try:
        src = request.remote_addr or ""
        src_ip = ipaddress.ip_address(src.split("%")[0])
    except ValueError:
        return request.remote_addr or ""
    trusted_gateway = src_ip.is_loopback or src_ip in _DOCKER_NET
    if trusted_gateway:
        fwd = request.headers.get("X-Forwarded-For", "")
        first = fwd.split(",")[0].strip()
        if first:
            return first
    return request.remote_addr or ""

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["300 per minute"],
    storage_uri="memory://"
)

# ── Lazy imports for deploy modules ─────────────────────────────────────────
_deploy_db     = None
_deploy_engine = None

def get_db():
    global _deploy_db
    if _deploy_db is None:
        try:
            from deploy_db import DeployDB
            _deploy_db = DeployDB(str(DB_PATH))
        except Exception as e:
            print(f"[DB Error] {e}", flush=True)
    return _deploy_db

def get_engine():
    global _deploy_engine
    if _deploy_engine is None:
        db = get_db()
        if db:
            try:
                from deploy_engine import DeployEngine
                _deploy_engine = DeployEngine(db, str(APP_DIR))
            except Exception as e:
                print(f"[Engine Error] {e}", flush=True)
    return _deploy_engine

# ── Sessions (persistent across restarts) ────────────────────────────────────
# Sessions are persisted to a JSON file so HomeHub restarts (watchdog,
# compose rebuilds, crashes) don't silently log everyone out — which was
# showing as "the Security page not talking to the server" after a 401.
SESSION_FILE = APP_DIR / ".hh_sessions.json"
SESSION_TTL = 8 * 3600  # 8 hours
_sessions = {}
_sessions_lock = threading.Lock()

def _load_sessions():
    try:
        if SESSION_FILE.exists():
            data = json.loads(SESSION_FILE.read_text())
            now = time.time()
            return {
                k: v for k, v in data.items()
                if isinstance(v, dict) and v.get("expires_at", 0) > now
            }
    except Exception:
        pass
    return {}

def _save_sessions():
    try:
        SESSION_FILE.write_text(json.dumps(_sessions))
        os.chmod(SESSION_FILE, 0o600)
    except Exception:
        pass

_sessions = _load_sessions()

def create_session(username, role="root"):
    token = secrets.token_urlsafe(32)
    ip = ""
    try:
        ip = _client_ip()
    except Exception:
        pass
    with _sessions_lock:
        _sessions[token] = {"username": username, "role": role, "ip": ip,
                            "created_at": time.time(),
                            "expires_at": time.time() + SESSION_TTL}
        _save_sessions()
    return token

def get_session(token):
    if not token:
        return None
    with _sessions_lock:
        s = _sessions.get(token)
        if s and time.time() < s["expires_at"]:
            return s
        if s:
            del _sessions[token]
            _save_sessions()
    return None

def purge_sessions():
    with _sessions_lock:
        now = time.time()
        expired = [k for k, v in _sessions.items() if now >= v["expires_at"]]
        for k in expired:
            del _sessions[k]
        if expired:
            _save_sessions()

# ── Password Utilities ────────────────────────────────────────────────────────
def hash_password(password, salt=None):
    if not salt:
        salt = secrets.token_hex(16)
    hashed = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 200000).hex()
    return f"{salt}:{hashed}"

def verify_password(password, stored_hash):
    if not stored_hash or ":" not in stored_hash:
        return False
    salt, hashed = stored_hash.split(":", 1)
    check = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 200000).hex()
    return hmac.compare_digest(check, hashed)

# ── 2FA / TOTP (RFC 6238, sem dependências) ───────────────────────────────────
_TOTP_STEP = 30
_TOTP_DIGITS = 6

def _b32decode_pad(s):
    s = str(s).upper().replace(" ", "")
    s += "=" * ((8 - len(s) % 8) % 8)
    return base64.b32decode(s)

def _totp_at(secret_b32, counter):
    key = _b32decode_pad(secret_b32)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** _TOTP_DIGITS)
    return f"{code:0{_TOTP_DIGITS}d}"

def _totp_verify(secret_b32, code, window=1):
    if not secret_b32 or not code or not re.fullmatch(r"\d{6}", str(code)):
        return False
    step = int(time.time()) // _TOTP_STEP
    for i in range(-window, window + 1):
        if hmac.compare_digest(_totp_at(secret_b32, step + i), str(code)):
            return True
    return False

def _gen_totp_secret():
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")

def _otpauth_uri(secret, username):
    return (f"otpauth://totp/HomeHub:{username}?secret={secret}"
            "&issuer=HomeHub&algorithm=SHA1&digits=6&period=30")

# ── Auth Config ───────────────────────────────────────────────────────────────
def load_auth():
    default_user = os.environ.get("ADMIN_USER", "admin")
    default_pass = os.environ.get("ADMIN_PASSWORD", "admin123")
    if AUTH_F.exists():
        try:
            with open(AUTH_F) as f:
                d = json.load(f)
                if d.get("username") and d.get("password_hash"):
                    return d
        except Exception:
            pass
    d = {
        "username": default_user,
        "password_hash": hash_password(default_pass),
        "is_default_password": default_pass == "admin123",
        "created_at": time.time(), "updated_at": time.time()
    }
    save_auth(d)
    return d

def save_auth(data):
    with open(AUTH_F, "w") as f:
        json.dump(data, f, indent=2)

# ── Usuários do Hub (RBAC: root > sysadmin > developer > user1) ───────────────
USERS_F = APP_DIR / "users.json"
HUB_ROLES = ("root", "sysadmin", "developer", "user1")
_ROLE_LEVEL = {"user1": 1, "developer": 2, "sysadmin": 3, "root": 4}
TERMINAL_URL = os.environ.get("TERMINAL_URL", "http://host.docker.internal:7681")
TERMINAL_ADMIN_SECRET = os.environ.get("TERMINAL_ADMIN_SECRET", "")
TERMINAL_SESSION_PREFIX = "webterm-"

def load_hub_users():
    if USERS_F.exists():
        try:
            data = json.loads(USERS_F.read_text())
            if isinstance(data, dict) and isinstance(data.get("users"), list):
                return data
        except Exception:
            pass
    # Seed: a conta ROOT é a conta do auth.json — protegida, nunca excluída.
    try:
        root = load_auth()
        return {"users": [{
            "id": "u_root", "username": root.get("username", "admin"),
            "name": "Administrador ROOT", "role": "root", "email": "",
            "active": True, "created_at": time.time(), "last_login": None,
        }]}
    except Exception:
        return {"users": []}

def save_hub_users(data):
    USERS_F.write_text(json.dumps(data, indent=2, ensure_ascii=False))
    os.chmod(USERS_F, 0o600)

def find_hub_user(uid_or_username, data=None):
    data = data if data is not None else load_hub_users()
    target = str(uid_or_username or "").strip().lower()
    for u in data.get("users", []):
        u_email = str(u.get("email") or "").strip().lower()
        u_user = str(u.get("username") or "").strip().lower()
        u_id = str(u.get("id") or "").strip().lower()
        if target and (target == u_email or target == u_user or target == u_id):
            return data, u
    return data, None

def current_role():
    s = get_session(get_session_token())
    if not s:
        return None
    # Sessões antigas (sem role gravado) pertencem à conta root do auth.json.
    return s.get("role") or "root"

def current_level():
    return _ROLE_LEVEL.get(current_role() or "", 0)

def require_level(minimum):
    """RBAC no BACKEND: o frontend esconde botões, mas é aqui que a operação
    é realmente barrada mesmo chamando a API diretamente."""
    def deco(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            s = get_session(get_session_token())
            if not s:
                return jsonify({"success": False, "error": "Acesso não autorizado."}), 401
            lvl = _ROLE_LEVEL.get(s.get("role") or "root", 0)
            if lvl < minimum:
                return jsonify({"success": False,
                                "error": "Permissão insuficiente para esta operação."}), 403
            return f(*args, **kwargs)
        return wrapper
    return deco

def _terminal_api(method, path, payload=None):
    """Chama a API admin do Web Terminal. Best-effort: falha do terminal não
    bloqueia a operação no Hub (o terminal recarrega auth.json por mtime)."""
    if not TERMINAL_ADMIN_SECRET:
        return False
    try:
        r = http_requests.request(
            method, f"{TERMINAL_URL}{path}", json=payload or {},
            headers={"X-Admin-Secret": TERMINAL_ADMIN_SECRET}, timeout=6)
        return 200 <= r.status_code < 300
    except Exception:
        return False

def _terminal_request(method, path, payload=None):
    """Chama a API admin do Web Terminal e DEVOLVE o resultado ao cliente.
    Retorna (ok, corpo_dict, status_http)."""
    if not TERMINAL_ADMIN_SECRET:
        return False, {"error": "TERMINAL_ADMIN_SECRET não configurado no Hub."}, 503
    try:
        r = http_requests.request(
            method, f"{TERMINAL_URL}{path}", json=payload or {},
            headers={"X-Admin-Secret": TERMINAL_ADMIN_SECRET}, timeout=8)
        try:
            body = r.json()
        except Exception:
            body = {"error": f"Resposta inválida do terminal (HTTP {r.status_code})."}
        return (200 <= r.status_code < 300), body, r.status_code
    except Exception as e:
        return False, {"error": f"Terminal Web inacessível: {e}"}, 502

def _terminal_sync_user(username, password=None, hub_role=None, active=None, delete=False):
    """Espelha o usuário do Hub no terminal (mesmo username). Best-effort:
    se ele ainda não existir no terminal e houver senha, cria; se já existir,
    o endpoint de criação responde 409 e caímos no update de senha."""
    ok = True
    if delete:
        ok = _terminal_api("DELETE", f"/api/admin/users/{username}")
        return ok
    if password is not None:
        created = _terminal_api("POST", "/api/admin/users", {
            "username": username, "password": password,
            "hub_role": hub_role or "user1",
        })
        if not created:  # já existe (409) → só atualiza a senha
            created = _terminal_api("POST", f"/api/admin/users/{username}/password",
                                    {"password": password})
        ok = created and ok
    if hub_role is not None:
        ok = _terminal_api("POST", f"/api/admin/users/{username}/role", {"hub_role": hub_role}) and ok
    if active is not None:
        ok = _terminal_api("POST", f"/api/admin/users/{username}/active", {"active": active}) and ok
    return ok

# ── Projects ──────────────────────────────────────────────────────────────────
def load_projects():
    if PROJECTS_F.exists():
        try:
            with open(PROJECTS_F) as f:
                return json.load(f)
        except Exception:
            pass
    return []

def save_projects(projects):
    with open(PROJECTS_F, "w") as f:
        json.dump(projects, f, indent=2, ensure_ascii=False)

# ── Decorators ────────────────────────────────────────────────────────────────
def get_session_token():
    return request.cookies.get("homehub_session")

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        s = get_session(get_session_token())
        if not s:
            return jsonify({"success": False, "error": "Acesso não autorizado."}), 401
        return f(*args, **kwargs)
    return decorated

def audit(action, details=""):
    try:
        db = get_db()
        if db:
            s = get_session(get_session_token())
            user = s["username"] if s else "anonymous"
            db.add_audit(action, details, _client_ip(), user)
    except Exception:
        pass

# ── Security headers ──────────────────────────────────────────────────────────
@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    # CSP das páginas do próprio HomeHub (não aplica aos apps de terceiros em
    # /apps, /decam, /ridecheck — código arbitrário não pode ser restringido
    # aqui; o _proxy já elimina o cookie de sessão antes de encaminhar).
    if not request.path.startswith(("/apps/", "/decam", "/ridecheck")):
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://static.cloudflareinsights.com; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "img-src 'self' data: blob: https:; "
            "font-src 'self' data: https://fonts.gstatic.com; "
            "media-src 'self' data:; "
            "connect-src 'self' https://cloudflareinsights.com; "
            "object-src 'none'; "
            "frame-ancestors 'self'; base-uri 'self'; form-action 'self'"
        )
    return response

# ════════════════════════════════════════════════════════════════════════════
# STATIC FILE SERVING
# ════════════════════════════════════════════════════════════════════════════
# Assets needed by the login page / portal must render without a session,
# otherwise browsers receive the HTML but the CSS/JS load as 401.
PUBLIC_STATIC_EXTS = {
    ".css", ".js", ".mjs", ".map",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".avif", ".ico",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
}
# Never expose source code, database files, configs or backups over HTTP.
BLOCKED_STATIC_EXTS = {
    ".py", ".pyc", ".pyo", ".pyd",
    ".db", ".sqlite", ".sqlite3",
    ".log", ".bak", ".old", ".pem", ".key", ".env",
    ".json",
}
# Allowlist do que pode ser servido sob sessão (views locais). Qualquer extensão
# fora disso (ex.: .pre-redact-*, .bak-*) retorna 404 mesmo autenticado.
VIEW_STATIC_EXTS = {
    ".html", ".htm", ".xml", ".txt", ".md", ".webmanifest",
}

@app.route("/")
@app.route("/index.html")
def serve_index():
    resp = send_file(APP_DIR / "index.html")
    resp.headers["Cache-Control"] = "no-store"
    return resp

@app.route("/admin")
@app.route("/admin.html")
def serve_admin():
    resp = send_file(APP_DIR / "admin.html")
    resp.headers["Cache-Control"] = "no-store"
    return resp

@app.route("/apps/<slug>/", defaults={"proxy_path": ""}, methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
@app.route("/apps/<slug>/<path:proxy_path>", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
def serve_deployed_app(slug, proxy_path):
    """Expose a published Deploy Center app beneath the HomeHub public domain."""
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,79}", slug):
        abort(404)

    project = next((p for p in load_projects()
                    if p.get("slug") == slug or p.get("id") == slug), None)
    if not project or not project.get("published"):
        abort(404)

    db = get_db()
    deployed = db.get_app(project.get("id")) if db else None
    if not deployed:
        abort(404)

    try:
        port = int(deployed.get("port"))
    except (TypeError, ValueError):
        abort(404)
    if not (4000 <= port <= 4999 or port == 3010):
        abort(404)

    prefix = f"/apps/{slug}"
    # Projetos em subpath (/apps/<slug>/) exigem que o upstream receba o caminho
    # completo para que o basePath/base funcione. O tratamento da barra final
    # depende do tipo do app:
    #   • Next.js → responde 307/308 a partir do prefixo SEM a barra final
    #                ('/apps/<slug>'); se receber a barra, rebate para o mesmo
    #                e entra em loop 308 <-> barra (ERR_TOO_MANY_REDIRECTS).
    #   • Vite/estáticos servidos por nginx → precisam da barra final para cair
    #                no bloco 'location ^~ /apps/<slug>/' que serve o index.html.
    #                Sem ela, o 'location = /apps/<slug>' (exato) devolve um 301
    #                absoluto apontando para o host interno, quebrando o app.
    # Fix: antes enviávamos o prefixo SEM barra para todo proxy vazio; isso
    # quebrava qualquer app Vite/estático (como o Vistorias), pois o 301 do
    # nginx apontava para 172.17.0.1 (IP interno inacessível ao navegador).
    if project.get("subpath"):
        stack = (deployed.get("stack") or "").lower()
        if proxy_path:
            upstream_path = prefix + "/" + proxy_path
        elif stack == "nextjs":
            upstream_path = prefix            # Next: raiz do subpath sem barra
        else:
            upstream_path = prefix + "/"      # nginx/Vite/estáticos: com barra
    else:
        upstream_path = "/" + proxy_path
    target_host = "http://book_motorista_app:3010" if (deployed.get("container_name") == "book_motorista_app" or port == 3010) else f"http://172.17.0.1:{port}"
    proxied = _proxy(target_host, upstream_path, public_prefix=prefix)
    # Lembre o navegador a qual app pertence, para que assets absolutos
    # (ex.: /_next/...) possam ser roteados de volta ao container correto.
    resp = proxied[0] if isinstance(proxied, tuple) else proxied
    try:
        resp.set_cookie("hh-app-slug", slug, path="/", samesite="Lax")
    except Exception:
        pass
    return proxied

@app.route("/<path:filename>")
def serve_static(filename):
    # FIX: arquivos locais do portal (styles.css, admin.js, etc.) sao servidos
    # ANTES do proxy por cookie. Sem isso, quem visitou um app publicado
    # (cookie hh-app-slug) tinha os assets do portal desviados para o
    # container do app, que respondia index.html (text/html) ou 404 e a
    # pagina do portal quebrava (sem CSS/JS).
    clean = filename.split("?")[0].lstrip("/")
    safe = secure_filename(clean)
    filepath = APP_DIR / safe
    if filepath.exists() and filepath.is_file():
        ext = filepath.suffix.lower()
        # Sensitive files are never served, even to authenticated users.
        if ext in BLOCKED_STATIC_EXTS:
            abort(404)
        # Public assets (CSS/JS/images/fonts) render the login page and portal.
        if ext in PUBLIC_STATIC_EXTS:
            resp = send_file(filepath)
            resp.headers["Cache-Control"] = "no-cache"
            return resp
        # Everything else still requires a session AND must be a known view
        # extension (allowlist — .bak-*, .pre-redact-*, etc. never served).
        if ext not in VIEW_STATIC_EXTS:
            abort(404)
        s = get_session(get_session_token())
        if not s:
            return jsonify({"success": False, "error": "Acesso não autorizado."}), 401
        resp = send_file(filepath)
        if filepath.suffix in {".html", ".xml", ".txt"}:
            resp.headers["Cache-Control"] = "no-cache"
        return resp

    # Apps publicados (Next/Vite) emitem assets absolutos (/_next/..., /assets/...).
    # O nginx de borda envia X-App-Slug ou o portal seta o cookie hh-app-slug;
    # encaminha para o container correspondente em vez de dar 404.
    # So chega aqui se o arquivo NAO existe localmente.
    slug = request.headers.get("X-App-Slug") or request.cookies.get("hh-app-slug")
    is_api_auth = filename.startswith("api/auth/")
    if (slug and re.fullmatch(r"[a-z0-9][a-z0-9-]{0,79}", slug)
            and (is_api_auth or not filename.startswith(("api/", "apps/")))):
        project = next((p for p in load_projects()
                        if p.get("slug") == slug and p.get("published")), None)
        if project:
            db = get_db()
            deployed = db.get_app(project.get("id")) if db else None
            if deployed:
                try:
                    port = int(deployed.get("port"))
                except (TypeError, ValueError):
                    port = 0
                if 4000 <= port <= 4999 or port == 3010:
                    base = "http://book_motorista_app:3010" if (deployed.get("container_name") == "book_motorista_app" or port == 3010) else f"http://172.17.0.1:{port}"
                    prefix = f"/apps/{slug}"
                    # /api/auth/* dos apps é relativo à raiz do domínio. Para apps
                    # em subpath, o auth precisa atingir o basePath do app.
                    if is_api_auth:
                        if project.get("subpath"):
                            path = prefix + "/" + filename
                        else:
                            path = "/" + filename
                    else:
                        path = "/" + filename
                    return _proxy(base, path, public_prefix=prefix)

    # Missing asset-looking files are plain 404s, not auth challenges.
    ext = Path(filename.split("?")[0]).suffix.lower()
    if ext in PUBLIC_STATIC_EXTS:
        abort(404)
    s = get_session(get_session_token())
    if not s:
        return jsonify({"success": False, "error": "Acesso não autorizado."}), 401
    if filename.startswith("decam"):
        return _proxy("http://homeserver-decam:80", "/" + filename[5:])
    if filename.startswith("ridecheck"):
        return _proxy("http://ridecheck-web:3001", "/" + filename, public_prefix="")
    abort(404)

def _proxy(base_url, path, public_prefix=""):
    """Reverse proxy. When public_prefix is set, upstream redirects
    (Location headers) are rewritten to stay under the public prefix so
    sub-path mounts (/apps/<slug>/) keep working for Next.js/Vite apps."""
    try:
        url = base_url + path
        # Nunca vazar o cookie de sessão do HomeHub nem o Authorization do admin
        # para containers de terceiros (apps deployados são código arbitrário).
        upstream_headers = {}
        for k, v in request.headers:
            lk = k.lower()
            if lk in ("host", "connection", "authorization"):
                continue
            if lk == "cookie":
                kept = "; ".join(c.strip() for c in v.split(";")
                                 if not c.strip().lower().startswith("homehub_session="))
                if kept:
                    upstream_headers[k] = kept
                continue
            upstream_headers[k] = v
        resp = http_requests.request(
            method=request.method,
            url=url,
            headers=upstream_headers,
            data=request.get_data(),
            params=request.args,
            allow_redirects=False,
            timeout=15,
            stream=True
        )
        excluded = {"content-encoding", "transfer-encoding", "connection", "set-cookie"}
        headers = {k: v for k, v in resp.headers.items() if k.lower() not in excluded}
        if public_prefix and resp.status_code in (301, 302, 303, 307, 308):
            loc_key = next((k for k in headers if k.lower() == "location"), None)
            loc = headers.get(loc_key, "") if loc_key else ""
            if loc:
                headers[loc_key] = _prefix_location(loc, public_prefix)
        flask_resp = Response(resp.iter_content(65536), status=resp.status_code, headers=headers)
        if hasattr(resp, "raw") and hasattr(resp.raw, "headers") and hasattr(resp.raw.headers, "getlist"):
            for cookie in resp.raw.headers.getlist("Set-Cookie"):
                flask_resp.headers.add("Set-Cookie", cookie)
        elif "set-cookie" in resp.headers:
            flask_resp.headers.add("Set-Cookie", resp.headers["set-cookie"])
        return flask_resp
    except Exception as e:
        return jsonify({"error": str(e)}), 502


def _prefix_location(loc, prefix):
    """Join an upstream Location with the public prefix.

    Redirects absolutos para OUTROS hosts públicos (ex.: OAuth) são mantidos.
    Mas o nginx, com `absolute_redirect on` (default), gera 301 com o host
    absoluto do container interno (ex.: 172.17.0.1). Se passasse intacto, o
    navegador seguiria para esse IP interno e o app quebraria. Para esses hosts
    (IP literal), o caminho é reescrito como relativo sob o prefixo público.
    """
    import urllib.parse as _up
    path = loc
    if re.match(r"^https?://", loc):
        parsed = _up.urlparse(loc)
        host = (parsed.hostname or "").lower()
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
            # Redirecionamento para host interno (IP literal): descarta o host
            # e usa apenas o caminho, re-prefixado abaixo.
            path = parsed.path or "/"
        else:
            # Host externo (ex.: OAuth / outros domínios) — não toca.
            return loc
    else:
        if not loc.startswith("/"):
            path = "/" + loc
    if path.startswith(prefix.rstrip("/")):
        return path
    return prefix.rstrip("/") + path

# ════════════════════════════════════════════════════════════════════════════
# FILE MANAGER API
# ════════════════════════════════════════════════════════════════════════════
def _fm_resolve(requested):
    """Resolve um caminho relativo sob FILES_ROOT, bloqueando path-traversal."""
    if requested is None:
        requested = ""
    requested = requested.lstrip("/")
    full = (FILES_ROOT / requested).resolve()
    try:
        full.relative_to(FILES_ROOT)
    except (ValueError, OSError):
        return None
    return full

@app.route("/api/files")
@require_auth
@require_level(3)
def api_files_list():
    rel = request.args.get("path", "") or ""
    full = _fm_resolve(rel)
    if full is None:
        return jsonify({"success": False, "error": "Caminho fora da raiz permitida."}), 400
    if _fm_is_sensitive(rel):
        return jsonify({"success": False, "error": "Acesso negado a arquivos sensíveis."}), 403
    if not full.exists():
        return jsonify({"success": False, "error": "Caminho não existe."}), 404

    items = []
    if full.is_dir():
        try:
            entries = sorted(full.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower()))
        except PermissionError:
            entries = []
        for p in entries:
            try:
                st = p.stat()
            except OSError:
                continue
            try:
                rel = str(p.relative_to(FILES_ROOT))
            except ValueError:
                rel = p.name
            items.append({
                "name": p.name,
                "path": rel,
                "type": "dir" if p.is_dir() else "file",
                "size": st.st_size,
                "mtime": int(st.st_mtime),
            })

    parent = None
    if full != FILES_ROOT:
        try:
            parent = str(full.parent.relative_to(FILES_ROOT))
        except ValueError:
            parent = None

    return jsonify({
        "success": True,
        "root": str(FILES_ROOT),
        "absolute": str(full),
        "current": str(full.relative_to(FILES_ROOT)),
        "parent": parent,
        "is_dir": full.is_dir(),
        "items": items,
    })

@app.route("/api/files/download")
@require_auth
@require_level(3)
def api_files_download():
    rel = request.args.get("path", "") or ""
    full = _fm_resolve(rel)
    if full is None or not full.is_file():
        return jsonify({"success": False, "error": "Arquivo inválido."}), 400
    if _fm_is_sensitive(rel):
        return jsonify({"success": False, "error": "Acesso negado a arquivos sensíveis."}), 403
    audit("file_download", f"Baixou: {full}")
    return send_file(full, as_attachment=True, download_name=full.name)

@app.route("/api/files/download-all")
@require_auth
@require_level(3)
def api_files_download_all():
    rel = request.args.get("path", "") or ""
    full = _fm_resolve(rel)
    if full is None or not full.is_dir():
        return jsonify({"success": False, "error": "Diretório inválido."}), 400
    if _fm_is_sensitive(rel):
        return jsonify({"success": False, "error": "Acesso negado a arquivos sensíveis."}), 403

    import tempfile, zipfile, shutil
    tmp = tempfile.NamedTemporaryFile(suffix=".zip", delete=False)
    tmp_path = tmp.name
    tmp.close()
    try:
        with zipfile.ZipFile(tmp_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for root, _dirs, files in os.walk(full):
                for name in files:
                    fp = Path(root) / name
                    try:
                        rel = str(fp.relative_to(full.parent))
                        zf.write(fp, rel)
                    except Exception:
                        continue
        zip_name = (full.name if full.name else "servidor") + ".zip"
        audit("file_download_all", f"Zip: {full} -> {zip_name}")
        return send_file(tmp_path, as_attachment=True, download_name=zip_name)
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass

@app.route("/api/files/delete", methods=["POST"])
@require_auth
@require_level(3)
def api_files_delete():
    import shutil
    data = request.get_json(silent=True) or {}
    rel = data.get("path", "") or ""
    full = _fm_resolve(rel)
    if full is None or full == FILES_ROOT:
        return jsonify({"success": False, "error": "Ação não permitida no caminho informado."}), 400
    if _fm_is_sensitive(rel):
        return jsonify({"success": False, "error": "Acesso negado a arquivos sensíveis."}), 403
    if not full.exists():
        return jsonify({"success": False, "error": "Não existe."}), 404
    try:
        if full.is_dir():
            shutil.rmtree(full)
        else:
            full.unlink()
    except Exception as e:
        return jsonify({"success": False, "error": f"Erro ao excluir: {e}"}), 500
    audit("file_delete", f"Excluiu: {full}")
    return jsonify({"success": True, "message": f"Excluído: {full}"})


# ════════════════════════════════════════════════════════════════════════════
# PUBLIC API
# ════════════════════════════════════════════════════════════════════════════

@app.route("/api/projects")
def api_projects():
    projects = load_projects()
    # Expõe apenas a ficha pública (portal). Campos internos (source_path,
    # tracked_by_radar, stack, ports…) nunca saem por esta rota pública.
    public_keys = ("id", "slug", "name", "description", "icon", "category",
                   "badge", "url", "status", "featured", "published", "tags")
    return jsonify({"success": True, "projects": [
        {k: p.get(k) for k in public_keys if k in p} for p in projects]})

@app.route("/api/session")
def api_session():
    s = get_session(get_session_token())
    if s:
        auth = load_auth()
        return jsonify({"authenticated": True, "username": s["username"], "is_default_password": auth.get("is_default_password", False)})
    return jsonify({"authenticated": False, "username": None, "is_default_password": False})

# ════════════════════════════════════════════════════════════════════════════
# SYSTEM STATUS
# ════════════════════════════════════════════════════════════════════════════

_net_prev = {"rx": 0, "tx": 0, "ts": 0}

def _fmt_bytes(b):
    try:
        b = float(b or 0)
    except (TypeError, ValueError):
        b = 0.0
    if b < 0:
        b = 0.0
    units = ("B", "KB", "MB", "GB", "TB")
    i = 0
    while b >= 1024 and i < len(units) - 1:
        b /= 1024
        i += 1
    if i == 0:
        return f"{b:.0f} {units[i]}"
    if b >= 100:
        return f"{b:.0f} {units[i]}"
    if b >= 10:
        return f"{b:.1f} {units[i]}"
    return f"{b:.2f} {units[i]}"

def _get_net():
    global _net_prev
    try:
        with open("/proc/net/dev") as f:
            lines = f.readlines()[2:]
        rx = tx = 0
        for line in lines:
            parts = line.split()
            iface = parts[0].rstrip(":")
            if iface.startswith(("lo", "docker", "veth", "br-")):
                continue
            rx += int(parts[1]); tx += int(parts[9])
        now = time.time()
        dt = now - _net_prev["ts"] if _net_prev["ts"] else 1
        rx_speed = max(0, (rx - _net_prev["rx"]) / dt) if _net_prev["ts"] else 0
        tx_speed = max(0, (tx - _net_prev["tx"]) / dt) if _net_prev["ts"] else 0
        _net_prev = {"rx": rx, "tx": tx, "ts": now}
        return _fmt_bytes(rx_speed) + "/s", _fmt_bytes(tx_speed) + "/s", _fmt_bytes(rx), _fmt_bytes(tx)
    except Exception:
        return "0 B/s", "0 B/s", "0 B", "0 B"

def _parse_ngrok_tunnels(payload):
    ssh_host = ssh_port = http_url = None
    for t in (payload or {}).get("tunnels") or []:
        proto = (t.get("proto") or "").lower()
        public_url = (t.get("public_url") or "").strip()
        if not public_url:
            continue
        if proto == "tcp" or public_url.startswith("tcp://"):
            addr = public_url.replace("tcp://", "")
            host, _, port = addr.rpartition(":")
            if host and port:
                ssh_host, ssh_port = host, port
        elif proto in ("https", "http"):
            url = public_url.replace("http://", "https://") if public_url.startswith("http://") else public_url
            # Domínio fixo reservado (*.ngrok-free.dev) tem prioridade sobre
            # as URLs dinâmicas (*.ngrok-free.app)
            if "dashboard.ngrok.com" not in url and (http_url is None or ".ngrok-free.dev" in url):
                http_url = url
    return ssh_host, ssh_port, http_url

def _get_ngrok_info():
    """Read the live ngrok public TCP/HTTP endpoints via HTTP inspect API
    plus recent container logs. Hardening 2026-09-09 (task_0003): the old
    `docker exec <ngrok> wget/curl 127.0.0.1:4040` fallback was removed so
    the dashboard works with EXEC=0 on the socket-proxy. `docker logs`
    needs only CONTAINERS=1 (GET, no EXEC)."""
    # O gateway HTTPS do ngrok de sistema (HomeHub/terminal) expõe a API na
    # porta 4040; o túnel SSH TCP roda num agente local separado na 4041.
    # Consultamos ambos e combinamos: TCP -> acesso SSH, HTTPS -> domínio fixo.
    api_urls = [
        "http://172.19.0.1:4041/api/tunnels",
        "http://172.18.0.1:4041/api/tunnels",
        "http://172.17.0.1:4041/api/tunnels",
        "http://127.0.0.1:4041/api/tunnels",
        "http://homeserver-ngrok:4040/api/tunnels",
        "http://ngrok:4040/api/tunnels",
        "http://172.17.0.1:4040/api/tunnels",
        "http://127.0.0.1:4040/api/tunnels",
    ]
    ssh_host = ssh_port = http_url = None
    for url in api_urls:
        try:
            resp = http_requests.get(url, timeout=1.5)
            if not resp.ok:
                continue
            h, p, u = _parse_ngrok_tunnels(resp.json())
            if h and not ssh_host:
                ssh_host, ssh_port = h, p
            if u and not http_url:
                http_url = u
            if ssh_host and http_url:
                return ssh_host, ssh_port, http_url
        except Exception:
            continue

    if ssh_host or http_url:
        return ssh_host, ssh_port, http_url

    # Hardening 2026-09-09 (task_0003): sem fallback via `docker exec`
    # (exigia EXEC=1 no socket-proxy). A API HTTP acima + `docker logs`
    # abaixo (GET, só CONTAINERS=1) cobrem os casos sem EXEC.
    for name in ("homeserver-ngrok", "ngrok"):
        try:
            r = subprocess.run(
                ["docker", "logs", "--tail", "120", name],
                capture_output=True, text=True, timeout=5,
            )
            text = f"{r.stdout or ''}\n{r.stderr or ''}"
            tcp_hits = re.findall(r"tcp://([A-Za-z0-9.-]+\.ngrok[^/\s]*):(\d+)", text)
            https_hits = re.findall(r"https://[A-Za-z0-9.-]+\.ngrok[^/\s]*", text)
            host = port = http_url = None
            if tcp_hits:
                host, port = tcp_hits[-1]
            if https_hits:
                http_url = https_hits[-1]
            if host or http_url:
                return host, port, http_url
        except Exception:
            continue

    return None, None, None

# ── Cloudflare Tunnel URL (túnel rápido trycloudflare.com) ──────────────────
# O túnel rápido do Cloudflare é o gateway público HTTP principal (sem limite
# de requests). A URL só muda quando o container cloudflared reinicia, então
# cacheamos o resultado para não reler os logs a cada /api/status.
_cf_url_cache = {"url": None, "checked_at": 0.0}
_CF_URL_TTL = 30.0  # segundos

def _read_cloudflare_url():
    """Descobre a URL pública do túnel rápido do Cloudflare lendo os logs do
    container. Retorna None se o túnel não estiver no ar. Resultado fica em
    cache por _CF_URL_TTL segundos."""
    global _cf_url_cache
    now = time.time()
    if _cf_url_cache["url"] and (now - _cf_url_cache["checked_at"]) < _CF_URL_TTL:
        return _cf_url_cache["url"]

    url = None
    try:
        r = subprocess.run(
            ["docker", "logs", "homeserver-cloudflare"],
            capture_output=True, text=True, timeout=5,
        )
        text = f"{r.stdout or ''}\n{r.stderr or ''}"
        # O host do túnel usa letras minúsculas e hífens; descartamos o
        # endpoint da API (api.trycloudflare.com) que aparece nos logs.
        hits = re.findall(
            r"https://[a-z0-9](?:[a-z0-9-]{0,60}[a-z0-9])?\.trycloudflare\.com",
            text,
        )
        hits = [h for h in hits if h != "https://api.trycloudflare.com"]
        if hits:
            url = hits[-1]  # a última ocorrência é a URL vigente
    except Exception:
        pass

    if url:
        _cf_url_cache = {"url": url, "checked_at": now}
    return url

# ── Terminal web (ttyd) via túnel ngrok ─────────────────────────────────────
_terminal_url_cache = {"url": None, "checked_at": 0.0}
_TERMINAL_URL_TTL = 30.0

def _read_ngrok_terminal_url():
    """URL pública do Terminal Web (ttyd) via Cloudflare Tunnel nomeado.
    Fixo em terminal.decamservice.com sem limite de requests."""
    return "https://terminal.decamservice.com"

def _get_cpu_temp():
    """Return the CPU temperature in Celsius (float), or None if unavailable."""
    base = "/sys/class/thermal"
    try:
        zones = [z for z in os.listdir(base) if z.startswith("thermal_zone")]
    except Exception:
        zones = []
    best = None
    for z in zones:
        try:
            with open(os.path.join(base, z, "temp")) as f:
                millideg = int(f.read().strip())
            temp = millideg / 1000.0
            if 0 < temp < 120:  # sanity filter to drop bogus/invalid readings
                if best is None or temp > best:
                    best = temp
        except Exception:
            continue
    return round(best, 1) if best is not None else None

def get_system_status():
    status = {}
    # CPU
    try:
        with open("/proc/stat") as f:
            line = f.readline()
        vals = list(map(int, line.split()[1:]))
        idle = vals[3]; total = sum(vals)
        time.sleep(0.05)
        with open("/proc/stat") as f:
            line = f.readline()
        vals2 = list(map(int, line.split()[1:]))
        idle2 = vals2[3]; total2 = sum(vals2)
        dt = total2 - total
        status["cpu_percent"] = round((1 - (idle2 - idle) / dt) * 100, 1) if dt > 0 else 0
    except Exception:
        status["cpu_percent"] = 0

    # CPU temperature (°C)
    status["cpu_temp"] = _get_cpu_temp()

    # RAM
    try:
        mem = {}
        with open("/proc/meminfo") as f:
            for line in f:
                parts = line.split(":")
                if len(parts) == 2:
                    mem[parts[0].strip()] = int(parts[1].strip().split()[0])
        total_kb = mem.get("MemTotal", 0)
        avail_kb = mem.get("MemAvailable", 0)
        used_kb  = total_kb - avail_kb
        status["ram_total_gb"] = round(total_kb / (1024**2), 1)
        status["ram_used_gb"]  = round(used_kb  / (1024**2), 1)
        status["ram_percent"]  = round(used_kb / total_kb * 100, 1) if total_kb else 0
    except Exception:
        status.update({"ram_total_gb": 0, "ram_used_gb": 0, "ram_percent": 0})

    # Disk
    try:
        st = os.statvfs("/")
        total = st.f_blocks * st.f_frsize
        free  = st.f_bfree  * st.f_frsize
        used  = total - free
        status["disk_total_gb"] = round(total / (1024**3), 1)
        status["disk_used_gb"]  = round(used  / (1024**3), 1)
        status["disk_percent"]  = round(used / total * 100, 1) if total else 0
    except Exception:
        status.update({"disk_total_gb": 0, "disk_used_gb": 0, "disk_percent": 0})

    # Network
    rx_spd, tx_spd, rx_tot, tx_tot = _get_net()
    status.update({"net_rx_speed": rx_spd, "net_tx_speed": tx_spd, "net_rx_total": rx_tot, "net_tx_total": tx_tot})

    # Uptime
    try:
        with open("/proc/uptime") as f:
            secs = float(f.read().split()[0])
        d, r = divmod(int(secs), 86400); h, r = divmod(r, 3600); m = r // 60
        status["uptime"] = f"{d}d {h}h {m}m" if d else f"{h}h {m}m"
    except Exception:
        status["uptime"] = "--"

    # Docker containers
    containers = []
    try:
        r = subprocess.run(["docker", "ps", "--format", "{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}"],
                           capture_output=True, text=True, timeout=5)
        for line in r.stdout.strip().split("\n"):
            if not line: continue
            parts = line.split("\t")
            containers.append({
                "name": parts[0] if len(parts) > 0 else "",
                "image": parts[1] if len(parts) > 1 else "",
                "status": parts[2] if len(parts) > 2 else "",
                "ports": parts[3] if len(parts) > 3 else ""
            })
    except Exception:
        pass
    status["containers"] = containers

    # Services
    service_defs = [
        {"name": "Portainer", "icon": "🐳", "description": "Gerenciador visual de containers Docker", "url": "/portainer", "container": "homeserver-portainer"},
        {"name": "Adminer", "icon": "🗄️", "description": "Interface web para bancos de dados", "url": "/adminer", "container": "homeserver-adminer"},
        {"name": "PostgreSQL", "icon": "🐘", "description": "Banco de dados relacional principal", "url": None, "container": "homeserver-postgres"},
        {"name": "MySQL", "icon": "🐬", "description": "Banco de dados MySQL", "url": None, "container": "homeserver-mysql"},
        {"name": "Redis", "icon": "⚡", "description": "Cache e sessões in-memory", "url": None, "container": "homeserver-redis"},
        {"name": "Ngrok", "icon": "🌐", "description": "Domínio fixo (HomeHub) + túneis dinâmicos", "url": None, "container": "homeserver-ngrok"},
        {"name": "Cloudflare", "icon": "☁️", "description": "Gateway HTTPS backup (sem limite de requests)", "url": None, "container": "homeserver-cloudflare"},
        {"name": "Terminal Web", "icon": "🖥️", "description": "Shell no navegador via túnel (ttyd)", "url": None, "container": "homeserver-terminal"},
    ]
    active_containers = {c["name"] for c in containers}
    services = []
    for svc in service_defs:
        svc["status"] = "online" if svc["container"] in active_containers else "offline"
        services.append(svc)
    status["services"] = services

    # Tunnel público (live — host/port mudam quando o túnel reinicia)
    ssh_host, ssh_port, ngrok_http = _get_ngrok_info()
    if ssh_host:
        status["ngrok_ssh_host"] = ssh_host
    if ssh_port:
        status["ngrok_ssh_port"] = str(ssh_port)
    if ssh_host and ssh_port:
        user = os.environ.get("SSH_USER", "decsv")
        status["ngrok_ssh_cmd"] = f"ssh {user}@{ssh_host} -p {ssh_port}"

    # Cloudflare Tunnel: gateway HTTP backup (sem limite de requests)
    cf_url = _read_cloudflare_url()
    if cf_url:
        status["cf_url"] = cf_url

    # Terminal web (ttyd via ngrok) — acesso tipo SSH pelo navegador
    term_url = _read_ngrok_terminal_url()
    if term_url:
        status["terminal_url"] = term_url

    # ngrok: domínio fixo (*.ngrok-free.dev) aponta para o HomeHub — gateway
    # principal. URLs dinâmicas (*.ngrok-free.app) também aparecem aqui.
    if ngrok_http:
        status["ngrok_url"] = ngrok_http

    # Fallback para o túnel Vostro se ainda não preenchido
    if not status.get("ngrok_ssh_cmd"):
        v_file = Path("/app/vostro_stats.json")
        if v_file.exists():
            try:
                with open(v_file, "r", encoding="utf-8") as f:
                    vd = json.load(f)
                if vd.get("ngrok_ssh_cmd"):
                    status["ngrok_ssh_cmd"] = vd["ngrok_ssh_cmd"]
                    status["ngrok_ssh_host"] = vd.get("ngrok_ssh_host")
                    status["ngrok_ssh_port"] = vd.get("ngrok_ssh_port")
            except Exception:
                pass

    return status

@app.route("/api/system/clean-ram", methods=["POST"])
@require_auth
def api_clean_ram():
    try:
        import time, psutil
        trigger_path = "/app/clean_ram.trigger"
        with open(trigger_path, "w") as f:
            f.write(str(time.time()))

        time.sleep(1.2)

        mem = psutil.virtual_memory()
        used_gb = round((mem.total - mem.available) / (1024 ** 3), 1)
        total_gb = round(mem.total / (1024 ** 3), 1)
        percent = round(mem.percent, 1)

        return jsonify({
            "success": True,
            "message": f"Cache e memória RAM liberados com sucesso! ({percent}%)",
            "ram_percent": percent,
            "ram_used_gb": used_gb,
            "ram_total_gb": total_gb
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/status")
@require_auth
def api_status():
    return jsonify(get_system_status())

@app.route("/api/requests")
@require_auth
def api_requests():
    limit = request.args.get("limit", 200)
    for target in ["ngrok", "homeserver-ngrok", "localhost"]:
        try:
            resp = http_requests.get(f"http://{target}:4040/api/requests/http?limit={limit}", timeout=1)
            if resp.ok:
                data = resp.json()
                reqs = []
                for r in data.get("requests", []):
                    resp_obj = r.get("response", {})
                    ua_val = r.get("request", {}).get("headers", {}).get("User-Agent", "")
                    if isinstance(ua_val, list): ua_val = ua_val[0] if ua_val else ""
                    reqs.append({
                        "id": r.get("id"), "method": r.get("method"),
                        "path": r.get("path", r.get("uri", "/")),
                        "status_code": resp_obj.get("status_code"),
                        "duration_ms": r.get("duration"),
                        "remote_addr": r.get("remote_addr"),
                        "user_agent": ua_val,
                        "started_at": r.get("started_at"),
                    })
                return jsonify({"requests": reqs, "req_rate": 0})
        except Exception:
            continue
    return jsonify({"requests": [], "req_rate": 0})

# ════════════════════════════════════════════════════════════════════════════
# AUTH ENDPOINTS
# ════════════════════════════════════════════════════════════════════════════
_login_attempts = {}
_login_lock = threading.Lock()

@app.route("/api/login", methods=["POST"])
@limiter.limit("60 per minute")
def api_login():
    ip = _client_ip()
    with _login_lock:
        attempt = _login_attempts.get(ip, {"count": 0, "reset_at": 0})
        if time.time() > attempt["reset_at"]:
            attempt = {"count": 0, "reset_at": time.time() + 60}
        if attempt["count"] >= 60:
            return jsonify({"success": False, "error": "Muitas tentativas. Aguarde 1 minuto."}), 429
        attempt["count"] += 1
        _login_attempts[ip] = attempt

    data = request.get_json(silent=True) or {}
    login_input = str(data.get("username", "") or data.get("email", "")).strip()
    password = str(data.get("password", ""))
    auth = load_auth()

    # Busca usuário no users.json por e-mail ou username (sempre case-insensitive)
    hub_data, hub_user = find_hub_user(login_input)
    is_root = False
    auth_email = str(auth.get("username", "")).strip().lower()

    # 1. Checa se confere com auth.json
    if auth_email and (login_input.lower() == auth_email or login_input.lower() == "admin" or (hub_user and hub_user.get("role") == "root")):
        if verify_password(password, auth.get("password_hash", "")):
            is_root = True

    # 2. Checa com users.json
    if not is_root and hub_user:
        if hub_user.get("active", True) and verify_password(password, hub_user.get("password_hash", "")):
            if hub_user.get("role") == "root":
                is_root = True
                auth["password_hash"] = hub_user.get("password_hash")
                auth["username"] = hub_user.get("email") or auth["username"]
                save_auth(auth)
        else:
            hub_user = None

    if not is_root and not hub_user:
        return jsonify({"success": False, "error": "Credenciais incorretas. Verifique o e-mail e senha digitados."}), 401

    # 2FA para conta root
    if is_root and bool(auth.get("totp_enabled")) and auth.get("totp_secret"):
        code = str(data.get("totp", "") or "").strip()
        if not code:
            return jsonify({"success": False, "needs_totp": True,
                            "error": "Código de autenticação 2FA necessário."}), 200
        if not _totp_verify(auth["totp_secret"], code):
            return jsonify({"success": False, "error": "Código 2FA inválido."}), 401

    role = "root" if is_root else (hub_user.get("role") or "user1")
    session_user = (hub_user.get("email") or hub_user.get("username")) if hub_user else (auth.get("username") or login_input)

    with _login_lock:
        _login_attempts.pop(ip, None)

    token = create_session(session_user, role)
    if hub_data is not None and hub_user is not None:
        hub_user["last_login"] = time.time()
        hub_user["last_login_ip"] = ip
        save_hub_users(hub_data)

    resp = jsonify({
        "success": True,
        "token": token,
        "username": session_user,
        "role": role,
        "is_default_password": False
    })
    resp.set_cookie(
        "homehub_session", token,
        max_age=30 * 86400,
        httponly=True,
        samesite="Lax",
        secure=request.is_secure
    )
    return resp

@app.route("/api/2fa/status")
@require_auth
def api_2fa_status():
    auth = load_auth()
    return jsonify({"enabled": bool(auth.get("totp_enabled")),
                    "username": auth.get("username")})

@app.route("/api/2fa/setup", methods=["POST"])
@require_auth
def api_2fa_setup():
    data = request.get_json(silent=True) or {}
    auth = load_auth()
    if not auth.get("password_hash") or not verify_password(
            str(data.get("password", "")), auth["password_hash"]):
        return jsonify({"success": False, "error": "Senha atual inválida."}), 403
    if not auth.get("totp_secret"):
        auth["totp_secret"] = _gen_totp_secret()
        save_auth(auth)
    return jsonify({"success": True, "secret": auth["totp_secret"],
                    "uri": _otpauth_uri(auth["totp_secret"], auth.get("username", "admin")),
                    "enabled": bool(auth.get("totp_enabled"))})

@app.route("/api/2fa/confirm", methods=["POST"])
@require_auth
def api_2fa_confirm():
    data = request.get_json(silent=True) or {}
    auth = load_auth()
    if not auth.get("password_hash") or not verify_password(
            str(data.get("password", "")), auth["password_hash"]):
        return jsonify({"success": False, "error": "Senha atual inválida."}), 403
    if not auth.get("totp_secret"):
        return jsonify({"success": False, "error": "Nenhum segredo 2FA pendente."}), 400
    if not _totp_verify(auth["totp_secret"], str(data.get("code", "") or "").strip()):
        return jsonify({"success": False,
                        "error": "Código inválido. Confira o relógio do seu dispositivo."}), 400
    auth["totp_enabled"] = True
    save_auth(auth)
    return jsonify({"success": True})

@app.route("/api/2fa/disable", methods=["POST"])
@require_auth
def api_2fa_disable():
    data = request.get_json(silent=True) or {}
    auth = load_auth()
    if not auth.get("password_hash") or not verify_password(
            str(data.get("password", "")), auth["password_hash"]):
        return jsonify({"success": False, "error": "Senha atual inválida."}), 403
    if not bool(auth.get("totp_enabled")) or not auth.get("totp_secret"):
        return jsonify({"success": False, "error": "2FA não está ativo."}), 400
    if not _totp_verify(auth["totp_secret"], str(data.get("code", "") or "").strip()):
        return jsonify({"success": False, "error": "Código inválido."}), 400
    auth["totp_enabled"] = False
    auth.pop("totp_secret", None)
    save_auth(auth)
    return jsonify({"success": True})

@app.route("/api/logout", methods=["POST"])
def api_logout():
    token = get_session_token()
    if token:
        with _sessions_lock:
            _sessions.pop(token, None)
    audit("logout", "Logout")
    resp = jsonify({"success": True})
    resp.delete_cookie("homehub_session")
    return resp

@app.route("/api/change-password", methods=["POST"])
@require_auth
def api_change_password():
    data = request.get_json(silent=True) or {}
    old_pw  = str(data.get("old_password", ""))
    new_pw  = str(data.get("new_password", ""))
    if len(new_pw) < 6:
        return jsonify({"success": False, "error": "A nova senha deve ter pelo menos 6 caracteres."})
    s = get_session(get_session_token()) or {}
    username = s.get("username", "")
    role = s.get("role") or "root"
    if role == "root":
        auth = load_auth()
        if not verify_password(old_pw, auth["password_hash"]):
            return jsonify({"success": False, "error": "Senha atual incorreta."})
        auth["password_hash"] = hash_password(new_pw)
        auth["is_default_password"] = False
        auth["updated_at"] = time.time()
        save_auth(auth)
    else:
        # Usuário do Hub (users.json) — mesma lógica do reset via admin.
        data_users, user = find_hub_user(username)
        if not user or not verify_password(old_pw, user.get("password_hash", "")):
            return jsonify({"success": False, "error": "Senha atual incorreta."})
        user["password_hash"] = hash_password(new_pw)
        save_hub_users(data_users)
        # Mantém a senha do terminal sincronizada (mesmo login nos dois lados).
        _terminal_sync_user(username, password=new_pw)
    audit("change_password", "Senha alterada com sucesso")
    return jsonify({"success": True, "message": "Senha alterada com sucesso."})

# ════════════════════════════════════════════════════════════════════════════
# PROJECT MANAGEMENT
# ════════════════════════════════════════════════════════════════════════════

@app.route("/api/admin/projects", methods=["POST"])
@require_auth
def api_admin_projects_save():
    data = request.get_json(silent=True) or {}
    projects = load_projects()
    project_id = data.get("id", "").strip()
    if not project_id:
        project_id = f"proj-{secrets.token_hex(4)}"
        data["id"] = project_id
        projects.append(data)
        action = "create_project"
    else:
        found = False
        for i, p in enumerate(projects):
            if p.get("id") == project_id:
                projects[i] = data
                found = True
                break
        if not found:
            projects.append(data)
        action = "update_project"
    save_projects(projects)
    audit(action, f"Aplicação: {data.get('name', project_id)}")
    return jsonify({"success": True, "message": "Salvo com sucesso.", "projects": projects})

@app.route("/api/admin/projects/delete", methods=["POST"])
@require_auth
def api_admin_projects_delete():
    data = request.get_json(silent=True) or {}
    target_id = data.get("id", "")
    projects = load_projects()
    deleted = [p for p in projects if p.get("id") == target_id]
    if not deleted:
        return jsonify({"success": False, "error": "Aplicação não encontrada."}), 404
    project = deleted[0]
    projects = [p for p in projects if p.get("id") != target_id]
    save_projects(projects)

    cleanup = {"deploy_apps": [], "compose_containers": []}
    engine = get_engine()
    if engine:
        try:
            cleanup = engine.destroy_portal_project(project)
        except Exception as e:
            audit("delete_project_cleanup_error", str(e))
            return jsonify({
                "success": False,
                "error": f"Removido do portal, mas a limpeza Docker/Deploy Center falhou: {e}",
                "projects": projects,
                "cleanup": cleanup,
            }), 500

    name = project.get("name", target_id)
    audit("delete_project", f"Aplicação removida: {name} (docker={cleanup.get('compose_containers')} deploy={cleanup.get('deploy_apps')})")
    return jsonify({
        "success": True,
        "message": "Removido do portal, Docker e Deploy Center.",
        "projects": projects,
        "cleanup": cleanup,
    })

# ════════════════════════════════════════════════════════════════════════════
# DEPLOY CENTER
# ════════════════════════════════════════════════════════════════════════════
UPLOADS_DIR.mkdir(exist_ok=True)

def _allowed_file(filename):
    fn = filename.lower()
    return fn.endswith(".zip") or fn.endswith(".tar.gz") or fn.endswith(".tgz")

@app.route("/api/deploy/upload", methods=["POST"])
@require_auth
@require_level(3)
def api_deploy_upload():
    if "file" not in request.files:
        return jsonify({"success": False, "error": "Nenhum arquivo enviado."}), 400
    f = request.files["file"]
    if not f.filename or not _allowed_file(f.filename):
        return jsonify({"success": False, "error": "Formato inválido. Use .zip ou .tar.gz"}), 400

    MAX_BYTES = MAX_UPLOAD_MB * 1024 * 1024
    job_id = str(uuid.uuid4())
    upload_dir = UPLOADS_DIR / job_id
    upload_dir.mkdir(parents=True, exist_ok=True)
    safe_name = secure_filename(f.filename)
    dest = upload_dir / safe_name

    total = 0
    with open(dest, "wb") as out:
        while True:
            chunk = f.stream.read(65536)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_BYTES:
                import shutil; shutil.rmtree(upload_dir, ignore_errors=True)
                return jsonify({"success": False, "error": f"Arquivo muito grande. Máximo: {MAX_UPLOAD_MB}MB"}), 413
            out.write(chunk)

    db = get_db()
    app_name   = request.form.get("name", safe_name.rsplit(".", 1)[0])
    description= request.form.get("description", "")
    icon       = request.form.get("icon", "🚀")
    category   = request.form.get("category", "Deploy")
    publish    = request.form.get("publish_to_portal", "false").lower() == "true"
    featured   = request.form.get("featured", "false").lower() == "true"
    # Custom environment vars and extra networks (upload)
    custom_env_vars = request.form.get("custom_env_vars", "").strip()
    extra_networks = request.form.get("extra_networks", "").strip()
    meta       = json.dumps({"filename": safe_name, "size": total, "app_name": app_name,
                             "description": description, "icon": icon, "category": category,
                             "publish": publish, "featured": featured,
                             "custom_env_vars": custom_env_vars,
                             "extra_networks": extra_networks})
    if db:
        db.create_job(job_id, app_name, meta)

    engine = get_engine()
    if engine:
        t = threading.Thread(
            target=engine.run_deploy_job,
            args=(job_id, str(dest), app_name, description, icon, category, publish, featured, request.remote_addr or "", custom_env_vars, extra_networks),
            daemon=False,
        )
        t.start()
    else:
        if db: db.update_job(job_id, status="failed", step="Engine indisponível", error="Módulo de deploy não encontrado.")

    audit("deploy_start", f"Upload iniciado: {app_name} ({total/1024:.0f}KB)")
    return jsonify({"success": True, "job_id": job_id, "app_name": app_name})



def _parse_github_repo(repo_url):
    """Return (owner, repo, branch_hint) from a GitHub URL, or None."""
    url = (repo_url or "").strip()
    m = re.match(r"https?://github\.com/([^/\s]+)/([^/\s?#]+)", url, re.I)
    if not m:
        return None
    owner, repo = m.group(1), m.group(2)
    if repo.lower().endswith(".git"):
        repo = repo[:-4]
    branch_hint = None
    rest = url[m.end():]
    tm = re.search(r"/tree/([^/?#]+)", rest)
    if tm:
        branch_hint = tm.group(1)
    return owner, repo, branch_hint


def _github_api_json(path, token=""):
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "HomeHub-Deploy",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    url = f"https://api.github.com{path}"
    resp = http_requests.get(url, headers=headers, timeout=12)
    return resp


@app.route("/api/deploy/github-keys", methods=["GET"])
@require_auth
@require_level(4)
def api_deploy_github_keys():
    """Lista chaves do GitHub salvas (somente nome + sufixo; nunca o token completo.."""
    keys = _load_gh_keys()
    masked = [{"name": name, "hint": f"…{str(token)[-4:]}"} for name, token in keys.items()]
    return jsonify({"success": True, "keys": masked})

@app.route("/api/deploy/github-keys", methods=["POST"])
@require_auth
@require_level(4)
def api_deploy_github_keys_save():
    data = request.get_json(force=True, silent=True) or {}
    name  = (data.get("name") or "").strip()
    token = (data.get("token") or "").strip()
    if not name or not token:
        return jsonify({"success": False, "error": "Nome e token obrigatórios."}), 400
    if len(name) > 60:
        return jsonify({"success": False, "error": "Nome muito longo."}), 400
    keys = _load_gh_keys()
    keys[name] = token
    if _save_gh_keys(keys):
        return jsonify({"success": True, "message": f"Chave '{name}' salva com sucesso."})
    return jsonify({"success": False, "error": "Não foi possível salvar a chave."}), 500


@app.route("/api/deploy/github-keys/<path:key_name>", methods=["DELETE"])
@require_auth
@require_level(4)
def api_deploy_github_keys_delete(key_name):
    keys = _load_gh_keys()
    if key_name in keys:
        del keys[key_name]
        _save_gh_keys(keys)
        return jsonify({"success": True, "message": "Chave removida."})
    return jsonify({"success": False, "error": "Chave não encontrada."}), 404

@app.route("/api/deploy/github-keys", methods=["DELETE"])
@require_auth
@require_level(4)
def api_deploy_github_keys_clear():
    if GH_KEYS_FILE.exists():
        try: GH_KEYS_FILE.unlink()
        except Exception: pass
    return jsonify({"success": True, "message": "Todas as chaves removidas."})


@app.route("/api/deploy/github-branches", methods=["POST"])
@require_auth
@require_level(3)
def api_deploy_github_branches():
    """List branches for a GitHub repo URL so the UI can offer a select."""
    data = request.get_json(force=True, silent=True) or {}
    repo_url = (data.get("repo_url") or "").strip()
    saved_key = (data.get("saved_key") or "").strip()
    token      = _resolve_gh_token(saved_key, (data.get("token") or "").strip()) 
    parsed     = _parse_github_repo(repo_url)
    if not parsed:
        return jsonify({
            "success": False,
            "error": "URL inválida. Use: https://github.com/usuario/repositorio",
        }), 400
    owner, repo, branch_hint = parsed

    repo_resp = _github_api_json(f"/repos/{owner}/{repo}", token)
    if repo_resp.status_code == 404:
        return jsonify({
            "success": False,
            "error": "Repositório não encontrado. Se for privado, informe o token.",
        }), 404
    if repo_resp.status_code == 401:
        return jsonify({"success": False, "error": "Token do GitHub inválido."}), 401
    if repo_resp.status_code == 403:
        return jsonify({
            "success": False,
            "error": "GitHub recusou a consulta (rate limit ou sem permissão). Informe um token.",
        }), 403
    if repo_resp.status_code != 200:
        return jsonify({
            "success": False,
            "error": f"GitHub retornou {repo_resp.status_code} ao consultar o repositório.",
        }), 502

    repo_info = repo_resp.json() if repo_resp.content else {}
    default_branch = (repo_info.get("default_branch") or "main").strip() or "main"

    branches = []
    page = 1
    while page <= 5:
        br_resp = _github_api_json(
            f"/repos/{owner}/{repo}/branches?per_page=100&page={page}", token
        )
        if br_resp.status_code != 200:
            break
        batch = br_resp.json() if br_resp.content else []
        if not isinstance(batch, list) or not batch:
            break
        for item in batch:
            name = (item or {}).get("name")
            if name and name not in branches:
                branches.append(name)
        if len(batch) < 100:
            break
        page += 1

    if not branches:
        branches = [default_branch]

    selected = branch_hint if branch_hint in branches else default_branch
    if selected not in branches:
        branches.insert(0, selected)

    return jsonify({
        "success": True,
        "owner": owner,
        "repo": repo,
        "default_branch": default_branch,
        "selected": selected,
        "branches": branches,
    })


@app.route("/api/deploy/from-github", methods=["POST"])
@require_auth
@require_level(3)
def api_deploy_from_github():
    """Deploy from a public or private (token) GitHub repository URL."""
    from threading import Thread
    import re as _re, uuid as _uuid

    data = request.get_json(force=True, silent=True) or {}
    repo_url   = (data.get("repo_url") or "").strip()
    branch     = (data.get("branch") or "main").strip()
    app_name   = (data.get("name") or "").strip()
    category   = (data.get("category") or "Geral").strip()
    icon       = (data.get("icon") or "🚀").strip()
    description = (data.get("description") or "").strip()
    publish    = bool(data.get("publish_to_portal", True))
    featured   = bool(data.get("featured", False))
    saved_key  = (data.get("saved_key") or "").strip()
    key_name   = (data.get("key_name") or "").strip()
    save_token = bool(data.get("save_token"))
    token      = _resolve_gh_token(saved_key, (data.get("token") or "").strip())
    # Custom environment vars and extra networks (github)
    custom_env_vars = (data.get("custom_env_vars") or "").strip()
    extra_networks = (data.get("extra_networks") or "").strip()
    if save_token and token and not saved_key:
        _keys = _load_gh_keys()
        _keys[key_name or repo] = token
        _save_gh_keys(_keys)

    if not repo_url:
        return jsonify({"success": False, "error": "URL do repositório não informada."}), 400
    if not app_name:
        return jsonify({"success": False, "error": "Nome da aplicação não informado."}), 400

    parsed = _parse_github_repo(repo_url)
    if not parsed:
        return jsonify({"success": False, "error": "URL inválida. Use: https://github.com/usuario/repositorio"}), 400
    owner, repo, _hint = parsed
    repo_url = f"https://github.com/{owner}/{repo}"

    # Sanitize branch
    if not _re.match(r"^[a-zA-Z0-9_./\-]+$", branch):
        return jsonify({"success": False, "error": "Nome de branch inválido."}), 400

    db = get_db()
    engine = get_engine()
    if not db or not engine:
        return jsonify({"success": False, "error": "Módulo de deploy indisponível."}), 503

    job_id = str(_uuid.uuid4())
    db.create_job(job_id, app_name, json.dumps({"source": "github", "repo_url": repo_url, "branch": branch,
                                                 "custom_env_vars": custom_env_vars,
                                                 "extra_networks": extra_networks}))

    # The token is passed to the worker in memory only; it is never embedded
    # in a URL or persisted to the database.
    clone_url = repo_url + ".git"

    t = Thread(
        target=engine.run_github_deploy_job,
        args=(job_id, clone_url, branch, app_name, description, icon,
              category, publish, featured, request.remote_addr, token, custom_env_vars, extra_networks),
        daemon=False,
    )
    t.start()

    audit("deploy_github_start", f"GitHub deploy iniciado: {app_name} ({repo_url}@{branch})")
    return jsonify({"success": True, "job_id": job_id, "message": f"Deploy do repositório {repo_url} iniciado."})


@app.route("/api/deploy/jobs/<job_id>/status")
@require_auth
def api_deploy_job_status(job_id):
    db = get_db()
    if not db: return jsonify({"error": "DB unavailable"}), 503
    job = db.get_job(job_id)
    if not job: return jsonify({"error": "Job não encontrado"}), 404
    return jsonify(job)

@app.route("/api/deploy/jobs/active")
@require_auth
def api_deploy_job_active():
    db = get_db()
    if not db: return jsonify({"job": None})
    return jsonify({"job": db.get_active_job()})

@app.route("/api/deploy/jobs/<job_id>/logs")
@require_auth
def api_deploy_job_logs(job_id):
    db = get_db()
    if not db: return jsonify({"error": "DB unavailable"}), 503
    job = db.get_job(job_id)
    if not job: return jsonify({"error": "Job não encontrado"}), 404
    return jsonify({"job": job, "logs": db.get_logs(job_id)})

@app.route("/api/deploy/jobs/<job_id>/logs/stream")
@require_auth
def api_deploy_logs_stream(job_id):
    db = get_db()
    if not db:
        def gen(): yield 'data: {"error": "DB unavailable"}\n\n'
        return Response(stream_with_context(gen()), mimetype="text/event-stream")

    def generate():
        last_id = 0
        while True:
            logs = db.get_logs(job_id, since_id=last_id)
            for log in logs:
                last_id = log["id"]
                yield f"data: {json.dumps(log)}\n\n"
            job = db.get_job(job_id)
            if job and job.get("status") in ("success", "failed"):
                yield f"event: done\ndata: {json.dumps(job)}\n\n"
                break
            time.sleep(0.5)
    return Response(stream_with_context(generate()), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

@app.route("/api/deploy/apps")
@require_auth
@require_level(3)
def api_deploy_apps():
    db = get_db()
    if not db: return jsonify({"apps": []})
    return jsonify({"apps": db.list_apps()})

@app.route("/api/deploy/apps/<app_id>/versions")
@require_auth
@require_level(3)
def api_deploy_app_versions(app_id):
    db = get_db()
    if not db: return jsonify({"versions": []})
    return jsonify({"versions": db.get_versions(app_id)})

@app.route("/api/deploy/apps/<app_id>/rollback", methods=["POST"])
@require_auth
@require_level(3)
def api_deploy_rollback(app_id):
    data = request.get_json(silent=True) or {}
    version_num = data.get("version")
    if not version_num:
        return jsonify({"success": False, "error": "version é obrigatório"}), 400
    db = get_db()
    engine = get_engine()
    if not db or not engine:
        return jsonify({"success": False, "error": "Serviço indisponível"}), 503
    try:
        engine.rollback(app_id, int(version_num))
        audit("rollback", f"App {app_id} rollback para v{version_num}")
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/deploy/apps/<app_id>/delete", methods=["POST"])
@require_auth
@require_level(3)
def api_deploy_delete(app_id):
    db = get_db()
    engine = get_engine()
    if not db or not engine:
        return jsonify({"success": False, "error": "Serviço indisponível"}), 503
    app_data = db.get_app(app_id)
    if not app_data:
        return jsonify({"success": False, "error": "App não encontrado"}), 404
    try:
        cleanup = engine.destroy_app(app_id)
        # Keep Portal Público in sync when the Deploy Center entry is deleted.
        projects = [p for p in load_projects() if p.get("id") != app_id]
        save_projects(projects)
        audit("delete_deploy_app", f"App removido: {app_data.get('name')} ({app_id})")
        return jsonify({"success": True, "cleanup": cleanup, "projects": projects})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/deploy/apps/<app_id>/restart", methods=["POST"])
@require_auth
@require_level(3)
def api_deploy_restart(app_id):
    db = get_db()
    if not db: return jsonify({"success": False, "error": "DB unavailable"}), 503
    app_data = db.get_app(app_id)
    if not app_data: return jsonify({"success": False, "error": "App não encontrado"}), 404
    try:
        subprocess.run(["docker", "restart", app_data["container_name"]], timeout=30, check=True)
        audit("restart_app", f"App reiniciado: {app_data['name']}")
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route("/api/deploy/apps/<app_id>/stop", methods=["POST"])
@require_auth
@require_level(3)
def api_deploy_stop(app_id):
    db = get_db()
    if not db: return jsonify({"success": False, "error": "DB unavailable"}), 503
    app_data = db.get_app(app_id)
    if not app_data: return jsonify({"success": False, "error": "App não encontrado"}), 404
    try:
        subprocess.run(["docker", "stop", app_data["container_name"]], timeout=30, check=True)
        db.update_app(app_id, status="stopped")
        audit("stop_app", f"App parado: {app_data['name']}")
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route("/api/deploy/apps/<app_id>/start", methods=["POST"])
@require_auth
@require_level(3)
def api_deploy_start(app_id):
    db = get_db()
    if not db: return jsonify({"success": False, "error": "DB unavailable"}), 503
    app_data = db.get_app(app_id)
    if not app_data: return jsonify({"success": False, "error": "App não encontrado"}), 404
    try:
        subprocess.run(["docker", "start", app_data["container_name"]], timeout=30, check=True)
        db.update_app(app_id, status="running")
        audit("start_app", f"App iniciado: {app_data['name']}")
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

# ════════════════════════════════════════════════════════════════════════════
# AUDIT, SECURITY, BACKUP
# ════════════════════════════════════════════════════════════════════════════

@app.route("/api/audit")
@require_auth
def api_audit():
    db = get_db()
    if not db: return jsonify({"logs": []})
    limit  = int(request.args.get("limit", 100))
    offset = int(request.args.get("offset", 0))
    logs = db.get_audit(min(limit + offset, 2000), 0)
    # Filtros no BACKEND: usuário e tipo de ação.
    fu = (request.args.get("user") or "").strip().lower()
    fa = (request.args.get("action") or "").strip().lower()
    def _match(l):
        if fu and fu not in str(l.get("user", "")).lower(): return False
        if fa and fa not in str(l.get("action", "")).lower(): return False
        return True
    logs = [l for l in logs if _match(l)]
    return jsonify({"logs": logs[offset:offset + limit]})

@app.route("/api/admin/terminal/audit", methods=["GET"])
@require_auth
@require_level(3)
def api_terminal_audit():
    """Auditoria do Web Terminal (JSONL em /terminal-data, só leitura)."""
    try:
        limit = max(10, min(int(request.args.get("limit", "200")), 1000))
    except (ValueError, TypeError):
        limit = 200
    lines = []
    try:
        with open("/terminal-data/audit.jsonl", "r", encoding="utf-8") as f:
            lines = f.readlines()[-limit:]
    except FileNotFoundError:
        pass
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
    logs = []
    for l in lines:
        try:
            logs.append(json.loads(l))
        except Exception:
            continue
    logs.reverse()  # mais recente primeiro
    return jsonify({"success": True, "logs": logs})

@app.route("/api/admin/terminal/sessions", methods=["GET"])
@require_auth
@require_level(3)
def api_terminal_sessions():
    """Sessões (screen) do Web Terminal de TODOS os usuários — via admin API
    do terminal (X-Admin-Secret). Alimenta o card Terminais > Usuários."""
    ok, body, status = _terminal_request("GET", "/api/admin/sessions")
    if not ok:
        return jsonify({"success": False,
                        "error": body.get("error", "Falha no terminal.")}), status
    return jsonify({"success": True,
                    "sessions": body.get("sessions", []),
                    "terminal_url": TERMINAL_URL})

@app.route("/api/admin/terminal/sessions/<path:name>/kill", methods=["POST"])
@require_auth
@require_level(3)
def api_terminal_session_kill(name):
    """Encerra uma sessão do Web Terminal (ROOT/SYSADMIN)."""
    safe = _urlquote(name, safe="")
    ok, body, status = _terminal_request("DELETE", f"/api/admin/sessions/{safe}")
    if not ok:
        return jsonify({"success": False,
                        "error": body.get("error", "Falha ao encerrar sessão.")}), status
    audit("terminal_session_kill", f"encerrou sessão {name}")
    return jsonify({"success": True, "killed": body.get("killed", name)})

def _hub_user_public(u):
    res = {k: u.get(k) for k in ("id", "username", "name", "email", "role",
                                  "active", "created_at", "last_login", "last_login_ip")}
    res["has_password"] = bool(u.get("password_hash"))
    return res

@app.route("/api/admin/hubusers", methods=["GET"])
@require_auth
@require_level(3)
def api_hub_users_list():
    data = load_hub_users()
    users = [_hub_user_public(u) for u in data.get("users", [])]
    with _sessions_lock:
        active = {}
        for tok, s in _sessions.items():
            if time.time() < s.get("expires_at", 0):
                active[s["username"]] = active.get(s["username"], 0) + 1
    for u in users:
        u["active_sessions"] = active.get(u["username"], 0)
    return jsonify({"success": True, "users": users})

@app.route("/api/admin/hubusers", methods=["POST"])
@require_auth
@require_level(3)
def api_hub_users_create():
    data = load_hub_users()
    body = request.get_json(silent=True) or {}
    name = str(body.get("name") or "").strip()
    username = str(body.get("username") or "").strip().lower()
    password = str(body.get("password") or "")
    email = str(body.get("email") or "").strip()
    role = str(body.get("role") or "user1").strip().lower()
    active = bool(body.get("active", True))

    if not name or not username or not password:
        return jsonify({"success": False, "error": "Nome, usuário e senha são obrigatórios."}), 400
    if not re.match(r"^[a-z0-9_\-]{2,32}$", username):
        return jsonify({"success": False, "error": "Usuário: 2-32 caracteres (a-z, 0-9, _ -)."}), 400
    if len(password) < 6:
        return jsonify({"success": False, "error": "Senha precisa de ao menos 6 caracteres."}), 400
    if role not in ("sysadmin", "developer", "user1"):
        return jsonify({"success": False, "error": "Nível inválido. Contas ROOT não são criadas via API."}), 400
    _, exists = find_hub_user(username, data)
    if exists:
        return jsonify({"success": False, "error": "Usuário já existe."}), 409

    me_level = current_level()
    target_level = _ROLE_LEVEL[role]
    # SYSADMIN só cria developer/user1. ROOT cria sysadmin/developer/user1.
    if me_level < 4 and target_level >= 3:
        return jsonify({"success": False, "error": "Somente ROOT cria contas SYSADMIN."}), 403

    user = {
        "id": f"u_{secrets.token_hex(4)}", "username": username, "name": name,
        "email": email, "role": role, "active": active,
        "password_hash": hash_password(password),
        "created_at": time.time(), "last_login": None,
    }
    data["users"].append(user)
    save_hub_users(data)
    audit("user_create", f"criou usuário {username} ({role})")
    synced = _terminal_sync_user(username, password=password, hub_role=role, active=active)
    return jsonify({"success": True, "user": _hub_user_public(user),
                    "terminal_synced": bool(synced)})

def _protect_root(user, action):
    """REGRA CRÍTICA: a conta ROOT não pode ser excluída, desativada, rebaixada
    nem ter credenciais/permissões alteradas por OUTRO usuário — nem por outro
    ROOT (evita lockout acidental). Retorna (erro_msg, status) ou (None, None)."""
    if user.get("role") != "root":
        return None, None
    me = get_session(get_session_token()) or {}
    if me.get("role") == "root":
        return ("A conta ROOT é protegida e não pode ser modificada, desativada, "
                "rebaixada ou excluída por ninguém — nem por outro ROOT."), 403
    return (f"Operação '{action}' bloqueada: a conta ROOT é protegida e não pode "
            "ser alterada por SYSADMIN."), 403

def _revoke_user_sessions(username, reason=""):
    """Logout forçado: remove as sessões do Hub de um usuário."""
    n = 0
    with _sessions_lock:
        for tok in [k for k, v in _sessions.items() if v.get("username") == username]:
            del _sessions[tok]; n += 1
        if n:
            _save_sessions()
    return n

@app.route("/api/admin/hubusers/<uid>", methods=["PATCH"])
@require_auth
@require_level(3)
def api_hub_users_update(uid):
    data, user = find_hub_user(uid)
    if not user:
        return jsonify({"success": False, "error": "Usuário não encontrado."}), 404
    body = request.get_json(silent=True) or {}
    changed = []

    if "name" in body:
        name = str(body["name"]).strip()
        if not name:
            return jsonify({"success": False, "error": "Nome não pode ficar vazio."}), 400
        if name != user.get("name"):
            user["name"] = name; changed.append("name")
    if "email" in body:
        email = str(body["email"]).strip()
        if email != user.get("email"):
            user["email"] = email; changed.append("email")

    wants_role = "role" in body and str(body["role"]).lower() != user.get("role")
    wants_active = "active" in body and bool(body["active"]) != bool(user.get("active", True))
    synced = True
    if wants_role or wants_active:
        err, status = _protect_root(user, "role" if wants_role else "active")
        if err:
            return jsonify({"success": False, "error": err}), status
        if current_level() < 4:
            return jsonify({"success": False,
                            "error": "Somente ROOT altera nível de acesso ou estado ativo."}), 403
        if wants_role:
            role = str(body["role"]).lower()
            if role not in ("sysadmin", "developer", "user1"):
                return jsonify({"success": False, "error": "Nível inválido."}), 400
            user["role"] = role; changed.append(f"role={role}")
            synced = _terminal_sync_user(user["username"], hub_role=role) and synced
        if wants_active:
            active = bool(body["active"])
            user["active"] = active; changed.append(f"active={active}")
            synced = _terminal_sync_user(user["username"], active=active) and synced
            if not active:
                _revoke_user_sessions(user["username"], "usuário desativado")

    if not changed:
        return jsonify({"success": False, "error": "Nada para alterar."}), 400
    save_hub_users(data)
    audit("user_update", f"alterou {user['username']}: {', '.join(changed)}")
    return jsonify({"success": True, "user": _hub_user_public(user),
                    "terminal_synced": bool(synced)})

@app.route("/api/admin/hubusers/<uid>/password", methods=["POST"])
@require_auth
@require_level(3)
def api_hub_users_password(uid):
    data, user = find_hub_user(uid)
    if not user:
        return jsonify({"success": False, "error": "Usuário não encontrado."}), 404
    body = request.get_json(silent=True) or {}
    new_pw = str(body.get("password") or "")
    if len(new_pw) < 6:
        return jsonify({"success": False, "error": "Senha precisa de ao menos 6 caracteres."}), 400
    err, status = _protect_root(user, "password")
    if err:
        return jsonify({"success": False, "error": err}), status
    me = get_session(get_session_token()) or {}
    if me.get("username") != user["username"] and current_level() < _ROLE_LEVEL.get(user.get("role"), 0):
        return jsonify({"success": False, "error": "Você não pode redefinir a senha de um nível superior."}), 403
    user["password_hash"] = hash_password(new_pw)
    save_hub_users(data)
    audit("user_password_reset", f"redefiniu a senha de {user['username']}")
    synced = _terminal_sync_user(user["username"], password=new_pw)
    if me.get("username") != user["username"]:
        _revoke_user_sessions(user["username"], "senha redefinida por admin")
    return jsonify({"success": True, "terminal_synced": bool(synced)})

@app.route("/api/admin/hubusers/<uid>", methods=["DELETE"])
@require_auth
@require_level(3)
def api_hub_users_delete(uid):
    data, user = find_hub_user(uid)
    if not user:
        return jsonify({"success": False, "error": "Usuário não encontrado."}), 404
    err, status = _protect_root(user, "delete")
    if err:
        return jsonify({"success": False, "error": err}), status
    if current_level() < 4:
        return jsonify({"success": False, "error": "Somente ROOT exclui usuários."}), 403
    username = user["username"]
    data["users"] = [u for u in data["users"] if u.get("id") != user.get("id")]
    save_hub_users(data)
    audit("user_delete", f"excluiu usuário {username} ({user.get('role')})")
    synced = _terminal_sync_user(username, delete=True)
    _revoke_user_sessions(username, "usuário excluído")
    return jsonify({"success": True, "terminal_synced": bool(synced)})

@app.route("/api/admin/hubusers/<uid>/sessions", methods=["GET", "DELETE"])
@require_auth
@require_level(3)
def api_hub_users_sessions(uid):
    """Sessões ativas do Hub (GET, token mascarado) / encerrar todas (DELETE)."""
    data, user = find_hub_user(uid)
    if not user:
        return jsonify({"success": False, "error": "Usuário não encontrado."}), 404
    if request.method == "DELETE":
        n = _revoke_user_sessions(user["username"], "encerradas por administrador")
        audit("user_sessions_kill", f"encerrou {n} sessão(ões) de {user['username']}")
        return jsonify({"success": True, "revoked": n})
    out = []
    with _sessions_lock:
        for tok, s in _sessions.items():
            if s.get("username") != user["username"] or time.time() >= s.get("expires_at", 0):
                continue
            out.append({"token": tok[:8] + "…", "created_at": s.get("created_at"),
                        "expires_at": s.get("expires_at"), "ip": s.get("ip"),
                        "role": s.get("role")})
    return jsonify({"success": True, "username": user["username"], "sessions": out})

@app.route("/api/whoami")
@require_auth
def api_whoami():
    """Identidade + permissões do usuário logado. O frontend usa isto para
    esconder/mostrar itens — mas a decisão real é SEMPRE do backend."""
    s = get_session(get_session_token()) or {}
    role = s.get("role") or "root"
    lvl = _ROLE_LEVEL.get(role, 0)
    _, user = find_hub_user(s.get("username", ""))
    return jsonify({
        "success": True, "username": s.get("username"), "role": role, "level": lvl,
        "name": (user or {}).get("name") or ("Administrador ROOT" if role == "root" else s.get("username")),
        "email": (user or {}).get("email", ""),
        "perms": {
            "users_manage": lvl >= 3, "users_delete": lvl >= 4,
            "files_manage": lvl >= 3, "deploy": lvl >= 3, "docker": lvl >= 3,
            "backups": lvl >= 4, "security": lvl >= 3, "audit_view": lvl >= 3,
            "terminal_shell": lvl >= 2, "terminal_ai": True, "projects_view": True,
        },
    })

@app.route("/api/security/status")
@require_auth
@require_level(3)
def api_security_status():
    try:
        from security_check import check_security
        results = check_security()
    except Exception as e:
        results = [{"id": "error", "name": "Erro", "status": "error", "description": str(e), "action": None}]
    return jsonify({"checks": results, "checked_at": time.time()})

@app.route("/api/backup/live-logs")
@require_auth
@require_level(3)
def api_backup_live_logs():
    try:
        from backup_ctl import read_status
        data = read_status(APP_DIR)
        log_name = data.get("log")
        if log_name:
            log_name = os.path.basename(log_name)

        log_dirs = [
            APP_DIR / "backup-logs",
            Path("/app/backup-logs"),
            Path("/home/decsv/.local/share/homeserver-backup/logs")
        ]
        
        target_file = None
        # Tenta achar o arquivo específico informado no status
        if log_name:
            for d in log_dirs:
                candidate = d / log_name
                if candidate.exists():
                    target_file = candidate
                    break

        # Se não achou, pega o log mais recente de qualquer um dos diretórios existentes
        if not target_file:
            for d in log_dirs:
                if d.exists():
                    logs = sorted(d.glob("*.log"), key=os.path.getmtime, reverse=True)
                    if logs:
                        target_file = logs[0]
                        break

        if target_file and target_file.exists():
            with open(target_file, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()[-150:]
            return jsonify({"success": True, "lines": lines, "path": target_file.name})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
    return jsonify({"success": True, "lines": ["[HomeHub] Nenhum log encontrado até o momento."]})

@app.route("/api/backup/status")
@require_auth
@require_level(3)
def api_backup_status():
    try:
        from backup_ctl import read_status
        data = read_status(APP_DIR)
        flag = APP_DIR / "terabox-connected.flag"
        if flag.exists():
            data["connected"] = True
        return jsonify(data)
    except Exception as e:
        return jsonify({"connected": False, "error": str(e)}), 500

@app.route("/api/backup/trigger", methods=["POST"])
@require_auth
@require_level(4)
def api_backup_trigger():
    data = request.get_json(silent=True) or {}
    job_id = (data.get("job_id") or "servidor").strip()
    try:
        from backup_ctl import request_run
        request_run(APP_DIR, job_id)
        audit("backup_trigger", f"Backup manual solicitado ({job_id})")
        return jsonify({"success": True, "message": "Backup enfileirado. Começa em até 1 minuto."})
    except ValueError as e:
        return jsonify({"success": False, "error": str(e)}), 400
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 503

@app.route("/api/backup/terabox-cookie", methods=["POST"])
@require_auth
@require_level(4)
def api_backup_terabox_cookie():
    data = request.get_json(silent=True) or {}
    cookie = data.get("cookie") or data.get("ndus") or ""
    try:
        from backup_ctl import queue_cookie
        queue_cookie(APP_DIR, cookie)
        audit("backup_terabox_cookie", "Cookie Terabox atualizado pelo painel")
        return jsonify({"success": True, "message": "Cookie salvo. A conexão é testada em até 1 minuto."})
    except ValueError as e:
        return jsonify({"success": False, "error": str(e)}), 400

@app.route("/api/backup/config", methods=["GET", "POST"])
@require_auth
@require_level(4)
def api_backup_config():
    from backup_ctl import load_config, upsert_jobs, TZ_NAME
    if request.method == "GET":
        return jsonify(load_config(APP_DIR))
    data = request.get_json(silent=True) or {}
    try:
        cfg = upsert_jobs(APP_DIR, data)
        audit("update_backup_config", "Agendamentos de backup atualizados")
        return jsonify({"success": True, "timezone": TZ_NAME, "jobs": cfg["jobs"]})
    except ValueError as e:
        return jsonify({"success": False, "error": str(e)}), 400

@app.route("/api/backup/onedrive/connect")
@require_auth
def api_onedrive_connect():
    return jsonify({"success": False, "error": "OneDrive foi substituído pelo Terabox."}), 410

@app.route("/api/backup/onedrive/callback")
def api_onedrive_callback():
    return "OneDrive desativado. Use o Backup Terabox no painel.", 410



@app.route("/api/backup/snapshots")
@require_auth
@require_level(4)
def api_backup_snapshots():
    from restore_ctl import (
        ensure_refresh_requested,
        read_restore_progress,
        read_snapshots,
        snapshots_refreshed_at,
    )
    import time as _time
    snaps = read_snapshots(APP_DIR)
    stale = ensure_refresh_requested(APP_DIR)
    refreshed = snapshots_refreshed_at(APP_DIR)
    return jsonify({
        "success": True,
        "snapshots": snaps,
        "refreshed_at": refreshed,
        "stale": stale,
        "restore": read_restore_progress(APP_DIR),
        "server_now": _time.time(),
    })


@app.route("/api/backup/restore", methods=["POST"])
@require_auth
@require_level(4)
def api_backup_restore():
    from restore_ctl import request_restore
    data = request.get_json(silent=True) or {}
    confirm = str(data.get("confirm") or "").strip().lower()
    if confirm not in ("restaurar", "restore"):
        return jsonify({"success": False,
                        "error": 'Confirmação obrigatória: envie "confirm": "restaurar"'}), 400
    try:
        payload = request_restore(APP_DIR, data.get("snapshot_id") or "",
                                  include=data.get("include") or [],
                                  dry_run=bool(data.get("dry_run")))
    except ValueError as e:
        return jsonify({"success": False, "error": str(e)}), 400
    audit("backup_restore_request",
          f"Snapshot {payload['snapshot_id'][:8]} include={payload['include'] or 'TUDO'} dry_run={payload['dry_run']}")
    msg = ("Simulação da restauração solicitada. Acompanhe o progresso aqui na página."
           if payload["dry_run"] else
           "Restauração solicitada! O servidor vai aplicar o snapshot em instantes. Acompanhe aqui.")
    return jsonify({"success": True, "message": msg, "request": payload})


# ════════════════════════════════════════════════════════════════════════════
# STARTUP
# ════════════════════════════════════════════════════════════════════════════
def _bg_init():
    time.sleep(2)
    # ── Ensure SSH user exists for cluster commands ─────────────────────────────
    try:
        import subprocess as _sp
        _r = _sp.run(["id", "-u", "decsv"], capture_output=True)
        if _r.returncode != 0:
            _sp.run(["useradd", "-u", "1000", "-d", "/app", "-s", "/bin/bash", "decsv"],
                    capture_output=True)
            print("[HomeHub] Created 'decsv' user for SSH operations.", flush=True)
    except Exception as _e:
        print(f"[HomeHub] Warning: could not create decsv user: {_e}", flush=True)
    # ─────────────────────────────────────────────────────────────────────────

    db = get_db()
    if db: print("[HomeHub] Deploy DB ready.", flush=True)
    get_engine()
    print("[HomeHub] Deploy Engine ready.", flush=True)

# [MOVED TO EOF: app.run]


# ══════════════════════════════════════════════════════════════════════════════
# GESTÃO DE ADMINISTRADORES & CONVITES POR E-MAIL (Brevo SMTP)
# ══════════════════════════════════════════════════════════════════════════════
RESETS_F = APP_DIR / "password_resets.json"

def load_password_resets():
    if not RESETS_F.exists():
        return {}
    try:
        data = json.loads(RESETS_F.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}

def save_password_resets(data):
    try:
        RESETS_F.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        RESETS_F.chmod(0o600)
    except Exception as e:
        logger.error(f"Erro ao salvar password_resets: {e}")

def create_password_token(user_id, email, token_type="invite", hours_valid=48):
    data = load_password_resets()
    now = time.time()
    for tok, info in list(data.items()):
        if info.get("user_id") == user_id and not info.get("used"):
            info["used"] = True
            info["invalidated_at"] = now
    token = secrets.token_urlsafe(32)
    data[token] = {
        "user_id": user_id,
        "email": email,
        "created_at": now,
        "expires_at": now + (hours_valid * 3600),
        "used": False,
        "type": token_type
    }
    save_password_resets(data)
    return token

def send_password_setup_email(to_email, name, token, is_invite=True):
    import smtplib
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText
    
    smtp_host = os.environ.get("SMTP_HOST", "smtp-relay.brevo.com")
    smtp_port = int(os.environ.get("SMTP_PORT", 587))
    smtp_user = os.environ.get("SMTP_USER", "a89907001@smtp-brevo.com")
    smtp_pass = os.environ.get("SMTP_PASS", "")
    smtp_from = os.environ.get("SMTP_FROM", "nao-responda@decamservice.com")
    base_url = "https://decamservice.com"
    
    reset_url = f"{base_url}/admin.html?action=set-password&token={token}"
    subject = "Defina sua senha de Administrador — DECAM HomeHub" if is_invite else "Redefinição de Senha — DECAM HomeHub"
    
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = f"DECAM HomeHub <{smtp_from}>"
    msg["To"] = to_email
    
    html_content = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{subject}</title>
  <style>
    body {{ margin: 0; padding: 30px 15px; background-color: #0b1120; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; -webkit-font-smoothing: antialiased; }}
    .wrapper {{ max-width: 580px; margin: 0 auto; background: #131e30; border-radius: 16px; border: 1px solid rgba(255,255,255,0.1); padding: 36px 32px; box-shadow: 0 20px 40px rgba(0,0,0,0.5); }}
    .brand {{ display: flex; align-items: center; margin-bottom: 24px; }}
    .brand-title {{ font-size: 22px; font-weight: 700; color: #38bdf8; letter-spacing: -0.5px; margin: 0; }}
    .badge {{ display: inline-block; background: rgba(56,189,248,0.15); color: #38bdf8; border: 1px solid rgba(56,189,248,0.3); font-size: 11px; font-weight: 700; text-transform: uppercase; padding: 4px 10px; border-radius: 9999px; letter-spacing: 1px; margin-left: 12px; }}
    h1 {{ color: #ffffff; font-size: 20px; font-weight: 600; margin: 0 0 16px 0; }}
    p {{ color: #94a3b8; font-size: 14px; line-height: 1.6; margin: 0 0 18px 0; }}
    .btn-wrap {{ margin: 28px 0; text-align: center; }}
    .btn {{ display: inline-block; background: #0284c7; color: #ffffff !important; text-decoration: none; padding: 14px 32px; border-radius: 8px; font-weight: 600; font-size: 14px; box-shadow: 0 4px 12px rgba(2,132,199,0.3); }}
    .link-box {{ background: rgba(0,0,0,0.25); border: 1px solid rgba(255,255,255,0.06); border-radius: 8px; padding: 12px; word-break: break-all; font-family: monospace; font-size: 12px; color: #38bdf8; margin: 16px 0 24px 0; }}
    .footer {{ border-top: 1px solid rgba(255,255,255,0.08); padding-top: 20px; margin-top: 28px; font-size: 12px; color: #64748b; line-height: 1.5; }}
  </style>
</head>
<body>
  <div class="wrapper">
    <div class="brand">
      <div class="brand-title">⚡ DECAM HomeHub</div>
      <span class="badge">Acesso Seguro</span>
    </div>
    <h1>Olá, {name}!</h1>
    <p>Você foi convidado com privilégios de <strong>Administrador</strong> no painel de controle do servidor <strong>DECAM HomeHub</strong> (Expresso Nepomuceno).</p>
    <p>Para ativar sua conta e definir sua senha pessoal de acesso, clique no botão abaixo:</p>
    <div class="btn-wrap">
      <a href="{reset_url}" target="_blank" class="btn">Definir Minha Senha</a>
    </div>
    <p>Caso o botão não funcione, você também pode copiar e colar o link seguro diretamente no seu navegador:</p>
    <div class="link-box">{reset_url}</div>
    <div class="footer">
      <p>⚠️ Este link é exclusivo e expira em <strong>48 horas</strong>.<br>Se você não solicitou este acesso, desconsidere esta mensagem.</p>
      <p style="margin-top: 12px;">© 2026 DECAM Service & Expresso Nepomuceno. Todos os direitos reservados.</p>
    </div>
  </div>
</body>
</html>"""
    
    text_content = f"Olá, {name}!\n\nVocê foi convidado com privilégios de Administrador no DECAM HomeHub.\nPara ativar sua conta e definir sua senha, acesse o link abaixo:\n\n{reset_url}\n\nEste link expira em 48 horas.\n"
    msg.attach(MIMEText(text_content, "plain", "utf-8"))
    msg.attach(MIMEText(html_content, "html", "utf-8"))
    
    server = smtplib.SMTP(smtp_host, smtp_port, timeout=12)
    server.starttls()
    server.login(smtp_user, smtp_pass)
    server.sendmail(smtp_from, [to_email], msg.as_string())
    server.quit()
    return True

@app.route("/api/auth/set-password", methods=["POST"])
@app.route("/api/admin/set-password", methods=["POST"])
def api_auth_set_password():
    body = request.get_json(silent=True) or {}
    token = str(body.get("token") or "").strip()
    new_password = str(body.get("new_password") or "")
    
    if not token or not new_password:
        return jsonify({"success": False, "error": "Token e nova senha são obrigatórios."}), 400
    if len(new_password) < 6:
        return jsonify({"success": False, "error": "A senha deve ter no mínimo 6 caracteres."}), 400
        
    resets = load_password_resets()
    info = resets.get(token)
    if not info:
        return jsonify({"success": False, "error": "Token inválido ou expirado."}), 404
    if info.get("used"):
        return jsonify({"success": False, "error": "Este link já foi utilizado. Solicite um novo convite ao administrador."}), 410
    if time.time() > info.get("expires_at", 0):
        return jsonify({"success": False, "error": "Este link expirou (validade de 48h). Solicite um novo convite."}), 410
        
    user_id = info.get("user_id")
    data_users = load_hub_users()
    user = next((u for u in data_users.get("users", []) if u.get("id") == user_id), None)
    if not user:
        return jsonify({"success": False, "error": "Usuário não encontrado."}), 404
        
    user["password_hash"] = hash_password(new_password)
    user["active"] = True
    user["password_set_at"] = time.time()
    save_hub_users(data_users)
    
    info["used"] = True
    info["used_at"] = time.time()
    save_password_resets(resets)
    
    audit("user_password_set", f"Usuário {user.get('username')} ({user.get('email')}) definiu senha via token de e-mail")
    return jsonify({"success": True, "message": "Senha definida com sucesso! Agora você pode acessar o HomeHub."})

@app.route("/api/admin/users/invite", methods=["POST"])
@require_auth
@require_level(3)
def api_admin_users_invite():
    body = request.get_json(silent=True) or {}
    name = str(body.get("name") or "").strip()
    email = str(body.get("email") or "").strip().lower()
    role = str(body.get("role") or "sysadmin").strip().lower()
    username = str(body.get("username") or "").strip().lower()
    
    if not name or not email:
        return jsonify({"success": False, "error": "Nome e e-mail corporativo são obrigatórios."}), 400
    if "@" not in email:
        return jsonify({"success": False, "error": "E-mail inválido."}), 400
        
    if not username:
        username = email.split("@")[0].replace(".", "-").replace("_", "-")
        username = re.sub(r"[^a-z0-9_\-]", "", username)[:24]
        
    if role not in ("root", "sysadmin", "developer", "user1"):
        return jsonify({"success": False, "error": "Nível de acesso inválido."}), 400
        
    me_level = current_level()
    target_level = _ROLE_LEVEL.get(role, 1)
    if me_level < 4 and target_level >= 3:
        return jsonify({"success": False, "error": "Somente Super Administrador (ROOT) pode convidar administradores."}), 403
        
    data = load_hub_users()
    existing = next((u for u in data.get("users", []) if u.get("email", "").lower() == email or u.get("username") == username), None)
    
    if existing:
        user = existing
        user["name"] = name
        user["role"] = role
        user["email"] = email
    else:
        user = {
            "id": f"u_{secrets.token_hex(4)}",
            "username": username,
            "name": name,
            "email": email,
            "role": role,
            "active": True,
            "password_hash": "",
            "created_at": time.time(),
            "last_login": None
        }
        data["users"].append(user)
        
    save_hub_users(data)
    
    token = create_password_token(user["id"], email, token_type="invite", hours_valid=48)
    try:
        send_password_setup_email(email, name, token, is_invite=True)
        email_sent = True
        err_msg = ""
    except Exception as e:
        logger.error(f"Falha ao enviar e-mail de convite: {e}")
        email_sent = False
        err_msg = str(e)
        
    audit("user_invite", f"Convidou administrador {name} ({email}, {role}) - email_sent={email_sent}")
    return jsonify({
        "success": True,
        "user": _hub_user_public(user),
        "email_sent": email_sent,
        "error": err_msg,
        "message": f"Convite criado com sucesso e e-mail enviado para {email}!" if email_sent else f"Usuário criado, mas houve erro ao enviar e-mail: {err_msg}"
    })

@app.route("/api/admin/users/<uid>/resend-invite", methods=["POST"])
@require_auth
@require_level(3)
def api_admin_users_resend_invite(uid):
    data, user = find_hub_user(uid)
    if not user:
        return jsonify({"success": False, "error": "Usuário não encontrado."}), 404
        
    email = user.get("email")
    if not email or "@" not in email:
        return jsonify({"success": False, "error": "Este usuário não possui e-mail cadastrado."}), 400
        
    token = create_password_token(user["id"], email, token_type="invite", hours_valid=48)
    try:
        send_password_setup_email(email, user.get("name") or user.get("username"), token, is_invite=True)
        audit("user_resend_invite", f"Reenviou convite para {email}")
        return jsonify({"success": True, "message": f"Link de definição de senha reenviado com sucesso para {email}!"})
    except Exception as e:
        return jsonify({"success": False, "error": f"Falha no envio do e-mail: {e}"}), 500


# ─────────────────────────────────────────────────────────────────────────────
# CLUSTER DE ALTA DISPONIBILIDADE — Dell Vostro (Primary) + AWS EC2 (Standby)
# ─────────────────────────────────────────────────────────────────────────────
import shlex

AWS_HOST = "18.231.53.141"
AWS_USER = "ubuntu"
AWS_KEY  = "/app/keys/decam-aws.pem"
AWS_STATS_CMD = "python3 /home/ubuntu/decam-standby/get_stats.py"
SYNC_LOG  = "/app/sync_db_aws.log"  # copy updated by cron every minute
SYNC_SCRIPT_FWD = "/home/decsv/sync_db_to_aws.sh"
SYNC_SCRIPT_REV = "/home/decsv/sync_from_aws_to_vostro.sh"
AWS_ACTIVATE   = "/home/ubuntu/decam-standby/activate-failover.sh"
AWS_STANDBY    = "/home/ubuntu/decam-standby/standby-mode.sh"
CF_CONTAINER   = "homeserver-cloudflare"


def _ssh_aws(cmd: str, timeout: int = 8) -> str:
    """Run a command on AWS via SSH; return stdout. Raises on failure."""
    result = subprocess.run(
        ["ssh", "-i", AWS_KEY,
         "-o", "StrictHostKeyChecking=no",
         "-o", "ConnectTimeout=5",
         f"{AWS_USER}@{AWS_HOST}", cmd],
        capture_output=True, text=True, timeout=timeout
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or f"ssh exit {result.returncode}")
    return result.stdout.strip()


def _vostro_stats() -> dict:
    """Gather Vostro (local host) stats via docker exec + docker ps."""
    import psutil
    mem  = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    cpu  = psutil.cpu_percent(interval=0.3)
    uptime_s = time.time() - psutil.boot_time()
    h, r = divmod(int(uptime_s), 3600)
    m    = r // 60
    uptime_str = f"{h}h {m}m"

    # Check if Cloudflare tunnel container is running
    cf_active = False
    try:
        ps = subprocess.run(
            ["docker", "ps", "--filter", f"name={CF_CONTAINER}", "--format", "{{.Names}}"],
            capture_output=True, text=True, timeout=5
        )
        cf_active = CF_CONTAINER in ps.stdout
    except Exception:
        pass

    # Read last sync timestamp from log
    last_sync = None
    try:
        r = subprocess.run(
            ["bash", "-c", f"grep 'concluida com sucesso' {SYNC_LOG} 2>/dev/null | tail -n 1"],
            capture_output=True, text=True, timeout=5
        )
        line = r.stdout.strip()
        if line:
            # e.g. [2026-09-22 10:10:03] [SYNC] Sincronizacao concluida com sucesso em 2s!
            import re as _re
            m = _re.search(r'\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]', line)
            if m:
                last_sync = m.group(1)
    except Exception:
        pass

    return {
        "status": "online",
        "cpu_percent": round(cpu, 1),
        "ram_total_gb": round(mem.total / 1e9, 1),
        "ram_used_gb":  round(mem.used / 1e9, 1),
        "ram_percent":  round(mem.percent, 1),
        "disk_total_gb": round(disk.total / 1e9, 1),
        "disk_used_gb":  round(disk.used / 1e9, 1),
        "disk_percent":  round(disk.percent, 1),
        "uptime": uptime_str,
        "is_traffic_active": cf_active,
        "last_db_sync": last_sync,
    }


@app.route("/api/cluster/status", methods=["GET"])
@require_auth
def api_cluster_status():
    """Return real-time stats for both Vostro (primary) and AWS (standby)."""
    vostro = {}
    aws    = {}
    errors = {}

    try:
        vostro = _vostro_stats()
    except Exception as e:
        app.logger.error(f"[cluster] vostro stats error: {e}")
        vostro = {"status": "error", "error": str(e)}
        errors["vostro"] = str(e)

    try:
        raw = _ssh_aws(AWS_STATS_CMD, timeout=10)
        aws = json.loads(raw)
        aws["status"] = "online"
    except Exception as e:
        app.logger.error(f"[cluster] aws stats error: {e}")
        aws = {"status": "offline", "error": str(e)}
        errors["aws"] = str(e)

    return jsonify({
        "vostro": vostro,
        "aws": aws,
        "errors": errors,
        "timestamp": time.time(),
    })


def _stream_switch(target: str):
    """Connects to the host cluster agent via Unix socket and streams SSE events."""
    import socket
    sock_path = "/app/cluster.sock"
    if not os.path.exists(sock_path):
        err = json.dumps({
            "step": 0,
            "label": "Verificando saúde dos servidores",
            "status": "error",
            "detail": "Agente de cluster do host indisponível (/app/cluster.sock)"
        })
        yield f"data: {err}\n\n"
        return

    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(240)
        s.connect(sock_path)
        req = json.dumps({"action": "switch", "target": target})
        s.sendall(req.encode("utf-8"))

        buffer = ""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            buffer += chunk.decode("utf-8")
            while "\n" in buffer:
                line, buffer = buffer.split("\n", 1)
                line = line.strip()
                if not line:
                    continue
                yield f"data: {line}\n\n"
                try:
                    evt = json.loads(line)
                    if evt.get("step") == "complete" or evt.get("status") == "error":
                        s.close()
                        return
                except Exception:
                    pass
        s.close()
    except Exception as e:
        err = json.dumps({
            "step": 0,
            "label": "Erro de comunicação com o host",
            "status": "error",
            "detail": str(e)
        })
        yield f"data: {err}\n\n"


@app.route("/api/cluster/switch", methods=["POST"])
@require_auth
@require_level(4)
def api_cluster_switch():
    """Stream SSE progress events while switching the active server."""
    data = request.get_json(silent=True) or {}
    target = data.get("target", "").lower()
    if target not in ("aws", "vostro"):
        return jsonify({"success": False, "error": "target deve ser 'aws' ou 'vostro'"}), 400
    audit("cluster_switch", f"Iniciando troca de servidor para: {target}")
    return Response(
        stream_with_context(_stream_switch(target)),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        }
    )

if __name__ == "__main__":
    threading.Thread(target=_bg_init, daemon=True).start()
    print("[HomeHub] Starting Flask app on port 3000...", flush=True)
    app.run(host="0.0.0.0", port=3000, threaded=True, debug=False)
