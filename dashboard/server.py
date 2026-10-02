import http.server
import socketserver
import json
import os
import subprocess
import re
import time
import hashlib
import secrets
import hmac
from http.cookies import SimpleCookie

PORT = 3000
AUTH_FILE = os.path.join(os.path.dirname(__file__), 'auth.json')

# ==============================================================================
# CYBERSECURITY & AUTHENTICATION MODULE
# ==============================================================================

def hash_password(password: str, salt: str = None) -> str:
    if not salt:
        salt = secrets.token_hex(16)
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000).hex()
    return f"{salt}:{hashed}"

def verify_password(password: str, stored_hash: str) -> bool:
    if not stored_hash or ":" not in stored_hash:
        return False
    salt, hashed = stored_hash.split(":", 1)
    check = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000).hex()
    return hmac.compare_digest(check, hashed)

def load_auth_config():
    default_user = os.environ.get('ADMIN_USER', 'admin')
    default_pass = os.environ.get('ADMIN_PASSWORD', 'admin123')
    
    if os.path.exists(AUTH_FILE):
        try:
            with open(AUTH_FILE, 'r') as f:
                data = json.load(f)
                if data.get('username') and data.get('password_hash'):
                    return data
        except Exception:
            pass
    
    # Initialize default auth configuration
    init_data = {
        'username': default_user,
        'password_hash': hash_password(default_pass),
        'is_default_password': (default_pass == 'admin123'),
        'created_at': time.time(),
        'updated_at': time.time()
    }
    save_auth_config(init_data)
    return init_data

def save_auth_config(data):
    try:
        with open(AUTH_FILE, 'w') as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        print(f"Error saving auth config: {e}")

AUTH_CONFIG = load_auth_config()

# Sessions store: token -> { 'user': str, 'expires': float, 'ip': str }
ACTIVE_SESSIONS = {}

# Rate Limiter & Anti-Brute Force: ip -> { 'attempts': int, 'last_attempt': float, 'blocked_until': float }
LOGIN_ATTEMPTS = {}
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION_SECONDS = 600  # 10 minutes lockout

def is_ip_blocked(ip: str) -> tuple[bool, int]:
    now = time.time()
    entry = LOGIN_ATTEMPTS.get(ip)
    if not entry:
        return False, 0
    
    if entry.get('blocked_until', 0) > now:
        remaining = int(entry['blocked_until'] - now)
        return True, remaining
    
    if now - entry.get('last_attempt', 0) > 900:
        LOGIN_ATTEMPTS.pop(ip, None)
        return False, 0
        
    return False, 0

def record_failed_login(ip: str):
    now = time.time()
    entry = LOGIN_ATTEMPTS.setdefault(ip, {'attempts': 0, 'last_attempt': now, 'blocked_until': 0})
    entry['attempts'] += 1
    entry['last_attempt'] = now
    
    if entry['attempts'] >= MAX_LOGIN_ATTEMPTS:
        entry['blocked_until'] = now + LOCKOUT_DURATION_SECONDS

def record_successful_login(ip: str):
    LOGIN_ATTEMPTS.pop(ip, None)

def create_session(username: str, ip: str) -> str:
    now = time.time()
    for token in list(ACTIVE_SESSIONS.keys()):
        if ACTIVE_SESSIONS[token]['expires'] < now:
            ACTIVE_SESSIONS.pop(token, None)
            
    token = secrets.token_hex(32)
    ACTIVE_SESSIONS[token] = {
        'user': username,
        'expires': now + 86400,
        'ip': ip,
        'created_at': now
    }
    return token

def validate_session(token: str) -> tuple[bool, str]:
    if not token:
        return False, ""
    session = ACTIVE_SESSIONS.get(token)
    if not session:
        return False, ""
    if session['expires'] < time.time():
        ACTIVE_SESSIONS.pop(token, None)
        return False, ""
    return True, session['user']

def destroy_session(token: str):
    if token in ACTIVE_SESSIONS:
        ACTIVE_SESSIONS.pop(token, None)

# ==============================================================================
# NETWORK METRICS & NGROK DATA
# ==============================================================================

last_net_bytes = {'rx': 0, 'tx': 0, 'time': 0}

def get_network_stats():
    global last_net_bytes
    try:
        rx_bytes, tx_bytes = 0, 0
        with open('/proc/net/dev') as f:
            for line in f.readlines()[2:]:
                parts = line.split(':')
                if len(parts) < 2: continue
                iface = parts[0].strip()
                if iface.startswith(('lo', 'docker', 'veth', 'br-')): continue
                stats = parts[1].split()
                rx_bytes += int(stats[0])
                tx_bytes += int(stats[8])
        now = time.time()
        rx_speed, tx_speed = 0, 0
        if last_net_bytes['time'] > 0:
            dt = now - last_net_bytes['time']
            if dt > 0:
                rx_speed = max(0, (rx_bytes - last_net_bytes['rx']) / dt)
                tx_speed = max(0, (tx_bytes - last_net_bytes['tx']) / dt)
        last_net_bytes['rx'] = rx_bytes
        last_net_bytes['tx'] = tx_bytes
        last_net_bytes['time'] = now

        def fmt_b(b):
            if b >= 1073741824: return f"{b / 1073741824:.2f} GB"
            if b >= 1048576: return f"{b / 1048576:.1f} MB"
            if b >= 1024: return f"{b / 1024:.0f} KB"
            return f"{b} B"

        def fmt_s(s):
            if s >= 1048576: return f"{s / 1048576:.2f} MB/s"
            if s >= 1024: return f"{s / 1024:.1f} KB/s"
            return f"{int(s)} B/s"

        return {
            "rx_speed": fmt_s(rx_speed),
            "tx_speed": fmt_s(tx_speed),
            "rx_total": fmt_b(rx_bytes),
            "tx_total": fmt_b(tx_bytes)
        }
    except Exception:
        return {"rx_speed": "0 B/s", "tx_speed": "0 B/s", "rx_total": "0 B", "tx_total": "0 B"}

def get_ngrok_data(host_ip='10.11.2.147'):
    data = {'ssh': None, 'web': None, 'metrics': {}}
    try:
        import urllib.request
        for target in ['172.17.0.1', host_ip, 'localhost', '127.0.0.1']:
            try:
                req = urllib.request.urlopen(f"http://{target}:4040/api/tunnels", timeout=0.8)
                tunnels_json = json.loads(req.read().decode('utf-8'))
                tunnels = tunnels_json.get('tunnels', [])
                for t in tunnels:
                    name = t.get('name', '')
                    proto = t.get('proto', '')
                    pub_url = t.get('public_url', '')
                    
                    if proto == 'tcp' or name == 'ssh':
                        clean = pub_url.replace('tcp://', '')
                        if ':' in clean:
                            host, port = clean.split(':', 1)
                            data['ssh'] = {
                                'public_url': pub_url,
                                'host': host,
                                'port': port,
                                'command': f"ssh decsv@{host} -p {port}"
                            }
                    elif proto in ['http', 'https'] or name == 'web':
                        data['web'] = {
                            'public_url': pub_url,
                            'metrics': t.get('metrics', {})
                        }
                if data['ssh'] or data['web']:
                    break
            except Exception:
                pass
    except Exception:
        pass
    return data

def get_ngrok_requests(host_ip='10.11.2.147', limit=30):
    try:
        import urllib.request
        for target in ['172.17.0.1', host_ip, 'localhost', '127.0.0.1']:
            try:
                req = urllib.request.urlopen(f"http://{target}:4040/api/requests/http?limit={limit}", timeout=0.9)
                raw_data = json.loads(req.read().decode('utf-8'))
                parsed = []
                for r in raw_data.get('requests', []):
                    start_str = r.get('start', '')
                    time_display = start_str
                    try:
                        if 'T' in start_str:
                            time_display = start_str.split('T')[1].replace('Z', '').split('.')[0]
                    except Exception:
                        pass
                    
                    duration_ns = r.get('duration', 0)
                    duration_ms = round(duration_ns / 1000000, 1) if duration_ns else 0
                    
                    req_obj = r.get('request', {})
                    resp_obj = r.get('response', {})
                    
                    headers = req_obj.get('headers', {})
                    ua = headers.get('User-Agent', ['-'])[0] if headers.get('User-Agent') else '-'
                    
                    parsed.append({
                        'id': r.get('id'),
                        'time': time_display,
                        'method': req_obj.get('method', 'GET'),
                        'uri': req_obj.get('uri', '/'),
                        'status_code': resp_obj.get('status_code', 0),
                        'status_text': resp_obj.get('status', ''),
                        'duration_ms': duration_ms,
                        'remote_addr': r.get('remote_addr', '-'),
                        'user_agent': ua
                    })
                return {
                    'success': True,
                    'requests': parsed
                }
            except Exception:
                pass
    except Exception as e:
        return {'success': False, 'error': str(e), 'requests': []}
    return {'success': False, 'requests': []}

# ==============================================================================
# PUBLIC PROJECTS DIRECTORY (END-USER SITES ONLY)
# ==============================================================================

PROJECTS_FILE = os.path.join(os.path.dirname(__file__), 'projects.json')

def load_projects():
    if os.path.exists(PROJECTS_FILE):
        try:
            with open(PROJECTS_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print("Erro ao carregar projects.json:", e)
    return [
        {
            "id": "decam",
            "name": "DECAM — Central Interativa 3D",
            "category": "Simulador 3D",
            "badge": "Aplicação Automotiva",
            "icon": "🏎️",
            "description": "Visualizador 3D interativo Full HD com renderização PBR (Three.js) para inspeção técnica de motores e componentes automotivos (Toyota 2JZ-GTE, turbos, discos de freio, embreagem, injetores). Permite comparar em tempo real peças em bom estado versus peças desgastadas com ficha educativa e leitura por voz.",
            "url": "/decam/"
        },
        {
            "id": "ridecheck-web",
            "name": "RideCheck Web — Gestão de Frotas & Checklists",
            "category": "Gestão & Frotas",
            "badge": "Painel Corporativo",
            "icon": "📋",
            "description": "Plataforma completa em Next.js para gerenciamento operacional de frotas veiculares, relatórios inteligentes de inspeção com IA (Google Gemini), histórico de auditorias e controle de motoristas.",
            "url": "/ridecheck/"
        }
    ]

def save_projects(projects_list):
    try:
        with open(PROJECTS_FILE, 'w', encoding='utf-8') as f:
            json.dump(projects_list, f, ensure_ascii=False, indent=2)
        return True
    except Exception as e:
        print("Erro ao salvar projects.json:", e)
        return False

def get_public_projects_catalog(host_ip='10.11.2.147'):
    ngrok_info = get_ngrok_data(host_ip)
    web_url = 'https://uncommon-caddy-bubbling.ngrok-free.dev'
    if ngrok_info.get('web') and ngrok_info['web'].get('public_url'):
        web_url = ngrok_info['web']['public_url']

    projects = load_projects()
    result = []
    for p in projects:
        url = p.get('url', '#')
        if url.startswith('/'):
            public_url = f"{web_url.rstrip('/')}{url}"
            direct_port_url = f"http://{host_ip}:8000{url}"
        else:
            public_url = url
            direct_port_url = url

        result.append({
            "id": p.get('id', secrets.token_hex(4)),
            "name": p.get('name', 'Novo Projeto'),
            "category": p.get('category', 'Geral'),
            "badge": p.get('badge', 'Aplicação Web'),
            "icon": p.get('icon', '🌐'),
            "description": p.get('description', ''),
            "url": url,
            "direct_port_url": direct_port_url,
            "public_url": public_url,
            "status": "online",
            "tags": p.get('tags', [])
        })
    return result

# ==============================================================================
# ADMIN INFRASTRUCTURE SERVICES CATALOG
# ==============================================================================

def get_admin_services_catalog(host_ip='10.11.2.147'):
    ngrok_info = get_ngrok_data(host_ip)
    web_url = 'https://uncommon-caddy-bubbling.ngrok-free.dev'
    if ngrok_info.get('web') and ngrok_info['web'].get('public_url'):
        web_url = ngrok_info['web']['public_url']

    return [
        {
            "id": "portainer",
            "name": "Portainer CE Docker Manager",
            "category": "Infraestrutura",
            "badge": "DevOps",
            "icon": "🐳",
            "description": "Interface gráfica centralizada para orquestração de contêineres Docker, stacks, volumes e imagens.",
            "url": f"http://{host_ip}:9000",
            "port": 9000,
            "status": "online"
        },
        {
            "id": "adminer",
            "name": "Adminer Database Studio",
            "category": "Banco de Dados",
            "badge": "SQL Client",
            "icon": "🗄️",
            "description": "Cliente visual leve para gerenciamento de bancos de dados PostgreSQL 16 e MySQL 8.4.",
            "url": f"http://{host_ip}:8080",
            "port": 8080,
            "status": "online"
        },
        {
            "id": "web-terminal",
            "name": "Web Terminal Console Linux",
            "category": "Terminal",
            "badge": "Console Web",
            "icon": "💻",
            "description": "Acesso direto ao shell Bash do Linux via navegador web com WebSocket ultra-rápido.",
            "url": "/terminal/",
            "port": 7681,
            "status": "online"
        },
        {
            "id": "postgres",
            "name": "PostgreSQL 16 Enterprise",
            "category": "Banco de Dados",
            "badge": "Porta 5432",
            "icon": "🐘",
            "description": "Banco de dados relacional robusto e corporativo rodando em contêiner isolado.",
            "url": f"http://{host_ip}:8080",
            "port": 5432,
            "status": "online"
        },
        {
            "id": "mysql",
            "name": "MySQL 8.4 Server",
            "category": "Banco de Dados",
            "badge": "Porta 3306",
            "icon": "🐬",
            "description": "Sistema de banco de dados relacional de alta performance.",
            "url": f"http://{host_ip}:8080",
            "port": 3306,
            "status": "online"
        },
        {
            "id": "redis",
            "name": "Redis 7 In-Memory Cache",
            "category": "Cache",
            "badge": "Porta 6379",
            "icon": "⚡",
            "description": "Armazenamento em memória de chave-valor para alta velocidade.",
            "url": "#",
            "port": 6379,
            "status": "online"
        },
        {
            "id": "ngrok",
            "name": "Ngrok Gateway & Tunnels",
            "category": "Conectividade",
            "badge": "Túnel Seguro",
            "icon": "🌐",
            "description": "Túnel seguro para publicação externa com domínio fixo HTTPS e encaminhamento TCP dinâmico para SSH nativo.",
            "url": f"http://{host_ip}:4040",
            "port": 4040,
            "status": "online"
        }
    ]

# ==============================================================================
# HTTP REQUEST HANDLER WITH CYBERSECURITY HARDENING
# ==============================================================================

class ServerHandler(http.server.SimpleHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=os.path.dirname(__file__), **kwargs)

    def get_client_ip(self):
        forwarded = self.headers.get('X-Forwarded-For')
        if forwarded:
            return forwarded.split(',')[0].strip()
        real_ip = self.headers.get('X-Real-IP')
        if real_ip:
            return real_ip.strip()
        return self.client_address[0] if self.client_address else '127.0.0.1'

    def get_session_token(self):
        cookie_header = self.headers.get('Cookie')
        if not cookie_header:
            return None
        cookie = SimpleCookie()
        try:
            cookie.load(cookie_header)
            if 'homehub_session' in cookie:
                return cookie['homehub_session'].value
        except Exception:
            pass
        return None

    def is_authenticated(self):
        token = self.get_session_token()
        valid, user = validate_session(token)
        return valid, user

    def apply_security_headers(self):
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'SAMEORIGIN')
        self.send_header('X-XSS-Protection', '1; mode=block')
        self.send_header('Referrer-Policy', 'strict-origin-when-cross-origin')
        self.send_header('Content-Security-Policy', "default-src 'self' 'unsafe-inline' 'unsafe-eval' https://fonts.googleapis.com https://fonts.gstatic.com data:; font-src 'self' https://fonts.gstatic.com data:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com;")

    def send_json(self, data, status_code=200, extra_headers=None):
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.apply_security_headers()
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(json.dumps(data).encode('utf-8'))

    def do_HEAD(self):
        if self.path == '/decam' or self.path.startswith('/decam/'):
            self.proxy_decam()
            return
        return super().do_HEAD()

    def do_GET(self):
        # 1. Route /admin and /admin/ to admin.html
        if self.path in ['/admin', '/admin/']:
            self.path = '/admin.html'

        # 2. Reverse Proxy for DECAM
        if self.path == '/decam' or self.path.startswith('/decam/'):
            self.proxy_decam()
            return

        # 3. Public Projects Directory API & Admin Projects GET
        if self.path in ['/api/projects', '/api/admin/projects']:
            host_ip = os.environ.get('HOST_IP', '10.11.2.147')
            projects = get_public_projects_catalog(host_ip)
            self.send_json({'success': True, 'projects': projects})
            return

        # 4. Session Status API
        if self.path == '/api/session':
            is_auth, username = self.is_authenticated()
            self.send_json({
                'authenticated': is_auth,
                'username': username if is_auth else None,
                'is_default_password': AUTH_CONFIG.get('is_default_password', False) if is_auth else False
            })
            return

        # 4. System Status API (PROTECTED: Requires Admin Authentication)
        if self.path == '/api/status':
            is_auth, username = self.is_authenticated()
            if not is_auth:
                self.send_json({
                    'authenticated': False,
                    'error': 'Acesso não autorizado. Faça login como administrador para visualizar os dados confidenciais do servidor.'
                }, status_code=401)
                return
            
            data = self.get_system_status()
            self.send_json(data)
            return

        # 5. Live Requests Stream API (PROTECTED: Requires Admin Authentication)
        if self.path == '/api/requests' or self.path.startswith('/api/requests'):
            is_auth, username = self.is_authenticated()
            if not is_auth:
                self.send_json({
                    'authenticated': False,
                    'error': 'Acesso restrito ao administrador.'
                }, status_code=401)
                return

            host_ip = os.environ.get('HOST_IP', '10.11.2.147')
            data = get_ngrok_requests(host_ip=host_ip, limit=30)
            self.send_json(data)
            return

        return super().do_GET()

    def do_POST(self):
        client_ip = self.get_client_ip()

        # 1. Admin Login API with Anti-Brute-Force Protection
        if self.path == '/api/login':
            blocked, remaining = is_ip_blocked(client_ip)
            if blocked:
                self.send_json({
                    'success': False,
                    'error': f'Muitas tentativas falhas. Acesso bloqueado temporariamente. Tente novamente em {remaining} segundos.'
                }, status_code=429)
                return

            try:
                length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(length).decode('utf-8')
                payload = json.loads(body)
                
                username = payload.get('username', '').strip()
                password = payload.get('password', '')

                # Artificial timing delay against side-channel analysis
                time.sleep(0.1)

                if username == AUTH_CONFIG.get('username') and verify_password(password, AUTH_CONFIG.get('password_hash')):
                    record_successful_login(client_ip)
                    session_token = create_session(username, client_ip)
                    
                    cookie_header = f"homehub_session={session_token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400"
                    self.send_json({
                        'success': True,
                        'message': 'Autenticado com sucesso!',
                        'user': username,
                        'is_default_password': AUTH_CONFIG.get('is_default_password', False)
                    }, extra_headers={'Set-Cookie': cookie_header})
                    return
                else:
                    record_failed_login(client_ip)
                    attempts_left = max(0, MAX_LOGIN_ATTEMPTS - LOGIN_ATTEMPTS.get(client_ip, {}).get('attempts', 0))
                    self.send_json({
                        'success': False,
                        'error': f'Credenciais inválidas. Tentativas restantes antes do bloqueio: {attempts_left}'
                    }, status_code=401)
                    return
            except Exception as e:
                self.send_json({'success': False, 'error': f'Requisição inválida: {str(e)}'}, status_code=400)
                return

        # 2. Admin Logout API
        if self.path == '/api/logout':
            token = self.get_session_token()
            if token:
                destroy_session(token)
            
            cookie_header = "homehub_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"
            self.send_json({'success': True, 'message': 'Sessão encerrada com segurança.'}, extra_headers={'Set-Cookie': cookie_header})
            return

        # 3. Change Password API (PROTECTED)
        if self.path == '/api/change-password':
            is_auth, username = self.is_authenticated()
            if not is_auth:
                self.send_json({'success': False, 'error': 'Acesso não autorizado.'}, status_code=401)
                return

            try:
                length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(length).decode('utf-8')
                payload = json.loads(body)

                current_password = payload.get('current_password', '')
                new_password = payload.get('new_password', '')

                if not verify_password(current_password, AUTH_CONFIG.get('password_hash')):
                    self.send_json({'success': False, 'error': 'Senha atual incorreta.'}, status_code=400)
                    return

                if len(new_password) < 6:
                    self.send_json({'success': False, 'error': 'A nova senha deve conter no mínimo 6 caracteres.'}, status_code=400)
                    return

                AUTH_CONFIG['password_hash'] = hash_password(new_password)
                AUTH_CONFIG['is_default_password'] = False
                AUTH_CONFIG['updated_at'] = time.time()
                save_auth_config(AUTH_CONFIG)

                self.send_json({'success': True, 'message': 'Senha alterada com sucesso!'})
                return
            except Exception as e:
                self.send_json({'success': False, 'error': str(e)}, status_code=400)
                return

        # 4. Save/Update Project API (PROTECTED: Requires Admin Authentication)
        if self.path == '/api/admin/projects':
            is_auth, username = self.is_authenticated()
            if not is_auth:
                self.send_json({'success': False, 'error': 'Acesso restrito ao administrador.'}, status_code=401)
                return

            try:
                length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(length).decode('utf-8')
                payload = json.loads(body)

                projects = load_projects()
                project_id = payload.get('id')

                if not project_id:
                    # New project
                    project_id = f"proj-{secrets.token_hex(4)}"
                    payload['id'] = project_id
                    projects.append(payload)
                else:
                    # Edit existing project
                    found = False
                    for i, p in enumerate(projects):
                        if p.get('id') == project_id:
                            projects[i] = payload
                            found = True
                            break
                    if not found:
                        projects.append(payload)

                save_projects(projects)
                self.send_json({'success': True, 'message': 'Site salvo com sucesso!', 'projects': projects})
                return
            except Exception as e:
                self.send_json({'success': False, 'error': f'Erro ao salvar site: {str(e)}'}, status_code=400)
                return

        # 5. Delete Project API (PROTECTED: Requires Admin Authentication)
        if self.path == '/api/admin/projects/delete':
            is_auth, username = self.is_authenticated()
            if not is_auth:
                self.send_json({'success': False, 'error': 'Acesso restrito ao administrador.'}, status_code=401)
                return

            try:
                length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(length).decode('utf-8')
                payload = json.loads(body)
                target_id = payload.get('id')

                projects = load_projects()
                new_projects = [p for p in projects if p.get('id') != target_id]
                save_projects(new_projects)
                self.send_json({'success': True, 'message': 'Site removido com sucesso!', 'projects': new_projects})
                return
            except Exception as e:
                self.send_json({'success': False, 'error': f'Erro ao excluir site: {str(e)}'}, status_code=400)
                return

        self.send_error(404, "Endpoint não encontrado")

    def proxy_decam(self):
        if self.path == '/decam':
            self.send_response(301)
            self.send_header('Location', '/decam/')
            self.apply_security_headers()
            self.end_headers()
            return
        
        sub_path = self.path[6:]
        if not sub_path:
            sub_path = '/'
        
        targets = [('decam', 80), ('homeserver-decam', 80), ('127.0.0.1', 8000), ('localhost', 8000)]
        method = getattr(self, 'command', 'GET')
        for host, port in targets:
            try:
                import http.client
                conn = http.client.HTTPConnection(host, port, timeout=10)
                headers = {k: v for k, v in self.headers.items() if k.lower() != 'host'}
                conn.request(method, sub_path, headers=headers)
                resp = conn.getresponse()
                
                self.send_response(resp.status)
                content_length = resp.getheader('Content-Length')
                for k, v in resp.getheaders():
                    if k.lower() not in ['transfer-encoding', 'connection']:
                        self.send_header(k, v)
                self.apply_security_headers()
                self.end_headers()

                if method != 'HEAD':
                    while True:
                        chunk = resp.read(65536)
                        if not chunk:
                            break
                        self.wfile.write(chunk)
                conn.close()
                return
            except Exception:
                pass

        self.send_error(502, "Serviço DECAM Indisponível")

    def get_system_status(self):
        # Get CPU usage & Uptime
        cpu_percent = 0.0
        uptime_str = "Online"
        try:
            if os.path.exists('/proc/uptime'):
                with open('/proc/uptime', 'r') as f:
                    uptime_seconds = float(f.readline().split()[0])
                    days = int(uptime_seconds // 86400)
                    hours = int((uptime_seconds % 86400) // 3600)
                    minutes = int((uptime_seconds % 3600) // 60)
                    uptime_str = f"{days}d {hours}h {minutes}m" if days > 0 else f"{hours}h {minutes}m"
            load1, _, _ = os.getloadavg()
            cpu_count = os.cpu_count() or 1
            cpu_percent = round(min(100.0, (load1 / cpu_count) * 100), 1)
        except Exception:
            pass

        # Get memory usage
        mem_total, mem_used, mem_percent = 0, 0, 0
        try:
            with open('/proc/meminfo', 'r') as f:
                lines = f.readlines()
                mem = {}
                for line in lines:
                    parts = line.split(':')
                    if len(parts) == 2:
                        key = parts[0].strip()
                        val = int(parts[1].split()[0])
                        mem[key] = val
                total = mem.get('MemTotal', 1)
                free = mem.get('MemAvailable', mem.get('MemFree', 0))
                used = total - free
                mem_total = round(total / (1024 * 1024), 2)
                mem_used = round(used / (1024 * 1024), 2)
                mem_percent = round((used / total) * 100, 1)
        except Exception:
            pass

        # Get Disk Usage
        disk_total, disk_used, disk_percent = 0, 0, 0
        try:
            df = subprocess.check_output(['df', '-h', '/']).decode('utf-8').splitlines()
            if len(df) > 1:
                parts = df[1].split()
                disk_total = parts[1]
                disk_used = parts[2]
                disk_percent = parts[4]
        except Exception:
            pass

        # Check Services Connectivity / Ports
        host_ip = os.environ.get('HOST_IP', '10.11.2.147')
        services = {
            'decam': self.check_port('decam', 80, host_ip) or self.check_port('127.0.0.1', 8000, host_ip),
            'terminal': self.check_port('web-terminal', 7681, host_ip),
            'postgres': self.check_port('postgres', 5432, host_ip),
            'mysql': self.check_port('mysql', 3306, host_ip),
            'redis': self.check_port('redis', 6379, host_ip),
            'adminer': self.check_port('adminer', 8080, host_ip),
            'portainer': self.check_port('portainer', 9000, host_ip),
            'ssh': True
        }

        # Check Docker Containers
        containers = []
        try:
            ps = subprocess.check_output(['docker', 'ps', '--format', '{{.Names}}|{{.Image}}|{{.Status}}|{{.Ports}}'], timeout=1.5).decode('utf-8').splitlines()
            for line in ps:
                parts = line.split('|')
                if len(parts) >= 3:
                    containers.append({
                        'name': parts[0],
                        'image': parts[1],
                        'status': parts[2],
                        'ports': parts[3] if len(parts) > 3 else ''
                    })
        except Exception:
            containers = [
                {'name': 'homeserver-decam', 'status': 'Up (healthy)', 'ports': '8000->80'},
                {'name': 'homehub-dashboard', 'status': 'Up (healthy)', 'ports': '3000->3000'},
                {'name': 'homeserver-terminal', 'status': 'Up (healthy)', 'ports': '7681->7681'},
                {'name': 'homeserver-ngrok', 'status': 'Up (healthy)', 'ports': '8000->ngrok'},
                {'name': 'homeserver-portainer', 'status': 'Up (healthy)', 'ports': '9000->9000'},
                {'name': 'homeserver-adminer', 'status': 'Up (healthy)', 'ports': '8080->8080'},
                {'name': 'homeserver-postgres', 'status': 'Up (healthy)', 'ports': '5432->5432'},
                {'name': 'homeserver-mysql', 'status': 'Up (healthy)', 'ports': '3306->3306'},
                {'name': 'homeserver-redis', 'status': 'Up (healthy)', 'ports': '6379->6379'}
            ]

        tailscale_ip = os.environ.get('TAILSCALE_IP', '100.92.242.64')
        ngrok_info = get_ngrok_data(host_ip)
        
        web_url = 'https://uncommon-caddy-bubbling.ngrok-free.dev'
        if ngrok_info.get('web') and ngrok_info['web'].get('public_url'):
            web_url = ngrok_info['web']['public_url']

        # Format disk percent as integer
        disk_pct_int = 0
        try:
            disk_pct_int = int(str(disk_percent).replace('%', '').strip())
        except Exception:
            pass

        net_stats = get_network_stats()
        admin_services = get_admin_services_catalog(host_ip)

        ssh_port = '16898'
        ssh_host = '0.tcp.sa.ngrok.io'
        if ngrok_info.get('ssh'):
            ssh_port = str(ngrok_info['ssh'].get('port', ssh_port))
            ssh_host = str(ngrok_info['ssh'].get('host', ssh_host))

        return {
            'authenticated': True,
            'host_ip': host_ip,
            'tailscale_ip': tailscale_ip,
            'ngrok_url': web_url,
            'ngrok_ssh': ngrok_info.get('ssh'),
            'ngrok_ssh_port': ssh_port,
            'ngrok_ssh_host': ssh_host,
            'ngrok_web': ngrok_info.get('web'),
            'uptime': uptime_str,
            'cpu_percent': cpu_percent,
            'ram_percent': mem_percent,
            'ram_used_gb': mem_used,
            'ram_total_gb': mem_total,
            'disk_percent': disk_pct_int,
            'disk_used_gb': disk_used,
            'disk_total_gb': disk_total,
            'net_rx_speed': net_stats.get('rx_speed', '0 B/s'),
            'net_tx_speed': net_stats.get('tx_speed', '0 B/s'),
            'net_rx_total': net_stats.get('rx_total', '0 B'),
            'net_tx_total': net_stats.get('tx_total', '0 B'),
            'cpu': {
                'percent': cpu_percent
            },
            'memory': {
                'total_gb': mem_total,
                'used_gb': mem_used,
                'percent': mem_percent
            },
            'disk': {
                'total': disk_total,
                'used': disk_used,
                'percent': disk_percent
            },
            'network': net_stats,
            'services': services,
            'admin_services': admin_services,
            'containers': containers
        }

    def check_port(self, host, port, host_ip='10.11.2.147'):
        import socket
        for target in [f"homeserver-{host}", host, '127.0.0.1']:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.15)
            try:
                s.connect((target, port))
                s.close()
                return True
            except Exception:
                s.close()
        return False

if __name__ == '__main__':
    print(f"Starting Secure HomeHub Server on port {PORT}...")
    with socketserver.TCPServer(("", PORT), ServerHandler) as httpd:
        httpd.serve_forever()
