#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HomeHub — Radar do Servidor
──────────────────────────────────────────────────────────────────────────────
Duas frentes, ambas alimentando a página "Radar do Servidor" do painel Admin:

  1) scan_workspace()
     Varre a home real do servidor (bind-mount /hosthome → /home/decsv) em
     busca de projetos que estão sendo programados FORA do HomeHub. Para cada
     um descobre: stack, tamanho, última atividade (git + mtime), se existe
     container/porta rodando e se já está integrado ao catálogo do portal.
     Também lista serviços que respondem em portas do host mas NÃO são
     publicados por nenhum container (= processos soltos fora do Docker).

  2) docker_audit()
     Cruza `docker system df -v --format json` + `docker inspect` + deploy.db
     para separar o que está EM USO do que está OCIOSO: imagens sem container,
     containers parados, volumes órfãos, redes sem uso e cache de build.
     Devolve recomendações ordenadas por espaço recuperável.

Tudo aqui é somente-leitura, com exceção de run_prune(), que executa apenas os
comandos de limpeza explicitamente marcados pelo administrador no painel.
"""
import json
import os
import re
import socket
import sqlite3
import subprocess
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

APP_DIR    = Path(__file__).parent
DB_PATH    = APP_DIR / "deploy.db"
PROJECTS_F = APP_DIR / "projects.json"
KNOWN_F    = APP_DIR / "radar-known-services.json"

# Raiz da varredura: dentro do container o bind-mount /hosthome é a home real.
FILES_ROOT  = Path(os.environ.get("FILES_ROOT", str(Path.home()))).resolve()
MAX_DEPTH   = int(os.environ.get("RADAR_MAX_DEPTH", "6"))
SCAN_BUDGET = float(os.environ.get("RADAR_SCAN_BUDGET", "15"))
# Candidatos a "host" vistos de dentro do container (gateway das bridges + LAN).
PROBE_HOSTS = [h for h in [
    os.environ.get("RADAR_PROBE_HOST", ""),
    os.environ.get("HOST_IP", ""),
    "172.17.0.1", "172.18.0.1",
] if h]
PROBE_TIMEOUT = 0.4

# ── Ruído de varredura ────────────────────────────────────────────────────────
# Pastas que nunca são projeto (deps, caches, ferramentas, artefatos de build).
NOISE_DIRS = {
    "node_modules", ".next", ".nuxt", ".output", "dist", "build", "out",
    "coverage", ".venv", "venv", "env", "__pycache__", ".pytest_cache",
    ".mypy_cache", ".ruff_cache", ".turbo", ".swc", ".parcel-cache",
    ".gradle", ".android", ".cargo", ".rustup", "target", "vendor",
    ".npm", ".npm-global", ".yarn", ".pnpm-store", ".cache", ".local",
    ".vscode", ".vscode-server", ".antigravity", ".claude", ".codex",
    ".config", ".ssh", ".gnupg", ".pki", ".docker", ".kube", ".terraform",
    "snap", ".expo", ".app-store", ".mozilla", ".thunderbird", ".wine",
    ".Trash", ".gvfs", ".java", ".oracle_jre_usage", "site-packages",
    "Imagens", "Músicas", "Vídeos", "Modelos", "Público", "Documentos",
    "Área de trabalho",
}
# Pastas ocultas que valem a pena atravessar (o resto é ignorado).
ALLOW_HIDDEN = {".gemini"}
# Dentro de .gemini só o scratch interessa (é lá que vivem os projetos).
GEMINI_ALLOWED_PARTS = ("antigravity/scratch",)

# Marcadores que caracterizam um projeto de software.
STRONG_MARKERS = {
    ".git": "git",
    "package.json": "node",
    "requirements.txt": "python",
    "pyproject.toml": "python",
    "Pipfile": "python",
    "setup.py": "python",
    "docker-compose.yml": "compose",
    "docker-compose.yaml": "compose",
    "compose.yml": "compose",
    "compose.yaml": "compose",
    "Dockerfile": "docker",
    "Cargo.toml": "rust",
    "go.mod": "go",
    "composer.json": "php",
    "pom.xml": "java",
    "build.gradle": "java",
    "Gemfile": "ruby",
    "pubspec.yaml": "flutter",
}
# App python "solto" (sem requirements.txt): server.py/app.py + index.html/README.
PY_ENTRYPOINTS = {"server.py", "app.py", "main.py", "manage.py", "wsgi.py"}

# Portas candidatas à sondagem (services do host fora do Docker aparecem aqui).
DEFAULT_PROBE_PORTS = [
    3000, 3001, 3002, 3003, 3010, 4000, 4001, 4002, 4003, 5000, 5001, 5173,
    5432, 5433, 5438, 6379, 6380, 7681, 7682, 7683, 8000, 8001, 8008, 8080,
    8081, 8082, 8083, 8088, 8888, 9000, 9443, 3306, 4040, 4041, 20241,
]

# Serviços conhecidos do host (identificação amigável). Editável pelo arquivo
# radar-known-services.json sem precisar rebuildar o container.
DEFAULT_KNOWN_SERVICES = {
    "3000": "HomeHub (este painel)",
    "3001": "RideCheck Web (compose)",
    "3010": "Book do Motorista (Next.js dev/prod)",
    "4040": "ngrok inspect API",
    "4041": "ngrok inspect API (túnel SSH)",
    "5000": "Command Panel (command_panel/server.py)",
    "5438": "Postgres dev — Book do Motorista",
    "7681": "Terminal Web (container homeserver-terminal)",
    "7683": "ttyd legado no host (fora do Docker)",
    "8000": "DECAM — nginx (container homeserver-decam)",
    "8001": "Portal app.py (home do servidor)",
    "8081": "RideCheck Mobile / Expo",
    "8082": "fcc-server (free-claude-code)",
    "20241": "cloudflared métricas",
}

_cache = {}
_CACHE_TTL = 25.0


# ════════════════════════════════════════════════════════════════════════════
# HELPERS
# ════════════════════════════════════════════════════════════════════════════
def _fmt_bytes(b):
    try:
        b = float(b or 0)
    except (TypeError, ValueError):
        return "0 B"
    if b <= 0:
        return "0 B"
    units = ("B", "KB", "MB", "GB", "TB")
    i = 0
    while b >= 1024 and i < len(units) - 1:
        b /= 1024
        i += 1
    if i == 0:
        return f"{b:.0f} B"
    if b >= 100:
        return f"{b:.0f} {units[i]}"
    if b >= 10:
        return f"{b:.1f} {units[i]}"
    return f"{b:.2f} {units[i]}"


_SIZE_RE = re.compile(r"([\d.]+)\s*([KMGT]?i?B)", re.I)


def _parse_size(txt):
    """Converte '1.94GB' / '48.7MB' / '4.096kB' (saída do Docker) em bytes."""
    if not txt:
        return 0
    m = _SIZE_RE.search(str(txt))
    if not m:
        return 0
    try:
        n = float(m.group(1))
    except ValueError:
        return 0
    unit = m.group(2).upper().replace("I", "")
    return int(n * (1024 ** {"B": 0, "KB": 1, "MB": 2, "GB": 3, "TB": 4}.get(unit, 0)))


def _as_bool(v):
    """O Docker devolve booleans como STRING no --format json ('true'/'false')."""
    if isinstance(v, bool):
        return v
    return str(v).strip().lower() in ("true", "1", "yes")


def _df_summary():
    """Números oficiais do `docker system df` (fonte da verdade do reclaimable)."""
    out, _err = _docker_json(["system", "df", "--format", "json"], timeout=45)
    table = {}
    if not out:
        return table
    for line in out.strip().splitlines():
        try:
            row = json.loads(line)
        except Exception:                                    # noqa: BLE001
            continue
        table[row.get("Type") or ""] = {
            "total": int(row.get("TotalCount") or 0),
            "active": int(row.get("Active") or 0),
            "size": row.get("Size") or "",
            "size_bytes": _parse_size(row.get("Size")),
            "reclaimable": row.get("Reclaimable") or "",
            "reclaimable_bytes": _parse_size(row.get("Reclaimable")),
        }
    return table


def _run(cmd, timeout=25):
    """Executa um comando e devolve (ok, stdout, stderr). Nunca lança."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode == 0, r.stdout or "", r.stderr or ""
    except FileNotFoundError:
        return False, "", f"comando não encontrado: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return False, "", f"timeout após {timeout}s"
    except Exception as e:                                    # noqa: BLE001
        return False, "", str(e)


def _docker_json(args, timeout=30):
    ok, out, err = _run(["docker"] + args, timeout=timeout)
    if not ok:
        return None, err.strip()
    return out, None


def _mount_map():
    """Bind mounts do próprio container como [(destino_container, origem_host)]."""
    if "mount_map" in _cache:
        return _cache["mount_map"]
    mounts = []
    try:
        hn = socket.gethostname()[:12]
        out, _err = _docker_json(["inspect", hn, "--format", "{{json .Mounts}}"], timeout=10)
        if out:
            for m in json.loads(out):
                if m.get("Type") == "bind" and m.get("Destination") and m.get("Source"):
                    mounts.append((m["Destination"], m["Source"]))
    except Exception:                                        # noqa: BLE001
        pass
    mounts.sort(key=lambda x: len(x[0]), reverse=True)
    _cache["mount_map"] = mounts
    return mounts


def _host_root():
    """Caminho da home real no host (ex.: /home/decsv), lido dos mounts.

    Não confia no env FILES_ROOT: ele pode apontar para uma subpasta
    (ex.: /hosthome/Documentos, raiz do Gerenciador de Arquivos). O Radar
    precisa da home INTEIRA, então resolve o mount que a contém.
    """
    if "host_root" in _cache:
        return _cache["host_root"]
    root = os.environ.get("HOST_HOME", "").strip()
    if not root:
        for dest, src in _mount_map():
            if str(FILES_ROOT) == dest or str(FILES_ROOT).startswith(dest + "/"):
                root = src
                break
    root = root or "/home/decsv"
    _cache["host_root"] = root.rstrip("/")
    return _cache["host_root"]


def _scan_root():
    """Diretório DENTRO do container que espelha a home inteira do host."""
    if "scan_root" in _cache:
        return _cache["scan_root"]
    host_root = _host_root()
    dest = ""
    for d, s in _mount_map():
        if s == host_root:
            dest = d
            break
    root = Path(dest) if dest else Path(str(FILES_ROOT))
    _cache["scan_root"] = root
    return root


def to_host_path(container_path):
    p = str(container_path)
    prefix = str(_scan_root())
    if p == prefix:
        return _host_root()
    if p.startswith(prefix + "/"):
        return _host_root() + p[len(prefix):]
    return p


def _norm(name):
    return re.sub(r"[^a-z0-9]+", "", str(name or "").lower())


def _host_ip():
    """IP LAN do host, detectado ao vivo.

    O env HOST_IP do docker-compose pode ficar defasado (IP dinâmico via DHCP);
    usamos as interfaces vistas pelo container efêmero com netns do host.
    """
    if _cache.get("host_ip") and time.time() - _cache.get("host_ip_ts", 0) < 300:
        return _cache["host_ip"]
    lan = ""
    for name, ip in sorted((_cache.get("host_interfaces") or {}).items()):
        if name == "lo" or name.startswith(("docker", "br-", "veth", "tailscale",
                                            "wg", "zt", "virbr", "tun", "tap")):
            continue
        if ip.startswith(("127.", "169.254.")):
            continue
        lan = ip
        break
    if not lan:
        env_ip = os.environ.get("HOST_IP", "").strip()
        if env_ip and _port_open(env_ip, 22):
            lan = env_ip
    if not lan:
        lan = os.environ.get("HOST_IP", "").strip() or "localhost"
    _cache["host_ip"] = lan
    _cache["host_ip_ts"] = time.time()
    return lan


def _load_known_services():
    """Rótulos amigáveis de portas. Editável em radar-known-services.json."""
    known = dict(DEFAULT_KNOWN_SERVICES)
    try:
        if KNOWN_F.exists():
            extra = json.loads(KNOWN_F.read_text())
            if isinstance(extra, dict):
                known.update({str(k): str(v) for k, v in extra.items()})
    except Exception:                                        # noqa: BLE001
        pass
    return known


def _probe_host():
    """Escolhe um endereço do host alcançável a partir de dentro do container."""
    if _cache.get("probe_host") and time.time() - _cache.get("probe_host_ts", 0) < 120:
        return _cache["probe_host"]
    chosen = PROBE_HOSTS[0] if PROBE_HOSTS else "172.17.0.1"
    for host in PROBE_HOSTS:
        hit = False
        for port in (22, 3000, 8000):
            if _port_open(host, port):
                chosen, hit = host, True
                break
        if hit:
            break
    _cache["probe_host"] = chosen
    _cache["probe_host_ts"] = time.time()
    return chosen


def _port_open(host, port):
    try:
        with socket.create_connection((host, port), timeout=PROBE_TIMEOUT):
            return True
    except OSError:
        return False


def _http_identify(host, port):
    """Best-effort: identifica o serviço HTTP atrás de uma porta viva."""
    try:
        req = urllib.request.Request(f"http://{host}:{port}/",
                                     headers={"User-Agent": "HomeHub-Radar/1.0"})
        with urllib.request.urlopen(req, timeout=1.5) as resp:
            body = resp.read(4096).decode("utf-8", "ignore")
            server = resp.headers.get("Server") or ""
            code = resp.status
        title = ""
        m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
        if m:
            title = re.sub(r"\s+", " ", m.group(1)).strip()[:80]
        return {"http_status": code, "http_server": server, "http_title": title}
    except urllib.error.HTTPError as e:
        try:
            server = (e.headers or {}).get("Server") or ""
        except Exception:                                    # noqa: BLE001
            server = ""
        return {"http_status": e.code, "http_server": server, "http_title": ""}
    except Exception:                                        # noqa: BLE001
        return {}


def _deploy_db_rows():
    """Lê deploy.db (read-only): apps publicados e versões mantidas p/ rollback."""
    apps, versions = [], []
    try:
        con = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True, timeout=2)
        con.row_factory = sqlite3.Row
        for r in con.execute("select * from deploy_apps"):
            apps.append(dict(r))
        for r in con.execute("select * from deploy_versions"):
            versions.append(dict(r))
        con.close()
    except Exception:                                        # noqa: BLE001
        pass
    return apps, versions


def _git_info(path):
    """Branch, último commit, remote e sujeira do working tree."""
    if not (path / ".git").exists():
        return None
    info = {"branch": "", "last_commit_at": None, "last_commit_msg": "",
            "dirty": None, "remote": ""}
    base = ["git", "-C", str(path), "-c", "safe.directory=*"]
    ok, out, _ = _run(base + ["rev-parse", "--abbrev-ref", "HEAD"], timeout=8)
    if ok:
        info["branch"] = out.strip()
    ok, out, _ = _run(base + ["log", "-1", "--pretty=%ct%x09%s"], timeout=8)
    if ok and out.strip():
        parts = out.strip().split("\t", 1)
        try:
            info["last_commit_at"] = float(parts[0])
        except (ValueError, IndexError):
            pass
        if len(parts) > 1:
            info["last_commit_msg"] = parts[1][:120]
    ok, out, _ = _run(base + ["status", "--porcelain"], timeout=12)
    if ok:
        info["dirty"] = len([l for l in out.splitlines() if l.strip()])
    ok, out, _ = _run(base + ["remote", "get-url", "origin"], timeout=6)
    if ok:
        info["remote"] = out.strip()
    return info

# ════════════════════════════════════════════════════════════════════════════
# VARREDURA DO HOST — PROJETOS EM DESENVOLVIMENTO
# ════════════════════════════════════════════════════════════════════════════
def _iter_dirs(root=None, budget=None, max_depth=None):
    """Gera (path, depth, entries) dos diretórios candidatos da home.

    Poda caches/dependências e atravessa apenas as pastas ocultas úteis
    (.gemini → antigravity/scratch, onde vivem os projetos do servidor).
    """
    root = Path(root or _scan_root())
    budget = SCAN_BUDGET if budget is None else budget
    max_depth = MAX_DEPTH if max_depth is None else max_depth
    deadline = time.time() + budget
    stack = [(root, 0)]
    visited = 0
    while stack:
        if time.time() > deadline or visited > 40000:
            return
        path, depth = stack.pop()
        try:
            with os.scandir(path) as it:
                entries = list(it)
        except (PermissionError, OSError):
            continue
        visited += 1
        yield path, depth, entries
        if depth >= max_depth:
            continue
        for e in entries:
            try:
                if not e.is_dir(follow_symlinks=False):
                    continue
            except OSError:
                continue
            name = e.name
            if name in NOISE_DIRS:
                continue
            if name.startswith("."):
                if name not in ALLOW_HIDDEN:
                    continue
                if name == ".gemini":
                    sub = Path(e.path) / "antigravity" / "scratch"
                    if sub.is_dir():
                        stack.append((sub, depth + 1))
                continue
            child = Path(e.path)
            # Corta na hora raízes de terceiros (tarball, bundle de IDE…):
            # assim a subárvore inteira nem entra na fila.
            try:
                sub_names = [x.name for x in os.scandir(child)]
            except OSError:
                continue
            if _is_third_party_root(child, sub_names):
                continue
            stack.append((child, depth + 1))


_VERSION_DIR_RE = re.compile(r"^[A-Za-z][\w.+~-]*-\d+(\.\d+)+")


def _looks_vendored(name, names):
    """Código-fonte baixado (ex.: Python-3.14.7) não é projeto do usuário."""
    return bool(_VERSION_DIR_RE.match(name)) and ".git" not in names


def _is_third_party_root(path, names):
    """Raízes de terceiros: tarballs, bundles de IDE/Electron, pacotes Python.

    Quando uma pasta destas é detectada a subárvore INTEIRA é descartada —
    senão cada extensão de IDE (com package.json) viraria um "projeto".
    """
    name = path.name
    if name in ("site-packages", "dist-packages", "bower_components", "jspm_packages"):
        return True
    if _looks_vendored(name, names):
        return True
    # Bundle tipo VSCode/Antigravity: <App>/resources/app/extensions/*
    if (path / "resources" / "app" / "extensions").is_dir():
        return True
    if "product.json" in names and "extensions" in names:
        return True
    # Aplicativos empacotados (nome com espaço + estrutura de bundle)
    if " " in name and {"resources", "bin", "lib"} & set(names) \
            and not ({".git", "package.json"} & set(names)):
        return True
    return False


def _similar(a, b):
    """Comparação tolerante de nomes — exige tamanho mínimo p/ evitar 'r' == tudo."""
    a, b = _norm(a), _norm(b)
    if not a or not b:
        return False
    if a == b:
        return True
    if len(a) >= 5 and len(b) >= 5:
        return a in b or b in a
    return False


def _detect_stack(path, names):
    """Identifica stack, marcadores e portas declaradas no package.json."""
    stack, markers, ports = [], [], []
    for marker, kind in STRONG_MARKERS.items():
        if marker in names:
            markers.append(marker)
            if kind not in stack:
                stack.append(kind)
    lower = {n.lower() for n in names}
    for nxt in ("next.config.js", "next.config.mjs", "next.config.ts"):
        if nxt in lower and "nextjs" not in stack:
            stack.insert(0, "nextjs")
            break
    pkg = path / "package.json"
    if pkg.exists():
        try:
            data = json.loads(pkg.read_text(errors="ignore"))
            deps = {**(data.get("dependencies") or {}), **(data.get("devDependencies") or {})}
            scripts = " ".join((data.get("scripts") or {}).values())
            for key, label in [
                ("next", "nextjs"), ("react-native", "react-native"), ("expo", "expo"),
                ("react", "react"), ("vue", "vue"), ("vite", "vite"), ("svelte", "svelte"),
                ("@nestjs/core", "nestjs"), ("express", "express"), ("prisma", "prisma"),
                ("jest", "jest"), ("tailwindcss", "tailwind"), ("three", "threejs"),
            ]:
                if key in deps and label not in stack:
                    stack.append(label)
            ports = [int(x) for x in re.findall(r"(?:-p|--port)[=\s]+(\d{2,5})", scripts)]
        except Exception:                                    # noqa: BLE001
            pass
    return stack, markers, ports



def _parse_compose_light(text):
    """Parser enxuto de docker-compose (sem PyYAML): services, containers, portas."""
    services, volumes, networks = [], [], []
    block, current = None, None
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" \t"))
        line = raw.strip()
        if indent == 0:
            block = line.rstrip(":").strip()
            current = None
            continue
        key_only = line.endswith(":") and ":" not in line[:-1]
        if block == "services" and indent <= 4 and key_only:
            current = {"name": line[:-1].strip(), "container_name": "", "image": "",
                       "build": "", "ports": []}
            services.append(current)
            continue
        if block == "services" and current is not None:
            m = re.match(r"container_name:\s*(.+)$", line)
            if m:
                current["container_name"] = m.group(1).strip().strip("'\"")
                continue
            m = re.match(r"image:\s*(.+)$", line)
            if m:
                current["image"] = m.group(1).strip().strip("'\"")
                continue
            m = re.match(r"build:\s*(.+)$", line)
            if m:
                current["build"] = m.group(1).strip().strip("'\"")
                continue
            m = re.match(r"-\s*['\"]?(\d{1,5}):(\d{1,5})", line)
            if m:
                current["ports"].append(int(m.group(1)))
                continue
        if block == "volumes" and indent <= 4 and key_only:
            volumes.append(line[:-1].strip())
        if block == "networks" and indent <= 4 and key_only:
            networks.append(line[:-1].strip())
    return {"services": services, "volumes": volumes, "networks": networks}


def _docker_containers():
    """Fotografia dos containers: estado, portas, mounts (caminhos do host) e labels."""
    out, err = _docker_json(["system", "df", "-v", "--format", "json"], timeout=60)
    if not out:
        return [], {}, err or "docker indisponível"
    try:
        data = json.loads(out.strip().splitlines()[0])
    except Exception as e:                                   # noqa: BLE001
        return [], {}, f"falha ao ler docker system df: {e}"
    containers = []
    for c in data.get("Containers") or []:
        labels = {}
        for pair in (c.get("Labels") or "").split(","):
            if "=" in pair:
                k, v = pair.split("=", 1)
                labels[k.strip()] = v.strip()
        mounts = [m for m in (c.get("Mounts") or "").split(",") if m.strip()]
        ports = []
        for chunk in (c.get("Ports") or "").split(","):
            m = re.search(r":(\d{1,5})->(\d{1,5})/", chunk.strip())
            if m:
                ports.append(int(m.group(1)))
        containers.append({
            "name": (c.get("Names") or "").lstrip("/"),
            "image": c.get("Image") or "",
            "state": c.get("State") or "",
            "status": c.get("Status") or "",
            "ports": sorted(set(ports)),
            "ports_raw": c.get("Ports") or "",
            "mounts": mounts,
            "labels": labels,
            "compose_project": labels.get("com.docker.compose.project", ""),
            "compose_service": labels.get("com.docker.compose.service", ""),
            "working_dir": labels.get("com.docker.compose.project.working_dir", ""),
            "size": c.get("Size") or "",
            "size_bytes": _parse_size((c.get("Size") or "").split("(")[0]),
            "running_for": c.get("RunningFor") or "",
            "created_at": c.get("CreatedAt") or "",
            "networks": [n for n in (c.get("Networks") or "").split(",") if n.strip()],
            "local_volumes": int(c.get("LocalVolumes") or 0),
        })
    return containers, data, ""


def _project_size(path):
    """Tamanho do código (exclui dependências pesadas) via `du`.

    `du` retorna código != 0 quando algum subdiretório é ilegível (ex.: data/
    do postgres dentro do compose) — mesmo assim o total parcial é útil.
    """
    _ok, out, _err = _run(["du", "-sb", "--exclude=node_modules", "--exclude=.git",
                           "--exclude=.next", "--exclude=dist", "--exclude=build",
                           "--exclude=__pycache__", "--exclude=.venv", str(path)],
                          timeout=12)
    if out.strip():
        try:
            return int(out.split()[0])
        except (ValueError, IndexError):
            return 0
    return 0


def _last_activity(path, names):
    """mtime mais recente entre os arquivos relevantes (varredura limitada)."""
    newest = 0.0
    seen = 0
    for e_name in names:
        p = path / e_name
        try:
            if p.is_file():
                newest = max(newest, p.stat().st_mtime)
        except OSError:
            continue
    for sub, _depth, entries in _iter_dirs(root=path, budget=2.5, max_depth=3):
        for e in entries:
            if e.name in NOISE_DIRS or e.name.startswith("."):
                continue
            try:
                if e.is_file(follow_symlinks=False):
                    newest = max(newest, e.stat().st_mtime)
                    seen += 1
                    if seen > 1500:
                        return newest
            except OSError:
                continue
    return newest


def _age_label(ts):
    if not ts:
        return "--"
    delta = max(0, time.time() - float(ts))
    if delta < 3600:
        return f"há {int(delta // 60)} min"
    if delta < 86400:
        return f"há {int(delta // 3600)} h"
    if delta < 86400 * 30:
        return f"há {int(delta // 86400)} d"
    return f"há {int(delta // (86400 * 30))} meses"



def _load_catalog():
    """Catálogo atual do portal público (projects.json)."""
    try:
        if PROJECTS_F.exists():
            data = json.loads(PROJECTS_F.read_text())
            return data if isinstance(data, list) else []
    except Exception:                                        # noqa: BLE001
        pass
    return []


def _match_catalog(project, catalog, deploy_apps):
    """Descobre se o projeto já está integrado ao HomeHub (portal ou Deploy Center)."""
    npath = _norm(project["name"])
    ports = {str(p) for p in project.get("ports") or []}
    for entry in catalog:
        url = str(entry.get("url") or "")
        url_ports = set(re.findall(r":(\d{2,5})", url))
        if _similar(project["name"], entry.get("name")) \
           or _similar(project["name"], entry.get("slug")) \
           or _norm(entry.get("source_path")) == _norm(project["path"]) \
           or (url_ports and url_ports & ports):
            return {"integrated": True, "where": "Portal Público",
                    "entry": entry.get("name"), "url": url}
    for app in deploy_apps:
        cport = str(app.get("port") or "")
        if _similar(project["name"], app.get("name")) or (cport and cport in ports):
            return {"integrated": True, "where": "Deploy Center",
                    "entry": app.get("name"),
                    "url": f"http://{os.environ.get('HOST_IP', 'localhost')}:{cport}"}
    return {"integrated": False, "where": "", "entry": "", "url": ""}


def _scan_projects(containers, deploy_apps, catalog):
    """Percorre a home e monta a ficha de cada projeto encontrado."""
    host_root = _host_root()
    # Artefatos internos do próprio HomeHub não são "projetos em desenvolvimento".
    skip_prefixes = []
    for dest, src in _mount_map():
        if dest == str(APP_DIR) and src.startswith(_host_root() + "/"):
            rel = src[len(_host_root()) + 1:]
            base = _scan_root() / rel
            skip_prefixes = [str(base / name) for name in
                             ("uploads", "backups", "pre-sync-20260902")]
            break
    found = []
    for path, depth, entries in _iter_dirs():
        names = [e.name for e in entries]
        if _looks_vendored(path.name, names):
            continue
        if skip_prefixes and str(path).startswith(tuple(skip_prefixes)):
            continue
        stack, markers, declared_ports = _detect_stack(path, names)
        if not markers:
            continue
        host_path = to_host_path(path)
        if host_path == host_root:
            continue
        compose = None
        for cname in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"):
            cf = path / cname
            if cf.exists():
                try:
                    compose = _parse_compose_light(cf.read_text(errors="ignore"))
                    compose["file"] = cname
                except Exception:                            # noqa: BLE001
                    compose = None
                break
        ports = set(declared_ports)
        if compose:
            for svc in compose["services"]:
                ports.update(svc["ports"])
        env_ports = set()
        for envname in (".env", ".env.local", ".env.example"):
            ef = path / envname
            if ef.exists():
                try:
                    env_ports.update(int(x) for x in
                                     re.findall(r"(?m)^\s*PORT\s*=\s*(\d{2,5})",
                                                ef.read_text(errors="ignore")))
                except Exception:                            # noqa: BLE001
                    pass
        ports.update(env_ports)
        activity = _last_activity(path, names)
        git = _git_info(path) if ".git" in names else None
        if git and git.get("last_commit_at"):
            activity = max(activity or 0, float(git["last_commit_at"]))
        size = _project_size(path)
        parent = ""
        for other in found:
            op = other["path"]
            if host_path.startswith(op + "/") and len(op) > len(parent):
                parent = other["name"]
        found.append({
            "name": path.name,
            "path": host_path,
            "container_path": str(path),
            "depth": depth,
            "parent": parent,
            "stack": stack[:8],
            "markers": markers[:8],
            "size_bytes": size,
            "size": _fmt_bytes(size),
            "last_activity": activity or None,
            "last_activity_label": _age_label(activity),
            "git": git,
            "declared_ports": sorted(ports),
            "ports": sorted(ports),
            "compose": compose,
            "containers": [],
            "running_containers": [],
            "compose_not_running": [],
            "integration": {"integrated": False, "where": "", "entry": "", "url": ""},
            "notes": [],
        })
    return found


def _attach_containers(projects, containers):
    """Vincula cada container ao projeto certo.

    Prioridade: (1) nome do serviço compose / container == nome do projeto;
    (2) bind-mount que aponta para a pasta do projeto (mais específico vence);
    (3) working_dir do compose (vínculo fraco — só se nada acima casar).
    """
    host_root = _host_root()
    by_name = {}
    for p in projects:
        by_name.setdefault(_norm(p["name"]), []).append(p)
    by_path = sorted(projects, key=lambda p: len(p["path"]), reverse=True)

    def _pick(cands, score):
        best = None
        for m in cands:
            for p in by_path:                  # já ordenado do mais específico
                hp = p["path"]
                hit = (m == hp) if score in (3, 1) else m.startswith(hp + "/")
                if hit:
                    if best is None or len(hp) > len(best["path"]):
                        best = p
                    break
        return best

    for c in containers:
        best = None
        for key in (_norm(c.get("compose_service")), _norm(c.get("name"))):
            if key and key in by_name:
                best = max(by_name[key], key=lambda p: len(p["path"]))
                break
        if best is None:
            mounts = [m for m in c["mounts"]
                      if m and m != host_root and m != "/var/run/docker.sock"]
            best = _pick(mounts, 3) or _pick(mounts, 2)
        if best is None and c.get("working_dir"):
            best = _pick([c["working_dir"]], 1) or _pick([c["working_dir"]], 0)
        if best is None:
            continue
        best["containers"].append({
            "name": c["name"], "image": c["image"], "state": c["state"],
            "status": c["status"], "ports": c["ports"], "ports_raw": c["ports_raw"],
        })
        if c["state"] == "running":
            best["running_containers"].append(c["name"])
        best["ports"] = sorted(set(best["ports"]) | set(c["ports"]))


def _finalize_projects(projects, running_names, alive_ports, published_ports):
    """Compose parado + notas legíveis + status final de cada projeto."""
    infra_names = {"homehub-dashboard"}
    for p in projects:
        if p.get("compose"):
            for svc in p["compose"]["services"]:
                cname = svc.get("container_name") or ""
                if cname and cname not in running_names:
                    p["compose_not_running"].append({
                        "service": svc["name"], "container_name": cname,
                        "image": svc.get("image") or ("build local" if svc.get("build") else ""),
                    })
        # Infra do próprio HomeHub (containers homeserver-* / homehub-dashboard)
        p["infra"] = any(c["name"] in infra_names or c["name"].startswith("homeserver-")
                         for c in p["containers"])
        notes = []
        if p["running_containers"]:
            notes.append("Em Docker: " + ", ".join(p["running_containers"][:6])
                         + ("…" if len(p["running_containers"]) > 6 else ""))
        elif p["containers"]:
            notes.append("Container parado: " + ", ".join(c["name"] for c in p["containers"]))
        if p["compose_not_running"]:
            notes.append("Compose define e NÃO roda: "
                         + ", ".join(s["container_name"] for s in p["compose_not_running"]))
        # Porta viva que NENHUM container publica = processo solto no host
        live = sorted({port for port in p["ports"]
                       if port in alive_ports and port not in published_ports})
        if live:
            notes.append("Porta viva fora do Docker: " + ", ".join(str(x) for x in live))
        git = p.get("git") or {}
        if git.get("branch"):
            extra = f" · {git['dirty']} sem commit" if git.get("dirty") else ""
            notes.append(f"git {git['branch']}{extra}")
        if not p["integration"]["integrated"] and not p["infra"]:
            notes.append("Fora do HomeHub (não aparece no portal)")
        p["notes"] = notes
        p["status"] = ("running" if p["running_containers"]
                       else ("stopped" if p["containers"] else "idle"))


def _host_listeners():
    """Portas TCP em LISTEN no HOST, vistas de verdade.

    Um container efêmero com `--network host` lê /proc/net/tcp{,6} do host
    (sondar de dentro da bridge do HomeHub só enxerga parte das portas).
    Fontes em ordem de preferência: python:3.11-slim (script host_listen.py)
    → alpine + busybox netstat → sondagem TCP (último recurso).
    """
    dash_src = ""
    for dest, src in _mount_map():
        if dest == str(APP_DIR):
            dash_src = src
            break
    ok, out, err = _run(["docker", "run", "--rm", "--network", "host", "--pid", "host",
                         "-v", f"{dash_src or APP_DIR}:/radar:ro", "python:3.11-slim",
                         "python", "/radar/host_listen.py"], timeout=120)
    if out:
        try:
            data = json.loads(out.strip().splitlines()[-1])
            listeners = data.get("listeners") if isinstance(data, dict) else data
            if isinstance(listeners, list) and listeners:
                _cache["host_interfaces"] = (data.get("interfaces") or {}) \
                    if isinstance(data, dict) else {}
                _cache["host_interfaces_ts"] = time.time()
                return listeners, "", "netns-python"
        except Exception as e:                              # noqa: BLE001
            err = f"host_listen.py: {e}"
    ok2, out2, _err2 = _run(["docker", "run", "--rm", "--network", "host", "--pid", "host",
                             "alpine:latest", "netstat", "-tln"], timeout=90)
    if out2:
        found = {}
        for line in out2.splitlines():
            parts = line.split()
            if len(parts) < 4 or parts[0] != "tcp":
                continue
            local = parts[3]
            try:
                port = int(local.rsplit(":", 1)[1])
            except (ValueError, IndexError):
                continue
            entry = found.setdefault(port, {"port": port, "addrs": set()})
            entry["addrs"].add(local.rsplit(":", 1)[0])
        if found:
            data = [{"port": p, "addrs": sorted(v["addrs"])}
                    for p, v in sorted(found.items())]
            return data, "", "netns-netstat"
    return [], (err or ""), "tcp-probe"


def _host_services(containers, projects):
    """Portas vivas no host: publicadas por container vs. processos soltos."""
    known = _load_known_services()
    published = {}
    for c in containers:
        for port in c["ports"]:
            published.setdefault(port, []).append(c["name"])
    listeners, lerr, method = _host_listeners()
    if listeners:
        alive_ports = {l["port"]: l.get("addrs") or [] for l in listeners}
    else:
        host = _probe_host()
        candidates = set(DEFAULT_PROBE_PORTS) | set(published)
        for pr in projects:
            candidates.update(pr.get("ports") or [])
        candidates = sorted({int(p) for p in candidates if 1 <= int(p) <= 65535})
        alive = {}
        if candidates:
            with ThreadPoolExecutor(max_workers=min(32, len(candidates))) as ex:
                alive = dict(zip(candidates,
                                 ex.map(lambda p: _port_open(host, p), candidates)))
        alive_ports = {p: [] for p, is_up in alive.items() if is_up}
    services = []
    for port in sorted(alive_ports):
        addrs = alive_ports[port] or []
        owners = published.get(port) or []
        svc = {
            "port": port,
            "alive": True,
            "origin": "docker" if owners else "host",
            "published_by": owners,
            "addrs": addrs,
            "loopback_only": bool(addrs) and all(a.startswith("127.") for a in addrs),
            "system": port in {22, 53, 631, 5353, 111},
            "label": known.get(str(port), ""),
            "method": method,
            "http": {},
        }
        if not owners and not svc["system"] and not svc["loopback_only"]:
            svc["http"] = _http_identify(_probe_host(), port)
            if not svc["label"]:
                svc["label"] = (svc["http"].get("http_title")
                                or svc["http"].get("http_server") or "")
        if not svc["label"]:
            if owners:
                svc["label"] = "container: " + ", ".join(owners)
            elif svc["system"]:
                svc["label"] = "serviço do sistema"
            else:
                svc["label"] = "processo no host (fora do Docker)"
        services.append(svc)
    return services, set(alive_ports), lerr, method


def _loose_files():
    """Artefatos soltos na raiz da home (scripts, logs, binários, pacotes)."""
    exts = {".py", ".sh", ".log", ".deb", ".yml", ".yaml", ".html", ".json",
            ".zip", ".tar", ".gz", ".exe", ".bak", ".txt"}
    out = []
    try:
        with os.scandir(_scan_root()) as it:
            entries = list(it)
    except OSError:
        return out
    for e in entries:
        try:
            if not e.is_file(follow_symlinks=False):
                continue
            st = e.stat()
        except OSError:
            continue
        ext = os.path.splitext(e.name)[1].lower()
        big = st.st_size >= 10 * 1024 * 1024
        if ext not in exts and not big:
            continue
        out.append({
            "name": e.name,
            "path": to_host_path(Path(e.path)),
            "size_bytes": st.st_size,
            "size": _fmt_bytes(st.st_size),
            "modified": st.st_mtime,
            "modified_label": _age_label(st.st_mtime),
            "kind": (ext.lstrip(".") or "binário").upper(),
        })
    out.sort(key=lambda x: x["size_bytes"], reverse=True)
    return out[:30]



# ════════════════════════════════════════════════════════════════════════════
# API PÚBLICA DO MÓDULO — VARREDURA DE PROJETOS
# ════════════════════════════════════════════════════════════════════════════
def scan_workspace(force=False):
    """Retorna o panorama completo: projetos do host + serviços + integração."""
    if not force and _cache.get("workspace") \
            and time.time() - _cache.get("workspace_ts", 0) < _CACHE_TTL:
        return _cache["workspace"]
    started = time.time()
    containers, _df, docker_error = _docker_containers()
    deploy_apps, _versions = _deploy_db_rows()
    catalog = _load_catalog()

    projects = _scan_projects(containers, deploy_apps, catalog)
    _attach_containers(projects, containers)
    services, alive_ports, listeners_err, listeners_method = _host_services(containers, projects)
    running_names = {c["name"] for c in containers if c["state"] == "running"}
    published_ports = {p for c in containers for p in c["ports"]}
    for p in projects:
        p["integration"] = _match_catalog(p, catalog, deploy_apps)
    _finalize_projects(projects, running_names, set(alive_ports), published_ports)
    loose = _loose_files()

    projects.sort(key=lambda p: (p["infra"], p["integration"]["integrated"],
                                 -(p["last_activity"] or 0)))
    integrated = sum(1 for p in projects if p["integration"]["integrated"])
    infra = sum(1 for p in projects if p["infra"])
    outside = [p for p in projects if not p["infra"]]
    result = {
        "ok": True,
        "generated_at": time.time(),
        "duration_ms": int((time.time() - started) * 1000),
        "root": _host_root(),
        "docker_error": docker_error,
        "listeners_method": listeners_method,
        "listeners_error": listeners_err,
        "host_ip": _host_ip(),
        "projects": projects,
        "host_services": services,
        "loose_files": loose,
        "catalog": catalog,
        "deploy_apps": [{
            "id": a.get("id"), "name": a.get("name"), "stack": a.get("stack"),
            "port": a.get("port"), "container_name": a.get("container_name"),
            "status": a.get("status"), "current_version": a.get("current_version"),
        } for a in deploy_apps],
        "containers": containers,
        "summary": {
            "projects": len(projects),
            "integrated": integrated,
            "not_integrated": len(outside) - sum(1 for p in outside
                                                 if p["integration"]["integrated"]),
            "infra": infra,
            "outside_homehub": len(outside),
            "running_in_docker": sum(1 for p in projects if p["running_containers"]),
            "idle": sum(1 for p in projects if p["status"] == "idle"),
            "host_only_services": sum(1 for s in services if s["origin"] == "host"),
            "docker_services": sum(1 for s in services if s["origin"] == "docker"),
            "loose_files": len(loose),
            "loose_bytes": sum(f["size_bytes"] for f in loose),
            "compose_not_running": sum(len(p["compose_not_running"]) for p in projects),
            "uncommitted": sum((p.get("git") or {}).get("dirty") or 0 for p in projects),
        },
    }
    _cache["workspace"] = result
    _cache["workspace_ts"] = time.time()
    return result


def track_project(payload, save):
    """Integra um projeto externo ao catálogo do portal público.

    `save(projects_list)` é a função save_projects() do app.py — assim o Radar
    reutiliza exatamente o mesmo arquivo/formato usado pelo Portal Público.
    """
    import secrets
    data = payload or {}
    path = str(data.get("path") or "").strip()
    if not path:
        return {"success": False, "error": "Caminho do projeto é obrigatório."}
    scan = scan_workspace()
    match = next((p for p in scan["projects"]
                  if p["path"] == path or p["container_path"] == path), None)
    if not match:
        return {"success": False,
                "error": "Projeto não encontrado na varredura. Reescaneie e tente novamente."}
    if match["integration"]["integrated"]:
        return {"success": False,
                "error": f"Já integrado em: {match['integration']['where']} "
                         f"({match['integration']['entry']})"}

    host_ip = _host_ip()
    ports = match.get("ports") or []
    url = str(data.get("url") or "").strip()
    if not url:
        url = f"http://{host_ip}:{ports[0]}" if ports else ""
    name = str(data.get("name") or match["name"]).strip()
    category = str(data.get("category") or "Desenvolvimento").strip()
    projects = _load_catalog()
    entry = {
        "id": f"proj-{secrets.token_hex(4)}",
        "slug": re.sub(r"[^a-z0-9-]+", "-", name.lower()).strip("-") or match["name"],
        "name": name,
        "description": str(data.get("description")
                           or f"Projeto em desenvolvimento em {match['path']}"),
        "icon": str(data.get("icon") or "🛰️"),
        "category": category,
        "badge": category,
        "url": url,
        "status": "online" if match["running_containers"] else "maintenance",
        "featured": bool(data.get("featured")),
        "published": bool(data.get("published", True)),
        "source_path": match["path"],
        "stack": match["stack"],
        "tracked_by_radar": True,
        "tags": ["Radar", category],
    }
    projects.append(entry)
    save(projects)
    _cache.pop("workspace", None)
    _cache.pop("workspace_ts", None)
    return {"success": True, "message": f"'{name}' integrado ao portal público.",
            "entry": entry}



# ════════════════════════════════════════════════════════════════════════════
# API PÚBLICA DO MÓDULO — AUDITORIA DOCKER
# ════════════════════════════════════════════════════════════════════════════
_FROM_RE = re.compile(r"(?im)^\s*FROM\s+(--platform=\S+\s+)?([^\s]+)")


def _base_images():
    """Imagens-base usadas nos Dockerfiles do servidor (não podem ser apagadas)."""
    if _cache.get("base_images") and time.time() - _cache.get("base_images_ts", 0) < 300:
        return _cache["base_images"]
    refs = set()
    for path, _depth, entries in _iter_dirs(budget=6):
        names = [e.name for e in entries]
        for fn in ("Dockerfile", "Dockerfile.dev", "Dockerfile.prod"):
            if fn not in names:
                continue
            try:
                text = (path / fn).read_text(errors="ignore")
            except OSError:
                continue
            for m in _FROM_RE.finditer(text):
                ref = m.group(2).strip()
                if not ref or ref.lower() in ("scratch", "builder", "deps", "runner", "base"):
                    continue
                refs.add(ref.lower())
                if ":" not in ref:
                    refs.add(ref.lower() + ":latest")
    _cache["base_images"] = refs
    _cache["base_images_ts"] = time.time()
    return refs


def _networks_state():
    """Redes Docker e quantos containers cada uma ancora."""
    out, err = _docker_json(["network", "ls", "--format", "{{json .}}"], timeout=15)
    if not out:
        return [], err or ""
    nets = []
    for line in out.strip().splitlines():
        try:
            n = json.loads(line)
        except Exception:                                    # noqa: BLE001
            continue
        name = n.get("Name") or ""
        count = None
        if n.get("Scope") == "local" and name not in ("bridge", "host", "none"):
            o2, _e2 = _docker_json(["network", "inspect", name,
                                    "--format", "{{len .Containers}}"], timeout=10)
            if o2 is not None:
                try:
                    count = int(o2.strip())
                except ValueError:
                    count = None
        nets.append({
            "name": name, "id": (n.get("ID") or "")[:12], "driver": n.get("Driver") or "",
            "scope": n.get("Scope") or "", "containers": count,
            "state": ("padrão" if name in ("bridge", "host", "none")
                      else ("em uso" if count else "ociosa" if count == 0 else "desconhecido")),
        })
    return nets, ""


def docker_audit(force=False):
    """Separar o que o Docker está USANDO do que está OCioso + recomendações."""
    if not force and _cache.get("docker_audit") \
            and time.time() - _cache.get("docker_audit_ts", 0) < _CACHE_TTL:
        return _cache["docker_audit"]
    started = time.time()
    containers, df, err = _docker_containers()
    if not df:
        return {"ok": False, "error": err, "generated_at": time.time()}

    deploy_apps, versions = _deploy_db_rows()
    rollback_tags, current_tags = {}, set()
    for v in versions:
        tag = (v.get("image_tag") or "").strip()
        if not tag:
            continue
        rollback_tags.setdefault(tag, []).append(v.get("app_id"))
        if v.get("is_current"):
            current_tags.add(tag)
    app_names = {a.get("id"): a.get("name") for a in deploy_apps}
    base_images = _base_images()
    running_names = {c["name"] for c in containers if c["state"] == "running"}

    used_by = {}
    for c in containers:
        used_by.setdefault(c["image"], []).append(c["name"])

    images = []
    for img in df.get("Images") or []:
        repo = (img.get("Repository") or "").strip()
        tag = (img.get("Tag") or "").strip()
        dangling = repo in ("<none>", "<untagged>", "") or tag in ("<none>", "<untagged>", "")
        full = "" if dangling else f"{repo}:{tag}"
        users = []
        if not dangling:
            users = used_by.get(full) or used_by.get(repo) or []
        running_users = [u for u in users if u in running_names]
        unique = _parse_size(img.get("UniqueSize"))
        total = _parse_size(img.get("Size"))
        if running_users:
            state, safe, note = "em_uso", False, "Usada por: " + ", ".join(running_users)
        elif users:
            state, safe, note = "container_parado", False, \
                "Só há container PARADO usando: " + ", ".join(users)
        elif dangling:
            state, safe, note = "dangling", True, "Camada órfã de build antigo (sem tag)"
        elif full in current_tags:
            state, safe, note = "deploy_center", False, \
                "Versão atual de: " + ", ".join(
                    str(app_names.get(a, a)) for a in rollback_tags.get(full, []))
        elif full in rollback_tags:
            state, safe, note = "rollback", False, \
                "Versão anterior (rollback) de: " + ", ".join(
                    str(app_names.get(a, a)) for a in rollback_tags.get(full, []))
        elif repo.lower() in base_images or full.lower() in base_images:
            state, safe, note = "base_build", False, "Imagem-base de Dockerfile do servidor"
        else:
            state, safe, note = "ociosa", True, "Nenhum container (nem parado) usa esta imagem"
        images.append({
            "repository": repo, "tag": tag, "name": full or "<sem tag>",
            "id": (img.get("ID") or "").replace("sha256:", "")[:12],
            "size": img.get("Size") or "", "size_bytes": total,
            "unique_size": img.get("UniqueSize") or "", "unique_size_bytes": unique,
            "shared_size": img.get("SharedSize") or "",
            "created_since": img.get("CreatedSince") or "",
            "containers": int(img.get("Containers") or 0),
            "used_by": users, "state": state, "safe_to_remove": safe, "note": note,
        })


    # ── Containers ────────────────────────────────────────────────────────────
    cont_out = []
    for c in containers:
        cont_out.append({
            "name": c["name"], "image": c["image"], "state": c["state"],
            "status": c["status"], "ports": c["ports"], "ports_raw": c["ports_raw"],
            "size": c["size"], "size_bytes": c["size_bytes"],
            "compose_project": c["compose_project"], "compose_service": c["compose_service"],
            "running_for": c["running_for"], "created_at": c["created_at"],
            "networks": c["networks"], "local_volumes": c["local_volumes"],
            "mounts": c["mounts"][:6],
            "restart_policy": c["labels"].get("com.docker.compose.service", ""),
        })
    stopped = [c for c in cont_out if c["state"] != "running"]

    # ── Volumes ───────────────────────────────────────────────────────────────
    volumes = []
    for v in df.get("Volumes") or []:
        try:
            links = int(v.get("Links") or 0)
        except (TypeError, ValueError):
            links = 0
        labels = {}
        for pair in (v.get("Labels") or "").split(","):
            if "=" in pair:
                k, val = pair.split("=", 1)
                labels[k.strip()] = val.strip()
        size = _parse_size(v.get("Size"))
        volumes.append({
            "name": v.get("Name") or "", "driver": v.get("Driver") or "",
            "size": v.get("Size") or "", "size_bytes": size,
            "mountpoint": v.get("Mountpoint") or "", "links": links,
            "project": labels.get("com.docker.compose.project", ""),
            "state": "em_uso" if links else "ocioso",
        })

    networks, net_err = _networks_state()

    # ── Build cache ───────────────────────────────────────────────────────────
    cache_entries = df.get("BuildCache") or []
    cache_total = sum(_parse_size(e.get("Size")) for e in cache_entries)
    cache_in_use = sum(1 for e in cache_entries if _as_bool(e.get("InUse")))
    # Entradas livres de verdade: não estão em uso nem são compartilhadas com
    # alguém em uso (é assim que o Docker calcula o reclaimable).
    cache_unused = sum(_parse_size(e.get("Size")) for e in cache_entries
                       if not _as_bool(e.get("InUse")) and not _as_bool(e.get("Shared")))
    cache_free_all = sum(_parse_size(e.get("Size")) for e in cache_entries
                         if not _as_bool(e.get("InUse")))
    # Números oficiais do `docker system df` prevalecem (batem com o CLI).
    dfsum = _df_summary()
    bc_rep = dfsum.get("Build Cache") or {}
    if bc_rep.get("reclaimable_bytes"):
        cache_unused = bc_rep["reclaimable_bytes"]
    if bc_rep.get("size_bytes"):
        cache_total = bc_rep["size_bytes"]
    stale = sorted((e for e in cache_entries if not _as_bool(e.get("InUse"))),
                   key=lambda e: e.get("LastUsedSince") or "")

    # ── Totais ────────────────────────────────────────────────────────────────
    unused_imgs = [i for i in images if i["safe_to_remove"]]
    reclaim_imgs = sum(i["unique_size_bytes"] for i in unused_imgs)
    reclaim_conts = sum(c["size_bytes"] for c in stopped)
    reclaim_vols = sum(v["size_bytes"] for v in volumes if v["state"] == "ocioso")
    images_total = sum(i["size_bytes"] for i in images)
    summary = {
        "images": {
            "total": len(images),
            "in_use": sum(1 for i in images if i["state"] == "em_uso"),
            "stopped_only": sum(1 for i in images if i["state"] == "container_parado"),
            "dangling": sum(1 for i in images if i["state"] == "dangling"),
            "rollback": sum(1 for i in images if i["state"] == "rollback"),
            "base_build": sum(1 for i in images if i["state"] == "base_build"),
            "deploy_center": sum(1 for i in images if i["state"] == "deploy_center"),
            "unused": len(unused_imgs),
            "size": _fmt_bytes(images_total), "size_bytes": images_total,
            "reclaimable": _fmt_bytes(reclaim_imgs), "reclaimable_bytes": reclaim_imgs,
        },
        "containers": {
            "total": len(cont_out),
            "running": sum(1 for c in cont_out if c["state"] == "running"),
            "stopped": len(stopped),
            "reclaimable": _fmt_bytes(reclaim_conts), "reclaimable_bytes": reclaim_conts,
        },
        "volumes": {
            "total": len(volumes),
            "in_use": sum(1 for v in volumes if v["state"] == "em_uso"),
            "unused": sum(1 for v in volumes if v["state"] == "ocioso"),
            "size_bytes": sum(v["size_bytes"] for v in volumes),
            "reclaimable": _fmt_bytes(reclaim_vols), "reclaimable_bytes": reclaim_vols,
        },
        "networks": {
            "total": len(networks),
            "unused": sum(1 for n in networks if n["state"] == "ociosa"),
            "reclaimable_bytes": 0, "reclaimable": "0 B",
        },
        "build_cache": {
            "entries": len(cache_entries), "in_use": cache_in_use,
            "unused": len(cache_entries) - cache_in_use,
            "size": _fmt_bytes(cache_total), "size_bytes": cache_total,
            "reclaimable": _fmt_bytes(cache_unused), "reclaimable_bytes": cache_unused,
            "free_if_all_pruned": _fmt_bytes(cache_free_all),
            "free_if_all_pruned_bytes": cache_free_all,
            "reported": bc_rep.get("reclaimable") or "",
            "oldest_unused": (stale[0].get("LastUsedSince") if stale else ""),
        },
        "total_size_bytes": images_total + cache_total + reclaim_conts,
        "total_reclaimable_bytes": reclaim_imgs + reclaim_conts + reclaim_vols + cache_unused,
    }
    summary["total_size"] = _fmt_bytes(summary["total_size_bytes"])
    summary["total_reclaimable"] = _fmt_bytes(summary["total_reclaimable_bytes"])

    # ── Recomendações (ordenadas por espaço recuperável) ──────────────────────
    recs = []
    if cache_unused:
        recs.append({
            "scope": "build_cache",
            "title": "Limpar cache de build do BuildKit",
            "detail": (f"{len(cache_entries) - cache_in_use} entradas de cache sem uso — "
                       "é o maior desperdício do servidor. Efeito colateral: o próximo "
                       "build (Deploy Center / compose) fica mais lento na 1ª vez."),
            "reclaimable_bytes": cache_unused, "reclaimable": _fmt_bytes(cache_unused),
            "command": "docker builder prune -f", "risk": "baixo",
        })
    dangling = [i for i in unused_imgs if i["state"] == "dangling"]
    idle = [i for i in unused_imgs if i["state"] == "ociosa"]
    if dangling:
        recs.append({
            "scope": "dangling_images",
            "title": f"Remover {len(dangling)} imagem(ns) dangling (<none>)",
            "detail": "Camadas órfãs de builds antigos, sem tag e sem container. "
                      "Remoção 100% segura.",
            "reclaimable_bytes": sum(i["unique_size_bytes"] for i in dangling),
            "reclaimable": _fmt_bytes(sum(i["unique_size_bytes"] for i in dangling)),
            "command": "docker image prune -f", "risk": "baixo",
        })
    if idle:
        recs.append({
            "scope": "unused_images",
            "title": f"Remover {len(idle)} imagem(ns) sem nenhum container",
            "detail": "Nenhum container (nem parado) usa: "
                      + ", ".join(i["name"] for i in idle[:8])
                      + ("…" if len(idle) > 8 else "")
                      + ". Imagens de rollback e imagens-base de Dockerfile são "
                        "excluídas desta lista automaticamente.",
            "reclaimable_bytes": sum(i["unique_size_bytes"] for i in idle),
            "reclaimable": _fmt_bytes(sum(i["unique_size_bytes"] for i in idle)),
            "command": "docker rmi " + " ".join(i["name"] for i in idle),
            "risk": "médio",
        })
    if stopped:
        recs.append({
            "scope": "stopped_containers",
            "title": f"Remover {len(stopped)} container(es) parado(s)",
            "detail": "Containers em estado exited: " + ", ".join(c["name"] for c in stopped)
                      + ". A camada gravável é descartada (volumes são preservados).",
            "reclaimable_bytes": reclaim_conts, "reclaimable": _fmt_bytes(reclaim_conts),
            "command": "docker container prune -f", "risk": "baixo",
        })
    unused_nets = [n for n in networks if n["state"] == "ociosa"]
    if unused_nets:
        recs.append({
            "scope": "unused_networks",
            "title": f"Remover {len(unused_nets)} rede(s) sem containers",
            "detail": "Redes bridge órfãs: " + ", ".join(n["name"] for n in unused_nets) + ".",
            "reclaimable_bytes": 0, "reclaimable": "0 B",
            "command": "docker network prune -f", "risk": "baixo",
        })
    unused_vols = [v for v in volumes if v["state"] == "ocioso"]
    if unused_vols:
        recs.append({
            "scope": "unused_volumes",
            "title": f"Remover {len(unused_vols)} volume(s) sem uso",
            "detail": "ATENÇÃO: volume órfão pode conter DADOS de banco: "
                      + ", ".join(f"{v['name']} ({v['size']})" for v in unused_vols)
                      + ". Só execute após confirmar backup.",
            "reclaimable_bytes": reclaim_vols, "reclaimable": _fmt_bytes(reclaim_vols),
            "command": "docker volume prune -f", "risk": "alto",
        })
    recs.sort(key=lambda r: r["reclaimable_bytes"], reverse=True)

    result = {
        "ok": True,
        "generated_at": time.time(),
        "duration_ms": int((time.time() - started) * 1000),
        "docker_error": err or net_err,
        "summary": summary,
        "images": sorted(images, key=lambda i: (i["state"] != "ociosa",
                                                i["state"] != "dangling",
                                                -i["unique_size_bytes"])),
        "containers": sorted(cont_out, key=lambda c: (c["state"] == "running",
                                                      -c["size_bytes"])),
        "stopped_containers": stopped,
        "volumes": volumes,
        "networks": networks,
        "build_cache": summary["build_cache"],
        "recommendations": recs,
        "base_images": sorted(base_images)[:40],
    }
    _cache["docker_audit"] = result
    _cache["docker_audit_ts"] = time.time()
    return result


# ════════════════════════════════════════════════════════════════════════════
# LIMPEZA EXECUTÁVEL (apenas o que o administrador marcar no painel)
# ════════════════════════════════════════════════════════════════════════════
PRUNE_SCOPES = {
    "stopped_containers": {"label": "Containers parados", "risk": "baixo",
                           "cmd": ["docker", "container", "prune", "-f"]},
    "dangling_images":    {"label": "Imagens dangling", "risk": "baixo",
                           "cmd": ["docker", "image", "prune", "-f"]},
    "build_cache":        {"label": "Cache de build (não usado)", "risk": "baixo",
                           "cmd": ["docker", "builder", "prune", "-f"]},
    "build_cache_all":    {"label": "Cache de build (todo o não usado)", "risk": "médio",
                           "cmd": ["docker", "builder", "prune", "-a", "-f"]},
    "unused_networks":    {"label": "Redes órfãs", "risk": "baixo",
                           "cmd": ["docker", "network", "prune", "-f"]},
    "unused_images":      {"label": "Imagens sem container", "risk": "médio",
                           "cmd": None},   # montado dinamicamente via docker rmi
    "unused_volumes":     {"label": "Volumes órfãos (DADOS!)", "risk": "alto",
                           "cmd": ["docker", "volume", "prune", "-f"]},
}
_RECLAIMED_RE = re.compile(r"Total reclaimed space:\s*([^\n]+)")


def run_prune(scopes, confirm=""):
    """Executa a limpeza dos escopos escolhidos e devolve o espaço recuperado."""
    scopes = [s for s in (scopes or []) if s in PRUNE_SCOPES]
    if not scopes:
        return {"success": False, "error": "Nenhum escopo de limpeza válido."}
    risky = [s for s in scopes if PRUNE_SCOPES[s]["risk"] == "alto"]
    if risky and str(confirm).strip().lower() not in ("limpar", "confirmar", "ok", "yes"):
        return {"success": False,
                "error": f"Escopo de risco ({', '.join(risky)}) exige "
                         f'confirm="limpar".'}
    audit = docker_audit(force=True)
    results, total = [], 0
    for scope in scopes:
        spec = PRUNE_SCOPES[scope]
        cmd = spec["cmd"]
        if scope == "unused_images":
            targets = [i["name"] for i in audit.get("images", [])
                       if i["state"] == "ociosa" and i["safe_to_remove"]]
            if not targets:
                results.append({"scope": scope, "label": spec["label"], "ok": True,
                                "reclaimed": "0 B", "reclaimed_bytes": 0,
                                "output": "Nada a remover."})
                continue
            cmd = ["docker", "rmi"] + targets
        ok, out, err = _run(cmd, timeout=600)
        text = (out or "") + (("\n" + err) if err else "")
        reclaimed = 0
        m = _RECLAIMED_RE.search(text)
        if m:
            reclaimed = _parse_size(m.group(1))
        elif not ok:
            # docker rmi não imprime "Total reclaimed space" — soma pelo audit
            if scope == "unused_images":
                reclaimed = sum(i["unique_size_bytes"] for i in audit.get("images", [])
                                if i["state"] == "ociosa" and i["safe_to_remove"])
        total += reclaimed
        results.append({
            "scope": scope, "label": spec["label"], "ok": ok,
            "command": " ".join(cmd), "reclaimed": _fmt_bytes(reclaimed),
            "reclaimed_bytes": reclaimed,
            "output": text.strip()[-1500:],
        })
    for key in ("docker_audit", "docker_audit_ts", "workspace", "workspace_ts"):
        _cache.pop(key, None)
    return {"success": True, "results": results,
            "total_reclaimed": _fmt_bytes(total), "total_reclaimed_bytes": total,
            "audit": docker_audit(force=True)}

