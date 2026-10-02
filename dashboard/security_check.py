"""
HomeHub Security Check Module
Audits the server and returns a list of security check results.
"""
import subprocess, os, json, shlex

def _run(cmd):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=20)
        return r.stdout.strip(), r.returncode
    except Exception as e:
        return str(e), -1

def _read_host_file(path):
    """Read 'path' from the Docker HOST via the mounted docker.sock.

    HomeHub runs as a container, so commands inside it inspect the container,
    not the server. This helper obtains the real host state by mounting the
    host file read-only into a scratch alpine container. Returns
    (contents, from_host|False).
    """
    try:
        cmd = (
            "docker run --rm "
            f"-v {shlex.quote(path)}:{shlex.quote(path)}:ro "
            f"alpine cat {shlex.quote(path)}"
        )
        out, code = _run(cmd)
        if code == 0 and out:
            return out, True
    except Exception:
        pass
    try:
        with open(path) as f:
            return f.read(), False
    except Exception:
        return "", False

def check_security():
    results = []

    # 1. Firewall  — checks the Docker HOST, not this container
    conf, conf_from_host = _read_host_file("/etc/ufw/ufw.conf")
    rules, _ = _read_host_file("/etc/ufw/user.rules")
    enabled = "ENABLED=yes" in conf
    has_rules = bool(rules.strip())
    if conf_from_host and enabled and has_rules:
        results.append({"id": "firewall", "name": "Firewall (ufw)", "status": "ok",
                        "description": "Firewall ufw está ativo no servidor host (ENABLED=yes com regras aplicadas).",
                        "action": None})
    elif conf_from_host and (enabled or conf):
        results.append({"id": "firewall", "name": "Firewall (ufw)", "status": "warning",
                        "description": "ufw instalado e habilitado no host, mas sem regras em /etc/ufw/user.rules.",
                        "action": "Revise as regras: sudo ufw status verbose"})
    else:
        # Fallback: não foi possível ler o host — procura o comando no container
        out, code = _run("ufw status 2>/dev/null")
        if "Status: active" in out:
            results.append({"id": "firewall", "name": "Firewall (ufw)", "status": "ok",
                            "description": "Firewall ufw está ativo e protegendo o servidor.", "action": None})
        elif code == 127 or not out:
            results.append({"id": "firewall", "name": "Firewall (ufw)", "status": "error",
                            "description": "Não foi possível confirmar o ufw do host pelo docker.sock e o comando ufw não existe neste container. Verifique manualmente no host: sudo ufw status.",
                            "action": "No host: sudo ufw status && sudo ufw enable"})
        else:
            results.append({"id": "firewall", "name": "Firewall (ufw)", "status": "warning",
                            "description": "ufw está instalado mas não está ativo.", "action": "Ativar firewall: sudo ufw enable"})

    # 2. Docker socket permissions
    try:
        stat = os.stat("/var/run/docker.sock")
        mode = oct(stat.st_mode)
        if mode.endswith("660") or mode.endswith("600"):
            results.append({"id": "docker_sock", "name": "Docker Socket", "status": "ok",
                            "description": "Docker socket tem permissões seguras (660).", "action": None})
        else:
            results.append({"id": "docker_sock", "name": "Docker Socket", "status": "warning",
                            "description": f"Docker socket tem permissões: {mode}. Verifique se está exposto demais.", "action": "Verifique: ls -la /var/run/docker.sock"})
    except Exception:
        results.append({"id": "docker_sock", "name": "Docker Socket", "status": "warning",
                        "description": "Não foi possível verificar o Docker socket.", "action": None})

    # 3. Privileged containers
    try:
        out, _ = _run("docker ps -q 2>/dev/null")
        container_ids = [c for c in out.split() if c]
        privileged = []
        for cid in container_ids:
            inspect_out, _ = _run(f"docker inspect {cid} --format '{{{{.Name}}}} {{{{.HostConfig.Privileged}}}}'")
            if "true" in inspect_out.lower():
                privileged.append(inspect_out.split()[0].lstrip("/"))
        if privileged:
            results.append({"id": "privileged_containers", "name": "Containers Privilegiados", "status": "warning",
                            "description": f"Containers rodando com --privileged: {', '.join(privileged)}. Isso concede acesso quase total ao host.", "action": "Revise a necessidade de --privileged. Remova se não for essencial."})
        else:
            results.append({"id": "privileged_containers", "name": "Containers Privilegiados", "status": "ok",
                            "description": "Nenhum container rodando com --privileged.", "action": None})
    except Exception as e:
        results.append({"id": "privileged_containers", "name": "Containers Privilegiados", "status": "warning",
                        "description": f"Não foi possível verificar: {e}", "action": None})

    # 4. Auth security - default password
    try:
        auth_file = "/app/auth.json"
        if os.path.exists(auth_file):
            with open(auth_file) as f:
                auth = json.load(f)
            if auth.get("is_default_password"):
                results.append({"id": "default_password", "name": "Senha Padrão", "status": "error",
                                "description": "A senha padrão de administrador ainda está em uso.", "action": "Altere a senha imediatamente em Usuários → Alterar Senha."})
            else:
                results.append({"id": "default_password", "name": "Senha Padrão", "status": "ok",
                                "description": "Senha de administrador personalizada configurada.", "action": None})
    except Exception:
        results.append({"id": "default_password", "name": "Senha Padrão", "status": "warning",
                        "description": "Não foi possível verificar a configuração de autenticação.", "action": None})

    # 5. Pending OS updates
    out, _ = _run("apt list --upgradable 2>/dev/null | wc -l")
    try:
        count = int(out.strip()) - 1  # subtract header line
        if count <= 0:
            results.append({"id": "os_updates", "name": "Atualizações do Sistema", "status": "ok",
                            "description": "Sistema operacional atualizado.", "action": None})
        elif count < 10:
            results.append({"id": "os_updates", "name": "Atualizações do Sistema", "status": "warning",
                            "description": f"{count} atualizações de sistema pendentes.", "action": "Execute: sudo apt update && sudo apt upgrade"})
        else:
            results.append({"id": "os_updates", "name": "Atualizações do Sistema", "status": "error",
                            "description": f"{count} atualizações pendentes. O sistema está desatualizado.", "action": "Execute: sudo apt update && sudo apt upgrade"})
    except Exception:
        results.append({"id": "os_updates", "name": "Atualizações do Sistema", "status": "warning",
                        "description": "Não foi possível verificar atualizações.", "action": None})

    # 6. Running process user
    uid = os.getuid()
    if uid == 0:
        results.append({"id": "root_process", "name": "Processo como root", "status": "warning",
                        "description": "O HomeHub roda como root dentro do container (padrão da imagem Python). "
                                       "O Docker socket do host (660 root:docker, gid do grupo 'docker') fica acessível "
                                       "pelo daemon. Mitigação recomendada: rodar com usuário dedicado não-root.",
                        "action": "Aplicar hardening: no serviço 'homehub' do docker-compose, adicione 'user: \"1000:973\"' "
                                  "(uid do host + gid do grupo docker) e recrie o container."})
    else:
        results.append({"id": "root_process", "name": "Processo como root", "status": "ok",
                        "description": f"HomeHub rodando como UID {uid} (não-root).", "action": None})

    # 7. HTTPS / Tunnel
    out, _ = _run("docker ps --filter name=ngrok --filter name=cloudflare --format '{{.Names}}' 2>/dev/null")
    tunnels = [t for t in out.split() if t]
    if tunnels:
        results.append({"id": "https", "name": "HTTPS / Tunnel", "status": "ok",
                        "description": f"Tunnels ativos: {', '.join(tunnels)}. Acesso externo via HTTPS.", "action": None})
    else:
        results.append({"id": "https", "name": "HTTPS / Tunnel", "status": "warning",
                        "description": "Nenhum tunnel (Ngrok/Cloudflare) detectado. Acesso externo pode ser sem HTTPS.", "action": "Configure um tunnel Ngrok ou Cloudflare para HTTPS."})

    # 8. Docker version
    out, _ = _run("docker --version 2>/dev/null")
    results.append({"id": "docker_version", "name": "Versão do Docker", "status": "ok",
                    "description": out or "Docker instalado.", "action": None})

    return results
