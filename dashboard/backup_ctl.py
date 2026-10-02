"""Backup jobs config (timezone America/Sao_Paulo). Stored next to the dashboard."""
from __future__ import annotations

import json
import re
import time
import uuid
from pathlib import Path

TZ_NAME = "America/Sao_Paulo"
CFG_NAME = "backup-jobs.json"
RUN_NAME = "backup-run.now"
STATUS_NAME = "backup-status.json"
COOKIE_REQ = "terabox-cookie.request"

DAY_NAMES = ["Dom", "Seg", "Ter", "Qua", "Qui", "Sex", "Sáb"]


def default_config():
    return {
        "timezone": TZ_NAME,
        "jobs": [
            {
                "id": "servidor",
                "name": "Servidor completo",
                "enabled": True,
                "kind": "restic-gdrive",
                "days": [0],
                "hour": 23,
                "minute": 0,
                "keep_weekly": 4,
                "keep_monthly": 3,
                "cloud": True,
            }
        ],
    }


def cfg_path(app_dir: Path) -> Path:
    return Path(app_dir) / CFG_NAME


def load_config(app_dir: Path) -> dict:
    path = cfg_path(app_dir)
    if not path.exists():
        cfg = default_config()
        save_config(app_dir, cfg)
        return cfg
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default_config()
    if not isinstance(data, dict):
        return default_config()
    data.setdefault("timezone", TZ_NAME)
    jobs = data.get("jobs")
    if not isinstance(jobs, list) or not jobs:
        data["jobs"] = default_config()["jobs"]
    return data


def save_config(app_dir: Path, cfg: dict) -> None:
    path = cfg_path(app_dir)
    text = json.dumps(cfg, indent=2, ensure_ascii=False)
    path.write_text(text + "\n", encoding="utf-8")


def _clean_job(raw: dict, existing_id: str | None = None) -> dict:
    name = str(raw.get("name") or "Backup").strip()[:80] or "Backup"
    days = raw.get("days") or []
    if isinstance(days, str):
        days = [int(x) for x in re.findall(r"\d", days)]
    clean_days = sorted({int(d) for d in days if str(d).isdigit() and 0 <= int(d) <= 6})
    if not clean_days:
        clean_days = [0]
    hour = int(raw.get("hour", 23))
    minute = int(raw.get("minute", 0))
    hour = max(0, min(23, hour))
    minute = max(0, min(59, minute))
    jid = existing_id or str(raw.get("id") or "").strip() or uuid.uuid4().hex[:10]
    if not re.match(r"^[a-zA-Z0-9_-]{1,32}$", jid):
        jid = uuid.uuid4().hex[:10]
    return {
        "id": jid,
        "name": name,
        "enabled": bool(raw.get("enabled", True)),
        "kind": "restic-gdrive",
        "days": clean_days,
        "hour": hour,
        "minute": minute,
        "keep_weekly": max(1, min(12, int(raw.get("keep_weekly", 4)))),
        "keep_monthly": max(1, min(12, int(raw.get("keep_monthly", 3)))),
        "cloud": bool(raw.get("cloud", True)),
    }


def upsert_jobs(app_dir: Path, payload: dict) -> dict:
    cfg = load_config(app_dir)
    incoming = payload.get("jobs")
    if incoming is None:
        if "job" in payload:
            incoming = [payload["job"]]
        else:
            incoming = cfg["jobs"]
    if not isinstance(incoming, list):
        raise ValueError("jobs inválidos")
    by_id = {j.get("id"): j for j in cfg["jobs"] if j.get("id")}
    out = []
    seen = set()
    for raw in incoming:
        if not isinstance(raw, dict):
            continue
        jid = str(raw.get("id") or "")
        cleaned = _clean_job(raw, jid if jid in by_id or jid == "servidor" else None)
        if cleaned["id"] in seen:
            continue
        seen.add(cleaned["id"])
        out.append(cleaned)
    if not any(j["id"] == "servidor" for j in out):
        out.insert(0, _clean_job(by_id.get("servidor") or default_config()["jobs"][0], "servidor"))
        out[0]["id"] = "servidor"
    if len(out) > 8:
        raise ValueError("Máximo de 8 agendamentos")
    cfg["timezone"] = TZ_NAME
    cfg["jobs"] = out
    save_config(app_dir, cfg)
    return cfg


def request_run(app_dir: Path, job_id: str) -> None:
    cfg = load_config(app_dir)
    ids = {j["id"] for j in cfg["jobs"]}
    if job_id not in ids:
        raise ValueError("Job não encontrado")
    payload = {"job_id": job_id, "requested_at": time.time()}
    (Path(app_dir) / RUN_NAME).write_text(json.dumps(payload), encoding="utf-8")
    st = Path(app_dir) / STATUS_NAME
    status = {}
    if st.exists():
        try:
            status = json.loads(st.read_text(encoding="utf-8"))
        except Exception:
            status = {}
    status.update({"running": True, "requested_job": job_id, "started_at": time.time(), "percent": 5, "step_num": 1, "step_name": "Iniciando Disaster Recovery...", "speed": "", "eta": "~ 2m 15s", "transferred": "", "message": "Backup solicitado pelo painel"})
    st.write_text(json.dumps(status, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def queue_cookie(app_dir: Path, cookie: str) -> None:
    cookie = (cookie or "").strip()
    cookie = re.sub(r"(?i)^cookie:\s*", "", cookie)
    if len(cookie) < 8:
        raise ValueError("Cookie muito curto")
    path = Path(app_dir) / COOKIE_REQ
    path.write_text(cookie + "\n", encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass


def read_status(app_dir: Path) -> dict:
    cfg = load_config(app_dir)
    status = {}
    st = Path(app_dir) / STATUS_NAME
    if st.exists():
        try:
            status = json.loads(st.read_text(encoding="utf-8"))
        except Exception:
            status = {}
    cookie_file = Path.home() / ".config/rclone/terabox.cookie"
    # Inside the container Path.home() is not the host user — flag via status/cloud
    connected = bool(status.get("cloud") in ("ok",) or status.get("connected"))
    if status.get("cloud") == "skipped" and "cookie" in str(status.get("cloud_error") or "").lower():
        connected = False
    if status.get("cloud") == "ok":
        connected = True
    running = bool(status.get("running"))
    local_ok = status.get("local_ok")
    if local_ok is None:
        local_ok = bool(status.get("success"))
    # exit_partial=True significa "backup OK mas com avisos" (prune/check/lock
    # velho). Nao pode aparecer como falha: normaliza p/ parcial visivel.
    exit_partial = bool(status.get("exit_partial"))
    if running:
        last_status = "running"
    elif local_ok:
        last_status = "partial" if exit_partial else "success"
    else:
        last_status = status.get("last_backup_status") or "never"
    msg = status.get("message") or ""
    if local_ok and exit_partial and "avisos" not in str(msg).lower() and "warn" not in str(msg).lower():
        msg = (msg + " (com avisos: prune/check — veja o log)").strip()
    return {
        "timezone": TZ_NAME,
        "timezone_label": "Horário de Brasília (GMT-3)",
        "jobs": cfg["jobs"],
        "connected": connected,
        "running": running,
        "started_at": status.get("started_at"),
        "requested_job": status.get("requested_job"),
        "written_at": status.get("written_at"),
        "last_backup": status.get("last_backup"),
        "repo_bytes": status.get("repo_bytes"),
        "local_ok": bool(local_ok),
        "success": bool(local_ok),
        "exit_partial": exit_partial,
        "cloud": status.get("cloud"),
        "cloud_error": status.get("cloud_error"),
        "last_backup_status": last_status,
        "message": msg,
        "log": status.get("log"),
        "percent": int(status.get("percent") or 0),
        "step_num": int(status.get("step_num") or 0),
        "step_name": status.get("step_name") or "",
        "speed": status.get("speed") or "",
        "eta": status.get("eta") or "",
        "transferred": status.get("transferred") or "",
        "archive_bytes": int(status.get("archive_bytes") or 0),
    }
