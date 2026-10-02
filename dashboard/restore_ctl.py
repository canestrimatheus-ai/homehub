"""Snapshot history + restore requests for the Restic backups (panel <-> host worker)."""
from __future__ import annotations

import json
import re
import time
from pathlib import Path

SNAP_NAME = "backup-snapshots.json"
REQ_NAME = "backup-restore.now"
PROG_NAME = "backup-restore-progress.json"
REFRESH_NAME = "backup-snapshots.refresh"
SNAP_ID_RE = re.compile(r"^[a-f0-9]{8,64}$")
STALE_RUNNING_SECONDS = 6 * 3600


def _p(app_dir: Path, name: str) -> Path:
    return Path(app_dir) / name


def read_snapshots(app_dir: Path) -> list:
    try:
        data = json.loads(_p(app_dir, SNAP_NAME).read_text(encoding="utf-8"))
        snaps = data.get("snapshots")
        return snaps if isinstance(snaps, list) else []
    except Exception:
        return []


def snapshots_refreshed_at(app_dir: Path) -> float:
    try:
        data = json.loads(_p(app_dir, SNAP_NAME).read_text(encoding="utf-8"))
        return float(data.get("refreshed_at") or 0)
    except Exception:
        return 0.0


def ensure_refresh_requested(app_dir: Path, max_age_seconds: int = 3600) -> bool:
    """Pede ao worker do host uma lista nova quando a atual está velha."""
    age = time.time() - snapshots_refreshed_at(app_dir)
    stale = age > max_age_seconds
    if stale:
        try:
            _p(app_dir, REFRESH_NAME).write_text(str(time.time()) + "\n", encoding="utf-8")
        except OSError:
            pass
    return stale


def read_restore_progress(app_dir: Path) -> dict:
    try:
        data = json.loads(_p(app_dir, PROG_NAME).read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return {}
        w_at = float(data.get("written_at") or 0)
        # Se não está rodando e já passou mais de 2 minutos do término, descarta mensagem antiga
        if not data.get("running") and (time.time() - w_at > 120):
            return {}
        return data
    except Exception:
        return {}


def request_restore(app_dir: Path, snapshot_id: str, include=None, dry_run: bool = False) -> dict:
    snapshot_id = (snapshot_id or "").strip().lower()
    if not SNAP_ID_RE.match(snapshot_id):
        raise ValueError("ID de snapshot inválido")
    include = [str(x).strip() for x in (include or []) if str(x).strip()]
    include = [p if p.startswith("/") else "/home/decsv/" + p.lstrip("~/") for p in include]
    prog = read_restore_progress(app_dir)
    if prog.get("running"):
        started = float(prog.get("written_at") or 0)
        if time.time() - started < STALE_RUNNING_SECONDS:
            raise ValueError("Já existe uma restauração em andamento. Aguarde a conclusão.")
    payload = {
        "snapshot_id": snapshot_id,
        "include": include,
        "dry_run": bool(dry_run),
        "requested_at": time.time(),
    }
    path = _p(app_dir, REQ_NAME)
    path.write_text(json.dumps(payload) + "\n", encoding="utf-8")
    try:
        path.chmod(0o644)
    except OSError:
        pass
    return payload
