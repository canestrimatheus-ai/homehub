"""
HomeHub Deploy Center — SQLite Database Layer
"""
import sqlite3, time, json, uuid, threading
from pathlib import Path

class DeployDB:
    def __init__(self, db_path="/app/deploy.db"):
        self.db_path = db_path
        self._lock = threading.Lock()
        self._init_db()

    def _conn(self):
        c = sqlite3.connect(self.db_path, timeout=10)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA foreign_keys=ON")
        return c

    def _init_db(self):
        with self._lock:
            with self._conn() as c:
                c.executescript("""
                    CREATE TABLE IF NOT EXISTS deploy_apps (
                        id TEXT PRIMARY KEY,
                        name TEXT NOT NULL,
                        description TEXT DEFAULT "",
                        icon TEXT DEFAULT "🚀",
                        category TEXT DEFAULT "Deploy",
                        stack TEXT DEFAULT "unknown",
                        port INTEGER,
                        container_name TEXT,
                        current_version INTEGER DEFAULT 0,
                        status TEXT DEFAULT "pending",
                        created_at REAL,
                        updated_at REAL,
                        publish_to_portal INTEGER DEFAULT 0,
                        featured INTEGER DEFAULT 0
                    );

                    CREATE TABLE IF NOT EXISTS deploy_versions (
                        id TEXT PRIMARY KEY,
                        app_id TEXT NOT NULL,
                        version_num INTEGER NOT NULL,
                        image_tag TEXT,
                        container_name TEXT,
                        port INTEGER,
                        built_at REAL,
                        health_ok INTEGER DEFAULT 0,
                        is_current INTEGER DEFAULT 0,
                        build_log TEXT DEFAULT "",
                        deployed_by TEXT DEFAULT "admin"
                    );

                    CREATE TABLE IF NOT EXISTS deploy_jobs (
                        id TEXT PRIMARY KEY,
                        app_id TEXT,
                        app_name TEXT,
                        status TEXT DEFAULT "pending",
                        step TEXT DEFAULT "",
                        step_index INTEGER DEFAULT 0,
                        total_steps INTEGER DEFAULT 9,
                        error TEXT,
                        created_at REAL,
                        updated_at REAL,
                        meta TEXT DEFAULT "{}"
                    );

                    CREATE TABLE IF NOT EXISTS deploy_logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        job_id TEXT NOT NULL,
                        timestamp REAL,
                        level TEXT DEFAULT "INFO",
                        message TEXT
                    );

                    CREATE TABLE IF NOT EXISTS audit_logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp REAL,
                        action TEXT,
                        details TEXT,
                        ip_address TEXT,
                        username TEXT DEFAULT "admin"
                    );

                    CREATE TABLE IF NOT EXISTS app_config (
                        key TEXT PRIMARY KEY,
                        value TEXT
                    );

                    CREATE INDEX IF NOT EXISTS idx_deploy_logs_job ON deploy_logs(job_id);
                    CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_logs(timestamp DESC);
                    CREATE INDEX IF NOT EXISTS idx_versions_app ON deploy_versions(app_id, version_num);
                """)
                # A process restart terminates deploy worker threads. Do not leave
                # their jobs permanently advertised as active in the dashboard.
                now = time.time()
                interrupted = c.execute(
                    "SELECT id FROM deploy_jobs WHERE status IN ('pending','running')"
                ).fetchall()
                for row in interrupted:
                    c.execute(
                        "UPDATE deploy_jobs SET status='failed', step='Interrompido', error=?, updated_at=? WHERE id=?",
                        ("Deploy interrompido pela reinicialização do HomeHub. Inicie novamente.", now, row["id"]),
                    )
                    c.execute(
                        "INSERT INTO deploy_logs(job_id,timestamp,level,message) VALUES(?,?,?,?)",
                        (row["id"], now, "ERROR", "✗ Deploy interrompido pela reinicialização do HomeHub."),
                    )

    # ── Jobs ────────────────────────────────────────────────────────────────
    def create_job(self, job_id, app_name, meta=None):
        now = time.time()
        with self._lock:
            with self._conn() as c:
                c.execute(
                    "INSERT INTO deploy_jobs(id,app_name,status,step,created_at,updated_at,meta) VALUES(?,?,?,?,?,?,?)",
                    (job_id, app_name, "pending", "Aguardando", now, now, meta or "{}")
                )

    def update_job(self, job_id, status=None, step=None, step_index=None, error=None, app_id=None):
        sets, vals = [], []
        if status is not None:   sets.append("status=?");     vals.append(status)
        if step is not None:     sets.append("step=?");       vals.append(step)
        if step_index is not None: sets.append("step_index=?"); vals.append(step_index)
        if error is not None:    sets.append("error=?");      vals.append(error)
        if app_id is not None:   sets.append("app_id=?");     vals.append(app_id)
        sets.append("updated_at=?"); vals.append(time.time())
        vals.append(job_id)
        if not sets:
            return
        with self._lock:
            with self._conn() as c:
                c.execute(f"UPDATE deploy_jobs SET {','.join(sets)} WHERE id=?", vals)

    def get_job(self, job_id):
        with self._conn() as c:
            row = c.execute("SELECT * FROM deploy_jobs WHERE id=?", (job_id,)).fetchone()
            return dict(row) if row else None

    def get_active_job(self):
        with self._conn() as c:
            row = c.execute(
                "SELECT * FROM deploy_jobs WHERE status IN ('pending','running') ORDER BY created_at DESC LIMIT 1"
            ).fetchone()
            return dict(row) if row else None

    # ── Logs ────────────────────────────────────────────────────────────────
    def add_log(self, job_id, message, level="INFO"):
        with self._lock:
            with self._conn() as c:
                c.execute(
                    "INSERT INTO deploy_logs(job_id,timestamp,level,message) VALUES(?,?,?,?)",
                    (job_id, time.time(), level, message)
                )

    def get_logs(self, job_id, since_id=0):
        with self._conn() as c:
            rows = c.execute(
                "SELECT id,timestamp,level,message FROM deploy_logs WHERE job_id=? AND id>? ORDER BY id",
                (job_id, since_id)
            ).fetchall()
            return [dict(r) for r in rows]

    # ── Apps ────────────────────────────────────────────────────────────────
    def create_app(self, app_id, name, description, icon, category, stack, port, container_name,
                   publish=False, featured=False):
        now = time.time()
        with self._lock:
            with self._conn() as c:
                c.execute("""
                    INSERT INTO deploy_apps(id,name,description,icon,category,stack,port,container_name,
                        status,created_at,updated_at,publish_to_portal,featured)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
                """, (app_id, name, description, icon, category, stack, port, container_name,
                      "running", now, now, 1 if publish else 0, 1 if featured else 0))
        return self.get_app(app_id)

    def update_app(self, app_id, **kwargs):
        allowed = {"name","description","icon","category","stack","port","container_name",
                   "current_version","status","publish_to_portal","featured","updated_at"}
        sets, vals = [], []
        for k, v in kwargs.items():
            if k in allowed:
                sets.append(f"{k}=?"); vals.append(v)
        if not sets:
            return
        sets.append("updated_at=?"); vals.append(time.time())
        vals.append(app_id)
        with self._lock:
            with self._conn() as c:
                c.execute(f"UPDATE deploy_apps SET {','.join(sets)} WHERE id=?", vals)

    def get_app(self, app_id):
        with self._conn() as c:
            row = c.execute("SELECT * FROM deploy_apps WHERE id=?", (app_id,)).fetchone()
            return dict(row) if row else None

    def list_apps(self):
        with self._conn() as c:
            rows = c.execute("SELECT * FROM deploy_apps ORDER BY created_at DESC").fetchall()
            return [dict(r) for r in rows]

    def delete_app(self, app_id):
        with self._lock:
            with self._conn() as c:
                job_ids = [r["id"] for r in c.execute(
                    "SELECT id FROM deploy_jobs WHERE app_id=?", (app_id,)
                ).fetchall()]
                for jid in job_ids:
                    c.execute("DELETE FROM deploy_logs WHERE job_id=?", (jid,))
                c.execute("DELETE FROM deploy_jobs WHERE app_id=?", (app_id,))
                c.execute("DELETE FROM deploy_versions WHERE app_id=?", (app_id,))
                c.execute("DELETE FROM deploy_apps WHERE id=?", (app_id,))

    def find_apps_for_portal_project(self, project):
        """Match Deploy Center rows to a Portal Público catalog entry."""
        pid = (project.get("id") or "").strip()
        pname = (project.get("name") or "").strip().lower()
        url = (project.get("url") or "").strip()
        seen, matches = set(), []
        for app in self.list_apps():
            aid = app.get("id") or ""
            aname = (app.get("name") or "").strip().lower()
            cname = (app.get("container_name") or "").strip()
            if aid in seen:
                continue
            matched = False
            if pid and aid == pid:
                matched = True
            elif pname and aname == pname:
                matched = True
            elif pid and cname in {pid, f"hh-{pid}", f"homeserver-{pid}"}:
                matched = True
            elif pid and cname.endswith(pid):
                matched = True
            elif url and app.get("port") and f":{app['port']}" in url:
                matched = True
            if matched:
                seen.add(aid)
                matches.append(app)
        return matches

    # ── Versions ────────────────────────────────────────────────────────────
    def create_version(self, app_id, image_tag, container_name, port, health_ok, build_log, deployed_by="admin"):
        # Determine next version number
        with self._conn() as c:
            row = c.execute("SELECT MAX(version_num) as m FROM deploy_versions WHERE app_id=?", (app_id,)).fetchone()
            next_v = (row["m"] or 0) + 1
        ver_id = str(uuid.uuid4())
        with self._lock:
            with self._conn() as c:
                # Deactivate all current
                c.execute("UPDATE deploy_versions SET is_current=0 WHERE app_id=?", (app_id,))
                c.execute("""
                    INSERT INTO deploy_versions(id,app_id,version_num,image_tag,container_name,port,
                        built_at,health_ok,is_current,build_log,deployed_by)
                    VALUES(?,?,?,?,?,?,?,?,1,?,?)
                """, (ver_id, app_id, next_v, image_tag, container_name, port,
                      time.time(), 1 if health_ok else 0, build_log, deployed_by))
        self.update_app(app_id, current_version=next_v)
        return next_v

    def get_versions(self, app_id):
        with self._conn() as c:
            rows = c.execute(
                "SELECT * FROM deploy_versions WHERE app_id=? ORDER BY version_num DESC", (app_id,)
            ).fetchall()
            return [dict(r) for r in rows]

    def get_version(self, app_id, version_num):
        with self._conn() as c:
            row = c.execute(
                "SELECT * FROM deploy_versions WHERE app_id=? AND version_num=?", (app_id, version_num)
            ).fetchone()
            return dict(row) if row else None

    def set_current_version(self, app_id, version_num):
        with self._lock:
            with self._conn() as c:
                c.execute("UPDATE deploy_versions SET is_current=0 WHERE app_id=?", (app_id,))
                c.execute("UPDATE deploy_versions SET is_current=1 WHERE app_id=? AND version_num=?",
                          (app_id, version_num))
        self.update_app(app_id, current_version=version_num)

    # ── Audit ────────────────────────────────────────────────────────────────
    def add_audit(self, action, details="", ip_address="", username="admin"):
        with self._lock:
            with self._conn() as c:
                c.execute(
                    "INSERT INTO audit_logs(timestamp,action,details,ip_address,username) VALUES(?,?,?,?,?)",
                    (time.time(), action, details, ip_address, username)
                )

    def get_audit(self, limit=100, offset=0):
        with self._conn() as c:
            rows = c.execute(
                "SELECT * FROM audit_logs ORDER BY id DESC LIMIT ? OFFSET ?", (limit, offset)
            ).fetchall()
            return [dict(r) for r in rows]

    # ── Config ───────────────────────────────────────────────────────────────
    def get_config(self, key, default=None):
        with self._conn() as c:
            row = c.execute("SELECT value FROM app_config WHERE key=?", (key,)).fetchone()
            return row["value"] if row else default

    def set_config(self, key, value):
        with self._lock:
            with self._conn() as c:
                c.execute("INSERT OR REPLACE INTO app_config(key,value) VALUES(?,?)", (key, str(value)))
