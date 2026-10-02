"""
HomeHub Backup Manager — OneDrive integration via Microsoft Graph API
"""
import os, json, time, subprocess, hashlib, tempfile, tarfile, shutil
from pathlib import Path

GRAPH_API = "https://graph.microsoft.com/v1.0"
AUTH_URL   = "https://login.microsoftonline.com/common/oauth2/v2.0"
SCOPE      = "Files.ReadWrite offline_access"
REDIRECT   = "http://localhost:3000/api/backup/onedrive/callback"

class BackupManager:
    def __init__(self, db, app_dir):
        self.db = db
        self.app_dir = Path(app_dir)

    def get_oauth_url(self):
        import urllib.parse
        client_id = self.db.get_config("onedrive_client_id", "")
        if not client_id:
            raise Exception("Client ID não configurado.")
        params = {
            "client_id": client_id,
            "response_type": "code",
            "redirect_uri": REDIRECT,
            "scope": SCOPE,
            "response_mode": "query",
        }
        return f"{AUTH_URL}/authorize?" + urllib.parse.urlencode(params)

    def exchange_code(self, code):
        import requests
        client_id = self.db.get_config("onedrive_client_id", "")
        if not client_id:
            raise Exception("Client ID não configurado.")
        resp = requests.post(f"{AUTH_URL}/token", data={
            "client_id": client_id, "code": code,
            "redirect_uri": REDIRECT, "grant_type": "authorization_code",
            "scope": SCOPE,
        })
        resp.raise_for_status()
        data = resp.json()
        self.db.set_config("onedrive_access_token", data["access_token"])
        self.db.set_config("onedrive_refresh_token", data.get("refresh_token", ""))
        self.db.set_config("onedrive_token_expires", str(time.time() + data.get("expires_in", 3600)))
        self.db.set_config("onedrive_connected", "true")

    def _refresh_token(self):
        import requests
        client_id = self.db.get_config("onedrive_client_id", "")
        refresh = self.db.get_config("onedrive_refresh_token", "")
        if not refresh:
            raise Exception("Token de refresh não disponível. Reconecte o OneDrive.")
        resp = requests.post(f"{AUTH_URL}/token", data={
            "client_id": client_id, "refresh_token": refresh,
            "grant_type": "refresh_token", "scope": SCOPE,
        })
        resp.raise_for_status()
        data = resp.json()
        self.db.set_config("onedrive_access_token", data["access_token"])
        self.db.set_config("onedrive_token_expires", str(time.time() + data.get("expires_in", 3600)))
        return data["access_token"]

    def _get_token(self):
        expires = float(self.db.get_config("onedrive_token_expires", "0"))
        if time.time() > expires - 60:
            return self._refresh_token()
        return self.db.get_config("onedrive_access_token", "")

    def run_backup(self):
        self.db.set_config("last_backup_status", "running")
        try:
            # Create temp dir for backup package
            with tempfile.TemporaryDirectory() as tmpdir:
                archive_path = Path(tmpdir) / f"homehub-backup-{int(time.time())}.tar.gz"

                # Collect backup items
                backup_items = [
                    self.app_dir / "projects.json",
                    self.app_dir / "auth.json",
                    self.app_dir / "deploy.db",
                ]

                # Create tar.gz
                with tarfile.open(archive_path, "w:gz") as tar:
                    for item in backup_items:
                        if item.exists():
                            tar.add(item, arcname=item.name)

                # Compute checksum
                sha256 = hashlib.sha256(archive_path.read_bytes()).hexdigest()
                size = archive_path.stat().st_size

                # Upload to OneDrive
                if self.db.get_config("onedrive_connected", "false") == "true":
                    self._upload_to_onedrive(archive_path)

                self.db.set_config("last_backup_at", str(time.time()))
                self.db.set_config("last_backup_size", str(size))
                self.db.set_config("last_backup_sha256", sha256)
                self.db.set_config("last_backup_status", "success")
                self.db.set_config("last_backup_error", "")
                self.db.add_audit("backup_success", f"Backup concluído. Tamanho: {size/1024:.0f}KB SHA256: {sha256[:16]}...")

        except Exception as e:
            self.db.set_config("last_backup_status", "failed")
            self.db.set_config("last_backup_error", str(e))
            self.db.add_audit("backup_failed", f"Backup falhou: {type(e).__name__}")

    def _upload_to_onedrive(self, file_path):
        import requests
        token = self._get_token()
        fname = file_path.name
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/octet-stream"}
        url = f"{GRAPH_API}/me/drive/root:/HomeHub Backups/weekly/{fname}:/content"
        with open(file_path, "rb") as f:
            resp = requests.put(url, data=f, headers=headers)
        resp.raise_for_status()
