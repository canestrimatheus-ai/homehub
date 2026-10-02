"""HomeHub Audit Logger"""
import time, threading

_lock = threading.Lock()
_db = None

def set_db(db):
    global _db
    _db = db

def log(action, details="", ip="", username="admin"):
    global _db
    if _db is None:
        return
    try:
        with _lock:
            _db.add_audit(action, details, ip, username)
    except Exception:
        pass
