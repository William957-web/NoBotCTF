from pathlib import Path
import os
import secrets


BASE_DIR = Path(__file__).resolve().parent.parent
INSTANCE_DIR = BASE_DIR / "instance"
UPLOAD_DIR = Path(os.environ.get("CTF_UPLOAD_DIR", INSTANCE_DIR / "uploads"))
DB_PATH = Path(os.environ.get("CTF_DB_PATH", INSTANCE_DIR / "ctf_platform.sqlite3"))
SECRET_PATH = Path(os.environ.get("CTF_SECRET_PATH", INSTANCE_DIR / "secret.key"))
APP_TZ = os.environ.get("APP_TZ", "Asia/Taipei")
SESSION_COOKIE = "ctf_session"
SESSION_DAYS = 14
MAX_UPLOAD_BYTES = int(os.environ.get("CTF_MAX_UPLOAD_BYTES", str(50 * 1024 * 1024)))


def load_secret() -> bytes:
    INSTANCE_DIR.mkdir(parents=True, exist_ok=True)
    if SECRET_PATH.exists():
        return SECRET_PATH.read_bytes().strip()
    secret = secrets.token_urlsafe(48).encode("ascii")
    SECRET_PATH.write_bytes(secret + b"\n")
    SECRET_PATH.chmod(0o600)
    return secret
