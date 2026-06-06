from __future__ import annotations

import base64
import hashlib
import hmac
import secrets

from .config import load_secret


SECRET = load_secret()


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _unb64(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def sign(value: str) -> str:
    digest = hmac.new(SECRET, value.encode("utf-8"), hashlib.sha256).digest()
    return f"{value}.{_b64(digest)}"


def unsign(signed: str) -> str | None:
    if "." not in signed:
        return None
    value, supplied = signed.rsplit(".", 1)
    expected = sign(value).rsplit(".", 1)[1]
    if hmac.compare_digest(supplied, expected):
        return value
    return None


def hash_secret(value: str) -> str:
    salt = secrets.token_bytes(16)
    n, r, p, dklen = 2**14, 8, 1, 32
    digest = hashlib.scrypt(value.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=dklen)
    return f"scrypt${n}${r}${p}${_b64(salt)}${_b64(digest)}"


def verify_secret(value: str, encoded: str) -> bool:
    try:
        algo, n, r, p, salt, digest = encoded.split("$", 5)
        if algo != "scrypt":
            return False
        expected = _unb64(digest)
        actual = hashlib.scrypt(
            value.encode("utf-8"),
            salt=_unb64(salt),
            n=int(n),
            r=int(r),
            p=int(p),
            dklen=len(expected),
        )
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


def hash_password(password: str) -> str:
    return hash_secret(password)


def verify_password(password: str, encoded: str) -> bool:
    return verify_secret(password, encoded)
