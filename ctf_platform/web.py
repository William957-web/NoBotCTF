from __future__ import annotations

from datetime import timedelta
from html import escape
import json
import mimetypes
import os
import re
import sqlite3
import secrets
from http.cookies import SimpleCookie
from pathlib import Path
from socketserver import ThreadingMixIn
from typing import Callable
from urllib.parse import parse_qs, quote, unquote
from wsgiref.simple_server import WSGIRequestHandler, WSGIServer, make_server

import bleach
from jinja2 import Environment, FileSystemLoader, pass_context, select_autoescape
import markdown
from markupsafe import Markup

from .config import BASE_DIR, MAX_UPLOAD_BYTES, SESSION_COOKIE, SESSION_DAYS, UPLOAD_DIR
from .db import connect, init_db, query_all, query_one, transaction
from .security import (
    flag_attempt_digest,
    hash_flag,
    hash_flag_pattern,
    hash_password,
    sign,
    unsign,
    verify_flag,
    verify_password,
)
from .utils import (
    clip,
    display_duration,
    display_time,
    iso_utc,
    parse_iso,
    parse_local_datetime,
    slugify,
    to_local_value,
    utcnow,
)


RouteHandler = Callable[..., "Response"]
ROUTES: list[tuple[str, re.Pattern[str], RouteHandler]] = []
COMPETITION_PREVIEW_LIMIT = 4
COMPETITION_PAGE_SIZE = 10
LIST_PREVIEW_LIMIT = 10
SCOREBOARD_PREVIEW_LIMIT = 12
SCOREBOARD_PAGE_SIZE = 50


class Response:
    def __init__(self, body: str | bytes = b"", status: int = 200, headers: list[tuple[str, str]] | None = None):
        self.status = status
        self.headers = headers or []
        self.body = body.encode("utf-8") if isinstance(body, str) else body


class Request:
    def __init__(self, environ):
        self.environ = environ
        self.method = environ.get("REQUEST_METHOD", "GET").upper()
        self.path = unquote(environ.get("PATH_INFO", "/"))
        self.query = self._parse_query(environ.get("QUERY_STRING", ""))
        self.cookies = SimpleCookie(environ.get("HTTP_COOKIE", ""))
        self.session_id: str | None = None
        self.session = None
        self.current_user = None
        self._form: dict[str, str] | None = None
        self.files = {}
        self.set_cookie: str | None = None

    @staticmethod
    def _parse_query(raw: str) -> dict[str, str]:
        values = parse_qs(raw, keep_blank_values=True)
        return {key: vals[-1] if vals else "" for key, vals in values.items()}

    @property
    def form(self) -> dict[str, str]:
        if self._form is not None:
            return self._form
        length = int(self.environ.get("CONTENT_LENGTH") or 0)
        if length > 1024 * 1024:
            self._form = {}
            return self._form
        raw = self.environ["wsgi.input"].read(length).decode("utf-8", "replace")
        values = parse_qs(raw, keep_blank_values=True)
        self._form = {key: vals[-1] if vals else "" for key, vals in values.items()}
        return self._form

    @property
    def csrf_token(self) -> str:
        return self.session["csrf_token"] if self.session else ""


def route(method: str, pattern: str):
    def decorator(handler: RouteHandler):
        ROUTES.append((method.upper(), re.compile(f"^{pattern}$"), handler))
        return handler

    return decorator


@pass_context
def csrf_input(ctx) -> Markup:
    request = ctx["request"]
    token = escape(request.csrf_token)
    return Markup(f'<input type="hidden" name="_csrf" value="{token}">')


MARKDOWN_TAGS = [
    "a",
    "blockquote",
    "br",
    "code",
    "dd",
    "del",
    "div",
    "dl",
    "dt",
    "em",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "hr",
    "img",
    "li",
    "ol",
    "p",
    "pre",
    "strong",
    "table",
    "tbody",
    "td",
    "th",
    "thead",
    "tr",
    "ul",
]
MARKDOWN_ATTRS = {
    "a": ["href", "title", "rel"],
    "img": ["alt", "src", "title"],
    "th": ["align"],
    "td": ["align"],
}


def markdown_safe(value: str) -> Markup:
    rendered = markdown.markdown(
        value or "",
        extensions=["fenced_code", "tables", "sane_lists", "nl2br"],
        output_format="html5",
    )
    cleaned = bleach.clean(
        rendered,
        tags=MARKDOWN_TAGS,
        attributes=MARKDOWN_ATTRS,
        protocols=["http", "https", "mailto"],
        strip=True,
    )
    return Markup(cleaned)


TEMPLATES = Environment(
    loader=FileSystemLoader(BASE_DIR / "templates"),
    autoescape=select_autoescape(["html", "xml"]),
)
TEMPLATES.globals["csrf_input"] = csrf_input
TEMPLATES.filters["local_time"] = display_time
TEMPLATES.filters["local_input"] = to_local_value
TEMPLATES.filters["duration"] = display_duration
TEMPLATES.filters["markdown_safe"] = markdown_safe


def status_line(code: int) -> str:
    labels = {
        200: "200 OK",
        302: "302 Found",
        400: "400 Bad Request",
        403: "403 Forbidden",
        404: "404 Not Found",
        409: "409 Conflict",
        500: "500 Internal Server Error",
    }
    return labels.get(code, f"{code} OK")


def redirect(location: str) -> Response:
    return Response(b"", 302, [("Location", location)])


def json_response(payload: dict, status: int = 200) -> Response:
    return Response(json.dumps(payload, ensure_ascii=False), status, [("Content-Type", "application/json; charset=utf-8")])


def render(request: Request, template: str, status: int = 200, **context) -> Response:
    body = TEMPLATES.get_template(template).render(
        request=request,
        current_user=request.current_user,
        notice=request.query.get("notice"),
        error=request.query.get("error"),
        admin_ready=admin_exists(),
        platform_name=get_platform_name(),
        list_preview_limit=LIST_PREVIEW_LIMIT,
        default_scoreboard_preview_limit=SCOREBOARD_PREVIEW_LIMIT,
        **context,
    )
    return Response(body, status, [("Content-Type", "text/html; charset=utf-8")])


def error_page(request: Request, status: int, message: str) -> Response:
    return render(request, "error.html", status=status, message=message)


def with_notice(path: str, message: str) -> str:
    separator = "&" if "?" in path else "?"
    return f"{path}{separator}notice={quote(message)}"


def with_error(path: str, message: str) -> str:
    separator = "&" if "?" in path else "?"
    return f"{path}{separator}error={quote(message)}"


def load_session(request: Request) -> None:
    signed = request.cookies.get(SESSION_COOKIE)
    sid = unsign(signed.value) if signed else None
    now = iso_utc()
    if sid:
        with connect() as conn:
            row = conn.execute("SELECT * FROM sessions WHERE id = ? AND expires_at > ?", (sid, now)).fetchone()
            if row:
                request.session_id = row["id"]
                request.session = row
                if row["user_id"]:
                    user = conn.execute("SELECT * FROM users WHERE id = ? AND is_active = 1", (row["user_id"],)).fetchone()
                    request.current_user = user
                return

    session_id = secrets.token_urlsafe(32)
    csrf_token = secrets.token_urlsafe(32)
    expires_at = iso_utc(utcnow() + timedelta(days=SESSION_DAYS))
    with transaction() as conn:
        conn.execute(
            "INSERT INTO sessions(id, user_id, csrf_token, created_at, expires_at) VALUES (?, NULL, ?, ?, ?)",
            (session_id, csrf_token, now, expires_at),
        )
    request.session_id = session_id
    request.set_cookie = make_cookie(session_id, max_age=SESSION_DAYS * 24 * 3600)
    request.session = {"id": session_id, "user_id": None, "csrf_token": csrf_token, "created_at": now, "expires_at": expires_at}


def make_cookie(session_id: str, max_age: int) -> str:
    cookie = SimpleCookie()
    cookie[SESSION_COOKIE] = sign(session_id)
    cookie[SESSION_COOKIE]["path"] = "/"
    cookie[SESSION_COOKIE]["httponly"] = True
    cookie[SESSION_COOKIE]["samesite"] = "Lax"
    cookie[SESSION_COOKIE]["max-age"] = str(max_age)
    return cookie.output(header="").strip()


def clear_cookie() -> str:
    cookie = SimpleCookie()
    cookie[SESSION_COOKIE] = ""
    cookie[SESSION_COOKIE]["path"] = "/"
    cookie[SESSION_COOKIE]["httponly"] = True
    cookie[SESSION_COOKIE]["samesite"] = "Lax"
    cookie[SESSION_COOKIE]["max-age"] = "0"
    return cookie.output(header="").strip()


def admin_exists() -> bool:
    return bool(query_one("SELECT 1 FROM users WHERE role = 'admin' AND is_active = 1 LIMIT 1"))


def get_platform_name() -> str:
    row = query_one("SELECT value FROM platform_settings WHERE key = 'platform_name'")
    return row["value"] if row else "Time-Windowed CTF Arena"


def set_platform_name(conn, value: str) -> None:
    conn.execute(
        """
        INSERT INTO platform_settings(key, value, updated_at)
        VALUES ('platform_name', ?, ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
        """,
        (value, iso_utc()),
    )


def require_login(request: Request) -> Response | None:
    if request.current_user:
        return None
    return redirect(f"/login?next={quote(request.path)}")


def require_roles(request: Request, *roles: str) -> Response | None:
    missing = require_login(request)
    if missing:
        return missing
    if request.current_user["role"] not in roles:
        return error_page(request, 403, "You do not have permission to perform this action.")
    return None


def is_admin(user) -> bool:
    return bool(user and user["role"] == "admin")


def collaboration_role(user, competition) -> str | None:
    if not user or not competition:
        return None
    if user["role"] == "admin":
        return "admin"
    if user["id"] == competition["owner_id"]:
        return "owner"
    row = query_one(
        """
        SELECT role FROM competition_collaborators
        WHERE competition_id = ? AND user_id = ?
        """,
        (competition["id"], user["id"]),
    )
    return row["role"] if row else None


def can_manage_competition(user, competition) -> bool:
    return collaboration_role(user, competition) in ("admin", "owner", "editor")


def can_view_competition(user, competition) -> bool:
    return bool(competition and (competition["status"] in ("approved", "archived") or collaboration_role(user, competition)))


def competition_is_archived(competition, ends_at: str | None = None, now: str | None = None) -> bool:
    if not competition:
        return False
    current = now or iso_utc()
    end_value = ends_at
    if not end_value and hasattr(competition, "keys") and "ends_at" in competition.keys():
        end_value = competition["ends_at"]
    return bool(competition["status"] == "archived" or (end_value and end_value <= current))


def competition_is_running(competition, ends_at: str | None = None, now: str | None = None) -> bool:
    if not competition:
        return False
    current = now or iso_utc()
    end_value = ends_at
    if not end_value and hasattr(competition, "keys") and "ends_at" in competition.keys():
        end_value = competition["ends_at"]
    return bool(competition["status"] == "approved" and competition["starts_at"] <= current and end_value and current < end_value)


def competition_is_upcoming(competition, now: str | None = None) -> bool:
    if not competition:
        return False
    current = now or iso_utc()
    return bool(competition["status"] == "approved" and current < competition["starts_at"])


def form_text(request: Request, name: str, limit: int = 4000) -> str:
    return clip(request.form.get(name, ""), limit)


def normalize_tags(value: str, limit: int = 8) -> str:
    tags: list[str] = []
    seen: set[str] = set()
    for raw in re.split(r"[,;#]+", value):
        tag = re.sub(r"\s+", "-", raw.strip())
        tag = re.sub(r"[^A-Za-z0-9._+\-]+", "", tag).strip("._+-")
        if not tag:
            continue
        clipped = clip(tag, 32)
        key = clipped.lower()
        if key in seen:
            continue
        seen.add(key)
        tags.append(clipped)
        if len(tags) >= limit:
            break
    return ", ".join(tags)


def normalize_team_mode(value: str) -> str:
    return value if value in ("individual", "teams") else "individual"


def normalize_scoring_mode(value: str) -> str:
    return value if value in ("fixed", "dynamic") else "fixed"


def normalize_invite_role(value: str) -> str:
    return value if value in ("editor", "viewer") else "editor"


def validate_url(value: str) -> bool:
    return not value or bool(re.fullmatch(r"https?://[^\s]{3,500}", value))


def profile_payload(request: Request) -> tuple[dict | None, str | None]:
    display_name = form_text(request, "display_name", 80)
    affiliation = form_text(request, "affiliation", 120)
    website_url = form_text(request, "website_url", 500)
    bio = form_text(request, "bio", 1200)
    if website_url and not validate_url(website_url):
        return None, "Website must be a valid http(s) URL."
    return {
        "display_name": display_name,
        "affiliation": affiliation,
        "website_url": website_url,
        "bio": bio,
    }, None


def nonnegative_int(value, default: int = 0, minimum: int = 0) -> int:
    try:
        return max(minimum, int(value))
    except Exception:
        return default


def bounded_int(value, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except Exception:
        return default
    return min(maximum, max(minimum, parsed))


def competition_form_payload(request: Request) -> tuple[dict | None, str | None]:
    try:
        starts_at = iso_utc(parse_local_datetime(request.form.get("starts_at", "")))
        scoreboard_freeze_minutes = int(request.form.get("scoreboard_freeze_minutes", "0") or "0")
        scoreboard_preview_limit = bounded_int(
            request.form.get("scoreboard_preview_limit", SCOREBOARD_PREVIEW_LIMIT),
            SCOREBOARD_PREVIEW_LIMIT,
            1,
            100,
        )
    except Exception:
        return None, "Invalid competition start time or freeze duration."
    writeup_url = form_text(request, "writeup_url", 500)
    if scoreboard_freeze_minutes < 0:
        return None, "Scoreboard freeze duration cannot be negative."
    if not validate_url(writeup_url):
        return None, "Writeup URL must be a valid http(s) URL."
    return {
        "title": form_text(request, "title", 120),
        "summary": form_text(request, "summary", 1000),
        "rules": form_text(request, "rules", 4000),
        "slug": form_text(request, "slug", 80),
        "starts_at": starts_at,
        "registration_open": 1 if request.form.get("registration_open") == "on" else 0,
        "team_mode": normalize_team_mode(request.form.get("team_mode", "individual")),
        "scoring_mode": normalize_scoring_mode(request.form.get("scoring_mode", "fixed")),
        "scoreboard_freeze_minutes": scoreboard_freeze_minutes,
        "scoreboard_preview_limit": scoreboard_preview_limit,
        "writeup_url": writeup_url,
    }, None


def validate_username(username: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9_]{3,32}", username))


def validate_password(password: str) -> bool:
    return len(password) >= 10


def normalize_flag_type(value: str) -> str:
    return value if value in ("static", "regex") else "static"


def validate_flag_regex(pattern: str) -> str | None:
    try:
        re.compile(pattern)
    except re.error as exc:
        return f"Invalid regex: {exc}"
    return None


def challenge_flag_matches(flag: str, challenge) -> bool:
    value = flag.strip()
    if len(value) > 512:
        return False
    if challenge["flag_type"] == "regex":
        pattern = challenge["flag_pattern"] or ""
        if not pattern:
            return False
        try:
            return re.fullmatch(pattern, value) is not None
        except re.error:
            return False
    return verify_flag(value, challenge["flag_hash"])


def flag_config_from_form(request: Request, current=None) -> tuple[dict | None, str | None]:
    flag_type = normalize_flag_type(request.form.get("flag_type", "static"))
    static_flag = request.form.get("flag", "").strip()
    regex_pattern = request.form.get("flag_pattern", "").strip()
    if flag_type == "regex":
        if not regex_pattern and current and current["flag_type"] == "regex":
            return {"flag_type": "regex", "flag_hash": current["flag_hash"], "flag_pattern": current["flag_pattern"]}, None
        if not regex_pattern:
            return None, "Regex flags require a pattern."
        regex_error = validate_flag_regex(regex_pattern)
        if regex_error:
            return None, regex_error
        return {"flag_type": "regex", "flag_hash": hash_flag_pattern(regex_pattern), "flag_pattern": regex_pattern}, None

    if not static_flag and current and current["flag_type"] == "static":
        return {"flag_type": "static", "flag_hash": current["flag_hash"], "flag_pattern": None}, None
    if not static_flag:
        return None, "Static flags require a complete flag value."
    return {"flag_type": "static", "flag_hash": hash_flag(static_flag), "flag_pattern": None}, None


def safe_filename(filename: str) -> str:
    name = Path(filename).name.strip().replace("\x00", "")
    name = re.sub(r"[^A-Za-z0-9._ -]+", "_", name)
    name = re.sub(r"\s+", "_", name).strip("._ ")
    return clip(name, 160) or "dist.bin"


def latest_challenge_file(conn, challenge_id: int):
    return conn.execute(
        """
        SELECT * FROM challenge_files
        WHERE challenge_id = ?
        ORDER BY created_at DESC, id DESC
        LIMIT 1
        """,
        (challenge_id,),
    ).fetchone()


def save_dist_file(conn, challenge_id: int, uploaded) -> int | None:
    if not uploaded or not uploaded.filename:
        return None
    if uploaded.size > MAX_UPLOAD_BYTES:
        raise ValueError("Uploaded file exceeds the size limit.")
    original = safe_filename(uploaded.filename)
    stored = f"{challenge_id}/{secrets.token_urlsafe(18)}_{original}"
    target = (UPLOAD_DIR / stored).resolve()
    upload_root = UPLOAD_DIR.resolve()
    if not str(target).startswith(str(upload_root)):
        raise ValueError("Invalid upload filename.")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(uploaded.data)
    cur = conn.execute(
        """
        INSERT INTO challenge_files(challenge_id, original_filename, stored_filename, content_type, size_bytes, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (challenge_id, original, stored, uploaded.content_type, uploaded.size, iso_utc()),
    )
    return cur.lastrowid


def can_download_dist(user, competition, challenge, registered: bool) -> bool:
    if collaboration_role(user, competition):
        return True
    if competition_is_archived(competition):
        return True
    if not user or not registered:
        return False
    now = iso_utc()
    return bool(competition["status"] == "approved" and challenge["opens_at"] <= now < challenge["closes_at"])


def audit(conn, actor_id: int | None, action: str, target_type: str, target_id: int | None, metadata: dict | None = None) -> None:
    conn.execute(
        "INSERT INTO audit_log(actor_id, action, target_type, target_id, metadata, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (actor_id, action, target_type, target_id, json.dumps(metadata or {}, ensure_ascii=False), iso_utc()),
    )


def unique_competition_slug(conn, wanted: str, title: str, exclude_id: int | None = None) -> str:
    base = slugify(wanted or title, "competition")
    candidate = base
    counter = 2
    while True:
        if exclude_id:
            row = conn.execute("SELECT id FROM competitions WHERE slug = ? AND id != ?", (candidate, exclude_id)).fetchone()
        else:
            row = conn.execute("SELECT id FROM competitions WHERE slug = ?", (candidate,)).fetchone()
        if not row:
            return candidate
        candidate = f"{base}-{counter}"
        counter += 1


def unique_challenge_slug(conn, competition_id: int, wanted: str, title: str, exclude_id: int | None = None) -> str:
    base = slugify(wanted or title, "challenge")
    candidate = base
    counter = 2
    while True:
        if exclude_id:
            row = conn.execute(
                "SELECT id FROM challenges WHERE competition_id = ? AND slug = ? AND id != ?",
                (competition_id, candidate, exclude_id),
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT id FROM challenges WHERE competition_id = ? AND slug = ?",
                (competition_id, candidate),
            ).fetchone()
        if not row:
            return candidate
        candidate = f"{base}-{counter}"
        counter += 1


def challenge_overlap(conn, competition_id: int, opens_at: str, closes_at: str, exclude_id: int | None = None):
    params = [competition_id, closes_at, opens_at]
    sql = """
        SELECT * FROM challenges
        WHERE competition_id = ?
          AND opens_at < ?
          AND closes_at > ?
    """
    if exclude_id:
        sql += " AND id != ?"
        params.append(exclude_id)
    sql += " LIMIT 1"
    return conn.execute(sql, tuple(params)).fetchone()


def recalculate_challenge_schedule(conn, competition_id: int) -> None:
    competition = conn.execute("SELECT id, starts_at FROM competitions WHERE id = ?", (competition_id,)).fetchone()
    if not competition:
        return
    cursor = parse_iso(competition["starts_at"])
    challenges = conn.execute(
        """
        SELECT id, duration_minutes
        FROM challenges
        WHERE competition_id = ?
        ORDER BY position ASC, id ASC
        """,
        (competition_id,),
    ).fetchall()
    for position, challenge in enumerate(challenges, start=1):
        duration = max(1, int(challenge["duration_minutes"] or 15))
        closes_at = cursor + timedelta(minutes=duration)
        conn.execute(
            """
            UPDATE challenges
            SET position = ?, duration_minutes = ?, opens_at = ?, closes_at = ?
            WHERE id = ?
            """,
            (position, duration, iso_utc(cursor), iso_utc(closes_at), challenge["id"]),
        )
        cursor = closes_at


def competition_end_at(conn, competition_id: int, fallback_start: str | None = None) -> str:
    row = conn.execute(
        "SELECT MAX(closes_at) AS ends_at FROM challenges WHERE competition_id = ?",
        (competition_id,),
    ).fetchone()
    if row and row["ends_at"]:
        return row["ends_at"]
    if fallback_start:
        return fallback_start
    competition = conn.execute("SELECT starts_at FROM competitions WHERE id = ?", (competition_id,)).fetchone()
    return competition["starts_at"] if competition else iso_utc()


def competition_freeze_cutoff(conn, competition_id: int) -> str | None:
    competition = conn.execute(
        "SELECT starts_at, scoreboard_freeze_minutes FROM competitions WHERE id = ?",
        (competition_id,),
    ).fetchone()
    if not competition or competition["scoreboard_freeze_minutes"] <= 0:
        return None
    ends_at = parse_iso(competition_end_at(conn, competition_id, competition["starts_at"]))
    freeze_at = ends_at - timedelta(minutes=int(competition["scoreboard_freeze_minutes"]))
    now = utcnow()
    if freeze_at <= now < ends_at:
        return iso_utc(freeze_at)
    return None


def create_collaboration_invite(
    conn,
    competition_id: int,
    actor_id: int | None,
    role: str = "editor",
    expires_days: int | None = 14,
) -> str:
    token = secrets.token_urlsafe(24)
    created_at = iso_utc()
    expires_at = iso_utc(utcnow() + timedelta(days=expires_days)) if expires_days else None
    conn.execute(
        """
        INSERT INTO competition_collaborator_invites(competition_id, token, role, created_by, created_at, expires_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (competition_id, token, normalize_invite_role(role), actor_id, created_at, expires_at),
    )
    audit(conn, actor_id, "create_collaboration_invite", "competition", competition_id, {"role": role, "expires_at": expires_at})
    return token


def challenge_hint_unlocked(challenge, server_now: str) -> bool:
    if not challenge["hint_text"]:
        return False
    unlock_at = parse_iso(challenge["opens_at"]) + timedelta(minutes=int(challenge["hint_unlock_minutes"] or 0))
    return parse_iso(server_now) >= unlock_at


def competition_by_id(comp_id: int):
    return query_one(
        """
        SELECT competitions.*, users.username AS owner_name,
               COALESCE((SELECT MAX(ch.closes_at) FROM challenges ch WHERE ch.competition_id = competitions.id), competitions.starts_at) AS ends_at,
               (SELECT COUNT(*) FROM challenges ch WHERE ch.competition_id = competitions.id) AS challenge_count,
               (SELECT COUNT(*) FROM competition_registrations r WHERE r.competition_id = competitions.id) AS player_count
        FROM competitions
        JOIN users ON users.id = competitions.owner_id
        WHERE competitions.id = ?
        """,
        (comp_id,),
    )


def challenge_by_id(challenge_id: int):
    return query_one(
        """
        SELECT challenges.*, competitions.title AS competition_title, competitions.status AS competition_status,
               competitions.owner_id AS owner_id
        FROM challenges
        JOIN competitions ON competitions.id = challenges.competition_id
        WHERE challenges.id = ?
        """,
        (challenge_id,),
    )


def active_challenge(conn, competition_id: int):
    now = iso_utc()
    return conn.execute(
        """
        SELECT * FROM challenges
        WHERE competition_id = ? AND opens_at <= ? AND closes_at > ?
        ORDER BY position ASC, opens_at ASC, id ASC
        LIMIT 1
        """,
        (competition_id, now, now),
    ).fetchone()


def scoreboard_preview_limit_for(competition) -> int:
    if not competition:
        return SCOREBOARD_PREVIEW_LIMIT
    try:
        value = competition["scoreboard_preview_limit"]
    except Exception:
        value = SCOREBOARD_PREVIEW_LIMIT
    return bounded_int(value, SCOREBOARD_PREVIEW_LIMIT, 1, 100)


def scoreboard(conn, competition_id: int, limit: int | None = 20):
    competition = conn.execute("SELECT scoring_mode FROM competitions WHERE id = ?", (competition_id,)).fetchone()
    cutoff = competition_freeze_cutoff(conn, competition_id)
    cutoff_clause = "AND solves.created_at <= ?" if cutoff else ""
    params: list = [competition_id]
    if cutoff:
        params.append(cutoff)
    rows = conn.execute(
        f"""
        SELECT solves.user_id, users.username, solves.challenge_id, solves.created_at,
               challenges.points,
               (SELECT COUNT(*) FROM solves s2
                WHERE s2.challenge_id = solves.challenge_id {("AND s2.created_at <= ?" if cutoff else "")}) AS challenge_solve_count
        FROM solves
        JOIN users ON users.id = solves.user_id
        JOIN challenges ON challenges.id = solves.challenge_id
        WHERE solves.competition_id = ? {cutoff_clause}
        ORDER BY solves.created_at ASC
        """,
        tuple(([cutoff] if cutoff else []) + params),
    ).fetchall()
    by_user: dict[int, dict] = {}
    dynamic = bool(competition and competition["scoring_mode"] == "dynamic")
    for row in rows:
        user_score = by_user.setdefault(
            row["user_id"],
            {"user_id": row["user_id"], "username": row["username"], "solved_count": 0, "score": 0, "last_solve": None},
        )
        solve_count = max(1, int(row["challenge_solve_count"] or 1))
        points = int(row["points"])
        awarded = max(10, min(points, round(points * (0.92 ** (solve_count - 1))))) if dynamic else points
        user_score["solved_count"] += 1
        user_score["score"] += awarded
        user_score["last_solve"] = row["created_at"]
    ranked = sorted(by_user.values(), key=lambda item: (-item["score"], item["last_solve"] or ""))
    return ranked if limit is None else ranked[:limit]


def public_competitions():
    now = iso_utc()
    return query_all(
        """
        SELECT c.*, u.username AS owner_name,
               COALESCE((SELECT MAX(ch.closes_at) FROM challenges ch WHERE ch.competition_id = c.id), c.starts_at) AS ends_at,
               (SELECT COUNT(*) FROM challenges ch WHERE ch.competition_id = c.id) AS challenge_count,
               (SELECT COUNT(*) FROM competition_registrations r WHERE r.competition_id = c.id) AS player_count,
               (SELECT title FROM challenges ch
                WHERE ch.competition_id = c.id AND ch.opens_at <= ? AND ch.closes_at > ?
                ORDER BY ch.position ASC LIMIT 1) AS live_title
        FROM competitions c
        JOIN users u ON u.id = c.owner_id
        WHERE c.status = 'approved'
        ORDER BY c.starts_at ASC, c.created_at DESC
        """,
        (now, now),
    )


def index_competitions():
    now = iso_utc()
    return query_all(
        """
        SELECT c.*, u.username AS owner_name,
               COALESCE((SELECT MAX(ch.closes_at) FROM challenges ch WHERE ch.competition_id = c.id), c.starts_at) AS ends_at,
               (SELECT COUNT(*) FROM challenges ch WHERE ch.competition_id = c.id) AS challenge_count,
               (SELECT COUNT(*) FROM competition_registrations r WHERE r.competition_id = c.id) AS player_count,
               (SELECT title FROM challenges ch
                WHERE ch.competition_id = c.id AND ch.opens_at <= ? AND ch.closes_at > ?
                ORDER BY ch.position ASC LIMIT 1) AS live_title
        FROM competitions c
        JOIN users u ON u.id = c.owner_id
        WHERE c.status IN ('approved', 'archived')
        ORDER BY c.starts_at ASC, c.created_at DESC
        """,
        (now, now),
    )


def competition_sections(rows) -> dict[str, list]:
    now = iso_utc()
    running = []
    upcoming = []
    archived = []
    for row in rows:
        if row["status"] == "archived" or row["ends_at"] <= now:
            archived.append(row)
        elif row["starts_at"] <= now < row["ends_at"]:
            running.append(row)
        else:
            upcoming.append(row)
    running.sort(key=lambda row: row["starts_at"], reverse=True)
    upcoming.sort(key=lambda row: row["starts_at"])
    archived.sort(key=lambda row: row["ends_at"], reverse=True)
    return {"running": running, "upcoming": upcoming, "archived": archived}


def paginate_rows(rows: list, page: int, page_size: int = COMPETITION_PAGE_SIZE) -> dict:
    total = len(rows)
    total_pages = max(1, (total + page_size - 1) // page_size)
    current_page = min(max(1, page), total_pages)
    start = (current_page - 1) * page_size
    return {
        "items": rows[start : start + page_size],
        "page": current_page,
        "total_pages": total_pages,
        "total": total,
        "has_prev": current_page > 1,
        "has_next": current_page < total_pages,
        "prev_page": current_page - 1,
        "next_page": current_page + 1,
    }


@route("GET", r"/")
def home(request: Request) -> Response:
    if not admin_exists():
        return redirect("/setup")
    if request.current_user:
        return redirect("/dashboard")
    competitions = public_competitions()
    return render(
        request,
        "home.html",
        competitions=competitions[:COMPETITION_PREVIEW_LIMIT],
        competition_count=len(competitions),
        preview_limit=COMPETITION_PREVIEW_LIMIT,
    )


@route("GET", r"/setup")
def setup_get(request: Request) -> Response:
    if admin_exists():
        return redirect("/dashboard")
    return render(request, "setup.html")


@route("POST", r"/setup")
def setup_post(request: Request) -> Response:
    if admin_exists():
        return redirect("/dashboard")
    platform_name = form_text(request, "platform_name", 80) or "Time-Windowed CTF Arena"
    username = form_text(request, "username", 32)
    email = form_text(request, "email", 160)
    password = request.form.get("password", "")
    if len(platform_name) < 3:
        return render(request, "setup.html", form=request.form, form_error="Platform name must be at least 3 characters.", status=400)
    if not validate_username(username):
        return render(request, "setup.html", form=request.form, form_error="Username must be 3-32 letters, numbers, or underscores.", status=400)
    if "@" not in email or len(email) < 5:
        return render(request, "setup.html", form=request.form, form_error="Enter a valid email address.", status=400)
    if not validate_password(password):
        return render(request, "setup.html", form=request.form, form_error="Password must be at least 10 characters.", status=400)
    try:
        with transaction() as conn:
            if conn.execute("SELECT 1 FROM users WHERE role = 'admin' AND is_active = 1 LIMIT 1").fetchone():
                return redirect("/dashboard")
            now = iso_utc()
            set_platform_name(conn, platform_name)
            cur = conn.execute(
                """
                INSERT INTO users(username, email, password_hash, role, is_active, created_at)
                VALUES (?, ?, ?, 'admin', 1, ?)
                """,
                (username, email, hash_password(password), now),
            )
            user_id = cur.lastrowid
            conn.execute("UPDATE sessions SET user_id = ? WHERE id = ?", (user_id, request.session_id))
            audit(conn, user_id, "setup_admin", "user", user_id)
    except Exception:
        return render(request, "setup.html", form=request.form, form_error="Username or email is already in use.", status=409)
    return redirect(with_notice("/dashboard", "Admin account created."))


@route("GET", r"/login")
def login_get(request: Request) -> Response:
    if not admin_exists():
        return redirect("/setup")
    return render(request, "login.html", next_path=request.query.get("next", "/dashboard"))


@route("POST", r"/login")
def login_post(request: Request) -> Response:
    if not admin_exists():
        return redirect("/setup")
    username = form_text(request, "username", 80)
    password = request.form.get("password", "")
    next_path = request.form.get("next", "/dashboard")
    with connect() as conn:
        user = conn.execute(
            "SELECT * FROM users WHERE (username = ? OR email = ?) AND is_active = 1",
            (username, username),
        ).fetchone()
    if not user or not verify_password(password, user["password_hash"]):
        return render(request, "login.html", form=request.form, next_path=next_path, form_error="Invalid login credentials.", status=403)
    with transaction() as conn:
        conn.execute("UPDATE sessions SET user_id = ? WHERE id = ?", (user["id"], request.session_id))
        audit(conn, user["id"], "login", "user", user["id"])
    if not next_path.startswith("/") or next_path.startswith("//"):
        next_path = "/dashboard"
    return redirect(next_path)


@route("POST", r"/logout")
def logout_post(request: Request) -> Response:
    with transaction() as conn:
        if request.session_id:
            conn.execute("DELETE FROM sessions WHERE id = ?", (request.session_id,))
        if request.current_user:
            audit(conn, request.current_user["id"], "logout", "user", request.current_user["id"])
    response = redirect("/")
    response.headers.append(("Set-Cookie", clear_cookie()))
    return response


@route("GET", r"/register")
def register_get(request: Request) -> Response:
    if not admin_exists():
        return redirect("/setup")
    return render(request, "register.html")


@route("POST", r"/register")
def register_post(request: Request) -> Response:
    if not admin_exists():
        return redirect("/setup")
    username = form_text(request, "username", 32)
    email = form_text(request, "email", 160)
    password = request.form.get("password", "")
    if not validate_username(username):
        return render(request, "register.html", form=request.form, form_error="Username must be 3-32 letters, numbers, or underscores.", status=400)
    if "@" not in email or len(email) < 5:
        return render(request, "register.html", form=request.form, form_error="Enter a valid email address.", status=400)
    if not validate_password(password):
        return render(request, "register.html", form=request.form, form_error="Password must be at least 10 characters.", status=400)
    try:
        with transaction() as conn:
            now = iso_utc()
            cur = conn.execute(
                """
                INSERT INTO users(username, email, password_hash, role, is_active, created_at)
                VALUES (?, ?, ?, 'player', 1, ?)
                """,
                (username, email, hash_password(password), now),
            )
            user_id = cur.lastrowid
            conn.execute("UPDATE sessions SET user_id = ? WHERE id = ?", (user_id, request.session_id))
            audit(conn, user_id, "register", "user", user_id)
    except Exception:
        return render(request, "register.html", form=request.form, form_error="Username or email is already in use.", status=409)
    return redirect(with_notice("/dashboard", "Registration complete."))


@route("GET", r"/dashboard")
def dashboard(request: Request) -> Response:
    missing = require_login(request)
    if missing:
        return missing
    user = request.current_user
    with connect() as conn:
        latest_application = conn.execute(
            "SELECT * FROM organizer_applications WHERE user_id = ? ORDER BY created_at DESC LIMIT 1",
            (user["id"],),
        ).fetchone()
        owned = conn.execute(
            """
            SELECT c.*,
                   COALESCE((SELECT MAX(ch.closes_at) FROM challenges ch WHERE ch.competition_id = c.id), c.starts_at) AS ends_at,
                   (SELECT COUNT(*) FROM challenges ch WHERE ch.competition_id = c.id) AS challenge_count
            FROM competitions c
            WHERE c.owner_id = ?
            ORDER BY c.updated_at DESC
            """,
            (user["id"],),
        ).fetchall()
        collaborative = conn.execute(
            """
            SELECT c.*, cc.role AS collaboration_role,
                   COALESCE((SELECT MAX(ch.closes_at) FROM challenges ch WHERE ch.competition_id = c.id), c.starts_at) AS ends_at,
                   (SELECT COUNT(*) FROM challenges ch WHERE ch.competition_id = c.id) AS challenge_count
            FROM competition_collaborators cc
            JOIN competitions c ON c.id = cc.competition_id
            WHERE cc.user_id = ?
            ORDER BY cc.created_at DESC
            """,
            (user["id"],),
        ).fetchall()
        registrations = conn.execute(
            """
            SELECT c.*, r.created_at AS joined_at,
                   COALESCE((SELECT MAX(ch.closes_at) FROM challenges ch WHERE ch.competition_id = c.id), c.starts_at) AS ends_at
            FROM competition_registrations r
            JOIN competitions c ON c.id = r.competition_id
            WHERE r.user_id = ?
            ORDER BY r.created_at DESC
            """,
            (user["id"],),
        ).fetchall()
    competitions = public_competitions()
    return render(
        request,
        "dashboard.html",
        latest_application=latest_application,
        owned_competitions=owned,
        collaborative_competitions=collaborative,
        registrations=registrations,
        competitions=competitions[:COMPETITION_PREVIEW_LIMIT],
        competition_count=len(competitions),
        preview_limit=COMPETITION_PREVIEW_LIMIT,
    )


@route("GET", r"/profile")
def profile_edit_get(request: Request) -> Response:
    missing = require_login(request)
    if missing:
        return missing
    return redirect(f"/users/{quote(request.current_user['username'])}?edit=1")


@route("POST", r"/profile")
def profile_edit_post(request: Request) -> Response:
    missing = require_login(request)
    if missing:
        return missing
    payload, form_error = profile_payload(request)
    if form_error:
        return redirect(with_error(f"/users/{quote(request.current_user['username'])}?edit=1", form_error))
    with transaction() as conn:
        conn.execute(
            """
            UPDATE users
            SET display_name = ?, affiliation = ?, website_url = ?, bio = ?
            WHERE id = ?
            """,
            (
                payload["display_name"],
                payload["affiliation"],
                payload["website_url"],
                payload["bio"],
                request.current_user["id"],
            ),
        )
        audit(conn, request.current_user["id"], "update_profile", "user", request.current_user["id"])
    return redirect(with_notice(f"/users/{quote(request.current_user['username'])}", "Profile updated."))


@route("GET", r"/users")
def users_index(request: Request) -> Response:
    query = form_query = clip(request.query.get("q", ""), 80)
    where = "WHERE u.is_active = 1"
    params: list[str] = []
    if query:
        like = f"%{query}%"
        where += " AND (u.username LIKE ? OR u.display_name LIKE ? OR u.affiliation LIKE ? OR u.email LIKE ?)"
        params.extend([like, like, like, like])
    with connect() as conn:
        users = conn.execute(
            f"""
            SELECT u.*,
                   (SELECT COUNT(*) FROM competition_registrations r WHERE r.user_id = u.id) AS joined_count,
                   (SELECT COUNT(*) FROM solves s WHERE s.user_id = u.id) AS solve_count,
                   (SELECT COUNT(*) FROM competitions c WHERE c.owner_id = u.id) AS hosted_count
            FROM users u
            {where}
            ORDER BY
              CASE u.role WHEN 'admin' THEN 0 WHEN 'organizer' THEN 1 ELSE 2 END,
              u.username COLLATE NOCASE ASC
            """,
            tuple(params),
        ).fetchall()
    return render(request, "users.html", users=users, q=form_query)


@route("GET", r"/users/(?P<username>[A-Za-z0-9_]{3,32})")
def user_profile(request: Request, username: str) -> Response:
    with connect() as conn:
        user = conn.execute("SELECT * FROM users WHERE username = ? AND is_active = 1", (username,)).fetchone()
        if not user:
            return error_page(request, 404, "User not found.")
        can_edit_profile = bool(request.current_user and request.current_user["id"] == user["id"])
        show_private = bool(can_edit_profile or is_admin(request.current_user))
        status_clause = "" if show_private else "AND c.status IN ('approved', 'archived')"
        owned_competitions = conn.execute(
            f"""
            SELECT c.*,
                   COALESCE((SELECT MAX(ch.closes_at) FROM challenges ch WHERE ch.competition_id = c.id), c.starts_at) AS ends_at,
                   (SELECT COUNT(*) FROM challenges ch WHERE ch.competition_id = c.id) AS challenge_count,
                   (SELECT COUNT(*) FROM competition_registrations r WHERE r.competition_id = c.id) AS player_count
            FROM competitions c
            WHERE c.owner_id = ? {status_clause}
            ORDER BY c.starts_at DESC
            """,
            (user["id"],),
        ).fetchall()
        joined_competitions = conn.execute(
            f"""
            SELECT c.*, r.created_at AS joined_at,
                   COALESCE((SELECT MAX(ch.closes_at) FROM challenges ch WHERE ch.competition_id = c.id), c.starts_at) AS ends_at,
                   (SELECT COUNT(*) FROM challenges ch WHERE ch.competition_id = c.id) AS challenge_count,
                   (SELECT COUNT(*) FROM competition_registrations rr WHERE rr.competition_id = c.id) AS player_count
            FROM competition_registrations r
            JOIN competitions c ON c.id = r.competition_id
            WHERE r.user_id = ? {status_clause}
            ORDER BY r.created_at DESC
            """,
            (user["id"],),
        ).fetchall()
        placements = []
        for competition in joined_competitions:
            board = scoreboard(conn, competition["id"], 500)
            placement = None
            for index, row in enumerate(board, start=1):
                if row["user_id"] == user["id"]:
                    placement = {
                        "rank": index,
                        "score": row["score"],
                        "solved_count": row["solved_count"],
                        "last_solve": row["last_solve"],
                    }
                    break
            placements.append({"competition": competition, "placement": placement})
        recent_submissions = conn.execute(
            f"""
            SELECT s.*, c.title AS competition_title, c.status AS competition_status, ch.title AS challenge_title
            FROM submissions s
            JOIN competitions c ON c.id = s.competition_id
            JOIN challenges ch ON ch.id = s.challenge_id
            WHERE s.user_id = ? {" " if show_private else "AND c.status IN ('approved', 'archived')"}
            ORDER BY s.created_at DESC
            LIMIT 50
            """,
            (user["id"],),
        ).fetchall()
        solved_count = conn.execute("SELECT COUNT(*) AS n FROM solves WHERE user_id = ?", (user["id"],)).fetchone()["n"]
    return render(
        request,
        "profile.html",
        profile_user=user,
        can_edit_profile=can_edit_profile,
        show_edit=request.query.get("edit") == "1" and can_edit_profile,
        owned_competitions=owned_competitions,
        joined_competitions=joined_competitions,
        placements=placements,
        recent_submissions=recent_submissions,
        solved_count=solved_count,
    )


@route("POST", r"/organizer/apply")
def organizer_apply(request: Request) -> Response:
    missing = require_login(request)
    if missing:
        return missing
    user = request.current_user
    if user["role"] in ("organizer", "admin"):
        return redirect(with_notice("/dashboard", "You already have organizer permissions."))
    reason = form_text(request, "reason", 2000)
    if len(reason) < 20:
        return redirect(with_error("/dashboard", "The request reason must be at least 20 characters."))
    with transaction() as conn:
        pending = conn.execute(
            "SELECT id FROM organizer_applications WHERE user_id = ? AND status = 'pending'",
            (user["id"],),
        ).fetchone()
        if pending:
            return redirect(with_notice("/dashboard", "You already have a pending organizer request."))
        cur = conn.execute(
            "INSERT INTO organizer_applications(user_id, reason, status, created_at) VALUES (?, ?, 'pending', ?)",
            (user["id"], reason, iso_utc()),
        )
        audit(conn, user["id"], "request_organizer", "organizer_application", cur.lastrowid)
    return redirect(with_notice("/dashboard", "Organizer request submitted for admin review."))


@route("GET", r"/admin")
def admin_dashboard(request: Request) -> Response:
    missing = require_roles(request, "admin")
    if missing:
        return missing
    with connect() as conn:
        applications = conn.execute(
            """
            SELECT a.*, u.username, u.email
            FROM organizer_applications a
            JOIN users u ON u.id = a.user_id
            ORDER BY CASE a.status WHEN 'pending' THEN 0 ELSE 1 END, a.created_at DESC
            """
        ).fetchall()
        competitions = conn.execute(
            """
            SELECT c.*, u.username AS owner_name,
                   COALESCE((SELECT MAX(ch.closes_at) FROM challenges ch WHERE ch.competition_id = c.id), c.starts_at) AS ends_at,
                   (SELECT COUNT(*) FROM challenges ch WHERE ch.competition_id = c.id) AS challenge_count,
                   (SELECT COUNT(*) FROM competition_registrations r WHERE r.competition_id = c.id) AS player_count
            FROM competitions c
            JOIN users u ON u.id = c.owner_id
            ORDER BY CASE c.status WHEN 'pending_review' THEN 0 WHEN 'approved' THEN 1 ELSE 2 END, c.updated_at DESC
            """
        ).fetchall()
        users = conn.execute(
            """
            SELECT u.*,
                   (SELECT COUNT(*) FROM competition_registrations r WHERE r.user_id = u.id) AS joined_count,
                   (SELECT COUNT(*) FROM solves s WHERE s.user_id = u.id) AS solve_count
            FROM users u
            ORDER BY u.created_at DESC
            """
        ).fetchall()
    return render(request, "admin.html", applications=applications, competitions=competitions, users=users)


@route("POST", r"/admin/organizer-applications/(?P<app_id>\d+)/review")
def admin_review_application(request: Request, app_id: str) -> Response:
    missing = require_roles(request, "admin")
    if missing:
        return missing
    decision = request.form.get("decision", "")
    note = form_text(request, "review_note", 1000)
    if decision not in ("approved", "rejected"):
        return error_page(request, 400, "Invalid review decision.")
    with transaction() as conn:
        application = conn.execute("SELECT * FROM organizer_applications WHERE id = ?", (app_id,)).fetchone()
        if not application:
            return error_page(request, 404, "Application not found.")
        conn.execute(
            """
            UPDATE organizer_applications
            SET status = ?, reviewed_by = ?, reviewed_at = ?, review_note = ?
            WHERE id = ?
            """,
            (decision, request.current_user["id"], iso_utc(), note, app_id),
        )
        if decision == "approved":
            conn.execute("UPDATE users SET role = 'organizer' WHERE id = ?", (application["user_id"],))
        audit(conn, request.current_user["id"], f"review_organizer_{decision}", "organizer_application", int(app_id))
    return redirect(with_notice("/admin", "Organizer application updated."))


@route("POST", r"/admin/competitions/(?P<comp_id>\d+)/review")
def admin_review_competition(request: Request, comp_id: str) -> Response:
    missing = require_roles(request, "admin")
    if missing:
        return missing
    decision = request.form.get("decision", "")
    note = form_text(request, "review_note", 1000)
    if decision not in ("approved", "rejected", "archived"):
        return error_page(request, 400, "Invalid review decision.")
    with transaction() as conn:
        comp = conn.execute("SELECT * FROM competitions WHERE id = ?", (comp_id,)).fetchone()
        if not comp:
            return error_page(request, 404, "Competition not found.")
        if decision == "approved":
            count = conn.execute("SELECT COUNT(*) AS n FROM challenges WHERE competition_id = ?", (comp_id,)).fetchone()["n"]
            if count < 1:
                return redirect(with_error("/admin", "A competition needs at least one challenge before approval."))
        conn.execute(
            """
            UPDATE competitions
            SET status = ?, review_note = ?, reviewed_by = ?, reviewed_at = ?, updated_at = ?
            WHERE id = ?
            """,
            (decision, note, request.current_user["id"], iso_utc(), iso_utc(), comp_id),
        )
        audit(conn, request.current_user["id"], f"review_competition_{decision}", "competition", int(comp_id))
    return redirect(with_notice("/admin", "Competition review status updated."))


@route("POST", r"/admin/users/(?P<user_id>\d+)/role")
def admin_user_role(request: Request, user_id: str) -> Response:
    missing = require_roles(request, "admin")
    if missing:
        return missing
    role = request.form.get("role", "")
    if role not in ("admin", "organizer", "player"):
        return error_page(request, 400, "Invalid role.")
    with transaction() as conn:
        target = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if not target:
            return error_page(request, 404, "User not found.")
        if target["role"] == "admin" and role != "admin":
            admins = conn.execute("SELECT COUNT(*) AS n FROM users WHERE role = 'admin' AND is_active = 1").fetchone()["n"]
            if admins <= 1:
                return redirect(with_error("/admin", "You cannot remove the last active admin."))
        conn.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))
        audit(conn, request.current_user["id"], "change_user_role", "user", int(user_id), {"role": role})
    return redirect(with_notice("/admin", "User role updated."))


@route("POST", r"/admin/users/(?P<user_id>\d+)/toggle")
def admin_user_toggle(request: Request, user_id: str) -> Response:
    missing = require_roles(request, "admin")
    if missing:
        return missing
    with transaction() as conn:
        target = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if not target:
            return error_page(request, 404, "User not found.")
        if int(user_id) == request.current_user["id"]:
            return redirect(with_error("/admin", "You cannot disable your own active account."))
        if target["role"] == "admin" and target["is_active"]:
            admins = conn.execute("SELECT COUNT(*) AS n FROM users WHERE role = 'admin' AND is_active = 1").fetchone()["n"]
            if admins <= 1:
                return redirect(with_error("/admin", "You cannot disable the last active admin."))
        next_active = 0 if target["is_active"] else 1
        conn.execute("UPDATE users SET is_active = ? WHERE id = ?", (next_active, user_id))
        if not next_active:
            conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
        audit(conn, request.current_user["id"], "toggle_user_active", "user", int(user_id), {"is_active": next_active})
    return redirect(with_notice("/admin", "User status updated."))


@route("POST", r"/admin/users/(?P<user_id>\d+)/password")
def admin_user_password(request: Request, user_id: str) -> Response:
    missing = require_roles(request, "admin")
    if missing:
        return missing
    password = request.form.get("password", "")
    if not validate_password(password):
        return redirect(with_error("/admin", "New password must be at least 10 characters."))
    with transaction() as conn:
        target = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if not target:
            return error_page(request, 404, "User not found.")
        conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (hash_password(password), user_id))
        if int(user_id) != request.current_user["id"]:
            conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
        audit(conn, request.current_user["id"], "reset_user_password", "user", int(user_id))
    return redirect(with_notice("/admin", "User password updated."))


@route("GET", r"/competitions")
def competitions_index(request: Request) -> Response:
    my_competitions = []
    if request.current_user:
        my_competitions = query_all(
            """
            SELECT c.*,
                   COALESCE((SELECT MAX(ch.closes_at) FROM challenges ch WHERE ch.competition_id = c.id), c.starts_at) AS ends_at,
                   (SELECT COUNT(*) FROM challenges ch WHERE ch.competition_id = c.id) AS challenge_count
            FROM competitions c
            WHERE c.owner_id = ?
            ORDER BY c.updated_at DESC
            """,
            (request.current_user["id"],),
        )
    sections = competition_sections(index_competitions())
    section_labels = {
        "running": "running CTFs",
        "upcoming": "upcoming CTFs",
        "archived": "archived CTFs",
    }
    browse_section = request.query.get("section", "")
    page = nonnegative_int(request.query.get("page", "1"), 1, 1)
    paginated = None
    if browse_section in sections:
        paginated = paginate_rows(sections[browse_section], page)
    return render(
        request,
        "competitions.html",
        running_competitions=sections["running"][:COMPETITION_PREVIEW_LIMIT],
        upcoming_competitions=sections["upcoming"][:COMPETITION_PREVIEW_LIMIT],
        archived_competitions=sections["archived"][:COMPETITION_PREVIEW_LIMIT],
        section_counts={key: len(value) for key, value in sections.items()},
        preview_limit=COMPETITION_PREVIEW_LIMIT,
        browse_section=browse_section if browse_section in sections else None,
        browse_label=section_labels.get(browse_section),
        paginated=paginated,
        my_competitions=my_competitions,
    )


@route("GET", r"/competitions/new")
def competition_new(request: Request) -> Response:
    missing = require_roles(request, "admin", "organizer")
    if missing:
        return missing
    default_start = to_local_value(iso_utc(utcnow() + timedelta(hours=1)))
    return render(request, "competition_form.html", competition=None, default_start=default_start)


@route("GET", r"/competitions/import")
def competition_import_get(request: Request) -> Response:
    missing = require_roles(request, "admin", "organizer")
    if missing:
        return missing
    return render(request, "competition_import.html")


@route("POST", r"/competitions/import")
def competition_import_post(request: Request) -> Response:
    missing = require_roles(request, "admin", "organizer")
    if missing:
        return missing
    raw_config = request.form.get("config_json", "")
    try:
        payload = json.loads(raw_config)
        competition_payload = payload["competition"]
        challenge_payloads = payload.get("challenges", [])
        starts_at = iso_utc(parse_iso(competition_payload.get("starts_at") or iso_utc(utcnow() + timedelta(hours=1))))
    except Exception:
        return render(request, "competition_import.html", form=request.form, form_error="Paste a valid competition export JSON file.", status=400)
    title = clip(str(competition_payload.get("title", "")), 120)
    if len(title) < 3:
        return render(request, "competition_import.html", form=request.form, form_error="Imported competition title must be at least 3 characters.", status=400)
    with transaction() as conn:
        now = iso_utc()
        final_slug = unique_competition_slug(conn, str(competition_payload.get("slug", "")), title)
        cur = conn.execute(
            """
            INSERT INTO competitions(
                title, slug, summary, rules, starts_at, registration_open, team_mode, scoring_mode,
                scoreboard_freeze_minutes, scoreboard_preview_limit, writeup_url, owner_id, status, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'draft', ?, ?)
            """,
            (
                title,
                final_slug,
                clip(str(competition_payload.get("summary", "")), 1000),
                clip(str(competition_payload.get("rules", "")), 4000),
                starts_at,
                1 if competition_payload.get("registration_open", True) else 0,
                normalize_team_mode(str(competition_payload.get("team_mode", "individual"))),
                normalize_scoring_mode(str(competition_payload.get("scoring_mode", "fixed"))),
                nonnegative_int(competition_payload.get("scoreboard_freeze_minutes", 0), 0, 0),
                bounded_int(competition_payload.get("scoreboard_preview_limit", SCOREBOARD_PREVIEW_LIMIT), SCOREBOARD_PREVIEW_LIMIT, 1, 100),
                clip(str(competition_payload.get("writeup_url", "")), 500),
                request.current_user["id"],
                now,
                now,
            ),
        )
        comp_id = cur.lastrowid
        for index, item in enumerate(challenge_payloads, start=1):
            challenge_title = clip(str(item.get("title", f"Challenge {index}")), 120)
            challenge_slug = unique_challenge_slug(conn, comp_id, str(item.get("slug", "")), challenge_title)
            duration = nonnegative_int(item.get("duration_minutes", 15), 15, 1)
            placeholder_flag = f"FLAG{{replace_me_{challenge_slug}}}"
            flag_type = normalize_flag_type(str(item.get("flag_type", "static")))
            flag_pattern = str(item.get("flag_pattern") or "").strip() if flag_type == "regex" else None
            flag_hash = hash_flag_pattern(flag_pattern) if flag_type == "regex" and flag_pattern else hash_flag(placeholder_flag)
            if flag_type == "regex" and not flag_pattern:
                flag_type = "static"
                flag_pattern = None
            conn.execute(
                """
                INSERT INTO challenges(
                    competition_id, title, slug, category, tags, body, points, flag_type, flag_hash, flag_pattern,
                    position, duration_minutes, hint_text, hint_cost, hint_unlock_minutes,
                    opens_at, closes_at, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    comp_id,
                    challenge_title,
                    challenge_slug,
                    clip(str(item.get("category", "misc")), 40) or "misc",
                    normalize_tags(str(item.get("tags", ""))),
                    clip(str(item.get("body", "")), 8000) or "Imported challenge body.",
                    nonnegative_int(item.get("points", 100), 100, 1),
                    flag_type,
                    flag_hash,
                    flag_pattern,
                    index,
                    duration,
                    clip(str(item.get("hint_text", "")), 1200),
                    nonnegative_int(item.get("hint_cost", 0), 0, 0),
                    nonnegative_int(item.get("hint_unlock_minutes", 0), 0, 0),
                    starts_at,
                    iso_utc(parse_iso(starts_at) + timedelta(minutes=duration)),
                    now,
                    now,
                ),
            )
        recalculate_challenge_schedule(conn, comp_id)
        create_collaboration_invite(conn, comp_id, request.current_user["id"], role="editor", expires_days=14)
        audit(conn, request.current_user["id"], "import_competition", "competition", comp_id, {"challenge_count": len(challenge_payloads)})
    return redirect(with_notice(f"/competitions/{comp_id}", "Competition imported as a draft. Review placeholder flags before approval."))


@route("POST", r"/competitions")
def competition_create(request: Request) -> Response:
    missing = require_roles(request, "admin", "organizer")
    if missing:
        return missing
    payload, form_error = competition_form_payload(request)
    if form_error:
        return render(request, "competition_form.html", competition=None, form=request.form, form_error=form_error, status=400)
    if len(payload["title"]) < 3:
        return render(request, "competition_form.html", competition=None, form=request.form, form_error="Competition title must be at least 3 characters.", status=400)
    with transaction() as conn:
        now = iso_utc()
        final_slug = unique_competition_slug(conn, payload["slug"], payload["title"])
        cur = conn.execute(
            """
            INSERT INTO competitions(
                title, slug, summary, rules, starts_at, registration_open, team_mode, scoring_mode,
                scoreboard_freeze_minutes, scoreboard_preview_limit, writeup_url, owner_id, status, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'draft', ?, ?)
            """,
            (
                payload["title"],
                final_slug,
                payload["summary"],
                payload["rules"],
                payload["starts_at"],
                payload["registration_open"],
                payload["team_mode"],
                payload["scoring_mode"],
                payload["scoreboard_freeze_minutes"],
                payload["scoreboard_preview_limit"],
                payload["writeup_url"],
                request.current_user["id"],
                now,
                now,
            ),
        )
        comp_id = cur.lastrowid
        create_collaboration_invite(conn, comp_id, request.current_user["id"], role="editor", expires_days=14)
        audit(conn, request.current_user["id"], "create_competition", "competition", comp_id)
    return redirect(with_notice(f"/competitions/{comp_id}", "Competition created. Add challenges, then submit it for admin review."))


@route("GET", r"/competitions/(?P<comp_id>\d+)/edit")
def competition_edit(request: Request, comp_id: str) -> Response:
    missing = require_login(request)
    if missing:
        return missing
    competition = competition_by_id(int(comp_id))
    if not competition:
        return error_page(request, 404, "Competition not found.")
    if not can_manage_competition(request.current_user, competition):
        return error_page(request, 403, "You do not have permission to edit this competition.")
    return render(request, "competition_form.html", competition=competition)


@route("POST", r"/competitions/(?P<comp_id>\d+)/edit")
def competition_update(request: Request, comp_id: str) -> Response:
    missing = require_login(request)
    if missing:
        return missing
    competition = competition_by_id(int(comp_id))
    if not competition:
        return error_page(request, 404, "Competition not found.")
    if not can_manage_competition(request.current_user, competition):
        return error_page(request, 403, "You do not have permission to edit this competition.")
    payload, form_error = competition_form_payload(request)
    if form_error:
        return render(request, "competition_form.html", competition=competition, form=request.form, form_error=form_error, status=400)
    if len(payload["title"]) < 3:
        return render(request, "competition_form.html", competition=competition, form=request.form, form_error="Competition title must be at least 3 characters.", status=400)
    with transaction() as conn:
        final_slug = unique_competition_slug(conn, payload["slug"], payload["title"], exclude_id=int(comp_id))
        status = competition["status"]
        if status == "approved" and not is_admin(request.current_user):
            status = "pending_review"
        conn.execute(
            """
            UPDATE competitions
            SET title = ?, slug = ?, summary = ?, rules = ?, starts_at = ?, registration_open = ?,
                team_mode = ?, scoring_mode = ?, scoreboard_freeze_minutes = ?, scoreboard_preview_limit = ?, writeup_url = ?,
                status = ?, updated_at = ?
            WHERE id = ?
            """,
            (
                payload["title"],
                final_slug,
                payload["summary"],
                payload["rules"],
                payload["starts_at"],
                payload["registration_open"],
                payload["team_mode"],
                payload["scoring_mode"],
                payload["scoreboard_freeze_minutes"],
                payload["scoreboard_preview_limit"],
                payload["writeup_url"],
                status,
                iso_utc(),
                comp_id,
            ),
        )
        recalculate_challenge_schedule(conn, int(comp_id))
        audit(conn, request.current_user["id"], "update_competition", "competition", int(comp_id))
    return redirect(with_notice(f"/competitions/{comp_id}", "Competition updated."))


@route("POST", r"/competitions/(?P<comp_id>\d+)/submit-review")
def competition_submit_review(request: Request, comp_id: str) -> Response:
    missing = require_login(request)
    if missing:
        return missing
    competition = competition_by_id(int(comp_id))
    if not competition:
        return error_page(request, 404, "Competition not found.")
    if not can_manage_competition(request.current_user, competition):
        return error_page(request, 403, "You do not have permission to submit this competition for review.")
    with transaction() as conn:
        count = conn.execute("SELECT COUNT(*) AS n FROM challenges WHERE competition_id = ?", (comp_id,)).fetchone()["n"]
        if count < 1:
            return redirect(with_error(f"/competitions/{comp_id}", "Add at least one challenge before submitting for review."))
        conn.execute(
            "UPDATE competitions SET status = 'pending_review', updated_at = ? WHERE id = ?",
            (iso_utc(), comp_id),
        )
        audit(conn, request.current_user["id"], "submit_competition_review", "competition", int(comp_id))
    return redirect(with_notice(f"/competitions/{comp_id}", "Competition submitted for admin review."))


@route("POST", r"/competitions/(?P<comp_id>\d+)/register")
def competition_register(request: Request, comp_id: str) -> Response:
    missing = require_login(request)
    if missing:
        return missing
    with transaction() as conn:
        competition = conn.execute("SELECT * FROM competitions WHERE id = ?", (comp_id,)).fetchone()
        if not competition or competition["status"] != "approved":
            return error_page(request, 404, "No open competition found.")
        if not competition["registration_open"]:
            return redirect(with_error(f"/competitions/{comp_id}", "Registration is closed for this competition."))
        if competition_end_at(conn, int(comp_id), competition["starts_at"]) <= iso_utc():
            return redirect(with_error(f"/competitions/{comp_id}", "This competition has already ended."))
        conn.execute(
            "INSERT OR IGNORE INTO competition_registrations(competition_id, user_id, created_at) VALUES (?, ?, ?)",
            (comp_id, request.current_user["id"], iso_utc()),
        )
        audit(conn, request.current_user["id"], "register_competition", "competition", int(comp_id))
    return redirect(with_notice(f"/competitions/{comp_id}", "You joined the competition."))


@route("GET", r"/competitions/(?P<comp_id>\d+)")
def competition_detail(request: Request, comp_id: str) -> Response:
    competition = competition_by_id(int(comp_id))
    if not competition:
        return error_page(request, 404, "Competition not found.")
    manager = can_manage_competition(request.current_user, competition)
    collab_role = collaboration_role(request.current_user, competition)
    if not can_view_competition(request.current_user, competition):
        return error_page(request, 404, "Competition not found.")
    with connect() as conn:
        server_now = iso_utc()
        active = active_challenge(conn, int(comp_id))
        active_file = latest_challenge_file(conn, active["id"]) if active else None
        challenges = conn.execute(
            """
            SELECT challenges.*,
                   (SELECT COUNT(*) FROM challenge_files f WHERE f.challenge_id = challenges.id) AS dist_file_count,
                   (SELECT original_filename FROM challenge_files f
                    WHERE f.challenge_id = challenges.id
                    ORDER BY f.created_at DESC, f.id DESC LIMIT 1) AS latest_file_name,
                   (SELECT size_bytes FROM challenge_files f
                    WHERE f.challenge_id = challenges.id
                    ORDER BY f.created_at DESC, f.id DESC LIMIT 1) AS latest_file_size,
                   (SELECT COUNT(*) FROM solves s WHERE s.challenge_id = challenges.id) AS solve_count
            FROM challenges
            WHERE competition_id = ?
            ORDER BY position ASC, opens_at ASC, id ASC
            """,
            (comp_id,),
        ).fetchall()
        ends_at = competition_end_at(conn, int(comp_id), competition["starts_at"])
        public_archive = competition_is_archived(competition, ends_at, server_now)
        public_running = competition_is_running(competition, ends_at, server_now)
        public_upcoming = competition_is_upcoming(competition, server_now)
        competition_phase = "archived" if public_archive else "running" if public_running else "upcoming" if public_upcoming else competition["status"]
        can_see_all_challenges = bool(collab_role or public_archive)
        freeze_cutoff = competition_freeze_cutoff(conn, int(comp_id))
        scoreboard_limit = scoreboard_preview_limit_for(competition)
        full_board = scoreboard(conn, int(comp_id), None)
        board = full_board[:scoreboard_limit]
        registered = False
        if request.current_user:
            registered = bool(
                conn.execute(
                    "SELECT 1 FROM competition_registrations WHERE competition_id = ? AND user_id = ?",
                    (comp_id, request.current_user["id"]),
                ).fetchone()
            )
        recent_submissions = []
        my_submissions = []
        invites = []
        collaborators = []
        announcements = conn.execute(
            """
            SELECT a.*, u.username AS author_name
            FROM competition_announcements a
            LEFT JOIN users u ON u.id = a.created_by
            WHERE a.competition_id = ?
            ORDER BY a.created_at DESC
            LIMIT 10
            """,
            (comp_id,),
        ).fetchall()
        audit_events = []
        if manager:
            recent_submissions = conn.execute(
                """
                SELECT s.*, u.username, ch.title AS challenge_title
                FROM submissions s
                JOIN users u ON u.id = s.user_id
                JOIN challenges ch ON ch.id = s.challenge_id
                WHERE s.competition_id = ?
                ORDER BY s.created_at DESC
                LIMIT 30
                """,
                (comp_id,),
            ).fetchall()
            invites = conn.execute(
                """
                SELECT i.*, u.username AS creator_name
                FROM competition_collaborator_invites i
                LEFT JOIN users u ON u.id = i.created_by
                WHERE i.competition_id = ?
                ORDER BY i.created_at DESC
                """,
                (comp_id,),
            ).fetchall()
            collaborators = conn.execute(
                """
                SELECT c.*, u.username, u.email, inviter.username AS invited_by_name
                FROM competition_collaborators c
                JOIN users u ON u.id = c.user_id
                LEFT JOIN users inviter ON inviter.id = c.invited_by
                WHERE c.competition_id = ?
                ORDER BY c.created_at DESC
                """,
                (comp_id,),
            ).fetchall()
            audit_events = conn.execute(
                """
                SELECT a.*, u.username AS actor_name
                FROM audit_log a
                LEFT JOIN users u ON u.id = a.actor_id
                WHERE (a.target_type = 'competition' AND a.target_id = ?)
                   OR (a.target_type = 'challenge' AND a.target_id IN (SELECT id FROM challenges WHERE competition_id = ?))
                ORDER BY a.created_at DESC
                LIMIT 30
                """,
                (comp_id, comp_id),
            ).fetchall()
        if request.current_user:
            my_submissions = conn.execute(
                """
                SELECT s.*, ch.title AS challenge_title
                FROM submissions s
                JOIN challenges ch ON ch.id = s.challenge_id
                WHERE s.competition_id = ? AND s.user_id = ?
                ORDER BY s.created_at DESC
                LIMIT 20
                """,
                (comp_id, request.current_user["id"]),
            ).fetchall()
    return render(
        request,
        "competition_detail.html",
        competition=competition,
        active_challenge=active,
        active_file=active_file,
        active_hint_unlocked=challenge_hint_unlocked(active, server_now) if active else False,
        challenges=challenges,
        visible_challenges=challenges if can_see_all_challenges else [],
        scoreboard=board,
        scoreboard_total=len(full_board),
        scoreboard_preview_limit=scoreboard_limit,
        registered=registered,
        can_register=bool(competition["status"] == "approved" and competition["registration_open"] and ends_at > server_now),
        manager=manager,
        collaboration_role=collab_role,
        competition_phase=competition_phase,
        public_archive=public_archive,
        public_running=public_running,
        public_upcoming=public_upcoming,
        can_see_all_challenges=can_see_all_challenges,
        recent_submissions=recent_submissions,
        my_submissions=my_submissions,
        announcements=announcements,
        collaborators=collaborators,
        invites=invites,
        audit_events=audit_events,
        ends_at=ends_at,
        freeze_cutoff=freeze_cutoff,
        server_now=server_now,
    )


@route("GET", r"/competitions/(?P<comp_id>\d+)/scoreboard")
def competition_scoreboard(request: Request, comp_id: str) -> Response:
    competition = competition_by_id(int(comp_id))
    if not competition:
        return error_page(request, 404, "Competition not found.")
    if not can_view_competition(request.current_user, competition):
        return error_page(request, 404, "Competition not found.")
    page = nonnegative_int(request.query.get("page", "1"), 1, 1)
    with connect() as conn:
        server_now = iso_utc()
        ends_at = competition_end_at(conn, int(comp_id), competition["starts_at"])
        freeze_cutoff = competition_freeze_cutoff(conn, int(comp_id))
        board = scoreboard(conn, int(comp_id), None)
    return render(
        request,
        "scoreboard.html",
        competition=competition,
        paginated=paginate_rows(board, page, SCOREBOARD_PAGE_SIZE),
        scoreboard_page_size=SCOREBOARD_PAGE_SIZE,
        freeze_cutoff=freeze_cutoff,
        server_now=server_now,
        ends_at=ends_at,
    )


@route("GET", r"/competitions/(?P<comp_id>\d+)/challenges/new")
def challenge_new(request: Request, comp_id: str) -> Response:
    missing = require_login(request)
    if missing:
        return missing
    competition = competition_by_id(int(comp_id))
    if not competition:
        return error_page(request, 404, "Competition not found.")
    if not can_manage_competition(request.current_user, competition):
        return error_page(request, 403, "You do not have permission to add challenges.")
    return render(request, "challenge_form.html", competition=competition, challenge=None, default_duration=15)


@route("POST", r"/competitions/(?P<comp_id>\d+)/challenges")
def challenge_create(request: Request, comp_id: str) -> Response:
    missing = require_login(request)
    if missing:
        return missing
    competition = competition_by_id(int(comp_id))
    if not competition:
        return error_page(request, 404, "Competition not found.")
    if not can_manage_competition(request.current_user, competition):
        return error_page(request, 403, "You do not have permission to add challenges.")
    title = form_text(request, "title", 120)
    category = form_text(request, "category", 40) or "misc"
    tags = normalize_tags(request.form.get("tags", ""))
    body = form_text(request, "body", 8000)
    slug = form_text(request, "slug", 80)
    hint_text = form_text(request, "hint_text", 1200)
    flag_config, flag_error = flag_config_from_form(request)
    try:
        points = int(request.form.get("points", "100"))
        duration = int(request.form.get("duration_minutes", "15"))
        hint_cost = int(request.form.get("hint_cost", "0") or "0")
        hint_unlock_minutes = int(request.form.get("hint_unlock_minutes", "0") or "0")
    except Exception:
        return render(request, "challenge_form.html", competition=competition, challenge=None, form=request.form, form_error="Invalid score, duration, or hint settings.", status=400)
    if flag_error:
        return render(request, "challenge_form.html", competition=competition, challenge=None, form=request.form, form_error=flag_error, status=400)
    if len(title) < 2 or not body or points <= 0 or duration <= 0 or hint_cost < 0 or hint_unlock_minutes < 0:
        return render(request, "challenge_form.html", competition=competition, challenge=None, form=request.form, form_error="Challenge title, body, flag, score, and time must be valid.", status=400)
    with transaction() as conn:
        position = conn.execute(
            "SELECT COALESCE(MAX(position), 0) + 1 AS next_position FROM challenges WHERE competition_id = ?",
            (comp_id,),
        ).fetchone()["next_position"]
        competition_row = conn.execute("SELECT starts_at FROM competitions WHERE id = ?", (comp_id,)).fetchone()
        cursor = parse_iso(competition_row["starts_at"])
        prior = conn.execute(
            "SELECT COALESCE(SUM(duration_minutes), 0) AS total_minutes FROM challenges WHERE competition_id = ?",
            (comp_id,),
        ).fetchone()["total_minutes"]
        opens_at = iso_utc(cursor + timedelta(minutes=int(prior or 0)))
        closes_at = iso_utc(parse_iso(opens_at) + timedelta(minutes=duration))
        final_slug = unique_challenge_slug(conn, int(comp_id), slug, title)
        now = iso_utc()
        cur = conn.execute(
            """
            INSERT INTO challenges(
                competition_id, title, slug, category, tags, body, points, flag_type, flag_hash, flag_pattern,
                position, duration_minutes, hint_text, hint_cost, hint_unlock_minutes,
                opens_at, closes_at, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                comp_id,
                title,
                final_slug,
                category,
                tags,
                body,
                points,
                flag_config["flag_type"],
                flag_config["flag_hash"],
                flag_config["flag_pattern"],
                position,
                duration,
                hint_text,
                hint_cost,
                hint_unlock_minutes,
                opens_at,
                closes_at,
                now,
                now,
            ),
        )
        try:
            file_id = save_dist_file(conn, cur.lastrowid, request.files.get("dist_file"))
        except ValueError as exc:
            return render(request, "challenge_form.html", competition=competition, challenge=None, form=request.form, form_error=str(exc), status=400)
        recalculate_challenge_schedule(conn, int(comp_id))
        if competition["status"] == "approved" and not is_admin(request.current_user):
            conn.execute("UPDATE competitions SET status = 'pending_review', updated_at = ? WHERE id = ?", (now, comp_id))
        else:
            conn.execute("UPDATE competitions SET updated_at = ? WHERE id = ?", (now, comp_id))
        audit(conn, request.current_user["id"], "create_challenge", "challenge", cur.lastrowid, {"dist_file_id": file_id})
    return redirect(with_notice(f"/competitions/{comp_id}", "Challenge created."))


@route("GET", r"/challenges/(?P<challenge_id>\d+)/edit")
def challenge_edit(request: Request, challenge_id: str) -> Response:
    missing = require_login(request)
    if missing:
        return missing
    challenge = challenge_by_id(int(challenge_id))
    if not challenge:
        return error_page(request, 404, "Challenge not found.")
    competition = competition_by_id(challenge["competition_id"])
    if not can_manage_competition(request.current_user, competition):
        return error_page(request, 403, "You do not have permission to edit this challenge.")
    duration = int(challenge["duration_minutes"] or 15)
    return render(request, "challenge_form.html", competition=competition, challenge=challenge, default_duration=duration)


@route("POST", r"/challenges/(?P<challenge_id>\d+)/edit")
def challenge_update(request: Request, challenge_id: str) -> Response:
    missing = require_login(request)
    if missing:
        return missing
    challenge = challenge_by_id(int(challenge_id))
    if not challenge:
        return error_page(request, 404, "Challenge not found.")
    competition = competition_by_id(challenge["competition_id"])
    if not can_manage_competition(request.current_user, competition):
        return error_page(request, 403, "You do not have permission to edit this challenge.")
    title = form_text(request, "title", 120)
    category = form_text(request, "category", 40) or "misc"
    tags = normalize_tags(request.form.get("tags", ""))
    body = form_text(request, "body", 8000)
    slug = form_text(request, "slug", 80)
    hint_text = form_text(request, "hint_text", 1200)
    flag_config, flag_error = flag_config_from_form(request, current=challenge)
    try:
        points = int(request.form.get("points", "100"))
        duration = int(request.form.get("duration_minutes", "15"))
        hint_cost = int(request.form.get("hint_cost", "0") or "0")
        hint_unlock_minutes = int(request.form.get("hint_unlock_minutes", "0") or "0")
    except Exception:
        return render(request, "challenge_form.html", competition=competition, challenge=challenge, form=request.form, form_error="Invalid score, duration, or hint settings.", status=400)
    if flag_error:
        return render(request, "challenge_form.html", competition=competition, challenge=challenge, form=request.form, form_error=flag_error, status=400)
    if len(title) < 2 or not body or points <= 0 or duration <= 0 or hint_cost < 0 or hint_unlock_minutes < 0:
        return render(request, "challenge_form.html", competition=competition, challenge=challenge, form=request.form, form_error="Challenge title, body, score, and time must be valid.", status=400)
    with transaction() as conn:
        final_slug = unique_challenge_slug(conn, competition["id"], slug, title, exclude_id=int(challenge_id))
        conn.execute(
            """
            UPDATE challenges
            SET title = ?, slug = ?, category = ?, tags = ?, body = ?, points = ?,
                flag_type = ?, flag_hash = ?, flag_pattern = ?,
                duration_minutes = ?, hint_text = ?, hint_cost = ?, hint_unlock_minutes = ?, updated_at = ?
            WHERE id = ?
            """,
            (
                title,
                final_slug,
                category,
                tags,
                body,
                points,
                flag_config["flag_type"],
                flag_config["flag_hash"],
                flag_config["flag_pattern"],
                duration,
                hint_text,
                hint_cost,
                hint_unlock_minutes,
                iso_utc(),
                challenge_id,
            ),
        )
        recalculate_challenge_schedule(conn, competition["id"])
        try:
            file_id = save_dist_file(conn, int(challenge_id), request.files.get("dist_file"))
        except ValueError as exc:
            return render(request, "challenge_form.html", competition=competition, challenge=challenge, form=request.form, form_error=str(exc), status=400)
        if competition["status"] == "approved" and not is_admin(request.current_user):
            conn.execute("UPDATE competitions SET status = 'pending_review', updated_at = ? WHERE id = ?", (iso_utc(), competition["id"]))
        else:
            conn.execute("UPDATE competitions SET updated_at = ? WHERE id = ?", (iso_utc(), competition["id"]))
        audit(conn, request.current_user["id"], "update_challenge", "challenge", int(challenge_id), {"dist_file_id": file_id})
    return redirect(with_notice(f"/competitions/{competition['id']}", "Challenge updated."))


@route("POST", r"/challenges/(?P<challenge_id>\d+)/delete")
def challenge_delete(request: Request, challenge_id: str) -> Response:
    missing = require_login(request)
    if missing:
        return missing
    challenge = challenge_by_id(int(challenge_id))
    if not challenge:
        return error_page(request, 404, "Challenge not found.")
    competition = competition_by_id(challenge["competition_id"])
    if not can_manage_competition(request.current_user, competition):
        return error_page(request, 403, "You do not have permission to delete this challenge.")
    with transaction() as conn:
        conn.execute("DELETE FROM challenges WHERE id = ?", (challenge_id,))
        recalculate_challenge_schedule(conn, competition["id"])
        conn.execute("UPDATE competitions SET updated_at = ? WHERE id = ?", (iso_utc(), competition["id"]))
        audit(conn, request.current_user["id"], "delete_challenge", "challenge", int(challenge_id))
    return redirect(with_notice(f"/competitions/{competition['id']}", "Challenge deleted."))


@route("POST", r"/competitions/(?P<comp_id>\d+)/challenges/reorder")
def challenge_reorder(request: Request, comp_id: str) -> Response:
    missing = require_login(request)
    if missing:
        return missing
    competition = competition_by_id(int(comp_id))
    if not competition:
        return json_response({"error": "Competition not found."}, 404)
    if not can_manage_competition(request.current_user, competition):
        return json_response({"error": "You do not have permission to reorder challenges."}, 403)
    try:
        ordered_ids = [int(value) for value in request.form.get("order", "").split(",") if value.strip()]
    except ValueError:
        return json_response({"error": "Invalid challenge order."}, 400)
    with transaction() as conn:
        existing = conn.execute(
            "SELECT id FROM challenges WHERE competition_id = ? ORDER BY position ASC, id ASC",
            (comp_id,),
        ).fetchall()
        existing_ids = [row["id"] for row in existing]
        if sorted(existing_ids) != sorted(ordered_ids):
            return json_response({"error": "Challenge list changed. Refresh and try again."}, 409)
        for position, challenge_id_value in enumerate(ordered_ids, start=1):
            conn.execute("UPDATE challenges SET position = ? WHERE id = ?", (position, challenge_id_value))
        recalculate_challenge_schedule(conn, int(comp_id))
        status = competition["status"]
        if status == "approved" and not is_admin(request.current_user):
            conn.execute("UPDATE competitions SET status = 'pending_review', updated_at = ? WHERE id = ?", (iso_utc(), comp_id))
        else:
            conn.execute("UPDATE competitions SET updated_at = ? WHERE id = ?", (iso_utc(), comp_id))
        audit(conn, request.current_user["id"], "reorder_challenges", "competition", int(comp_id), {"order": ordered_ids})
    return json_response({"ok": True})


@route("POST", r"/competitions/(?P<comp_id>\d+)/collaboration-invites")
def collaboration_invite_create(request: Request, comp_id: str) -> Response:
    missing = require_login(request)
    if missing:
        return missing
    competition = competition_by_id(int(comp_id))
    if not competition:
        return error_page(request, 404, "Competition not found.")
    if not can_manage_competition(request.current_user, competition):
        return error_page(request, 403, "You do not have permission to create collaboration links.")
    role = normalize_invite_role(request.form.get("role", "editor"))
    try:
        expires_days = int(request.form.get("expires_days", "14") or "14")
    except ValueError:
        expires_days = 14
    if expires_days < 1 or expires_days > 365:
        return redirect(with_error(f"/competitions/{comp_id}", "Invite expiry must be between 1 and 365 days."))
    with transaction() as conn:
        create_collaboration_invite(conn, int(comp_id), request.current_user["id"], role=role, expires_days=expires_days)
    return redirect(with_notice(f"/competitions/{comp_id}", "Collaboration link created."))


@route("POST", r"/competition-invites/(?P<invite_id>\d+)/revoke")
def collaboration_invite_revoke(request: Request, invite_id: str) -> Response:
    missing = require_login(request)
    if missing:
        return missing
    with transaction() as conn:
        invite = conn.execute("SELECT * FROM competition_collaborator_invites WHERE id = ?", (invite_id,)).fetchone()
        if not invite:
            return error_page(request, 404, "Invite not found.")
        competition = conn.execute("SELECT * FROM competitions WHERE id = ?", (invite["competition_id"],)).fetchone()
        if not can_manage_competition(request.current_user, competition):
            return error_page(request, 403, "You do not have permission to revoke this invite.")
        conn.execute("UPDATE competition_collaborator_invites SET revoked_at = ? WHERE id = ?", (iso_utc(), invite_id))
        audit(conn, request.current_user["id"], "revoke_collaboration_invite", "competition", invite["competition_id"], {"invite_id": int(invite_id)})
    return redirect(with_notice(f"/competitions/{invite['competition_id']}", "Collaboration link revoked."))


@route("GET", r"/collaborate/(?P<token>[A-Za-z0-9_\-]+)")
def collaboration_accept(request: Request, token: str) -> Response:
    missing = require_login(request)
    if missing:
        return missing
    with transaction() as conn:
        invite = conn.execute(
            """
            SELECT i.*, c.title AS competition_title, c.owner_id
            FROM competition_collaborator_invites i
            JOIN competitions c ON c.id = i.competition_id
            WHERE i.token = ?
            """,
            (token,),
        ).fetchone()
        if not invite or invite["revoked_at"]:
            return error_page(request, 404, "Collaboration link not found.")
        if invite["expires_at"] and invite["expires_at"] <= iso_utc():
            return error_page(request, 403, "This collaboration link has expired.")
        if request.current_user["id"] != invite["owner_id"]:
            now = iso_utc()
            conn.execute(
                """
                INSERT INTO competition_collaborators(competition_id, user_id, role, invited_by, accepted_at, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(competition_id, user_id) DO UPDATE SET
                    role = excluded.role,
                    invited_by = excluded.invited_by,
                    accepted_at = excluded.accepted_at
                """,
                (invite["competition_id"], request.current_user["id"], invite["role"], invite["created_by"], now, now),
            )
        audit(
            conn,
            request.current_user["id"],
            "accept_collaboration_invite",
            "competition",
            invite["competition_id"],
            {"role": invite["role"]},
        )
    return redirect(with_notice(f"/competitions/{invite['competition_id']}", f"You can now collaborate on {invite['competition_title']}."))


@route("POST", r"/competitions/(?P<comp_id>\d+)/announcements")
def announcement_create(request: Request, comp_id: str) -> Response:
    missing = require_login(request)
    if missing:
        return missing
    competition = competition_by_id(int(comp_id))
    if not competition:
        return error_page(request, 404, "Competition not found.")
    if not can_manage_competition(request.current_user, competition):
        return error_page(request, 403, "You do not have permission to post announcements.")
    title = form_text(request, "title", 120)
    body = form_text(request, "body", 2000)
    if len(title) < 2 or len(body) < 2:
        return redirect(with_error(f"/competitions/{comp_id}", "Announcement title and body are required."))
    with transaction() as conn:
        cur = conn.execute(
            """
            INSERT INTO competition_announcements(competition_id, title, body, created_by, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (comp_id, title, body, request.current_user["id"], iso_utc()),
        )
        audit(conn, request.current_user["id"], "create_announcement", "competition", int(comp_id), {"announcement_id": cur.lastrowid})
    return redirect(with_notice(f"/competitions/{comp_id}", "Announcement posted."))


@route("GET", r"/competitions/(?P<comp_id>\d+)/export.json")
def competition_export(request: Request, comp_id: str) -> Response:
    missing = require_login(request)
    if missing:
        return missing
    competition = competition_by_id(int(comp_id))
    if not competition:
        return error_page(request, 404, "Competition not found.")
    if not can_manage_competition(request.current_user, competition):
        return error_page(request, 403, "You do not have permission to export this competition.")
    with connect() as conn:
        challenges = conn.execute(
            """
            SELECT title, slug, category, tags, body, points, flag_type, flag_pattern, position,
                   duration_minutes, hint_text, hint_cost, hint_unlock_minutes
            FROM challenges
            WHERE competition_id = ?
            ORDER BY position ASC, id ASC
            """,
            (comp_id,),
        ).fetchall()
        announcements = conn.execute(
            "SELECT title, body, created_at FROM competition_announcements WHERE competition_id = ? ORDER BY created_at ASC",
            (comp_id,),
        ).fetchall()
    payload = {
        "competition": {
            "title": competition["title"],
            "slug": competition["slug"],
            "summary": competition["summary"],
            "rules": competition["rules"],
            "starts_at": competition["starts_at"],
            "ends_at": competition["ends_at"],
            "registration_open": bool(competition["registration_open"]),
            "team_mode": competition["team_mode"],
            "scoring_mode": competition["scoring_mode"],
            "scoreboard_freeze_minutes": competition["scoreboard_freeze_minutes"],
            "scoreboard_preview_limit": competition["scoreboard_preview_limit"],
            "writeup_url": competition["writeup_url"],
        },
        "challenges": [dict(row) for row in challenges],
        "announcements": [dict(row) for row in announcements],
    }
    headers = [
        ("Content-Type", "application/json; charset=utf-8"),
        ("Content-Disposition", f"attachment; filename={competition['slug']}-export.json"),
    ]
    return Response(json.dumps(payload, ensure_ascii=False, indent=2), 200, headers)


@route("GET", r"/challenges/(?P<challenge_id>\d+)/preview")
def challenge_preview(request: Request, challenge_id: str) -> Response:
    missing = require_login(request)
    if missing:
        return missing
    challenge = challenge_by_id(int(challenge_id))
    if not challenge:
        return error_page(request, 404, "Challenge not found.")
    competition = competition_by_id(challenge["competition_id"])
    if not collaboration_role(request.current_user, competition):
        return error_page(request, 403, "You do not have permission to preview this challenge.")
    with connect() as conn:
        dist_file = latest_challenge_file(conn, int(challenge_id))
    return render(
        request,
        "challenge_preview.html",
        competition=competition,
        challenge=challenge,
        dist_file=dist_file,
        manager=can_manage_competition(request.current_user, competition),
    )


@route("GET", r"/challenges/(?P<challenge_id>\d+)/dist")
def challenge_dist_download(request: Request, challenge_id: str) -> Response:
    challenge = challenge_by_id(int(challenge_id))
    if not challenge:
        return error_page(request, 404, "Challenge not found.")
    competition = competition_by_id(challenge["competition_id"])
    if not competition:
        return error_page(request, 404, "Competition not found.")
    if not request.current_user and not competition_is_archived(competition):
        return redirect(f"/login?next=/competitions/{competition['id']}")
    with connect() as conn:
        registered = False
        if request.current_user:
            registered = bool(
                conn.execute(
                    "SELECT 1 FROM competition_registrations WHERE competition_id = ? AND user_id = ?",
                    (competition["id"], request.current_user["id"]),
                ).fetchone()
            )
        dist_file = latest_challenge_file(conn, int(challenge_id))
    if not dist_file:
        return error_page(request, 404, "This challenge has no dist file.")
    if not can_download_dist(request.current_user, competition, challenge, registered):
        return error_page(request, 403, "You cannot download this dist file right now.")
    target = (UPLOAD_DIR / dist_file["stored_filename"]).resolve()
    upload_root = UPLOAD_DIR.resolve()
    if not str(target).startswith(str(upload_root)) or not target.is_file():
        return error_page(request, 404, "Uploaded file not found.")
    filename = dist_file["original_filename"]
    headers = [
        ("Content-Type", dist_file["content_type"] or "application/octet-stream"),
        ("Content-Length", str(target.stat().st_size)),
        ("Content-Disposition", f"attachment; filename*=UTF-8''{quote(filename)}"),
    ]
    return Response(target.read_bytes(), 200, headers)


@route("POST", r"/challenges/(?P<challenge_id>\d+)/submit")
def submit_flag(request: Request, challenge_id: str) -> Response:
    missing = require_login(request)
    if missing:
        return missing
    flag = request.form.get("flag", "")
    if not flag.strip():
        return redirect(with_error("/competitions", "Enter a flag."))
    digest = flag_attempt_digest(flag)
    with transaction() as conn:
        challenge = conn.execute(
            """
            SELECT ch.*, c.status AS competition_status
            FROM challenges ch
            JOIN competitions c ON c.id = ch.competition_id
            WHERE ch.id = ?
            """,
            (challenge_id,),
        ).fetchone()
        if not challenge:
            return error_page(request, 404, "Challenge not found.")
        comp_id = challenge["competition_id"]
        registered = conn.execute(
            "SELECT 1 FROM competition_registrations WHERE competition_id = ? AND user_id = ?",
            (comp_id, request.current_user["id"]),
        ).fetchone()
        now = iso_utc()
        if not registered:
            return redirect(with_error(f"/competitions/{comp_id}", "Join the competition before submitting flags."))
        if challenge["competition_status"] != "approved" or not (challenge["opens_at"] <= now < challenge["closes_at"]):
            conn.execute(
                """
                INSERT INTO submissions(competition_id, challenge_id, user_id, flag_digest, result, created_at)
                VALUES (?, ?, ?, ?, 'closed', ?)
                """,
                (comp_id, challenge_id, request.current_user["id"], digest, now),
            )
            return redirect(with_error(f"/competitions/{comp_id}", "This challenge is not open right now. Submission was not scored."))
        already = conn.execute(
            "SELECT 1 FROM solves WHERE user_id = ? AND challenge_id = ?",
            (request.current_user["id"], challenge_id),
        ).fetchone()
        if already:
            conn.execute(
                """
                INSERT INTO submissions(competition_id, challenge_id, user_id, flag_digest, result, created_at)
                VALUES (?, ?, ?, ?, 'duplicate', ?)
                """,
                (comp_id, challenge_id, request.current_user["id"], digest, now),
            )
            return redirect(with_notice(f"/competitions/{comp_id}", "You already solved this challenge. This submission was not scored again."))
        if not challenge_flag_matches(flag, challenge):
            conn.execute(
                """
                INSERT INTO submissions(competition_id, challenge_id, user_id, flag_digest, result, created_at)
                VALUES (?, ?, ?, ?, 'wrong', ?)
                """,
                (comp_id, challenge_id, request.current_user["id"], digest, now),
            )
            return redirect(with_error(f"/competitions/{comp_id}", "Incorrect flag."))
        try:
            conn.execute(
                """
                INSERT INTO solves(competition_id, challenge_id, user_id, points, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (comp_id, challenge_id, request.current_user["id"], challenge["points"], now),
            )
            result = "correct"
            message = "Correct flag. Score updated."
        except sqlite3.IntegrityError:
            result = "duplicate"
            message = "You already solved this challenge. This submission was not scored again."
        conn.execute(
            """
            INSERT INTO submissions(competition_id, challenge_id, user_id, flag_digest, result, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (comp_id, challenge_id, request.current_user["id"], digest, result, now),
        )
        audit(conn, request.current_user["id"], f"submit_{result}", "challenge", int(challenge_id))
    return redirect(with_notice(f"/competitions/{comp_id}", message))


@route("GET", r"/api/competitions/(?P<comp_id>\d+)/state")
def competition_state(request: Request, comp_id: str) -> Response:
    competition = competition_by_id(int(comp_id))
    if not competition:
        return json_response({"error": "not found"}, 404)
    if not can_view_competition(request.current_user, competition):
        return json_response({"error": "not found"}, 404)
    now = utcnow()
    with connect() as conn:
        active = active_challenge(conn, int(comp_id))
        scoreboard_limit = scoreboard_preview_limit_for(competition)
        full_board = scoreboard(conn, int(comp_id), None)
        board = full_board[:scoreboard_limit]
    active_payload = None
    if active:
        closes = parse_iso(active["closes_at"])
        active_payload = {
            "id": active["id"],
            "title": active["title"],
            "category": active["category"],
            "tags": active["tags"],
            "points": active["points"],
            "opens_at": active["opens_at"],
            "closes_at": active["closes_at"],
            "remaining_seconds": max(0, int((closes - now).total_seconds())),
        }
    return json_response(
        {
            "server_time": iso_utc(now),
            "active": active_payload,
            "scoreboard_limit": scoreboard_limit,
            "scoreboard_total": len(full_board),
            "scoreboard": [
                {
                    "username": row["username"],
                    "score": row["score"],
                    "solved_count": row["solved_count"],
                    "last_solve": row["last_solve"],
                }
                for row in board
            ],
        }
    )


def serve_static(path: str) -> Response | None:
    roots = {
        "/static/": BASE_DIR / "static",
    }
    for prefix, root in roots.items():
        if path.startswith(prefix):
            relative = path[len(prefix) :]
            target = (root / relative).resolve()
            if not str(target).startswith(str(root.resolve())) or not target.is_file():
                return Response("Not found", 404, [("Content-Type", "text/plain; charset=utf-8")])
            content_type = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
            return Response(target.read_bytes(), 200, [("Content-Type", content_type)])
    return None


def application(environ, start_response):
    request = Request(environ)
    static_response = serve_static(request.path)
    if static_response:
        start_response(status_line(static_response.status), static_response.headers)
        return [static_response.body]

    try:
        load_session(request)
        if request.method == "POST" and request.form.get("_csrf") != request.csrf_token:
            response = error_page(request, 403, "Invalid CSRF token. Go back and try again.")
        else:
            response = None
            for method, pattern, handler in ROUTES:
                if method != request.method:
                    continue
                match = pattern.match(request.path)
                if match:
                    response = handler(request, **match.groupdict())
                    break
            if response is None:
                response = error_page(request, 404, "Page not found.")
    except Exception as exc:
        response = Response(
            f"Internal Server Error\n{escape(str(exc))}",
            500,
            [("Content-Type", "text/plain; charset=utf-8")],
        )

    headers = list(response.headers)
    if request.set_cookie:
        headers.append(("Set-Cookie", request.set_cookie))
    start_response(status_line(response.status), headers)
    return [response.body]


class ThreadedWSGIServer(ThreadingMixIn, WSGIServer):
    daemon_threads = True


def run() -> None:
    init_db()
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8000"))
    print(f"CTF platform running at http://{host}:{port}")
    with make_server(host, port, application, server_class=ThreadedWSGIServer, handler_class=WSGIRequestHandler) as httpd:
        httpd.serve_forever()
