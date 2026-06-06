from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import sqlite3

from .config import DB_PATH, INSTANCE_DIR


SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    display_name TEXT NOT NULL DEFAULT '',
    affiliation TEXT NOT NULL DEFAULT '',
    website_url TEXT NOT NULL DEFAULT '',
    bio TEXT NOT NULL DEFAULT '',
    role TEXT NOT NULL DEFAULT 'player'
        CHECK(role IN ('admin', 'organizer', 'player')),
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    csrf_token TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS platform_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS organizer_applications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    reason TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK(status IN ('pending', 'approved', 'rejected')),
    reviewed_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    reviewed_at TEXT,
    review_note TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS competitions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    slug TEXT NOT NULL UNIQUE COLLATE NOCASE,
    summary TEXT NOT NULL DEFAULT '',
    rules TEXT NOT NULL DEFAULT '',
    starts_at TEXT NOT NULL,
    registration_open INTEGER NOT NULL DEFAULT 1,
    team_mode TEXT NOT NULL DEFAULT 'individual'
        CHECK(team_mode IN ('individual', 'teams')),
    scoring_mode TEXT NOT NULL DEFAULT 'fixed'
        CHECK(scoring_mode IN ('fixed', 'dynamic')),
    scoreboard_freeze_minutes INTEGER NOT NULL DEFAULT 0 CHECK(scoreboard_freeze_minutes >= 0),
    scoreboard_preview_limit INTEGER NOT NULL DEFAULT 12 CHECK(scoreboard_preview_limit BETWEEN 1 AND 100),
    writeup_url TEXT NOT NULL DEFAULT '',
    owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    status TEXT NOT NULL DEFAULT 'draft'
        CHECK(status IN ('draft', 'pending_review', 'approved', 'rejected', 'archived')),
    review_note TEXT,
    reviewed_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    reviewed_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS competition_registrations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    competition_id INTEGER NOT NULL REFERENCES competitions(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    UNIQUE(competition_id, user_id)
);

CREATE TABLE IF NOT EXISTS challenges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    competition_id INTEGER NOT NULL REFERENCES competitions(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    slug TEXT NOT NULL COLLATE NOCASE,
    category TEXT NOT NULL DEFAULT 'misc',
    tags TEXT NOT NULL DEFAULT '',
    body TEXT NOT NULL,
    points INTEGER NOT NULL CHECK(points > 0),
    flag_type TEXT NOT NULL DEFAULT 'static'
        CHECK(flag_type IN ('static', 'regex')),
    flag_hash TEXT NOT NULL,
    flag_pattern TEXT,
    position INTEGER NOT NULL DEFAULT 0,
    duration_minutes INTEGER NOT NULL DEFAULT 15 CHECK(duration_minutes > 0),
    hint_text TEXT NOT NULL DEFAULT '',
    hint_cost INTEGER NOT NULL DEFAULT 0 CHECK(hint_cost >= 0),
    hint_unlock_minutes INTEGER NOT NULL DEFAULT 0 CHECK(hint_unlock_minutes >= 0),
    opens_at TEXT NOT NULL,
    closes_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(competition_id, slug),
    CHECK(closes_at > opens_at)
);

CREATE INDEX IF NOT EXISTS idx_challenges_live
    ON challenges(competition_id, opens_at, closes_at, position);

CREATE TABLE IF NOT EXISTS challenge_files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    challenge_id INTEGER NOT NULL REFERENCES challenges(id) ON DELETE CASCADE,
    original_filename TEXT NOT NULL,
    stored_filename TEXT NOT NULL UNIQUE,
    content_type TEXT NOT NULL DEFAULT 'application/octet-stream',
    size_bytes INTEGER NOT NULL CHECK(size_bytes >= 0),
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_challenge_files_challenge
    ON challenge_files(challenge_id, created_at DESC);

CREATE TABLE IF NOT EXISTS competition_collaborator_invites (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    competition_id INTEGER NOT NULL REFERENCES competitions(id) ON DELETE CASCADE,
    token TEXT NOT NULL UNIQUE,
    role TEXT NOT NULL DEFAULT 'editor'
        CHECK(role IN ('editor', 'viewer')),
    created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT,
    revoked_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_competition_invites_competition
    ON competition_collaborator_invites(competition_id, created_at DESC);

CREATE TABLE IF NOT EXISTS competition_collaborators (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    competition_id INTEGER NOT NULL REFERENCES competitions(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role TEXT NOT NULL DEFAULT 'editor'
        CHECK(role IN ('editor', 'viewer')),
    invited_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    accepted_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(competition_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_competition_collaborators_user
    ON competition_collaborators(user_id, competition_id);

CREATE TABLE IF NOT EXISTS competition_announcements (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    competition_id INTEGER NOT NULL REFERENCES competitions(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_competition_announcements_competition
    ON competition_announcements(competition_id, created_at DESC);

CREATE TABLE IF NOT EXISTS submissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    competition_id INTEGER NOT NULL REFERENCES competitions(id) ON DELETE CASCADE,
    challenge_id INTEGER NOT NULL REFERENCES challenges(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    flag_digest TEXT NOT NULL,
    result TEXT NOT NULL CHECK(result IN ('correct', 'wrong', 'closed', 'duplicate')),
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_submissions_competition
    ON submissions(competition_id, created_at DESC);

CREATE TABLE IF NOT EXISTS solves (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    competition_id INTEGER NOT NULL REFERENCES competitions(id) ON DELETE CASCADE,
    challenge_id INTEGER NOT NULL REFERENCES challenges(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    points INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(user_id, challenge_id)
);

CREATE INDEX IF NOT EXISTS idx_solves_scoreboard
    ON solves(competition_id, user_id, created_at);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id INTEGER,
    metadata TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);
"""


def connect() -> sqlite3.Connection:
    INSTANCE_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=15, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 15000")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def init_db() -> None:
    with connect() as conn:
        conn.executescript(SCHEMA)
        migrate(conn)
        conn.execute("DELETE FROM sessions WHERE expires_at < datetime('now')")


def migrate(conn: sqlite3.Connection) -> None:
    user_columns = {row["name"] for row in conn.execute("PRAGMA table_info(users)").fetchall()}
    if "display_name" not in user_columns:
        conn.execute("ALTER TABLE users ADD COLUMN display_name TEXT NOT NULL DEFAULT ''")
    if "affiliation" not in user_columns:
        conn.execute("ALTER TABLE users ADD COLUMN affiliation TEXT NOT NULL DEFAULT ''")
    if "website_url" not in user_columns:
        conn.execute("ALTER TABLE users ADD COLUMN website_url TEXT NOT NULL DEFAULT ''")
    if "bio" not in user_columns:
        conn.execute("ALTER TABLE users ADD COLUMN bio TEXT NOT NULL DEFAULT ''")

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS platform_settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    competition_columns = {row["name"] for row in conn.execute("PRAGMA table_info(competitions)").fetchall()}
    if "starts_at" not in competition_columns:
        conn.execute("ALTER TABLE competitions ADD COLUMN starts_at TEXT")
    if "registration_open" not in competition_columns:
        conn.execute("ALTER TABLE competitions ADD COLUMN registration_open INTEGER NOT NULL DEFAULT 1")
    if "team_mode" not in competition_columns:
        conn.execute("ALTER TABLE competitions ADD COLUMN team_mode TEXT NOT NULL DEFAULT 'individual'")
    if "scoring_mode" not in competition_columns:
        conn.execute("ALTER TABLE competitions ADD COLUMN scoring_mode TEXT NOT NULL DEFAULT 'fixed'")
    if "scoreboard_freeze_minutes" not in competition_columns:
        conn.execute("ALTER TABLE competitions ADD COLUMN scoreboard_freeze_minutes INTEGER NOT NULL DEFAULT 0")
    if "scoreboard_preview_limit" not in competition_columns:
        conn.execute("ALTER TABLE competitions ADD COLUMN scoreboard_preview_limit INTEGER NOT NULL DEFAULT 12")
    if "writeup_url" not in competition_columns:
        conn.execute("ALTER TABLE competitions ADD COLUMN writeup_url TEXT NOT NULL DEFAULT ''")
    conn.execute(
        """
        UPDATE competitions
        SET starts_at = COALESCE(
            (SELECT MIN(ch.opens_at) FROM challenges ch WHERE ch.competition_id = competitions.id),
            created_at
        )
        WHERE starts_at IS NULL OR starts_at = ''
        """
    )

    challenge_columns = {row["name"] for row in conn.execute("PRAGMA table_info(challenges)").fetchall()}
    if "flag_type" not in challenge_columns:
        conn.execute("ALTER TABLE challenges ADD COLUMN flag_type TEXT NOT NULL DEFAULT 'static'")
    if "flag_pattern" not in challenge_columns:
        conn.execute("ALTER TABLE challenges ADD COLUMN flag_pattern TEXT")
    if "tags" not in challenge_columns:
        conn.execute("ALTER TABLE challenges ADD COLUMN tags TEXT NOT NULL DEFAULT ''")
    if "duration_minutes" not in challenge_columns:
        conn.execute("ALTER TABLE challenges ADD COLUMN duration_minutes INTEGER")
        conn.execute(
            """
            UPDATE challenges
            SET duration_minutes = MAX(1, CAST(ROUND((julianday(closes_at) - julianday(opens_at)) * 1440) AS INTEGER))
            WHERE duration_minutes IS NULL OR duration_minutes <= 0
            """
        )
    if "hint_text" not in challenge_columns:
        conn.execute("ALTER TABLE challenges ADD COLUMN hint_text TEXT NOT NULL DEFAULT ''")
    if "hint_cost" not in challenge_columns:
        conn.execute("ALTER TABLE challenges ADD COLUMN hint_cost INTEGER NOT NULL DEFAULT 0")
    if "hint_unlock_minutes" not in challenge_columns:
        conn.execute("ALTER TABLE challenges ADD COLUMN hint_unlock_minutes INTEGER NOT NULL DEFAULT 0")
    conn.execute("UPDATE challenges SET duration_minutes = 15 WHERE duration_minutes IS NULL OR duration_minutes <= 0")
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS competition_collaborator_invites (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            competition_id INTEGER NOT NULL REFERENCES competitions(id) ON DELETE CASCADE,
            token TEXT NOT NULL UNIQUE,
            role TEXT NOT NULL DEFAULT 'editor'
                CHECK(role IN ('editor', 'viewer')),
            created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT,
            revoked_at TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_competition_invites_competition
            ON competition_collaborator_invites(competition_id, created_at DESC);

        CREATE TABLE IF NOT EXISTS competition_collaborators (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            competition_id INTEGER NOT NULL REFERENCES competitions(id) ON DELETE CASCADE,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            role TEXT NOT NULL DEFAULT 'editor'
                CHECK(role IN ('editor', 'viewer')),
            invited_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
            accepted_at TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(competition_id, user_id)
        );

        CREATE INDEX IF NOT EXISTS idx_competition_collaborators_user
            ON competition_collaborators(user_id, competition_id);

        CREATE TABLE IF NOT EXISTS competition_announcements (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            competition_id INTEGER NOT NULL REFERENCES competitions(id) ON DELETE CASCADE,
            title TEXT NOT NULL,
            body TEXT NOT NULL,
            created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
            created_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_competition_announcements_competition
            ON competition_announcements(competition_id, created_at DESC);
        """
    )
    _recalculate_existing_schedules(conn)


def _parse_db_time(value: str) -> datetime:
    try:
        return datetime.fromisoformat(value).astimezone(timezone.utc)
    except Exception:
        return datetime.now(timezone.utc).replace(microsecond=0)


def _iso_db_time(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat()


def _recalculate_existing_schedules(conn: sqlite3.Connection) -> None:
    competitions = conn.execute("SELECT id, starts_at FROM competitions").fetchall()
    for competition in competitions:
        cursor = _parse_db_time(competition["starts_at"])
        challenges = conn.execute(
            """
            SELECT id, duration_minutes
            FROM challenges
            WHERE competition_id = ?
            ORDER BY position ASC, opens_at ASC, id ASC
            """,
            (competition["id"],),
        ).fetchall()
        for index, challenge in enumerate(challenges, start=1):
            duration = max(1, int(challenge["duration_minutes"] or 15))
            closes_at = cursor + timedelta(minutes=duration)
            conn.execute(
                """
                UPDATE challenges
                SET position = ?, duration_minutes = ?, opens_at = ?, closes_at = ?
                WHERE id = ?
                """,
                (index, duration, _iso_db_time(cursor), _iso_db_time(closes_at), challenge["id"]),
            )
            cursor = closes_at


@contextmanager
def transaction():
    conn = connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def query_all(sql: str, params: tuple = ()):
    with connect() as conn:
        return conn.execute(sql, params).fetchall()


def query_one(sql: str, params: tuple = ()):
    with connect() as conn:
        return conn.execute(sql, params).fetchone()
