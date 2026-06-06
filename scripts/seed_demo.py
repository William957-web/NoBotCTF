from __future__ import annotations

from datetime import timedelta
from io import BytesIO
import sys
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ctf_platform import web
from ctf_platform.config import UPLOAD_DIR
from ctf_platform.db import connect, init_db, transaction
from ctf_platform.security import hash_flag, hash_password
from ctf_platform.utils import iso_utc, parse_iso, slugify, utcnow


DEMO_PASSWORD = "DemoPass123!"


USERS = [
    ("demo_admin", "admin@demo.ctf", "admin", "Demo Admin", "Platform operations", "https://example.com/admin", "Runs reviews, users, and platform settings."),
    ("alice_org", "alice@demo.ctf", "organizer", "Alice Organizer", "Blue Team Lab", "https://example.com/alice", "Designs time-windowed CTF events."),
    ("bob_org", "bob@demo.ctf", "organizer", "Bob Organizer", "Weekend Qualifiers", "https://example.com/bob", "Builds beginner-friendly qualifier rounds."),
    ("ada_player", "ada@demo.ctf", "player", "Ada", "NCKU CTF", "https://example.com/ada", "Web and forensics player."),
    ("lin_player", "lin@demo.ctf", "player", "Lin", "NTU Sec", "https://example.com/lin", "Crypto and reverse engineering."),
    ("mika_player", "mika@demo.ctf", "player", "Mika", "Solo", "", "Likes live scoreboard pressure."),
    ("neo_player", "neo@demo.ctf", "player", "Neo", "Pwn Club", "", "Binary exploitation beginner."),
    ("kim_player", "kim@demo.ctf", "player", "Kim", "Archive Hunters", "", "Reads writeups after events."),
    ("rio_player", "rio@demo.ctf", "player", "Rio", "Packet Lab", "", "Network warmup player."),
    ("yen_player", "yen@demo.ctf", "player", "Yen", "Crypto Club", "", "Practices short live rounds."),
    ("ivy_player", "ivy@demo.ctf", "player", "Ivy", "Web Guild", "", "Focuses on web exploitation."),
    ("kai_player", "kai@demo.ctf", "player", "Kai", "Forensics Team", "", "Likes packet captures."),
    ("nora_player", "nora@demo.ctf", "player", "Nora", "Rev Lab", "", "Reads VM bytecode traces."),
    ("omar_player", "omar@demo.ctf", "player", "Omar", "Blue Team Lab", "", "Tries every live challenge."),
    ("pia_player", "pia@demo.ctf", "player", "Pia", "NCKU CTF", "", "Writes concise solve notes."),
    ("sam_player", "sam@demo.ctf", "player", "Sam", "Solo", "", "Competes in beginner qualifiers."),
    ("tess_player", "tess@demo.ctf", "player", "Tess", "NTU Sec", "", "Enjoys scoreboard races."),
    ("uma_player", "uma@demo.ctf", "player", "Uma", "Archive Hunters", "", "Uses archived CTFs for practice."),
]


CHALLENGES = {
    "running": [
        ("Packet Warmup", "network", 100, 15, "Inspect the live capture and recover the token from the suspicious DNS request.", "FLAG{dns-live-warmup}", "Look for the longest TXT response.", 0, 8),
        ("Cookie Jar", "web", 200, 10, "A session cookie is signed incorrectly. Find the role escalation path.", "FLAG{cookie-jar-editor}", "Compare the guest and editor cookies byte by byte.", 20, 10),
        ("Clock Drift", "misc", 150, 8, "A service accepts timestamps. Abuse the drift and submit the accepted timestamp proof.", "FLAG{server-time-matters}", "The server accepts a small future skew.", 0, 5),
    ],
    "upcoming": [
        ("Starter Portal", "web", 100, 3, "Warmup web challenge for the qualifier.", "FLAG{starter-portal}", "Check robots.txt.", 0, 0),
        ("Tiny RSA", "crypto", 250, 12, "A tiny RSA modulus was generated with weak primes.", "FLAG{tiny-rsa}", "Factor before decrypting.", 30, 10),
        ("Memory Strings", "forensics", 150, 10, "Find the secret embedded in a memory dump.", "FLAG{strings-are-not-enough}", "Look around shell history.", 0, 8),
    ],
    "archived": [
        ("Archive Login", "web", 100, 7, "The old login endpoint leaked too much information. Review the response and recover the flag.", "FLAG{archive-login-leak}", "The error message changes by account state.", 0, 0),
        ("Frozen Scoreboard", "misc", 150, 3, "Reconstruct the final visible scoreboard from archived submissions.", "FLAG{frozen-but-fair}", "Freeze time is 20 minutes before end.", 0, 0),
        ("Layer Cake", "forensics", 200, 9, "Multiple encodings hide the final answer. Peel each layer in order.", "FLAG{layer-cake}", "Start with base64, then compression.", 10, 0),
        ("Mini VM", "rev", 300, 15, "A small bytecode VM checks the flag. Reverse its instruction set.", "FLAG{mini-vm-opcodes}", "Trace opcode 0x13.", 50, 0),
    ],
}


def markdown_body(title: str, category: str, prompt: str, points: int, duration: int) -> str:
    return f"""# {title}

**Category:** `{category}`  
**Points:** `{points}`  
**Round length:** `{duration} minutes`

## Objective

{prompt}

## Files

Download the attached dist file and start from `README.md`.

## Submission

Submit a flag in this format:

```text
FLAG{{example}}
```

## Notes

- The live round uses server time.
- Hints may unlock after the challenge has been open for a while.
- Keep any writeup notes locally until the CTF is archived.
"""


def dist_zip_bytes(title: str, category: str, prompt: str, flag: str, created_at: str) -> bytes:
    buffer = BytesIO()
    with ZipFile(buffer, "w", ZIP_DEFLATED) as archive:
        archive.writestr(
            "README.md",
            f"""# {title} dist

Category: {category}

This is a demo distribution file for the live CTF platform.

## Prompt

{prompt}

## What to inspect

- `artifact.txt`
- `sample.log`

The real flag is stored server-side. This archive is intentionally safe demo content.
""",
        )
        archive.writestr(
            "artifact.txt",
            f"""challenge={title}
category={category}
demo=true
server_side_flag_hash_only=true
sample_token={flag.replace('FLAG{', '').replace('}', '')[:8]}
""",
        )
        archive.writestr(
            "sample.log",
            f"""{created_at} connection opened
{created_at} suspicious request captured
{created_at} analyst note: inspect the artifact
""",
        )
    return buffer.getvalue()


def attach_dist_file(conn, challenge_id: int, title: str, category: str, prompt: str, flag: str, now: str) -> None:
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    original = f"{slugify(title, 'challenge')}-dist.zip"
    stored = f"{challenge_id}/demo_{original}"
    target = UPLOAD_DIR / stored
    target.parent.mkdir(parents=True, exist_ok=True)
    data = dist_zip_bytes(title, category, prompt, flag, now)
    target.write_bytes(data)
    conn.execute(
        """
        INSERT INTO challenge_files(challenge_id, original_filename, stored_filename, content_type, size_bytes, created_at)
        VALUES (?, ?, ?, 'application/zip', ?, ?)
        """,
        (challenge_id, original, stored, len(data), now),
    )


def clear_existing(conn) -> None:
    for table in [
        "audit_log",
        "solves",
        "submissions",
        "competition_announcements",
        "competition_collaborators",
        "competition_collaborator_invites",
        "challenge_files",
        "challenges",
        "competition_registrations",
        "competitions",
        "organizer_applications",
        "sessions",
        "users",
        "platform_settings",
    ]:
        conn.execute(f"DELETE FROM {table}")
    conn.execute("DELETE FROM sqlite_sequence")
    if UPLOAD_DIR.exists():
        for path in sorted(UPLOAD_DIR.rglob("*"), reverse=True):
            if path.is_file():
                path.unlink()
            elif path.is_dir():
                path.rmdir()


def create_competition(conn, user_ids, key, title, slug, summary, owner, starts_at, status, team_mode, scoring_mode, freeze, writeup, now_dt, now):
    comp_id = conn.execute(
        """
        INSERT INTO competitions(
            title, slug, summary, rules, starts_at, registration_open, team_mode, scoring_mode,
            scoreboard_freeze_minutes, scoreboard_preview_limit, writeup_url, owner_id, status, created_at, updated_at
        )
        VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, 12, ?, ?, ?, ?, ?)
        """,
        (
            title,
            slug,
            summary,
            "All flags use FLAG{...}. Respect server time; only the active challenge accepts submissions during live play.",
            starts_at,
            team_mode,
            scoring_mode,
            freeze,
            writeup,
            user_ids[owner],
            status,
            now,
            now,
        ),
    ).lastrowid
    conn.execute(
        """
        INSERT INTO competition_announcements(competition_id, title, body, created_by, created_at)
        VALUES (?, 'Welcome', ?, ?, ?)
        """,
        (comp_id, f"{title} is ready. Watch the live round panel for the current challenge.", user_ids[owner], now),
    )
    cursor = parse_iso(starts_at)
    for position, (ch_title, category, points, duration, body, flag, hint, hint_cost, hint_unlock) in enumerate(CHALLENGES[key], start=1):
        closes_at = cursor + timedelta(minutes=duration)
        challenge_id = conn.execute(
            """
            INSERT INTO challenges(
                competition_id, title, slug, category, body, points, flag_type, flag_hash, flag_pattern,
                position, duration_minutes, hint_text, hint_cost, hint_unlock_minutes,
                opens_at, closes_at, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, 'static', ?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                comp_id,
                ch_title,
                web.unique_challenge_slug(conn, comp_id, "", ch_title),
                category,
                markdown_body(ch_title, category, body, points, duration),
                points,
                hash_flag(flag),
                position,
                duration,
                hint,
                hint_cost,
                hint_unlock,
                iso_utc(cursor),
                iso_utc(closes_at),
                now,
                now,
            ),
        ).lastrowid
        attach_dist_file(conn, challenge_id, ch_title, category, body, flag, now)
        cursor = closes_at
    web.recalculate_challenge_schedule(conn, comp_id)
    web.create_collaboration_invite(conn, comp_id, user_ids[owner], role="editor", expires_days=30)
    web.audit(conn, user_ids[owner], "seed_competition", "competition", comp_id, {"phase": key})
    return comp_id


def seed() -> None:
    init_db()
    now_dt = utcnow()
    now = iso_utc(now_dt)
    with transaction() as conn:
        clear_existing(conn)
        web.set_platform_name(conn, "NoBot CTF Live Demo")
        user_ids = {}
        for username, email, role, display_name, affiliation, website, bio in USERS:
            user_id = conn.execute(
                """
                INSERT INTO users(username, email, password_hash, display_name, affiliation, website_url, bio, role, is_active, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
                """,
                (username, email, hash_password(DEMO_PASSWORD), display_name, affiliation, website, bio, role, now),
            ).lastrowid
            user_ids[username] = user_id
            web.audit(conn, user_id, "seed_user", "user", user_id, {"role": role})

        running_id = create_competition(conn, user_ids, "running", "Cyber Relay Live CTF", "cyber-relay-live", "A live time-windowed CTF with one visible challenge at a time.", "alice_org", iso_utc(now_dt - timedelta(minutes=10)), "approved", "teams", "dynamic", 10, "", now_dt, now)
        upcoming_id = create_competition(conn, user_ids, "upcoming", "Weekend Qualifier 2026", "weekend-qualifier-2026", "Upcoming qualifier with web, crypto, and forensics rounds.", "bob_org", iso_utc(now_dt + timedelta(hours=2)), "approved", "individual", "fixed", 0, "", now_dt, now)
        archived_id = create_competition(conn, user_ids, "archived", "Spring Archive CTF", "spring-archive-ctf", "Completed CTF with every challenge publicly readable.", "alice_org", iso_utc(now_dt - timedelta(days=4)), "archived", "individual", "fixed", 20, "https://example.com/spring-archive-writeups", now_dt, now)

        player_names = [
            username
            for username, _email, role, _display_name, _affiliation, _website, _bio in USERS
            if role == "player"
        ]
        for comp_id in (running_id, upcoming_id, archived_id):
            for username in player_names:
                conn.execute("INSERT INTO competition_registrations(competition_id, user_id, created_at) VALUES (?, ?, ?)", (comp_id, user_ids[username], now))

        def add_solve(comp_id, challenge_position, username, minutes_ago):
            challenge = conn.execute("SELECT * FROM challenges WHERE competition_id = ? AND position = ?", (comp_id, challenge_position)).fetchone()
            solved_at = iso_utc(now_dt - timedelta(minutes=minutes_ago))
            digest = f"seed-{comp_id}-{challenge_position}-{username}"
            conn.execute("INSERT INTO submissions(competition_id, challenge_id, user_id, flag_digest, result, created_at) VALUES (?, ?, ?, ?, 'correct', ?)", (comp_id, challenge["id"], user_ids[username], digest, solved_at))
            conn.execute("INSERT INTO solves(competition_id, challenge_id, user_id, points, created_at) VALUES (?, ?, ?, ?, ?)", (comp_id, challenge["id"], user_ids[username], challenge["points"], solved_at))

        for index, username in enumerate(player_names, start=1):
            add_solve(running_id, 1, username, 10 - (index * 0.45))
        for args in [
            (archived_id, 1, "ada_player", 4000),
            (archived_id, 1, "lin_player", 3990),
            (archived_id, 2, "ada_player", 3980),
            (archived_id, 2, "neo_player", 3975),
            (archived_id, 3, "ada_player", 3960),
            (archived_id, 3, "kim_player", 3950),
            (archived_id, 4, "lin_player", 3940),
        ]:
            add_solve(*args)


def main() -> None:
    seed()
    with connect() as conn:
        print("seeded demo users/password:", DEMO_PASSWORD)
        print("users", conn.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"])
        print("competitions", conn.execute("SELECT COUNT(*) AS n FROM competitions").fetchone()["n"])
        print("challenges", conn.execute("SELECT COUNT(*) AS n FROM challenges").fetchone()["n"])
        print("challenge files", conn.execute("SELECT COUNT(*) AS n FROM challenge_files").fetchone()["n"])
        print("solves", conn.execute("SELECT COUNT(*) AS n FROM solves").fetchone()["n"])


if __name__ == "__main__":
    main()
