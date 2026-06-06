# Time-Windowed CTF Platform

A full-stack CTF operations platform for running time-windowed competitions. It is based on the original proposal in `期中專題提案_限時CTF平台.pptx`, but the current implementation is a complete platform experience: organizers create competitions, players join live rounds, archived CTFs remain readable, admins review and manage the platform, and a seeded live demo can be rebuilt with one command.

The app is implemented with Python, FastAPI/ASGI, Jinja templates, SQLite, vanilla JavaScript, and Docker Compose.

## Feature Overview

### Competition Lifecycle

- First-admin setup flow with platform name.
- Organizer application flow with admin review.
- Competition review flow: draft -> pending review -> approved/rejected/archived.
- Required competition start time.
- Competition end time is derived automatically from ordered challenge durations.
- Competition index separated into:
  - Running CTFs
  - Upcoming CTFs
  - Archived CTFs
  - My drafts / pending review
- Competition lists show recent items first, with SHOW MORE links into paginated browsing.
- Archived CTFs keep all challenge statements visible to everyone.
- Running CTFs only show the currently active challenge to players.
- Upcoming CTFs hide challenge details until live windows open.
- Registration open/closed setting.
- Individual and team-mode metadata.
- Fixed and dynamic scoring modes.
- Scoreboard freeze window.
- Writeup URL for archived events.
- Competition JSON export and import.

### Challenge Authoring

- Challenge scheduling uses only `duration_minutes`; `opens_at` and `closes_at` are derived from competition start time plus challenge order.
- Challenge order can be changed by drag-and-drop.
- Markdown challenge statements rendered through sanitized HTML.
- Categories, points, hints, hint costs, and hint unlock timing.
- Static flag validation.
- Regex flag validation with full-match behavior.
- Per-challenge dist file upload.
- Dist files are downloadable during the active live round by registered players.
- Archived challenge dist files are publicly downloadable.
- Organizer/collaborator challenge preview.

### Player Experience

- User registration, login, logout.
- Live round panel with active challenge, countdown, server-time windows, and submission form.
- Downloadable dist files for eligible challenges.
- Live scoreboard updates through WebSocket with polling fallback.
- Notification sound toggle.
- Challenge-change sound when the active round changes.
- Personal submission history.
- Player profiles showing joined competitions, placements, solves, and submissions.
- User directory with username search.
- Links to visible users open their profile pages.

### UI And Frontend

- Dark terminal-inspired platform layout.
- Text links use normal text color with underline instead of bright colored backgrounds.
- Buttons are visually distinct from text links.
- Repeated lists use compact previews with SHOW MORE / pagination patterns where appropriate.
- Live challenge panel highlights only the active round while a CTF is running.
- Archived challenge cards show full Markdown body, hints, and dist downloads.
- Responsive tables and action rows for desktop and smaller screens.

### Scoreboard

- Competition detail page shows only the top scoreboard preview rows.
- Default preview size is 12 players.
- Organizers can customize `Scoreboard preview rows` per competition.
- Full scoreboard page is available at `/competitions/<id>/scoreboard`.
- Full scoreboard uses pagination.
- Live API/WebSocket updates respect the scoreboard preview limit and report total ranked players.

### Collaboration

- Organizers can create collaboration invite links.
- Invite roles:
  - `editor`: edit competition, challenges, uploads, sorting, announcements.
  - `viewer`: preview-only access.
- Invite links can expire and be revoked.
- Accepted collaborators are listed on the competition management page.
- Audit log records collaboration and competition-management actions.

### Admin

- Admin dashboard for:
  - Organizer applications
  - Competition review / archive decisions
  - User roles
  - User active/inactive status
  - Admin password reset for users
- Admin can promote/demote users while protecting the last active admin.
- Admin can review pending competitions and organizer requests.

### Security And Consistency

- HMAC-signed HttpOnly sessions.
- SameSite=Lax session cookies.
- scrypt password hashing.
- CSRF protection on POST forms.
- Flag attempts are digested before storing submission history.
- Static flags are hashed server-side.
- Regex flags are validated and full-matched.
- Uploaded dist files are stored outside route paths and served through permission checks.
- SQLite writes use `BEGIN IMMEDIATE`.
- `solves` has `UNIQUE(user_id, challenge_id)` so duplicate or concurrent correct submissions score once.

## Live Demo

The easiest demo path is the one-command setup script. It clears the local demo database and uploads, rebuilds Docker, starts the platform on `0.0.0.0:8000`, and seeds realistic demo data.

### 1. Prepare Python dependencies

The demo script uses the local `.venv` for syntax checks and seeding.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
```

### 2. Rebuild and seed the demo

```bash
./scripts/setup_demo.sh
```

The script performs:

- Python syntax check.
- Flag regex behavior check.
- `docker compose down`.
- Database and upload cleanup.
- `docker compose up --build -d`.
- Demo database seed.

It uses `docker compose` when available. If the user is not in the Docker group, it falls back to `sudo -n docker compose`.

### 3. Open the demo

Open:

```text
http://127.0.0.1:8000/competitions
```

If browsing from another machine, use the host's address:

```text
http://<host-ip>:8000/competitions
```

Docker Compose binds:

```text
0.0.0.0:8000->8000/tcp
```

### Demo Accounts

All seeded demo accounts use:

```text
DemoPass123!
```

Useful accounts:

| Role | Username | Password |
| --- | --- | --- |
| Admin | `demo_admin` | `DemoPass123!` |
| Organizer | `alice_org` | `DemoPass123!` |
| Organizer | `bob_org` | `DemoPass123!` |
| Player | `ada_player` | `DemoPass123!` |

Additional player accounts are seeded so the running CTF scoreboard has more than 12 ranked players.

### Demo Data

`scripts/seed_demo.py` creates:

- 18 users.
- 3 competitions:
  - Running: `Cyber Relay Live CTF`
  - Upcoming: `Weekend Qualifier 2026`
  - Archived: `Spring Archive CTF`
- 10 challenges.
- Challenge round lengths from 3 to 15 minutes.
- Markdown challenge statements for every demo challenge.
- One ZIP dist file per demo challenge.
- Demo registrations, solves, submissions, announcements, profiles, and collaboration links.
- A running CTF with 15 ranked players, so the competition detail page shows top 12 and the full scoreboard page shows the rest.

Example archived dist download:

```text
http://127.0.0.1:8000/challenges/7/dist
```

## Local Development

Run without Docker:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python app.py
```

Open:

```text
http://127.0.0.1:8000
```

On first launch without seeded data, the app shows the setup page and asks for the platform name and first admin account.

## Docker

Run:

```bash
docker compose up --build
```

Or detached:

```bash
docker compose up --build -d
```

Compose uses these persistent host paths:

- `./instance:/app/instance` for SQLite and the secret key.
- `./uploads:/app/uploads` for challenge dist files.

Useful commands:

```bash
docker compose ps
docker compose logs -f
docker compose down
```

## Scripts

### `scripts/setup_demo.sh`

One-command live demo rebuild. It is destructive for local demo data:

- Removes `instance/ctf_platform.sqlite3`.
- Clears `uploads/`.
- Rebuilds Docker.
- Seeds demo users, competitions, challenges, solves, and dist files.

### `scripts/seed_demo.py`

Seeds demo data using the current time, not hard-coded competition times. It can be run manually after starting Docker:

```bash
CTF_DB_PATH=instance/ctf_platform.sqlite3 CTF_UPLOAD_DIR=uploads .venv/bin/python scripts/seed_demo.py
```

### `scripts/check_flag_regex.py`

Verifies static flag matching and regex full-match behavior:

```bash
.venv/bin/python scripts/check_flag_regex.py
```

## Important Routes

| Route | Purpose |
| --- | --- |
| `/setup` | First admin setup |
| `/login` | Login |
| `/dashboard` | User dashboard |
| `/users` | User list and username search |
| `/users/<username>` | Public user profile |
| `/profile` | Edit current user profile |
| `/admin` | Admin dashboard |
| `/competitions` | Running/upcoming/archived competition index |
| `/competitions/new` | Create competition |
| `/competitions/<id>` | Competition detail and live round |
| `/competitions/<id>/scoreboard` | Full scoreboard |
| `/competitions/<id>/challenges/new` | Create challenge |
| `/challenges/<id>/preview` | Organizer/collaborator challenge preview |
| `/challenges/<id>/dist` | Challenge dist download |
| `/competitions/<id>/export.json` | Export competition config |
| `/competitions/import` | Import competition config |
| `/api/competitions/<id>/state` | Live state JSON API |
| `/ws/competitions/<id>` | Live state WebSocket |

## Environment Variables

| Name | Default | Purpose |
| --- | --- | --- |
| `HOST` | `0.0.0.0` in Docker | Server bind host |
| `PORT` | `8000` | Server port |
| `APP_TZ` | `Asia/Taipei` | Local display timezone |
| `CTF_DB_PATH` | `instance/ctf_platform.sqlite3` | SQLite database path |
| `CTF_SECRET_PATH` | `instance/secret.key` | Session signing secret |
| `CTF_UPLOAD_DIR` | `instance/uploads` locally, `/app/uploads` in Docker | Dist file storage |
| `CTF_MAX_UPLOAD_BYTES` | `52428800` | Upload limit |

## Race Condition Protection

Flag submission runs in a single SQLite transaction:

1. Re-read challenge round and competition status.
2. Check registration.
3. Check `opens_at <= now < closes_at` with server time.
4. Validate the flag.
5. Insert into `solves`.
6. Record the submission result.

The `UNIQUE(user_id, challenge_id)` constraint prevents duplicated solves from scoring twice, even under concurrent correct submissions.
