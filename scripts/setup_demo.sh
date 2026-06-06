#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if docker compose ps >/dev/null 2>&1; then
  COMPOSE=(docker compose)
elif sudo -n docker compose ps >/dev/null 2>&1; then
  COMPOSE=(sudo -n docker compose)
else
  echo "Cannot access Docker. Add this user to the docker group or enable passwordless sudo for docker." >&2
  exit 1
fi

echo "[1/6] Checking Python syntax and flag behavior"
.venv/bin/python -m compileall ctf_platform app.py >/dev/null
.venv/bin/python scripts/check_flag_regex.py

echo "[2/6] Stopping Docker services"
"${COMPOSE[@]}" down

echo "[3/6] Clearing database and uploads"
rm -f instance/ctf_platform.sqlite3 instance/ctf_platform.sqlite3-shm instance/ctf_platform.sqlite3-wal
mkdir -p uploads
find uploads -mindepth 1 -delete

echo "[4/6] Building and starting Docker"
"${COMPOSE[@]}" up --build -d

echo "[5/6] Waiting for web service"
for _ in $(seq 1 40); do
  if curl -fsS http://127.0.0.1:8000/ >/dev/null 2>&1; then
    break
  fi
  sleep 0.5
done

echo "[6/6] Seeding demo data"
CTF_DB_PATH=instance/ctf_platform.sqlite3 CTF_UPLOAD_DIR=uploads .venv/bin/python scripts/seed_demo.py

echo
echo "Demo ready: http://127.0.0.1:8000/competitions"
echo "Admin: demo_admin / DemoPass123!"
echo "Organizer: alice_org / DemoPass123!"
echo "Player: ada_player / DemoPass123!"
