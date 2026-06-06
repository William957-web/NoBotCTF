from __future__ import annotations

import asyncio
import json
from html import escape
from http.cookies import SimpleCookie
import os
from urllib.parse import parse_qs

from fastapi import FastAPI, Request as FastAPIRequest, WebSocket, WebSocketDisconnect
from starlette.datastructures import UploadFile
from fastapi.staticfiles import StaticFiles
from starlette.responses import Response as ASGIResponse
import uvicorn

from . import web
from .config import BASE_DIR, MAX_UPLOAD_BYTES, SESSION_COOKIE
from .db import connect, init_db
from .security import unsign
from .utils import iso_utc, parse_iso, utcnow


class UploadedFile:
    def __init__(self, filename: str, content_type: str, data: bytes):
        self.filename = filename
        self.content_type = content_type or "application/octet-stream"
        self.data = data
        self.size = len(data)


class AppRequest:
    def __init__(
        self,
        method: str,
        path: str,
        query_string: str,
        cookies: dict[str, str],
        body: bytes,
        form: dict[str, str] | None = None,
        files: dict[str, UploadedFile] | None = None,
    ):
        self.method = method.upper()
        self.path = path
        self.query = self._parse_query(query_string)
        self.cookies = SimpleCookie()
        for name, value in cookies.items():
            self.cookies[name] = value
        self.session_id: str | None = None
        self.session = None
        self.current_user = None
        self._body = body
        self._form: dict[str, str] | None = form
        self.files = files or {}
        self.set_cookie: str | None = None

    @staticmethod
    def _parse_query(raw: str) -> dict[str, str]:
        values = parse_qs(raw, keep_blank_values=True)
        return {key: vals[-1] if vals else "" for key, vals in values.items()}

    @property
    def form(self) -> dict[str, str]:
        if self._form is not None:
            return self._form
        if len(self._body) > 1024 * 1024:
            self._form = {}
            return self._form
        raw = self._body.decode("utf-8", "replace")
        values = parse_qs(raw, keep_blank_values=True)
        self._form = {key: vals[-1] if vals else "" for key, vals in values.items()}
        return self._form

    @property
    def csrf_token(self) -> str:
        return self.session["csrf_token"] if self.session else ""


def to_asgi_response(response: web.Response, request: AppRequest) -> ASGIResponse:
    asgi_response = ASGIResponse(content=response.body, status_code=response.status)
    for name, value in response.headers:
        asgi_response.headers.append(name, value)
    if request.set_cookie:
        asgi_response.headers.append("Set-Cookie", request.set_cookie)
    return asgi_response


def load_user_from_cookie(cookies: dict[str, str]):
    signed = cookies.get(SESSION_COOKIE)
    sid = unsign(signed) if signed else None
    if not sid:
        return None
    now = iso_utc()
    with connect() as conn:
        session = conn.execute("SELECT * FROM sessions WHERE id = ? AND expires_at > ?", (sid, now)).fetchone()
        if not session or not session["user_id"]:
            return None
        return conn.execute("SELECT * FROM users WHERE id = ? AND is_active = 1", (session["user_id"],)).fetchone()


def build_competition_state(comp_id: int) -> dict:
    now = utcnow()
    with connect() as conn:
        competition = conn.execute("SELECT * FROM competitions WHERE id = ?", (comp_id,)).fetchone()
        active = web.active_challenge(conn, comp_id)
        scoreboard_limit = web.scoreboard_preview_limit_for(competition)
        full_board = web.scoreboard(conn, comp_id, None)
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
    return {
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


class LiveClient:
    def __init__(self, websocket: WebSocket):
        self.websocket = websocket
        self.lock = asyncio.Lock()

    async def send_json(self, payload: dict) -> None:
        async with self.lock:
            await self.websocket.send_json(payload)


class LiveHub:
    def __init__(self):
        self.connections: dict[int, set[LiveClient]] = {}
        self.last_active: dict[int, int | None] = {}
        self.lock = asyncio.Lock()
        self._running = True

    async def connect(self, comp_id: int, websocket: WebSocket) -> LiveClient:
        await websocket.accept()
        client = LiveClient(websocket)
        async with self.lock:
            self.connections.setdefault(comp_id, set()).add(client)
        payload = build_competition_state(comp_id)
        payload["type"] = "hello"
        payload["competition_id"] = comp_id
        await client.send_json(payload)
        return client

    async def disconnect(self, comp_id: int, client: LiveClient) -> None:
        async with self.lock:
            clients = self.connections.get(comp_id)
            if clients:
                clients.discard(client)
                if not clients:
                    self.connections.pop(comp_id, None)
                    self.last_active.pop(comp_id, None)

    async def snapshot(self) -> dict[int, list[LiveClient]]:
        async with self.lock:
            return {comp_id: list(clients) for comp_id, clients in self.connections.items()}

    async def run(self) -> None:
        while self._running:
            for comp_id, clients in (await self.snapshot()).items():
                payload = build_competition_state(comp_id)
                active_id = payload["active"]["id"] if payload["active"] else None
                previous_id = self.last_active.get(comp_id)
                payload["type"] = "round_changed" if active_id != previous_id else "tick"
                payload["competition_id"] = comp_id
                self.last_active[comp_id] = active_id
                stale: list[LiveClient] = []
                for client in clients:
                    try:
                        await client.send_json(payload)
                    except Exception:
                        stale.append(client)
                for client in stale:
                    await self.disconnect(comp_id, client)
            await asyncio.sleep(1)

    def stop(self) -> None:
        self._running = False


hub = LiveHub()
app = FastAPI(title="Time-windowed CTF Arena")
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")


@app.on_event("startup")
async def on_startup() -> None:
    init_db()
    app.state.live_task = asyncio.create_task(hub.run())


@app.on_event("shutdown")
async def on_shutdown() -> None:
    hub.stop()
    task = getattr(app.state, "live_task", None)
    if task:
        task.cancel()


@app.websocket("/ws/competitions/{comp_id}")
async def competition_ws(websocket: WebSocket, comp_id: int) -> None:
    competition = web.competition_by_id(comp_id)
    user = load_user_from_cookie(websocket.cookies)
    if not competition or not web.can_view_competition(user, competition):
        await websocket.close(code=1008)
        return

    client = await hub.connect(comp_id, websocket)
    try:
        while True:
            raw = await websocket.receive_text()
            try:
                message = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if message.get("type") == "sync":
                await client.send_json(
                    {
                        "type": "sync",
                        "competition_id": comp_id,
                        "client_sent_at": message.get("client_sent_at"),
                        "server_time": iso_utc(),
                    }
                )
    except WebSocketDisconnect:
        pass
    finally:
        await hub.disconnect(comp_id, client)


@app.api_route("/{path:path}", methods=["GET", "HEAD", "POST"])
async def dispatch(path: str, fastapi_request: FastAPIRequest) -> ASGIResponse:
    method = fastapi_request.method.upper()
    body = b""
    form = None
    files: dict[str, UploadedFile] = {}
    content_type = fastapi_request.headers.get("content-type", "")
    if method == "POST" and content_type.startswith("multipart/form-data"):
        form = {}
        form_data = await fastapi_request.form()
        for key, value in form_data.multi_items():
            if isinstance(value, UploadFile):
                if not value.filename:
                    continue
                data = await value.read()
                if len(data) > MAX_UPLOAD_BYTES:
                    request = AppRequest(
                        "GET" if method == "HEAD" else method,
                        "/" + path,
                        fastapi_request.url.query,
                        fastapi_request.cookies,
                        b"",
                        form,
                        files,
                    )
                    web.load_session(request)
                    return to_asgi_response(web.error_page(request, 400, "Uploaded file exceeds the size limit."), request)
                files[key] = UploadedFile(value.filename, value.content_type, data)
            else:
                form[key] = str(value)
    elif method == "POST":
        body = await fastapi_request.body()
    request = AppRequest(
        "GET" if method == "HEAD" else method,
        "/" + path,
        fastapi_request.url.query,
        fastapi_request.cookies,
        body,
        form,
        files,
    )
    try:
        web.load_session(request)
        if request.method == "POST" and request.form.get("_csrf") != request.csrf_token:
            response = web.error_page(request, 403, "Invalid CSRF token. Go back and try again.")
        else:
            response = None
            for route_method, pattern, handler in web.ROUTES:
                if route_method != request.method:
                    continue
                match = pattern.match(request.path)
                if match:
                    response = handler(request, **match.groupdict())
                    break
            if response is None:
                response = web.error_page(request, 404, "Page not found.")
    except Exception as exc:
        response = web.Response(
            f"Internal Server Error\n{escape(str(exc))}",
            500,
            [("Content-Type", "text/plain; charset=utf-8")],
        )
    return to_asgi_response(response, request)


def run() -> None:
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8000"))
    uvicorn.run("ctf_platform.asgi:app", host=host, port=port)
