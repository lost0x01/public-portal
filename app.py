from __future__ import annotations

import csv
import ipaddress
import os
import secrets
import sqlite3
from contextlib import contextmanager
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import uvicorn
from fastapi import FastAPI, Form, HTTPException, Request, UploadFile, File
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

APP_TITLE = "Operations Portal"
APP_SUBTITLE = "A generic internal workspace for requests, tasks, documents, costs, and deliverables."
NAV_GROUPS = [
    {
        "label": "Command",
        "items": [
            {"label": "Dashboard", "href": "#dashboard"},
            {"label": "Requests", "href": "#requests"},
            {"label": "Tasks", "href": "#tasks"},
        ],
    },
    {
        "label": "Response",
        "items": [
            {"label": "SOAR", "href": "#soar"},
            {"label": "Cases", "href": "#cases"},
            {"label": "Playbooks", "href": "#playbooks"},
            {"label": "Approvals", "href": "#approvals"},
        ],
    },
    {
        "label": "Delivery",
        "items": [
            {"label": "Documents", "href": "#documents"},
            {"label": "Costs", "href": "#costs"},
            {"label": "Deliverables", "href": "#deliverables"},
        ],
    },
]
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.getenv("PORTAL_DATA_DIR", BASE_DIR / "data"))
DOCUMENTS_DIR = Path(os.getenv("PORTAL_DOCUMENTS_DIR", DATA_DIR / "documents"))
DB_PATH = DATA_DIR / "portal.db"
STATIC_DIR = BASE_DIR / "static"
TEMPLATES_DIR = BASE_DIR / "templates"
DEFAULT_ALLOWED_CIDRS = "127.0.0.1/32,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"
DEFAULT_SECRET = "public-portal-change-me"
TRUST_X_FORWARDED_FOR = os.getenv("PORTAL_TRUST_X_FORWARDED_FOR", "false").strip().lower() in {"1", "true", "yes", "on"}

SOAR_DEMO_CASES = [
    {
        "id": 1042,
        "title": "Suspicious identity reset burst",
        "severity": "high",
        "status": "open",
        "case_type": "identity",
        "summary": "Multiple password reset attempts and VPN logins from a new geography were grouped into one case.",
        "latest_event": "Artifact bundle attached and analyst triage is in progress.",
    },
    {
        "id": 1038,
        "title": "Endpoint beaconing review",
        "severity": "medium",
        "status": "monitoring",
        "case_type": "endpoint",
        "summary": "A workstation was isolated for outbound beacon-like traffic and needs follow-up validation.",
        "latest_event": "Playbook queued for observable enrichment and host containment checks.",
    },
]
SOAR_DEMO_PLAYBOOKS = [
    {
        "key": "identity-triage",
        "title": "Identity triage",
        "scope": "identity",
        "trigger": "manual",
        "description": "Collect reset activity, sign-in telemetry, and asset context before operator review.",
        "steps": ["Collect evidence", "Enrich accounts", "Assess blast radius", "Escalate if confirmed"],
    },
    {
        "key": "endpoint-enrichment",
        "title": "Endpoint enrichment",
        "scope": "endpoint",
        "trigger": "manual",
        "description": "Normalize host indicators, review detections, and stage a containment recommendation.",
        "steps": ["Pull host facts", "Attach observables", "Check detections", "Prepare next action"],
    },
]
SOAR_DEMO_APPROVALS = [
    {
        "id": 77,
        "task_title": "Disable suspicious account session",
        "case_title": "Suspicious identity reset burst",
        "action": "account-disable",
        "reason": "Human approval required before impacting a business-critical user.",
        "status": "pending",
    }
]

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(title=APP_TITLE, lifespan=lifespan)
app.add_middleware(SessionMiddleware, secret_key=os.getenv("PORTAL_SECRET_KEY", DEFAULT_SECRET), same_site="lax")
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def parse_cidrs() -> list[ipaddress._BaseNetwork]:
    raw = os.getenv("PORTAL_ALLOWED_CIDRS", DEFAULT_ALLOWED_CIDRS)
    return [ipaddress.ip_network(part.strip(), strict=False) for part in raw.split(",") if part.strip()]


def client_ip(request: Request) -> str:
    if TRUST_X_FORWARDED_FOR:
        forwarded = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
        if forwarded:
            return forwarded
    host = request.client.host if request.client else "127.0.0.1"
    # Starlette's TestClient uses a symbolic host; treat it as local-only.
    return "127.0.0.1" if host == "testclient" else host


@app.middleware("http")
async def cidr_allowlist(request: Request, call_next):
    try:
        ip = ipaddress.ip_address(client_ip(request))
        if not any(ip in network for network in parse_cidrs()):
            return JSONResponse({"detail": "Forbidden"}, status_code=403)
    except ValueError:
        return JSONResponse({"detail": "Forbidden"}, status_code=403)
    return await call_next(request)


@contextmanager
def db() -> Any:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    DOCUMENTS_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    with db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                display_name TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                requester TEXT NOT NULL,
                category TEXT NOT NULL,
                summary TEXT NOT NULL,
                details TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'new'
            );
            CREATE TABLE IF NOT EXISTS tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                title TEXT NOT NULL,
                owner TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'todo',
                priority TEXT NOT NULL DEFAULT 'normal',
                due_date TEXT DEFAULT '',
                notes TEXT DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS costs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                cost_date TEXT NOT NULL,
                provider TEXT NOT NULL,
                category TEXT NOT NULL,
                amount REAL NOT NULL,
                notes TEXT DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS deliverables (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                title TEXT NOT NULL,
                owner TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'planned',
                due_date TEXT DEFAULT '',
                url TEXT DEFAULT '',
                notes TEXT DEFAULT ''
            );
            """
        )
        bootstrap_admin(conn)


def password_hash(password: str, salt: str | None = None) -> str:
    salt = salt or secrets.token_hex(16)
    import hashlib

    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 120_000).hex()
    return f"pbkdf2_sha256${salt}${digest}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, salt, digest = stored.split("$", 2)
    except ValueError:
        return False
    if algo != "pbkdf2_sha256":
        return False
    return secrets.compare_digest(password_hash(password, salt).split("$", 2)[2], digest)


def bootstrap_admin(conn: sqlite3.Connection) -> None:
    username = os.getenv("PORTAL_ADMIN_USERNAME", "admin")
    password = os.getenv("PORTAL_ADMIN_PASSWORD", "change-me")
    display = os.getenv("PORTAL_ADMIN_DISPLAY_NAME", "Administrator")
    exists = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
    if not exists:
        conn.execute(
            "INSERT INTO users (username, password_hash, display_name, created_at) VALUES (?, ?, ?, ?)",
            (username, password_hash(password), display, now_iso()),
        )


def authenticated(request: Request) -> bool:
    return bool(request.session.get("user_id"))


def require_auth(request: Request) -> None:
    if not authenticated(request):
        raise HTTPException(status_code=401, detail="Authentication required")


def rowdicts(rows: list[sqlite3.Row]) -> list[dict[str, Any]]:
    return [dict(row) for row in rows]


def dashboard_data() -> dict[str, Any]:
    with db() as conn:
        open_requests = conn.execute("SELECT COUNT(*) AS c FROM requests WHERE status != 'closed'").fetchone()["c"]
        active_tasks = conn.execute("SELECT COUNT(*) AS c FROM tasks WHERE status NOT IN ('done','cancelled')").fetchone()["c"]
        planned_deliverables = conn.execute("SELECT COUNT(*) AS c FROM deliverables WHERE status != 'published'").fetchone()["c"]
        total_cost = conn.execute("SELECT COALESCE(SUM(amount), 0) AS c FROM costs").fetchone()["c"]
        requests = rowdicts(conn.execute("SELECT * FROM requests ORDER BY id DESC LIMIT 8").fetchall())
        tasks = rowdicts(conn.execute("SELECT * FROM tasks ORDER BY id DESC LIMIT 8").fetchall())
        deliverables = rowdicts(conn.execute("SELECT * FROM deliverables ORDER BY id DESC LIMIT 8").fetchall())
    return {
        "metrics": {
            "open_requests": open_requests,
            "active_tasks": active_tasks,
            "planned_deliverables": planned_deliverables,
            "total_cost": f"${total_cost:,.2f}",
        },
        "requests": requests,
        "tasks": tasks,
        "deliverables": deliverables,
        "soar_demo": {
            "summary": {
                "open_cases": len([case for case in SOAR_DEMO_CASES if case["status"] != "closed"]),
                "active_runs": len(SOAR_DEMO_PLAYBOOKS),
                "pending_approvals": len([item for item in SOAR_DEMO_APPROVALS if item["status"] == "pending"]),
                "playbook_count": len(SOAR_DEMO_PLAYBOOKS),
            },
            "cases": SOAR_DEMO_CASES,
            "playbooks": SOAR_DEMO_PLAYBOOKS,
            "approvals": SOAR_DEMO_APPROVALS,
        },
    }


def document_items() -> list[dict[str, str]]:
    DOCUMENTS_DIR.mkdir(parents=True, exist_ok=True)
    items = []
    for path in sorted(DOCUMENTS_DIR.rglob("*")):
        if path.is_file():
            stat = path.stat()
            rel = path.relative_to(DOCUMENTS_DIR).as_posix()
            items.append({
                "name": rel,
                "size": f"{stat.st_size / 1024:.1f} KB",
                "modified": datetime.fromtimestamp(stat.st_mtime, timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
                "url": f"/documents/file/{rel}",
            })
    return items


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok", "app": APP_TITLE}


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse(request, "login.html", {"title": APP_TITLE, "error": None})


@app.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...)):
    with db() as conn:
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if not user or not verify_password(password, user["password_hash"]):
        return templates.TemplateResponse(request, "login.html", {"title": APP_TITLE, "error": "Invalid username or password"}, status_code=401)
    request.session.update({"user_id": user["id"], "username": user["username"], "display_name": user["display_name"]})
    return RedirectResponse("/", status_code=303)


@app.post("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    if not authenticated(request):
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "title": APP_TITLE,
            "subtitle": APP_SUBTITLE,
            "user": request.session,
            "nav_groups": NAV_GROUPS,
            **dashboard_data(),
            "documents": document_items(),
        },
    )


@app.post("/requests")
def create_request(request: Request, requester: str = Form(...), category: str = Form(...), summary: str = Form(...), details: str = Form("")):
    require_auth(request)
    with db() as conn:
        conn.execute("INSERT INTO requests (created_at, requester, category, summary, details) VALUES (?, ?, ?, ?, ?)", (now_iso(), requester, category, summary, details))
    return RedirectResponse("/#requests", status_code=303)


@app.post("/tasks")
def create_task(request: Request, title: str = Form(...), owner: str = Form(...), priority: str = Form("normal"), due_date: str = Form(""), notes: str = Form("")):
    require_auth(request)
    with db() as conn:
        conn.execute("INSERT INTO tasks (created_at, title, owner, priority, due_date, notes) VALUES (?, ?, ?, ?, ?, ?)", (now_iso(), title, owner, priority, due_date, notes))
    return RedirectResponse("/#tasks", status_code=303)


@app.post("/tasks/{task_id}/status")
def update_task_status(request: Request, task_id: int, status: str = Form(...)):
    require_auth(request)
    allowed = {"todo", "in_progress", "blocked", "done", "cancelled"}
    if status not in allowed:
        raise HTTPException(status_code=400, detail="Invalid status")
    with db() as conn:
        conn.execute("UPDATE tasks SET status = ? WHERE id = ?", (status, task_id))
    return RedirectResponse("/#tasks", status_code=303)


@app.post("/costs")
def create_cost(request: Request, cost_date: str = Form(...), provider: str = Form(...), category: str = Form(...), amount: float = Form(...), notes: str = Form("")):
    require_auth(request)
    with db() as conn:
        conn.execute("INSERT INTO costs (created_at, cost_date, provider, category, amount, notes) VALUES (?, ?, ?, ?, ?, ?)", (now_iso(), cost_date, provider, category, amount, notes))
    return RedirectResponse("/#costs", status_code=303)


@app.post("/deliverables")
def create_deliverable(request: Request, title: str = Form(...), owner: str = Form(...), status: str = Form("planned"), due_date: str = Form(""), url: str = Form(""), notes: str = Form("")):
    require_auth(request)
    with db() as conn:
        conn.execute("INSERT INTO deliverables (created_at, title, owner, status, due_date, url, notes) VALUES (?, ?, ?, ?, ?, ?, ?)", (now_iso(), title, owner, status, due_date, url, notes))
    return RedirectResponse("/#deliverables", status_code=303)


@app.post("/documents/upload")
async def upload_document(request: Request, file: UploadFile = File(...)):
    require_auth(request)
    safe_name = Path(file.filename or "upload.bin").name
    target = DOCUMENTS_DIR / safe_name
    target.write_bytes(await file.read())
    return RedirectResponse("/#documents", status_code=303)


@app.get("/documents/file/{path:path}")
def get_document(request: Request, path: str):
    require_auth(request)
    target = (DOCUMENTS_DIR / path).resolve()
    if not str(target).startswith(str(DOCUMENTS_DIR.resolve())) or not target.is_file():
        raise HTTPException(status_code=404, detail="Not found")
    return StreamingResponse(open(target, "rb"), media_type="application/octet-stream", headers={"Content-Disposition": f'attachment; filename="{target.name}"'})


@app.get("/data.json")
def data_json(request: Request):
    require_auth(request)
    return {**dashboard_data(), "documents": document_items()}


@app.get("/export/{table}.csv")
def export_csv(request: Request, table: str):
    require_auth(request)
    allowed = {"requests", "tasks", "costs", "deliverables"}
    if table not in allowed:
        raise HTTPException(status_code=404, detail="Unknown export")
    with db() as conn:
        rows = rowdicts(conn.execute(f"SELECT * FROM {table} ORDER BY id DESC").fetchall())
    def generate():
        if not rows:
            yield "\n"
            return
        import io
        buffer = io.StringIO()
        writer = csv.DictWriter(buffer, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
        yield buffer.getvalue()
    return StreamingResponse(generate(), media_type="text/csv", headers={"Content-Disposition": f'attachment; filename="{table}.csv"'})


if __name__ == "__main__":
    uvicorn.run("app:app", host=os.getenv("PORTAL_HOST", "127.0.0.1"), port=int(os.getenv("PORTAL_PORT", "8008")), reload=False)
