import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("PORTAL_SECRET_KEY", "test-secret")
os.environ.setdefault("PORTAL_ADMIN_USERNAME", "admin")
os.environ.setdefault("PORTAL_ADMIN_PASSWORD", "password")

from fastapi.testclient import TestClient
import app as portal


def make_client(tmp_path: Path):
    portal.DATA_DIR = tmp_path / "data"
    portal.DOCUMENTS_DIR = portal.DATA_DIR / "documents"
    portal.DB_PATH = portal.DATA_DIR / "portal.db"
    portal.init_db()
    return TestClient(portal.app)


def login(client: TestClient):
    return client.post("/login", data={"username": "admin", "password": "password"}, follow_redirects=False)


def test_healthz():
    with tempfile.TemporaryDirectory() as d:
        client = make_client(Path(d))
        response = client.get("/healthz")
        assert response.status_code == 200
        assert response.json()["status"] == "ok"


def test_login_and_dashboard_renders_generic_branding_only():
    with tempfile.TemporaryDirectory() as d:
        client = make_client(Path(d))
        response = login(client)
        assert response.status_code == 303
        page = client.get("/")
        assert page.status_code == 200
        assert "Operations Portal" in page.text
        assert "<img" not in page.text.lower()
        assert "brand" not in page.text.lower()
        assert 'class="tabs grouped-nav"' in page.text
        assert ">Command<" in page.text
        assert ">Delivery<" in page.text
        assert 'href="#requests"' in page.text
        assert 'href="#deliverables"' in page.text
        assert page.text.index(">Command<") < page.text.index(">Delivery<")


def test_create_records_and_export_json():
    with tempfile.TemporaryDirectory() as d:
        client = make_client(Path(d))
        login(client)
        assert client.post("/requests", data={"requester":"Alex", "category":"ops", "summary":"Need review", "details":"details"}, follow_redirects=False).status_code == 303
        assert client.post("/tasks", data={"title":"Prepare update", "owner":"Sam", "priority":"high"}, follow_redirects=False).status_code == 303
        assert client.post("/costs", data={"cost_date":"2026-01-01", "provider":"Example", "category":"hosting", "amount":"12.50"}, follow_redirects=False).status_code == 303
        assert client.post("/deliverables", data={"title":"Monthly memo", "owner":"Sam", "status":"planned"}, follow_redirects=False).status_code == 303
        data = client.get("/data.json").json()
        assert data["metrics"]["open_requests"] == 1
        assert data["metrics"]["active_tasks"] == 1
        assert data["metrics"]["total_cost"] == "$12.50"
        csv_response = client.get("/export/tasks.csv")
        assert csv_response.status_code == 200
        assert "Prepare update" in csv_response.text


def test_document_upload_and_download():
    with tempfile.TemporaryDirectory() as d:
        client = make_client(Path(d))
        login(client)
        response = client.post("/documents/upload", files={"file": ("hello.txt", b"hello", "text/plain")}, follow_redirects=False)
        assert response.status_code == 303
        page = client.get("/")
        assert "hello.txt" in page.text
        download = client.get("/documents/file/hello.txt")
        assert download.status_code == 200
        assert download.content == b"hello"


def test_protected_routes_require_login():
    with tempfile.TemporaryDirectory() as d:
        client = make_client(Path(d))
        assert client.get("/data.json").status_code == 401
        assert client.post("/tasks", data={"title":"x", "owner":"y"}).status_code == 401
