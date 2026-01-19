"""End‑to‑end tests for the backup service API.

These tests exercise key functionality of the server to ensure that
registration, file structure reporting, task scheduling and status
reporting all work as expected.  A temporary SQLite database is
used so that the tests do not affect production data.  To execute
these tests, run ``pytest`` in the root of the repository.

Note: The tests import FastAPI and SQLAlchemy; ensure that these
dependencies are installed in your development environment.  In
offline or minimal environments you may need to install them
manually before running the tests.
"""

import os
import tempfile
import pytest
from datetime import datetime, timedelta

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backup_service.server import models, auth, database, main as server_app


@pytest.fixture(scope="function")
def test_client(tmp_path):
    """Set up a FastAPI TestClient with an isolated SQLite database.

    The fixture creates a temporary file for the SQLite database,
    overrides the ``get_db`` dependency to use a session bound to
    this database, and ensures that all tables are created before
    returning the TestClient instance.  After the test the overrides
    are cleared.
    """
    # Create a temporary SQLite database file
    db_path = tmp_path / "test.db"
    engine = create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})
    # Bind a sessionmaker to the temporary engine
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    # Create all tables on the temporary engine
    models.Base.metadata.create_all(bind=engine)

    # Dependency override to use the test session
    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    server_app.app.dependency_overrides[database.get_db] = override_get_db

    # Yield a TestClient instance
    with TestClient(server_app.app) as client:
        yield client

    # Clear overrides after the test to avoid side effects
    server_app.app.dependency_overrides.clear()


def _create_admin_user(db_session, username="admin", password="secret"):
    """Helper to insert an admin user into the database.

    Returns the created User object.  The password is hashed using
    the server's authentication helper so that the login endpoint
    functions correctly.
    """
    user = models.User(
        username=username,
        hashed_password=auth.hash_password(password),
        is_admin=True,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


def test_register_and_backup_flow(test_client):
    """End‑to‑end test of client registration, file listing, task
    creation and status reporting.

    This test performs the following steps:

    1. Insert an admin user into the test database.
    2. Log in as the admin to obtain a JWT token.
    3. Register a new client and capture its token and ID.
    4. Post a file structure for the client and verify it can be retrieved.
    5. Create a backup task via the admin API and verify it appears in the task list returned to the client.
    6. Schedule the task to run immediately and record a success status.
    7. Confirm that the task's ``last_run`` and ``next_run`` fields are updated accordingly.
    """
    # Access the test DB via the overridden get_db dependency
    db = next(server_app.app.dependency_overrides[database.get_db]())
    # Create an admin user in the DB so that login works
    admin = _create_admin_user(db)

    # Step 1: login to get JWT
    resp = test_client.post(
        "/api/login",
        data={"username": admin.username, "password": "secret"},
    )
    assert resp.status_code == 200
    token = resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Step 2: register a new client
    resp = test_client.post(
        "/api/clients/register",
        json={"name": "TestClient"},
        headers=headers,
    )
    assert resp.status_code == 200
    client_data = resp.json()
    client_id = client_data["id"]
    client_token = client_data["token"]

    # Step 3: post file structure
    file_list = [
        {"path": "/data", "is_dir": True},
        {"path": "/data/file.txt", "is_dir": False},
    ]
    resp = test_client.post(f"/api/clients/{client_token}/files", json=file_list)
    assert resp.status_code == 200
    assert resp.json()["status"] == "updated"
    # Verify admin can retrieve the file structure
    resp = test_client.get(f"/api/clients/{client_id}/files", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == len(file_list)
    paths = {entry["path"] for entry in data}
    assert "/data" in paths and "/data/file.txt" in paths

    # Step 4: create a task for backing up /data/file.txt every 5 minutes
    resp = test_client.post(
        f"/api/clients/{client_id}/tasks",
        data={
            "path": "/data/file.txt",
            "frequency_minutes": "5",
            "pre_commands": "echo pre",
            "retention_versions": "3",
            "retention_days": "30",
            "compress": "true",
        },
        headers=headers,
    )
    # The endpoint returns a 303 redirect on success
    assert resp.status_code == 303
    # Fetch tasks as the client would
    resp = test_client.get(f"/api/clients/{client_token}/tasks")
    assert resp.status_code == 200
    tasks = resp.json()
    assert len(tasks) == 1
    task = tasks[0]
    assert task["path"] == "/data/file.txt"
    assert task["frequency_minutes"] == 5
    assert task["retention_versions"] == 3
    assert task["retention_days"] == 30
    assert task["compress"] is True

    # Step 5: schedule the task to run immediately
    resp = test_client.post(
        f"/api/clients/{client_id}/tasks/{task['id']}/run",
        headers=headers,
    )
    assert resp.status_code == 200
    run_id = resp.json()["run_id"]
    # Fetch tasks again; pending_run_id should be set
    resp = test_client.get(f"/api/clients/{client_token}/tasks")
    task_with_pending = resp.json()[0]
    assert task_with_pending["pending_run_id"] == run_id

    # Step 6: simulate client reporting success
    resp = test_client.post(
        f"/api/clients/{client_token}/tasks/{task['id']}/status",
        data={"run_id": str(run_id), "status": "SUCCESS", "message": "ok"},
    )
    assert resp.status_code == 200
    # After reporting, pending_run_id should be cleared
    resp = test_client.get(f"/api/clients/{client_token}/tasks")
    updated_task = resp.json()[0]
    assert updated_task.get("pending_run_id") is None
    # The last_run and next_run fields should be set
    assert updated_task.get("last_run") is not None
    assert updated_task.get("next_run") is not None
