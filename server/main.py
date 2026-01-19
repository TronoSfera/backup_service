"""Main application entry point for the backup server.

This FastAPI application implements both a REST API for clients to register,
upload backups and send health checks, as well as a minimal web interface
for administrators to monitor clients and manage retention policies.  The
design follows the requirements:

* Clients register themselves with the server and obtain a unique token used
  for subsequent API calls.
* Files are uploaded as multipart form data; the server computes the file's
  hash and uses a hash‑to‑storage lookup to avoid reuploading duplicates
 【744670406339295†L270-L339】.
* Retention policies can be configured per user via maximum age (days) or
  maximum number of versions, reflecting best practices for balancing version
  depth against storage consumption【709290716836410†L142-L159】.
* The server can be run under Docker and stores data in a relational database
  and optionally S3 for the backing file store.  A simple admin interface
  displays client statuses and last backup times.
"""

from __future__ import annotations

import asyncio
import datetime
import hashlib
import os
from typing import List, Optional

from fastapi import (
    FastAPI,
    Depends,
    HTTPException,
    status,
    File,
    UploadFile,
    Form,
    Request,
    Response,
)
from fastapi.responses import HTMLResponse, FileResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.exception_handlers import http_exception_handler
from sqlalchemy.orm import Session

from . import models, schemas, auth, storage as storage_module, database

app = FastAPI(title="Backup Service")
templates = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "templates"))

storage = storage_module.get_storage()


def ensure_default_admin() -> None:
    """Seed an initial admin user when the database is empty.

    Uses ADMIN_USERNAME/ADMIN_PASSWORD, falling back to USERNAME/PASSWORD for
    backward compatibility with existing compose files and .env settings.
    """
    username = os.getenv("ADMIN_USERNAME") or os.getenv("USERNAME")
    password = os.getenv("ADMIN_PASSWORD") or os.getenv("PASSWORD")
    if not username or not password:
        return
    db = database.SessionLocal()
    try:
        existing_user = db.query(models.User).first()
        if existing_user:
            return
        admin = models.User(
            username=username,
            hashed_password=auth.hash_password(password),
            is_admin=True,
        )
        db.add(admin)
        db.commit()
    finally:
        db.close()


@app.exception_handler(HTTPException)
async def custom_http_exception_handler(request: Request, exc: HTTPException) -> Response:
    if (
        exc.status_code == status.HTTP_401_UNAUTHORIZED
        and "text/html" in request.headers.get("accept", "")
        and not request.url.path.startswith("/api")
    ):
        return RedirectResponse(url="/login")
    return await http_exception_handler(request, exc)


@app.on_event("startup")
async def on_startup() -> None:
    # Create database tables if they do not exist
    models.Base.metadata.create_all(bind=database.engine)

    # Ensure the `pre_commands` column exists on the clients table.  SQLite will
    # ignore the ALTER TABLE if the column already exists.  For other
    # databases this may fail gracefully if the column exists.
    try:
        with database.engine.connect() as conn:
            conn.execute("""ALTER TABLE clients ADD COLUMN pre_commands TEXT""")
    except Exception:
        # Column already exists or migration failed; ignore
        pass

    ensure_default_admin()


@app.post("/api/register_user", response_model=schemas.UserOut)
async def register_user(
    user: schemas.UserCreate,
    db: Session = Depends(database.get_db),
    current_admin: models.User = Depends(auth.get_current_admin),
) -> schemas.UserOut:
    """Create a new user.

    Only administrators may create users.  The user's password is hashed
    before storage.  Retention policies can be optionally provided.
    """
    existing = db.query(models.User).filter(models.User.username == user.username).first()
    if existing:
        raise HTTPException(status_code=400, detail="Username already exists")
    hashed_password = auth.hash_password(user.password)
    db_user = models.User(
        username=user.username,
        hashed_password=hashed_password,
        is_admin=user.is_admin,
        retention_days=user.retention_days,
        retention_versions=user.retention_versions,
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


@app.post("/api/login", response_model=schemas.Token)
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(database.get_db),
) -> schemas.Token:
    """Authenticate a user and return a JWT token."""
    user = db.query(models.User).filter(models.User.username == form_data.username).first()
    if not user or not auth.verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = auth.create_access_token(data={"sub": user.id, "is_admin": user.is_admin})
    return schemas.Token(access_token=access_token)


@app.post("/api/clients/register", response_model=schemas.ClientOut)
async def register_client(
    req: schemas.ClientRegisterRequest,
    db: Session = Depends(database.get_db),
    current_admin: models.User = Depends(auth.get_current_admin),
) -> schemas.ClientOut:
    """Register a new client and return its unique token.

    Only administrators may call this endpoint.  A client belongs to a specific
    user (owner).  If ``owner_id`` is omitted the current admin becomes the
    owner.
    """
    owner_id = req.owner_id or current_admin.id
    owner = db.query(models.User).filter(models.User.id == owner_id).first()
    if owner is None:
        raise HTTPException(status_code=404, detail="Owner not found")
    # Generate a random token; collisions are extremely unlikely
    token = hashlib.sha256(os.urandom(32)).hexdigest()
    client = models.Client(name=req.name, token=token, owner_id=owner.id)
    db.add(client)
    db.commit()
    db.refresh(client)
    return client


def get_client_by_token(token: str, db: Session) -> models.Client:
    client = db.query(models.Client).filter(models.Client.token == token).first()
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    return client


@app.post("/api/clients/{client_token}/ping")
async def client_ping(
    client_token: str,
    db: Session = Depends(database.get_db),
) -> dict[str, str]:
    """Update the last ping time for a client.

    Clients should call this endpoint periodically to indicate they are alive.
    """
    client = get_client_by_token(client_token, db)
    client.last_ping = datetime.datetime.utcnow()
    db.commit()
    return {"status": "pong"}


async def prune_old_versions(
    db: Session,
    client: models.Client,
    original_path: str,
    retention_days: Optional[int],
    retention_versions: Optional[int],
) -> None:
    """Prune old backup versions according to retention policies.

    This helper deletes the oldest entries that fall outside the specified
    retention age or count.  Both policies can be combined; whichever removes
    more versions takes effect.  The current (most recent) version is always
    retained.
    """
    query = (
        db.query(models.BackupFile)
        .join(models.FileHash)
        .filter(models.BackupFile.client_id == client.id)
        .filter(models.BackupFile.original_path == original_path)
        .order_by(models.BackupFile.version_time.desc())
    )
    backups: List[models.BackupFile] = query.all()
    if not backups:
        return
    # Keep the newest backup always
    backups_to_consider = backups[1:]
    to_delete: List[models.BackupFile] = []
    now = datetime.datetime.utcnow()
    # Age‑based retention
    if retention_days is not None:
        cutoff = now - datetime.timedelta(days=retention_days)
        for bf in backups_to_consider:
            if bf.version_time < cutoff:
                to_delete.append(bf)
    # Count‑based retention
    if retention_versions is not None and len(backups) > retention_versions:
        to_delete.extend(backups[retention_versions:])
    # Remove duplicates in case both policies selected the same backup
    unique_to_delete = {b.id: b for b in to_delete}.values()
    for bf in unique_to_delete:
        # Delete database record
        db.delete(bf)
        # Determine if file hash is still referenced by any backup
        if len(bf.file_hash.backups) == 1:
            # Last reference; remove physical file
            asyncio.create_task(storage.delete_file(bf.file_hash.storage_path))  # schedule deletion
            db.delete(bf.file_hash)
    db.commit()


@app.post("/api/clients/{client_token}/backup", response_model=schemas.BackupEntryOut)
async def upload_backup(
    client_token: str,
    file: UploadFile = File(...),
    path: str = Form(..., description="Original file path on the client"),
    retention_days: Optional[int] = Form(None, description="Override retention days for this file"),
    retention_versions: Optional[int] = Form(None, description="Override retention versions for this file"),
    db: Session = Depends(database.get_db),
) -> schemas.BackupEntryOut:
    """Upload a file from a client and create a backup entry.

    The client is identified by its token.  The server computes a SHA256 hash of
    the uploaded content; if a file with the same hash already exists in the
    deduplicated store, the new backup entry simply references the existing
    storage path【744670406339295†L270-L339】.  Retention policies defined on the
    owning user (either age or version count) are applied.
    """
    client = get_client_by_token(client_token, db)
    data = await file.read()
    hash_value = hashlib.sha256(data).hexdigest()
    # Check if file already exists
    file_hash = db.query(models.FileHash).filter(models.FileHash.hash_value == hash_value).first()
    storage_path: str
    if file_hash:
        storage_path = file_hash.storage_path
    else:
        # Save file to storage backend
        storage_path = await storage.save_file(data, filename=file.filename)
        file_hash = models.FileHash(hash_value=hash_value, storage_path=storage_path)
        db.add(file_hash)
    # Create backup record
    backup = models.BackupFile(
        client_id=client.id,
        file_hash=file_hash,
        original_path=path,
        size=len(data),
        version_time=datetime.datetime.utcnow(),
    )
    db.add(backup)
    # Update last backup time
    client.last_backup = backup.version_time
    db.commit()
    db.refresh(backup)
    # Apply retention policy.  Use overrides from the request if provided;
    # otherwise fall back to the owner's defaults.  This allows per‑file
    # policies configured via backup tasks.
    owner = client.owner
    effective_retention_days = retention_days if retention_days is not None else owner.retention_days
    effective_retention_versions = (
        retention_versions if retention_versions is not None else owner.retention_versions
    )
    await prune_old_versions(
        db=db,
        client=client,
        original_path=path,
        retention_days=effective_retention_days,
        retention_versions=effective_retention_versions,
    )
    return schemas.BackupEntryOut(
        id=backup.id,
        original_path=backup.original_path,
        version_time=backup.version_time,
        size=backup.size,
        file_hash=hash_value,
    )


@app.get("/api/clients/{client_token}/backups", response_model=List[schemas.BackupEntryOut])
async def list_backups(
    client_token: str,
    db: Session = Depends(database.get_db),
) -> List[schemas.BackupEntryOut]:
    """List backups for a client, ordered by newest first."""
    client = get_client_by_token(client_token, db)
    backups = (
        db.query(models.BackupFile)
        .filter(models.BackupFile.client_id == client.id)
        .order_by(models.BackupFile.version_time.desc())
        .all()
    )
    return [
        schemas.BackupEntryOut(
            id=b.id,
            original_path=b.original_path,
            version_time=b.version_time,
            size=b.size,
            file_hash=b.file_hash.hash_value,
        )
        for b in backups
    ]


@app.get("/api/clients/{client_token}/download/{backup_id}")
async def download_backup(
    client_token: str,
    backup_id: int,
    db: Session = Depends(database.get_db),
) -> Response:
    """Download the contents of a backup file.

    This endpoint streams the content of the stored file back to the client.  For
    S3 storage backends the content is downloaded from S3 on demand.  For local
    storage backends the file is read from disk.
    """
    client = get_client_by_token(client_token, db)
    backup = (
        db.query(models.BackupFile)
        .filter(models.BackupFile.id == backup_id)
        .filter(models.BackupFile.client_id == client.id)
        .first()
    )
    if not backup:
        raise HTTPException(status_code=404, detail="Backup not found")
    file_hash = backup.file_hash
    # Determine if storage is local
    if isinstance(storage, storage_module.LocalStorage):
        file_path = storage.root_dir / file_hash.storage_path
        return FileResponse(path=file_path, filename=os.path.basename(backup.original_path))
    else:
        # For S3 return the object contents
        s3 = storage.s3
        obj = s3.get_object(Bucket=storage.bucket_name, Key=file_hash.storage_path)
        content = obj["Body"].read()
        return Response(content=content, media_type="application/octet-stream")


@app.post("/api/clients/{client_token}/log")
async def log_from_client(
    client_token: str,
    level: str = Form(...),
    message: str = Form(...),
    db: Session = Depends(database.get_db),
) -> dict[str, str]:
    """Receive a log message from a client."""
    client = get_client_by_token(client_token, db)
    log_entry = models.ClientLog(
        client_id=client.id, level=level.upper(), message=message
    )
    db.add(log_entry)
    db.commit()
    return {"status": "logged"}


# ======== File structure and task management endpoints ========

@app.post("/api/clients/{client_token}/files")
async def update_client_files(
    client_token: str,
    files: List[dict],
    db: Session = Depends(database.get_db),
) -> dict[str, str]:
    """Receive a full file listing from a client and replace existing entries.

    The payload should be a list of objects with keys ``path`` and ``is_dir``.
    All existing ``ClientFile`` records for the client are removed and
    recreated from the provided list.  This endpoint allows the server to
    present a file tree in the web interface.
    """
    client = get_client_by_token(client_token, db)
    # Delete existing file entries
    db.query(models.ClientFile).filter(models.ClientFile.client_id == client.id).delete()
    # Insert new entries
    for item in files:
        p = item.get("path")
        is_dir = bool(item.get("is_dir"))
        if not p:
            continue
        cf = models.ClientFile(client_id=client.id, path=p, is_dir=is_dir)
        db.add(cf)
    db.commit()
    return {"status": "updated"}


@app.get("/api/clients/{client_id}/files", response_model=List[schemas.ClientFileOut])
async def list_client_files(
    client_id: int,
    db: Session = Depends(database.get_db),
    current_admin: models.User = Depends(auth.get_current_admin),
) -> List[schemas.ClientFileOut]:
    """Return the file structure for a given client.

    Administrators can query this endpoint to display a file tree in the web
    interface.  Files are returned unsorted; the UI may organise them into
    a hierarchical view.
    """
    client = db.query(models.Client).filter(models.Client.id == client_id).first()
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    entries = (
        db.query(models.ClientFile)
        .filter(models.ClientFile.client_id == client.id)
        .all()
    )
    return [schemas.ClientFileOut.from_orm(e) for e in entries]


@app.get("/api/clients/{client_token}/tasks", response_model=List[schemas.TaskOut])
async def get_tasks_for_client(
    client_token: str,
    db: Session = Depends(database.get_db),
) -> List[schemas.TaskOut]:
    """Return backup tasks for a client.

    This endpoint is called by the client to retrieve its scheduled tasks.  The
    `pre_commands` field is returned as a list of strings for easier
    consumption by the client.
    """
    client = get_client_by_token(client_token, db)
    tasks = (
        db.query(models.BackupTask)
        .filter(models.BackupTask.client_id == client.id)
        .all()
    )
    result: List[schemas.TaskOut] = []
    for t in tasks:
        commands: List[str] = []
        if t.pre_commands:
            commands = [cmd for cmd in t.pre_commands.splitlines() if cmd.strip()]
        # Determine pending run ID if there is a run with status PENDING
        pending_run = (
            db.query(models.TaskRun)
            .filter(models.TaskRun.task_id == t.id, models.TaskRun.status == "PENDING")
            .order_by(models.TaskRun.start_time.desc())
            .first()
        )
        pending_id = pending_run.id if pending_run else None
        result.append(
            schemas.TaskOut(
                id=t.id,
                path=t.path,
                frequency_minutes=t.frequency_minutes,
                pre_commands=commands,
                retention_days=t.retention_days,
                retention_versions=t.retention_versions,
                compress=t.compress,
                last_run=t.last_run,
                next_run=t.next_run,
                pending_run_id=pending_id,
            )
        )
    return result


@app.get("/api/clients/{client_id}/tasks", response_model=List[schemas.TaskOut])
async def list_tasks_for_admin(
    client_id: int,
    db: Session = Depends(database.get_db),
    current_admin: models.User = Depends(auth.get_current_admin),
) -> List[schemas.TaskOut]:
    """List tasks associated with a client (admin view)."""
    client = db.query(models.Client).filter(models.Client.id == client_id).first()
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    tasks = (
        db.query(models.BackupTask)
        .filter(models.BackupTask.client_id == client.id)
        .all()
    )
    out: List[schemas.TaskOut] = []
    for t in tasks:
        cmds = []
        if t.pre_commands:
            cmds = [c for c in t.pre_commands.splitlines() if c.strip()]
        pending_run = (
            db.query(models.TaskRun)
            .filter(models.TaskRun.task_id == t.id, models.TaskRun.status == "PENDING")
            .order_by(models.TaskRun.start_time.desc())
            .first()
        )
        pending_id = pending_run.id if pending_run else None
        out.append(
            schemas.TaskOut(
                id=t.id,
                path=t.path,
                frequency_minutes=t.frequency_minutes,
                pre_commands=cmds,
                retention_days=t.retention_days,
                retention_versions=t.retention_versions,
                compress=t.compress,
                last_run=t.last_run,
                next_run=t.next_run,
                pending_run_id=pending_id,
            )
        )
    return out


@app.post("/api/clients/{client_id}/tasks")
async def create_task(
    client_id: int,
    path: str = Form(...),
    frequency_minutes: int = Form(..., gt=0, description="Run frequency in minutes"),
    pre_commands: str = Form("", description="One command per line", max_length=4000),
    retention_days: Optional[int] = Form(None),
    retention_versions: Optional[int] = Form(None),
    compress: bool = Form(False),
    db: Session = Depends(database.get_db),
    current_admin: models.User = Depends(auth.get_current_admin),
) -> Response:
    """Create a new backup task for the specified client.

    Administrators use this endpoint (via the web UI) to schedule backups for
    specific files or directories.  The client will execute the task at the
    configured frequency.
    """
    client = db.query(models.Client).filter(models.Client.id == client_id).first()
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    task = models.BackupTask(
        client_id=client.id,
        path=path,
        frequency_minutes=frequency_minutes,
        pre_commands=pre_commands.strip() if pre_commands else None,
        retention_days=retention_days,
        retention_versions=retention_versions,
        compress=compress,
    )
    # Next run time initialised to now so that the client will pick up the task
    task.next_run = datetime.datetime.utcnow()
    db.add(task)
    db.commit()
    db.refresh(task)
    # Redirect back to the client detail page
    return Response(status_code=303, headers={"Location": f"/clients/{client_id}"})


@app.post("/api/clients/{client_id}/tasks/{task_id}/run")
async def run_task_now(
    client_id: int,
    task_id: int,
    db: Session = Depends(database.get_db),
    current_admin: models.User = Depends(auth.get_current_admin),
) -> dict[str, str]:
    """Request immediate execution of a task.

    This sets the task's ``next_run`` to the current time so the client will
    execute it on its next polling cycle.  A new ``TaskRun`` entry is
    created with status ``PENDING``.
    """
    task = (
        db.query(models.BackupTask)
        .filter(models.BackupTask.id == task_id, models.BackupTask.client_id == client_id)
        .first()
    )
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    now = datetime.datetime.utcnow()
    task.next_run = now
    # Create a TaskRun entry with pending status; it will be updated when
    # the client reports completion
    run = models.TaskRun(task_id=task.id, start_time=now, status="PENDING")
    db.add(run)
    db.commit()
    return {"status": "scheduled", "run_id": run.id}


@app.post("/api/clients/{client_token}/tasks/{task_id}/status")
async def report_task_status(
    client_token: str,
    task_id: int,
    run_id: int = Form(...),
    status: str = Form(...),
    message: str = Form(""),
    db: Session = Depends(database.get_db),
) -> dict[str, str]:
    """Receive status updates for a task run from the client.

    The client should call this endpoint after executing a task, providing
    the run ID (created by ``run_task_now``) along with its status and any
    message.  The server records the end time and updates the task's
    ``last_run`` and ``next_run`` values.
    """
    client = get_client_by_token(client_token, db)
    task = (
        db.query(models.BackupTask)
        .filter(models.BackupTask.id == task_id, models.BackupTask.client_id == client.id)
        .first()
    )
    if not task:
        raise HTTPException(status_code=404, detail="Task not found for this client")
    run = db.query(models.TaskRun).filter(models.TaskRun.id == run_id, models.TaskRun.task_id == task.id).first()
    now = datetime.datetime.utcnow()
    if not run:
        # If the run does not exist (e.g. scheduled automatically), create it
        run = models.TaskRun(task_id=task.id, start_time=now)
        db.add(run)
    run.end_time = now
    run.status = status
    run.message = message
    # Update task last_run and next_run times
    task.last_run = run.end_time
    if task.frequency_minutes:
        task.next_run = run.end_time + datetime.timedelta(minutes=task.frequency_minutes)
    db.commit()
    return {"status": "recorded", "run_id": run.id}


# ======== Client configuration endpoints =========

@app.get("/api/clients/{client_token}/config", response_model=schemas.ClientConfigOut)
async def get_client_config(
    client_token: str,
    db: Session = Depends(database.get_db),
) -> schemas.ClientConfigOut:
    """Return configuration information for a client.

    Currently this includes the list of pre‑backup commands.  The client
    requests this endpoint to retrieve any commands set by administrators.
    """
    client = get_client_by_token(client_token, db)
    commands = []
    if client.pre_commands:
        commands = [cmd for cmd in client.pre_commands.splitlines() if cmd.strip()]
    return schemas.ClientConfigOut(pre_commands=commands)


@app.post("/api/clients/{client_id}/config")
async def update_client_config(
    client_id: int,
    pre_commands: str = Form(..., description="One command per line"),
    db: Session = Depends(database.get_db),
    current_admin: models.User = Depends(auth.get_current_admin),
) -> Response:
    """Update configuration for a client.

    Administrators can set shell commands to be executed by the client before
    each backup.  These commands are stored on the server and delivered to
    clients via the `/api/clients/{client_token}/config` endpoint.  Commands
    should be separated by newlines.
    """
    client = db.query(models.Client).filter(models.Client.id == client_id).first()
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    client.pre_commands = pre_commands.strip() if pre_commands else None
    db.commit()
    # Redirect back to the client details page
    return Response(status_code=303, headers={"Location": f"/clients/{client_id}"})


# ======== Web interface routes =========

@app.get("/login", response_class=HTMLResponse)
async def login_page(
    request: Request,
    db: Session = Depends(database.get_db),
) -> Response:
    raw_token = request.cookies.get("access_token")
    if raw_token:
        try:
            current_user = await auth.get_current_user(request=request, token=None, db=db)
        except HTTPException:
            current_user = None
        if current_user and current_user.is_admin:
            return RedirectResponse(url="/clients", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse(
        "login.html",
        {
            "request": request,
            "title": "Admin Login",
        },
    )


@app.post("/login", response_class=HTMLResponse)
async def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(database.get_db),
) -> Response:
    user = db.query(models.User).filter(models.User.username == username).first()
    if not user or not auth.verify_password(password, user.hashed_password):
        return templates.TemplateResponse(
            "login.html",
            {
                "request": request,
                "title": "Admin Login",
                "error": "Invalid username or password.",
            },
            status_code=status.HTTP_401_UNAUTHORIZED,
        )
    access_token = auth.create_access_token(data={"sub": user.id, "is_admin": user.is_admin})
    response = RedirectResponse(url="/clients", status_code=status.HTTP_303_SEE_OTHER)
    response.set_cookie(
        "access_token",
        access_token,
        httponly=True,
        samesite="lax",
        path="/",
        max_age=auth.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )
    return response


@app.get("/logout")
async def logout() -> Response:
    response = RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie("access_token")
    return response


@app.get("/clients", response_class=HTMLResponse)
async def list_clients_page(
    request: Request,
    current_user: models.User = Depends(auth.get_current_admin),
    db: Session = Depends(database.get_db),
) -> Response:
    """Render a page that lists all clients with management actions."""
    clients = db.query(models.Client).all()
    return templates.TemplateResponse(
        "clients.html",
        {
            "request": request,
            "user": current_user,
            "clients": clients,
        },
    )


@app.get("/clients/{client_id}", response_class=HTMLResponse)
async def client_detail_page(
    client_id: int,
    request: Request,
    current_user: models.User = Depends(auth.get_current_admin),
    db: Session = Depends(database.get_db),
) -> Response:
    """Render details for a specific client, including backups and configuration."""
    client = db.query(models.Client).filter(models.Client.id == client_id).first()
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    # fetch backups ordered by latest
    backups = (
        db.query(models.BackupFile)
        .filter(models.BackupFile.client_id == client.id)
        .order_by(models.BackupFile.version_time.desc())
        .all()
    )
    files = (
        db.query(models.ClientFile)
        .filter(models.ClientFile.client_id == client.id)
        .order_by(models.ClientFile.path)
        .all()
    )
    tasks = (
        db.query(models.BackupTask)
        .filter(models.BackupTask.client_id == client.id)
        .all()
    )
    logs = (
        db.query(models.ClientLog)
        .filter(models.ClientLog.client_id == client.id)
        .order_by(models.ClientLog.timestamp.desc())
        .limit(50)
        .all()
    )
    # Prepare mappings for task history.  For each task, collect its run history and
    # the backup entries that correspond to the task's path.  This allows the
    # template to display run status and available versions per task.
    runs_map: dict[int, list] = {}
    backups_map: dict[str, list] = {}
    # Precompute runs for each task
    for t in tasks:
        runs = (
            db.query(models.TaskRun)
            .filter(models.TaskRun.task_id == t.id)
            .order_by(models.TaskRun.start_time.desc())
            .all()
        )
        runs_map[t.id] = runs
    # Group backups by original path
    for b in backups:
        backups_map.setdefault(b.original_path, []).append(b)

    return templates.TemplateResponse(
        "client_detail.html",
        {
            "request": request,
            "user": current_user,
            "client": client,
            "backups": backups,
            "files": files,
            "tasks": tasks,
            "logs": logs,
            "runs_map": runs_map,
            "backups_map": backups_map,
        },
    )


@app.get("/", response_class=HTMLResponse)
async def root_redirect(request: Request) -> Response:
    """Redirect the root URL to the clients list.

    The main administration interface is available at ``/clients``.  This
    redirect keeps the root endpoint simple and ensures there is no
    ambiguity with multiple handlers for ``/``.
    """
    return Response(status_code=303, headers={"Location": "/clients"})
