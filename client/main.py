"""Client agent for the backup service.

The client agent runs inside its own Docker container and periodically backs
up files to the backup server.  It performs the following operations:

1. On first run, authenticate to the server using credentials provided via
   environment variables and register itself as a new client.  The returned
   client token is stored locally.
2. Run optional pre‑backup commands specified in ``PRE_COMMANDS``.  These
   commands are executed in the container shell before each backup cycle; for
   example, you can use this feature to dump a PostgreSQL database to a
   file.
3. Walk through the directories specified in ``MONITORED_PATHS`` (comma
   separated) and compute a SHA256 hash of each file.  If the hash has not
   changed since the previous backup, the file is skipped to conserve
   bandwidth.  Otherwise, the file is uploaded to the server via the
   ``/api/clients/{client_token}/backup`` endpoint.
4. Periodically send a ``ping`` to the server to update the client's last
   heartbeat time.
5. Send log messages to the server when errors occur.

Configuration is provided entirely through environment variables:

    * ``SERVER_URL`` (required): Base URL of the backup server, e.g. ``http://server:8000``.
    * ``USERNAME`` and ``PASSWORD``: Credentials of a user with permission to
      register new clients.
    * ``CLIENT_NAME``: Human‑readable name for this client.
    * ``MONITORED_PATHS``: Comma‑separated list of directory paths to back up.
    * ``PRE_COMMANDS``: Semicolon‑separated list of shell commands to run before
      each backup cycle (optional).
    * ``PING_INTERVAL``: Seconds between ping requests (default: 300).
    * ``BACKUP_INTERVAL``: Seconds between backup cycles (default: 3600).

State such as the client token and previously computed file hashes is saved in
``state.json`` within the working directory.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, Optional, List, Tuple

import requests
import yaml  # type: ignore
import subprocess
from urllib.parse import urlparse
import datetime

# Imports for the web interface
from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
import threading
import uvicorn


STATE_FILE = "state.json"


@dataclass
class ClientState:
    token: Optional[str] = None  # client token assigned by server
    client_id: Optional[int] = None  # numeric ID assigned by server
    access_token: Optional[str] = None  # bearer token for API authentication
    file_hashes: Dict[str, str] = None  # maps file paths to last known hash

    def to_json(self) -> str:
        return json.dumps(asdict(self))

    @classmethod
    def from_json(cls, data: str) -> "ClientState":
        obj = json.loads(data)
        return cls(
            token=obj.get("token"),
            client_id=obj.get("client_id"),
            access_token=obj.get("access_token"),
            file_hashes=obj.get("file_hashes", {}),
        )


class BackupClient:
    def __init__(self) -> None:
        # Read initial configuration from environment variables.  These may be empty
        # when the client is first started; in that case the client will run
        # exclusively as a web UI until the user supplies configuration.
        self.server_url = os.environ.get("SERVER_URL") or ""
        self.username = os.environ.get("USERNAME") or ""
        self.password = os.environ.get("PASSWORD") or ""
        self.client_name = os.environ.get("CLIENT_NAME", os.uname().nodename)
        self.monitored_paths = [p.strip() for p in os.environ.get("MONITORED_PATHS", "").split(",") if p.strip()]
        self.pre_commands: List[str] = [c.strip() for c in os.environ.get("PRE_COMMANDS", "").split(";") if c.strip()]
        self.ping_interval = int(os.environ.get("PING_INTERVAL", "300"))
        self.backup_interval = int(os.environ.get("BACKUP_INTERVAL", "3600"))

        # A flag indicating whether the web UI should be enabled.  By default
        # the UI runs so that the client can be configured interactively when
        # environment variables are not provided.  Set the environment
        # variable ``CLIENT_UI_ENABLED`` to ``false`` or ``0`` to disable the
        # UI and run solely based on environment configuration.  When the UI
        # is disabled and mandatory settings are missing, the client will
        # terminate with an error.
        ui_env = os.environ.get("CLIENT_UI_ENABLED", "true").lower()
        self.ui_enabled = ui_env not in ("false", "0", "no")

        # Determine whether the client is configured enough to start backing up.
        self.configured = bool(self.server_url and self.username and self.password and self.monitored_paths)

        # Load saved state (token, access token, hashes).
        self.state = self._load_state()

        # Remote pre‑backup commands retrieved from the server; overrides local commands
        self.remote_pre_commands: List[str] = []

        # Track last run timestamps for each task ID so we don't run tasks too frequently
        # This dict maps task IDs to the last time we attempted to run them.
        self.task_last_run: Dict[int, float] = {}

    def _load_state(self) -> ClientState:
        if os.path.exists(STATE_FILE):
            with open(STATE_FILE, "r") as f:
                try:
                    return ClientState.from_json(f.read())
                except Exception:
                    pass
        return ClientState(token=None, client_id=None, access_token=None, file_hashes={})

    def _save_state(self) -> None:
        with open(STATE_FILE, "w") as f:
            f.write(self.state.to_json())

    def _login(self) -> None:
        """Authenticate using username/password and obtain an access token."""
        url = f"{self.server_url}/api/login"
        data = {"username": self.username, "password": self.password}
        # Use form-encoded data as required by OAuth2PasswordRequestForm
        response = requests.post(url, data=data)
        if response.status_code != 200:
            raise RuntimeError(f"Failed to login: {response.text}")
        token = response.json()["access_token"]
        self.state.access_token = token
        self._save_state()

    def _register_client(self) -> None:
        """Register this client and obtain a client token and ID."""
        url = f"{self.server_url}/api/clients/register"
        headers = {"Authorization": f"Bearer {self.state.access_token}"}
        payload = {"name": self.client_name}
        response = requests.post(url, json=payload, headers=headers)
        if response.status_code != 200:
            raise RuntimeError(f"Failed to register client: {response.text}")
        data = response.json()
        # The server returns the new client object, which includes id and token
        self.state.token = data.get("token")
        self.state.client_id = data.get("id")
        self._save_state()

    def ensure_authenticated(self) -> None:
        """Ensure we have valid tokens; login and register if necessary."""
        if not self.state.access_token:
            self._login()
        if not self.state.token:
            self._register_client()

    def run_pre_commands(self) -> None:
        # Use remote commands if available, otherwise fall back to local pre_commands
        commands = self.remote_pre_commands if self.remote_pre_commands else self.pre_commands
        for cmd in commands:
            if not cmd:
                continue
            try:
                subprocess.run(cmd, shell=True, check=True)
            except subprocess.CalledProcessError as e:
                self.send_log(level="ERROR", message=f"Pre‑command '{cmd}' failed: {e}")

    def compute_file_hash(self, path: Path) -> str:
        """Compute SHA256 hash of a file."""
        sha256 = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    def scan_and_backup(self) -> None:
        """Walk monitored directories and upload changed files."""
        headers = {
            "Authorization": f"Bearer {self.state.access_token}",
        }
        for dir_path in self.monitored_paths:
            p = Path(dir_path)
            if not p.exists():
                self.send_log(level="ERROR", message=f"Monitored path does not exist: {dir_path}")
                continue
            for file_path in p.rglob("*"):
                if file_path.is_file():
                    try:
                        current_hash = self.compute_file_hash(file_path)
                    except Exception as e:
                        self.send_log(level="ERROR", message=f"Failed to hash {file_path}: {e}")
                        continue
                    last_hash = self.state.file_hashes.get(str(file_path))
                    if last_hash == current_hash:
                        continue  # unchanged
                    # Upload file
                    url = f"{self.server_url}/api/clients/{self.state.token}/backup"
                    try:
                        with file_path.open("rb") as f:
                            files = {"file": (file_path.name, f, "application/octet-stream")}
                            data = {"path": str(file_path)}
                            resp = requests.post(url, headers=headers, files=files, data=data)
                        if resp.status_code == 200:
                            self.state.file_hashes[str(file_path)] = current_hash
                            self._save_state()
                        else:
                            self.send_log(level="ERROR", message=f"Failed to upload {file_path}: {resp.text}")
                    except Exception as e:
                        self.send_log(level="ERROR", message=f"Exception uploading {file_path}: {e}")

        # After completing the backup cycle, update the server with the current
        # file structure.  This allows administrators to browse the client's
        # filesystem in the web UI.  Only do this if we are authenticated.
        if self.state.token:
            try:
                structure = self.get_file_structure()
                url = f"{self.server_url}/api/clients/{self.state.token}/files"
                # Send JSON body (list of {path, is_dir})
                requests.post(url, json=structure)
            except Exception as e:
                self.send_log(level="ERROR", message=f"Failed to send file structure: {e}")

    def send_ping(self) -> None:
        url = f"{self.server_url}/api/clients/{self.state.token}/ping"
        try:
            requests.post(url)
        except Exception as e:
            self.send_log(level="ERROR", message=f"Ping failed: {e}")

    def send_log(self, level: str, message: str) -> None:
        if not self.state.token:
            return
        url = f"{self.server_url}/api/clients/{self.state.token}/log"
        try:
            data = {"level": level, "message": message}
            requests.post(url, data=data)
        except Exception:
            pass

    # ======== Extended functionality for tasks and file structure ========

    def get_file_structure(self) -> List[dict]:
        """
        Collect a list of files and directories under the monitored paths.

        Returns a list of dictionaries with keys ``path`` and ``is_dir``.  Paths
        are absolute as seen by the client container.  Duplicate entries are
        removed.
        """
        items: List[dict] = []
        seen = set()
        for root in self.monitored_paths:
            root_path = Path(root)
            if not root_path.exists():
                continue
            # Walk directory tree
            for dirpath, dirnames, filenames in os.walk(root_path):
                # Record directory itself
                if dirpath not in seen:
                    seen.add(dirpath)
                    items.append({"path": str(dirpath), "is_dir": True})
                for fname in filenames:
                    fpath = os.path.join(dirpath, fname)
                    if fpath not in seen:
                        seen.add(fpath)
                        items.append({"path": fpath, "is_dir": False})
        return items

    def fetch_tasks(self) -> List[dict]:
        """Retrieve the list of tasks for this client from the server."""
        if not self.state.token:
            return []
        url = f"{self.server_url}/api/clients/{self.state.token}/tasks"
        try:
            resp = requests.get(url)
            if resp.status_code == 200:
                return resp.json()
        except Exception as e:
            self.send_log(level="ERROR", message=f"Failed to fetch tasks: {e}")
        return []

    def run_task(self, task: dict) -> None:
        """
        Execute a single backup task according to its specification.

        This method handles running any specified pre‑commands, compressing
        files if requested, uploading the file to the server with
        retention overrides and reporting the result back to the server.
        """
        task_id = task.get("id")
        path = task.get("path")
        frequency = task.get("frequency_minutes") or 0
        pre_commands = task.get("pre_commands", []) or []
        retention_days = task.get("retention_days")
        retention_versions = task.get("retention_versions")
        compress = task.get("compress", False)
        next_run = task.get("next_run")
        pending_run_id = task.get("pending_run_id")

        # Parse next_run into a timestamp if provided
        due = True
        if next_run:
            try:
                dt = datetime.datetime.fromisoformat(next_run)
                # Compare as naive UTC
                due = datetime.datetime.utcnow() >= dt.replace(tzinfo=None)
            except Exception:
                pass
        # Check local rate limiting: avoid running tasks too frequently in this loop
        last = self.task_last_run.get(task_id)
        if last and (time.time() - last) < (frequency * 60 if frequency else 0):
            due = False
        if not due:
            return

        # Record start time
        self.task_last_run[task_id] = time.time()
        # Combine commands: first client's remote pre_commands, then task commands
        commands = self.remote_pre_commands + pre_commands
        run_status = "SUCCESS"
        run_message = ""
        # Determine run_id: if there is a pending run id from server, use it
        run_id = pending_run_id or 0
        try:
            # Execute pre‑commands
            for cmd in commands:
                if not cmd:
                    continue
                subprocess.run(cmd, shell=True, check=True)
            # Determine file to upload
            file_path = Path(path)
            if not file_path.exists():
                raise FileNotFoundError(f"Task path does not exist: {path}")
            upload_path = file_path
            temp_path: Optional[Path] = None
            if compress and file_path.is_file():
                # Create a gzipped archive of the file in memory
                import tarfile
                import tempfile
                temp_fd, temp_name = tempfile.mkstemp(suffix=".tar.gz")
                os.close(temp_fd)
                temp_path = Path(temp_name)
                with tarfile.open(temp_path, "w:gz") as tar:
                    tar.add(file_path, arcname=file_path.name)
                upload_path = temp_path
            # Upload the file; pass retention overrides if provided
            url = f"{self.server_url}/api/clients/{self.state.token}/backup"
            with open(upload_path, "rb") as f:
                files = {"file": (upload_path.name, f, "application/octet-stream")}
                data = {"path": str(path)}
                if retention_days is not None:
                    data["retention_days"] = str(retention_days)
                if retention_versions is not None:
                    data["retention_versions"] = str(retention_versions)
                resp = requests.post(url, headers={"Authorization": f"Bearer {self.state.access_token}"}, files=files, data=data)
            # Clean up temporary file
            if compress and temp_path and temp_path.exists():
                try:
                    temp_path.unlink()
                except Exception:
                    pass
            if resp.status_code != 200:
                raise RuntimeError(f"Failed to upload task file: {resp.text}")
        except Exception as e:
            run_status = "FAILED"
            run_message = str(e)
            self.send_log(level="ERROR", message=f"Task {task_id} failed: {e}")
        finally:
            # Report status back to the server
            status_url = f"{self.server_url}/api/clients/{self.state.token}/tasks/{task_id}/status"
            try:
                requests.post(
                    status_url,
                    data={
                        "run_id": str(run_id),
                        "status": run_status,
                        "message": run_message,
                    },
                )
            except Exception:
                # Avoid raising exceptions if status reporting fails
                pass

    # ===== Configuration helpers for the web UI =====
    def apply_config(
        self,
        server_url: str,
        username: str,
        password: str,
        client_name: str,
        monitored_paths: List[str],
    ) -> Tuple[Optional[int], Optional[str]]:
        """
        Apply a new configuration provided by the user via the web UI.

        This method updates the client's connection settings, resets any stored
        authentication tokens and file hashes, and registers the client with
        the server.  It returns the newly assigned client ID on success.

        Args:
            server_url: Base URL of the backup server (e.g. ``http://localhost:8000``).
            username: Username of a server user with permission to register clients.
            password: Password for the user.
            client_name: Human‑readable name for this client.
            monitored_paths: List of directory paths to back up.
        Returns:
            A tuple of (client_id, error_message). ``client_id`` is the
            numeric client ID assigned by the server on success; otherwise
            ``None`` and a human-readable error message are returned.
        """
        # Update attributes
        self.server_url = server_url.strip()
        self.username = username.strip()
        self.password = password.strip()
        self.client_name = client_name.strip() or os.uname().nodename
        self.monitored_paths = monitored_paths or []
        # Mark the client as configured only if essential fields are provided
        self.configured = bool(self.server_url and self.username and self.password and self.monitored_paths)
        # Reset state
        self.state.access_token = None
        self.state.token = None
        self.state.client_id = None
        self.state.file_hashes = {}
        try:
            # Authenticate and register
            self._login()
            self._register_client()
            # Save state to disk
            self._save_state()
            return self.state.client_id, None
        except Exception as e:
            # Log any error; the backup loop will skip operations until configured
            self.send_log(level="ERROR", message=str(e))
            return None, str(e)

    def run(self) -> None:
        """
        Main loop for the backup client.

        If the client is not yet configured (no server URL, credentials or
        monitored paths), this loop simply waits until configuration is
        provided via the web interface.  Once configured, it ensures the
        client is authenticated and then periodically sends pings and
        performs backups according to the configured intervals.
        """
        last_backup = 0.0
        last_ping = 0.0
        last_task_check = 0.0
        while True:
            # If configuration is incomplete, skip any activity
            if not self.configured:
                time.sleep(1)
                continue
            # Ensure authentication; if tokens are missing the client will
            # attempt to login/register.  Errors are logged but do not
            # terminate the loop.
            try:
                self.ensure_authenticated()
            except Exception as e:
                self.send_log(level="ERROR", message=f"Authentication failed: {e}")
                time.sleep(5)
                continue

            now = time.time()
            if now - last_ping >= self.ping_interval:
                self.send_ping()
                last_ping = now
            if now - last_backup >= self.backup_interval:
                # Retrieve remote commands before each backup cycle
                try:
                    if self.state.token:
                        config_url = f"{self.server_url}/api/clients/{self.state.token}/config"
                        resp = requests.get(config_url)
                        if resp.status_code == 200:
                            data = resp.json()
                            self.remote_pre_commands = data.get("pre_commands", [])
                except Exception as e:
                    self.send_log(level="ERROR", message=f"Failed to fetch config: {e}")

                self.run_pre_commands()
                self.scan_and_backup()
                last_backup = now
            # Periodically check for scheduled tasks.  Tasks are fetched
            # independently of the backup interval so that "run now" requests
            # are handled promptly.  Adjust the frequency as needed.
            if now - last_task_check >= 30:
                tasks = self.fetch_tasks()
                for t in tasks:
                    try:
                        self.run_task(t)
                    except Exception as e:
                        # Catch any unexpected exception and log it
                        self.send_log(level="ERROR", message=f"Task execution error: {e}")
                last_task_check = now
            time.sleep(1)


def create_app(client: BackupClient) -> FastAPI:
    """Instantiate and return a FastAPI application for configuring the client.

    The web interface exposes a simple form at the root URL which asks for
    the server address, user credentials, client name and monitored paths.  On
    submission the client is configured and registered with the server, and
    the user is redirected to the server's web UI for the newly created client.

    Args:
        client: The BackupClient instance to be configured via the UI.

    Returns:
        A FastAPI application ready to be served by Uvicorn or another ASGI server.
    """
    app = FastAPI()
    # Determine template directory relative to this file
    templates_dir = Path(__file__).parent / "templates"
    templates = Jinja2Templates(directory=str(templates_dir))

    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request):
        # Render the configuration form.  Prepopulate fields with current
        # settings where available.  If an error message exists in the query
        # parameters it will be displayed on the page.
        error = request.query_params.get("error")
        return templates.TemplateResponse(
            "login.html",
            {
                "request": request,
                "server_url": client.server_url or "",
                "username": client.username or "",
                "client_name": client.client_name or "",
                "monitored_paths": ",".join(client.monitored_paths) if client.monitored_paths else "",
                "error": error,
            },
        )

    @app.post("/configure")
    async def configure(
        request: Request,
        server_url: str = Form(...),
        username: str = Form(...),
        password: str = Form(...),
        client_name: str = Form(""),
        monitored_paths: str = Form(""),
    ):
        """
        Handle submission of the configuration form.  Before registering the
        client, validate the inputs to catch common mistakes such as
        malformed URLs or missing credentials.  If validation fails, the form
        is re-rendered with an error message.  On success the client is
        registered and a success page with a link to the server UI is
        displayed.
        """
        # Trim whitespace
        server_url = server_url.strip()
        username = username.strip()
        password = password.strip()
        client_name = client_name.strip()
        # Parse monitored paths from comma-separated input
        paths = [p.strip() for p in monitored_paths.split(",") if p.strip()]

        # Validate the server URL
        parsed = urlparse(server_url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            return templates.TemplateResponse(
                "login.html",
                {
                    "request": request,
                    "server_url": server_url,
                    "username": username,
                    "client_name": client_name,
                    "monitored_paths": monitored_paths,
                    "error": "Invalid server URL. Please enter a valid http or https URL.",
                },
            )

        # Validate required fields
        if not username or not password:
            return templates.TemplateResponse(
                "login.html",
                {
                    "request": request,
                    "server_url": server_url,
                    "username": username,
                    "client_name": client_name,
                    "monitored_paths": monitored_paths,
                    "error": "Username and password are required.",
                },
            )
        if not paths:
            return templates.TemplateResponse(
                "login.html",
                {
                    "request": request,
                    "server_url": server_url,
                    "username": username,
                    "client_name": client_name,
                    "monitored_paths": monitored_paths,
                    "error": "Please specify at least one directory to back up.",
                },
            )

        # Apply configuration and attempt to register the client.  apply_config
        # returns the client_id if registration succeeds.
        client_id, error_message = client.apply_config(
            server_url=server_url,
            username=username,
            password=password,
            client_name=client_name,
            monitored_paths=paths,
        )
        if client_id:
            # On success show a confirmation page with a link to the server UI.
            return templates.TemplateResponse(
                "success.html",
                {
                    "request": request,
                    "server_url": server_url.rstrip("/"),
                    "client_id": client_id,
                },
            )
        # If registration failed, re-render the form with a generic error message
        error_message = error_message or "Failed to authenticate or register. Please check your credentials and server address."
        return templates.TemplateResponse(
            "login.html",
            {
                "request": request,
                "server_url": server_url,
                "username": username,
                "client_name": client_name,
                "monitored_paths": monitored_paths,
                "error": error_message,
            },
        )

    return app


if __name__ == "__main__":
    """
    Entry point for the client container.  The behaviour depends on the
    ``CLIENT_UI_ENABLED`` environment variable:

    * When ``CLIENT_UI_ENABLED`` is true (default), the client runs a small
      web server on port 8080 to collect configuration from the user.  The
      backup loop will start automatically once the user submits the form.
    * When ``CLIENT_UI_ENABLED`` is false (e.g. ``CLIENT_UI_ENABLED=0``), the
      client skips launching the web UI.  In this mode all required
      configuration must be provided via environment variables.  If any
      required setting is missing the program will exit with an error.
    """
    client = BackupClient()

    if client.ui_enabled:
        # Launch the web interface in a background thread.  The UI allows
        # interactive configuration when environment variables are absent.
        def start_web() -> None:
            app = create_app(client)
            uvicorn.run(app, host="0.0.0.0", port=8080, log_level="info")

        web_thread = threading.Thread(target=start_web, daemon=True)
        web_thread.start()
        # In UI mode always run the backup loop; it will no‑op until
        # configuration is applied by the user.
        client.run()
    else:
        # UI disabled.  Ensure the client has enough configuration to run.
        if not client.configured:
            # Emit an error and terminate.  Without configuration and without
            # the UI there is no way for the user to provide settings.
            sys.stderr.write(
                "Error: CLIENT_UI_ENABLED is false but mandatory configuration\n"
                "(SERVER_URL, USERNAME, PASSWORD and MONITORED_PATHS) was not provided.\n"
                "Either set these environment variables or enable the UI.\n"
            )
            sys.exit(1)
        # Configuration is provided via environment variables.  Start the
        # backup loop immediately.
        client.run()
