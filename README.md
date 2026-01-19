# Backup Service

This repository contains a simple backup system composed of a server and a
client.  The service was designed to meet the requirements outlined in the
problem statement: it provides a REST API for storing and retrieving
deduplicated backups for multiple users, a web interface for administrators to
monitor clients, configurable retention policies (by age or version count),
support for both local filesystem storage and Amazon S3, and a Dockerised
client that periodically uploads files and runs pre‑backup commands.

## Architecture Overview

The system is split into two components:

1. **Server** (`./server`)
   * Built with [FastAPI](https://fastapi.tiangolo.com/) and SQLAlchemy.
   * Stores user accounts, clients, deduplicated file hashes, backup records
     and client logs in a relational database.
   * Uses SHA‑256 to detect duplicate uploads and stores each unique file only
     once.  A key–value style table (`file_hashes`) maps the content hash to
     the storage path【744670406339295†L270-L339】.
   * Supports local filesystem storage or S3.  When the `S3_BUCKET`
     environment variable is set, files are uploaded to S3; otherwise they are
     saved under `./data`.  S3 lifecycle rules can be used to automatically
     expire old versions of objects【17949889377376†L188-L219】.
   * Implements retention policies on a per‑user basis.  Administrators can
     specify either a maximum number of versions or a maximum age (in days);
     when a new backup is uploaded, older versions outside the policy are
     pruned, preserving only the latest copy【709290716836410†L142-L159】.
   * Provides a minimal HTML dashboard (`/`) displaying clients, their tokens,
     and last ping/backup times.  Forms for creating users and clients are
     included as a starting point.

2. **Client** (`./client`)
   * Written in Python and runs continuously inside a container.
   * Authenticates to the server using credentials provided via environment
     variables, registers itself to obtain a unique client token, then
     periodically sends pings and backups.
   * Recursively scans directories listed in `MONITORED_PATHS`, computes
     SHA‑256 hashes of each file and uploads only those that have changed
     since the previous run.  This reduces network and storage overhead while
     still allowing the server to deduplicate identical content.
   * Supports optional `PRE_COMMANDS` that run before each backup cycle.  This
     feature can be used to generate database dumps (e.g. running
     `pg_dump`) or any other preparatory work.
   * Sends log messages to the server when errors occur to aid debugging.

### Web Interface and Configuration

The server now includes a simple but more complete web interface built with
Jinja2 templates:

* `/clients` – lists all registered clients with last ping/backup times and
  displays the pre‑backup commands configured for each client.  It includes
  forms to create new users and new clients.
* `/clients/{id}` – shows details for a specific client.  Administrators can
  edit the **pre‑backup commands** for that client using a multiline text
  area.  The page also lists recent backups (with download links) and the
  last 50 log messages.

Behind the scenes, pre‑backup commands are stored in the client record in
the database.  Clients call `/api/clients/{token}/config` to retrieve their
commands before each backup cycle.  This allows administrators to update
backup behaviour centrally without redeploying clients.

### Client Web Interface

In addition to the server dashboard, the backup **client** offers its own
minimal web interface.  When the client container starts it opens a small
FastAPI application on port **8080** that presents a form where you can
enter the server URL, username and password for registration, an optional
client name, and the directories to monitor for backups.  Once you submit
the form the client stores the configuration, registers itself with the
server, and begins running backup cycles automatically.  A confirmation
page provides a direct link to the new client's page on the server.

This interface is enabled by default to make configuration easy.  You can
disable it by setting the environment variable `CLIENT_UI_ENABLED=false`.
When the UI is disabled the client does not launch the HTTP server and will
exit if mandatory environment variables (`SERVER_URL`, `USERNAME`,
`PASSWORD` and `MONITORED_PATHS`) are missing.  Use a `.env` file (see
`.env.example`) or set environment variables in your compose file to
configure the client non‑interactively.

## Deployment with Docker Compose

Rather than a single all‑in‑one compose file, the repository now provides
three Compose configurations to support a variety of deployment scenarios:

| Compose file                  | Description                                                                       |
|------------------------------|-----------------------------------------------------------------------------------|
| **`docker-compose.yml`**     | Launches the server, PostgreSQL, MinIO and a client in one stack.  Useful for
|                              | local testing or demonstration where all components run on the same host.         |
| **`docker-compose.server.yml`** | Starts only the server stack (FastAPI app, database and MinIO).  Use this when
|                              | deploying the server to a dedicated host or cloud.                                |
| **`docker-compose.client.yml`** | Runs just the client container.  Use this to deploy the backup agent on a
|                              | separate machine and point it at your existing server.  The client exposes
|                              | port 8080 for its configuration UI.                                               |

To run the all‑in‑one configuration:

```bash
cd backup_service
docker compose up --build
```

To run just the server or just the client, specify the appropriate compose file:

```bash
docker compose -f docker-compose.server.yml up --build
```

and, on a different host or in a separate terminal:

```bash
docker compose -f docker-compose.client.yml up --build
```

The default server configuration uses SQLite for simplicity, storing files in
a volume mounted at `/app/data`.  The provided compose files demonstrate how
to switch to PostgreSQL and MinIO by setting `DATABASE_URL`, `S3_BUCKET`,
`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_REGION` and `S3_ENDPOINT`.
Consult the comments in the compose files and the included `.env.example`
for guidance.  The client container mounts a volume called `client_data` at
`/data`; any files placed in this directory will be backed up.  You can
configure the client by editing environment variables in the compose file,
by supplying a `.env` file, or via the built‑in web interface on port 8080.

## Usage Notes

* Before starting the client you must create a user on the server.  One way
  to do this is to run the server, visit `http://localhost:8000` in a
  browser, authenticate using a token from `/api/login`, and use the “Create
  User” form.  Alternatively, you can call the `/api/register_user` endpoint
  directly using a bearer token from an existing admin.
* Ensure that the retention policies set on each user reflect your backup
  strategy.  For example, specifying `retention_versions=5` keeps the five
  most recent versions of each file; specifying `retention_days=30` retains
  versions from the last 30 days【709290716836410†L142-L159】.
* When using S3, consider configuring lifecycle rules to automatically expire
  old objects or transition them to cheaper storage classes.  S3 lifecycle
  rules can automate the deletion of objects after a specified period to meet
  data retention requirements【17949889377376†L188-L219】.

## Limitations and Future Work

This sample implementation is intended as a starting point.  Some features
that could be improved include:

* A richer web interface for managing users, clients and retention policies.
* More granular client configuration (e.g. inclusion/exclusion patterns,
  incremental or differential backups) and scheduling via cron.
* Support for compressing and encrypting data before upload.
* Streaming large files to the server to avoid loading them entirely into
  memory.
* Integration tests and better error handling.

Despite these limitations, the provided code demonstrates the core
functionality required for a secure, deduplicated backup service and
provides a foundation for further development.