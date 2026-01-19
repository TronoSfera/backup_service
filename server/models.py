"""Database models for the backup service.

This module defines SQLAlchemy ORM models used by the backup service. The schema
supports user accounts with optional administrator privileges, client machines
that connect to the server, deduplicated file storage keyed by a content
hash, individual backup entries referencing those hashes, and logs from
clients.  Users can also specify retention policies either by limiting the
number of versions retained or by specifying an age after which old versions
should expire.

References:
    * Balancing versioning depth against storage consumption is an important
      consideration when designing backup systems【709290716836410†L142-L159】.  The schema
      includes fields for both a maximum number of versions and a maximum
      retention age so administrators can adjust these policies according to
      their needs.
    * Using a key-value store to map file hashes to storage locations makes it
      efficient to check whether a file already exists and avoid uploading
      duplicates【744670406339295†L270-L284】.
"""

from __future__ import annotations

import datetime
from typing import Optional, List

from sqlalchemy import (
    Column,
    Integer,
    String,
    Boolean,
    DateTime,
    ForeignKey,
    UniqueConstraint,
    Text,
    func,
)
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    __allow_unmapped__ = True


class User(Base):
    """Represents an authenticated user.

    Users may be administrators (``is_admin=True``) and are allowed to create
    other users and clients.  Non‑admin users are intended to authenticate
    against the API to view and download their backups.
    """

    __tablename__ = "users"
    id: int = Column(Integer, primary_key=True)
    username: str = Column(String(50), unique=True, nullable=False)
    hashed_password: str = Column(String(128), nullable=False)
    is_admin: bool = Column(Boolean, default=False)
    # Optional retention policies set per user
    retention_days: Optional[int] = Column(Integer, nullable=True)
    retention_versions: Optional[int] = Column(Integer, nullable=True)
    created_at: datetime.datetime = Column(
        DateTime, nullable=False, server_default=func.now()
    )
    updated_at: datetime.datetime = Column(
        DateTime,
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    clients: List[Client] = relationship("Client", back_populates="owner")


class Client(Base):
    """Represents a client machine that sends backups to the server.

    Each client holds a unique token used for authenticating API requests
    originating from that machine.  The server tracks the last ping and
    backup times to display client health in the web interface.
    """

    __tablename__ = "clients"
    id: int = Column(Integer, primary_key=True)
    name: str = Column(String(128), nullable=False)
    token: str = Column(String(64), unique=True, nullable=False)
    owner_id: int = Column(Integer, ForeignKey("users.id"), nullable=False)
    # Timestamp of the most recent ping request
    last_ping: Optional[datetime.datetime] = Column(DateTime, nullable=True)
    # Timestamp of the most recent backup
    last_backup: Optional[datetime.datetime] = Column(DateTime, nullable=True)
    created_at: datetime.datetime = Column(
        DateTime, nullable=False, server_default=func.now()
    )
    updated_at: datetime.datetime = Column(
        DateTime,
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    owner: User = relationship("User", back_populates="clients")
    backups: List[BackupFile] = relationship(
        "BackupFile", back_populates="client", cascade="all, delete-orphan"
    )
    logs: List[ClientLog] = relationship(
        "ClientLog", back_populates="client", cascade="all, delete-orphan"
    )

    # Relationship to file structure entries.  Each client maintains a list
    # of files and directories that are present on the monitored machine.
    # The list is updated whenever the client sends its file structure via
    # the `/api/clients/{token}/files` endpoint.  Entries are deleted
    # automatically when the client is removed.
    files: List[ClientFile] = relationship(
        "ClientFile", back_populates="client", cascade="all, delete-orphan"
    )

    # Backup tasks configured for this client.  Each task defines a path to
    # backup, a frequency and optional pre‑commands and retention settings.
    tasks: List[BackupTask] = relationship(
        "BackupTask", back_populates="client", cascade="all, delete-orphan"
    )

    # Optional list of shell commands to run on the client before each backup.
    # The commands are stored as a newline‑separated string so they can be
    # edited in the admin UI.  When the client requests its configuration the
    # server returns these commands as a list.
    pre_commands: Optional[str] = Column(Text, nullable=True)


class FileHash(Base):
    """Represents a deduplicated file stored in the backend storage.

    The `hash_value` uniquely identifies the file contents.  The `storage_path`
    field stores the path or key used by the storage backend (local filesystem
    or S3).  Multiple backup records may reference the same FileHash if clients
    upload identical files【744670406339295†L270-L339】.
    """

    __tablename__ = "file_hashes"
    id: int = Column(Integer, primary_key=True)
    hash_value: str = Column(String(128), unique=True, nullable=False)
    storage_path: str = Column(String(512), nullable=False)
    created_at: datetime.datetime = Column(
        DateTime, nullable=False, server_default=func.now()
    )

    backups: List[BackupFile] = relationship(
        "BackupFile", back_populates="file_hash", cascade="all, delete-orphan"
    )


class BackupFile(Base):
    """Represents a single backup entry for a file on a client machine.

    Each backup entry references a deduplicated file via the `file_hash_id`
    foreign key.  The `original_path` records the path of the file on the
    client.  The `version_time` stores when the backup was taken.
    """

    __tablename__ = "backup_files"
    id: int = Column(Integer, primary_key=True)
    client_id: int = Column(Integer, ForeignKey("clients.id"), nullable=False)
    file_hash_id: int = Column(Integer, ForeignKey("file_hashes.id"), nullable=False)
    original_path: str = Column(String(1024), nullable=False)
    version_time: datetime.datetime = Column(
        DateTime, nullable=False, server_default=func.now()
    )
    # Additional metadata such as file size could be stored here
    size: Optional[int] = Column(Integer, nullable=True)

    client: Client = relationship("Client", back_populates="backups")
    file_hash: FileHash = relationship("FileHash", back_populates="backups")

    __table_args__ = (
        # Unique constraint ensures that the same client cannot record two
        # backups for the same path at the exact same time; this prevents
        # accidentally creating duplicate entries if a client retries a request.
        UniqueConstraint("client_id", "original_path", "version_time"),
    )


class ClientLog(Base):
    """Represents log entries sent by clients.

    Log messages are stored with a timestamp and arbitrary text.  This table is
    useful for debugging and auditing client behaviour.
    """

    __tablename__ = "client_logs"
    id: int = Column(Integer, primary_key=True)
    client_id: int = Column(Integer, ForeignKey("clients.id"), nullable=False)
    timestamp: datetime.datetime = Column(
        DateTime, nullable=False, server_default=func.now()
    )
    level: str = Column(String(20), nullable=False, default="INFO")
    message: str = Column(Text, nullable=False)

    client: Client = relationship("Client", back_populates="logs")


# ====================== Additional models for advanced features ======================

class ClientFile(Base):
    """Represents a file or directory present on a client machine.

    The server stores the file structure sent by each client so that
    administrators can browse the client's filesystem from the web UI.  The
    `is_dir` flag distinguishes directories from regular files.  Entries are
    updated wholesale when the client sends its file listing; old entries are
    removed and replaced with the new listing.
    """

    __tablename__ = "client_files"
    id: int = Column(Integer, primary_key=True)
    client_id: int = Column(Integer, ForeignKey("clients.id", ondelete="CASCADE"), nullable=False)
    path: str = Column(String(1024), nullable=False)
    is_dir: bool = Column(Boolean, default=False, nullable=False)
    # Timestamp when this entry was last reported by the client
    reported_at: datetime.datetime = Column(DateTime, nullable=False, server_default=func.now(), onupdate=func.now())

    client: Client = relationship("Client", back_populates="files")


class BackupTask(Base):
    """Represents a scheduled backup task for a specific file on a client.

    A task defines a path on the client machine to back up at a regular
    interval (specified in minutes).  Optional shell commands may run before
    backing up, and retention settings can override the user's defaults on a
    per‑task basis.  The `compress` flag indicates whether the client should
    archive the file before uploading it.  The server tracks the last and
    next run times to aid scheduling logic on the client side.
    """

    __tablename__ = "backup_tasks"
    id: int = Column(Integer, primary_key=True)
    client_id: int = Column(Integer, ForeignKey("clients.id", ondelete="CASCADE"), nullable=False)
    path: str = Column(String(1024), nullable=False)
    # Frequency in minutes; the client should run this task at least this often
    frequency_minutes: int = Column(Integer, nullable=False)
    pre_commands: Optional[str] = Column(Text, nullable=True)
    retention_days: Optional[int] = Column(Integer, nullable=True)
    retention_versions: Optional[int] = Column(Integer, nullable=True)
    compress: bool = Column(Boolean, default=False, nullable=False)
    last_run: Optional[datetime.datetime] = Column(DateTime, nullable=True)
    next_run: Optional[datetime.datetime] = Column(DateTime, nullable=True)
    created_at: datetime.datetime = Column(DateTime, nullable=False, server_default=func.now())
    updated_at: datetime.datetime = Column(DateTime, nullable=False, server_default=func.now(), onupdate=func.now())

    client: Client = relationship("Client", back_populates="tasks")
    runs: List[TaskRun] = relationship(
        "TaskRun", back_populates="task", cascade="all, delete-orphan"
    )


class TaskRun(Base):
    """Represents a single execution of a backup task.

    The client reports the outcome of each run back to the server.  This
    information allows administrators to see whether tasks are succeeding and
    inspect any error messages.  Timestamps record when the run started and
    ended.
    """

    __tablename__ = "task_runs"
    id: int = Column(Integer, primary_key=True)
    task_id: int = Column(Integer, ForeignKey("backup_tasks.id", ondelete="CASCADE"), nullable=False)
    start_time: datetime.datetime = Column(DateTime, nullable=False, server_default=func.now())
    end_time: Optional[datetime.datetime] = Column(DateTime, nullable=True)
    status: str = Column(String(50), nullable=False)
    message: Optional[str] = Column(Text, nullable=True)

    task: BackupTask = relationship("BackupTask", back_populates="runs")
