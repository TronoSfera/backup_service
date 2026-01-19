"""Pydantic models for request and response bodies.

These schemas define the shape of data sent to and from the API.  They are
used by FastAPI to validate input and generate OpenAPI documentation.
"""

from __future__ import annotations

from typing import Optional, List
from datetime import datetime

from pydantic import BaseModel, Field, constr


# User schemas
class UserCreate(BaseModel):
    username: constr(strip_whitespace=True, min_length=3, max_length=50)
    password: constr(min_length=6)
    is_admin: bool = False
    retention_days: Optional[int] = Field(
        None, description="Maximum age (in days) to retain old versions."
    )
    retention_versions: Optional[int] = Field(
        None, description="Maximum number of versions to retain per file."
    )


class UserOut(BaseModel):
    id: int
    username: str
    is_admin: bool
    retention_days: Optional[int] = None
    retention_versions: Optional[int] = None

    class Config:
        orm_mode = True


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


# Client schemas
class ClientRegisterRequest(BaseModel):
    name: str
    owner_id: Optional[int] = None  # Only used when admin registers on behalf of user


class ClientOut(BaseModel):
    id: int
    name: str
    token: str
    owner_id: int
    last_ping: Optional[datetime] = None
    last_backup: Optional[datetime] = None
    pre_commands: Optional[str] = None

    class Config:
        orm_mode = True


class ClientConfigOut(BaseModel):
    """Configuration returned to the client.

    Currently it exposes the list of pre‑backup commands.  Additional fields
    could be added here in future (e.g. inclusion/exclusion patterns).
    """
    pre_commands: List[str]


# Backup-related schemas
class BackupEntryOut(BaseModel):
    id: int
    original_path: str
    version_time: datetime
    size: Optional[int]
    file_hash: str = Field(..., description="Content hash of the stored file")

    class Config:
        orm_mode = True


class ClientLogEntry(BaseModel):
    timestamp: datetime
    level: str
    message: str

    class Config:
        orm_mode = True


# ==================== Additional schemas for advanced features ====================

class ClientFileOut(BaseModel):
    id: int
    path: str
    is_dir: bool

    class Config:
        orm_mode = True


class TaskOut(BaseModel):
    id: int
    path: str
    frequency_minutes: int
    pre_commands: List[str] = []
    retention_days: Optional[int] = None
    retention_versions: Optional[int] = None
    compress: bool
    last_run: Optional[datetime] = None
    next_run: Optional[datetime] = None
    pending_run_id: Optional[int] = None

    class Config:
        orm_mode = True


class TaskCreate(BaseModel):
    path: str
    frequency_minutes: int
    pre_commands: Optional[str] = None
    retention_days: Optional[int] = None
    retention_versions: Optional[int] = None
    compress: bool = False


class TaskRunOut(BaseModel):
    id: int
    start_time: datetime
    end_time: Optional[datetime]
    status: str
    message: Optional[str] = None

    class Config:
        orm_mode = True