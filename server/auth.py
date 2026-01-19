"""Authentication utilities for the backup service.

This module implements password hashing, JSON Web Token (JWT) generation and
verification, and FastAPI dependencies for authenticating API calls.  Users
authenticate via the ``/api/login`` endpoint by providing their username and
password; upon successful authentication a signed JWT is returned.  The JWT
must be included in the ``Authorization: Bearer <token>`` header for
subsequent requests.

The JWT contains the user's ID and role (admin flag).  Token expiration is
configurable via the ``ACCESS_TOKEN_EXPIRE_MINUTES`` environment variable.
"""

from __future__ import annotations

import os
import datetime
import hashlib
from typing import Optional

from jose import JWTError, jwt
from passlib.context import CryptContext
from passlib.handlers import bcrypt as passlib_bcrypt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from . import models
from .database import get_db


# Configuration
SECRET_KEY = os.getenv("SECRET_KEY", "CHANGE_ME")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))


def _build_password_context() -> CryptContext:
    """Create a password hashing context with a safe backend fallback."""
    try:
        passlib_bcrypt.bcrypt.set_backend("builtin")
        passlib_bcrypt.bcrypt_sha256.set_backend("builtin")
        passlib_bcrypt.bcrypt_sha256.hash("passlib-backend-check")
        return CryptContext(schemes=["bcrypt_sha256", "bcrypt"], deprecated="auto")
    except Exception:
        # bcrypt backends can fail with newer bcrypt releases; fall back to pbkdf2.
        return CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")


pwd_context = _build_password_context()


def _normalize_bcrypt_password(password: str) -> str:
    """Normalize passwords to avoid bcrypt's 72-byte length limit.

    Some bcrypt backends raise a ValueError for passwords longer than 72 bytes.
    Instead of truncating, hash the original bytes with SHA-256 to preserve
    entropy while ensuring the input length stays within bcrypt limits.
    """
    encoded = password.encode("utf-8")
    if len(encoded) <= 72:
        return password
    return hashlib.sha256(encoded).hexdigest()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/login", auto_error=False)


def hash_password(password: str) -> str:
    normalized = _normalize_bcrypt_password(password)
    return pwd_context.hash(normalized)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    normalized = _normalize_bcrypt_password(plain_password)
    return pwd_context.verify(normalized, hashed_password)


def create_access_token(data: dict, expires_delta: Optional[datetime.timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.datetime.utcnow() + (
        expires_delta or datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(
    request: Request,
    token: str | None = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> models.User:
    """Retrieve the current user from a JWT token."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    raw_token = token or request.cookies.get("access_token")
    if not raw_token:
        raise credentials_exception
    try:
        payload = jwt.decode(raw_token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: int | None = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError as e:
        raise credentials_exception from e
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(
    current_user: models.User = Depends(get_current_user),
) -> models.User:
    return current_user


async def get_current_admin(
    current_user: models.User = Depends(get_current_user),
) -> models.User:
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough privileges",
        )
    return current_user
