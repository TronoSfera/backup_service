"""Abstraction over storage backends for the backup service.

The backup server supports storing files either on the local filesystem or in
Amazon S3.  At runtime the storage backend is chosen based on environment
variables.  Using S3 for storage enables durable, scalable backup storage and
facilitates lifecycle management (for example, using S3 expiration rules to
delete old versions of objects automatically【17949889377376†L188-L219】).  When no
S3 configuration is provided the service falls back to storing files on disk
under a configurable directory.

The Storage base class defines a common API for saving and deleting files.  The
local storage implementation simply writes files to disk.  The S3
implementation uses boto3 to upload objects to a bucket and generate unique
keys.
"""

from __future__ import annotations

import hashlib
import os
import uuid
from pathlib import Path
from typing import Optional

import boto3


class Storage:
    """Abstract base class for storage backends."""

    async def save_file(self, data: bytes, filename: Optional[str] = None) -> str:
        """Save a binary blob and return a storage key/path.

        Args:
            data: The file content to store.
            filename: Optional file name hint; ignored by some backends.

        Returns:
            A string representing the storage location (e.g. file path or S3 key).
        """
        raise NotImplementedError

    async def delete_file(self, key: str) -> None:
        """Delete a file from storage.

        Args:
            key: The storage key previously returned by ``save_file``.
        """
        raise NotImplementedError


class LocalStorage(Storage):
    """Filesystem storage backend.

    Files are stored inside a root directory defined by the ``BACKUP_STORAGE_PATH``
    environment variable (default: ``./data``).  Each saved file is placed
    under its hash name to avoid collisions; this also allows the backend to
    deduplicate by content easily.
    """

    def __init__(self, root_dir: Optional[str] = None) -> None:
        self.root_dir = Path(root_dir or os.getenv("BACKUP_STORAGE_PATH", "./data")).resolve()
        self.root_dir.mkdir(parents=True, exist_ok=True)

    async def save_file(self, data: bytes, filename: Optional[str] = None) -> str:
        # Use SHA256 of the content as file name to ensure uniqueness
        hash_value = hashlib.sha256(data).hexdigest()
        # Place files in subdirectories to avoid too many files in one folder
        subdir = self.root_dir / hash_value[:2]
        subdir.mkdir(parents=True, exist_ok=True)
        file_path = subdir / hash_value
        if not file_path.exists():
            with open(file_path, "wb") as f:
                f.write(data)
        # Return relative path from root to allow migration if root changes
        return str(file_path.relative_to(self.root_dir))

    async def delete_file(self, key: str) -> None:
        file_path = self.root_dir / key
        try:
            file_path.unlink()
        except FileNotFoundError:
            pass


class S3Storage(Storage):
    """Amazon S3 storage backend.

    Files are uploaded to an S3 bucket defined by the ``S3_BUCKET`` environment
    variable.  A UUID-based key is generated for each file.  With S3 versioning
    enabled, an object can have multiple versions, and lifecycle rules can be
    applied to automatically expire old versions【17949889377376†L188-L219】.
    """

    def __init__(self, bucket_name: str, prefix: str = "backups/") -> None:
        self.bucket_name = bucket_name
        self.prefix = prefix
        # boto3 will automatically use credentials from environment variables
        # Allow overriding the S3 endpoint to support self‑hosted services like MinIO.
        # When using a custom endpoint, you should also specify a region (any string),
        # otherwise boto3 will attempt to infer AWS regions.  We pass through
        # ``S3_ENDPOINT`` from the environment if present.
        endpoint_url = os.getenv("S3_ENDPOINT")
        self.s3 = boto3.client(
            "s3",
            aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
            aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
            region_name=os.getenv("AWS_REGION"),
            endpoint_url=endpoint_url,
        )

    async def save_file(self, data: bytes, filename: Optional[str] = None) -> str:
        # Generate a random key; include original filename for readability if provided
        key = f"{self.prefix}{uuid.uuid4().hex}"
        if filename:
            # Sanitize filename to avoid path traversal
            basename = os.path.basename(filename)
            key = f"{self.prefix}{uuid.uuid4().hex}-{basename}"
        self.s3.put_object(Bucket=self.bucket_name, Key=key, Body=data)
        return key

    async def delete_file(self, key: str) -> None:
        self.s3.delete_object(Bucket=self.bucket_name, Key=key)


def get_storage() -> Storage:
    """Factory function returning the configured storage backend.

    If the ``S3_BUCKET`` environment variable is set the service uses S3,
    otherwise it falls back to local storage.  Additional configuration options
    such as ``S3_PREFIX`` and ``BACKUP_STORAGE_PATH`` can also be used to
    customise the storage key prefix and local directory.
    """
    bucket = os.getenv("S3_BUCKET")
    if bucket:
        prefix = os.getenv("S3_PREFIX", "backups/")
        return S3Storage(bucket_name=bucket, prefix=prefix)
    else:
        root = os.getenv("BACKUP_STORAGE_PATH", "./data")
        return LocalStorage(root_dir=root)