"""Vault data model and encrypted SQLite CRUD operations."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

try:
    from encryption import EncryptionManager
except ImportError:  # pragma: no cover - fallback for package execution style
    from password_manager.encryption import EncryptionManager


@dataclass
class PasswordEntry:
    """Represents one stored credential in the vault."""

    id: Optional[int]
    service_name: str
    username: str
    encrypted_password: str
    url: str
    category: str
    date_added: str
    date_modified: str

    @classmethod
    def from_db_row(cls, row: sqlite3.Row) -> "PasswordEntry":
        """Build model instance from SQLite row object."""
        return cls(
            id=row["id"],
            service_name=row["service_name"],
            username=row["username"],
            encrypted_password=row["encrypted_password"],
            url=row["url"],
            category=row["category"],
            date_added=row["date_added"],
            date_modified=row["date_modified"],
        )

    def to_insert_params(self) -> tuple[str, str, str, str, str, str, str]:
        """Convert model to insert SQL parameter tuple."""
        return (
            self.service_name,
            self.username,
            self.encrypted_password,
            self.url,
            self.category,
            self.date_added,
            self.date_modified,
        )


class Vault:
    """Handles encrypted password storage and retrieval from SQLite."""

    SORTABLE_FIELDS = {
        "service_name": "service_name",
        "category": "category",
        "date_added": "date_added",
    }

    SEARCHABLE_FIELDS = {
        "service_name": "service_name",
        "category": "category",
        "username": "username",
    }

    def __init__(self, database_path: str | Path, encryption_manager: EncryptionManager) -> None:
        """Create vault manager with encryption dependency."""
        self.database_path = str(database_path)
        self.encryption_manager = encryption_manager
        self._initialize_entries_table()

    def _connect(self) -> sqlite3.Connection:
        """Open SQLite connection with row access by column name."""
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize_entries_table(self) -> None:
        """Create vault entries table if it does not already exist."""
        with self._connect() as connection:
            cursor = connection.cursor()
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS entries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    service_name TEXT NOT NULL,
                    username TEXT NOT NULL,
                    encrypted_password TEXT NOT NULL,
                    url TEXT DEFAULT '',
                    category TEXT DEFAULT 'Other',
                    date_added TEXT NOT NULL,
                    date_modified TEXT NOT NULL
                )
                """
            )
            connection.commit()

    def add_entry(
        self,
        service_name: str,
        username: str,
        plaintext_password: str,
        url: str = "",
        category: str = "Other",
    ) -> PasswordEntry:
        """Encrypt and insert a new credential record into the vault."""
        if not service_name.strip():
            raise ValueError("Service name is required.")
        if not username.strip():
            raise ValueError("Username is required.")
        if not plaintext_password:
            raise ValueError("Password is required.")

        now_iso = datetime.utcnow().isoformat(timespec="seconds")
        encrypted_password = self.encryption_manager.encrypt_password(plaintext_password)

        entry = PasswordEntry(
            id=None,
            service_name=service_name.strip(),
            username=username.strip(),
            encrypted_password=encrypted_password,
            url=url.strip(),
            category=category.strip() or "Other",
            date_added=now_iso,
            date_modified=now_iso,
        )

        with self._connect() as connection:
            cursor = connection.cursor()
            cursor.execute(
                """
                INSERT INTO entries (
                    service_name, username, encrypted_password, url, category, date_added, date_modified
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                entry.to_insert_params(),
            )
            connection.commit()
            entry.id = int(cursor.lastrowid)
        return entry

    def get_entry(self, entry_id: int, include_decrypted_password: bool = True) -> Optional[dict[str, Any]]:
        """Fetch single credential by ID, optionally including decrypted password."""
        with self._connect() as connection:
            cursor = connection.cursor()
            cursor.execute("SELECT * FROM entries WHERE id = ?", (entry_id,))
            row = cursor.fetchone()
            if row is None:
                return None
            return self._row_to_record(row, include_decrypted_password)

    def update_entry(
        self,
        entry_id: int,
        service_name: str,
        username: str,
        plaintext_password: str,
        url: str = "",
        category: str = "Other",
    ) -> bool:
        """Update an existing record after encrypting the new password value."""
        if not service_name.strip():
            raise ValueError("Service name is required.")
        if not username.strip():
            raise ValueError("Username is required.")
        if not plaintext_password:
            raise ValueError("Password is required.")

        encrypted_password = self.encryption_manager.encrypt_password(plaintext_password)
        modified_timestamp = datetime.utcnow().isoformat(timespec="seconds")

        with self._connect() as connection:
            cursor = connection.cursor()
            cursor.execute(
                """
                UPDATE entries
                SET service_name = ?, username = ?, encrypted_password = ?, url = ?, category = ?, date_modified = ?
                WHERE id = ?
                """,
                (
                    service_name.strip(),
                    username.strip(),
                    encrypted_password,
                    url.strip(),
                    category.strip() or "Other",
                    modified_timestamp,
                    entry_id,
                ),
            )
            connection.commit()
            return cursor.rowcount > 0

    def delete_entry(self, entry_id: int) -> bool:
        """Delete credential record by ID."""
        with self._connect() as connection:
            cursor = connection.cursor()
            cursor.execute("DELETE FROM entries WHERE id = ?", (entry_id,))
            connection.commit()
            return cursor.rowcount > 0

    def get_all_entries(self, include_decrypted_password: bool = False) -> list[dict[str, Any]]:
        """Return all stored entries ordered by service name."""
        with self._connect() as connection:
            cursor = connection.cursor()
            cursor.execute("SELECT * FROM entries ORDER BY LOWER(service_name) ASC")
            rows = cursor.fetchall()
        return [self._row_to_record(row, include_decrypted_password) for row in rows]

    def search_entries(
        self,
        query: str,
        filter_by: str = "service_name",
        include_decrypted_password: bool = False,
    ) -> list[dict[str, Any]]:
        """Search entries by service name, category, or username."""
        normalized_field = self.SEARCHABLE_FIELDS.get(filter_by, "service_name")
        like_query = f"%{query.strip()}%"

        sql = f"SELECT * FROM entries WHERE {normalized_field} LIKE ? ORDER BY LOWER(service_name) ASC"
        with self._connect() as connection:
            cursor = connection.cursor()
            cursor.execute(sql, (like_query,))
            rows = cursor.fetchall()
        return [self._row_to_record(row, include_decrypted_password) for row in rows]

    def sort_entries(
        self,
        field: str = "service_name",
        order: str = "asc",
        include_decrypted_password: bool = False,
    ) -> list[dict[str, Any]]:
        """Sort entries by service name, category, or date added."""
        safe_field = self.SORTABLE_FIELDS.get(field, "service_name")
        safe_order = "DESC" if order.lower() == "desc" else "ASC"

        if safe_field in {"service_name", "category"}:
            sql = f"SELECT * FROM entries ORDER BY LOWER({safe_field}) {safe_order}"
        else:
            sql = f"SELECT * FROM entries ORDER BY {safe_field} {safe_order}"

        with self._connect() as connection:
            cursor = connection.cursor()
            cursor.execute(sql)
            rows = cursor.fetchall()
        return [self._row_to_record(row, include_decrypted_password) for row in rows]

    def _row_to_record(
        self, row: sqlite3.Row, include_decrypted_password: bool
    ) -> dict[str, Any]:
        """Convert row to plain dict and optionally decrypt password."""
        entry = PasswordEntry.from_db_row(row)
        record: dict[str, Any] = {
            "id": entry.id,
            "service_name": entry.service_name,
            "username": entry.username,
            "encrypted_password": entry.encrypted_password,
            "url": entry.url,
            "category": entry.category,
            "date_added": entry.date_added,
            "date_modified": entry.date_modified,
        }
        if include_decrypted_password:
            try:
                record["decrypted_password"] = self.encryption_manager.decrypt_password(
                    entry.encrypted_password
                )
                record["decryption_error"] = None
            except ValueError as error:
                # Keep the entry visible even when one ciphertext cannot be decrypted
                # with the current master key (e.g. after key reset/migration).
                record["decrypted_password"] = ""
                record["decryption_error"] = str(error)
        return record
