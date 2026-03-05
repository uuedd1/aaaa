"""Master authentication and key derivation logic."""

from __future__ import annotations

import base64
import hashlib
import secrets
import sqlite3
import time
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class MasterAuth:
    """Manage master-password lifecycle and vault unlock state."""

    def __init__(
        self,
        database_path: str | Path,
        pbkdf2_iterations: int = 200_000,
        max_failed_attempts: int = 3,
        lockout_seconds: int = 120,
    ) -> None:
        """Initialize configuration storage and security parameters."""
        self.database_path = str(database_path)
        self.pbkdf2_iterations = pbkdf2_iterations
        self.max_failed_attempts = max_failed_attempts
        self.lockout_seconds = lockout_seconds
        self._initialize_config_table()

    def _connect(self) -> sqlite3.Connection:
        """Create a new database connection."""
        return sqlite3.connect(self.database_path)

    def _initialize_config_table(self) -> None:
        """Create config table and required default keys if missing."""
        with self._connect() as connection:
            cursor = connection.cursor()
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS config (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
                """
            )
            connection.commit()

        self._ensure_default_config("failed_attempts", "0")
        self._ensure_default_config("lockout_until", "0")

    def _ensure_default_config(self, key: str, default_value: str) -> None:
        """Insert default configuration value only if key is absent."""
        if self._get_config_value(key) is None:
            self._set_config_value(key, default_value)

    def _get_config_value(self, key: str) -> Optional[str]:
        """Read a string configuration value from SQLite."""
        with self._connect() as connection:
            cursor = connection.cursor()
            cursor.execute("SELECT value FROM config WHERE key = ?", (key,))
            row = cursor.fetchone()
            return row[0] if row else None

    def _set_config_value(self, key: str, value: str) -> None:
        """Write configuration value using UPSERT semantics."""
        with self._connect() as connection:
            cursor = connection.cursor()
            cursor.execute(
                """
                INSERT INTO config (key, value)
                VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                (key, value),
            )
            connection.commit()

    def is_master_password_set(self) -> bool:
        """Return True when both hash and salt are already configured."""
        return (
            self._get_config_value("master_hash") is not None
            and self._get_config_value("salt") is not None
        )

    def setup_master_password(
        self, master_password: str, confirm_password: str
    ) -> tuple[bool, str]:
        """Create initial master password and persist salted verification hash."""
        if self.is_master_password_set():
            return False, "Master password is already configured."

        if not master_password or not confirm_password:
            return False, "Both password fields are required."

        if master_password != confirm_password:
            return False, "Passwords do not match."

        if len(master_password) < 8:
            return False, "Master password must be at least 8 characters long."

        salt_bytes = secrets.token_bytes(16)
        key_material = self._derive_key_material(master_password, salt_bytes)
        master_hash = hashlib.sha256(key_material).hexdigest()

        self._set_config_value("salt", base64.urlsafe_b64encode(salt_bytes).decode("utf-8"))
        self._set_config_value("master_hash", master_hash)
        self._reset_failed_attempts()
        return True, "Master password created successfully."

    def verify_master_password(
        self, candidate_password: str
    ) -> tuple[bool, str, Optional[bytes]]:
        """Verify candidate master password and return Fernet key on success."""
        if not self.is_master_password_set():
            return False, "No master password has been configured yet.", None

        if not candidate_password:
            return False, "Please enter your master password.", None

        lockout_remaining = self.get_lockout_remaining_seconds()
        if lockout_remaining > 0:
            return (
                False,
                f"Vault is temporarily locked. Try again in {lockout_remaining} seconds.",
                None,
            )

        salt_value = self._get_config_value("salt")
        stored_hash = self._get_config_value("master_hash")
        if not salt_value or not stored_hash:
            return False, "Authentication data is incomplete. Reconfigure the vault.", None

        try:
            salt_bytes = base64.urlsafe_b64decode(salt_value.encode("utf-8"))
            key_material = self._derive_key_material(candidate_password, salt_bytes)
        except Exception:
            return False, "Stored authentication data is corrupted.", None
        candidate_hash = hashlib.sha256(key_material).hexdigest()

        if secrets.compare_digest(candidate_hash, stored_hash):
            self._reset_failed_attempts()
            fernet_key = base64.urlsafe_b64encode(key_material)
            return True, "Vault unlocked.", fernet_key

        attempts_remaining = self._record_failed_attempt()
        if attempts_remaining <= 0:
            return (
                False,
                f"Too many failed attempts. Vault locked for {self.lockout_seconds} seconds.",
                None,
            )
        return (
            False,
            f"Incorrect password. {attempts_remaining} attempt(s) remaining.",
            None,
        )

    def derive_encryption_key(self, master_password: str) -> bytes:
        """Derive and return Fernet key from configured salt and given master password."""
        salt_value = self._get_config_value("salt")
        if not salt_value:
            raise ValueError("Missing salt configuration. Set a master password first.")

        try:
            salt_bytes = base64.urlsafe_b64decode(salt_value.encode("utf-8"))
            key_material = self._derive_key_material(master_password, salt_bytes)
        except Exception as error:
            raise ValueError("Unable to derive encryption key from stored configuration.") from error
        return base64.urlsafe_b64encode(key_material)

    def get_remaining_attempts(self) -> int:
        """Return remaining failed attempts before lockout."""
        failed_attempts = int(self._get_config_value("failed_attempts") or "0")
        return max(0, self.max_failed_attempts - failed_attempts)

    def get_lockout_remaining_seconds(self) -> int:
        """Return active lockout time left in seconds, or 0 if unlocked."""
        lockout_until = int(self._get_config_value("lockout_until") or "0")
        current_time = int(time.time())
        if lockout_until <= current_time:
            # When lockout expires, reset counters so the user gets a clean retry window.
            if lockout_until != 0:
                self._set_config_value("lockout_until", "0")
                self._set_config_value("failed_attempts", "0")
            return 0
        return lockout_until - current_time

    def _record_failed_attempt(self) -> int:
        """Increment failed-attempt count and activate lockout when threshold is reached."""
        failed_attempts = int(self._get_config_value("failed_attempts") or "0") + 1
        self._set_config_value("failed_attempts", str(failed_attempts))

        if failed_attempts >= self.max_failed_attempts:
            lockout_until = int(time.time()) + self.lockout_seconds
            self._set_config_value("lockout_until", str(lockout_until))
            return 0
        return self.max_failed_attempts - failed_attempts

    def _reset_failed_attempts(self) -> None:
        """Clear failed-attempt and lockout state after successful authentication."""
        self._set_config_value("failed_attempts", "0")
        self._set_config_value("lockout_until", "0")

    def _derive_key_material(self, master_password: str, salt: bytes) -> bytes:
        """Derive fixed-size key material for auth hash and Fernet key creation."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self.pbkdf2_iterations,
        )
        return kdf.derive(master_password.encode("utf-8"))
