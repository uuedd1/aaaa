"""Symmetric encryption wrapper for vault passwords."""

from __future__ import annotations

from cryptography.fernet import Fernet, InvalidToken


class EncryptionManager:
    """Centralized password encryption/decryption service.

    All password fields must pass through this class so the rest of the
    codebase cannot accidentally write plaintext credentials to storage.
    """

    def __init__(self, key: bytes) -> None:
        """Create an encryption manager using a Fernet-compatible key."""
        self._fernet = Fernet(key)

    def encrypt_password(self, plaintext_password: str) -> str:
        """Encrypt plaintext password and return a UTF-8 ciphertext string."""
        encrypted_bytes = self._fernet.encrypt(plaintext_password.encode("utf-8"))
        return encrypted_bytes.decode("utf-8")

    def decrypt_password(self, encrypted_password: str) -> str:
        """Decrypt ciphertext and return plaintext password.

        Raises:
            ValueError: If the ciphertext is invalid or the key does not match.
        """
        try:
            decrypted_bytes = self._fernet.decrypt(encrypted_password.encode("utf-8"))
        except InvalidToken as exc:
            raise ValueError(
                "Unable to decrypt password. The vault key may be invalid."
            ) from exc
        return decrypted_bytes.decode("utf-8")
