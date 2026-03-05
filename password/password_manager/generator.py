"""Cryptographically secure password generation."""

from __future__ import annotations

import secrets
import string


class PasswordGenerator:
    """Generate secure passwords based on user-selected character classes."""

    def __init__(self) -> None:
        """Initialize immutable character pools."""
        self.uppercase_characters = string.ascii_uppercase
        self.lowercase_characters = string.ascii_lowercase
        self.digit_characters = string.digits
        self.symbol_characters = string.punctuation

    def generate_password(
        self,
        length: int = 16,
        include_uppercase: bool = True,
        include_lowercase: bool = True,
        include_digits: bool = True,
        include_symbols: bool = True,
    ) -> str:
        """Generate a secure password honoring length and selected character groups."""
        if length < 8 or length > 64:
            raise ValueError("Password length must be between 8 and 64 characters.")

        selected_groups: list[str] = []
        if include_uppercase:
            selected_groups.append(self.uppercase_characters)
        if include_lowercase:
            selected_groups.append(self.lowercase_characters)
        if include_digits:
            selected_groups.append(self.digit_characters)
        if include_symbols:
            selected_groups.append(self.symbol_characters)

        if not selected_groups:
            raise ValueError("Select at least one character type.")

        if length < len(selected_groups):
            raise ValueError(
                "Length is too short for the selected character-type requirements."
            )

        password_characters = [secrets.choice(group) for group in selected_groups]
        full_pool = "".join(selected_groups)

        for _ in range(length - len(password_characters)):
            password_characters.append(secrets.choice(full_pool))

        self._secure_shuffle(password_characters)
        return "".join(password_characters)

    def _secure_shuffle(self, items: list[str]) -> None:
        """Shuffle in-place using cryptographic randomness (Fisher-Yates)."""
        for index in range(len(items) - 1, 0, -1):
            swap_index = secrets.randbelow(index + 1)
            items[index], items[swap_index] = items[swap_index], items[index]
