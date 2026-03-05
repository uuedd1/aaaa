"""Custom password-strength analysis algorithms."""

from __future__ import annotations

import math
import re
from pathlib import Path
from typing import Any


class StrengthAnalyser:
    """Evaluate password quality using custom heuristic and entropy checks.

    The class intentionally avoids third-party strength libraries so the
    algorithm is transparent and explainable for IA assessment criteria.
    """

    KEYBOARD_ROWS = [
        "1234567890",
        "qwertyuiop",
        "asdfghjkl",
        "zxcvbnm",
    ]

    # Small local dictionary list used to catch embedded words.
    # A lightweight list keeps checks deterministic and offline.
    BASIC_DICTIONARY_WORDS = {
        "admin",
        "apple",
        "bank",
        "baseball",
        "computer",
        "dragon",
        "email",
        "football",
        "freedom",
        "hello",
        "iloveyou",
        "letmein",
        "linkedin",
        "login",
        "master",
        "michael",
        "money",
        "monkey",
        "office",
        "pass",
        "password",
        "qwerty",
        "school",
        "secret",
        "security",
        "shopping",
        "summer",
        "superman",
        "twitter",
        "welcome",
        "winter",
        "work",
    }

    def __init__(self, common_passwords_path: str | Path | None = None) -> None:
        """Load common password reference data from a local file."""
        default_path = Path(__file__).resolve().parent / "common_passwords.txt"
        self.common_passwords_path = Path(common_passwords_path) if common_passwords_path else default_path
        self.common_passwords = self._load_common_passwords()

    def analyze_password(self, password: str) -> dict[str, Any]:
        """Return a detailed strength report for the supplied password."""
        unique_character_count = len(set(password))
        unique_ratio = (unique_character_count / len(password)) if password else 0.0

        has_lowercase = any(character.islower() for character in password)
        has_uppercase = any(character.isupper() for character in password)
        has_digit = any(character.isdigit() for character in password)
        has_symbol = any(not character.isalnum() for character in password)

        pool_size = self._calculate_pool_size(
            has_lowercase=has_lowercase,
            has_uppercase=has_uppercase,
            has_digit=has_digit,
            has_symbol=has_symbol,
        )
        raw_entropy = self._calculate_entropy(len(password), pool_size)

        sequential_pattern = self._contains_sequential_pattern(password)
        repeated_pattern = self._contains_repeated_pattern(password)
        repeated_block_pattern = self._contains_repeated_block_pattern(password)
        keyboard_pattern = self._contains_keyboard_walk(password)
        common_password = self._is_common_password(password)
        dictionary_word = self._contains_dictionary_word(password)

        adjusted_entropy = self._apply_entropy_penalties(
            raw_entropy=raw_entropy,
            password_length=len(password),
            unique_ratio=unique_ratio,
            unique_character_count=unique_character_count,
            common_password=common_password,
            dictionary_word=dictionary_word,
            sequential_pattern=sequential_pattern,
            repeated_pattern=repeated_pattern,
            repeated_block_pattern=repeated_block_pattern,
            keyboard_pattern=keyboard_pattern,
        )

        checks = {
            "length_at_least_12": len(password) >= 12,
            "has_lowercase": has_lowercase,
            "has_uppercase": has_uppercase,
            "has_digits": has_digit,
            "has_symbols": has_symbol,
            "not_common_password": not common_password,
            "no_dictionary_word": not dictionary_word,
            "no_sequential_pattern": not sequential_pattern,
            "no_repeated_pattern": not repeated_pattern,
            "no_repeated_block_pattern": not repeated_block_pattern,
            "no_keyboard_walk": not keyboard_pattern,
        }

        suggestions = self._build_suggestions(checks)
        rating = self._rating_from_entropy(adjusted_entropy)
        if common_password:
            # A direct hit in the common-password list should never be rated moderate+.
            rating = "Weak"
        elif unique_character_count <= 1:
            # A string of the same character repeated is trivial to guess despite length.
            rating = "Weak"
        elif repeated_block_pattern and unique_character_count <= 4:
            # Entire passwords made from short repeated chunks are also weak in practice.
            rating = "Weak"

        pattern_flags = []
        if sequential_pattern:
            pattern_flags.append("Sequential characters detected (e.g. abc, 123).")
        if repeated_pattern:
            pattern_flags.append("Repeated character pattern detected (e.g. aaa).")
        if repeated_block_pattern:
            pattern_flags.append("Repeated block pattern detected (e.g. abcabc, 121212).")
        if keyboard_pattern:
            pattern_flags.append("Keyboard walk detected (e.g. qwerty, asdf).")
        if common_password:
            pattern_flags.append("Password exists in common-password list.")
        if dictionary_word:
            pattern_flags.append("Dictionary-style word was found in the password.")

        return {
            "length": len(password),
            "pool_size": pool_size,
            "unique_character_count": unique_character_count,
            "unique_ratio": round(unique_ratio, 2),
            "entropy": round(adjusted_entropy, 2),
            "raw_entropy": round(raw_entropy, 2),
            "rating": rating,
            "checks": checks,
            "issues_found": pattern_flags,
            "suggestions": suggestions,
        }

    def _load_common_passwords(self) -> set[str]:
        """Load local common-password list; fallback to a minimal safe default."""
        if not self.common_passwords_path.exists():
            return {"password", "123456", "qwerty", "letmein", "admin"}

        with self.common_passwords_path.open("r", encoding="utf-8") as file:
            return {line.strip().lower() for line in file if line.strip()}

    def _calculate_pool_size(
        self,
        has_lowercase: bool,
        has_uppercase: bool,
        has_digit: bool,
        has_symbol: bool,
    ) -> int:
        """Compute effective symbol pool used by entropy formula."""
        pool_size = 0
        if has_lowercase:
            pool_size += 26
        if has_uppercase:
            pool_size += 26
        if has_digit:
            pool_size += 10
        if has_symbol:
            pool_size += 33
        return pool_size

    def _calculate_entropy(self, password_length: int, pool_size: int) -> float:
        """Calculate theoretical entropy from password length and symbol pool size."""
        if password_length <= 0 or pool_size <= 0:
            return 0.0
        return password_length * math.log2(pool_size)

    def _contains_sequential_pattern(self, password: str) -> bool:
        """Detect simple ascending/descending 3-char alphanumeric sequences."""
        lowered = password.lower()
        for index in range(len(lowered) - 2):
            segment = lowered[index : index + 3]
            if segment.isalpha() or segment.isdigit():
                step_one = ord(segment[1]) - ord(segment[0])
                step_two = ord(segment[2]) - ord(segment[1])
                if step_one == step_two and abs(step_one) == 1:
                    return True
        return False

    def _contains_repeated_pattern(self, password: str) -> bool:
        """Detect 3+ consecutive occurrences of the same character."""
        return re.search(r"(.)\1\1+", password) is not None

    def _contains_repeated_block_pattern(self, password: str) -> bool:
        """Detect passwords made by repeating the same substring end-to-end."""

        if len(password) < 6:
            return False

        for block_length in range(1, (len(password) // 2) + 1):
            if len(password) % block_length != 0:
                continue
            block = password[:block_length]
            if block * (len(password) // block_length) == password:
                return True
        return False

    def _contains_keyboard_walk(self, password: str) -> bool:
        """Detect keyboard-walk snippets such as qwe, asd, 123, and reverse."""
        lowered = password.lower()
        if len(lowered) < 3:
            return False

        for row in self.KEYBOARD_ROWS:
            reversed_row = row[::-1]
            for index in range(len(lowered) - 2):
                snippet = lowered[index : index + 3]
                if snippet in row or snippet in reversed_row:
                    return True
        return False

    def _is_common_password(self, password: str) -> bool:
        """Return True when password exactly matches local common-password list."""
        return password.lower() in self.common_passwords

    def _contains_dictionary_word(self, password: str) -> bool:
        """Return True when a built-in dictionary word appears in the password."""
        lowered = password.lower()
        for word in self.BASIC_DICTIONARY_WORDS:
            if len(word) >= 4 and word in lowered:
                return True
        return False

    def _rating_from_entropy(self, entropy: float) -> str:
        """Map entropy score into IA rubric-friendly rating bands."""
        if entropy < 28:
            return "Weak"
        if 28 <= entropy <= 50:
            return "Moderate"
        if 50 < entropy <= 70:
            return "Strong"
        return "Very Strong"

    def _apply_entropy_penalties(
        self,
        raw_entropy: float,
        password_length: int,
        unique_ratio: float,
        unique_character_count: int,
        common_password: bool,
        dictionary_word: bool,
        sequential_pattern: bool,
        repeated_pattern: bool,
        repeated_block_pattern: bool,
        keyboard_pattern: bool,
    ) -> float:
        """Apply heuristic deductions so predictable patterns reduce final score."""
        penalty = 0.0
        if password_length < 12:
            penalty += 5.0
        if common_password:
            penalty += 35.0
        if dictionary_word:
            penalty += 18.0
        if sequential_pattern:
            penalty += 12.0
        if repeated_pattern:
            penalty += 10.0
        if repeated_block_pattern:
            penalty += 30.0
        if unique_character_count <= 1:
            penalty += 45.0
        elif unique_character_count <= 2:
            penalty += 25.0
        if unique_ratio < 0.35:
            penalty += 20.0
        if keyboard_pattern:
            penalty += 12.0
        return max(0.0, raw_entropy - penalty)

    def _build_suggestions(self, checks: dict[str, bool]) -> list[str]:
        """Generate actionable recommendations from failed checks."""
        suggestions: list[str] = []
        if not checks["length_at_least_12"]:
            suggestions.append("Increase length to at least 12 characters.")
        if not checks["has_lowercase"]:
            suggestions.append("Add lowercase letters.")
        if not checks["has_uppercase"]:
            suggestions.append("Add uppercase letters.")
        if not checks["has_digits"]:
            suggestions.append("Add numeric digits.")
        if not checks["has_symbols"]:
            suggestions.append("Add symbols such as !@#$.")
        if not checks["not_common_password"]:
            suggestions.append("Avoid common passwords used by many users.")
        if not checks["no_dictionary_word"]:
            suggestions.append("Avoid dictionary words and predictable phrases.")
        if not checks["no_sequential_pattern"]:
            suggestions.append("Remove sequential character runs like abc or 123.")
        if not checks["no_repeated_pattern"]:
            suggestions.append("Avoid repeating the same character several times.")
        if not checks["no_repeated_block_pattern"]:
            suggestions.append("Avoid repeating short blocks like abcabc or 121212.")
        if not checks["no_keyboard_walk"]:
            suggestions.append("Avoid keyboard paths such as qwerty or asdf.")

        if not suggestions:
            suggestions.append("No obvious weaknesses found. Keep this password unique per service.")
        return suggestions
