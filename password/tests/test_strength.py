"""Tests for custom password-strength analysis logic."""

from __future__ import annotations

import random
import string
from pathlib import Path

import pytest

from password_manager.strength import StrengthAnalyser


@pytest.fixture(scope="module")
def analyser() -> StrengthAnalyser:
    """Create one analyser instance backed by the project password list."""
    common_passwords_file = (
        Path(__file__).resolve().parents[1] / "password_manager" / "common_passwords.txt"
    )
    return StrengthAnalyser(common_passwords_path=common_passwords_file)


@pytest.mark.parametrize(
    "password_value",
    [
        "password",
        "123456",
        "qwerty",
        "letmein",
    ],
)
def test_common_passwords_are_forced_to_weak(
    analyser: StrengthAnalyser, password_value: str
) -> None:
    """Known common passwords should never score above Weak."""
    report = analyser.analyze_password(password_value)
    assert report["checks"]["not_common_password"] is False
    assert report["rating"] == "Weak"


@pytest.mark.parametrize(
    "password_value",
    [
        "aaaaaaaaaaaaa",
        "1111111111111",
        "!!!!!!!!!!!!!",
        "ZZZZZZZZZZZZZ",
    ],
)
def test_single_character_repetition_is_weak(
    analyser: StrengthAnalyser, password_value: str
) -> None:
    """Long repeats of one symbol are weak despite high raw entropy."""
    report = analyser.analyze_password(password_value)
    assert report["unique_character_count"] == 1
    assert report["checks"]["no_repeated_pattern"] is False
    assert report["rating"] == "Weak"
    assert report["entropy"] <= report["raw_entropy"]


@pytest.mark.parametrize(
    "password_value",
    [
        "abababababab",
        "abcabcabcabc",
        "121212121212",
        "A1!aA1!aA1!a",
    ],
)
def test_repeated_blocks_are_detected_and_weak(
    analyser: StrengthAnalyser, password_value: str
) -> None:
    """Full-string repeated chunks are highly guessable and must be weak."""
    report = analyser.analyze_password(password_value)
    assert report["checks"]["no_repeated_block_pattern"] is False
    assert any("Repeated block pattern" in issue for issue in report["issues_found"])
    assert report["rating"] == "Weak"


@pytest.mark.parametrize(
    ("password_value", "expected_check_key"),
    [
        ("abcXYZ123", "no_sequential_pattern"),
        ("qwerty!234", "no_keyboard_walk"),
    ],
)
def test_predictable_patterns_are_flagged(
    analyser: StrengthAnalyser, password_value: str, expected_check_key: str
) -> None:
    """Sequential and keyboard-walk patterns should be explicitly marked as failed."""
    report = analyser.analyze_password(password_value)
    assert expected_check_key in report["checks"]
    assert report["checks"][expected_check_key] is False


def test_entropy_fields_are_consistent(analyser: StrengthAnalyser) -> None:
    """Adjusted entropy should never exceed raw entropy."""
    report = analyser.analyze_password("CorrectHorseBatteryStaple!42")
    assert report["raw_entropy"] >= report["entropy"]
    assert report["pool_size"] > 0
    assert report["length"] > 0


def test_randomized_repeated_blocks_are_never_strong(analyser: StrengthAnalyser) -> None:
    """Fuzz test repeated-block construction for regression protection."""
    generator = random.Random(42)
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"

    for _ in range(200):
        block_length = generator.randint(2, 4)
        repeats = generator.randint(3, 8)
        block = "".join(generator.choice(alphabet) for _ in range(block_length))
        password_value = block * repeats
        report = analyser.analyze_password(password_value)

        assert report["checks"]["no_repeated_block_pattern"] is False
        assert report["rating"] in {"Weak", "Moderate"}
        assert report["rating"] != "Very Strong"


def test_randomized_single_char_runs_always_weak(analyser: StrengthAnalyser) -> None:
    """Fuzz test one-character repeated passwords to ensure weak classification."""
    generator = random.Random(7)
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()"

    for _ in range(100):
        character = generator.choice(alphabet)
        length = generator.randint(8, 40)
        password_value = character * length
        report = analyser.analyze_password(password_value)
        assert report["rating"] == "Weak"
