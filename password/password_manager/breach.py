"""Have I Been Pwned password breach checker (k-anonymity model)."""

from __future__ import annotations

import hashlib
from typing import Any

import requests


class BreachChecker:
    """Check passwords against HIBP Pwned Passwords API without sending full hash."""

    API_URL_TEMPLATE = "https://api.pwnedpasswords.com/range/{prefix}"

    def __init__(self, timeout_seconds: int = 7) -> None:
        """Configure request timeout and static headers."""
        self.timeout_seconds = timeout_seconds
        self.request_headers = {
            "Add-Padding": "true",
            "User-Agent": "IB-PasswordManager-IA",
        }

    def check_password(self, password: str) -> dict[str, Any]:
        """Check one password against HIBP and return structured status details."""
        if not password:
            return {
                "checked": False,
                "breach_count": 0,
                "is_compromised": False,
                "error": "Password cannot be empty.",
            }

        sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        hash_prefix = sha1_hash[:5]
        hash_suffix = sha1_hash[5:]

        try:
            response = requests.get(
                self.API_URL_TEMPLATE.format(prefix=hash_prefix),
                headers=self.request_headers,
                timeout=self.timeout_seconds,
            )
            response.raise_for_status()
        except requests.exceptions.Timeout:
            return {
                "checked": False,
                "breach_count": 0,
                "is_compromised": False,
                "error": "Breach check timed out. Please check your internet connection.",
            }
        except requests.exceptions.RequestException:
            return {
                "checked": False,
                "breach_count": 0,
                "is_compromised": False,
                "error": "Unable to contact breach service right now.",
            }

        breach_count = 0
        for line in response.text.splitlines():
            suffix, count = self._parse_api_line(line)
            if suffix == hash_suffix:
                breach_count = count
                break

        return {
            "checked": True,
            "breach_count": breach_count,
            "is_compromised": breach_count > 0,
            "error": None,
        }

    def check_multiple_passwords(
        self, entry_records: list[dict[str, Any]], password_field: str = "decrypted_password"
    ) -> list[dict[str, Any]]:
        """Run breach checks for many entry records and return status per entry."""
        results: list[dict[str, Any]] = []
        for record in entry_records:
            password_value = record.get(password_field, "")
            check_result = self.check_password(str(password_value))
            results.append(
                {
                    "id": record.get("id"),
                    "service_name": record.get("service_name", ""),
                    "username": record.get("username", ""),
                    "breach_count": check_result["breach_count"],
                    "is_compromised": check_result["is_compromised"],
                    "checked": check_result["checked"],
                    "error": check_result["error"],
                }
            )
        return results

    def _parse_api_line(self, line: str) -> tuple[str, int]:
        """Parse `HASH_SUFFIX:COUNT` response line safely."""
        if ":" not in line:
            return "", 0
        suffix, count_text = line.split(":", maxsplit=1)
        try:
            return suffix.strip().upper(), int(count_text.strip())
        except ValueError:
            return suffix.strip().upper(), 0
