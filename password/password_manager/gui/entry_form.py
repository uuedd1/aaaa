"""Add/Edit credential form UI."""

from __future__ import annotations

from typing import Callable, Optional
from urllib.parse import urlparse

import customtkinter as ctk

try:
    from strength import StrengthAnalyser
except ImportError:  # pragma: no cover - fallback for package execution style
    from password_manager.strength import StrengthAnalyser


class EntryFormFrame(ctk.CTkFrame):
    """Form for creating or editing one vault entry."""

    CATEGORY_OPTIONS = [
        "Social Media",
        "Banking",
        "Email",
        "Shopping",
        "Work",
        "Other",
    ]

    def __init__(
        self,
        parent: ctk.CTk,
        analyser: StrengthAnalyser,
        on_save: Callable[[dict], None],
        on_cancel: Callable[[], None],
        on_generate_password: Callable[[], None],
        on_check_breach: Callable[[str], None],
        existing_entry: Optional[dict] = None,
    ) -> None:
        """Initialize form in add or edit mode."""
        super().__init__(parent)
        self.analyser = analyser
        self.on_save = on_save
        self.on_cancel = on_cancel
        self.on_generate_password = on_generate_password
        self.on_check_breach = on_check_breach
        self.existing_entry = existing_entry or {}

        self._build_layout()
        self._populate_existing_values()

    def _build_layout(self) -> None:
        """Create form fields and action buttons."""
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)

        title_text = "Edit Entry" if self.existing_entry else "Add New Entry"
        ctk.CTkLabel(self, text=title_text, font=ctk.CTkFont(size=28, weight="bold")).grid(
            row=0, column=0, columnspan=2, padx=24, pady=(24, 16), sticky="w"
        )

        ctk.CTkLabel(self, text="Service Name *").grid(row=1, column=0, padx=24, pady=(8, 4), sticky="w")
        self.service_entry = ctk.CTkEntry(self, placeholder_text="e.g. Gmail")
        self.service_entry.grid(row=2, column=0, columnspan=2, padx=24, pady=(0, 12), sticky="ew")

        ctk.CTkLabel(self, text="Username *").grid(row=3, column=0, padx=24, pady=(8, 4), sticky="w")
        self.username_entry = ctk.CTkEntry(self, placeholder_text="Email or username")
        self.username_entry.grid(row=4, column=0, columnspan=2, padx=24, pady=(0, 12), sticky="ew")

        ctk.CTkLabel(self, text="Password *").grid(row=5, column=0, padx=24, pady=(8, 4), sticky="w")
        self.password_entry = ctk.CTkEntry(self, show="*")
        self.password_entry.grid(row=6, column=0, padx=(24, 8), pady=(0, 8), sticky="ew")
        self.password_entry.bind("<KeyRelease>", self._on_password_changed)

        right_button_frame = ctk.CTkFrame(self, fg_color="transparent")
        right_button_frame.grid(row=6, column=1, padx=(8, 24), pady=(0, 8), sticky="e")
        ctk.CTkButton(
            right_button_frame,
            text="Generate Password",
            width=150,
            command=self.on_generate_password,
        ).pack(side="left", padx=(0, 6))
        ctk.CTkButton(
            right_button_frame,
            text="Check Breach",
            width=120,
            command=self._on_check_breach_clicked,
        ).pack(side="left")

        self.strength_label = ctk.CTkLabel(self, text="Strength: -")
        self.strength_label.grid(row=7, column=0, padx=24, pady=(0, 4), sticky="w")
        self.strength_bar = ctk.CTkProgressBar(self)
        self.strength_bar.grid(row=8, column=0, columnspan=2, padx=24, pady=(0, 12), sticky="ew")
        self.strength_bar.set(0.0)

        ctk.CTkLabel(self, text="URL (optional)").grid(row=9, column=0, padx=24, pady=(8, 4), sticky="w")
        self.url_entry = ctk.CTkEntry(self, placeholder_text="https://example.com")
        self.url_entry.grid(row=10, column=0, columnspan=2, padx=24, pady=(0, 12), sticky="ew")

        ctk.CTkLabel(self, text="Category").grid(row=11, column=0, padx=24, pady=(8, 4), sticky="w")
        self.category_menu = ctk.CTkOptionMenu(self, values=self.CATEGORY_OPTIONS)
        self.category_menu.grid(row=12, column=0, columnspan=2, padx=24, pady=(0, 12), sticky="ew")
        self.category_menu.set("Other")

        action_frame = ctk.CTkFrame(self, fg_color="transparent")
        action_frame.grid(row=13, column=0, columnspan=2, padx=24, pady=(12, 8), sticky="e")
        ctk.CTkButton(action_frame, text="Cancel", command=self.on_cancel).pack(side="left", padx=6)
        ctk.CTkButton(action_frame, text="Save", command=self._on_save_clicked).pack(side="left", padx=6)

        self.message_label = ctk.CTkLabel(self, text="", text_color="gray70")
        self.message_label.grid(row=14, column=0, columnspan=2, padx=24, pady=(0, 18), sticky="w")

    def _populate_existing_values(self) -> None:
        """Load existing values in edit mode."""
        if not self.existing_entry:
            return

        self.service_entry.insert(0, self.existing_entry.get("service_name", ""))
        self.username_entry.insert(0, self.existing_entry.get("username", ""))
        self.password_entry.insert(0, self.existing_entry.get("decrypted_password", ""))
        self.url_entry.insert(0, self.existing_entry.get("url", ""))

        existing_category = self.existing_entry.get("category", "Other")
        if existing_category in self.CATEGORY_OPTIONS:
            self.category_menu.set(existing_category)
        else:
            self.category_menu.set("Other")

        self._on_password_changed()

    def _on_password_changed(self, _event: object | None = None) -> None:
        """Update strength bar in real time as the password changes."""
        password = self.password_entry.get()
        report = self.analyser.analyze_password(password)
        rating = report["rating"]
        entropy = report["entropy"]
        raw_entropy = report.get("raw_entropy", entropy)
        strength_value = min(entropy / 100, 1.0)
        self.strength_bar.set(strength_value)
        self.strength_label.configure(
            text=f"Strength: {rating} (Effective Entropy: {entropy}, Raw: {raw_entropy})",
            text_color=self._strength_color(rating),
        )

    def _on_check_breach_clicked(self) -> None:
        """Check currently typed password against breach API."""
        self.on_check_breach(self.password_entry.get())

    def _on_save_clicked(self) -> None:
        """Validate input and submit form data through callback."""
        form_data = self._collect_form_data()
        validation_error = self._validate_form(form_data)
        if validation_error:
            self.set_message(validation_error, is_error=True)
            return

        self.set_message("")
        self.on_save(form_data)

    def _collect_form_data(self) -> dict:
        """Collect values from all form fields."""
        return {
            "id": self.existing_entry.get("id"),
            "service_name": self.service_entry.get().strip(),
            "username": self.username_entry.get().strip(),
            "password": self.password_entry.get(),
            "url": self.url_entry.get().strip(),
            "category": self.category_menu.get(),
        }

    def _validate_form(self, form_data: dict) -> str | None:
        """Return error message for invalid form state, else None."""
        if not form_data["service_name"]:
            return "Service name is required."
        if not form_data["username"]:
            return "Username is required."
        if not form_data["password"]:
            return "Password is required."
        if len(form_data["password"]) > 128:
            return "Password is too long (maximum 128 characters)."
        if form_data["url"] and not self._is_valid_url(form_data["url"]):
            return "URL must start with http:// or https:// and include a domain."
        return None

    def _is_valid_url(self, url_value: str) -> bool:
        """Validate URL format for optional URL field."""
        parsed = urlparse(url_value)
        return parsed.scheme in {"http", "https"} and bool(parsed.netloc)

    def set_generated_password(self, password: str) -> None:
        """Fill password input with generated password and update strength UI."""
        self.password_entry.delete(0, "end")
        self.password_entry.insert(0, password)
        self._on_password_changed()

    def set_message(self, message: str, is_error: bool = False) -> None:
        """Display transient form feedback."""
        color = "#ff6b6b" if is_error else "#7ed957"
        self.message_label.configure(text=message, text_color=color)

    def _strength_color(self, rating: str) -> str:
        """Map rating labels to consistent colors."""
        normalized = rating.lower()
        if normalized == "weak":
            return "#ff6b6b"
        if normalized == "moderate":
            return "#f6c85f"
        if normalized == "strong":
            return "#7ed957"
        return "#30c07a"
