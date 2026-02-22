"""Login and first-time setup view."""

from __future__ import annotations

from typing import Callable, Optional

import customtkinter as ctk


class LoginFrame(ctk.CTkFrame):
    """Handle master-password unlock and initial setup UI."""

    def __init__(
        self,
        parent: ctk.CTk,
        first_time_setup: bool,
        on_login: Callable[[str], None],
        on_setup: Callable[[str, str], None],
    ) -> None:
        """Build login/setup widgets."""
        super().__init__(parent)
        self.first_time_setup = first_time_setup
        self.on_login = on_login
        self.on_setup = on_setup

        self._build_layout()

    def _build_layout(self) -> None:
        """Create all login UI controls."""
        self.grid_columnconfigure(0, weight=1)

        title_text = (
            "Create Master Password" if self.first_time_setup else "Unlock Password Vault"
        )
        subtitle_text = (
            "Set a strong master password to secure your vault."
            if self.first_time_setup
            else "Enter your master password to unlock the vault."
        )

        title_label = ctk.CTkLabel(self, text=title_text, font=ctk.CTkFont(size=28, weight="bold"))
        title_label.grid(row=0, column=0, padx=24, pady=(40, 8), sticky="n")

        subtitle_label = ctk.CTkLabel(self, text=subtitle_text, text_color="gray70")
        subtitle_label.grid(row=1, column=0, padx=24, pady=(0, 24), sticky="n")

        self.password_entry = ctk.CTkEntry(
            self,
            placeholder_text="Master Password",
            show="*",
            width=320,
        )
        self.password_entry.grid(row=2, column=0, padx=24, pady=8, sticky="n")
        self.password_entry.bind("<Return>", self._handle_submit)

        self.confirm_entry: Optional[ctk.CTkEntry] = None
        if self.first_time_setup:
            self.confirm_entry = ctk.CTkEntry(
                self,
                placeholder_text="Confirm Master Password",
                show="*",
                width=320,
            )
            self.confirm_entry.grid(row=3, column=0, padx=24, pady=8, sticky="n")
            self.confirm_entry.bind("<Return>", self._handle_submit)

        self.show_password_var = ctk.BooleanVar(value=False)
        show_checkbox = ctk.CTkCheckBox(
            self,
            text="Show Password",
            variable=self.show_password_var,
            command=self._toggle_password_visibility,
        )
        show_checkbox.grid(row=4, column=0, padx=24, pady=(6, 10), sticky="n")

        button_text = "Create Vault" if self.first_time_setup else "Unlock"
        submit_button = ctk.CTkButton(self, text=button_text, width=220, command=self._handle_submit)
        submit_button.grid(row=5, column=0, padx=24, pady=10, sticky="n")

        self.status_label = ctk.CTkLabel(self, text="", text_color="gray80")
        self.status_label.grid(row=6, column=0, padx=24, pady=(4, 24), sticky="n")

    def _toggle_password_visibility(self) -> None:
        """Show/hide password characters on demand."""
        visibility = "" if self.show_password_var.get() else "*"
        self.password_entry.configure(show=visibility)
        if self.confirm_entry is not None:
            self.confirm_entry.configure(show=visibility)

    def _handle_submit(self, _event: object | None = None) -> None:
        """Route submit action to login or setup callback."""
        password = self.password_entry.get()
        if self.first_time_setup:
            confirm = self.confirm_entry.get() if self.confirm_entry else ""
            self.on_setup(password, confirm)
        else:
            self.on_login(password)

    def set_status(self, message: str, is_error: bool = False) -> None:
        """Display user feedback under the submit button."""
        color = "#ff6b6b" if is_error else "#7ee787"
        self.status_label.configure(text=message, text_color=color)

    def clear_fields(self) -> None:
        """Clear sensitive text fields from view."""
        self.password_entry.delete(0, "end")
        if self.confirm_entry is not None:
            self.confirm_entry.delete(0, "end")
