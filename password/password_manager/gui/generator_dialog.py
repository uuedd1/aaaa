"""Password generator popup dialog."""

from __future__ import annotations

from typing import Callable

import customtkinter as ctk

try:
    from generator import PasswordGenerator
    from strength import StrengthAnalyser
except ImportError:  # pragma: no cover - fallback for package execution style
    from password_manager.generator import PasswordGenerator
    from password_manager.strength import StrengthAnalyser


class GeneratorDialog(ctk.CTkToplevel):
    """Dialog for generating secure passwords with configurable rules."""

    def __init__(
        self,
        parent: ctk.CTk,
        generator: PasswordGenerator,
        analyser: StrengthAnalyser,
        on_copy_password: Callable[[str], None],
        on_use_password: Callable[[str], None] | None = None,
    ) -> None:
        """Initialize popup controls and default generation settings."""
        super().__init__(parent)
        self.generator = generator
        self.analyser = analyser
        self.on_copy_password = on_copy_password
        self.on_use_password = on_use_password

        self.title("Password Generator")
        self.geometry("520x420")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()

        self.generated_password = ""

        self._build_layout()
        self._generate()

    def _build_layout(self) -> None:
        """Create slider, options, and action controls."""
        self.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(self, text="Generate Secure Password", font=ctk.CTkFont(size=22, weight="bold")).grid(
            row=0, column=0, padx=20, pady=(16, 12), sticky="w"
        )

        self.length_label = ctk.CTkLabel(self, text="Length: 16")
        self.length_label.grid(row=1, column=0, padx=20, pady=(0, 4), sticky="w")

        self.length_slider = ctk.CTkSlider(self, from_=8, to=64, number_of_steps=56, command=self._on_length_change)
        self.length_slider.grid(row=2, column=0, padx=20, pady=(0, 14), sticky="ew")
        self.length_slider.set(16)

        options_frame = ctk.CTkFrame(self)
        options_frame.grid(row=3, column=0, padx=20, pady=(0, 14), sticky="ew")
        options_frame.grid_columnconfigure((0, 1), weight=1)

        self.uppercase_var = ctk.BooleanVar(value=True)
        self.lowercase_var = ctk.BooleanVar(value=True)
        self.digits_var = ctk.BooleanVar(value=True)
        self.symbols_var = ctk.BooleanVar(value=True)

        ctk.CTkCheckBox(options_frame, text="Uppercase", variable=self.uppercase_var).grid(
            row=0, column=0, padx=8, pady=8, sticky="w"
        )
        ctk.CTkCheckBox(options_frame, text="Lowercase", variable=self.lowercase_var).grid(
            row=0, column=1, padx=8, pady=8, sticky="w"
        )
        ctk.CTkCheckBox(options_frame, text="Digits", variable=self.digits_var).grid(
            row=1, column=0, padx=8, pady=8, sticky="w"
        )
        ctk.CTkCheckBox(options_frame, text="Symbols", variable=self.symbols_var).grid(
            row=1, column=1, padx=8, pady=8, sticky="w"
        )

        ctk.CTkButton(self, text="Generate", command=self._generate).grid(
            row=4, column=0, padx=20, pady=(0, 10), sticky="ew"
        )

        self.password_entry = ctk.CTkEntry(self)
        self.password_entry.grid(row=5, column=0, padx=20, pady=(0, 8), sticky="ew")

        self.strength_label = ctk.CTkLabel(self, text="Strength: -")
        self.strength_label.grid(row=6, column=0, padx=20, pady=(0, 8), sticky="w")

        self.message_label = ctk.CTkLabel(self, text="", text_color="gray70")
        self.message_label.grid(row=7, column=0, padx=20, pady=(0, 8), sticky="w")

        button_frame = ctk.CTkFrame(self, fg_color="transparent")
        button_frame.grid(row=8, column=0, padx=20, pady=(8, 16), sticky="e")

        ctk.CTkButton(button_frame, text="Copy to Clipboard", command=self._copy_password).pack(
            side="left", padx=6
        )
        if self.on_use_password is not None:
            ctk.CTkButton(button_frame, text="Use This Password", command=self._use_password).pack(
                side="left", padx=6
            )

    def _on_length_change(self, slider_value: float) -> None:
        """Update length label whenever slider is moved."""
        self.length_label.configure(text=f"Length: {int(slider_value)}")

    def _generate(self) -> None:
        """Generate and display a fresh password."""
        try:
            password = self.generator.generate_password(
                length=int(self.length_slider.get()),
                include_uppercase=self.uppercase_var.get(),
                include_lowercase=self.lowercase_var.get(),
                include_digits=self.digits_var.get(),
                include_symbols=self.symbols_var.get(),
            )
        except ValueError as error:
            self.message_label.configure(text=str(error), text_color="#ff6b6b")
            return

        self.generated_password = password
        self.password_entry.delete(0, "end")
        self.password_entry.insert(0, password)

        report = self.analyser.analyze_password(password)
        effective_entropy = report["entropy"]
        raw_entropy = report.get("raw_entropy", effective_entropy)
        self.strength_label.configure(
            text=(
                f"Strength: {report['rating']} "
                f"(Effective Entropy: {effective_entropy}, Raw: {raw_entropy})"
            ),
            text_color=self._strength_color(report["rating"]),
        )
        self.message_label.configure(text="Password generated successfully.", text_color="#7ed957")

    def _copy_password(self) -> None:
        """Copy generated password to clipboard using app-level callback."""
        if not self.generated_password:
            self.message_label.configure(text="Generate a password first.", text_color="#ff6b6b")
            return
        self.on_copy_password(self.generated_password)
        self.message_label.configure(
            text="Copied. Clipboard will clear automatically in 30 seconds.",
            text_color="#7ed957",
        )

    def _use_password(self) -> None:
        """Return generated password to the caller context."""
        if self.on_use_password is None:
            return
        if not self.generated_password:
            self.message_label.configure(text="Generate a password first.", text_color="#ff6b6b")
            return
        self.on_use_password(self.generated_password)
        self.destroy()

    def _strength_color(self, rating: str) -> str:
        """Map strength ratings to color values."""
        normalized = rating.lower()
        if normalized == "weak":
            return "#ff6b6b"
        if normalized == "moderate":
            return "#f6c85f"
        if normalized == "strong":
            return "#7ed957"
        return "#30c07a"
