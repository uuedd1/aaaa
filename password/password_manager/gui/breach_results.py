"""Breach checking results view."""

from __future__ import annotations

from typing import Callable

import customtkinter as ctk


class BreachResultsFrame(ctk.CTkFrame):
    """Display batch breach-check results with clear status colors."""

    def __init__(
        self,
        parent: ctk.CTk,
        on_recheck: Callable[[], None],
        on_back: Callable[[], None],
    ) -> None:
        """Initialize result list and action buttons."""
        super().__init__(parent)
        self.on_recheck = on_recheck
        self.on_back = on_back
        self._build_layout()

    def _build_layout(self) -> None:
        """Create static layout for results screen."""
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        header_frame = ctk.CTkFrame(self)
        header_frame.grid(row=0, column=0, padx=16, pady=(16, 8), sticky="ew")
        header_frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            header_frame,
            text="Breach Check Results",
            font=ctk.CTkFont(size=26, weight="bold"),
        ).grid(row=0, column=0, padx=12, pady=12, sticky="w")

        ctk.CTkButton(header_frame, text="Recheck", command=self.on_recheck).grid(
            row=0, column=1, padx=6, pady=12
        )
        ctk.CTkButton(header_frame, text="Back", command=self.on_back).grid(
            row=0, column=2, padx=(0, 12), pady=12
        )

        self.results_container = ctk.CTkScrollableFrame(self, label_text="Entry Status")
        self.results_container.grid(row=1, column=0, padx=16, pady=(0, 16), sticky="nsew")
        self.results_container.grid_columnconfigure(0, weight=1)

    def populate_results(self, results: list[dict]) -> None:
        """Render all breach result rows."""
        for widget in self.results_container.winfo_children():
            widget.destroy()

        if not results:
            ctk.CTkLabel(self.results_container, text="No results to display.").pack(
                padx=12, pady=16, anchor="w"
            )
            return

        for result in results:
            card = ctk.CTkFrame(self.results_container)
            card.pack(fill="x", padx=8, pady=6)

            entry_header = f"{result.get('service_name', '')} ({result.get('username', '')})"
            ctk.CTkLabel(
                card,
                text=entry_header,
                font=ctk.CTkFont(weight="bold"),
            ).pack(anchor="w", padx=10, pady=(8, 2))

            if not result.get("checked", False):
                status_text = f"Could not check: {result.get('error', 'Unknown error')}"
                color = "#f6c85f"
            elif result.get("is_compromised", False):
                breach_count = result.get("breach_count", 0)
                status_text = f"Compromised ({breach_count} breaches found)"
                color = "#ff6b6b"
            else:
                status_text = "Safe (no breach found)"
                color = "#30c07a"

            ctk.CTkLabel(card, text=status_text, text_color=color).pack(
                anchor="w", padx=10, pady=(0, 8)
            )
