"""Main dashboard listing vault entries."""

from __future__ import annotations

from typing import Callable

import customtkinter as ctk


class DashboardFrame(ctk.CTkFrame):
    """Display searchable/sortable list of vault credentials."""

    def __init__(
        self,
        parent: ctk.CTk,
        on_add_new: Callable[[], None],
        on_edit_selected: Callable[[int], None],
        on_delete_selected: Callable[[int], None],
        on_generate_password: Callable[[], None],
        on_check_all_breaches: Callable[[], None],
        on_logout: Callable[[], None],
        on_search_change: Callable[[str], None],
        on_filter_change: Callable[[str], None],
        on_sort_change: Callable[[str, str], None],
    ) -> None:
        """Create dashboard controls and list container."""
        super().__init__(parent)
        self.on_add_new = on_add_new
        self.on_edit_selected = on_edit_selected
        self.on_delete_selected = on_delete_selected
        self.on_generate_password = on_generate_password
        self.on_check_all_breaches = on_check_all_breaches
        self.on_logout = on_logout
        self.on_search_change = on_search_change
        self.on_filter_change = on_filter_change
        self.on_sort_change = on_sort_change

        self.selected_entry_var = ctk.StringVar(value="")
        self._last_selected_value = ""
        self.entry_records: list[dict] = []

        self._build_layout()

    def _build_layout(self) -> None:
        """Build main dashboard widgets."""
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(3, weight=1)

        top_bar = ctk.CTkFrame(self)
        top_bar.grid(row=0, column=0, sticky="ew", padx=16, pady=(16, 10))
        top_bar.grid_columnconfigure(0, weight=1)

        self.search_var = ctk.StringVar()
        self.search_var.trace_add("write", self._on_search_var_changed)
        search_entry = ctk.CTkEntry(
            top_bar,
            textvariable=self.search_var,
            placeholder_text="Search by service, username, or category...",
        )
        search_entry.grid(row=0, column=0, padx=10, pady=10, sticky="ew")

        filter_values = [
            "All Categories",
            "Social Media",
            "Banking",
            "Email",
            "Shopping",
            "Work",
            "Other",
        ]
        self.filter_menu = ctk.CTkOptionMenu(
            top_bar,
            values=filter_values,
            command=self._on_filter_selected,
            width=160,
        )
        self.filter_menu.grid(row=0, column=1, padx=8, pady=10)
        self.filter_menu.set("All Categories")

        self.sort_field_menu = ctk.CTkOptionMenu(
            top_bar,
            values=["service_name", "category", "date_added"],
            command=self._emit_sort_change,
            width=140,
        )
        self.sort_field_menu.grid(row=0, column=2, padx=8, pady=10)
        self.sort_field_menu.set("service_name")

        self.sort_order_menu = ctk.CTkOptionMenu(
            top_bar,
            values=["asc", "desc"],
            command=self._emit_sort_change,
            width=90,
        )
        self.sort_order_menu.grid(row=0, column=3, padx=(0, 10), pady=10)
        self.sort_order_menu.set("asc")

        action_bar = ctk.CTkFrame(self)
        action_bar.grid(row=1, column=0, sticky="ew", padx=16, pady=(0, 10))

        ctk.CTkButton(action_bar, text="Add New", command=self.on_add_new).pack(
            side="left", padx=8, pady=10
        )
        ctk.CTkButton(action_bar, text="Edit Selected", command=self._edit_selected).pack(
            side="left", padx=8, pady=10
        )
        ctk.CTkButton(
            action_bar,
            text="Delete Selected",
            fg_color="#aa3c3c",
            hover_color="#8a2f2f",
            command=self._delete_selected,
        ).pack(side="left", padx=8, pady=10)
        ctk.CTkButton(
            action_bar,
            text="Generate Password",
            command=self.on_generate_password,
        ).pack(side="left", padx=8, pady=10)
        ctk.CTkButton(
            action_bar,
            text="Check All for Breaches",
            command=self.on_check_all_breaches,
        ).pack(side="left", padx=8, pady=10)
        ctk.CTkButton(
            action_bar,
            text="Lock Vault",
            fg_color="#4e5d94",
            hover_color="#3d4975",
            command=self.on_logout,
        ).pack(side="right", padx=8, pady=10)

        self.status_label = ctk.CTkLabel(self, text="", text_color="gray70")
        self.status_label.grid(row=2, column=0, sticky="ew", padx=20, pady=(0, 8))

        self.list_container = ctk.CTkScrollableFrame(self, label_text="Stored Credentials")
        self.list_container.grid(row=3, column=0, sticky="nsew", padx=16, pady=(0, 16))
        self.list_container.grid_columnconfigure(1, weight=1)

        self.empty_label = ctk.CTkLabel(
            self.list_container, text="No entries available. Add one to get started."
        )
        self.empty_label.grid(row=0, column=0, columnspan=5, padx=8, pady=20)

    def populate_entries(self, entries: list[dict]) -> None:
        """Render rows for the provided entry list."""
        self.entry_records = entries

        for widget in self.list_container.winfo_children():
            widget.destroy()

        valid_entry_ids = {str(entry["id"]) for entry in entries}
        if self.selected_entry_var.get() not in valid_entry_ids:
            self.selected_entry_var.set("")
            self._last_selected_value = ""

        if not entries:
            self.empty_label = ctk.CTkLabel(
                self.list_container, text="No matching entries found."
            )
            self.empty_label.grid(row=0, column=0, columnspan=5, padx=8, pady=20)
            return

        header_labels = ["Select", "Service", "Username", "Category", "Strength"]
        for index, header in enumerate(header_labels):
            ctk.CTkLabel(
                self.list_container,
                text=header,
                font=ctk.CTkFont(weight="bold"),
                text_color="gray70",
            ).grid(row=0, column=index, padx=8, pady=(8, 4), sticky="w")

        for row_index, entry in enumerate(entries, start=1):
            entry_id_value = str(entry["id"])
            selection_button = ctk.CTkRadioButton(
                self.list_container,
                text="",
                variable=self.selected_entry_var,
                value=entry_id_value,
                command=lambda value=entry_id_value: self._toggle_selection(value),
            )
            selection_button.grid(row=row_index, column=0, padx=8, pady=8, sticky="w")

            ctk.CTkLabel(self.list_container, text=entry["service_name"]).grid(
                row=row_index, column=1, padx=8, pady=8, sticky="w"
            )
            ctk.CTkLabel(self.list_container, text=entry["username"]).grid(
                row=row_index, column=2, padx=8, pady=8, sticky="w"
            )
            ctk.CTkLabel(self.list_container, text=entry["category"]).grid(
                row=row_index, column=3, padx=8, pady=8, sticky="w"
            )

            strength_label = entry.get("strength_rating", "Unknown")
            strength_color = self._strength_color(strength_label)
            ctk.CTkLabel(
                self.list_container,
                text=strength_label,
                text_color=strength_color,
            ).grid(row=row_index, column=4, padx=8, pady=8, sticky="w")

    def get_selected_entry_id(self) -> int | None:
        """Return currently selected entry ID, if any."""
        selected = self.selected_entry_var.get().strip()
        if not selected:
            return None
        return int(selected)

    def _toggle_selection(self, selected_value: str) -> None:
        """Toggle current radio selection off when same row is clicked again."""
        if self._last_selected_value == selected_value:
            self.selected_entry_var.set("")
            self._last_selected_value = ""
        else:
            self._last_selected_value = selected_value

    def set_status_message(self, message: str, is_error: bool = False) -> None:
        """Show a brief status message using the dedicated status label."""
        color = "#ff6b6b" if is_error else "#7ed957"
        self.status_label.configure(text=message, text_color=color)

    def _edit_selected(self) -> None:
        """Open edit flow for selected row."""
        entry_id = self.get_selected_entry_id()
        if entry_id is not None:
            self.on_edit_selected(entry_id)

    def _delete_selected(self) -> None:
        """Delete selected row from vault."""
        entry_id = self.get_selected_entry_id()
        if entry_id is not None:
            self.on_delete_selected(entry_id)

    def _on_search_var_changed(self, *_args: object) -> None:
        """Emit real-time search updates while the user types."""
        self.on_search_change(self.search_var.get())

    def _on_filter_selected(self, selected_filter: str) -> None:
        """Apply category filter."""
        self.on_filter_change(selected_filter)

    def _emit_sort_change(self, _selected: str | None = None) -> None:
        """Apply selected sort field/order pair."""
        self.on_sort_change(self.sort_field_menu.get(), self.sort_order_menu.get())

    def _strength_color(self, strength_label: str) -> str:
        """Return color token for strength category."""
        normalized = strength_label.lower()
        if normalized == "weak":
            return "#ff6b6b"
        if normalized == "moderate":
            return "#f6c85f"
        if normalized == "strong":
            return "#7ed957"
        if normalized == "very strong":
            return "#30c07a"
        return "gray80"
