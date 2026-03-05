"""Main CustomTkinter application controller."""

from __future__ import annotations

from pathlib import Path
import threading
from typing import Any, Callable, Optional

import customtkinter as ctk

try:
    from auth import MasterAuth
    from breach import BreachChecker
    from encryption import EncryptionManager
    from generator import PasswordGenerator
    from gui.breach_results import BreachResultsFrame
    from gui.dashboard import DashboardFrame
    from gui.entry_form import EntryFormFrame
    from gui.generator_dialog import GeneratorDialog
    from gui.login import LoginFrame
    from strength import StrengthAnalyser
    from vault import Vault
except ImportError:  # pragma: no cover - fallback for package execution style
    from password_manager.auth import MasterAuth
    from password_manager.breach import BreachChecker
    from password_manager.encryption import EncryptionManager
    from password_manager.generator import PasswordGenerator
    from password_manager.gui.breach_results import BreachResultsFrame
    from password_manager.gui.dashboard import DashboardFrame
    from password_manager.gui.entry_form import EntryFormFrame
    from password_manager.gui.generator_dialog import GeneratorDialog
    from password_manager.gui.login import LoginFrame
    from password_manager.strength import StrengthAnalyser
    from password_manager.vault import Vault


class App(ctk.CTk):
    """Root GUI controller that wires views to auth, vault, and utilities."""

    INACTIVITY_TIMEOUT_MS = 5 * 60 * 1000

    def __init__(self) -> None:
        """Initialize application state, services, and the first visible screen."""
        super().__init__()
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.title("Secure Password Manager")
        self.geometry("1100x700")
        self.minsize(960, 620)

        self.database_path = Path(__file__).resolve().parent.parent / "database.db"

        self.auth = MasterAuth(self.database_path)
        self.strength_analyser = StrengthAnalyser(
            Path(__file__).resolve().parent.parent / "common_passwords.txt"
        )
        self.password_generator = PasswordGenerator()
        self.breach_checker = BreachChecker()

        self.encryption_manager: Optional[EncryptionManager] = None
        self.vault: Optional[Vault] = None

        self.active_frame: Optional[ctk.CTkFrame] = None
        self.current_entry_form: Optional[EntryFormFrame] = None
        self.dashboard_frame: Optional[DashboardFrame] = None

        self.current_search_query = ""
        self.current_category_filter = "All Categories"
        self.current_sort_field = "service_name"
        self.current_sort_order = "asc"
        self.pending_dashboard_message: tuple[str, bool] = ("", False)
        self.entry_strength_cache: dict[int, str] = {}
        self.breach_check_in_progress = False

        self.clipboard_clear_job: str | None = None
        self.inactivity_job: str | None = None
        self.bind_all("<Any-KeyPress>", self._reset_inactivity_timer)
        self.bind_all("<Any-Button>", self._reset_inactivity_timer)

        self.show_login_screen()

    def show_login_screen(self) -> None:
        """Display login/setup screen based on vault initialization state."""
        self._cancel_inactivity_timer()
        first_time_setup = not self.auth.is_master_password_set()
        login_frame = LoginFrame(
            parent=self,
            first_time_setup=first_time_setup,
            on_login=self._handle_unlock_request,
            on_setup=self._handle_setup_request,
        )
        self._show_frame(login_frame)

    def _handle_setup_request(self, master_password: str, confirm_password: str) -> None:
        """Create initial master password, then unlock the vault."""
        if not isinstance(self.active_frame, LoginFrame):
            return

        success, message = self.auth.setup_master_password(master_password, confirm_password)
        self.active_frame.set_status(message, is_error=not success)
        self.active_frame.clear_fields()
        if success:
            # Auto-login after setup to reduce friction in first-time flow.
            self._handle_unlock_request(master_password)

    def _handle_unlock_request(self, candidate_password: str) -> None:
        """Authenticate user and initialize encrypted vault session."""
        if not isinstance(self.active_frame, LoginFrame):
            return

        success, message, derived_key = self.auth.verify_master_password(candidate_password)
        self.active_frame.set_status(message, is_error=not success)
        self.active_frame.clear_fields()

        if not success or derived_key is None:
            return

        self.encryption_manager = EncryptionManager(derived_key)
        self.vault = Vault(self.database_path, self.encryption_manager)
        self._rebuild_strength_cache()
        self.show_dashboard()

    def show_dashboard(self) -> None:
        """Display main dashboard and load current vault entries."""
        self._reset_dashboard_view_state()
        dashboard = DashboardFrame(
            parent=self,
            on_add_new=self._open_add_entry_form,
            on_edit_selected=self._open_edit_entry_form,
            on_delete_selected=self._delete_entry,
            on_generate_password=self._open_generator_dialog_standalone,
            on_check_all_breaches=self._check_all_entries_for_breaches,
            on_logout=self.lock_vault,
            on_search_change=self._on_search_changed,
            on_filter_change=self._on_filter_changed,
            on_sort_change=self._on_sort_changed,
        )
        self.dashboard_frame = dashboard
        self._show_frame(dashboard)
        self._refresh_dashboard_entries()

        if self.pending_dashboard_message[0]:
            message, is_error = self.pending_dashboard_message
            dashboard.set_status_message(message, is_error)
            self.pending_dashboard_message = ("", False)

        self._reset_inactivity_timer()

    def _reset_dashboard_view_state(self) -> None:
        """Reset dashboard search/filter/sort state before rendering.

        The dashboard frame is recreated when navigating between views. We reset
        state here to avoid invisible filters from previous sessions hiding new
        entries while the visible UI controls appear to be at defaults.
        """
        self.current_search_query = ""
        self.current_category_filter = "All Categories"
        self.current_sort_field = "service_name"
        self.current_sort_order = "asc"

    def _open_add_entry_form(self) -> None:
        """Open empty entry form for new credential."""
        self._open_entry_form(existing_entry=None)

    def _open_edit_entry_form(self, entry_id: int) -> None:
        """Open populated form to edit existing credential."""
        if self.vault is None:
            return
        try:
            entry_record = self.vault.get_entry(entry_id, include_decrypted_password=True)
        except Exception:
            self.pending_dashboard_message = ("Unable to load selected entry.", True)
            self.show_dashboard()
            return

        if entry_record is None:
            self.pending_dashboard_message = ("Selected entry no longer exists.", True)
            self.show_dashboard()
            return
        self._open_entry_form(existing_entry=entry_record)

    def _open_entry_form(self, existing_entry: dict | None) -> None:
        """Render add/edit form view."""
        entry_form = EntryFormFrame(
            parent=self,
            analyser=self.strength_analyser,
            on_save=self._save_entry_from_form,
            on_cancel=self.show_dashboard,
            on_generate_password=self._open_generator_dialog_for_form,
            on_check_breach=self._check_single_password_from_form,
            existing_entry=existing_entry,
        )
        self.current_entry_form = entry_form
        self._show_frame(entry_form)
        if existing_entry and existing_entry.get("decryption_error"):
            entry_form.set_message(
                "Stored password could not be decrypted. Enter a new password to overwrite it.",
                is_error=True,
            )
        self._reset_inactivity_timer()

    def _save_entry_from_form(self, form_data: dict) -> None:
        """Persist add/edit form values through vault service."""
        if self.vault is None:
            self.pending_dashboard_message = ("Vault is locked.", True)
            self.show_login_screen()
            return

        try:
            if form_data.get("id"):
                updated = self.vault.update_entry(
                    entry_id=int(form_data["id"]),
                    service_name=form_data["service_name"],
                    username=form_data["username"],
                    plaintext_password=form_data["password"],
                    url=form_data.get("url", ""),
                    category=form_data.get("category", "Other"),
                )
                if not updated:
                    self.pending_dashboard_message = ("No changes were saved.", True)
                else:
                    self.pending_dashboard_message = ("Entry updated successfully.", False)
                    updated_id = int(form_data["id"])
                    self.entry_strength_cache[updated_id] = self.strength_analyser.analyze_password(
                        str(form_data["password"])
                    )["rating"]
            else:
                added_entry = self.vault.add_entry(
                    service_name=form_data["service_name"],
                    username=form_data["username"],
                    plaintext_password=form_data["password"],
                    url=form_data.get("url", ""),
                    category=form_data.get("category", "Other"),
                )
                self.pending_dashboard_message = ("Entry added successfully.", False)
                if added_entry.id is not None:
                    self.entry_strength_cache[int(added_entry.id)] = self.strength_analyser.analyze_password(
                        str(form_data["password"])
                    )["rating"]
        except Exception as error:
            if self.current_entry_form:
                self.current_entry_form.set_message(f"Save failed: {error}", is_error=True)
            return

        self.show_dashboard()

    def _delete_entry(self, entry_id: int) -> None:
        """Delete selected credential from vault."""
        if self.vault is None:
            return
        try:
            deleted = self.vault.delete_entry(entry_id)
        except Exception:
            self.pending_dashboard_message = ("Delete failed due to database error.", True)
            self.show_dashboard()
            return

        if deleted:
            self.pending_dashboard_message = ("Entry deleted.", False)
            self.entry_strength_cache.pop(entry_id, None)
        else:
            self.pending_dashboard_message = ("Entry not found.", True)
        self.show_dashboard()

    def _refresh_dashboard_entries(self) -> None:
        """Apply search/filter/sort state and refresh dashboard list."""
        if self.vault is None or self.dashboard_frame is None:
            return

        try:
            sorted_entries = self.vault.sort_entries(
                field=self.current_sort_field,
                order=self.current_sort_order,
                include_decrypted_password=False,
            )
        except Exception:
            self.dashboard_frame.populate_entries([])
            self.dashboard_frame.set_status_message("Unable to load entries.", True)
            return

        filtered_entries = []
        search_lower = self.current_search_query.lower().strip()

        for entry in sorted_entries:
            if (
                self.current_category_filter != "All Categories"
                and entry.get("category") != self.current_category_filter
            ):
                continue

            if search_lower:
                searchable_text = " ".join(
                    [
                        str(entry.get("service_name", "")),
                        str(entry.get("username", "")),
                        str(entry.get("category", "")),
                    ]
                ).lower()
                if search_lower not in searchable_text:
                    continue

            entry_id = int(entry.get("id", 0))
            entry["strength_rating"] = self.entry_strength_cache.get(entry_id, "Unknown")
            filtered_entries.append(entry)

        self.dashboard_frame.populate_entries(filtered_entries)

    def _on_search_changed(self, query: str) -> None:
        """Handle live search query updates."""
        self.current_search_query = query
        self._refresh_dashboard_entries()

    def _on_filter_changed(self, selected_filter: str) -> None:
        """Handle category filter updates."""
        self.current_category_filter = selected_filter
        self._refresh_dashboard_entries()

    def _on_sort_changed(self, sort_field: str, sort_order: str) -> None:
        """Handle sort settings updates."""
        self.current_sort_field = sort_field
        self.current_sort_order = sort_order
        self._refresh_dashboard_entries()

    def _open_generator_dialog_standalone(self) -> None:
        """Open password generator popup without auto-fill target."""
        GeneratorDialog(
            parent=self,
            generator=self.password_generator,
            analyser=self.strength_analyser,
            on_copy_password=self.copy_to_clipboard,
            on_use_password=None,
        )

    def _open_generator_dialog_for_form(self) -> None:
        """Open generator popup and inject chosen password into current form."""
        if self.current_entry_form is None:
            return

        GeneratorDialog(
            parent=self,
            generator=self.password_generator,
            analyser=self.strength_analyser,
            on_copy_password=self.copy_to_clipboard,
            on_use_password=self.current_entry_form.set_generated_password,
        )

    def _check_single_password_from_form(self, password: str) -> None:
        """Run breach check for password in add/edit form."""
        if self.current_entry_form is None:
            return

        if not password:
            self.current_entry_form.set_message("Password is required for breach check.", is_error=True)
            return

        form_reference = self.current_entry_form
        form_reference.set_message("Checking breach status...", is_error=False)

        def worker() -> dict[str, Any]:
            """Perform single-password breach API lookup."""
            return self.breach_checker.check_password(password)

        def on_success(result: dict[str, Any]) -> None:
            """Render successful single-password breach check result."""
            if self.current_entry_form is not form_reference:
                return
            if not result["checked"]:
                form_reference.set_message(result["error"], is_error=True)
                return
            if result["is_compromised"]:
                form_reference.set_message(
                    f"Compromised: seen {result['breach_count']} times in breaches.",
                    is_error=True,
                )
            else:
                form_reference.set_message("No breach found for this password.", is_error=False)

        def on_error(error: Exception) -> None:
            """Render single-password breach check failure state."""
            if self.current_entry_form is form_reference:
                form_reference.set_message(f"Breach check failed: {error}", is_error=True)

        self._run_in_background(worker, on_success, on_error)

    def _check_all_entries_for_breaches(self) -> None:
        """Batch-check all vault entries and show dedicated results view."""
        if self.vault is None:
            return
        if self.breach_check_in_progress:
            if isinstance(self.active_frame, DashboardFrame):
                self.active_frame.set_status_message("Breach check already in progress.", is_error=True)
            return

        vault_reference = self.vault
        self.breach_check_in_progress = True
        if isinstance(self.active_frame, DashboardFrame):
            self.active_frame.set_status_message(
                "Checking all entries for breaches... this may take a moment.",
                is_error=False,
            )

        def worker() -> list[dict[str, Any]]:
            """Fetch all entries and perform batch breach checks off the GUI thread."""
            entries = vault_reference.get_all_entries(include_decrypted_password=True)

            results: list[dict[str, Any]] = []
            checkable_entries: list[dict[str, Any]] = []
            for entry in entries:
                if entry.get("decryption_error"):
                    results.append(
                        {
                            "id": entry.get("id"),
                            "service_name": entry.get("service_name", ""),
                            "username": entry.get("username", ""),
                            "breach_count": 0,
                            "is_compromised": False,
                            "checked": False,
                            "error": "Entry cannot be decrypted with the current master password.",
                        }
                    )
                else:
                    checkable_entries.append(entry)

            results.extend(self.breach_checker.check_multiple_passwords(checkable_entries))
            for entry in entries:
                entry.pop("decrypted_password", None)
            return results

        def on_success(results: list[dict[str, Any]]) -> None:
            """Render breach result screen when batch check succeeds."""
            self.breach_check_in_progress = False
            if self.vault is None:
                return
            breach_frame = BreachResultsFrame(
                parent=self,
                on_recheck=self._check_all_entries_for_breaches,
                on_back=self.show_dashboard,
            )
            breach_frame.populate_results(results)
            self._show_frame(breach_frame)

        def on_error(error: Exception) -> None:
            """Return to dashboard with error status if batch check fails."""
            self.breach_check_in_progress = False
            self.pending_dashboard_message = (f"Breach check failed: {error}", True)
            self.show_dashboard()

        self._run_in_background(worker, on_success, on_error)

    def copy_to_clipboard(self, text_value: str) -> None:
        """Copy text to clipboard and schedule automatic cleanup."""
        self.clipboard_clear()
        self.clipboard_append(text_value)
        self.update_idletasks()

        if self.clipboard_clear_job is not None:
            self.after_cancel(self.clipboard_clear_job)
        self.clipboard_clear_job = self.after(30_000, self.clear_clipboard)

    def clear_clipboard(self) -> None:
        """Clear system clipboard content."""
        self.clipboard_clear()
        self.clipboard_clear_job = None

    def lock_vault(self) -> None:
        """Lock vault session and return to login view."""
        self.encryption_manager = None
        self.vault = None
        self.entry_strength_cache = {}
        self.breach_check_in_progress = False
        self.current_entry_form = None
        self.pending_dashboard_message = ("", False)
        self.show_login_screen()

    def _show_frame(self, frame: ctk.CTkFrame) -> None:
        """Replace active frame with a new one."""
        if self.active_frame is not None:
            self.active_frame.destroy()
        self.active_frame = frame
        frame.pack(fill="both", expand=True)

    def _reset_inactivity_timer(self, _event: object | None = None) -> None:
        """Reset inactivity timeout only while vault is unlocked."""
        if self.vault is None:
            return
        if self.inactivity_job is not None:
            self.after_cancel(self.inactivity_job)
        self.inactivity_job = self.after(self.INACTIVITY_TIMEOUT_MS, self._auto_lock_due_to_inactivity)

    def _cancel_inactivity_timer(self) -> None:
        """Cancel scheduled inactivity lock if present."""
        if self.inactivity_job is not None:
            self.after_cancel(self.inactivity_job)
            self.inactivity_job = None

    def _auto_lock_due_to_inactivity(self) -> None:
        """Automatically lock the vault after inactivity period."""
        self.lock_vault()
        if isinstance(self.active_frame, LoginFrame):
            self.active_frame.set_status(
                "Vault locked automatically after 5 minutes of inactivity.",
                is_error=True,
            )

    def _run_in_background(
        self,
        worker: Callable[[], Any],
        on_success: Callable[[Any], None],
        on_error: Callable[[Exception], None] | None = None,
    ) -> None:
        """Run blocking work in a daemon thread and marshal callbacks to GUI thread."""

        def thread_target() -> None:
            """Execute worker and marshal completion callbacks to main GUI thread."""
            try:
                result = worker()
            except Exception as error:
                if on_error is not None:
                    self.after(0, lambda: on_error(error))
                return
            self.after(0, lambda: on_success(result))

        threading.Thread(target=thread_target, daemon=True).start()

    def _rebuild_strength_cache(self) -> None:
        """Build per-entry strength cache once per unlock to avoid repeated decrypts."""
        self.entry_strength_cache = {}
        if self.vault is None:
            return

        try:
            entries = self.vault.get_all_entries(include_decrypted_password=True)
        except Exception:
            return

        for entry in entries:
            entry_id = entry.get("id")
            if entry_id is None:
                continue
            if entry.get("decryption_error"):
                self.entry_strength_cache[int(entry_id)] = "Unavailable"
            else:
                password_value = str(entry.get("decrypted_password", ""))
                rating = self.strength_analyser.analyze_password(password_value)["rating"]
                self.entry_strength_cache[int(entry_id)] = rating
            entry.pop("decrypted_password", None)
