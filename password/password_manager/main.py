"""Application entry point for the Secure Password Manager."""

try:
    from gui.app import App
except ImportError:  # pragma: no cover - fallback for package execution style
    from password_manager.gui.app import App


def main() -> None:
    """Launch the GUI application."""
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
