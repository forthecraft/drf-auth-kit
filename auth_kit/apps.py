"""
Django app configuration for Auth Kit.
"""

from django.apps import AppConfig


class AuthKitConfig(AppConfig):
    """App configuration for auth_kit."""

    name = "auth_kit"

    def ready(self) -> None:
        """Import checks module to register system checks."""
        import auth_kit.checks  # noqa: F401  # pyright: ignore[reportUnusedImport]
