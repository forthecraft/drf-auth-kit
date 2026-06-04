"""
Configuration settings for Auth Kit Passwordless package.

This module provides a centralized configuration system for passwordless
authentication, allowing dynamic loading of handlers, serializers, and
views based on user settings.
"""

# pyright: reportAssignmentType=false
# mypy: disable-error-code=assignment

from typing import TYPE_CHECKING, Any, cast

from django.core.signals import setting_changed

from auth_kit.app_settings import (
    ImportStr,
    create_api_settings_from_model,
    get_import_strings,
)

if TYPE_CHECKING:
    from auth_kit.passwordless.handlers.base import PasswordlessBaseHandler
    from auth_kit.passwordless.views.login import (
        PasswordlessInitiateView,
        PasswordlessVerifyView,
    )


class PasswordlessSetting:
    """
    Default passwordless settings configuration for Auth Kit.

    Provides all configurable options for passwordless authentication
    including handler configuration, token expiry, and view/serializer classes.
    """

    # Handler Configuration
    PASSWORDLESS_HANDLERS: list[type["PasswordlessBaseHandler"]] = ImportStr(
        [
            "auth_kit.passwordless.handlers.email_link.EmailLinkHandler",
        ]
    )

    # Token Expiry Configuration
    PASSWORDLESS_EPHEMERAL_TOKEN_EXPIRY: int = 60 * 15  # 15 minutes in seconds

    # Email Magic Link Configuration
    PASSWORDLESS_EMAIL_SUBJECT: str = "Your login link"
    PASSWORDLESS_EMAIL_PLAIN_TEMPLATE: str = (
        "auth_kit/passwordless/email/magic_link.txt"
    )
    PASSWORDLESS_EMAIL_HTML_TEMPLATE: str = (
        "auth_kit/passwordless/email/magic_link.html"
    )
    PASSWORDLESS_MAGIC_LINK_URL: str = ""

    # When enabled, an unknown email is signed up on first magic link use.
    # The account is only created once the link is clicked, so an unverified
    # address can never leave a user row behind.
    PASSWORDLESS_EMAIL_SIGNUP: bool = False

    # View Configuration
    PASSWORDLESS_INITIATE_VIEW: type["PasswordlessInitiateView"] = ImportStr(
        "auth_kit.passwordless.views.PasswordlessInitiateView"
    )
    PASSWORDLESS_VERIFY_VIEW: type["PasswordlessVerifyView"] = ImportStr(
        "auth_kit.passwordless.views.PasswordlessVerifyView"
    )

    # Field to satisfy the type checker for APISettings compatibility
    user_settings: dict[str, Any] = {}


IMPORT_STRINGS = get_import_strings(PasswordlessSetting)

auth_kit_passwordless_settings = cast(
    PasswordlessSetting,
    create_api_settings_from_model(PasswordlessSetting, IMPORT_STRINGS),
)


def reload_api_settings(*args: Any, **kwargs: Any) -> None:  # pragma: no cover
    """Reload API settings when Django settings change."""
    global auth_kit_passwordless_settings  # noqa

    setting, value = kwargs["setting"], kwargs["value"]
    if setting == "AUTH_KIT":
        auth_kit_passwordless_settings = cast(
            PasswordlessSetting,
            create_api_settings_from_model(PasswordlessSetting, IMPORT_STRINGS, value),
        )


setting_changed.connect(reload_api_settings)
