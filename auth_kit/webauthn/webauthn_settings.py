"""
Configuration settings for Auth Kit WebAuthn package.

This module provides a centralized configuration system for WebAuthn functionality,
allowing dynamic loading of views, serializers, and WebAuthn relying party
configuration based on user settings.
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
from auth_kit.webauthn.types import (
    AttestationPreference,
    ResidentKeyRequirement,
    UserVerification,
)

if TYPE_CHECKING:
    from auth_kit.webauthn.models import WebAuthnCredential
    from auth_kit.webauthn.serializers.credential import (
        WebAuthnCredentialCreateSerializer,
        WebAuthnCredentialSerializer,
        WebAuthnCredentialUpdateSerializer,
    )
    from auth_kit.webauthn.views import WebAuthnCredentialViewSet


class WebAuthnSetting:
    """
    Default WebAuthn settings configuration for Auth Kit.

    Provides all configurable options for WebAuthn functionality including
    relying party configuration, credential management views and serializers.
    """

    # Relying Party Configuration
    WEBAUTHN_RP_ID: str = "localhost"
    WEBAUTHN_RP_NAME: str = "My Application"
    WEBAUTHN_ORIGIN: str | list[str] = "http://localhost:8000"

    # Ceremony Configuration
    WEBAUTHN_TIMEOUT: int = 60000  # milliseconds
    WEBAUTHN_ATTESTATION: AttestationPreference = "none"
    WEBAUTHN_USER_VERIFICATION: UserVerification = "preferred"
    WEBAUTHN_RESIDENT_KEY: ResidentKeyRequirement = "preferred"

    # Challenge Storage
    WEBAUTHN_CHALLENGE_EXPIRY: int = 300  # seconds

    # Model Configuration
    WEBAUTHN_CREDENTIAL_MODEL: type["WebAuthnCredential"] = ImportStr(
        "auth_kit.webauthn.models.WebAuthnCredential"
    )

    # View Configuration
    WEBAUTHN_CREDENTIAL_VIEW_SET: type["WebAuthnCredentialViewSet"] = ImportStr(
        "auth_kit.webauthn.views.WebAuthnCredentialViewSet"
    )

    # Serializer Configuration
    WEBAUTHN_CREDENTIAL_SERIALIZER: type["WebAuthnCredentialSerializer"] = ImportStr(
        "auth_kit.webauthn.serializers.credential.WebAuthnCredentialSerializer"
    )
    WEBAUTHN_CREDENTIAL_CREATE_SERIALIZER: type[
        "WebAuthnCredentialCreateSerializer"
    ] = ImportStr(
        "auth_kit.webauthn.serializers.credential.WebAuthnCredentialCreateSerializer"
    )
    WEBAUTHN_CREDENTIAL_UPDATE_SERIALIZER: type[
        "WebAuthnCredentialUpdateSerializer"
    ] = ImportStr(
        "auth_kit.webauthn.serializers.credential.WebAuthnCredentialUpdateSerializer"
    )

    # Field to satisfy the type checker for APISettings compatibility
    user_settings: dict[str, Any] = {}


IMPORT_STRINGS = get_import_strings(WebAuthnSetting)

auth_kit_webauthn_settings = cast(
    WebAuthnSetting, create_api_settings_from_model(WebAuthnSetting, IMPORT_STRINGS)
)


def reload_api_settings(*args: Any, **kwargs: Any) -> None:  # pragma: no cover
    """Reload API settings when Django settings change."""
    global auth_kit_webauthn_settings  # noqa

    setting, value = kwargs["setting"], kwargs["value"]
    if setting == "AUTH_KIT":
        auth_kit_webauthn_settings = cast(
            WebAuthnSetting,
            create_api_settings_from_model(WebAuthnSetting, IMPORT_STRINGS, value),
        )


setting_changed.connect(reload_api_settings)
