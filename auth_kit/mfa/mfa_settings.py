"""
Configuration settings for Auth Kit MFA package.

This module provides a centralized configuration system for MFA functionality,
allowing dynamic loading of handlers, serializers, views, and authentication
classes based on user settings.
"""

# pyright: reportAssignmentType=false
# mypy: disable-error-code=assignment

from collections.abc import Callable
from typing import TYPE_CHECKING, Any, cast

from django.core.signals import setting_changed
from rest_framework.serializers import Serializer

from auth_kit.app_settings import (
    ImportStr,
    create_api_settings_from_model,
    get_import_strings,
)

if TYPE_CHECKING:
    from auth_kit.mfa.handlers.base import MFABaseHandler
    from auth_kit.mfa.models import MFAMethod
    from auth_kit.mfa.serializers.login_factors import (
        MFAChangeMethodSerializer,
        MFAFirstStepResponseSerializer,
        MFALoginChallengeSerializer,
        MFAResendSerializer,
        MFASecondStepRequestSerializer,
    )
    from auth_kit.mfa.serializers.mfa import (
        MFAMethodChallengeSerializer,
        MFAMethodConfigSerializer,
        MFAMethodConfirmSerializer,
        MFAMethodCreateSerializer,
        MFAMethodDeactivateSerializer,
        MFAMethodDeleteSerializer,
        MFAMethodPrimaryUpdateSerializer,
        MFAMethodSendCodeSerializer,
    )
    from auth_kit.mfa.views import (
        LoginChangeMethodView,
        LoginFirstStepView,
        LoginMFAChallengeView,
        LoginMFAResendView,
        LoginSecondStepView,
        MFAMethodViewSet,
    )


class MFASetting:
    """
    Default MFA settings configuration for Auth Kit.

    Provides all configurable options for MFA functionality including
    handler configuration, security settings, view/serializer classes,
    and behavioral constraints.
    """

    # MFA Model Configuration
    MFA_MODEL: type["MFAMethod"] = ImportStr("auth_kit.mfa.models.MFAMethod")

    # Handler Configuration
    MFA_HANDLERS: list[type["MFABaseHandler"]] = ImportStr(
        [
            "auth_kit.mfa.handlers.app.MFAAppHandler",
            "auth_kit.mfa.handlers.email.MFAEmailHandler",
        ]
    )

    # Backup Code Settings
    NUM_OF_BACKUP_CODES: int = 5
    BACKUP_CODE_LENGTH: int = 12
    BACKUP_CODE_ALLOWED_CHARS: str = (
        "0123456789ABCDEFGHJKMNPQRSTVWXYZ"  # Crockford Base32
    )
    BACKUP_CODE_SECURE_HASH: bool = True

    # TOTP Configuration
    MFA_TOTP_DEFAULT_VALID_WINDOW: int = 0  # seconds
    MFA_TOTP_DEFAULT_INTERVAL: int = 30  # seconds

    # Application Settings
    MFA_APPLICATION_NAME: str = "MyApplication"

    # Token Expiry Configuration
    MFA_EPHEMERAL_TOKEN_EXPIRY: int = 60 * 15  # 15 minutes in seconds

    # MFA Update Constraints
    MFA_UPDATE_PRIMARY_METHOD_REQUIRED_PRIMARY_CODE: bool = False
    MFA_PREVENT_DELETE_ACTIVE_METHOD: bool = False
    MFA_PREVENT_DELETE_PRIMARY_METHOD: bool = False
    MFA_DELETE_ACTIVE_METHOD_REQUIRE_CODE: bool = False

    # MFA Views Configuration
    LOGIN_FIRST_STEP_VIEW: type["LoginFirstStepView"] = ImportStr(
        "auth_kit.mfa.views.LoginFirstStepView"
    )
    LOGIN_SECOND_STEP_VIEW: type["LoginSecondStepView"] = ImportStr(
        "auth_kit.mfa.views.LoginSecondStepView"
    )
    LOGIN_CHANGE_METHOD_VIEW: type["LoginChangeMethodView"] = ImportStr(
        "auth_kit.mfa.views.LoginChangeMethodView"
    )
    LOGIN_MFA_RESEND_VIEW: type["LoginMFAResendView"] = ImportStr(
        "auth_kit.mfa.views.LoginMFAResendView"
    )
    LOGIN_MFA_CHALLENGE_VIEW: type["LoginMFAChallengeView"] = ImportStr(
        "auth_kit.mfa.views.LoginMFAChallengeView"
    )
    LOGIN_MFA_METHOD_VIEW_SET: type["MFAMethodViewSet"] = ImportStr(
        "auth_kit.mfa.views.MFAMethodViewSet"
    )

    # MFA Response Serializers
    MFA_FIRST_STEP_RESPONSE_SERIALIZER: type["MFAFirstStepResponseSerializer"] = (
        ImportStr(
            "auth_kit.mfa.serializers.login_factors.MFAFirstStepResponseSerializer"
        )
    )
    MFA_SECOND_STEP_REQUEST_SERIALIZER: type["MFASecondStepRequestSerializer"] = (
        ImportStr(
            "auth_kit.mfa.serializers.login_factors.MFASecondStepRequestSerializer"
        )
    )
    MFA_CHANGE_METHOD_SERIALIZER: type["MFAChangeMethodSerializer"] = ImportStr(
        "auth_kit.mfa.serializers.login_factors.MFAChangeMethodSerializer"
    )
    MFA_RESEND_SERIALIZER: type["MFAResendSerializer"] = ImportStr(
        "auth_kit.mfa.serializers.login_factors.MFAResendSerializer"
    )
    MFA_LOGIN_CHALLENGE_SERIALIZER: type["MFALoginChallengeSerializer"] = ImportStr(
        "auth_kit.mfa.serializers.login_factors.MFALoginChallengeSerializer"
    )

    # Serializer Factories
    GET_NO_MFA_LOGIN_RESPONSE_SERIALIZER: Callable[
        [], type[Serializer[dict[str, Any]]]
    ] = ImportStr(
        "auth_kit.mfa.serializers.login_factors.get_no_mfa_login_response_serializer"
    )

    MFA_FIRST_STEP_SERIALIZER_FACTORY: Callable[
        [], type[Serializer[dict[str, Any]]]
    ] = ImportStr("auth_kit.mfa.serializers.login.get_mfa_first_step_serializer")
    MFA_SECOND_STEP_SERIALIZER_FACTORY: Callable[
        [], type[Serializer[dict[str, Any]]]
    ] = ImportStr("auth_kit.mfa.serializers.login.get_mfa_second_step_serializer")

    # MFA Management Serializers
    MFA_METHOD_CHALLENGE_SERIALIZER: type["MFAMethodChallengeSerializer"] = ImportStr(
        "auth_kit.mfa.serializers.mfa.MFAMethodChallengeSerializer"
    )
    MFA_METHOD_CONFIG_SERIALIZER: type["MFAMethodConfigSerializer"] = ImportStr(
        "auth_kit.mfa.serializers.mfa.MFAMethodConfigSerializer"
    )
    MFA_METHOD_CONFIRM_SERIALIZER: type["MFAMethodConfirmSerializer"] = ImportStr(
        "auth_kit.mfa.serializers.mfa.MFAMethodConfirmSerializer"
    )
    MFA_METHOD_CREATE_SERIALIZER: type["MFAMethodCreateSerializer"] = ImportStr(
        "auth_kit.mfa.serializers.mfa.MFAMethodCreateSerializer"
    )
    MFA_METHOD_DEACTIVATE_SERIALIZER: type["MFAMethodDeactivateSerializer"] = ImportStr(
        "auth_kit.mfa.serializers.mfa.MFAMethodDeactivateSerializer"
    )
    MFA_METHOD_DELETE_SERIALIZER: type["MFAMethodDeleteSerializer"] = ImportStr(
        "auth_kit.mfa.serializers.mfa.MFAMethodDeleteSerializer"
    )
    MFA_METHOD_PRIMARY_UPDATE_SERIALIZER: type["MFAMethodPrimaryUpdateSerializer"] = (
        ImportStr("auth_kit.mfa.serializers.mfa.MFAMethodPrimaryUpdateSerializer")
    )
    MFA_METHOD_SEND_CODE_SERIALIZER: type["MFAMethodSendCodeSerializer"] = ImportStr(
        "auth_kit.mfa.serializers.mfa.MFAMethodSendCodeSerializer"
    )

    # Field to satisfy the type checker for APISettings compatibility
    user_settings: dict[str, Any] = {}


IMPORT_STRINGS = get_import_strings(MFASetting)

auth_kit_mfa_settings = cast(
    MFASetting, create_api_settings_from_model(MFASetting, IMPORT_STRINGS)
)


def reload_api_settings(*args: Any, **kwargs: Any) -> None:
    """Reload API settings when Django settings change."""
    global auth_kit_mfa_settings  # noqa

    setting, value = kwargs["setting"], kwargs["value"]
    if setting == "AUTH_KIT":
        auth_kit_mfa_settings = cast(
            MFASetting,
            create_api_settings_from_model(MFASetting, IMPORT_STRINGS, value),
        )


setting_changed.connect(reload_api_settings)
