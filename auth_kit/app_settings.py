"""
Configuration settings for Auth Kit package.

This module provides a centralized configuration system for Auth Kit,
allowing dynamic loading of serializers, views, and authentication classes
based on user settings.
"""

# pyright: reportAssignmentType=false
# mypy: disable-error-code=assignment

from collections.abc import Callable
from datetime import timedelta
from typing import TYPE_CHECKING, Any, Literal, cast

from django.conf import settings
from django.core.signals import setting_changed
from rest_framework.serializers import Serializer
from rest_framework.settings import APISettings

if TYPE_CHECKING:
    from rest_framework.authtoken.models import Token
    from rest_framework.viewsets import GenericViewSet

    from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

    from auth_kit.serializers.login_factors import BaseLoginResponseSerializer
    from auth_kit.social.views import SocialConnectView, SocialLoginView
    from auth_kit.views import (
        LoginView,
        LogoutView,
        PasswordChangeView,
        PasswordResetConfirmView,
        PasswordResetView,
        RegisterView,
        ResendEmailVerificationView,
        UserView,
        VerifyEmailView,
    )
    from auth_kit.views.jwt import RefreshViewWithCookieSupport

else:
    TokenObtainPairSerializer = Token = GenericAPIView = BaseLoginResponseSerializer = (
        Any
    )


class ImportStr(str):
    """String subclass that marks a setting as requiring import resolution."""

    pass


class MySetting:
    """Default settings configuration for Auth Kit."""

    # ===================================================================
    # CORE AUTHENTICATION SETTINGS
    # ===================================================================
    AUTH_TYPE: Literal["jwt", "token", "custom"] = "jwt"  # jwt | token | custom
    USE_AUTH_COOKIE: bool = True
    SESSION_LOGIN: bool = False
    ALLOW_LOGIN_REDIRECT: bool = False

    # ===================================================================
    # COOKIE CONFIGURATION
    # ===================================================================
    AUTH_COOKIE_SECURE: bool = False
    AUTH_COOKIE_HTTPONLY: bool = True
    AUTH_COOKIE_SAMESITE: Literal["Lax", "Strict", "None"] = "Lax"
    AUTH_COOKIE_DOMAIN: str | None = None

    # ===================================================================
    # JWT AUTHENTICATION SETTINGS
    # ===================================================================
    AUTH_JWT_COOKIE_NAME: str = "auth-jwt"
    AUTH_JWT_COOKIE_PATH: str = "/"
    AUTH_JWT_REFRESH_COOKIE_NAME: str = "auth-refresh-jwt"
    AUTH_JWT_REFRESH_COOKIE_PATH: str = "/"

    # ===================================================================
    # TOKEN AUTHENTICATION SETTINGS
    # ===================================================================
    AUTH_TOKEN_MODEL: Token = ImportStr("rest_framework.authtoken.models.Token")
    AUTH_TOKEN_COOKIE_NAME: str = "auth-token"
    AUTH_TOKEN_COOKIE_PATH: str = "/"
    AUTH_TOKEN_COOKIE_EXPIRE_TIME: timedelta = timedelta(days=1)

    # ===================================================================
    # LOGIN & LOGOUT SERIALIZERS & VIEWS
    # ===================================================================
    LOGIN_REQUEST_SERIALIZER: type[Serializer[dict[str, Any]]] = ImportStr(
        "auth_kit.serializers.login_factors.LoginRequestSerializer"
    )
    LOGIN_RESPONSE_SERIALIZER: type[BaseLoginResponseSerializer] = ImportStr(
        "auth_kit.serializers.login_factors.BaseLoginResponseSerializer"
    )
    LOGIN_SERIALIZER_FACTORY: Callable[[], type[Serializer[dict[str, Any]]]] = (
        ImportStr("auth_kit.serializers.login.get_login_serializer")
    )
    LOGIN_VIEW: type["LoginView"] = ImportStr("auth_kit.views.LoginView")

    LOGOUT_SERIALIZER: type[Serializer[dict[str, Any]]] = ImportStr(
        "auth_kit.serializers.logout.AuthKitLogoutSerializer"
    )
    LOGOUT_VIEW: type["LogoutView"] = ImportStr("auth_kit.views.LogoutView")

    # ===================================================================
    # USER MANAGEMENT SERIALIZERS & VIEWS
    # ===================================================================
    USER_SERIALIZER: type[Serializer[dict[str, Any]]] = ImportStr(
        "auth_kit.serializers.user.UserSerializer"
    )
    USER_VIEW: type["UserView"] = ImportStr("auth_kit.views.UserView")

    # ===================================================================
    # REGISTRATION SERIALIZERS & VIEWS
    # ===================================================================
    REGISTER_SERIALIZER: type[Serializer[dict[str, Any]]] = ImportStr(
        "auth_kit.serializers.RegisterSerializer"
    )
    REGISTER_VIEW: type["RegisterView"] = ImportStr("auth_kit.views.RegisterView")

    # Email Verification
    VERIFY_EMAIL_VIEW: type["VerifyEmailView"] = ImportStr(
        "auth_kit.views.VerifyEmailView"
    )
    RESEND_EMAIL_VERIFICATION_VIEW: type["ResendEmailVerificationView"] = ImportStr(
        "auth_kit.views.ResendEmailVerificationView"
    )

    # Registration Configuration
    FRONTEND_BASE_URL: str | None = None
    REGISTER_EMAIL_CONFIRM_PATH: str | None = None
    GET_EMAIL_VERIFICATION_URL_FUNC: Callable[..., str] = ImportStr(
        "auth_kit.views.registration.get_email_verification_url"
    )
    SEND_VERIFY_EMAIL_FUNC: Callable[..., None] = ImportStr(
        "auth_kit.views.registration.send_verify_email"
    )
    POST_SIGNUP_FUNC: Callable[..., None] = ImportStr(
        "auth_kit.views.registration.default_post_signup"
    )

    # ===================================================================
    # PASSWORD MANAGEMENT SERIALIZERS & VIEWS
    # ===================================================================
    PASSWORD_CHANGE_SERIALIZER: type[Serializer[dict[str, Any]]] = ImportStr(
        "auth_kit.serializers.PasswordChangeSerializer"
    )
    PASSWORD_CHANGE_VIEW: type["PasswordChangeView"] = ImportStr(
        "auth_kit.views.PasswordChangeView"
    )

    PASSWORD_RESET_SERIALIZER: type[Serializer[dict[str, Any]]] = ImportStr(
        "auth_kit.serializers.PasswordResetSerializer"
    )
    PASSWORD_RESET_VIEW: type["PasswordResetView"] = ImportStr(
        "auth_kit.views.PasswordResetView"
    )

    PASSWORD_RESET_CONFIRM_SERIALIZER: type[Serializer[dict[str, Any]]] = ImportStr(
        "auth_kit.serializers.PasswordResetConfirmSerializer"
    )
    PASSWORD_RESET_CONFIRM_VIEW: type["PasswordResetConfirmView"] = ImportStr(
        "auth_kit.views.PasswordResetConfirmView"
    )

    # Password Configuration
    PASSWORD_RESET_CONFIRM_PATH: str | None = None
    PASSWORD_RESET_URL_GENERATOR: Callable[..., str] = ImportStr(
        "auth_kit.forms.password_reset_url_generator"
    )
    SEND_PASSWORD_RESET_EMAIL_FUNC: Callable[..., None] = ImportStr(
        "auth_kit.forms.send_password_reset_email"
    )
    OLD_PASSWORD_FIELD_ENABLED: bool = False
    PASSWORD_RESET_PREVENT_ENUMERATION: bool = True

    # ===================================================================
    # JWT SPECIFIC SETTINGS
    # ===================================================================
    JWT_TOKEN_CLAIMS_SERIALIZER: type[TokenObtainPairSerializer] = ImportStr(
        "rest_framework_simplejwt.serializers.TokenObtainPairSerializer"
    )
    JWT_REFRESH_VIEW: type["RefreshViewWithCookieSupport"] = ImportStr(
        "auth_kit.views.jwt.RefreshViewWithCookieSupport"
    )

    # ===================================================================
    # SOCIAL AUTHENTICATION
    # ===================================================================
    SOCIAL_LOGIN_AUTH_TYPE: Literal["token", "code"] = "code"
    SOCIAL_LOGIN_AUTO_CONNECT_BY_EMAIL: bool = True
    SOCIAL_LOGIN_CALLBACK_BASE_URL: str = ""
    SOCIAL_CONNECT_CALLBACK_BASE_URL: str = ""
    SOCIAL_HIDE_AUTH_ERROR_DETAILS: bool = True
    SOCIAL_CONNECT_REQUIRE_EMAIL_MATCH: bool = True

    # Social Views & Serializers
    SOCIAL_LOGIN_VIEW: type["SocialLoginView"] = ImportStr(
        "auth_kit.social.views.login.SocialLoginView"
    )
    SOCIAL_CONNECT_VIEW: type["SocialConnectView"] = ImportStr(
        "auth_kit.social.views.connect.SocialConnectView"
    )
    SOCIAL_ACCOUNT_VIEW_SET: type["GenericViewSet[Any]"] = ImportStr(
        "auth_kit.social.views.account.SocialAccountViewSet"
    )
    SOCIAL_LOGIN_SERIALIZER_FACTORY: Callable[
        [str], type[Serializer[dict[str, Any]]]
    ] = ImportStr("auth_kit.social.serializers.get_social_login_serializer")
    SOCIAL_LOGIN_CALLBACK_URL_GENERATOR: Callable[..., str] = ImportStr(
        "auth_kit.social.utils.get_social_login_callback_url"
    )
    SOCIAL_CONNECT_CALLBACK_URL_GENERATOR: Callable[..., str] = ImportStr(
        "auth_kit.social.utils.get_social_connect_callback_url"
    )

    # ===================================================================
    # MULTI-FACTOR AUTHENTICATION
    # ===================================================================
    USE_MFA: bool = False

    # ===================================================================
    # URL & UTILITY SETTINGS
    # ===================================================================
    URL_NAMESPACE: str = ""
    EXCLUDED_URL_NAMES: list[str] = []

    # Field to satisfy the type checker for APISettings compatibility
    user_settings: dict[str, Any] = {}


# Dynamically generate IMPORT_STRINGS from MySetting class
IMPORT_STRINGS = tuple(
    field
    for field in dir(MySetting)
    if isinstance(getattr(MySetting, field), ImportStr)
)


def create_api_settings_from_model(
    model_class: type,
    import_strings: tuple[str, ...],
    override_value: dict[str, Any] | None = None,
) -> MySetting:
    """
    Create API settings instance from a model class.

    Args:
        model_class: The settings model class to use as defaults
        import_strings: Tuple of setting names that require import resolution
        override_value: Optional override values for settings

    Returns:
        Configured MySetting instance
    """
    # Get user settings from Django settings
    user_settings = getattr(settings, "AUTH_KIT", override_value)

    # Get defaults from class variables
    defaults_dict = {}
    for attr_name in dir(model_class):
        if attr_name.startswith("_"):
            continue

        attr_value = getattr(model_class, attr_name)
        # Skip methods and other non-setting attributes
        if not callable(attr_value):
            defaults_dict[attr_name] = attr_value

    # Create APISettings instance
    api_settings = APISettings(
        user_settings=user_settings,  # type: ignore
        defaults=defaults_dict,  # type: ignore
        import_strings=import_strings,
    )

    return cast(MySetting, api_settings)


auth_kit_settings = create_api_settings_from_model(MySetting, IMPORT_STRINGS)


def reload_api_settings(*args: Any, **kwargs: Any) -> None:
    """
    Reload API settings when Django settings change.

    Args:
        *args: Variable length argument list
        **kwargs: Arbitrary keyword arguments including 'setting' and 'value'
    """
    global auth_kit_settings  # noqa

    setting, value = kwargs["setting"], kwargs["value"]
    if setting == "AUTH_KIT":
        auth_kit_settings = create_api_settings_from_model(
            MySetting, IMPORT_STRINGS, value
        )


setting_changed.connect(reload_api_settings)
