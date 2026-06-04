"""
URL configuration for Auth Kit authentication endpoints.

This module defines all URL patterns for authentication-related views
including login, logout, registration, password reset, and email verification.
"""

from django.urls import URLPattern, URLResolver, include, re_path

from rest_framework_simplejwt.views import TokenVerifyView

from auth_kit.utils import filter_excluded_urls

from .app_settings import auth_kit_settings

urlpatterns: list[URLPattern | URLResolver] = [
    # URLs that do not require a session or valid token
    re_path(
        r"password/reset/?$",
        auth_kit_settings.PASSWORD_RESET_VIEW.as_view(),
        name="rest_password_reset",
    ),
    re_path(
        r"password/reset/confirm/?$",
        auth_kit_settings.PASSWORD_RESET_CONFIRM_VIEW.as_view(),
        name="rest_password_reset_confirm",
    ),
    # URLs that require a user to be logged in with a valid session / token.
    re_path(r"logout/?$", auth_kit_settings.LOGOUT_VIEW.as_view(), name="rest_logout"),
    re_path(
        r"user/?$",
        auth_kit_settings.USER_VIEW.as_view(),
        name="rest_user",
    ),
    re_path(
        r"password/change/?$",
        auth_kit_settings.PASSWORD_CHANGE_VIEW.as_view(),
        name="rest_password_change",
    ),
    re_path(
        r"registration/?$",
        auth_kit_settings.REGISTER_VIEW.as_view(),
        name="rest_register",
    ),
    re_path(
        r"registration/verify-email/?$",
        auth_kit_settings.VERIFY_EMAIL_VIEW.as_view(),
        name="rest_verify_email",
    ),
    re_path(
        r"registration/resend-email/?$",
        auth_kit_settings.RESEND_EMAIL_VERIFICATION_VIEW.as_view(),
        name="rest_resend_email",
    ),
]

if not auth_kit_settings.USE_MFA:
    login_urls: list[URLPattern | URLResolver] = [
        re_path(r"login/?$", auth_kit_settings.LOGIN_VIEW.as_view(), name="rest_login"),
    ]
    urlpatterns.extend(login_urls)
else:

    urlpatterns.extend([re_path("", include("auth_kit.mfa.urls"))])

if auth_kit_settings.USE_PASSWORDLESS:
    urlpatterns.extend([re_path("", include("auth_kit.passwordless.urls"))])

if auth_kit_settings.AUTH_TYPE == "jwt":
    jwt_urls: list[URLPattern | URLResolver] = [
        re_path(r"token/verify/?$", TokenVerifyView.as_view(), name="token_verify"),
        re_path(
            r"token/refresh/?$",
            auth_kit_settings.JWT_REFRESH_VIEW.as_view(),
            name="token_refresh",
        ),
    ]
    urlpatterns.extend(jwt_urls)

# Apply URL exclusion filtering
urlpatterns = filter_excluded_urls(urlpatterns)
