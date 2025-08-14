"""
JWT cookie authentication utilities.

This module provides utility functions for setting and unsetting
JWT authentication cookies in HTTP responses.
"""

from datetime import datetime

from django.contrib.auth.base_user import AbstractBaseUser
from rest_framework.response import Response

from rest_framework_simplejwt.tokens import AccessToken, RefreshToken

from .app_settings import auth_kit_settings


def set_auth_kit_cookie(
    response: Response,
    cookie_name: str,
    cookie_value: str,
    cookie_path: str,
    cookie_exp_time: datetime | None,
) -> None:
    """
    Set an authentication cookie in the HTTP response.

    Args:
        response: The HTTP response object
        cookie_name: Name of the cookie to set
        cookie_value: Value to store in the cookie
        cookie_path: Path for which the cookie is valid
        cookie_exp_time: Expiration time for the cookie
    """

    response.set_cookie(
        cookie_name,
        cookie_value,
        expires=cookie_exp_time,
        secure=auth_kit_settings.AUTH_COOKIE_SECURE,
        httponly=auth_kit_settings.AUTH_COOKIE_HTTPONLY,
        samesite=auth_kit_settings.AUTH_COOKIE_SAMESITE,
        path=cookie_path,
        domain=auth_kit_settings.AUTH_COOKIE_DOMAIN,
    )


def unset_jwt_cookies(response: Response) -> None:
    """
    Remove JWT authentication cookies from the HTTP response.

    Args:
        response: The HTTP response object
    """
    cookie_samesite = auth_kit_settings.AUTH_COOKIE_SAMESITE
    cookie_domain = auth_kit_settings.AUTH_COOKIE_DOMAIN

    response.delete_cookie(
        auth_kit_settings.AUTH_JWT_COOKIE_NAME,
        samesite=cookie_samesite,
        domain=cookie_domain,
    )
    response.delete_cookie(
        auth_kit_settings.AUTH_JWT_REFRESH_COOKIE_NAME,
        path=auth_kit_settings.AUTH_JWT_REFRESH_COOKIE_PATH,
        samesite=cookie_samesite,
        domain=cookie_domain,
    )


def unset_token_cookie(response: Response) -> None:
    """
    Remove token authentication cookie from the HTTP response.

    Args:
        response: The HTTP response object
    """
    cookie_samesite = auth_kit_settings.AUTH_COOKIE_SAMESITE
    cookie_domain = auth_kit_settings.AUTH_COOKIE_DOMAIN

    response.delete_cookie(
        auth_kit_settings.AUTH_TOKEN_COOKIE_NAME,
        samesite=cookie_samesite,
        domain=cookie_domain,
    )


def jwt_encode(user: AbstractBaseUser) -> tuple[AccessToken, RefreshToken]:
    """
    Generate JWT access and refresh tokens for a user.

    Args:
        user: The user to generate tokens for

    Returns:
        Tuple containing (access_token, refresh_token)
    """
    from auth_kit.app_settings import auth_kit_settings

    refresh: RefreshToken = auth_kit_settings.JWT_TOKEN_CLAIMS_SERIALIZER.get_token(user)  # type: ignore
    return refresh.access_token, refresh
