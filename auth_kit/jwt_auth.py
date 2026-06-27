"""
JWT cookie authentication utilities.

This module provides utility functions for setting and unsetting
JWT authentication cookies in HTTP responses.
"""

from datetime import datetime

from django.contrib.auth.base_user import AbstractBaseUser
from django.utils.dateparse import parse_datetime
from rest_framework.response import Response

from rest_framework_simplejwt.tokens import AccessToken, RefreshToken

from .app_settings import auth_kit_settings
from .cookie_profiles import CookieProfile


def _apply_partitioned_flag(response: Response, cookie_name: str) -> None:
    """
    Append the Partitioned attribute to a Set-Cookie header.

    Django does not natively support the Partitioned cookie attribute yet
    (pending Django ticket #34613, blocked on Python 3.14's stdlib support).
    This patches the cookie's Morsel to recognize ``Partitioned`` as a
    boolean flag, the same way ``Secure`` and ``HttpOnly`` work.

    Args:
        response: The HTTP response object
        cookie_name: Name of the cookie to patch
    """
    if cookie_name in response.cookies:  # pragma: no branch
        morsel = response.cookies[cookie_name]
        # Register "partitioned" as a known boolean flag on the Morsel,
        # mirroring how "secure" and "httponly" are handled internally.
        morsel._reserved["partitioned"] = "Partitioned"  # type: ignore[attr-defined]
        morsel._flags.add("partitioned")  # type: ignore[attr-defined]
        morsel["partitioned"] = True  # pyright: ignore[reportIndexIssue]


def set_auth_kit_cookie(
    response: Response,
    cookie_name: str,
    cookie_value: str,
    cookie_path: str,
    cookie_exp_time: datetime | str | None,
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
    if isinstance(cookie_exp_time, str):
        cookie_exp_time = parse_datetime(cookie_exp_time)

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

    if auth_kit_settings.AUTH_COOKIE_PARTITIONED:
        _apply_partitioned_flag(response, cookie_name)


def unset_jwt_cookies(response: Response, profile: CookieProfile) -> None:
    """
    Remove JWT authentication cookies from the HTTP response.

    Args:
        response: The HTTP response object
        profile: The cookie profile whose JWT cookies should be removed
    """
    cookie_samesite = auth_kit_settings.AUTH_COOKIE_SAMESITE
    cookie_domain = auth_kit_settings.AUTH_COOKIE_DOMAIN

    response.delete_cookie(
        profile.jwt_cookie_name,
        path=profile.jwt_cookie_path,
        samesite=cookie_samesite,
        domain=cookie_domain,
    )
    response.delete_cookie(
        profile.refresh_cookie_name,
        path=profile.refresh_cookie_path,
        samesite=cookie_samesite,
        domain=cookie_domain,
    )

    if auth_kit_settings.AUTH_COOKIE_PARTITIONED:
        _apply_partitioned_flag(response, profile.jwt_cookie_name)
        _apply_partitioned_flag(response, profile.refresh_cookie_name)


def unset_token_cookie(response: Response, profile: CookieProfile) -> None:
    """
    Remove the token authentication cookie from the HTTP response.

    Args:
        response: The HTTP response object
        profile: The cookie profile whose token cookie should be removed
    """
    cookie_samesite = auth_kit_settings.AUTH_COOKIE_SAMESITE
    cookie_domain = auth_kit_settings.AUTH_COOKIE_DOMAIN

    response.delete_cookie(
        profile.token_cookie_name,
        path=profile.token_cookie_path,
        samesite=cookie_samesite,
        domain=cookie_domain,
    )

    if auth_kit_settings.AUTH_COOKIE_PARTITIONED:
        _apply_partitioned_flag(response, profile.token_cookie_name)


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
