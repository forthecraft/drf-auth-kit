"""
Authentication classes for Auth Kit.

This module provides cookie-based authentication classes that work with
JWT tokens, DRF tokens, and custom authentication backends.
"""

from typing import Any

from django.contrib.auth.base_user import AbstractBaseUser
from rest_framework.authentication import TokenAuthentication
from rest_framework.request import Request

from drf_spectacular.contrib.rest_framework_simplejwt import SimpleJWTScheme
from drf_spectacular.plumbing import (
    build_bearer_security_scheme_object,
)
from rest_framework_simplejwt.authentication import JWTAuthentication

from auth_kit.app_settings import auth_kit_settings
from auth_kit.cookie_profiles import resolve_cookie_profile


class AuthKitCookieAuthentication(JWTAuthentication):
    """
    Base authentication class that supports both header and cookie-based authentication.

    An authentication plugin that authenticates requests through tokens provided
    in request cookies or headers, with preference given to headers.
    """

    def authenticate_with_cookie(
        self, request: Request, cookie_name: str | None
    ) -> tuple[Any, Any] | None:
        """
        Authenticate using header or cookie-based token with header taking priority.

        Args:
            request: The HTTP request object
            cookie_name: Name of the cookie containing the authentication token

        Returns:
            Tuple of (user, token) if authentication succeeds, None otherwise
        """
        header = self.get_header(request)
        if header is None and cookie_name:  # pyright: ignore
            raw_token = request.COOKIES.get(cookie_name)
            raw_token = raw_token.encode("utf-8") if raw_token else None
        else:
            raw_token = self.get_raw_token(header)

        if raw_token is None:
            return None

        token = raw_token.decode()

        if auth_kit_settings.AUTH_TYPE == "jwt":
            validated_token = self.get_validated_token(raw_token)
            user: AbstractBaseUser = self.get_user(validated_token)
            return user, validated_token
        elif auth_kit_settings.AUTH_TYPE == "token":
            return self.authenticate_credentials(token)
        else:
            return self.custom_authenticate(token)

    def authenticate_credentials(
        self, key: str
    ) -> tuple[Any, Any] | None:  # pragma: no cover
        """
        Authenticate using token credentials.

        Args:
            key: The token key to authenticate

        Returns:
            Tuple of (user, token) if authentication succeeds, None otherwise
        """
        pass

    def custom_authenticate(self, token: str) -> tuple[Any, Any] | None:
        """
        Custom authentication method for non-standard auth types.

        Args:
            token: The token to authenticate

        Returns:
            Tuple of (user, token) if authentication succeeds, None otherwise
        """


class TokenCookieAuthentication(TokenAuthentication, AuthKitCookieAuthentication):
    """Authentication class for DRF token-based authentication with cookie support."""

    keyword = "Bearer"

    def authenticate(self, request: Request) -> tuple[Any, Any] | None:
        """
        Authenticate the request using DRF token from cookie or header.

        Args:
            request: The HTTP request object

        Returns:
            Tuple of (user, token) if authentication succeeds, None otherwise
        """
        profile = resolve_cookie_profile(request)
        return self.authenticate_with_cookie(request, profile.token_cookie_name)


class TokenCookieAuthenticationScheme(SimpleJWTScheme):  # type: ignore[no-untyped-call]
    """OpenAPI schema for token cookie authentication."""

    target_class = "auth_kit.authentication.TokenCookieAuthentication"
    optional = True
    name = [  # type: ignore[assignment]
        "TokenAuthentication",
        "TokenCookieAuthentication",
    ]  # name used in the schema

    def get_security_definition(  # pyright: ignore[reportIncompatibleMethodOverride]
        self, auto_schema: Any
    ) -> list[dict[str, Any]]:
        """
        Get security definition for OpenAPI schema.

        Args:
            auto_schema: The auto schema generator instance

        Returns:
            List of security definitions for the schema
        """
        return [
            build_bearer_security_scheme_object(  # type: ignore[no-untyped-call]
                header_name="HTTP_AUTHORIZATION",
                token_prefix=TokenCookieAuthentication.keyword,
                bearer_format="DRF Token",
            ),
            {
                "type": "apiKey",
                "in": "cookie",
                "name": auth_kit_settings.AUTH_TOKEN_COOKIE_NAME,
            },
        ]


class JWTCookieAuthentication(AuthKitCookieAuthentication):
    """Authentication class for JWT-based authentication with cookie support."""

    def authenticate(self, request: Request) -> tuple[Any, Any] | None:
        """
        Authenticate the request using JWT from cookie or header.

        Args:
            request: The HTTP request object

        Returns:
            Tuple of (user, token) if authentication succeeds, None otherwise
        """
        profile = resolve_cookie_profile(request)
        return self.authenticate_with_cookie(request, profile.jwt_cookie_name)


class JWTCookieAuthenticationScheme(SimpleJWTScheme):  # type: ignore[no-untyped-call]
    """OpenAPI schema for JWT cookie authentication."""

    target_class = "auth_kit.authentication.JWTCookieAuthentication"
    optional = True
    name = ["JWTAuthentication", "JWTCookieAuthentication"]  # type: ignore[assignment]

    def get_security_definition(  # pyright: ignore[reportIncompatibleMethodOverride]
        self, auto_schema: Any
    ) -> list[dict[str, Any]]:
        """
        Get security definition for OpenAPI schema.

        Args:
            auto_schema: The auto schema generator instance

        Returns:
            List of security definitions for the schema
        """
        return [
            super().get_security_definition(auto_schema),  # type: ignore[no-untyped-call]
            {
                "type": "apiKey",
                "in": "cookie",
                "name": auth_kit_settings.AUTH_JWT_COOKIE_NAME,
            },
        ]
