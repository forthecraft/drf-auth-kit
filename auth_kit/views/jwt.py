"""
JWT token views for Auth Kit.

This module provides views for JWT token refresh with cookie support.
"""

from typing import Any

from django.utils import timezone
from rest_framework import status
from rest_framework.request import Request
from rest_framework.response import Response

from drf_spectacular.utils import (
    extend_schema,
)
from rest_framework_simplejwt.settings import api_settings as jwt_settings
from rest_framework_simplejwt.views import TokenRefreshView

from auth_kit.api_descriptions import get_jwt_refresh_description
from auth_kit.app_settings import auth_kit_settings
from auth_kit.cookie_profiles import resolve_cookie_profile
from auth_kit.jwt_auth import set_auth_kit_cookie
from auth_kit.serializers import CookieTokenRefreshSerializer


class RefreshViewWithCookieSupport(TokenRefreshView):
    """
    JWT Token Refresh

    Refresh JWT access tokens using refresh tokens.
    Supports both request data and cookie-based refresh tokens.
    """

    serializer_class = CookieTokenRefreshSerializer  # type: ignore[assignment,unused-ignore]

    @extend_schema(description=get_jwt_refresh_description())
    def post(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        """Refresh JWT access tokens."""
        return super().post(request, *args, **kwargs)

    def finalize_response(
        self, request: Request, response: Response, *args: Any, **kwargs: Any
    ) -> Response:
        """
        Finalize the response by setting JWT cookies.

        Args:
            request: The DRF request object
            response: The DRF response object
            *args: Variable length argument list
            **kwargs: Arbitrary keyword arguments

        Returns:
            The finalized DRF response with cookies set
        """
        is_ok = response.status_code == status.HTTP_200_OK
        profile = resolve_cookie_profile(request) if is_ok else None

        if profile is not None and "access" in response.data:
            response.data["access_expiration"] = (
                timezone.now() + jwt_settings.ACCESS_TOKEN_LIFETIME
            )
            set_auth_kit_cookie(
                response,
                profile.jwt_cookie_name,
                response.data["access"],
                profile.jwt_cookie_path,
                response.data["access_expiration"],
            )

        if profile is not None and "refresh" in response.data:
            response.data["refresh_expiration"] = (
                timezone.now() + jwt_settings.REFRESH_TOKEN_LIFETIME
            )
            set_auth_kit_cookie(
                response,
                profile.refresh_cookie_name,
                response.data["refresh"],
                profile.refresh_cookie_path,
                response.data["refresh_expiration"],
            )

            if auth_kit_settings.AUTH_COOKIE_HTTPONLY:
                response.data["refresh"] = ""

        return super().finalize_response(request, response, *args, **kwargs)
