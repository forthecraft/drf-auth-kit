"""
JWT token serializers for Auth Kit.

This module provides serializers for handling JWT tokens,
including refresh token functionality with cookie support.
"""

from typing import Any

from django.utils.translation import gettext_lazy as _
from rest_framework import serializers

from rest_framework_simplejwt.exceptions import InvalidToken
from rest_framework_simplejwt.serializers import TokenRefreshSerializer
from rest_framework_simplejwt.settings import api_settings as jwt_settings

from auth_kit.cookie_profiles import resolve_cookie_profile


class JWTSerializer(serializers.Serializer[dict[str, str]]):
    """JWT access and refresh tokens with expiration timestamps."""

    access = serializers.CharField(read_only=True)
    refresh = serializers.CharField(read_only=True)
    access_expiration = serializers.DateTimeField(read_only=True)
    refresh_expiration = serializers.DateTimeField(read_only=True)


class CookieTokenRefreshSerializer(TokenRefreshSerializer, JWTSerializer):
    """JWT token refresh with cookie and request data support."""

    refresh = serializers.CharField(
        required=False, help_text=_("Will override cookie."), allow_blank=True
    )

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """
        Initialize password change serializer.

        Args:
            *args: Variable length argument list
            **kwargs: Arbitrary keyword arguments
        """
        super().__init__(*args, **kwargs)

        if not jwt_settings.ROTATE_REFRESH_TOKENS:
            self.fields.pop("refresh_expiration")
            self.fields["refresh"].write_only = True

        self.request = self.context.get("request")
        self.user = getattr(self.request, "user", None)

    def extract_refresh_token(self) -> str:
        """
        Extract refresh token from request data or cookies.

        Returns:
            The refresh token string

        Raises:
            InvalidToken: If no valid refresh token is found
        """
        request = self.context["request"]
        if "refresh" in request.data and request.data["refresh"] != "":
            return str(request.data["refresh"])
        profile = resolve_cookie_profile(request)
        cookie_name = profile.refresh_cookie_name
        if cookie_name and cookie_name in request.COOKIES:
            return str(request.COOKIES.get(cookie_name))
        else:
            raise InvalidToken(str(_("No valid refresh token found.")))

    def validate(self, attrs: dict[str, Any]) -> dict[str, str]:
        """
        Validate the refresh token from request data or cookies.

        Args:
            attrs: Input attributes dictionary

        Returns:
            Validated attributes with refresh token
        """
        attrs["refresh"] = self.extract_refresh_token()
        return super().validate(attrs)
