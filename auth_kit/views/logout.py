"""
Logout views for Auth Kit.

This module provides logout functionality with support for different
authentication types and token cleanup.
"""

from typing import Any

from django.conf import settings
from django.contrib.auth import logout as django_logout
from django.core.exceptions import ObjectDoesNotExist
from django.utils.translation import gettext_lazy as _
from rest_framework import status
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.serializers import Serializer

from drf_spectacular.utils import (
    extend_schema,
)
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import RefreshToken

from auth_kit.api_descriptions import get_logout_description
from auth_kit.app_settings import auth_kit_settings
from auth_kit.jwt_auth import unset_jwt_cookies, unset_token_cookie
from auth_kit.serializers.logout import get_logout_serializer


class LogoutView(GenericAPIView[Any]):
    """
    User Logout

    Logout user and invalidate authentication tokens.
    Clears authentication cookies and blacklists tokens when available.
    """

    permission_classes = (IsAuthenticated,)
    throttle_scope = "auth_kit"

    def get_serializer_class(self) -> type[Serializer[dict[str, Any]]]:
        """
        Get the logout serializer class based on current settings.

        Returns the appropriate serializer class for handling logout requests
        based on the configured authentication type (JWT, token, or custom).

        Returns:
            The logout serializer class from the auth kit settings
        """
        return get_logout_serializer()

    def initial(self, request: Request, *args: Any, **kwargs: Any) -> None:
        """
        Initialize the request with refresh token from cookies.

        Args:
            request: The DRF request object
            *args: Variable length argument list
            **kwargs: Arbitrary keyword arguments
        """
        super().initial(request, *args, **kwargs)
        cookie_name = auth_kit_settings.AUTH_JWT_REFRESH_COOKIE_NAME

        if cookie_name and cookie_name in request.COOKIES:
            self.request.data["refresh"] = request.COOKIES.get(cookie_name)

    @extend_schema(description=get_logout_description())
    def post(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        """
        Logout user and invalidate tokens.

        Args:
            request: The DRF request object
            *args: Variable length argument list
            **kwargs: Arbitrary keyword arguments

        Returns:
            DRF response with logout result
        """
        return self.logout(request)

    def logout_jwt(self, request: Request, response: Response) -> None:
        """
        Handle JWT logout including token blacklisting.

        Args:
            request: The DRF request object
            response: The DRF response object
        """
        if auth_kit_settings.USE_AUTH_COOKIE:
            unset_jwt_cookies(response)

        if "rest_framework_simplejwt.token_blacklist" in settings.INSTALLED_APPS:
            try:
                token = RefreshToken(None)
                if auth_kit_settings.USE_AUTH_COOKIE:
                    try:
                        token = RefreshToken(
                            request.COOKIES[  # type: ignore
                                auth_kit_settings.AUTH_JWT_REFRESH_COOKIE_NAME
                            ]
                        )
                    except KeyError:
                        response.data = {
                            "detail": _(
                                "Refresh token was not included in cookie data."
                            )
                        }
                        response.status_code = status.HTTP_401_UNAUTHORIZED
                else:
                    try:
                        token = RefreshToken(request.data["refresh"])
                    except KeyError:
                        response.data = {
                            "detail": _(
                                "Refresh token was not included in request data."
                            )
                        }
                        response.status_code = status.HTTP_401_UNAUTHORIZED

                token.blacklist()
            except TokenError as error:
                response.data = {"detail": _(str(error))}
                response.status_code = status.HTTP_400_BAD_REQUEST
                return
            except (AttributeError, TypeError):
                response.data = {"detail": _("An error has occurred.")}
                response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR

    def logout(self, request: Request) -> Response:
        """
        Perform user logout based on authentication type.

        Args:
            request: The DRF request object

        Returns:
            DRF response with logout result
        """
        if auth_kit_settings.SESSION_LOGIN:
            django_logout(request)

        response = Response(
            {"detail": _("Successfully logged out.")},
            status=status.HTTP_200_OK,
        )

        if auth_kit_settings.AUTH_TYPE == "jwt":
            self.logout_jwt(request, response)
        elif auth_kit_settings.AUTH_TYPE == "token":
            try:
                request.user.auth_token.delete()  # type: ignore[union-attr]
            except (AttributeError, ObjectDoesNotExist):
                pass
            if auth_kit_settings.USE_AUTH_COOKIE:
                unset_token_cookie(response)
        else:
            self.logout_custom(request, response)
        return response

    def logout_custom(self, request: Request, response: Response) -> None:
        """
        Handle custom logout logic.

        Override this method to implement custom logout behavior.

        Args:
            request: The DRF request object
            response: The DRF response object
        """
        pass
