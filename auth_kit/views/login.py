"""
Login views for Auth Kit.

This module provides login view with support for different authentication
types and cookie-based token management.
"""

from typing import Any, cast

from django.contrib.auth import login as django_login
from django.contrib.auth.base_user import AbstractBaseUser
from django.contrib.auth.models import AbstractUser
from django.http import HttpResponseBase, HttpResponseRedirect
from django.utils import timezone
from django.utils.functional import lazy
from rest_framework import status
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import AllowAny
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.serializers import BaseSerializer, Serializer

from drf_spectacular.utils import (
    extend_schema,
)

from auth_kit.api_descriptions import get_login_description
from auth_kit.app_settings import auth_kit_settings
from auth_kit.jwt_auth import set_auth_kit_cookie
from auth_kit.utils import sensitive_post_parameters_m


class LoginView(GenericAPIView[Any]):
    """
    User Authentication

    Authenticate users and obtain access tokens for API access.
    Supports both JWT and DRF token authentication based on configuration.
    """

    permission_classes = (AllowAny,)
    authentication_classes = []
    throttle_scope = "auth_kit"

    def __init__(self, **kwargs: Any) -> None:
        """
        Initialize login view.

        Args:
            **kwargs: Arbitrary keyword arguments
        """
        super().__init__(**kwargs)
        self.user: AbstractUser | AbstractBaseUser | None = None
        self.access_token: str | None = None
        self.refresh_token: str | None = None

    def get_serializer_class(self) -> type[Serializer[dict[str, Any]]]:
        """
        Get the login serializer class based on current settings.

        Returns the appropriate serializer class for handling login requests
        and responses based on the configured authentication type (JWT, token, or custom).

        Returns:
            The login serializer class from the auth kit settings
        """
        return auth_kit_settings.LOGIN_SERIALIZER_FACTORY()

    @sensitive_post_parameters_m
    def dispatch(self, *args: Any, **kwargs: Any) -> HttpResponseBase:
        """
        Dispatch the request with sensitive parameter protection.

        Args:
            *args: Variable length argument list
            **kwargs: Arbitrary keyword arguments

        Returns:
            HTTP response
        """
        return super().dispatch(*args, **kwargs)

    def perform_session_login(self, user: AbstractBaseUser) -> None:
        """
        Process user login using Django's login function.
        """
        django_login(self.request, user)  # type: ignore[unused-ignore, arg-type]

    def create_response_with_cookies(self, serializer: BaseSerializer[Any]) -> Response:
        """
        Create login response with authentication cookies.

        Args:
            serializer: Validated login serializer containing tokens

        Returns:
            DRF response with authentication cookies set
        """
        data = serializer.data
        validated_data = serializer.data
        response = Response(data, status=status.HTTP_200_OK)

        if auth_kit_settings.AUTH_TYPE == "jwt":
            set_auth_kit_cookie(
                response,
                auth_kit_settings.AUTH_JWT_COOKIE_NAME,
                data["access"],
                auth_kit_settings.AUTH_JWT_COOKIE_PATH,
                validated_data["access_expiration"],
            )
            set_auth_kit_cookie(
                response,
                auth_kit_settings.AUTH_JWT_REFRESH_COOKIE_NAME,
                data["refresh"],
                auth_kit_settings.AUTH_JWT_REFRESH_COOKIE_PATH,
                validated_data["refresh_expiration"],
            )
            response.data["refresh"] = ""
        elif auth_kit_settings.AUTH_TYPE == "token":
            token_cookie_expire_time = (
                timezone.now() + auth_kit_settings.AUTH_TOKEN_COOKIE_EXPIRE_TIME
                if auth_kit_settings.AUTH_TOKEN_COOKIE_EXPIRE_TIME
                else None
            )
            set_auth_kit_cookie(
                response,
                auth_kit_settings.AUTH_TOKEN_COOKIE_NAME,
                data["key"],
                auth_kit_settings.AUTH_TOKEN_COOKIE_PATH,
                token_cookie_expire_time,
            )
        else:  # custom
            self.set_custom_cookie(response)

        return response

    @extend_schema(description=lazy(get_login_description, str)())
    def post(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        """
        Authenticate user and return access tokens.

        Args:
            request: The DRF request object
            *args: Variable length argument list
            **kwargs: Arbitrary keyword arguments

        Returns:
            DRF response with login result
        """
        self.request = request
        serializer = self.get_serializer(data=self.request.data)
        serializer.is_valid(raise_exception=True)

        return self.perform_login(serializer)

    def create_redirect_response(
        self, serializer: BaseSerializer[Any], redirect_url: str
    ) -> HttpResponseRedirect:
        """
        Create HTTP redirect response with authentication cookies.

        Reuses the cookie setting logic from create_response_with_cookies.

        Args:
            serializer: Validated login serializer containing tokens
            redirect_url: URL to redirect to

        Returns:
            HttpResponseRedirect with authentication cookies set
        """
        # Create a temporary response to set cookies on
        temp_response = self.create_response_with_cookies(serializer)

        # Create redirect response
        redirect_response = HttpResponseRedirect(redirect_url)

        # Copy cookies from temp response to redirect response
        if auth_kit_settings.USE_AUTH_COOKIE:
            for cookie_name, cookie_value in temp_response.cookies.items():
                redirect_response.cookies[cookie_name] = cookie_value

        return redirect_response

    def perform_login(self, serializer: BaseSerializer[Any]) -> Response:
        """
        Complete the login process after successful validation.

        This method handles the final steps of user authentication including:

        - Creating the response with authentication tokens
        - Setting authentication cookies if configured
        - Performing Django session login if enabled
        - Redirecting if configured

        Args:
            serializer: The validated login serializer containing user data and tokens

        Returns:
            Response: DRF response with login result (cast from HttpResponseRedirect if redirecting)
        """
        if auth_kit_settings.SESSION_LOGIN:
            self.perform_session_login(serializer.validated_data["user"])

        # Check for redirect URL if enabled
        redirect_url = None
        if auth_kit_settings.ALLOW_LOGIN_REDIRECT:
            redirect_url = self.request.query_params.get(
                "next"
            ) or self.request.query_params.get("redirect_to")

        # If redirect URL is provided, return HttpResponseRedirect with cookies
        if redirect_url:
            return cast(
                Response, self.create_redirect_response(serializer, redirect_url)
            )

        # Standard API response
        if auth_kit_settings.USE_AUTH_COOKIE:
            response = self.create_response_with_cookies(serializer)
        else:
            response = Response(serializer.data, status=status.HTTP_200_OK)

        return response

    def set_custom_cookie(self, response: Response) -> None:
        """
        Set custom authentication cookies.

        Override this method to implement custom cookie setting logic.

        Args:
            response: The DRF response object
        """
