"""
Views for passwordless authentication login flow.

This module provides views for the two-step passwordless authentication:
request (initiate) and verify (complete).
"""

from typing import Any

from rest_framework import status
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import AllowAny
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.serializers import Serializer

from auth_kit.app_settings import auth_kit_settings
from auth_kit.passwordless.handlers.base import PasswordlessHandlerRegistry
from auth_kit.passwordless.serializers.login import (
    get_passwordless_verify_serializer,
)
from auth_kit.views import LoginView


class PasswordlessInitiateView(GenericAPIView[Any]):
    """
    Initiate passwordless authentication.

    Accepts handler-specific input (e.g., email for magic link,
    optional email for WebAuthn) and starts the passwordless flow.
    """

    permission_classes = (AllowAny,)
    authentication_classes: list[Any] = []
    throttle_scope = "auth_kit"

    def get_handler_class(self) -> Any:
        """Get the handler class from URL kwargs."""
        handler_name = self.kwargs["handler_name"]
        return PasswordlessHandlerRegistry.get_handler_class(handler_name)

    def get_serializer_class(self) -> type[Serializer[dict[str, Any]]]:
        """
        Get serializer class from handler.

        Returns:
            Combined request serializer class
        """
        handler_class = self.get_handler_class()
        return handler_class.get_initiate_serializer_class()  # type: ignore[no-any-return]

    def post(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        """
        Initiate passwordless authentication flow.

        Args:
            request: HTTP request with handler-specific data

        Returns:
            Response with handler-specific result
        """
        handler_class = self.get_handler_class()
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        result = handler_class.handle_initiate(
            serializer.validated_data,
            serializer.context,
        )

        # Read-only fields on the same serializer make up the response
        return Response(self.get_serializer(result).data, status=status.HTTP_200_OK)


class PasswordlessVerifyView(LoginView):
    """
    Verify passwordless authentication.

    Accepts handler-specific verification data and completes
    the passwordless authentication flow. Returns either login
    tokens directly or MFA first-step response depending on the
    handler's IS_MULTI_FACTOR flag and USE_MFA setting.
    """

    permission_classes = (AllowAny,)
    authentication_classes: list[Any] = []
    throttle_scope = "auth_kit"

    def get_handler_class(self) -> Any:
        """Get the handler class from URL kwargs."""
        handler_name = self.kwargs["handler_name"]
        return PasswordlessHandlerRegistry.get_handler_class(handler_name)

    def get_serializer_class(self) -> type[Serializer[dict[str, Any]]]:
        """
        Get serializer class from handler.

        Returns:
            Combined verify serializer class
        """
        handler_class = self.get_handler_class()
        return get_passwordless_verify_serializer(handler_class)

    def post(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        """
        Verify passwordless authentication and return tokens.

        Args:
            request: HTTP request with verification data

        Returns:
            Response with auth tokens or MFA first-step data
        """
        handler_class = self.get_handler_class()
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # Check if MFA interception is needed
        if not handler_class.IS_MULTI_FACTOR and auth_kit_settings.USE_MFA:
            # MFA response: return serializer data (ephemeral token + method)
            data = serializer.data
            if data.get("mfa_enabled"):
                return Response(data, status=status.HTTP_200_OK)

        return self.perform_login(serializer)
