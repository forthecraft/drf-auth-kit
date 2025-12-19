"""
MFA-enabled login views for Auth Kit.

This module provides multi-step authentication views including first step
credential validation, second step MFA verification, method switching,
and code resending functionality.
"""

from typing import Any

from rest_framework import status
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import AllowAny
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.serializers import Serializer

from drf_spectacular.utils import (
    PolymorphicProxySerializer,
    extend_schema,
)

from auth_kit.mfa.mfa_api_descriptions import (
    get_mfa_login_change_method_description,
    get_mfa_login_first_step_description,
    get_mfa_login_resend_description,
    get_mfa_login_second_step_description,
)
from auth_kit.mfa.mfa_settings import auth_kit_mfa_settings
from auth_kit.mfa.utils import get_mfa_login_first_step_response_schemas
from auth_kit.views import LoginView


class LoginFirstStepView(LoginView):
    """
    First step of MFA-enabled authentication.

    Validates user credentials and initiates MFA flow if enabled.
    Returns either ephemeral token for MFA verification or complete
    authentication tokens if MFA is disabled for the user.
    """

    permission_classes = (AllowAny,)
    authentication_classes = []
    throttle_scope = "auth_kit"

    def get_serializer_class(self) -> type[Serializer[dict[str, Any]]]:
        """
        Get first step serializer class.

        Returns:
            Combined serializer for credential validation and MFA initiation
        """
        return auth_kit_mfa_settings.MFA_FIRST_STEP_SERIALIZER_FACTORY()

    @extend_schema(
        description=get_mfa_login_first_step_description(),
        responses=PolymorphicProxySerializer(
            component_name="FirstStepResponse",
            serializers=get_mfa_login_first_step_response_schemas,
            resource_type_field_name=None,
        ),
    )
    def post(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        """
        Process first step authentication.

        Args:
            request: HTTP request with credentials
            *args: Variable length argument list
            **kwargs: Arbitrary keyword arguments

        Returns:
            Response with ephemeral token or complete authentication
        """
        self.request = request
        serializer = self.get_serializer(data=self.request.data)
        serializer.is_valid(raise_exception=True)

        data = serializer.data

        if data.get("mfa_enabled"):
            return Response(data, status=status.HTTP_200_OK)

        return self.perform_login(serializer)


class LoginSecondStepView(LoginView):
    """
    Second step of MFA authentication.

    Verifies MFA code and ephemeral token to complete authentication.
    Returns full authentication tokens upon successful verification.
    """

    permission_classes = (AllowAny,)
    authentication_classes = []
    throttle_scope = "auth_kit"

    def get_serializer_class(self) -> type[Serializer[dict[str, Any]]]:
        """
        Get second step serializer class.

        Returns:
            Combined serializer for MFA verification and token generation
        """
        return auth_kit_mfa_settings.MFA_SECOND_STEP_SERIALIZER_FACTORY()

    @extend_schema(
        description=get_mfa_login_second_step_description(),
    )
    def post(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        """
        Process second step MFA verification.

        Args:
            request: HTTP request with ephemeral token and verification code
            *args: Variable length argument list
            **kwargs: Arbitrary keyword arguments

        Returns:
            Response with authentication tokens
        """
        return super().post(request, *args, **kwargs)


class LoginChangeMethodView(GenericAPIView[Any]):
    """
    Change MFA method during authentication flow.

    Allows users to switch to a different MFA method during login
    using their ephemeral token from first step authentication.
    """

    permission_classes = (AllowAny,)
    authentication_classes = []
    throttle_scope = "auth_kit"
    serializer_class = auth_kit_mfa_settings.MFA_CHANGE_METHOD_SERIALIZER

    @extend_schema(
        description=get_mfa_login_change_method_description(),
    )
    def post(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        """
        Switch to different MFA method.

        Args:
            request: HTTP request with ephemeral token and new method
            *args: Variable length argument list
            **kwargs: Arbitrary keyword arguments

        Returns:
            Response with new ephemeral token for selected method
        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data)


class LoginMFAResendView(GenericAPIView[Any]):
    """
    Resend MFA verification code during authentication.

    Allows users to request a new verification code for methods
    that support code dispatch (e.g., email) using their ephemeral token.
    """

    permission_classes = (AllowAny,)
    authentication_classes = []
    throttle_scope = "auth_kit"
    serializer_class = auth_kit_mfa_settings.MFA_RESEND_SERIALIZER

    @extend_schema(
        description=get_mfa_login_resend_description(),
    )
    def post(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        """
        Resend verification code.

        Args:
            request: HTTP request with ephemeral token
            *args: Variable length argument list
            **kwargs: Arbitrary keyword arguments

        Returns:
            Response with new ephemeral token
        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data)
