"""
MFA method management ViewSet for Auth Kit.

This module provides REST API endpoints for managing user MFA methods
including creation, activation, deactivation, and deletion of MFA configurations.
"""

from typing import Any

from rest_framework import mixins, status, viewsets
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response

from drf_spectacular.utils import extend_schema

from auth_kit.mfa.handlers.base import MFAHandlerRegistry
from auth_kit.mfa.mfa_api_descriptions import (
    MFA_METHOD_CONFIRM_DESCRIPTION,
    MFA_METHOD_CREATE_DESCRIPTION,
    MFA_METHOD_DEACTIVATE_DESCRIPTION,
    MFA_METHOD_LIST_DESCRIPTION,
    MFA_METHOD_SEND_CODE_DESCRIPTION,
    get_mfa_method_delete_description,
    get_mfa_method_primary_description,
)
from auth_kit.mfa.mfa_settings import auth_kit_mfa_settings


class MFAMethodViewSet(
    mixins.CreateModelMixin,
    mixins.ListModelMixin,
    viewsets.GenericViewSet[Any],
):
    """
    ViewSet for managing user MFA methods.

    Provides endpoints for listing available methods, creating new methods,
    confirming setup, managing activation status, and method deletion.
    All operations require authentication and operate on current user's methods.

    Actions:
        - list: Get all available MFA methods with setup status
        - create: Initialize new MFA method with backup codes
        - confirm: Activate newly created method with verification
        - deactivate: Deactivate active non-primary method
        - primary: Set method as primary for user
        - send: Send verification code for testing
        - delete: Permanently remove MFA method
    """

    permission_classes = (IsAuthenticated,)
    pagination_class = None

    def get_serializer_class(self) -> type[Any]:
        """
        Get appropriate serializer class based on action.

        Returns:
            Serializer class for current action
        """
        if self.action == "create":
            return auth_kit_mfa_settings.MFA_METHOD_CREATE_SERIALIZER
        else:
            return super().get_serializer_class()

    def get_queryset(self) -> Any:
        """
        Get queryset filtered to current user's MFA methods.

        Returns:
            QuerySet of user's MFA methods
        """
        return auth_kit_mfa_settings.MFA_MODEL.objects.filter(
            user_id=str(self.request.user.pk)
        )

    @extend_schema(
        description=MFA_METHOD_CREATE_DESCRIPTION,
    )
    def create(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        """
        Create a new MFA method for the user.

        Args:
            request: HTTP request with method configuration
            *args: Variable length argument list
            **kwargs: Arbitrary keyword arguments

        Returns:
            Response with created method details and backup codes
        """
        return super().create(request, *args, **kwargs)

    @extend_schema(
        description=MFA_METHOD_LIST_DESCRIPTION,
        responses=auth_kit_mfa_settings.MFA_METHOD_CONFIG_SERIALIZER(many=True),
    )
    def list(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        """
        List all available MFA methods with user's setup status.

        Args:
            request: HTTP request
            *args: Variable length argument list
            **kwargs: Arbitrary keyword arguments

        Returns:
            Response with method configurations and status
        """
        all_methods = MFAHandlerRegistry.list_handler_names()
        user_methods = self.get_queryset().values("name", "is_primary", "is_active")
        user_methods_map = {
            m["name"]: {
                "is_primary": m["is_primary"],
                "is_active": m["is_active"],
            }
            for m in user_methods
        }

        raw_data = [
            {
                "name": m,
                "is_primary": user_methods_map.get(m, {}).get("is_primary", False),
                "is_active": user_methods_map.get(m, {}).get("is_active", False),
                "is_setup": m in user_methods_map,
            }
            for m in all_methods
        ]

        return Response(raw_data)

    @extend_schema(
        description=MFA_METHOD_CONFIRM_DESCRIPTION,
    )
    @action(
        detail=False,
        methods=["post"],
        serializer_class=auth_kit_mfa_settings.MFA_METHOD_CONFIRM_SERIALIZER,
    )
    def confirm(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        """
        Confirm and activate newly created MFA method.

        Args:
            request: HTTP request with method name and verification code
            *args: Variable length argument list
            **kwargs: Arbitrary keyword arguments

        Returns:
            Response confirming method activation
        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data)

    @extend_schema(
        description=MFA_METHOD_DEACTIVATE_DESCRIPTION,
    )
    @action(
        detail=False,
        methods=["post"],
        serializer_class=auth_kit_mfa_settings.MFA_METHOD_DEACTIVATE_SERIALIZER,
    )
    def deactivate(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        """
        Deactivate active MFA method.

        Args:
            request: HTTP request with method name and verification code
            *args: Variable length argument list
            **kwargs: Arbitrary keyword arguments

        Returns:
            Response confirming method deactivation
        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data)

    @extend_schema(
        description=get_mfa_method_primary_description(),
    )
    @action(
        detail=False,
        methods=["post"],
        serializer_class=auth_kit_mfa_settings.MFA_METHOD_PRIMARY_UPDATE_SERIALIZER,
    )
    def primary(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        """
        Set MFA method as primary for user.

        Args:
            request: HTTP request with method name and optional primary code
            *args: Variable length argument list
            **kwargs: Arbitrary keyword arguments

        Returns:
            Response confirming primary method update
        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data)

    @extend_schema(
        description=MFA_METHOD_SEND_CODE_DESCRIPTION,
    )
    @action(
        detail=False,
        methods=["post"],
        serializer_class=auth_kit_mfa_settings.MFA_METHOD_SEND_CODE_SERIALIZER,
    )
    def send(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        """
        Send verification code for MFA method.

        Args:
            request: HTTP request with method name
            *args: Variable length argument list
            **kwargs: Arbitrary keyword arguments

        Returns:
            Response confirming code was sent
        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data)

    @extend_schema(
        description=get_mfa_method_delete_description(),
    )
    @action(
        detail=False,
        methods=["post"],
        serializer_class=auth_kit_mfa_settings.MFA_METHOD_DELETE_SERIALIZER,
    )
    def delete(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        """
        Permanently delete MFA method.

        Args:
            request: HTTP request with method name and optional verification code
            *args: Variable length argument list
            **kwargs: Arbitrary keyword arguments

        Returns:
            Empty response with 204 status
        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(status=status.HTTP_204_NO_CONTENT)
