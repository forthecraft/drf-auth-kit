"""
Views for WebAuthn credential management.

This module provides a ViewSet for authenticated users to manage
their WebAuthn credentials (register, list, rename, delete).
"""

from typing import Any, cast

from django.contrib.auth.base_user import AbstractBaseUser
from django.db.models import QuerySet
from django.utils.translation import gettext_lazy as _
from rest_framework import mixins, viewsets
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.serializers import Serializer

from drf_spectacular.utils import extend_schema, extend_schema_view

from auth_kit.webauthn import services
from auth_kit.webauthn.models import WebAuthnCredential
from auth_kit.webauthn.serializers.options import WebAuthnRegistrationOptionsSerializer
from auth_kit.webauthn.webauthn_api_descriptions import (
    WEBAUTHN_CREDENTIAL_CREATE_DESCRIPTION,
    WEBAUTHN_CREDENTIAL_DELETE_DESCRIPTION,
    WEBAUTHN_CREDENTIAL_LIST_DESCRIPTION,
    WEBAUTHN_CREDENTIAL_REGISTER_OPTIONS_DESCRIPTION,
    WEBAUTHN_CREDENTIAL_UPDATE_DESCRIPTION,
)
from auth_kit.webauthn.webauthn_settings import auth_kit_webauthn_settings


@extend_schema_view(
    list=extend_schema(description=WEBAUTHN_CREDENTIAL_LIST_DESCRIPTION),
    create=extend_schema(description=WEBAUTHN_CREDENTIAL_CREATE_DESCRIPTION),
    destroy=extend_schema(description=WEBAUTHN_CREDENTIAL_DELETE_DESCRIPTION),
)
class WebAuthnCredentialViewSet(
    mixins.CreateModelMixin,
    mixins.DestroyModelMixin,
    mixins.ListModelMixin,
    viewsets.GenericViewSet[WebAuthnCredential],
):
    """
    ViewSet for managing WebAuthn credentials.

    Provides endpoints for listing, registering, renaming,
    and deleting WebAuthn credentials for the authenticated user.
    """

    permission_classes = (IsAuthenticated,)
    pagination_class = None

    def get_serializer_class(self) -> type[Serializer[WebAuthnCredential]]:
        """
        Get serializer class based on the current action.

        Returns:
            Appropriate serializer class
        """
        if self.action == "create":
            return auth_kit_webauthn_settings.WEBAUTHN_CREDENTIAL_CREATE_SERIALIZER
        if self.action in ("partial_update", "rename"):
            return auth_kit_webauthn_settings.WEBAUTHN_CREDENTIAL_UPDATE_SERIALIZER
        return auth_kit_webauthn_settings.WEBAUTHN_CREDENTIAL_SERIALIZER

    def get_queryset(self) -> QuerySet[WebAuthnCredential]:
        """
        Get credentials for the authenticated user.

        Returns:
            QuerySet of user's WebAuthn credentials
        """
        user = cast(AbstractBaseUser, self.request.user)
        model = auth_kit_webauthn_settings.WEBAUTHN_CREDENTIAL_MODEL
        return model.objects.get_for_user(user.pk)

    @extend_schema(description=WEBAUTHN_CREDENTIAL_REGISTER_OPTIONS_DESCRIPTION)
    @action(detail=False, methods=["post"])
    def register_options(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        """
        Generate WebAuthn registration options.

        Returns the challenge and options needed by the browser's
        navigator.credentials.create() API.

        Args:
            request: HTTP request

        Returns:
            Response with registration options
        """
        options = services.begin_registration(user=cast(AbstractBaseUser, request.user))
        serializer = WebAuthnRegistrationOptionsSerializer(options)
        return Response(serializer.data)

    @extend_schema(description=WEBAUTHN_CREDENTIAL_UPDATE_DESCRIPTION)
    @action(detail=True, methods=["patch"])
    def rename(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        """
        Rename a WebAuthn credential.

        Args:
            request: HTTP request with new name

        Returns:
            Response with success message
        """
        credential = self.get_object()
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        credential.name = serializer.validated_data["name"]
        credential.save(update_fields=["name"])
        return Response({"detail": _("Credential renamed.")})
