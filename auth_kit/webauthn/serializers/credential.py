"""
Serializers for WebAuthn credential management operations.

This module provides serializers for listing, creating, updating,
and managing WebAuthn credentials for authenticated users.
"""

from typing import Any, cast

from django.contrib.auth.base_user import AbstractBaseUser
from django.utils.translation import gettext_lazy as _
from rest_framework import serializers
from rest_framework.request import Request

from webauthn.helpers.structs import AuthenticatorTransport

from auth_kit.webauthn import services
from auth_kit.webauthn.models import WebAuthnCredential


class WebAuthnCredentialSerializer(serializers.Serializer[WebAuthnCredential]):
    """
    Read serializer for WebAuthn credential listing.

    Displays credential metadata without exposing sensitive
    cryptographic material.
    """

    id = serializers.IntegerField(read_only=True)
    name = serializers.CharField(read_only=True)
    discoverable = serializers.BooleanField(read_only=True)
    transports = serializers.ListField(
        child=serializers.ChoiceField(
            choices=[e.value for e in AuthenticatorTransport]
        ),
        read_only=True,
    )
    aaguid = serializers.CharField(read_only=True)
    created_at = serializers.DateTimeField(read_only=True)
    last_used_at = serializers.DateTimeField(read_only=True)


class WebAuthnCredentialCreateSerializer(WebAuthnCredentialSerializer):
    """
    Serializer for registering a new WebAuthn credential.

    Accepts the credential response from navigator.credentials.create()
    and verifies it against the stored challenge. Inherits the read
    fields so the creation response matches the listing representation.

    Attributes:
        credential: The credential response JSON from the browser
        name: Optional user-friendly name for the credential
    """

    credential = serializers.JSONField(write_only=True)
    name = serializers.CharField(
        max_length=255,
        required=False,
        allow_blank=True,
        allow_null=True,
        default=None,
        help_text=_("Optional user-friendly name for this credential"),
    )

    def create(self, validated_data: dict[str, Any]) -> WebAuthnCredential:
        """
        Verify and store the WebAuthn credential.

        Args:
            validated_data: Validated input data

        Returns:
            The created credential
        """
        request = cast(Request, self.context.get("request"))
        return services.complete_registration(
            user=cast(AbstractBaseUser, request.user),
            credential_json=validated_data["credential"],
            name=validated_data.get("name") or "",
        )


class WebAuthnCredentialUpdateSerializer(serializers.Serializer[WebAuthnCredential]):
    """
    Serializer for updating a WebAuthn credential.

    Only allows updating the user-friendly name.
    """

    name = serializers.CharField(
        max_length=255,
        help_text=_("User-friendly name for this credential"),
    )
