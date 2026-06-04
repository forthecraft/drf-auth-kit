"""
WebAuthn serializers for passwordless authentication.

This module provides request and verify serializers for the WebAuthn
passwordless login flow (passkeys and security keys).
"""

import logging
from typing import Any

from django.contrib.auth import get_user_model
from django.utils.translation import gettext_lazy as _
from rest_framework import serializers
from rest_framework.exceptions import ValidationError

from auth_kit.webauthn import services as webauthn_services
from auth_kit.webauthn.exceptions import WebAuthnVerificationError
from auth_kit.webauthn.serializers.options import (
    WebAuthnAuthenticationOptionsSerializer,
)

UserModel = get_user_model()

logger = logging.getLogger(__name__)


class WebAuthnInitiateSerializer(WebAuthnAuthenticationOptionsSerializer):
    """
    Serializer for the WebAuthn initiate step.

    Optionally accepts an email to filter credentials for
    non-discoverable (security key) flows. If omitted,
    discoverable credential (passkey) flow is used. Inherits the
    ceremony options that make up the response.

    Attributes:
        email: Optional email to look up user credentials
    """

    email = serializers.EmailField(
        required=False,
        write_only=True,
        help_text=_(
            "Optional email for non-discoverable credential flow. "
            "Omit for passkey (discoverable) flow."
        ),
    )


class WebAuthnVerifySerializer(serializers.Serializer[dict[str, Any]]):
    """
    Serializer for verifying WebAuthn authentication assertions.

    Accepts the credential assertion response from the browser's
    navigator.credentials.get() API.

    Attributes:
        credential: The assertion response JSON from the browser
        session_id: Opaque session token from the initiate step
    """

    credential = serializers.JSONField(write_only=True)
    session_id = serializers.CharField(write_only=True)

    def validate(self, attrs: dict[str, Any]) -> dict[str, Any]:
        """
        Verify the WebAuthn assertion.

        Validates the assertion against stored credentials and
        returns the authenticated user.

        Args:
            attrs: Input attributes dictionary

        Returns:
            Validated attributes with user in context

        Raises:
            ValidationError: If assertion verification fails
        """
        try:
            user, _credential = webauthn_services.complete_authentication(
                credential_json=attrs["credential"],
                session_id=attrs["session_id"],
            )
        except WebAuthnVerificationError as e:
            # The client-facing message stays generic; the specific reason is
            # logged so operators can tell an expired challenge from an
            # unknown credential or a bad signature.
            logger.warning("WebAuthn authentication failed: %s", e.detail)
            raise ValidationError(_("WebAuthn authentication failed.")) from e

        self.context["user"] = user
        return attrs
