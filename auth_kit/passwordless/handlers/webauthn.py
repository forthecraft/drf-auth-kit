"""
WebAuthn handler for passwordless authentication.

This module provides the WebAuthnHandler that enables passwordless
login via passkeys (discoverable credentials) and security keys.
"""

from typing import Any, cast

from django.contrib.auth.base_user import AbstractBaseUser
from django.utils.translation import gettext_lazy as _
from rest_framework.serializers import Serializer

from auth_kit.passwordless.handlers.base import (
    PasswordlessBaseHandler,
    PasswordlessHandlerRegistry,
)
from auth_kit.passwordless.serializers.webauthn import (
    WebAuthnInitiateSerializer,
    WebAuthnVerifySerializer,
)
from auth_kit.utils import find_user_by_email
from auth_kit.webauthn import services as webauthn_services


class WebAuthnHandler(PasswordlessBaseHandler):
    """
    Passwordless authentication via WebAuthn (passkeys and security keys).

    Supports two flows:
    - Passkey (discoverable): No email needed, browser prompts for credential
    - Security key (non-discoverable): Email provided to filter allowed credentials

    Since WebAuthn inherently provides multi-factor assurance (something you
    have + something you are/know), MFA is skipped after successful verification.
    """

    NAME = "webauthn"
    DISPLAY_NAME = _("Passkey / Security Key")
    IS_MULTI_FACTOR = True

    @classmethod
    def get_initiate_serializer_class(cls) -> type[Serializer[Any]]:
        """Get serializer for the WebAuthn initiate step."""
        return WebAuthnInitiateSerializer

    @classmethod
    def get_verify_serializer_class(cls) -> type[Serializer[Any]]:
        """Get serializer for the WebAuthn verify step."""
        return WebAuthnVerifySerializer

    @classmethod
    def handle_initiate(
        cls, validated_data: dict[str, Any], context: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Generate WebAuthn authentication options.

        If email is provided, looks up the user and filters
        allowed credentials. Otherwise, uses discoverable
        credential flow.

        Args:
            validated_data: May contain 'email' field
            context: Serializer context

        Returns:
            Authentication options dictionary with challenge
        """
        email = validated_data.get("email")
        user: AbstractBaseUser | None = find_user_by_email(email) if email else None

        options = webauthn_services.begin_authentication(user=user)
        return cast(dict[str, Any], options)

    @classmethod
    def handle_verify(
        cls, validated_data: dict[str, Any], context: dict[str, Any]
    ) -> AbstractBaseUser:
        """
        Verify WebAuthn assertion.

        The actual assertion verification is done in the serializer's
        validate() method, which sets context['user'].

        Args:
            validated_data: Validated data from serializer
            context: Serializer context with 'user' key

        Returns:
            Authenticated user instance
        """
        return context["user"]  # type: ignore[no-any-return]


PasswordlessHandlerRegistry.register(WebAuthnHandler)
