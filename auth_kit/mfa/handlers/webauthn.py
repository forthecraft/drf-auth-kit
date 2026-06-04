"""
WebAuthn MFA handler for Auth Kit.

This module provides a WebAuthn handler for multi-factor authentication
that delegates to the shared webauthn services. This is a thin wrapper
that allows WebAuthn to be used as a second factor after password login.
"""

import json
import logging
from typing import Any, TypedDict, cast

from django.utils.translation import gettext_lazy as _
from rest_framework.serializers import Serializer

from auth_kit.mfa.handlers.base import MFABaseHandler, MFAHandlerRegistry
from auth_kit.webauthn import services as webauthn_services
from auth_kit.webauthn.exceptions import WebAuthnVerificationError
from auth_kit.webauthn.serializers.options import (
    WebAuthnAuthenticationOptionsSerializer,
    WebAuthnRegistrationOptionsSerializer,
)
from auth_kit.webauthn.types import WebAuthnRegistrationOptions

logger = logging.getLogger(__name__)


class WebAuthnMFASetupData(TypedDict):
    """Setup payload returned when adding WebAuthn as an MFA method."""

    options: WebAuthnRegistrationOptions


class WebAuthnMFASetupSerializer(Serializer[WebAuthnMFASetupData]):
    """Serializer for WebAuthn MFA method setup response."""

    options = WebAuthnRegistrationOptionsSerializer(
        read_only=True,
        help_text=_("Registration options for navigator.credentials.create()"),
    )


class MFAWebAuthnHandler(MFABaseHandler):
    """
    WebAuthn handler for multi-factor authentication.

    Allows using WebAuthn credentials (passkeys and security keys) as a
    second factor during the MFA login flow. Delegates all WebAuthn
    protocol operations to the shared webauthn services module.

    The credential is stored in the WebAuthnCredential model (in the
    webauthn app), not in MFAMethod. The MFAMethod(name="webauthn")
    row is used only for MFA state tracking (is_primary, is_active).
    """

    NAME = "webauthn"
    DISPLAY_NAME = _("Security Key / Passkey")
    REQUIRES_DISPATCH = False

    def send_code(self) -> None:
        """No-op: WebAuthn does not dispatch codes."""
        pass

    def initialize_method(self) -> dict[str, Any]:
        """
        Return WebAuthn registration options for adding a credential as MFA.

        Returns:
            Dictionary with registration options JSON
        """
        data: WebAuthnMFASetupData = {
            "options": webauthn_services.begin_registration(
                user=self.mfa_method.user,
            )
        }
        return cast(dict[str, Any], data)

    @classmethod
    def get_initialize_method_serializer_class(
        cls,
    ) -> type[Serializer[Any]]:
        """
        Get serializer class for WebAuthn MFA setup responses.

        Returns:
            WebAuthnMFASetupSerializer class
        """
        return WebAuthnMFASetupSerializer

    def get_login_challenge(self) -> dict[str, Any]:
        """
        Build authentication options scoped to the MFA user's credentials.

        Returns:
            WebAuthn authentication options including the session token
        """
        options = webauthn_services.begin_authentication(user=self.mfa_method.user)
        return cast(dict[str, Any], options)

    @classmethod
    def get_login_challenge_serializer_class(
        cls,
    ) -> type[Serializer[Any]]:
        """
        Get serializer class for WebAuthn login challenge responses.

        Returns:
            WebAuthnAuthenticationOptionsSerializer class
        """
        return WebAuthnAuthenticationOptionsSerializer

    def confirm_setup(self, code: str) -> bool:
        """
        Confirm WebAuthn MFA setup by completing the registration ceremony.

        The 'code' parameter is a JSON string containing the browser's
        credential registration response from navigator.credentials.create().

        Args:
            code: JSON-stringified WebAuthn registration credential

        Returns:
            True if registration completed successfully
        """
        try:
            credential_json = json.loads(code)
        except (json.JSONDecodeError, TypeError):
            return False

        try:
            webauthn_services.complete_registration(
                user=self.mfa_method.user,
                credential_json=credential_json,
            )
            return True
        except WebAuthnVerificationError as e:
            logger.warning("WebAuthn MFA registration failed: %s", e.detail)
            return False

    def validate_code(self, code: str) -> bool:
        """
        Validate WebAuthn assertion as MFA second factor.

        The 'code' parameter is expected to be a JSON string containing the
        WebAuthn assertion response. Anything that is not a JSON object is
        treated as a backup code, so a user who loses their authenticator can
        still recover with the codes issued when the method was set up.

        Args:
            code: JSON-stringified WebAuthn assertion, or a backup code

        Returns:
            True if the assertion or backup code is valid
        """
        try:
            parsed = json.loads(code)
        except (json.JSONDecodeError, TypeError):
            return self.validate_backup_code(code)

        if not isinstance(parsed, dict):
            return self.validate_backup_code(code)

        credential_json = cast(dict[str, Any], parsed)
        session_id = str(credential_json.pop("session_id", ""))

        try:
            user, _credential = webauthn_services.complete_authentication(
                credential_json=credential_json,
                session_id=session_id,
            )
            # Verify the authenticated user matches the MFA user
            return str(user.pk) == str(self.mfa_method.user.pk)
        except WebAuthnVerificationError as e:
            logger.warning("WebAuthn MFA verification failed: %s", e.detail)
            return False

    def validate_otp_code(self, otp_code: str) -> bool:
        """
        Validate WebAuthn assertion (alias for validate_code).

        Args:
            otp_code: JSON-stringified WebAuthn assertion response

        Returns:
            True if assertion is valid
        """
        return self.validate_code(otp_code)


MFAHandlerRegistry.register(MFAWebAuthnHandler)
