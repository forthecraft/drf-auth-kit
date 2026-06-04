"""Tests for MFA WebAuthn handler."""

import json
from unittest.mock import patch

from django.contrib.auth.hashers import make_password
from django.test import TestCase

from auth_kit.mfa.handlers.webauthn import (
    MFAWebAuthnHandler,
    WebAuthnMFASetupSerializer,
)
from auth_kit.mfa.models import MFAMethod
from auth_kit.webauthn import services as webauthn_services
from auth_kit.webauthn.models import WebAuthnCredential
from webauthn.helpers import base64url_to_bytes

from test_utils.mfa_factory import MFAMethodFactory
from test_utils.user_factory import UserFactory
from test_utils.webauthn_helpers import (
    create_authentication_response,
    create_registration_response,
)


class TestMFAWebAuthnHandler(TestCase):
    """Test cases for MFAWebAuthnHandler."""

    def setUp(self) -> None:
        """Set up test data."""
        self.user = UserFactory.create()
        self.mfa_method = MFAMethodFactory.create(
            user=self.user,
            name="webauthn",
            secret="dummy-not-used-for-webauthn",
        )
        self.handler = MFAWebAuthnHandler(self.mfa_method)

        # Register a real WebAuthn credential
        reg = create_registration_response(
            rp_id="localhost", origin="http://localhost:8000"
        )
        self.private_key = reg["private_key"]
        self.webauthn_credential = WebAuthnCredential.objects.create(
            user=self.user,
            credential_id=reg["credential_id"],
            public_key=reg["public_key"],
            sign_count=0,
            discoverable=True,
            transports=["internal"],
            name="Test Key",
        )

    def test_handler_name(self) -> None:
        """Test handler NAME is correct."""
        assert MFAWebAuthnHandler.NAME == "webauthn"

    def test_requires_dispatch_is_false(self) -> None:
        """Test REQUIRES_DISPATCH is False (no code to send)."""
        assert MFAWebAuthnHandler.REQUIRES_DISPATCH is False

    def test_send_code_is_noop(self) -> None:
        """Test send_code does nothing."""
        self.handler.send_code()  # Should not raise

    def test_get_initialize_method_serializer_class(self) -> None:
        """Test returns WebAuthnMFASetupSerializer."""
        cls = MFAWebAuthnHandler.get_initialize_method_serializer_class()
        assert cls is WebAuthnMFASetupSerializer

    @patch("auth_kit.mfa.handlers.webauthn.webauthn_services.begin_registration")
    def test_initialize_method(self, mock_begin: object) -> None:
        """Test initialize_method returns registration options."""
        mock_begin.return_value = {  # type: ignore
            "challenge": "test",
            "rp": {"id": "localhost"},
        }
        result = self.handler.initialize_method()
        assert "options" in result
        assert result["options"]["challenge"] == "test"

    def test_validate_code_with_valid_assertion(self) -> None:
        """Test validate_code with a valid WebAuthn assertion."""
        # Begin authentication to get a challenge in cache
        options = webauthn_services.begin_authentication(user=self.user)
        session_id = options["session_id"]

        # Get the challenge from cache
        challenge = base64url_to_bytes(options["challenge"])

        # Create valid assertion
        auth_response = create_authentication_response(
            private_key=self.private_key,
            credential_id=bytes(self.webauthn_credential.credential_id),
            rp_id="localhost",
            origin="http://localhost:8000",
            challenge=challenge,
            sign_count=1,
        )

        # Add session_id to the credential JSON
        credential_json = auth_response["credential"]
        credential_json["session_id"] = session_id

        result = self.handler.validate_code(json.dumps(credential_json))
        assert result is True

    def test_validate_code_with_invalid_json(self) -> None:
        """Test validate_code with invalid JSON returns False."""
        result = self.handler.validate_code("not-json")
        assert result is False

    def test_validate_code_with_invalid_assertion(self) -> None:
        """Test validate_code with invalid assertion returns False."""
        result = self.handler.validate_code(
            json.dumps({"id": "fake", "rawId": "fake", "type": "public-key"})
        )
        assert result is False

    def test_validate_code_accepts_backup_code(self) -> None:
        """
        A lost authenticator must still be recoverable.

        Setup issues backup codes for every method, WebAuthn included, so
        they have to be accepted at the second step.
        """
        method, raw_codes = MFAMethod.objects.create_with_backup_codes(
            user=UserFactory.create(),
            name="webauthn",
            secret="dummy-not-used-for-webauthn",
        )
        handler = MFAWebAuthnHandler(method)

        assert handler.validate_code(raw_codes.pop()) is True

    def test_validate_code_accepts_all_digit_backup_code(self) -> None:
        """
        Backup codes are Crockford Base32, so one can be all digits.

        json.loads parses those into an int rather than raising, which would
        otherwise fall through to the assertion branch and blow up.
        """
        method, _ = MFAMethod.objects.create_with_backup_codes(
            user=UserFactory.create(),
            name="webauthn",
            secret="dummy-not-used-for-webauthn",
        )
        method.backup_codes = {make_password("123456789012")}
        method.save()
        handler = MFAWebAuthnHandler(method)

        assert handler.validate_code("123456789012") is True
        assert handler.validate_code("999999999999") is False

    def test_validate_otp_code_delegates(self) -> None:
        """Test validate_otp_code delegates to validate_code."""
        result = self.handler.validate_otp_code("not-json")
        assert result is False

    def test_confirm_setup_rejects_malformed_json(self) -> None:
        """A non-JSON code must be rejected rather than raising."""
        assert self.handler.confirm_setup("not-json") is False

    def test_confirm_setup_rejects_unverifiable_credential(self) -> None:
        """A structurally valid but unverifiable credential returns False."""
        reg = create_registration_response(
            rp_id="localhost", origin="http://localhost:8000"
        )
        # No challenge was cached for this user, so verification must fail
        assert self.handler.confirm_setup(json.dumps(reg["credential"])) is False

    def test_confirm_setup_registers_credential(self) -> None:
        """A credential matching a cached challenge is stored."""
        options = self.handler.initialize_method()["options"]
        reg = create_registration_response(
            rp_id="localhost",
            origin="http://localhost:8000",
            challenge=base64url_to_bytes(options["challenge"]),
        )

        before = WebAuthnCredential.objects.filter(user=self.user).count()
        assert self.handler.confirm_setup(json.dumps(reg["credential"])) is True
        assert WebAuthnCredential.objects.filter(user=self.user).count() == before + 1
