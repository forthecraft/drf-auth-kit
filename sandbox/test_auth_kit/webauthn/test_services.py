"""Tests for WebAuthn service layer error paths."""

import os

from django.core.cache import cache
from django.test import TestCase

import pytest
from auth_kit.test_utils import settings_context
from auth_kit.webauthn import services
from auth_kit.webauthn.exceptions import WebAuthnVerificationError
from auth_kit.webauthn.models import WebAuthnCredential
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.structs import (
    AuthenticatorAttachment,
    AuthenticatorTransport,
)

from test_utils.user_factory import UserFactory
from test_utils.webauthn_helpers import (
    create_authentication_response,
    create_registration_response,
    generate_ec2_key_pair,
)


class TestBeginRegistration(TestCase):
    """Test begin_registration service function."""

    def setUp(self) -> None:
        self.user = UserFactory.create()

    def test_begin_registration_auto_fetches_credentials(self) -> None:
        """Test that existing_credentials=None fetches from DB."""
        # Create an existing credential
        WebAuthnCredential.objects.create(
            user=self.user,
            credential_id=os.urandom(32),
            public_key=os.urandom(77),
            sign_count=0,
            transports=["internal"],
        )

        # Call without passing existing_credentials (line 109-110)
        options = services.begin_registration(self.user)
        assert "challenge" in options
        assert "excludeCredentials" in options
        assert len(options["excludeCredentials"]) == 1

    def test_begin_registration_with_explicit_credentials(self) -> None:
        """Test passing existing_credentials explicitly (covers else branch line 109)."""
        options = services.begin_registration(self.user, existing_credentials=[])
        assert "challenge" in options
        assert options.get("excludeCredentials", []) == []

    def test_begin_registration_ignores_unknown_stored_transport(self) -> None:
        """An unrecognised stored transport must not break the ceremony."""
        WebAuthnCredential.objects.create(
            user=self.user,
            credential_id=os.urandom(32),
            public_key=os.urandom(77),
            sign_count=0,
            transports=["usb", "not-a-real-transport"],
        )

        options = services.begin_registration(self.user)
        exclude_credentials = options.get("excludeCredentials", [])
        assert exclude_credentials[0].get("transports") == ["usb"]


class TestCompleteRegistration(TestCase):
    """Test complete_registration error paths."""

    def setUp(self) -> None:
        self.user = UserFactory.create()

    def test_explicit_name_skips_auto_generation(self) -> None:
        """A caller-supplied name must be kept as-is."""
        options = services.begin_registration(self.user)
        reg = create_registration_response(
            rp_id="localhost",
            origin="http://localhost:8000",
            challenge=base64url_to_bytes(options["challenge"]),
        )

        credential = services.complete_registration(
            user=self.user,
            credential_json=reg["credential"],
            name="My Own Name",
        )

        assert credential.name == "My Own Name"

    def test_complete_registration_expired_challenge(self) -> None:
        """Test error when challenge is expired/missing (line 168-169)."""
        with pytest.raises(WebAuthnVerificationError, match="expired"):
            services.complete_registration(
                user=self.user,
                credential_json={"id": "test", "rawId": "test", "type": "public-key"},
            )

    def test_complete_registration_invalid_credential(self) -> None:
        """Test error when credential verification fails (lines 178-179)."""
        # Put a real challenge in cache
        services.begin_registration(self.user)

        # Submit garbage credential data — verification will fail
        with pytest.raises(WebAuthnVerificationError):
            services.complete_registration(
                user=self.user,
                credential_json={
                    "id": "bad",
                    "rawId": "bad",
                    "type": "public-key",
                    "response": {
                        "clientDataJSON": "bad",
                        "attestationObject": "bad",
                    },
                },
            )

        # Verify challenge was cleaned up from cache
        cache_key = f"webauthn:reg:{self.user.pk}"
        assert cache.get(cache_key) is None


class TestCompleteAuthentication(TestCase):
    """Test complete_authentication error paths."""

    def setUp(self) -> None:
        self.user = UserFactory.create()
        reg = create_registration_response(
            rp_id="localhost", origin="http://localhost:8000"
        )
        self.private_key = reg["private_key"]
        self.credential = WebAuthnCredential.objects.create(
            user=self.user,
            credential_id=reg["credential_id"],
            public_key=reg["public_key"],
            sign_count=0,
            discoverable=True,
            transports=["internal"],
        )

    def test_expired_challenge(self) -> None:
        """Test error when authentication challenge is expired."""
        with pytest.raises(WebAuthnVerificationError, match="expired"):
            services.complete_authentication(
                credential_json={"rawId": "test"},
                session_id="nonexistent",
            )

    def test_credential_not_found(self) -> None:
        """Test error when credential ID doesn't match any stored credential (lines 289-291)."""
        # Put a challenge in cache
        options = services.begin_authentication(user=self.user)
        session_id = options["session_id"]

        # Submit with a rawId that doesn't match any credential
        fake_raw_id = bytes_to_base64url(os.urandom(32))
        with pytest.raises(WebAuthnVerificationError, match="not found"):
            services.complete_authentication(
                credential_json={"rawId": fake_raw_id},
                session_id=session_id,
            )

    def test_non_string_raw_id(self) -> None:
        """Test handling of non-string rawId (line 283)."""
        # Put a challenge in cache
        options = services.begin_authentication(user=self.user)
        session_id = options["session_id"]

        # Submit with bytes-like rawId (not a string)
        # This will fail at credential lookup since random bytes won't match
        with pytest.raises(WebAuthnVerificationError):
            services.complete_authentication(
                credential_json={"rawId": list(os.urandom(32))},
                session_id=session_id,
            )

    def test_invalid_assertion_signature(self) -> None:
        """Test error when assertion signature is invalid (lines 302-303)."""
        # Get real challenge
        options = services.begin_authentication(user=self.user)
        session_id = options["session_id"]

        challenge = base64url_to_bytes(options["challenge"])

        # Create assertion with WRONG private key (different key pair)
        wrong_private_key, _ = generate_ec2_key_pair()
        auth_response = create_authentication_response(
            private_key=wrong_private_key,  # Wrong key!
            credential_id=bytes(self.credential.credential_id),
            rp_id="localhost",
            origin="http://localhost:8000",
            challenge=challenge,
            sign_count=1,
        )

        with pytest.raises(WebAuthnVerificationError):
            services.complete_authentication(
                credential_json=auth_response["credential"],
                session_id=session_id,
            )


class TestUserVerificationEnforcement(TestCase):
    """
    WEBAUTHN_USER_VERIFICATION must be enforced at verification time.

    The ceremony options only express a preference -- an authenticator is free
    to return UV=0 anyway. Since the passwordless WebAuthn handler declares
    IS_MULTI_FACTOR and skips MFA, an unverified assertion would otherwise
    grant a session on a single factor.
    """

    NO_UV_REGISTRATION_FLAGS = 0x41  # UP + AT, UV cleared
    NO_UV_ASSERTION_FLAGS = 0x01  # UP only, UV cleared

    def setUp(self) -> None:
        self.user = UserFactory.create()

    def _register(self, flags: int) -> None:
        options = services.begin_registration(self.user)
        reg = create_registration_response(
            rp_id="localhost",
            origin="http://localhost:8000",
            challenge=base64url_to_bytes(options["challenge"]),
            flags=flags,
        )
        services.complete_registration(self.user, reg["credential"])

    def _authenticate(self, flags: int) -> None:
        reg = create_registration_response(
            rp_id="localhost", origin="http://localhost:8000"
        )
        credential = WebAuthnCredential.objects.create(
            user=self.user,
            credential_id=reg["credential_id"],
            public_key=reg["public_key"],
            sign_count=0,
            transports=["internal"],
        )
        options = services.begin_authentication(user=self.user)
        auth_response = create_authentication_response(
            private_key=reg["private_key"],
            credential_id=bytes(credential.credential_id),
            rp_id="localhost",
            origin="http://localhost:8000",
            challenge=base64url_to_bytes(options["challenge"]),
            sign_count=1,
            flags=flags,
        )
        services.complete_authentication(
            credential_json=auth_response["credential"],
            session_id=options["session_id"],
        )

    def test_registration_rejects_unverified_user_when_required(self) -> None:
        with settings_context(WEBAUTHN_USER_VERIFICATION="required"):
            with pytest.raises(WebAuthnVerificationError):
                self._register(self.NO_UV_REGISTRATION_FLAGS)

    def test_registration_allows_unverified_user_when_preferred(self) -> None:
        with settings_context(WEBAUTHN_USER_VERIFICATION="preferred"):
            self._register(self.NO_UV_REGISTRATION_FLAGS)

        assert WebAuthnCredential.objects.filter(user=self.user).count() == 1

    def test_authentication_rejects_unverified_user_when_required(self) -> None:
        with settings_context(WEBAUTHN_USER_VERIFICATION="required"):
            with pytest.raises(WebAuthnVerificationError):
                self._authenticate(self.NO_UV_ASSERTION_FLAGS)

    def test_authentication_allows_unverified_user_when_preferred(self) -> None:
        with settings_context(WEBAUTHN_USER_VERIFICATION="preferred"):
            self._authenticate(self.NO_UV_ASSERTION_FLAGS)

    def test_authentication_accepts_verified_user_when_required(self) -> None:
        with settings_context(WEBAUTHN_USER_VERIFICATION="required"):
            self._authenticate(0x05)  # UP + UV


class TestGenerateCredentialName(TestCase):
    """Test default credential naming from authenticator metadata."""

    def test_known_aaguid_wins_over_transport(self) -> None:
        name = services._generate_credential_name(
            AuthenticatorAttachment.CROSS_PLATFORM,
            [AuthenticatorTransport.USB],
            "fbfc3007-154e-4ecc-8c0b-6e020557d7bd",
        )
        assert name == "iCloud Keychain"

    def test_platform_attachment_is_a_passkey(self) -> None:
        name = services._generate_credential_name(
            AuthenticatorAttachment.PLATFORM, [], ""
        )
        assert name == "Passkey"

    def test_transport_names(self) -> None:
        cases = {
            AuthenticatorTransport.USB: "USB Security Key",
            AuthenticatorTransport.NFC: "NFC Security Key",
            AuthenticatorTransport.BLE: "Bluetooth Security Key",
        }
        for transport, expected in cases.items():
            name = services._generate_credential_name(
                AuthenticatorAttachment.CROSS_PLATFORM, [transport], ""
            )
            assert name == expected

    def test_cross_platform_without_transports(self) -> None:
        name = services._generate_credential_name(
            AuthenticatorAttachment.CROSS_PLATFORM, [], ""
        )
        assert name == "Security Key"

    def test_unknown_attachment_defaults_to_passkey(self) -> None:
        assert services._generate_credential_name(None, [], "") == "Passkey"
        assert (
            services._generate_credential_name(
                None, [AuthenticatorTransport.INTERNAL], "unknown-aaguid"
            )
            == "Passkey"
        )
