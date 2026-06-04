"""Tests for WebAuthn passwordless login flow."""

from rest_framework import status
from rest_framework.test import APITestCase

from auth_kit.passwordless.handlers.webauthn import WebAuthnHandler
from auth_kit.webauthn.models import WebAuthnCredential
from webauthn.helpers import base64url_to_bytes

from test_utils.user_factory import UserFactory
from test_utils.webauthn_helpers import (
    create_authentication_response,
    create_registration_response,
)


class TestWebAuthnPasswordlessFlow(APITestCase):
    """Test cases for the WebAuthn passwordless flow."""

    def setUp(self) -> None:
        """Set up test data with a registered credential."""
        self.user, self.email_address = UserFactory.create_with_email_address(
            {
                "username": "testuser",
                "email": "test@example.com",
                "password": "testpass123",
            }
        )

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
            name="Test Passkey",
        )

    def test_request_authentication_options(self) -> None:
        """Test requesting WebAuthn authentication options (no mock)."""
        response = self.client.post(
            "/api/auth/passwordless/webauthn/initiate/",
            {},
            format="json",
        )
        assert response.status_code == status.HTTP_200_OK
        assert "challenge" in response.data
        assert "rpId" in response.data

    def test_request_with_email(self) -> None:
        """Test requesting options with email for non-discoverable flow."""
        response = self.client.post(
            "/api/auth/passwordless/webauthn/initiate/",
            {"email": "test@example.com"},
            format="json",
        )
        assert response.status_code == status.HTTP_200_OK
        assert "challenge" in response.data
        assert "allowCredentials" in response.data

    def test_request_with_unknown_email(self) -> None:
        """Test requesting options with non-existent email still works."""
        response = self.client.post(
            "/api/auth/passwordless/webauthn/initiate/",
            {"email": "unknown@example.com"},
            format="json",
        )
        assert response.status_code == status.HTTP_200_OK
        assert "challenge" in response.data

    def test_full_authentication_flow(self) -> None:
        """Test complete request + verify flow with real crypto."""
        request_response = self.client.post(
            "/api/auth/passwordless/webauthn/initiate/",
            {"email": "test@example.com"},
            format="json",
        )
        assert request_response.status_code == status.HTTP_200_OK

        session_id = request_response.data.get("session_id", str(self.user.pk))

        challenge = base64url_to_bytes(request_response.data["challenge"])
        auth_response = create_authentication_response(
            private_key=self.private_key,
            credential_id=bytes(self.credential.credential_id),
            rp_id="localhost",
            origin="http://localhost:8000",
            challenge=challenge,
            sign_count=1,
        )

        response = self.client.post(
            "/api/auth/passwordless/webauthn/verify/",
            {
                "credential": auth_response["credential"],
                "session_id": session_id,
            },
            format="json",
        )
        assert response.status_code == status.HTTP_200_OK
        assert "access" in response.data
        assert "user" in response.data

        self.credential.refresh_from_db()
        assert self.credential.sign_count == 1

    def test_verify_invalid_assertion(self) -> None:
        """Test verifying an invalid assertion returns error."""
        response = self.client.post(
            "/api/auth/passwordless/webauthn/verify/",
            {
                "credential": {
                    "id": "invalid",
                    "rawId": "invalid",
                    "type": "public-key",
                },
                "session_id": "invalid",
            },
            format="json",
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_handler_handle_verify(self) -> None:
        """Test handle_verify returns user from context."""
        user = WebAuthnHandler.handle_verify({}, {"user": self.user})
        assert user == self.user

    def test_deactivated_user_cannot_authenticate(self) -> None:
        """A valid passkey must not log in a disabled account."""
        request_response = self.client.post(
            "/api/auth/passwordless/webauthn/initiate/",
            {"email": "test@example.com"},
            format="json",
        )
        session_id = request_response.data["session_id"]

        auth_response = create_authentication_response(
            private_key=self.private_key,
            credential_id=bytes(self.credential.credential_id),
            rp_id="localhost",
            origin="http://localhost:8000",
            challenge=base64url_to_bytes(request_response.data["challenge"]),
            sign_count=1,
        )

        self.user.is_active = False
        self.user.save(update_fields=["is_active"])

        response = self.client.post(
            "/api/auth/passwordless/webauthn/verify/",
            {
                "credential": auth_response["credential"],
                "session_id": session_id,
            },
            format="json",
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
