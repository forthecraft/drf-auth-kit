"""Tests for WebAuthn credential views."""

from rest_framework import status
from rest_framework.test import APITestCase

from auth_kit.webauthn.models import WebAuthnCredential
from webauthn.helpers import base64url_to_bytes

from test_utils.user_factory import UserFactory
from test_utils.webauthn_factory import WebAuthnCredentialFactory
from test_utils.webauthn_helpers import create_registration_response


class TestWebAuthnCredentialViewSet(APITestCase):
    """Test cases for WebAuthnCredentialViewSet."""

    def setUp(self) -> None:
        """Set up test data."""
        self.user = UserFactory.create()
        self.user.set_password("testpass123")
        self.user.save()

    def test_list_credentials_unauthenticated(self) -> None:
        """Test that unauthenticated users cannot list credentials."""
        response = self.client.get("/api/auth/webauthn/credentials/")
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_list_credentials_empty(self) -> None:
        """Test listing credentials when user has none."""
        self.client.force_authenticate(user=self.user)
        response = self.client.get("/api/auth/webauthn/credentials/")
        assert response.status_code == status.HTTP_200_OK
        assert response.data == []

    def test_list_credentials(self) -> None:
        """Test listing user's credentials."""
        self.client.force_authenticate(user=self.user)
        WebAuthnCredentialFactory.create(user=self.user, name="Key 1")
        WebAuthnCredentialFactory.create(user=self.user, name="Key 2")

        response = self.client.get("/api/auth/webauthn/credentials/")
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data) == 2

    def test_list_credentials_scoped_to_user(self) -> None:
        """Test that credentials are scoped to the authenticated user."""
        other_user = UserFactory.create()
        self.client.force_authenticate(user=self.user)
        WebAuthnCredentialFactory.create(user=self.user, name="My Key")
        WebAuthnCredentialFactory.create(user=other_user, name="Other Key")

        response = self.client.get("/api/auth/webauthn/credentials/")
        assert len(response.data) == 1
        assert response.data[0]["name"] == "My Key"

    def test_rename_credential(self) -> None:
        """Test renaming a credential."""
        self.client.force_authenticate(user=self.user)
        credential = WebAuthnCredentialFactory.create(user=self.user, name="Old Name")

        response = self.client.patch(
            f"/api/auth/webauthn/credentials/{credential.pk}/rename/",
            {"name": "New Name"},
            format="json",
        )
        assert response.status_code == status.HTTP_200_OK
        credential.refresh_from_db()
        assert credential.name == "New Name"

    def test_delete_credential(self) -> None:
        """Test deleting a credential."""
        self.client.force_authenticate(user=self.user)
        credential = WebAuthnCredentialFactory.create(user=self.user)

        response = self.client.delete(
            f"/api/auth/webauthn/credentials/{credential.pk}/"
        )
        assert response.status_code == status.HTTP_204_NO_CONTENT
        assert not WebAuthnCredential.objects.filter(pk=credential.pk).exists()

    def test_register_options(self) -> None:
        """Test generating registration options (real, no mock)."""
        self.client.force_authenticate(user=self.user)

        response = self.client.post("/api/auth/webauthn/credentials/register_options/")
        assert response.status_code == status.HTTP_200_OK
        assert "challenge" in response.data
        assert "rp" in response.data
        assert response.data["rp"]["id"] == "localhost"

    def test_register_credential_full_flow(self) -> None:
        """Test full registration flow: get options, then register credential."""
        self.client.force_authenticate(user=self.user)

        # Step 1: Get registration options
        options_response = self.client.post(
            "/api/auth/webauthn/credentials/register_options/"
        )
        assert options_response.status_code == status.HTTP_200_OK

        # Step 2: Create a valid registration response using the real challenge
        challenge_b64 = options_response.data["challenge"]
        challenge = base64url_to_bytes(challenge_b64)

        reg_data = create_registration_response(
            rp_id="localhost",
            origin="http://localhost:8000",
            challenge=challenge,
        )

        # Step 3: Submit the credential
        response = self.client.post(
            "/api/auth/webauthn/credentials/",
            {"credential": reg_data["credential"]},
            format="json",
        )
        assert response.status_code == status.HTTP_201_CREATED
        assert WebAuthnCredential.objects.filter(user=self.user).count() == 1

        # The creation response must expose the full credential, matching the
        # listing representation, so clients can act on the new credential id.
        credential = WebAuthnCredential.objects.get(user=self.user)
        assert response.data["id"] == credential.pk
        assert set(response.data) == {
            "id",
            "name",
            "discoverable",
            "transports",
            "aaguid",
            "created_at",
            "last_used_at",
        }

        listing = self.client.get("/api/auth/webauthn/credentials/")
        assert set(listing.data[0]) == set(response.data)

    def test_register_credential_expired_challenge(self) -> None:
        """Test that expired/missing challenge fails."""
        self.client.force_authenticate(user=self.user)

        # Create a registration response without getting options first
        reg_data = create_registration_response()

        response = self.client.post(
            "/api/auth/webauthn/credentials/",
            {"credential": reg_data["credential"]},
            format="json",
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
