"""Tests for WebAuthn credential models."""

import os

from django.db import IntegrityError
from django.test import TestCase

import pytest
from auth_kit.webauthn.exceptions import WebAuthnCredentialDoesNotExistError
from auth_kit.webauthn.models import WebAuthnCredential

from test_utils.user_factory import UserFactory
from test_utils.webauthn_factory import WebAuthnCredentialFactory


class TestWebAuthnCredentialModel(TestCase):
    """Test cases for WebAuthnCredential model."""

    def setUp(self) -> None:
        """Set up test data."""
        self.user = UserFactory.create()

    def test_create_credential(self) -> None:
        """Test creating a WebAuthn credential."""
        credential = WebAuthnCredentialFactory.create(user=self.user)
        assert credential.pk is not None
        assert credential.user == self.user
        assert credential.sign_count == 0
        assert credential.discoverable is True

    def test_credential_str(self) -> None:
        """Test string representation with name."""
        credential = WebAuthnCredentialFactory.create(user=self.user, name="My YubiKey")
        assert "My YubiKey" in str(credential)

    def test_credential_str_no_name(self) -> None:
        """Test string representation without name."""
        credential = WebAuthnCredentialFactory.create(user=self.user, name="")
        assert "Credential" in str(credential)

    def test_unique_credential_id(self) -> None:
        """Test that credential_id must be unique."""
        cred_id = os.urandom(32)
        WebAuthnCredentialFactory.create(user=self.user, credential_id=cred_id)
        with pytest.raises(IntegrityError):
            WebAuthnCredentialFactory.create(user=self.user, credential_id=cred_id)

    def test_ordering(self) -> None:
        """Test default ordering by -created_at."""
        cred1 = WebAuthnCredentialFactory.create(user=self.user)
        cred2 = WebAuthnCredentialFactory.create(user=self.user)
        credentials = list(WebAuthnCredential.objects.all())
        assert credentials[0] == cred2
        assert credentials[1] == cred1


class TestWebAuthnCredentialManager(TestCase):
    """Test cases for WebAuthnCredentialManager."""

    def setUp(self) -> None:
        """Set up test data."""
        self.user = UserFactory.create()
        self.other_user = UserFactory.create()

    def test_get_by_credential_id(self) -> None:
        """Test retrieving credential by credential ID."""
        cred_id = os.urandom(32)
        credential = WebAuthnCredentialFactory.create(
            user=self.user, credential_id=cred_id
        )
        found = WebAuthnCredential.objects.get_by_credential_id(cred_id)
        assert found == credential

    def test_get_by_credential_id_not_found(self) -> None:
        """Test error when credential ID doesn't exist."""
        with pytest.raises(WebAuthnCredentialDoesNotExistError):
            WebAuthnCredential.objects.get_by_credential_id(os.urandom(32))

    def test_get_for_user(self) -> None:
        """Test retrieving all credentials for a user."""
        WebAuthnCredentialFactory.create(user=self.user)
        WebAuthnCredentialFactory.create(user=self.user)
        WebAuthnCredentialFactory.create(user=self.other_user)

        user_creds = WebAuthnCredential.objects.get_for_user(self.user.pk)
        assert user_creds.count() == 2

    def test_get_discoverable_for_user(self) -> None:
        """Test retrieving only discoverable credentials."""
        WebAuthnCredentialFactory.create(user=self.user, discoverable=True)
        WebAuthnCredentialFactory.create(user=self.user, discoverable=False)

        discoverable = WebAuthnCredential.objects.get_discoverable_for_user(
            self.user.pk
        )
        assert discoverable.count() == 1
