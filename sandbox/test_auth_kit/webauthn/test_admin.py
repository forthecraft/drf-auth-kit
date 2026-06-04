"""Tests for the WebAuthn credential admin display helpers."""

import os

from django.contrib.admin.sites import AdminSite
from django.test import RequestFactory, TestCase

from auth_kit.webauthn.admin import WebAuthnCredentialAdmin
from auth_kit.webauthn.models import WebAuthnCredential
from webauthn.helpers import bytes_to_base64url

from test_utils.user_factory import UserFactory


class TestWebAuthnCredentialAdmin(TestCase):
    """Test cases for WebAuthnCredentialAdmin."""

    def setUp(self) -> None:
        self.admin = WebAuthnCredentialAdmin(WebAuthnCredential, AdminSite())
        self.user = UserFactory.create()

    def _credential(self, credential_id: bytes) -> WebAuthnCredential:
        return WebAuthnCredential.objects.create(
            user=self.user,
            credential_id=credential_id,
            public_key=os.urandom(77),
            sign_count=0,
            transports=["usb"],
        )

    def test_credentials_cannot_be_added_by_hand(self) -> None:
        request = RequestFactory().get("/admin/")
        assert self.admin.has_add_permission(request) is False

    def test_credential_id_short_truncates_long_ids(self) -> None:
        credential = self._credential(os.urandom(32))
        short = self.admin.credential_id_short(credential)

        assert short.endswith("...")
        assert len(short) == 16 + 3

    def test_credential_id_short_keeps_short_ids_intact(self) -> None:
        credential = self._credential(b"ab")
        expected = bytes_to_base64url(b"ab")

        assert self.admin.credential_id_short(credential) == expected

    def test_credential_id_display_shows_full_value(self) -> None:
        raw = os.urandom(32)
        credential = self._credential(raw)

        html = self.admin.credential_id_display(credential)

        assert bytes_to_base64url(raw) in html
        assert "<code" in html

    def test_public_key_display_shows_value_and_byte_count(self) -> None:
        credential = self._credential(os.urandom(32))

        html = self.admin.public_key_display(credential)

        assert bytes_to_base64url(bytes(credential.public_key)) in html
        assert "77 bytes" in html
