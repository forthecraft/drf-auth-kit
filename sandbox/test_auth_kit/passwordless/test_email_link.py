"""Tests for email magic link passwordless login flow."""

import re

from django.contrib.auth import get_user_model
from django.contrib.auth.models import User
from django.core import mail
from django.core.cache import cache
from rest_framework import status
from rest_framework.test import APITestCase

from allauth.account.models import (  # pyright: ignore[reportMissingTypeStubs]
    EmailAddress,
)
from auth_kit.mfa.models import MFAMethod
from auth_kit.passwordless.handlers.email_link import EmailLinkHandler
from auth_kit.passwordless.serializers.email_link import (
    EmailLinkVerifySerializer,
)
from auth_kit.passwordless.services.token import passwordless_token_service
from auth_kit.test_utils import override_auth_kit_settings

from test_utils.user_factory import UserFactory

UserModel: type[User] = get_user_model()  # pyright: ignore[reportAssignmentType]


class TestEmailLinkPasswordlessFlow(APITestCase):
    """Test cases for the email magic link passwordless flow."""

    def setUp(self) -> None:
        """Set up test data."""
        self.user, self.email_address = UserFactory.create_with_email_address(
            {
                "username": "testuser",
                "email": "test@example.com",
                "password": "testpass123",
            }
        )

    def test_request_magic_link(self) -> None:
        """Test requesting a magic link sends an email."""
        response = self.client.post(
            "/api/auth/passwordless/email/initiate/",
            {"email": "test@example.com"},
            format="json",
        )
        assert response.status_code == status.HTTP_200_OK
        assert "detail" in response.data
        assert len(mail.outbox) == 1
        assert mail.outbox[0].to == ["test@example.com"]

    def test_request_magic_link_unknown_email(self) -> None:
        """Test requesting magic link for unknown email doesn't reveal it."""
        response = self.client.post(
            "/api/auth/passwordless/email/initiate/",
            {"email": "unknown@example.com"},
            format="json",
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(mail.outbox) == 0

    def test_verify_valid_token(self) -> None:
        """Test verifying a valid magic link token returns auth tokens."""
        token = passwordless_token_service.make_token(self.user)

        response = self.client.post(
            "/api/auth/passwordless/email/verify/",
            {"token": token},
            format="json",
        )
        assert response.status_code == status.HTTP_200_OK
        assert "access" in response.data
        assert "refresh" in response.data
        assert "user" in response.data

    def test_verify_invalid_token(self) -> None:
        """Test verifying an invalid token returns error."""
        response = self.client.post(
            "/api/auth/passwordless/email/verify/",
            {"token": "invalid-token"},
            format="json",
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_full_flow(self) -> None:
        """Test the complete request + verify flow."""
        self.client.post(
            "/api/auth/passwordless/email/initiate/",
            {"email": "test@example.com"},
            format="json",
        )
        assert len(mail.outbox) == 1

        token = passwordless_token_service.make_token(self.user)

        response = self.client.post(
            "/api/auth/passwordless/email/verify/",
            {"token": token},
            format="json",
        )
        assert response.status_code == status.HTTP_200_OK
        assert "access" in response.data

    @override_auth_kit_settings(
        PASSWORDLESS_MAGIC_LINK_URL="https://app.example.com/auth/verify"
    )
    def test_request_magic_link_with_url(self) -> None:
        """Test that magic link URL is included in email when configured."""
        response = self.client.post(
            "/api/auth/passwordless/email/initiate/",
            {"email": "test@example.com"},
            format="json",
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(mail.outbox) == 1
        body = mail.outbox[0].body
        assert "https://app.example.com/auth/verify?token=" in body

    def test_handler_handle_verify(self) -> None:
        """Test handle_verify returns user from context."""
        user = EmailLinkHandler.handle_verify({}, {"user": self.user})
        assert user == self.user

    def test_verify_with_mfa_enabled(self) -> None:
        """Test email verify with MFA enabled returns MFA response."""
        MFAMethod.objects.create(
            user=self.user,
            name="app",
            secret="JBSWY3DPEHPK3PXP",
            is_active=True,
            is_primary=True,
        )

        token = passwordless_token_service.make_token(self.user)

        response = self.client.post(
            "/api/auth/passwordless/email/verify/",
            {"token": token},
            format="json",
        )
        assert response.status_code == status.HTTP_200_OK
        assert "ephemeral_token" in response.data
        assert response.data["mfa_enabled"] is True

    def test_token_single_use(self) -> None:
        """Test that a magic link token cannot be reused."""
        token = passwordless_token_service.make_token(self.user)

        # First use should succeed
        response1 = self.client.post(
            "/api/auth/passwordless/email/verify/",
            {"token": token},
            format="json",
        )
        assert response1.status_code == status.HTTP_200_OK

        # Second use of same token should fail
        response2 = self.client.post(
            "/api/auth/passwordless/email/verify/",
            {"token": token},
            format="json",
        )
        assert response2.status_code == status.HTTP_400_BAD_REQUEST

    def test_signup_disabled_does_not_create_account(self) -> None:
        """By default an unknown email must not create anything or send mail."""
        mail.outbox = []
        before = UserModel.objects.count()

        response = self.client.post(
            "/api/auth/passwordless/email/initiate/",
            {"email": "nobody@example.com"},
            format="json",
        )

        assert response.status_code == status.HTTP_200_OK
        assert len(mail.outbox) == 0
        assert UserModel.objects.count() == before

    @override_auth_kit_settings(PASSWORDLESS_EMAIL_SIGNUP=True)
    def test_signup_creates_account_only_after_link_is_clicked(self) -> None:
        """The request step must never write a user row."""
        mail.outbox = []
        before = UserModel.objects.count()

        response = self.client.post(
            "/api/auth/passwordless/email/initiate/",
            {"email": "brand-new@example.com"},
            format="json",
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(mail.outbox) == 1
        assert UserModel.objects.count() == before

        token = re.search(r"[A-Za-z0-9_\-]{20,}", str(mail.outbox[0].body))
        assert token
        verify = self.client.post(
            "/api/auth/passwordless/email/verify/",
            {"token": token.group(0)},
            format="json",
        )

        assert verify.status_code == status.HTTP_200_OK
        assert UserModel.objects.count() == before + 1

        user = UserModel.objects.get(email="brand-new@example.com")
        assert not user.has_usable_password()
        assert EmailAddress.objects.get(user=user, email=user.email).verified

    @override_auth_kit_settings(PASSWORDLESS_EMAIL_SIGNUP=True)
    def test_differently_cased_address_reuses_the_existing_account(self) -> None:
        """
        Django only lowercases the domain half of an address, so a user
        stored as "Mixed@Example.com" must still be matched by a request for
        "mixed@example.com" rather than signed up a second time.
        """
        existing = UserFactory.create(username="mixedcase", email="Mixed@Example.com")
        mail.outbox = []
        before = UserModel.objects.count()

        self.client.post(
            "/api/auth/passwordless/email/initiate/",
            {"email": "mixed@example.com"},
            format="json",
        )
        token = re.search(r"[A-Za-z0-9_\-]{20,}", str(mail.outbox[0].body))
        assert token
        verify = self.client.post(
            "/api/auth/passwordless/email/verify/",
            {"token": token.group(0)},
            format="json",
        )

        assert verify.status_code == status.HTTP_200_OK
        assert UserModel.objects.count() == before
        assert verify.data["user"]["username"] == existing.username

    @override_auth_kit_settings(PASSWORDLESS_EMAIL_SIGNUP=True)
    def test_signup_token_is_single_use(self) -> None:
        mail.outbox = []
        self.client.post(
            "/api/auth/passwordless/email/initiate/",
            {"email": "once-only@example.com"},
            format="json",
        )
        match = re.search(r"[A-Za-z0-9_\-]{20,}", str(mail.outbox[0].body))
        assert match
        token = match.group(0)

        first = self.client.post(
            "/api/auth/passwordless/email/verify/", {"token": token}, format="json"
        )
        second = self.client.post(
            "/api/auth/passwordless/email/verify/", {"token": token}, format="json"
        )

        assert first.status_code == status.HTTP_200_OK
        assert second.status_code == status.HTTP_400_BAD_REQUEST
        assert UserModel.objects.filter(email="once-only@example.com").count() == 1

    @override_auth_kit_settings(PASSWORDLESS_EMAIL_SIGNUP=True)
    def test_signup_token_reuses_account_created_concurrently(self) -> None:
        """If the account appeared between request and click, reuse it."""
        mail.outbox = []
        self.client.post(
            "/api/auth/passwordless/email/initiate/",
            {"email": "raced@example.com"},
            format="json",
        )
        match = re.search(r"[A-Za-z0-9_\-]{20,}", str(mail.outbox[0].body))
        assert match

        # Simulate another path creating the account first
        raced = UserModel.objects.create(username="raced", email="raced@example.com")

        response = self.client.post(
            "/api/auth/passwordless/email/verify/",
            {"token": match.group(0)},
            format="json",
        )

        assert response.status_code == status.HTTP_200_OK
        assert UserModel.objects.filter(email="raced@example.com").count() == 1
        assert UserModel.objects.get(email="raced@example.com").pk == raced.pk

    def test_auto_verify_email_is_a_noop_without_an_address(self) -> None:
        """A user model with no email must not break verification."""
        user = UserModel.objects.create(username="no-email", email="")

        EmailLinkVerifySerializer._auto_verify_email(user)

        assert not EmailAddress.objects.filter(user=user).exists()

    def test_magic_link_is_single_use_without_the_cache(self) -> None:
        """Single-use must not depend on shared cache state alone."""
        mail.outbox = []
        self.client.post(
            "/api/auth/passwordless/email/initiate/",
            {"email": "test@example.com"},
            format="json",
        )
        match = re.search(r"[A-Za-z0-9_\-]{20,}", str(mail.outbox[0].body))
        assert match
        token = match.group(0)

        first = self.client.post(
            "/api/auth/passwordless/email/verify/", {"token": token}, format="json"
        )
        assert first.status_code == status.HTTP_200_OK

        # A different worker, an eviction, or a restart loses the used-marker
        cache.clear()

        replay = self.client.post(
            "/api/auth/passwordless/email/verify/", {"token": token}, format="json"
        )
        assert replay.status_code == status.HTTP_400_BAD_REQUEST

    def test_verify_records_last_login(self) -> None:
        mail.outbox = []
        assert self.user.last_login is None

        self.client.post(
            "/api/auth/passwordless/email/initiate/",
            {"email": "test@example.com"},
            format="json",
        )
        match = re.search(r"[A-Za-z0-9_\-]{20,}", str(mail.outbox[0].body))
        assert match
        self.client.post(
            "/api/auth/passwordless/email/verify/",
            {"token": match.group(0)},
            format="json",
        )

        self.user.refresh_from_db()
        assert self.user.last_login is not None

    def test_initiate_message_is_identical_for_unknown_addresses(self) -> None:
        """The response must not reveal whether an account exists."""
        known = self.client.post(
            "/api/auth/passwordless/email/initiate/",
            {"email": "test@example.com"},
            format="json",
        )
        unknown = self.client.post(
            "/api/auth/passwordless/email/initiate/",
            {"email": "nobody-at-all@example.com"},
            format="json",
        )

        assert known.data == unknown.data

    def test_deactivated_user_cannot_use_a_magic_link(self) -> None:
        """Passwordless bypasses authenticate(), so it must check is_active itself."""
        mail.outbox = []
        self.client.post(
            "/api/auth/passwordless/email/initiate/",
            {"email": "test@example.com"},
            format="json",
        )
        match = re.search(r"[A-Za-z0-9_\-]{20,}", str(mail.outbox[0].body))
        assert match

        self.user.is_active = False
        self.user.save(update_fields=["is_active"])

        response = self.client.post(
            "/api/auth/passwordless/email/verify/",
            {"token": match.group(0)},
            format="json",
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "disabled" in str(response.data)
