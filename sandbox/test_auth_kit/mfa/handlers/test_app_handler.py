"""Tests for authenticator app MFA handler."""

from typing import cast

from django.contrib.auth.base_user import AbstractBaseUser
from django.test import TestCase

from auth_kit.mfa.handlers.app import AppSetupSerializer, MFAAppHandler

from test_utils.mfa_factory import MFAMethodFactory
from test_utils.user_factory import UserFactory


class UsernamelessUser:
    """User stub without a username attribute, mimicking USERNAME_FIELD = "email"."""

    USERNAME_FIELD = "email"

    def __init__(self, email: str) -> None:
        """Store the email used as the username field."""
        self.email = email

    def get_username(self) -> str:
        """Return the value of the username field."""
        return self.email


class TestMFAAppHandler(TestCase):
    """Test cases for MFAAppHandler."""

    def setUp(self) -> None:
        """Set up test data."""
        self.user = UserFactory.create()
        self.mfa_method = MFAMethodFactory.create(
            user=self.user,
            name="app",
            secret="JBSWY3DPEHPK3PXP",
        )
        self.handler = MFAAppHandler(self.mfa_method)

    def test_initialize_method_returns_qr_link(self) -> None:
        """Test that initialization returns a TOTP provisioning URI."""
        result = self.handler.initialize_method()

        assert result["qr_link"].startswith("otpauth://totp/")
        assert self.user.get_username() in result["qr_link"]

    def test_create_qr_link_for_user_without_username_attribute(self) -> None:
        """Regression test for custom user models without a username field."""
        user = cast(AbstractBaseUser, UsernamelessUser("mfa@example.com"))

        qr_link = self.handler._create_qr_link(user)

        assert "mfa%40example.com" in qr_link

    def test_get_initialize_method_serializer_class(self) -> None:
        """Test getting serializer class for app setup response."""
        assert (
            self.handler.get_initialize_method_serializer_class() is AppSetupSerializer
        )
