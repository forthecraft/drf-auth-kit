"""Tests for MFA admin configuration."""

from unittest.mock import Mock, patch

from django.core.exceptions import FieldDoesNotExist
from django.test import TestCase

from auth_kit.mfa import admin as mfa_admin


class TestMFAMethodAdmin(TestCase):
    """Test cases for MFAMethodAdmin search field generation."""

    def test_default_user_model_fields(self) -> None:
        """Test search fields include username and email for the default model."""
        assert mfa_admin._user_search_fields() == ["user__username", "user__email"]

    def test_skips_missing_email_field(self) -> None:
        """Test fields absent from the user model are skipped."""

        def get_field(name: str) -> object:
            if name == "email":
                raise FieldDoesNotExist(name)
            return object()

        fake_model = Mock()
        fake_model.USERNAME_FIELD = "phone"
        fake_model.get_email_field_name.return_value = "email"
        fake_model._meta.get_field.side_effect = get_field

        with patch.object(mfa_admin, "UserModel", fake_model):
            assert mfa_admin._user_search_fields() == ["user__phone"]
