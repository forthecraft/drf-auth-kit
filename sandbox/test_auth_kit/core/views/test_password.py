import re
from typing import Any
from unittest.mock import MagicMock, patch

from django.contrib.auth import get_user_model
from django.core import mail
from django.urls import reverse
from rest_framework import status
from rest_framework.response import Response
from rest_framework.test import APITestCase

from allauth.account.forms import default_token_generator  # pyright: ignore
from allauth.account.utils import user_pk_to_url_str  # pyright: ignore
from auth_kit.test_utils import override_auth_kit_settings

from test_utils.user_factory import UserFactory

User = get_user_model()


class TestPasswordResetView(APITestCase):
    def setUp(self) -> None:
        self.user_data = {
            "username": "testuser",
            "email": "test@example.com",
            "password": "complexpass123",
        }
        self.url = reverse("rest_password_reset")

    def test_password_reset_success(self) -> None:
        """Test successful password reset request"""
        UserFactory.create_with_email_address(self.user_data)

        data = {"email": "test@example.com"}
        response: Response = self.client.post(self.url, data, format="json")

        assert response.status_code == status.HTTP_200_OK
        assert response.data["detail"] == "Password reset e-mail has been sent."

        # Check that email was sent
        assert len(mail.outbox) == 1
        assert mail.outbox[0].to == ["test@example.com"]
        assert "password reset" in mail.outbox[0].subject.lower()

    def test_password_reset_nonexistent_email(self) -> None:
        """Test password reset with non-existent email"""
        data = {"email": "nonexistent@example.com"}
        response: Response = self.client.post(self.url, data, format="json")

        # Should still return success for security reasons
        assert response.status_code == status.HTTP_200_OK
        assert response.data["detail"] == "Password reset e-mail has been sent."

        # No email should be sent
        assert len(mail.outbox) == 0

    @override_auth_kit_settings(PASSWORD_RESET_PREVENT_ENUMERATION=False)
    def test_password_reset_nonexistent_email_with_not_prevent_enumeration(
        self,
    ) -> None:
        """Test password reset with non-existent email"""
        data = {"email": "nonexistent@example.com"}
        response: Response = self.client.post(self.url, data, format="json")

        # Should still return success for security reasons
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert (
            "The email address is not assigned to any user account."
            in response.data["email"]
        )

        # No email should be sent
        assert len(mail.outbox) == 0

    def test_password_reset_invalid_email(self) -> None:
        """Test password reset with invalid email format"""
        data = {"email": "invalid-email"}
        response: Response = self.client.post(self.url, data, format="json")

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "email" in response.data

    def test_password_reset_missing_email(self) -> None:
        """Test password reset without email field"""
        data: dict[str, Any] = {}
        response: Response = self.client.post(self.url, data, format="json")

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "email" in response.data

    def test_password_reset_inactive_user(self) -> None:
        """Test password reset for inactive user"""
        user, _ = UserFactory.create_with_email_address(self.user_data)
        user.is_active = False
        user.save()

        data = {"email": "test@example.com"}
        response: Response = self.client.post(self.url, data, format="json")

        # Should still return success but no email sent
        assert response.status_code == status.HTTP_200_OK
        assert len(mail.outbox) == 0

    def test_password_reset_email_content(self) -> None:
        """Test that password reset email contains proper content"""
        UserFactory.create_with_email_address(self.user_data)

        data = {"email": "test@example.com"}
        response: Response = self.client.post(self.url, data, format="json")

        assert response.status_code == status.HTTP_200_OK
        assert len(mail.outbox) == 1

        email = mail.outbox[0]
        assert "test@example.com" in email.to

        # Check that email contains reset URL
        email_body = email.body
        assert "password" in email_body.lower()

        # Extract URL from email (should contain uid and token)
        url_pattern = r"https?://[^\s]+\?[^\s]*uid=[^\s&]+[^\s]*token=[^\s&]+"
        urls: list[Any] = re.findall(url_pattern, str(email_body))
        assert len(urls) >= 1

    @override_auth_kit_settings(
        FRONTEND_BASE_URL="https://frontend.example.com",
        PASSWORD_RESET_CONFIRM_PATH="/auth/reset-password",
    )
    def test_password_reset_email_content_with_frontend_base_url_and_path(self) -> None:
        """Test that password reset email uses frontend base URL with custom path"""
        UserFactory.create_with_email_address(self.user_data)

        data = {"email": "test@example.com"}
        response: Response = self.client.post(self.url, data, format="json")

        assert response.status_code == status.HTTP_200_OK
        assert len(mail.outbox) == 1

        email = mail.outbox[0]
        assert "test@example.com" in email.to

        # Check that email contains frontend reset URL
        email_body = email.body
        assert "password" in email_body.lower()

        # Verify the frontend URL with custom path is used
        assert "https://frontend.example.com/auth/reset-password?uid=" in email_body
        assert "&token=" in email_body

        # Ensure it's not using the default API endpoint
        assert "/api/auth/password/reset/confirm" not in email_body

        url_pattern = r"https://frontend\.example\.com/auth/reset-password\?uid=[a-zA-Z0-9]+&token=[a-zA-Z0-9\-]+"
        urls: list[Any] = re.findall(url_pattern, str(email_body))
        assert len(urls) >= 1

    @override_auth_kit_settings(FRONTEND_BASE_URL="https://frontend.example.com/")
    def test_password_reset_email_content_with_frontend_base_url_default_path(
        self,
    ) -> None:
        """Test that password reset email uses frontend base URL with default backend path"""
        UserFactory.create_with_email_address(self.user_data)

        data = {"email": "test@example.com"}
        response: Response = self.client.post(self.url, data, format="json")

        assert response.status_code == status.HTTP_200_OK
        assert len(mail.outbox) == 1

        email = mail.outbox[0]
        assert "test@example.com" in email.to

        # Check that email contains frontend reset URL with backend path
        email_body = email.body
        assert "password" in email_body.lower()

        # Should use frontend base URL with backend path when no custom path is set
        assert (
            "https://frontend.example.com/api/auth/password/reset/confirm?uid="
            in email_body
        )
        assert "&token=" in email_body

        url_pattern = r"https://frontend\.example\.com/api/auth/password/reset/confirm\?uid=[a-zA-Z0-9]+&token=[a-zA-Z0-9\-]+"
        urls: list[Any] = re.findall(url_pattern, str(email_body))
        assert len(urls) >= 1

    @override_auth_kit_settings(
        FRONTEND_BASE_URL="https://frontend.example.com",
        PASSWORD_RESET_CONFIRM_PATH="auth/reset-password",  # Test without leading slash
    )
    def test_password_reset_email_content_path_without_leading_slash(self) -> None:
        """Test that password reset email handles path without leading slash correctly"""
        UserFactory.create_with_email_address(self.user_data)

        data = {"email": "test@example.com"}
        response: Response = self.client.post(self.url, data, format="json")

        assert response.status_code == status.HTTP_200_OK
        assert len(mail.outbox) == 1

        email = mail.outbox[0]
        assert "test@example.com" in email.to

        email_body = email.body
        assert "password" in email_body.lower()

        # Should properly handle path without leading slash
        assert "https://frontend.example.com/auth/reset-password?uid=" in email_body
        assert "&token=" in email_body

        url_pattern = r"https://frontend\.example\.com/auth/reset-password\?uid=[a-zA-Z0-9]+&token=[a-zA-Z0-9\-]+"
        urls: list[Any] = re.findall(url_pattern, str(email_body))
        assert len(urls) >= 1


class TestPasswordResetConfirmView(APITestCase):
    def setUp(self) -> None:
        self.user_data = {
            "username": "testuser",
            "email": "test@example.com",
            "password": "complexpass123",
        }
        self.user, _ = UserFactory.create_with_email_address(self.user_data)
        self.url = reverse("rest_password_reset_confirm")

        # Generate valid uid and token
        self.uid = user_pk_to_url_str(self.user)
        self.token = default_token_generator.make_token(self.user)

    def test_password_reset_confirm_success(self) -> None:
        """Test successful password reset confirmation"""
        data = {
            "uid": self.uid,
            "token": self.token,
            "new_password1": "newcomplexpass456",
            "new_password2": "newcomplexpass456",
        }

        response: Response = self.client.post(self.url, data, format="json")

        assert response.status_code == status.HTTP_200_OK
        assert (
            response.data["detail"] == "Password has been reset with the new password."
        )

        # Verify password was actually changed
        self.user.refresh_from_db()
        assert self.user.check_password("newcomplexpass456")
        assert not self.user.check_password("complexpass123")

    def test_password_reset_confirm_password_mismatch(self) -> None:
        """Test password reset with mismatched passwords"""
        data = {
            "uid": self.uid,
            "token": self.token,
            "new_password1": "newcomplexpass456",
            "new_password2": "differentpass789",
        }

        response: Response = self.client.post(self.url, data, format="json")

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "password" in str(response.data).lower()

    def test_password_reset_confirm_invalid_uid(self) -> None:
        """Test password reset with invalid UID"""
        data = {
            "uid": "invalid-uid",
            "token": self.token,
            "new_password1": "newcomplexpass456",
            "new_password2": "newcomplexpass456",
        }

        response: Response = self.client.post(self.url, data, format="json")

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "uid" in response.data

    def test_password_reset_confirm_invalid_token(self) -> None:
        """Test password reset with invalid token"""
        data = {
            "uid": self.uid,
            "token": "invalid-token",
            "new_password1": "newcomplexpass456",
            "new_password2": "newcomplexpass456",
        }

        response: Response = self.client.post(self.url, data, format="json")

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "token" in response.data

    def test_password_reset_confirm_weak_password(self) -> None:
        """Test password reset with weak password"""
        data = {
            "uid": self.uid,
            "token": self.token,
            "new_password1": "123",
            "new_password2": "123",
        }

        response: Response = self.client.post(self.url, data, format="json")

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_password_reset_confirm_missing_fields(self) -> None:
        """Test password reset with missing required fields"""
        data = {
            "uid": self.uid,
            # Missing token and passwords
        }

        response: Response = self.client.post(self.url, data, format="json")

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_password_reset_confirm_used_token(self) -> None:
        """Test password reset with already used token"""
        # First successful reset
        data = {
            "uid": self.uid,
            "token": self.token,
            "new_password1": "newcomplexpass456",
            "new_password2": "newcomplexpass456",
        }

        response: Response = self.client.post(self.url, data, format="json")
        assert response.status_code == status.HTTP_200_OK

        # Try to use the same token again
        data["new_password1"] = "anothernewpass789"
        data["new_password2"] = "anothernewpass789"

        response2: Response = self.client.post(self.url, data, format="json")

        assert response2.status_code == status.HTTP_400_BAD_REQUEST
        assert "token" in response2.data


class TestPasswordChangeView(APITestCase):
    def setUp(self) -> None:
        self.user_data = {
            "username": "testuser",
            "email": "test@example.com",
            "password": "complexpass123",
        }
        self.user, _ = UserFactory.create_with_email_address(self.user_data)
        self.url = reverse("rest_password_change")

    def test_password_change_unauthenticated(self) -> None:
        """Test password change without authentication"""
        data = {
            "new_password1": "newcomplexpass456",
            "new_password2": "newcomplexpass456",
        }

        response: Response = self.client.post(self.url, data, format="json")

        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    @override_auth_kit_settings(OLD_PASSWORD_FIELD_ENABLED=True)
    def test_password_change_success_with_old_password(self) -> None:
        """Test successful password change with old password verification"""
        self.client.force_authenticate(user=self.user)

        data = {
            "old_password": "complexpass123",
            "new_password1": "newcomplexpass456",
            "new_password2": "newcomplexpass456",
        }

        response: Response = self.client.post(self.url, data, format="json")

        assert response.status_code == status.HTTP_200_OK
        assert response.data["detail"] == "New password has been saved."

        # Verify password was actually changed
        self.user.refresh_from_db()
        assert self.user.check_password("newcomplexpass456")
        assert not self.user.check_password("complexpass123")

    @override_auth_kit_settings(OLD_PASSWORD_FIELD_ENABLED=False)
    def test_password_change_success_without_old_password(self) -> None:
        """Test successful password change without old password verification"""
        self.client.force_authenticate(user=self.user)

        data = {
            "new_password1": "newcomplexpass456",
            "new_password2": "newcomplexpass456",
        }

        response: Response = self.client.post(self.url, data, format="json")

        assert response.status_code == status.HTTP_200_OK
        assert response.data["detail"] == "New password has been saved."

        # Verify password was actually changed
        self.user.refresh_from_db()
        assert self.user.check_password("newcomplexpass456")

    @override_auth_kit_settings(OLD_PASSWORD_FIELD_ENABLED=True)
    def test_password_change_wrong_old_password(self) -> None:
        """Test password change with incorrect old password"""
        self.client.force_authenticate(user=self.user)

        data = {
            "old_password": "wrongpassword",
            "new_password1": "newcomplexpass456",
            "new_password2": "newcomplexpass456",
        }

        response: Response = self.client.post(self.url, data, format="json")

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "old password" in str(response.data).lower()

    def test_password_change_password_mismatch(self) -> None:
        """Test password change with mismatched new passwords"""
        self.client.force_authenticate(user=self.user)

        data = {
            "new_password1": "newcomplexpass456",
            "new_password2": "differentpass789",
        }

        response: Response = self.client.post(self.url, data, format="json")

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_password_change_weak_password(self) -> None:
        """Test password change with weak password"""
        self.client.force_authenticate(user=self.user)

        data = {
            "new_password1": "123",
            "new_password2": "123",
        }

        response: Response = self.client.post(self.url, data, format="json")

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_password_change_missing_fields(self) -> None:
        """Test password change with missing required fields"""
        self.client.force_authenticate(user=self.user)

        data = {
            "new_password1": "newcomplexpass456",
            # Missing new_password2
        }

        response: Response = self.client.post(self.url, data, format="json")

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    @override_auth_kit_settings(OLD_PASSWORD_FIELD_ENABLED=True)
    def test_password_change_missing_old_password(self) -> None:
        """Test password change missing old password when required"""
        self.client.force_authenticate(user=self.user)

        data = {
            "new_password1": "newcomplexpass456",
            "new_password2": "newcomplexpass456",
            # Missing old_password
        }

        response: Response = self.client.post(self.url, data, format="json")

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_password_change_same_password(self) -> None:
        """Test password change to the same password"""
        self.client.force_authenticate(user=self.user)

        data = {
            "new_password1": "complexpass123",
            "new_password2": "complexpass123",
        }

        response: Response = self.client.post(self.url, data, format="json")

        # This should succeed (Django allows setting same password)
        assert response.status_code == status.HTTP_200_OK

    @patch("auth_kit.serializers.password.SetPasswordForm")
    def test_password_change_form_validation_error(
        self, mock_form_class: MagicMock
    ) -> None:
        """Test password change with form validation errors"""
        self.client.force_authenticate(user=self.user)

        # Mock form to return validation errors
        mock_form = MagicMock()
        mock_form.is_valid.return_value = False
        mock_form.errors = {"new_password1": ["This password is too common."]}
        mock_form_class.return_value = mock_form

        data = {
            "new_password1": "password123",
            "new_password2": "password123",
        }

        response: Response = self.client.post(self.url, data, format="json")

        assert response.status_code == status.HTTP_400_BAD_REQUEST
