from typing import cast

from django.contrib.auth import get_user_model
from django.core import mail
from django.urls import reverse
from rest_framework import status
from rest_framework.response import Response
from rest_framework.test import APITestCase

from auth_kit.mfa.handlers.app import MFAAppHandler
from auth_kit.mfa.handlers.base import MFAHandlerRegistry
from auth_kit.mfa.mfa_settings import auth_kit_mfa_settings
from auth_kit.test_utils import override_auth_kit_settings
from freezegun import freeze_time

from test_utils.mfa_factory import MFAMethodFactory
from test_utils.user_factory import UserFactory

User = get_user_model()


class TestMFALoginView(APITestCase):

    def setUp(self) -> None:
        self.login_data = {
            "username": "testuser",
            "password": "complexpass123",
        }
        self.user_data = {
            "username": "testuser",
            "email": "test@example.com",
            "password": "complexpass123",
        }
        self.login_url = reverse("rest_login")
        self.login_confirm_url = reverse("rest_login_verify")

    def test_login_no_mfa(self) -> None:
        UserFactory.create_with_email_address(self.user_data)

        response: Response = self.client.post(
            self.login_url, self.login_data, format="json"
        )

        assert response.status_code == status.HTTP_200_OK

        # Check JWT token fields
        expected_fields = {
            "access",
            "refresh",
            "access_expiration",
            "mfa_enabled",
            "refresh_expiration",
            "user",
        }
        actual_fields = set(response.data.keys())
        assert not response.data["mfa_enabled"]
        assert expected_fields == actual_fields

    @freeze_time("2012-01-14 12:00:01")
    def test_login_with_mfa_by_app_success(self) -> None:
        user, _email = UserFactory.create_with_email_address(self.user_data)
        mfa_method = MFAMethodFactory.create_primary(user=user)

        first_step_response: Response = self.client.post(
            self.login_url, self.login_data, format="json"
        )

        assert first_step_response.status_code == status.HTTP_200_OK
        expected_fields = {"ephemeral_token", "method", "mfa_enabled"}
        actual_fields = set(first_step_response.data.keys())
        assert expected_fields == actual_fields

        data = first_step_response.data
        assert data["method"] == "app"
        assert data["mfa_enabled"]

        ephemeral_token = data["ephemeral_token"]
        handler = MFAHandlerRegistry.get_handler(mfa_method)
        current_otp = handler.get_otp_code()

        confirm_login_data = {"ephemeral_token": ephemeral_token, "code": current_otp}
        second_step_response = self.client.post(
            self.login_confirm_url, confirm_login_data, format="json"
        )

        assert second_step_response.status_code == status.HTTP_200_OK

        # Check JWT token fields
        expected_fields = {
            "access",
            "refresh",
            "access_expiration",
            "refresh_expiration",
            "user",
        }
        actual_fields = set(second_step_response.data.keys())
        assert expected_fields == actual_fields

    @freeze_time("2012-01-14 12:00:01")
    def test_login_with_mfa_by_email_success(self) -> None:
        user, _email = UserFactory.create_with_email_address(self.user_data)
        mfa_method = MFAMethodFactory.create_primary(name="email", user=user)

        first_step_response: Response = self.client.post(
            self.login_url, self.login_data, format="json"
        )

        assert first_step_response.status_code == status.HTTP_200_OK
        expected_fields = {"ephemeral_token", "method", "mfa_enabled"}
        actual_fields = set(first_step_response.data.keys())
        assert expected_fields == actual_fields

        data = first_step_response.data
        assert data["method"] == "email"
        assert data["mfa_enabled"]

        ephemeral_token = data["ephemeral_token"]
        handler = MFAHandlerRegistry.get_handler(mfa_method)
        current_otp = handler.get_otp_code()

        assert len(mail.outbox) == 1
        otp_email = mail.outbox[0]
        assert current_otp in otp_email.body

        confirm_login_data = {"ephemeral_token": ephemeral_token, "code": current_otp}
        second_step_response = self.client.post(
            self.login_confirm_url, confirm_login_data, format="json"
        )

        assert second_step_response.status_code == status.HTTP_200_OK

        # Check JWT token fields
        expected_fields = {
            "access",
            "refresh",
            "access_expiration",
            "refresh_expiration",
            "user",
        }
        actual_fields = set(second_step_response.data.keys())
        assert expected_fields == actual_fields

    @freeze_time("2012-01-14 12:00:01")
    def test_login_with_mfa_by_backup_code_success(self) -> None:
        user, _email = UserFactory.create_with_email_address(self.user_data)
        _mfa_method, backup_codes = (
            MFAMethodFactory.create_primary_with_raw_backup_codes(user=user)
        )

        first_step_response: Response = self.client.post(
            self.login_url, self.login_data, format="json"
        )

        assert first_step_response.status_code == status.HTTP_200_OK
        expected_fields = {"ephemeral_token", "method", "mfa_enabled"}
        actual_fields = set(first_step_response.data.keys())
        assert expected_fields == actual_fields

        data = first_step_response.data
        assert data["method"] == "app"
        assert data["mfa_enabled"]

        ephemeral_token = data["ephemeral_token"]

        confirm_login_data = {
            "ephemeral_token": ephemeral_token,
            "code": backup_codes.pop(),
        }
        second_step_response = self.client.post(
            self.login_confirm_url, confirm_login_data, format="json"
        )

        assert second_step_response.status_code == status.HTTP_200_OK

        # Check JWT token fields
        expected_fields = {
            "access",
            "refresh",
            "access_expiration",
            "refresh_expiration",
            "user",
        }
        actual_fields = set(second_step_response.data.keys())
        assert expected_fields == actual_fields

    @freeze_time("2012-01-14 12:00:01")
    @override_auth_kit_settings(BACKUP_CODE_SECURE_HASH=True)
    def test_login_with_mfa_by_secure_backup_code_success(self) -> None:
        user, _email = UserFactory.create_with_email_address(self.user_data)
        _mfa_method, backup_codes = (
            MFAMethodFactory.create_primary_with_raw_backup_codes(user=user)
        )

        first_step_response: Response = self.client.post(
            self.login_url, self.login_data, format="json"
        )

        assert first_step_response.status_code == status.HTTP_200_OK
        expected_fields = {"ephemeral_token", "method", "mfa_enabled"}
        actual_fields = set(first_step_response.data.keys())
        assert expected_fields == actual_fields

        data = first_step_response.data
        assert data["method"] == "app"
        assert data["mfa_enabled"]

        ephemeral_token = data["ephemeral_token"]

        confirm_login_data = {
            "ephemeral_token": ephemeral_token,
            "code": backup_codes.pop(),
        }
        second_step_response = self.client.post(
            self.login_confirm_url, confirm_login_data, format="json"
        )

        assert second_step_response.status_code == status.HTTP_200_OK

        # Check JWT token fields
        expected_fields = {
            "access",
            "refresh",
            "access_expiration",
            "refresh_expiration",
            "user",
        }
        actual_fields = set(second_step_response.data.keys())
        assert expected_fields == actual_fields

    @freeze_time("2012-01-14 12:00:01")
    def test_login_with_mfa_invalid_credential(self) -> None:
        user, _email = UserFactory.create_with_email_address(self.user_data)
        MFAMethodFactory.create_primary(user=user)

        invalid_data = {
            "username": "testuser",
            "password": "wrongpass123",
        }
        first_step_response: Response = self.client.post(
            self.login_url, invalid_data, format="json"
        )

        assert first_step_response.status_code == status.HTTP_400_BAD_REQUEST
        assert "Unable to log in" in str(first_step_response.data)

    @freeze_time("2012-01-14 12:00:01")
    def test_login_with_mfa_invalid_code(self) -> None:
        user, _email = UserFactory.create_with_email_address(self.user_data)
        mfa_method = MFAMethodFactory.create_primary(user=user)

        first_step_response: Response = self.client.post(
            self.login_url, self.login_data, format="json"
        )

        assert first_step_response.status_code == status.HTTP_200_OK
        expected_fields = {"ephemeral_token", "method", "mfa_enabled"}
        actual_fields = set(first_step_response.data.keys())
        assert expected_fields == actual_fields

        data = first_step_response.data
        assert data["method"] == "app"
        assert data["mfa_enabled"]

        ephemeral_token = data["ephemeral_token"]
        handler = cast(MFAAppHandler, MFAHandlerRegistry.get_handler(mfa_method))
        current_otp = handler.get_otp_code()

        confirm_login_data = {
            "ephemeral_token": ephemeral_token,
            "code": current_otp + "123",
        }
        second_step_response = self.client.post(
            self.login_confirm_url, confirm_login_data, format="json"
        )

        assert second_step_response.status_code == status.HTTP_400_BAD_REQUEST

        assert "Invalid code" in str(second_step_response.data)

    @freeze_time("2012-01-14 12:00:01")
    @override_auth_kit_settings(BACKUP_CODE_SECURE_HASH=False)
    def test_login_with_mfa_invalid_backup_code(self) -> None:
        user, _email = UserFactory.create_with_email_address(self.user_data)
        MFAMethodFactory.create_primary(user=user)

        first_step_response: Response = self.client.post(
            self.login_url, self.login_data, format="json"
        )

        assert first_step_response.status_code == status.HTTP_200_OK
        expected_fields = {"ephemeral_token", "method", "mfa_enabled"}
        actual_fields = set(first_step_response.data.keys())
        assert expected_fields == actual_fields

        data = first_step_response.data
        assert data["method"] == "app"
        assert data["mfa_enabled"]

        ephemeral_token = data["ephemeral_token"]

        confirm_login_data = {
            "ephemeral_token": ephemeral_token,
            "code": "1" * auth_kit_mfa_settings.BACKUP_CODE_LENGTH,
        }
        second_step_response = self.client.post(
            self.login_confirm_url, confirm_login_data, format="json"
        )

        assert second_step_response.status_code == status.HTTP_400_BAD_REQUEST

        assert "Invalid code" in str(second_step_response.data)

    @freeze_time("2012-01-14 12:00:01")
    @override_auth_kit_settings(BACKUP_CODE_SECURE_HASH=True)
    def test_login_with_mfa_invalid_secure_backup_code(self) -> None:
        user, _email = UserFactory.create_with_email_address(self.user_data)
        MFAMethodFactory.create_primary(user=user)

        first_step_response: Response = self.client.post(
            self.login_url, self.login_data, format="json"
        )

        assert first_step_response.status_code == status.HTTP_200_OK
        expected_fields = {"ephemeral_token", "method", "mfa_enabled"}
        actual_fields = set(first_step_response.data.keys())
        assert expected_fields == actual_fields

        data = first_step_response.data
        assert data["method"] == "app"
        assert data["mfa_enabled"]

        ephemeral_token = data["ephemeral_token"]

        confirm_login_data = {
            "ephemeral_token": ephemeral_token,
            "code": "1" * auth_kit_mfa_settings.BACKUP_CODE_LENGTH,
        }
        second_step_response = self.client.post(
            self.login_confirm_url, confirm_login_data, format="json"
        )

        assert second_step_response.status_code == status.HTTP_400_BAD_REQUEST

        assert "Invalid code" in str(second_step_response.data)

    @freeze_time("2012-01-14 12:00:01")
    def test_login_with_mfa_invalid_token(self) -> None:
        user, _email = UserFactory.create_with_email_address(self.user_data)
        mfa_method = MFAMethodFactory.create_primary(user=user)

        first_step_response: Response = self.client.post(
            self.login_url, self.login_data, format="json"
        )

        assert first_step_response.status_code == status.HTTP_200_OK
        expected_fields = {"ephemeral_token", "method", "mfa_enabled"}
        actual_fields = set(first_step_response.data.keys())
        assert expected_fields == actual_fields

        data = first_step_response.data
        assert data["method"] == "app"
        assert data["mfa_enabled"]

        ephemeral_token = data["ephemeral_token"]
        handler = cast(MFAAppHandler, MFAHandlerRegistry.get_handler(mfa_method))
        current_otp = handler.get_otp_code()

        confirm_login_data = {
            "ephemeral_token": ephemeral_token + "1",
            "code": current_otp,
        }
        second_step_response = self.client.post(
            self.login_confirm_url, confirm_login_data, format="json"
        )

        assert second_step_response.status_code == status.HTTP_400_BAD_REQUEST

        assert "Invalid token" in str(second_step_response.data)

    @freeze_time("2012-01-14 12:00:01")
    def test_login_with_mfa_without_active_primary_method(self) -> None:
        user, _email = UserFactory.create_with_email_address(self.user_data)
        MFAMethodFactory.create(user=user)

        first_step_response: Response = self.client.post(
            self.login_url, self.login_data, format="json"
        )

        assert first_step_response.status_code == status.HTTP_200_OK

        # Check JWT token fields
        expected_fields = {
            "access",
            "refresh",
            "access_expiration",
            "mfa_enabled",
            "refresh_expiration",
            "user",
        }
        actual_fields = set(first_step_response.data.keys())
        assert expected_fields == actual_fields
        assert not first_step_response.data["mfa_enabled"]

    # Add these test methods to your existing TestMFALoginView class

    @freeze_time("2012-01-14 12:00:01")
    def test_change_method_success(self) -> None:
        user, _ = UserFactory.create_with_email_address(self.user_data)
        MFAMethodFactory.create_primary(name="app", user=user)
        MFAMethodFactory.create(name="email", user=user, is_active=True)

        # Get ephemeral token from first step
        first_step_response: Response = self.client.post(
            self.login_url, self.login_data, format="json"
        )
        ephemeral_token = first_step_response.data["ephemeral_token"]

        # Change method
        change_data = {"ephemeral_token": ephemeral_token, "new_method": "email"}
        change_response = self.client.post(
            reverse("rest_login_change_method"), change_data, format="json"
        )

        assert change_response.status_code == status.HTTP_200_OK
        assert "ephemeral_token" in change_response.data
        assert change_response.data["new_method"] == "email"

    def test_change_method_invalid_token(self) -> None:
        change_data = {"ephemeral_token": "invalid", "new_method": "email"}
        response = self.client.post(
            reverse("rest_login_change_method"), change_data, format="json"
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "Invalid token" in str(response.data)

    def test_change_method_same_method(self) -> None:
        user, _ = UserFactory.create_with_email_address(self.user_data)
        MFAMethodFactory.create_primary(name="app", user=user)

        first_step_response: Response = self.client.post(
            self.login_url, self.login_data, format="json"
        )
        ephemeral_token = first_step_response.data["ephemeral_token"]

        change_data = {"ephemeral_token": ephemeral_token, "new_method": "app"}
        response = self.client.post(
            reverse("rest_login_change_method"), change_data, format="json"
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "Please select a new method" in str(response.data)

    @freeze_time("2012-01-14 12:00:01")
    def test_resend_code_success(self) -> None:
        user, _ = UserFactory.create_with_email_address(self.user_data)
        MFAMethodFactory.create_primary(name="email", user=user)

        # Get ephemeral token
        first_step_response: Response = self.client.post(
            self.login_url, self.login_data, format="json"
        )
        ephemeral_token = first_step_response.data["ephemeral_token"]

        # Clear email outbox
        mail.outbox = []

        # Resend code
        resend_data = {"ephemeral_token": ephemeral_token}
        response = self.client.post(
            reverse("rest_login_resend"), resend_data, format="json"
        )

        assert response.status_code == status.HTTP_200_OK
        assert "ephemeral_token" in response.data
        assert len(mail.outbox) == 1  # New email sent

    def test_resend_code_invalid_token(self) -> None:
        resend_data = {"ephemeral_token": "invalid"}
        response = self.client.post(
            reverse("rest_login_resend"), resend_data, format="json"
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "Invalid token" in str(response.data)
