from typing import cast
from urllib.parse import quote_plus

from django.contrib.auth.models import User
from django.core import mail
from django.test import override_settings
from django.urls import reverse
from rest_framework import status
from rest_framework.response import Response
from rest_framework.test import APITestCase

from allauth.account.models import (  # pyright: ignore[reportMissingTypeStubs]
    EmailAddress,
    get_emailconfirmation_model,
)
from auth_kit.test_utils import override_auth_kit_settings

from test_utils.user_factory import UserFactory

EmailConfirmationModel = get_emailconfirmation_model()


class TestRegisterView(APITestCase):
    def setUp(self) -> None:
        self.registration_data = {
            "username": "testuser",
            "email": "test@example.com",
            "password1": "complexpass123",
            "password2": "complexpass123",
            "first_name": "John",
            "last_name": "Doe",
        }
        self.user_data = {
            "username": "testuser",
            "email": "test@example.com",
            "password": "complexpass123",
            "first_name": "John",
            "last_name": "Doe",
        }

    def test_register_default_case(self) -> None:
        url = reverse("rest_register")
        response: Response = self.client.post(
            url, self.registration_data, format="json"
        )

        assert response.status_code == status.HTTP_201_CREATED
        assert "Verification e-mail sent" in response.data["detail"]

        # Verify user was created
        user_exists = User.objects.filter(username="testuser").exists()
        assert user_exists is True

        # Verify user is active (default Django behavior)
        user = User.objects.get(username="testuser")
        assert user.is_active is True

        # Verify name fields are saved correctly
        assert user.first_name == "John"
        assert user.last_name == "Doe"

        # Verify email is not active
        email_address = EmailAddress.objects.get(user=user)
        assert not email_address.verified

        assert len(mail.outbox) == 1
        register_email = mail.outbox[0]

        assert register_email.to == [self.registration_data["email"]]
        assert (
            register_email.subject == "[testserver] Please Confirm Your Email Address"
        )
        assert (
            "http://testserver/api/auth/registration/verify-email?key="
            in register_email.body
        )

    def test_registration_without_name_fields(self) -> None:
        """Test registration without first_name and last_name fields (optional)"""
        url = reverse("rest_register")
        # Create registration data without name fields
        data = {
            "username": "testuser2",
            "email": "test2@example.com",
            "password1": "complexpass123",
            "password2": "complexpass123",
        }

        response: Response = self.client.post(url, data, format="json")

        assert response.status_code == status.HTTP_201_CREATED
        assert "Verification e-mail sent" in response.data["detail"]

        # Verify user was created with empty name fields (default values)
        user = User.objects.get(username="testuser2")
        assert user.first_name == ""
        assert user.last_name == ""

    def test_registration_with_empty_name_fields(self) -> None:
        """Test registration with empty/blank first_name and last_name"""
        url = reverse("rest_register")
        data = {
            "username": "testuser3",
            "email": "test3@example.com",
            "password1": "complexpass123",
            "password2": "complexpass123",
            "first_name": "",
            "last_name": "",
        }

        response: Response = self.client.post(url, data, format="json")

        assert response.status_code == status.HTTP_201_CREATED
        assert "Verification e-mail sent" in response.data["detail"]

        # Verify user was created with empty name fields
        user = User.objects.get(username="testuser3")
        assert user.first_name == ""
        assert user.last_name == ""

    def test_registration_password_mismatch(self) -> None:
        data = self.registration_data.copy()
        data["password2"] = "differentpass123"

        url = reverse("rest_register")
        response: Response = self.client.post(url, data, format="json")

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "password" in str(response.data).lower()

    def test_registration_duplicate_username(self) -> None:
        # Create first user
        UserFactory.create_with_email_address(self.user_data)

        url = reverse("rest_register")
        response: Response = self.client.post(
            url, self.registration_data, format="json"
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "username" in str(response.data).lower()

    def test_registration_duplicate_email(self) -> None:
        # Create first user
        UserFactory.create_with_email_address(self.user_data)

        url = reverse("rest_register")
        response: Response = self.client.post(
            url, self.registration_data, format="json"
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "already registered" in str(response.data).lower()

    def test_registration_missing_fields(self) -> None:
        """Test registration with missing required fields"""
        url = reverse("rest_register")

        # Test missing username
        data: dict[str, str] = {
            "email": "test@example.com",
            "password1": "complexpass123",
            "password2": "complexpass123",
        }
        response: Response = self.client.post(url, data, format="json")
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "username" in response.data

        # Test missing email
        data = {
            "username": "testuser",
            "password1": "complexpass123",
            "password2": "complexpass123",
        }
        response = self.client.post(url, data, format="json")
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "email" in response.data

    def test_registration_invalid_email_format(self) -> None:
        """Test registration with invalid email format"""
        url = reverse("rest_register")
        data = self.registration_data.copy()
        data["email"] = "invalid-email"

        response: Response = self.client.post(url, data, format="json")
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "email" in response.data

    def test_registration_weak_password(self) -> None:
        """Test registration with weak password"""
        url = reverse("rest_register")
        data = self.registration_data.copy()
        data["password1"] = "123"
        data["password2"] = "123"

        response: Response = self.client.post(url, data, format="json")
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    @override_settings(ACCOUNT_EMAIL_VERIFICATION="none")
    def test_registration_do_not_send_email_for_not_required_email_allauth_config(
        self,
    ) -> None:
        url = reverse("rest_register")
        response: Response = self.client.post(
            url, self.registration_data, format="json"
        )

        assert response.status_code == status.HTTP_201_CREATED
        assert "Successfully registered." in response.data["detail"]

        # Verify user was created
        user_exists = User.objects.filter(username="testuser").exists()
        assert user_exists is True

        # Verify user is active (default Django behavior)
        user = User.objects.get(username="testuser")
        assert user.is_active is True

        # Verify email is not active
        email_address = EmailAddress.objects.get(user=user)
        assert not email_address.verified

        assert len(mail.outbox) == 0

    @override_auth_kit_settings(
        FRONTEND_BASE_URL="https://frontend.example.com",
        REGISTER_EMAIL_CONFIRM_PATH="/auth/verify-email",
    )
    def test_registration_frontend_base_url_with_path(self) -> None:
        url = reverse("rest_register")
        response: Response = self.client.post(
            url, self.registration_data, format="json"
        )

        assert response.status_code == status.HTTP_201_CREATED
        assert "Verification e-mail sent" in response.data["detail"]

        assert len(mail.outbox) == 1
        register_email = mail.outbox[0]

        assert register_email.to == [self.registration_data["email"]]
        assert (
            register_email.subject == "[testserver] Please Confirm Your Email Address"
        )
        assert (
            "https://frontend.example.com/auth/verify-email?key=" in register_email.body
        )

    @override_auth_kit_settings(FRONTEND_BASE_URL="https://frontend.example.com/")
    def test_registration_frontend_base_url_default_path(self) -> None:
        url = reverse("rest_register")
        response: Response = self.client.post(
            url, self.registration_data, format="json"
        )

        assert response.status_code == status.HTTP_201_CREATED
        assert "Verification e-mail sent" in response.data["detail"]

        assert len(mail.outbox) == 1
        register_email = mail.outbox[0]

        assert register_email.to == [self.registration_data["email"]]
        assert (
            register_email.subject == "[testserver] Please Confirm Your Email Address"
        )
        # Should use the backend path when no custom path is set
        assert (
            "https://frontend.example.com/api/auth/registration/verify-email?key="
            in register_email.body
        )

    @override_auth_kit_settings(
        FRONTEND_BASE_URL="https://frontend.example.com",
        REGISTER_EMAIL_CONFIRM_PATH="auth/verify-email",  # Test without leading slash
    )
    def test_registration_frontend_base_url_path_without_leading_slash(self) -> None:
        url = reverse("rest_register")
        response: Response = self.client.post(
            url, self.registration_data, format="json"
        )

        assert response.status_code == status.HTTP_201_CREATED
        assert "Verification e-mail sent" in response.data["detail"]

        assert len(mail.outbox) == 1
        register_email = mail.outbox[0]

        assert register_email.to == [self.registration_data["email"]]
        assert (
            register_email.subject == "[testserver] Please Confirm Your Email Address"
        )
        assert (
            "https://frontend.example.com/auth/verify-email?key=" in register_email.body
        )


class TestVerifyEmailView(APITestCase):
    def setUp(self) -> None:
        self.user_data = {
            "username": "testuser",
            "email": "test@example.com",
            "password": "complexpass123",
            "first_name": "John",
            "last_name": "Doe",
        }
        self.url = reverse("rest_verify_email")

    def test_verify_email_success(self) -> None:
        """Test successful email verification"""
        # Create user with unverified email
        _user, email_address = UserFactory.create_with_email_address(
            self.user_data, {"verified": False}
        )

        # Create email confirmation
        confirmation = EmailConfirmationModel.create(email_address)

        data = {"key": cast(str, confirmation.key)}
        response: Response = self.client.post(self.url, data, format="json")

        assert response.status_code == status.HTTP_200_OK
        assert response.data["detail"] == "ok"

        # Verify email is now verified
        email_address.refresh_from_db()
        assert email_address.verified

    def test_verify_email_invalid_key(self) -> None:
        """Test email verification with invalid key"""
        data: dict[str, str] = {"key": "invalid-key"}
        response: Response = self.client.post(self.url, data, format="json")

        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_verify_email_missing_key(self) -> None:
        """Test email verification without key"""
        data: dict[str, str] = {}
        response: Response = self.client.post(self.url, data, format="json")

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "key" in response.data

    def test_verify_email_already_verified(self) -> None:
        """Test verifying already verified email"""
        # Create user with verified email
        _user, email_address = UserFactory.create_with_email_address(
            self.user_data, {"verified": True}
        )

        # Create email confirmation
        confirmation = EmailConfirmationModel.create(email_address)

        data = {"key": cast(str, confirmation.key)}
        response: Response = self.client.post(self.url, data, format="json")

        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_verify_email_get_method_not_allowed(self) -> None:
        """Test that GET method is not allowed"""
        response: Response = self.client.get(self.url)
        assert response.status_code == status.HTTP_405_METHOD_NOT_ALLOWED

    def test_verify_email_url_encoded_key(self) -> None:
        """Test email verification with URL-encoded key"""
        # Create user with unverified email
        _user, email_address = UserFactory.create_with_email_address(
            self.user_data, {"verified": False}
        )

        # Create email confirmation
        confirmation = EmailConfirmationModel.create(email_address)

        # URL encode the key (simulating what might happen in emails)
        encoded_key = quote_plus(cast(str, confirmation.key))

        data: dict[str, str] = {"key": encoded_key}
        response: Response = self.client.post(self.url, data, format="json")

        assert response.status_code == status.HTTP_200_OK
        assert response.data["detail"] == "ok"


class TestResendEmailVerificationView(APITestCase):
    def setUp(self) -> None:
        self.user_data = {
            "username": "testuser",
            "email": "test@example.com",
            "password": "complexpass123",
            "first_name": "John",
            "last_name": "Doe",
        }
        self.url = reverse("rest_resend_email")

    def test_resend_email_verification_success(self) -> None:
        """Test successful email verification resend"""
        # Create user with unverified email
        _user, _email_address = UserFactory.create_with_email_address(
            self.user_data, {"verified": False}
        )

        data: dict[str, str] = {"email": "test@example.com"}
        response: Response = self.client.post(self.url, data, format="json")

        assert response.status_code == status.HTTP_200_OK
        assert response.data["detail"] == "ok"

        # Check that email was sent
        assert len(mail.outbox) == 1
        assert mail.outbox[0].to == ["test@example.com"]

    def test_resend_email_verification_already_verified(self) -> None:
        """Test resending verification to already verified email"""
        # Create user with verified email
        UserFactory.create_with_email_address(self.user_data, {"verified": True})

        data: dict[str, str] = {"email": "test@example.com"}
        response: Response = self.client.post(self.url, data, format="json")

        assert response.status_code == status.HTTP_200_OK
        assert response.data["detail"] == "ok"

        # No email should be sent for already verified email
        assert len(mail.outbox) == 0

    def test_resend_email_verification_nonexistent_email(self) -> None:
        """Test resending verification to non-existent email"""
        data: dict[str, str] = {"email": "nonexistent@example.com"}
        response: Response = self.client.post(self.url, data, format="json")

        # Should still return success for security reasons
        assert response.status_code == status.HTTP_200_OK
        assert response.data["detail"] == "ok"

        # No email should be sent
        assert len(mail.outbox) == 0

    def test_resend_email_verification_invalid_email(self) -> None:
        """Test resending verification with invalid email format"""
        data: dict[str, str] = {"email": "invalid-email"}
        response: Response = self.client.post(self.url, data, format="json")

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "email" in response.data

    def test_resend_email_verification_missing_email(self) -> None:
        """Test resending verification without email field"""
        data: dict[str, str] = {}
        response: Response = self.client.post(self.url, data, format="json")

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "email" in response.data

    @override_settings(ACCOUNT_EMAIL_VERIFICATION="none")
    def test_resend_email_verification_disabled(self) -> None:
        """Test resending verification when email verification is disabled"""
        # Create user with unverified email
        UserFactory.create_with_email_address(self.user_data, {"verified": False})

        data: dict[str, str] = {"email": "test@example.com"}
        response: Response = self.client.post(self.url, data, format="json")

        assert response.status_code == status.HTTP_200_OK
        assert response.data["detail"] == "ok"

        # No email should be sent when verification is disabled
        assert len(mail.outbox) == 0

    def test_resend_email_verification_multiple_emails(self) -> None:
        """Test resending verification when user has multiple email addresses"""
        # Create user with multiple emails
        user, _primary_email = UserFactory.create_with_email_address(
            self.user_data, {"verified": False}
        )

        # Add another unverified email
        EmailAddress.objects.create(
            user=user, email="secondary@example.com", verified=False, primary=False
        )

        # Test resending to primary email
        data: dict[str, str] = {"email": "test@example.com"}
        response: Response = self.client.post(self.url, data, format="json")

        assert response.status_code == status.HTTP_200_OK
        assert len(mail.outbox) == 1

        # Test resending to secondary email
        data = {"email": "secondary@example.com"}
        response = self.client.post(self.url, data, format="json")

        assert response.status_code == status.HTTP_200_OK
        assert len(mail.outbox) == 2
