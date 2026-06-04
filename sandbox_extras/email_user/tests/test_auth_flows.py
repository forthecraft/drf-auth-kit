import re

from django.contrib.auth import get_user_model
from django.core import mail
from django.urls import reverse
from rest_framework import status
from rest_framework.response import Response
from rest_framework.test import APITestCase

from allauth.account.forms import default_token_generator
from allauth.account.models import EmailAddress, get_emailconfirmation_model
from allauth.account.utils import user_pk_to_url_str
from auth_kit.passwordless.serializers.email_link import EmailLinkVerifySerializer
from auth_kit.passwordless.services.token import passwordless_signup_token_service
from auth_kit.test_utils import override_auth_kit_settings
from sandbox.test_utils.user_factory import UserFactory

User = get_user_model()
EmailConfirmationModel = get_emailconfirmation_model()


class TestEmailOnlyAuthFlows(APITestCase):
    """Test authentication flows for email-only user model"""

    def setUp(self) -> None:
        self.user_data = {
            "email": "test@example.com",
            "password": "complexpass123",
        }

    def test_login_with_email_success(self) -> None:
        """Test successful login with email (no username)"""
        UserFactory.create_with_email_address(self.user_data)

        login_data = {
            "email": "test@example.com",
            "password": "complexpass123",
        }

        url = reverse("rest_login")
        response: Response = self.client.post(url, login_data, format="json")

        assert response.status_code == status.HTTP_200_OK

        # Check JWT token fields
        expected_fields = {
            "access",
            "refresh",
            "access_expiration",
            "refresh_expiration",
            "user",
        }
        actual_fields = set(response.data.keys())
        assert expected_fields.issubset(actual_fields)

        # Check user data - should have email, not username
        user_data = response.data["user"]
        assert user_data["email"] == "test@example.com"
        assert "username" not in user_data  # Username should not be present
        assert "pk" in user_data

    def test_login_with_invalid_email(self) -> None:
        """Test login with invalid email credentials"""
        UserFactory.create_with_email_address(self.user_data)

        login_data = {
            "email": "test@example.com",
            "password": "wrongpassword",
        }

        url = reverse("rest_login")
        response: Response = self.client.post(url, login_data, format="json")

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "Unable to log in" in str(response.data)

    def test_register_with_email_only(self) -> None:
        """Test user registration with email-only model"""
        registration_data = {
            "email": "newuser@example.com",
            "password1": "complexpass123",
            "password2": "complexpass123",
        }

        url = reverse("rest_register")
        response: Response = self.client.post(url, registration_data, format="json")

        assert response.status_code == status.HTTP_201_CREATED
        assert "Verification e-mail sent" in response.data["detail"]

        # Verify user was created with email as identifier
        user_exists = User.objects.filter(email="newuser@example.com").exists()
        assert user_exists is True

        user = User.objects.get(email="newuser@example.com")
        assert user.email == "newuser@example.com"
        assert user.username is None  # Username should be None
        assert user.is_active is True

        # Verify email address record
        email_address = EmailAddress.objects.get(user=user)
        assert email_address.email == "newuser@example.com"
        assert not email_address.verified  # Should be unverified initially

        # Verify verification email was sent
        assert len(mail.outbox) == 1
        verification_email = mail.outbox[0]
        assert verification_email.to == ["newuser@example.com"]
        assert "confirm" in verification_email.subject.lower()

    def test_email_verification_success(self) -> None:
        """Test successful email verification"""
        # Create user with unverified email
        user, email_address = UserFactory.create_with_email_address(
            self.user_data, {"verified": False}
        )

        # Create email confirmation
        confirmation = EmailConfirmationModel.create(email_address)

        url = reverse("rest_verify_email")
        data = {"key": confirmation.key}
        response: Response = self.client.post(url, data, format="json")

        assert response.status_code == status.HTTP_200_OK
        assert response.data["detail"] == "ok"

        # Verify email is now verified
        email_address.refresh_from_db()
        assert email_address.verified

    def test_email_verification_invalid_key(self) -> None:
        """Test email verification with invalid key"""
        url = reverse("rest_verify_email")
        data = {"key": "invalid-verification-key"}
        response: Response = self.client.post(url, data, format="json")

        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_resend_email_verification(self) -> None:
        """Test resending email verification"""
        # Create user with unverified email
        user, email_address = UserFactory.create_with_email_address(
            self.user_data, {"verified": False}
        )

        url = reverse("rest_resend_email")
        data = {"email": "test@example.com"}
        response: Response = self.client.post(url, data, format="json")

        assert response.status_code == status.HTTP_200_OK
        assert response.data["detail"] == "ok"

        # Check that verification email was sent
        assert len(mail.outbox) == 1
        assert mail.outbox[0].to == ["test@example.com"]

    def test_password_reset_request(self) -> None:
        """Test password reset request with email"""
        user, _ = UserFactory.create_with_email_address(self.user_data)

        url = reverse("rest_password_reset")
        data = {"email": "test@example.com"}
        response: Response = self.client.post(url, data, format="json")

        assert response.status_code == status.HTTP_200_OK
        assert response.data["detail"] == "Password reset e-mail has been sent."

        # Check that reset email was sent
        assert len(mail.outbox) == 1
        reset_email = mail.outbox[0]
        assert reset_email.to == ["test@example.com"]
        assert "password reset" in reset_email.subject.lower()

        # Verify email contains reset URL with uid and token
        email_body = reset_email.body
        assert "password" in email_body.lower()

        # Extract URL parameters for confirmation test
        url_pattern = r"uid=([a-zA-Z0-9]+).*token=([a-zA-Z0-9\-]+)"
        matches = re.search(url_pattern, email_body)
        assert matches is not None

        # Store for potential use in confirmation test
        self.reset_uid = matches.group(1)
        self.reset_token = matches.group(2)

    def test_password_reset_nonexistent_email(self) -> None:
        """Test password reset with non-existent email"""
        url = reverse("rest_password_reset")
        data = {"email": "nonexistent@example.com"}
        response: Response = self.client.post(url, data, format="json")

        # Should still return success for security reasons
        assert response.status_code == status.HTTP_200_OK
        assert response.data["detail"] == "Password reset e-mail has been sent."

        # No email should be sent
        assert len(mail.outbox) == 0

    def test_password_reset_confirm_success(self) -> None:
        """Test successful password reset confirmation"""
        user, _ = UserFactory.create_with_email_address(self.user_data)

        # Generate valid uid and token
        uid = user_pk_to_url_str(user)
        token = default_token_generator.make_token(user)

        url = reverse("rest_password_reset_confirm")
        data = {
            "uid": uid,
            "token": token,
            "new_password1": "newcomplexpass456",
            "new_password2": "newcomplexpass456",
        }

        response: Response = self.client.post(url, data, format="json")

        assert response.status_code == status.HTTP_200_OK
        assert (
            response.data["detail"] == "Password has been reset with the new password."
        )

        # Verify password was actually changed
        user.refresh_from_db()
        assert user.check_password("newcomplexpass456")
        assert not user.check_password("complexpass123")

    def test_password_reset_confirm_invalid_token(self) -> None:
        """Test password reset confirmation with invalid token"""
        user, _ = UserFactory.create_with_email_address(self.user_data)

        uid = user_pk_to_url_str(user)

        url = reverse("rest_password_reset_confirm")
        data = {
            "uid": uid,
            "token": "invalid-token",
            "new_password1": "newcomplexpass456",
            "new_password2": "newcomplexpass456",
        }

        response: Response = self.client.post(url, data, format="json")

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "token" in response.data

    def test_password_change_authenticated_user(self) -> None:
        """Test password change for authenticated email-only user"""
        user, _ = UserFactory.create_with_email_address(self.user_data)
        self.client.force_authenticate(user=user)

        url = reverse("rest_password_change")
        data = {
            "new_password1": "newnewcomplexpass789",
            "new_password2": "newnewcomplexpass789",
        }

        response: Response = self.client.post(url, data, format="json")

        assert response.status_code == status.HTTP_200_OK
        assert response.data["detail"] == "New password has been saved."

        # Verify password was changed
        user.refresh_from_db()
        assert user.check_password("newnewcomplexpass789")
        assert not user.check_password("complexpass123")

    def test_user_profile_retrieval(self) -> None:
        """Test retrieving user profile for email-only user"""
        user, _ = UserFactory.create_with_email_address(self.user_data)
        self.client.force_authenticate(user=user)

        url = reverse("rest_user")
        response: Response = self.client.get(url)

        assert response.status_code == status.HTTP_200_OK

        user_data = response.data
        assert user_data["email"] == "test@example.com"
        assert user_data["pk"] == user.pk
        assert "username" not in user_data  # Username should not be present

    @override_auth_kit_settings(
        FRONTEND_BASE_URL="https://myapp.com",
        PASSWORD_RESET_CONFIRM_PATH="/reset-password",
    )
    def test_password_reset_custom_url(self) -> None:
        """Test password reset with custom frontend URL and path"""
        user, _ = UserFactory.create_with_email_address(self.user_data)

        url = reverse("rest_password_reset")
        data = {"email": "test@example.com"}
        response: Response = self.client.post(url, data, format="json")

        assert response.status_code == status.HTTP_200_OK
        assert len(mail.outbox) == 1

        email_body = mail.outbox[0].body

        # Verify frontend URL with custom path is used instead of default API endpoint
        assert "https://myapp.com/reset-password?uid=" in email_body
        assert "&token=" in email_body
        assert "/api/auth/password/reset/confirm" not in email_body

        # Verify URL format with regex
        url_pattern = (
            r"https://myapp\.com/reset-password\?uid=[a-zA-Z0-9]+&token=[a-zA-Z0-9\-]+"
        )
        urls = re.findall(url_pattern, email_body)
        assert len(urls) >= 1


class TestPasswordlessSignupWithEmailAsUsername(APITestCase):
    """Signup must not invent a username when email IS the username field."""

    def test_signup_from_token_uses_email_as_username(self) -> None:
        token = passwordless_signup_token_service.make_token("fresh@example.com")

        user = EmailLinkVerifySerializer._signup_from_token(token)

        assert user is not None
        assert user.email == "fresh@example.com"
        assert User.USERNAME_FIELD == "email"
        assert not user.has_usable_password()
        assert EmailAddress.objects.get(user=user, email=user.email).verified

    def test_signup_from_token_rejects_unknown_token(self) -> None:
        assert EmailLinkVerifySerializer._signup_from_token("nope") is None
