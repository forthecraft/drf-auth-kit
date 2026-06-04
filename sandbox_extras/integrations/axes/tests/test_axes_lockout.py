from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework import status
from rest_framework.response import Response
from rest_framework.test import APITestCase

from axes.models import AccessAttempt
from sandbox.test_utils.user_factory import UserFactory

User = get_user_model()


class TestAxesLockout(APITestCase):
    """Test django-axes integration with auth_kit login."""

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
        self.url = reverse("rest_login")

    def test_login_success_before_lockout(self) -> None:
        """Normal login works when not locked out."""
        UserFactory.create_with_email_address(self.user_data)

        response: Response = self.client.post(self.url, self.login_data, format="json")

        assert response.status_code == status.HTTP_200_OK
        assert "access" in response.data

    def test_failed_login_returns_400(self) -> None:
        """Single failed login returns standard 400 error."""
        UserFactory.create_with_email_address(self.user_data)

        invalid_data = {
            "username": "testuser",
            "password": "wrongpass",
        }
        response: Response = self.client.post(self.url, invalid_data, format="json")

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "Unable to log in" in str(response.data)

    def test_lockout_after_max_failures(self) -> None:
        """After AXES_FAILURE_LIMIT (3) failed attempts, returns 429."""
        UserFactory.create_with_email_address(self.user_data)

        invalid_data = {
            "username": "testuser",
            "password": "wrongpass",
        }

        # First 2 attempts should return 400 (invalid credentials)
        for _ in range(2):
            response = self.client.post(self.url, invalid_data, format="json")
            assert response.status_code == status.HTTP_400_BAD_REQUEST

        # 3rd attempt triggers lockout - should return 429
        response = self.client.post(self.url, invalid_data, format="json")
        assert response.status_code == status.HTTP_429_TOO_MANY_REQUESTS
        assert "Account locked" in str(response.data)

    def test_lockout_persists_with_correct_credentials(self) -> None:
        """Even correct credentials are rejected while locked out."""
        UserFactory.create_with_email_address(self.user_data)

        invalid_data = {
            "username": "testuser",
            "password": "wrongpass",
        }

        # Trigger lockout
        for _ in range(3):
            self.client.post(self.url, invalid_data, format="json")

        # Try with correct password - should still be locked out
        response: Response = self.client.post(self.url, self.login_data, format="json")
        assert response.status_code == status.HTTP_429_TOO_MANY_REQUESTS
        assert "Account locked" in str(response.data)

    def test_lockout_reset_allows_login(self) -> None:
        """After resetting axes, login works again."""
        UserFactory.create_with_email_address(self.user_data)

        invalid_data = {
            "username": "testuser",
            "password": "wrongpass",
        }

        # Trigger lockout
        for _ in range(3):
            self.client.post(self.url, invalid_data, format="json")

        # Reset axes lockout
        AccessAttempt.objects.all().delete()

        # Should be able to login again
        response: Response = self.client.post(self.url, self.login_data, format="json")
        assert response.status_code == status.HTTP_200_OK
        assert "access" in response.data

    def test_different_users_locked_independently(self) -> None:
        """Lockout for one user doesn't affect another."""
        UserFactory.create_with_email_address(self.user_data)

        other_user_data = {
            "username": "otheruser",
            "email": "other@example.com",
            "password": "complexpass456",
        }
        UserFactory.create_with_email_address(other_user_data)

        # Lock out testuser
        invalid_data = {
            "username": "testuser",
            "password": "wrongpass",
        }
        for _ in range(3):
            self.client.post(self.url, invalid_data, format="json")

        # Other user should still be able to login
        other_login = {
            "username": "otheruser",
            "password": "complexpass456",
        }
        response: Response = self.client.post(self.url, other_login, format="json")
        assert response.status_code == status.HTTP_200_OK
