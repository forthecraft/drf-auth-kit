"""
Tests for SocialAccountViewSet and SocialAccountSerializer.

These tests cover listing, deleting, and managing social account connections
for authenticated users, including permissions and signal handling.
"""

from unittest.mock import Mock, patch

from django.contrib.auth.models import User
from django.urls import reverse
from rest_framework import status
from rest_framework.response import Response
from rest_framework.test import APITestCase

from allauth.socialaccount import signals  # pyright: ignore[reportMissingTypeStubs]
from allauth.socialaccount.models import (  # pyright: ignore[reportMissingTypeStubs]
    SocialAccount,
)
from auth_kit.social.views.account import SocialAccountViewSet


class TestSocialAccountViewSet(APITestCase):
    """Test SocialAccountViewSet functionality."""

    def setUp(self) -> None:
        """Set up test data."""
        # Create test users
        self.user = User.objects.create_user(
            username="testuser", email="test@example.com", password="testpass123"
        )

        self.other_user = User.objects.create_user(
            username="otheruser", email="other@example.com", password="testpass123"
        )

        # Create social accounts for test user
        self.google_account = SocialAccount.objects.create(
            user=self.user,
            provider="google",
            uid="google-123456",
            extra_data={
                "id": "google-123456",
                "email": "test@example.com",
                "name": "Test User",
                "picture": "https://example.com/avatar.jpg",
            },
        )

        self.github_account = SocialAccount.objects.create(
            user=self.user,
            provider="github",
            uid="github-789012",
            extra_data={
                "id": 789012,
                "login": "testuser",
                "name": "Test User",
                "avatar_url": "https://github.com/avatar.jpg",
            },
        )

        # Create social account for other user
        self.other_account = SocialAccount.objects.create(
            user=self.other_user,
            provider="facebook",
            uid="facebook-345678",
            extra_data={"id": "facebook-345678", "name": "Other User"},
        )

        self.list_url = reverse("social-account-list")

    def test_list_social_accounts_authenticated(self) -> None:
        """Test listing social accounts for authenticated user."""
        self.client.force_authenticate(user=self.user)

        response: Response = self.client.get(self.list_url)

        assert response.status_code == status.HTTP_200_OK
        data = response.data
        assert data["count"] == 2

        # Check that only user's accounts are returned
        account_ids = [account["id"] for account in data["results"]]
        assert self.google_account.pk in account_ids
        assert self.github_account.pk in account_ids
        assert self.other_account.pk not in account_ids

    def test_list_social_accounts_unauthenticated(self) -> None:
        """Test listing social accounts without authentication."""
        response: Response = self.client.get(self.list_url)

        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_list_social_accounts_empty(self) -> None:
        """Test listing social accounts when user has none."""
        # Create user with no social accounts
        user_no_accounts = User.objects.create_user(
            username="noaccounts", email="no@example.com", password="testpass123"
        )

        self.client.force_authenticate(user=user_no_accounts)

        response: Response = self.client.get(self.list_url)

        assert response.status_code == status.HTTP_200_OK
        assert response.data["count"] == 0

    def test_list_social_accounts_response_format(self) -> None:
        """Test the format of social account list response."""
        self.client.force_authenticate(user=self.user)

        response: Response = self.client.get(self.list_url)

        assert response.status_code == status.HTTP_200_OK

        account_data = response.data["results"][0]
        expected_fields = {"id", "provider", "uid", "last_login", "date_joined"}
        actual_fields = set(account_data.keys())

        assert expected_fields.issubset(actual_fields)

        # Verify data types and content
        assert isinstance(account_data["id"], int)
        assert isinstance(account_data["provider"], str)
        assert isinstance(account_data["uid"], str)
        assert account_data["provider"] in ["google", "github"]

    def test_delete_social_account_success(self) -> None:
        """Test successful deletion of social account."""
        self.client.force_authenticate(user=self.user)

        url = reverse("social-account-detail", kwargs={"pk": self.google_account.pk})

        with patch.object(signals.social_account_removed, "send") as mock_signal:
            response: Response = self.client.delete(url)

        assert response.status_code == status.HTTP_204_NO_CONTENT

        # Verify account was deleted
        assert not SocialAccount.objects.filter(pk=self.google_account.pk).exists()

        # Verify signal was sent
        mock_signal.assert_called()

    def test_delete_social_account_unauthenticated(self) -> None:
        """Test deleting social account without authentication."""
        url = reverse("social-account-detail", kwargs={"pk": self.google_account.pk})

        response: Response = self.client.delete(url)

        assert response.status_code == status.HTTP_401_UNAUTHORIZED

        # Verify account was not deleted
        assert SocialAccount.objects.filter(pk=self.google_account.pk).exists()

    def test_delete_other_users_social_account(self) -> None:
        """Test that users cannot delete other users' social accounts."""
        self.client.force_authenticate(user=self.user)

        # Try to delete other user's account
        url = reverse("social-account-detail", kwargs={"pk": self.other_account.pk})

        response: Response = self.client.delete(url)

        assert response.status_code == status.HTTP_404_NOT_FOUND

        # Verify account was not deleted
        assert SocialAccount.objects.filter(pk=self.other_account.pk).exists()

    def test_delete_nonexistent_social_account(self) -> None:
        """Test deleting a non-existent social account."""
        self.client.force_authenticate(user=self.user)

        # Use a non-existent ID
        url = reverse("social-account-detail", kwargs={"pk": 99999})

        response: Response = self.client.delete(url)

        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_get_queryset_filters_by_user(self) -> None:
        """Test that get_queryset properly filters by current user."""
        viewset = SocialAccountViewSet()

        # Mock request with user
        viewset.request = Mock()
        viewset.request.user = self.user

        queryset = viewset.get_queryset()

        # Should only return accounts for the authenticated user
        assert queryset.count() == 2
        assert self.google_account in queryset
        assert self.github_account in queryset
        assert self.other_account not in queryset

    def test_perform_destroy_sends_signal(self) -> None:
        """Test that perform_destroy sends the social_account_removed signal."""
        viewset = SocialAccountViewSet()
        viewset.request = Mock()

        with patch.object(signals.social_account_removed, "send") as mock_signal:
            with patch.object(self.google_account, "delete") as mock_delete:
                viewset.perform_destroy(self.google_account)

        # Verify signal was sent before deletion
        mock_signal.assert_called_once_with(
            sender=SocialAccount,
            request=viewset.request,
            socialaccount=self.google_account,
        )

        # Verify delete was called
        mock_delete.assert_called_once()

    def test_create_method_not_allowed(self) -> None:
        """Test that creating social accounts via API is not allowed."""
        self.client.force_authenticate(user=self.user)

        data = {
            "provider": "twitter",
            "uid": "twitter-123",
        }

        response: Response = self.client.post(self.list_url, data, format="json")

        assert response.status_code == status.HTTP_405_METHOD_NOT_ALLOWED

    def test_update_method_not_allowed(self) -> None:
        """Test that updating social accounts via API is not allowed."""
        self.client.force_authenticate(user=self.user)

        url = reverse("social-account-detail", kwargs={"pk": self.google_account.pk})
        data = {"provider": "modified"}

        # Test both PUT and PATCH
        put_response: Response = self.client.put(url, data, format="json")
        patch_response: Response = self.client.patch(url, data, format="json")

        assert put_response.status_code == status.HTTP_405_METHOD_NOT_ALLOWED
        assert patch_response.status_code == status.HTTP_405_METHOD_NOT_ALLOWED

    def test_retrieve_method_not_implemented(self) -> None:
        """Test that retrieving individual social accounts is not available."""
        self.client.force_authenticate(user=self.user)

        url = reverse("social-account-detail", kwargs={"pk": self.google_account.pk})

        response: Response = self.client.get(url)

        # Should return 405 since RetrieveModelMixin is not included
        assert response.status_code == status.HTTP_405_METHOD_NOT_ALLOWED
