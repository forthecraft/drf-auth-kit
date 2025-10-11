"""Tests for Auth Kit UI view."""

from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase

import responses
from allauth.socialaccount.models import SocialAccount, SocialApp  # pyright: ignore
from auth_kit.test_utils import override_auth_kit_settings

from test_utils.user_factory import UserFactory


class TestAuthKitUIView(APITestCase):
    """Test cases for the comprehensive Auth Kit UI view."""

    def test_view_accessible_to_all_users(self) -> None:
        """Test that both authenticated and unauthenticated users can access the UI."""
        # Unauthenticated
        response = self.client.get(reverse("auth_kit_ui"))
        assert response.status_code == status.HTTP_200_OK
        assert response.context["is_authenticated"] is False

        # Authenticated
        user = UserFactory.create(username="testuser", email="test@example.com")
        self.client.force_authenticate(user=user)
        response = self.client.get(reverse("auth_kit_ui"))
        assert response.status_code == status.HTTP_200_OK
        assert response.context["is_authenticated"] is True

    def test_context_contains_required_variables(self) -> None:
        """Test that context includes all required variables."""
        response = self.client.get(reverse("auth_kit_ui"))

        assert response.status_code == status.HTTP_200_OK
        # Auth settings
        assert response.context["auth_type"] == "jwt"
        assert response.context["use_auth_cookie"] is True
        assert response.context["has_social_auth"] is True

        # Field detection
        assert response.context["username_field"] == "username"
        assert response.context["login_uses_username"] is True
        assert response.context["has_username_field"] is True

    def test_username_field_value_handling(self) -> None:
        """Test username field value for authenticated and unauthenticated users."""
        # Unauthenticated - should be empty
        response = self.client.get(reverse("auth_kit_ui"))
        assert response.context["username_field_value"] == ""

        # Authenticated - should have user's username
        user = UserFactory.create(username="testuser")
        self.client.force_authenticate(user=user)
        response = self.client.get(reverse("auth_kit_ui"))
        assert response.context["username_field_value"] == "testuser"

    @override_auth_kit_settings(USE_MFA=True, AUTH_TYPE="token", USE_AUTH_COOKIE=False)
    def test_settings_reflected_in_context(self) -> None:
        """Test that auth_kit settings are reflected in context."""
        response = self.client.get(reverse("auth_kit_ui"))

        assert response.status_code == status.HTTP_200_OK
        assert response.context["use_mfa"] is True
        assert response.context["auth_type"] == "token"
        assert response.context["use_auth_cookie"] is False


class TestAuthKitUIViewWithSocial(APITestCase):
    """Test cases for Auth Kit UI view with social authentication."""

    def test_social_context_variables(self) -> None:
        """Test that social providers and connections are in context."""
        # Mock LinkedIn OpenID Connect config to avoid external HTTP requests
        with responses.RequestsMock() as rsps:
            rsps.add(
                responses.GET,
                "https://www.linkedin.com/oauth/.well-known/openid-configuration",
                json={
                    "issuer": "https://www.linkedin.com/oauth",
                    "authorization_endpoint": (
                        "https://www.linkedin.com/oauth/v2/authorization"
                    ),
                    "token_endpoint": "https://www.linkedin.com/oauth/v2/accessToken",
                    "userinfo_endpoint": "https://api.linkedin.com/v2/userinfo",
                },
                status=200,
            )

            # Unauthenticated - should have providers but no connections
            response = self.client.get(reverse("auth_kit_ui"))
            assert response.status_code == status.HTTP_200_OK
            assert "social_providers" in response.context
            assert "social_connections" in response.context
            assert isinstance(response.context["social_providers"], list)
            assert isinstance(response.context["social_connections"], list)

            # Authenticated with no connections
            user = UserFactory.create(username="testuser")
            self.client.force_authenticate(user=user)
            response = self.client.get(reverse("auth_kit_ui"))
            assert response.context["social_connections"] == []

    def test_without_social_auth_installed(self) -> None:
        """Test UI when social auth is not installed."""
        from unittest.mock import patch

        with patch("auth_kit.views.ui.HAS_SOCIAL_AUTH", False):
            response = self.client.get(reverse("auth_kit_ui"))

            assert response.status_code == status.HTTP_200_OK
            assert response.context["social_providers"] == []
            assert response.context["social_connections"] == []

    def test_with_no_social_providers_configured(self) -> None:
        """Test when social auth is installed but no providers configured."""
        from unittest.mock import MagicMock, patch

        mock_adapter = MagicMock()
        mock_adapter.list_apps.return_value = []

        with patch("auth_kit.views.ui.get_social_adapter", return_value=mock_adapter):
            response = self.client.get(reverse("auth_kit_ui"))

            assert response.status_code == status.HTTP_200_OK
            assert response.context["social_providers"] == []

    def test_social_connection_with_missing_social_app(self) -> None:
        """Test social connection when SocialApp doesn't exist."""

        user = UserFactory.create(username="testuser")
        self.client.force_authenticate(user=user)

        # Create a SocialAccount without corresponding SocialApp
        SocialAccount.objects.create(user=user, provider="nonexistent", uid="12345")

        response = self.client.get(reverse("auth_kit_ui"))

        assert response.status_code == status.HTTP_200_OK
        assert "social_connections" in response.context
        connections = response.context["social_connections"]
        assert len(connections) == 1
        # Should use fallback display name
        assert connections[0]["name"] == "Nonexistent"
        assert connections[0]["provider"] == "nonexistent"

    def test_social_connection_with_existing_social_app(self) -> None:
        """Test social connection when SocialApp exists (success path)."""

        user = UserFactory.create(username="testuser")
        self.client.force_authenticate(user=user)

        # Create a SocialApp and corresponding SocialAccount
        SocialApp.objects.create(
            provider="github", name="GitHub", client_id="test_id", secret="test_secret"
        )
        SocialAccount.objects.create(user=user, provider="github", uid="12345")

        response = self.client.get(reverse("auth_kit_ui"))

        assert response.status_code == status.HTTP_200_OK
        assert "social_connections" in response.context
        connections = response.context["social_connections"]
        assert len(connections) == 1
        # Should use display name from social app
        assert connections[0]["name"] == "GitHub"
        assert connections[0]["provider"] == "github"
        assert connections[0]["uid"] == "12345"
