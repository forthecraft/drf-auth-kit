from typing import Any
from unittest.mock import MagicMock
from urllib.parse import parse_qs

from django.contrib.auth.models import User
from django.urls import reverse
from rest_framework import status
from rest_framework.response import Response
from rest_framework.test import APITestCase

import pytest
import responses
from allauth.socialaccount.models import (  # pyright: ignore[reportMissingTypeStubs]
    SocialAccount,
    SocialApp,
)
from auth_kit.social.utils import get_social_login_callback_url
from auth_kit.social.views import SocialLoginView
from auth_kit.test_utils import override_auth_kit_settings

from .helper import SocialTestMixin


class SocialLoginTestCase(SocialTestMixin, APITestCase):
    """Base test case for social login functionality."""


class TestSocialLoginWithTokenView(SocialLoginTestCase):

    @responses.activate
    @override_auth_kit_settings(SOCIAL_LOGIN_AUTH_TYPE="token")
    def test_google_login_with_token_success(self) -> None:
        self.mock_oauth_responses("google")

        url = reverse("rest_social_google_login")
        data = {"access_token": "test-google-access-token"}

        response: Response = self.client.post(url, data, format="json")

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

        # Check user data
        user_data = response.data["user"]

        user = self.assert_user_created_correctly(user_data["email"], "google")
        self.assert_social_account_created(user, "google")

    @responses.activate
    @override_auth_kit_settings(SOCIAL_LOGIN_AUTH_TYPE="token")
    def test_github_login_with_token_success(self) -> None:
        self.mock_oauth_responses("github")

        url = reverse("rest_social_github_login")
        data = {"access_token": "test-github-access-token"}

        response: Response = self.client.post(url, data, format="json")

        assert response.status_code == status.HTTP_200_OK

        # Check user data
        user_data = response.data["user"]
        assert user_data["email"] == "test@example.com"

        user = self.assert_user_created_correctly(user_data["email"], "github")
        self.assert_social_account_created(user, "github")


class TestSocialLoginWithCodeView(SocialLoginTestCase):
    """Test social login using authorization codes (server-side OAuth)."""

    @responses.activate
    def test_google_login_with_code_success(self) -> None:
        self.mock_oauth_responses("google")

        url = reverse("rest_social_google_login")
        data = {"code": "test-authorization-code"}

        response: Response = self.client.post(url, data, format="json")

        assert response.status_code == status.HTTP_200_OK

        # Verify token exchange was called with correct parameters
        token_request = responses.calls[0].request

        assert token_request.url == "https://oauth2.googleapis.com/token"
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

        # Check user data
        user_data = response.data["user"]
        user = self.assert_user_created_correctly(user_data["email"], "google")
        self.assert_social_account_created(user, "google")

    @responses.activate
    def test_github_login_with_code_success(self) -> None:
        self.mock_oauth_responses("github")

        url = reverse("rest_social_github_login")
        data = {"code": "test-authorization-code"}

        response: Response = self.client.post(url, data, format="json")

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

        # Check user data
        user_data = response.data["user"]
        user = self.assert_user_created_correctly(user_data["email"], "github")
        self.assert_social_account_created(user, "github")

    @responses.activate
    def test_facebook_login_with_code_success(self) -> None:
        self.mock_oauth_responses("facebook")

        url = reverse("rest_social_facebook_login")
        data = {"code": "test-authorization-code"}

        response: Response = self.client.post(url, data, format="json")

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

        # Check user data
        user_data = response.data["user"]
        user = self.assert_user_created_correctly(user_data["email"], "facebook")
        self.assert_social_account_created(user, "facebook")

    @responses.activate
    def test_linked_in_login_with_code_success(self) -> None:
        self.mock_oauth_responses("linkedin")

        url = reverse("rest_social_linkedin_login")
        data = {"code": "test-authorization-code"}

        response: Response = self.client.post(url, data, format="json")

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

        # Check user data
        user_data = response.data["user"]
        user = self.assert_user_created_correctly(user_data["email"], "linkedin")
        self.assert_social_account_created(user, "linkedin")

    @responses.activate
    def test_social_login_invalid_code(self) -> None:
        # Mock failed token exchange
        responses.add(
            responses.POST,
            "https://oauth2.googleapis.com/token",
            json={
                "error": "invalid_grant",
                "error_description": "Invalid authorization code",
            },
            status=400,
        )

        url = reverse("rest_social_google_login")
        data = {"code": "invalid-code"}

        response: Response = self.client.post(url, data, format="json")

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "Failed to exchange code for access token" in str(response.data)

    @override_auth_kit_settings(SOCIAL_HIDE_AUTH_ERROR_DETAILS=False)
    @responses.activate
    def test_social_login_detailed_error_message(self) -> None:
        # Mock failed token exchange with specific error
        error_response = {
            "error": "invalid_client",
            "error_description": "The OAuth client was not found.",
        }
        responses.add(
            responses.POST,
            "https://oauth2.googleapis.com/token",
            json=error_response,
            status=401,
        )

        url = reverse("rest_social_google_login")
        data = {"code": "test-code"}

        response: Response = self.client.post(url, data, format="json")

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        # Should show detailed error when SOCIAL_HIDE_AUTH_ERROR_DETAILS=False
        assert "The OAuth client was not found" in str(response.data)

    @responses.activate
    def test_social_login_user_info_request_fails(self) -> None:
        # Mock successful token exchange
        responses.add(
            responses.POST,
            "https://oauth2.googleapis.com/token",
            json=self.GOOGLE_TOKEN_RESPONSE,
            status=200,
        )

        # Mock failed user info request
        responses.add(
            responses.GET,
            "https://www.googleapis.com/oauth2/v2/userinfo",
            json={"error": {"code": 401, "message": "Invalid token"}},
            status=401,
        )

        url = reverse("rest_social_google_login")
        data = {"code": "test-authorization-code"}

        response: Response = self.client.post(url, data, format="json")

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "Failed to complete OAuth flow" in str(response.data)

    @responses.activate
    def test_social_login_missing_required_fields(self) -> None:
        url = reverse("rest_social_google_login")
        data: dict[str, Any] = {}  # Missing required fields

        response: Response = self.client.post(url, data, format="json")

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "code" in str(response.data)

    def test_social_login_view_without_adapter_class_raises_error(self) -> None:
        """Test that SocialLoginView raises ValueError when adapter_class is not defined."""

        # Create a SocialLoginView subclass without adapter_class
        class InvalidSocialLoginView(SocialLoginView):
            pass  # Missing adapter_class attribute

        with pytest.raises(ValueError) as exc_info:
            InvalidSocialLoginView()

        assert str(exc_info.value) == "adapter_class is not defined"

    @responses.activate
    @override_auth_kit_settings(
        SOCIAL_LOGIN_CALLBACK_BASE_URL="https://example.com/callback"
    )
    def test_social_login_with_custom_callback_base_url(self) -> None:
        self.mock_oauth_responses("google")

        url = reverse("rest_social_google_login")
        data = {"code": "test-authorization-code"}

        response: Response = self.client.post(url, data, format="json")

        assert response.status_code == status.HTTP_200_OK

        # Verify token exchange was called with correct parameters
        token_request = responses.calls[0].request

        body = str(token_request.body)

        qs = parse_qs(body)
        assert qs["redirect_uri"] == ["https://example.com/callback/google"]
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

    def test_social_login_with_direct_callback_url_on_view(self) -> None:
        self.mock_oauth_responses("google")

        # Create mock view with callback_url attribute
        mock_view = MagicMock()
        mock_view.callback_url = "https://myapp.com/custom/google/callback"

        # Create mock social app
        mock_social_app = MagicMock(spec=SocialApp)
        mock_social_app.provider = "google"
        mock_social_app.name = "Google"

        # Create mock request
        mock_request = MagicMock()

        # Test the callback URL generation
        callback_url = get_social_login_callback_url(
            mock_request, mock_view, mock_social_app
        )

        # Should use the direct callback_url from the view
        assert callback_url == "https://myapp.com/custom/google/callback"

    @responses.activate
    @override_auth_kit_settings(SOCIAL_HIDE_AUTH_ERROR_DETAILS=False)
    def test_oauth_error_with_raw_details(self) -> None:
        responses.add(
            responses.POST,
            "https://oauth2.googleapis.com/token",
            json=self.GOOGLE_TOKEN_RESPONSE,
            status=200,
        )

        # Mock failed user info request that will trigger OAuth2Error
        responses.add(
            responses.GET,
            "https://www.googleapis.com/oauth2/v2/userinfo",
            json={"error": {"code": 401, "message": "Invalid credentials"}},
            status=401,
        )

        url = reverse("rest_social_google_login")
        data = {"code": "test-authorization-code"}

        response: Response = self.client.post(url, data, format="json")

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "Request to user info failed" in str(response.data)

    @responses.activate
    @override_auth_kit_settings(SOCIAL_LOGIN_AUTO_CONNECT_BY_EMAIL=False)
    def test_existing_user_with_auto_connect_disabled_and_not_connected(self) -> None:
        # Create existing user with same email
        User.objects.create_user(
            username="existinguser", email="test@example.com", password="password123"
        )

        self.mock_oauth_responses("google")

        url = reverse("rest_social_google_login")
        data = {"code": "test-authorization-code"}
        response: Response = self.client.post(url, data, format="json")

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "User is already registered with this e-mail address" in str(
            response.data
        )

    @responses.activate
    @override_auth_kit_settings(SOCIAL_LOGIN_AUTO_CONNECT_BY_EMAIL=False)
    def test_existing_user_with_auto_connect_disabled_and_connected(self) -> None:
        # Create existing user with same email
        user = User.objects.create_user(
            username="existinguser", email="test@example.com", password="password123"
        )
        SocialAccount.objects.create(user=user, provider="google", uid="123456789")

        self.mock_oauth_responses("google")

        url = reverse("rest_social_google_login")
        data = {"code": "test-authorization-code"}
        response: Response = self.client.post(url, data, format="json")

        assert response.status_code == status.HTTP_200_OK
        expected_fields = {
            "access",
            "refresh",
            "access_expiration",
            "refresh_expiration",
            "user",
        }
        actual_fields = set(response.data.keys())
        assert expected_fields.issubset(actual_fields)

    @responses.activate
    @override_auth_kit_settings(SOCIAL_LOGIN_AUTO_CONNECT_BY_EMAIL=True)
    def test_existing_user_with_auto_connect_enable(self) -> None:
        # Create existing user with same email
        User.objects.create_user(
            username="existinguser", email="test@example.com", password="password123"
        )

        self.mock_oauth_responses("google")

        url = reverse("rest_social_google_login")
        data = {"code": "test-authorization-code"}
        response: Response = self.client.post(url, data, format="json")

        assert response.status_code == status.HTTP_200_OK
        expected_fields = {
            "access",
            "refresh",
            "access_expiration",
            "refresh_expiration",
            "user",
        }
        actual_fields = set(response.data.keys())
        assert expected_fields.issubset(actual_fields)
