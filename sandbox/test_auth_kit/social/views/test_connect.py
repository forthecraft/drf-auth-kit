from unittest.mock import MagicMock
from urllib.parse import parse_qs

from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework import status
from rest_framework.response import Response
from rest_framework.test import APITestCase

import responses
from allauth.socialaccount.models import (  # pyright: ignore[reportMissingTypeStubs]
    SocialAccount,
    SocialApp,
)
from auth_kit.social.utils import get_social_connect_callback_url
from auth_kit.test_utils import override_auth_kit_settings

from test_utils.user_factory import UserFactory

from .helper import SocialTestMixin

User = get_user_model()


class SocialConnectTestCase(SocialTestMixin, APITestCase):
    """Base test case for social connect functionality."""


class TestSocialLoginWithCodeView(SocialConnectTestCase):
    """Test social connect using authorization codes (server-side OAuth)."""

    def setUp(self) -> None:
        self.user_data = {
            "username": "testuser",
            "email": "test@example.com",
            "password": "complexpass123",
        }
        self.user, _ = UserFactory.create_with_email_address(self.user_data)

    @responses.activate
    def test_google_connect_with_code_success(self) -> None:
        self.mock_oauth_responses("google")
        self.client.force_authenticate(user=self.user)

        url = reverse("rest_social_google_connect")
        data = {"code": "test-authorization-code"}

        assert SocialAccount.objects.count() == 0

        response: Response = self.client.post(url, data, format="json")

        assert response.status_code == status.HTTP_200_OK

        assert response.data["detail"] == "Connected"

        # Check user data
        self.assert_social_account_created(self.user, "google")

    @responses.activate
    def test_linked_in_connect_with_code_success(self) -> None:
        self.mock_oauth_responses("linkedin")
        self.client.force_authenticate(user=self.user)

        url = reverse("rest_social_linkedin_connect")
        data = {"code": "test-authorization-code"}

        assert SocialAccount.objects.count() == 0

        response: Response = self.client.post(url, data, format="json")

        assert response.status_code == status.HTTP_200_OK

        assert response.data["detail"] == "Connected"

        # Check user data
        self.assert_social_account_created(self.user, "linkedin")

    @responses.activate
    @override_auth_kit_settings(SOCIAL_CONNECT_REQUIRE_EMAIL_MATCH=True)
    def test_google_connect_with_different_email_error_when_enforced(self) -> None:
        self.mock_oauth_responses("google")
        other_data = {
            "username": "other",
            "password": "complexpass123",
            "email": "other@example.com",
        }
        other_user, _ = UserFactory.create_with_email_address(other_data)
        self.client.force_authenticate(user=other_user)

        url = reverse("rest_social_google_connect")
        data = {"code": "test-authorization-code"}

        assert SocialAccount.objects.count() == 0

        response: Response = self.client.post(url, data, format="json")

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "Social account email must match your current account email." in str(
            response.data
        )

        assert SocialAccount.objects.count() == 0

    @responses.activate
    @override_auth_kit_settings(SOCIAL_CONNECT_REQUIRE_EMAIL_MATCH=False)
    def test_google_connect_with_different_email_ok_when_not_enforced(self) -> None:
        self.mock_oauth_responses("google")
        other_data = {
            "username": "other",
            "password": "complexpass123",
            "email": "other@example.com",
        }
        other_user, _ = UserFactory.create_with_email_address(other_data)
        self.client.force_authenticate(user=other_user)

        url = reverse("rest_social_google_connect")
        data = {"code": "test-authorization-code"}

        assert SocialAccount.objects.count() == 0

        response: Response = self.client.post(url, data, format="json")

        assert response.status_code == status.HTTP_200_OK
        assert response.data["detail"] == "Connected"

        self.assert_social_account_created(other_user, "google")

    @responses.activate
    @override_auth_kit_settings(
        SOCIAL_CONNECT_CALLBACK_BASE_URL="https://example.com/connect/callback"
    )
    def test_social_connect_with_custom_base_url(self) -> None:
        self.mock_oauth_responses("google")
        self.client.force_authenticate(user=self.user)

        url = reverse("rest_social_google_connect")
        data = {"code": "test-authorization-code"}

        assert SocialAccount.objects.count() == 0

        response: Response = self.client.post(url, data, format="json")

        assert response.status_code == status.HTTP_200_OK

        assert response.data["detail"] == "Connected"

        token_request = responses.calls[0].request

        body = str(token_request.body)

        qs = parse_qs(body)
        assert qs["redirect_uri"] == ["https://example.com/connect/callback/google"]

    def test_social_connect_with_direct_callback_url_on_view(self) -> None:
        mock_view = MagicMock()
        mock_view.connect_callback_url = "https://myapp.com/custom/google/callback"

        # Create mock social app
        mock_social_app = MagicMock(spec=SocialApp)
        mock_social_app.provider = "google"
        mock_social_app.name = "Google"

        # Create mock request
        mock_request = MagicMock()

        # Test the callback URL generation
        callback_url = get_social_connect_callback_url(
            mock_request, mock_view, mock_social_app
        )

        # Should use the direct callback_url from the view
        assert callback_url == "https://myapp.com/custom/google/callback"
