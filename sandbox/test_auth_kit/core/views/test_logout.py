from typing import Any
from unittest.mock import MagicMock, patch

from django.contrib.auth import get_user_model
from django.test import override_settings
from django.urls import reverse
from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.response import Response
from rest_framework.test import APITestCase

from auth_kit.serializers.logout import get_logout_serializer
from auth_kit.test_utils import override_auth_kit_settings
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import RefreshToken

from test_utils.user_factory import UserFactory

User = get_user_model()


class TestLogoutView(APITestCase):
    def setUp(self) -> None:
        self.user_data = {
            "username": "testuser",
            "email": "test@example.com",
            "password": "complexpass123",
        }
        self.user, _ = UserFactory.create_with_email_address(self.user_data)
        self.url = reverse("rest_logout")

    def test_logout_unauthenticated(self) -> None:
        """Test logout without authentication"""
        response: Response = self.client.post(self.url, format="json")

        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_logout_jwt_success_with_cookie(self) -> None:
        """Test successful JWT logout with cookie"""
        # Authenticate user
        self.client.force_authenticate(user=self.user)

        # Create refresh token
        refresh_token = RefreshToken.for_user(self.user)

        # Set refresh token in cookie
        self.client.cookies["auth-refresh-jwt"] = str(refresh_token)

        response: Response = self.client.post(self.url, format="json")

        assert response.status_code == status.HTTP_200_OK
        assert response.data["detail"] == "Successfully logged out."

        # Verify cookies are cleared
        assert "auth-jwt" in response.cookies
        assert "auth-refresh-jwt" in response.cookies

    @override_auth_kit_settings(USE_AUTH_COOKIE=False)
    def test_logout_jwt_success_with_request_data(self) -> None:
        """Test successful JWT logout with refresh token in request data"""
        # Authenticate user
        self.client.force_authenticate(user=self.user)

        # Create refresh token
        refresh_token = RefreshToken.for_user(self.user)

        data = {"refresh": str(refresh_token)}
        response: Response = self.client.post(self.url, data, format="json")

        assert response.status_code == status.HTTP_200_OK
        assert response.data["detail"] == "Successfully logged out."

    @override_auth_kit_settings(USE_AUTH_COOKIE=False)
    def test_logout_jwt_no_cookie_mode(self) -> None:
        """Test JWT logout when not using cookies"""
        get_logout_serializer.cache_clear()

        # Authenticate user
        self.client.force_authenticate(user=self.user)

        # Create refresh token
        refresh_token = RefreshToken.for_user(self.user)

        data = {"refresh": str(refresh_token)}
        response: Response = self.client.post(self.url, data, format="json")

        assert response.status_code == status.HTTP_200_OK
        assert response.data["detail"] == "Successfully logged out."

    @override_auth_kit_settings(USE_AUTH_COOKIE=False)
    def test_logout_jwt_missing_refresh_token_no_cookie(self) -> None:
        """Test JWT logout without refresh token when not using cookies"""
        get_logout_serializer.cache_clear()

        # Authenticate user
        self.client.force_authenticate(user=self.user)

        data: dict[str, Any] = {}  # No refresh token
        response = self.client.post(self.url, data, format="json")

        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert (
            "Refresh token was not included in request data" in response.data["detail"]
        )

    def test_logout_jwt_missing_refresh_token_with_cookie(self) -> None:
        """Test JWT logout without refresh token cookie when using cookies"""
        # Authenticate user
        self.client.force_authenticate(user=self.user)

        # Don't set refresh token cookie
        response: Response = self.client.post(self.url, format="json")

        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert (
            "Refresh token was not included in cookie data" in response.data["detail"]
        )

    @override_auth_kit_settings(USE_AUTH_COOKIE=False)
    def test_logout_jwt_invalid_refresh_token(self) -> None:
        """Test JWT logout with invalid refresh token"""
        # Authenticate user
        self.client.force_authenticate(user=self.user)

        data = {"refresh": "invalid-token"}
        response: Response = self.client.post(self.url, data, format="json")

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "detail" in response.data

    @override_settings(
        INSTALLED_APPS=[
            "django.contrib.auth",
            "django.contrib.contenttypes",
            "rest_framework",
            "rest_framework_simplejwt",
            "rest_framework_simplejwt.token_blacklist",  # Include blacklist
            "auth_kit",
        ]
    )
    def test_logout_jwt_with_blacklist_success(self) -> None:
        """Test JWT logout with token blacklisting enabled"""
        # Authenticate user
        self.client.force_authenticate(user=self.user)

        # Create refresh token
        refresh_token = RefreshToken.for_user(self.user)

        # Set refresh token in cookie
        self.client.cookies["auth-refresh-jwt"] = str(refresh_token)

        response: Response = self.client.post(self.url, format="json")

        assert response.status_code == status.HTTP_200_OK
        assert response.data["detail"] == "Successfully logged out."

    @override_settings(
        INSTALLED_APPS=[
            "django.contrib.auth",
            "django.contrib.contenttypes",
            "rest_framework",
            "rest_framework_simplejwt",
            # No token_blacklist app
            "auth_kit",
        ]
    )
    def test_logout_jwt_without_blacklist(self) -> None:
        """Test JWT logout without token blacklisting app"""
        # Authenticate user
        self.client.force_authenticate(user=self.user)

        # Create refresh token
        refresh_token = RefreshToken.for_user(self.user)

        # Set refresh token in cookie
        self.client.cookies["auth-refresh-jwt"] = str(refresh_token)

        response: Response = self.client.post(self.url, format="json")

        assert response.status_code == status.HTTP_200_OK
        assert response.data["detail"] == "Successfully logged out."

    @patch("rest_framework_simplejwt.tokens.RefreshToken.blacklist")
    def test_logout_jwt_blacklist_error(self, mock_blacklist: MagicMock) -> None:
        """Test JWT logout when blacklist raises an error"""
        # Mock blacklist to raise TokenError
        mock_blacklist.side_effect = TokenError("Token is blacklisted")

        # Authenticate user
        self.client.force_authenticate(user=self.user)

        # Create refresh token
        refresh_token = RefreshToken.for_user(self.user)

        # Set refresh token in cookie
        self.client.cookies["auth-refresh-jwt"] = str(refresh_token)

        response: Response = self.client.post(self.url, format="json")

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "Token is blacklisted" in response.data["detail"]

    @override_auth_kit_settings(AUTH_TYPE="token")
    def test_logout_token_success(self) -> None:
        """Test successful DRF token logout"""
        get_logout_serializer.cache_clear()

        # Create token for user
        token = Token.objects.create(user=self.user)

        # Authenticate user
        self.client.force_authenticate(user=self.user, token=token)

        response: Response = self.client.post(self.url, format="json")

        assert response.status_code == status.HTTP_200_OK
        assert response.data["detail"] == "Successfully logged out."

        # Verify token was deleted
        assert not Token.objects.filter(user=self.user).exists()

    @override_auth_kit_settings(AUTH_TYPE="token")
    def test_logout_token_with_cookie(self) -> None:
        """Test DRF token logout with cookie clearing"""
        get_logout_serializer.cache_clear()

        # Create token for user
        token = Token.objects.create(user=self.user)

        # Authenticate user
        self.client.force_authenticate(user=self.user, token=token)

        response: Response = self.client.post(self.url, format="json")

        assert response.status_code == status.HTTP_200_OK
        assert response.data["detail"] == "Successfully logged out."

        # Verify token cookie is cleared
        assert "auth-token" in response.cookies

    @override_auth_kit_settings(AUTH_TYPE="token")
    def test_logout_token_no_token_exists(self) -> None:
        """Test DRF token logout when user has no token"""
        get_logout_serializer.cache_clear()

        # Authenticate user without creating token
        self.client.force_authenticate(user=self.user)

        response: Response = self.client.post(self.url, format="json")

        # Should still succeed
        assert response.status_code == status.HTTP_200_OK
        assert response.data["detail"] == "Successfully logged out."

    @override_auth_kit_settings(AUTH_TYPE="token", USE_AUTH_COOKIE=False)
    def test_logout_token_with_auth_cookie_disabled(self) -> None:
        """Test DRF token logout with USE_AUTH_COOKIE=False skips unset_token_cookie"""
        get_logout_serializer.cache_clear()

        # Create token for user
        token = Token.objects.create(user=self.user)

        # Authenticate user
        self.client.force_authenticate(user=self.user, token=token)

        response: Response = self.client.post(self.url, format="json")

        assert response.status_code == status.HTTP_200_OK
        assert response.data["detail"] == "Successfully logged out."

        # Verify token was deleted from database
        assert not Token.objects.filter(user=self.user).exists()

        # Verify NO token cookie is set/cleared when USE_AUTH_COOKIE=False
        # This covers the case where the if condition is False, so unset_token_cookie is NOT called
        assert "auth-token" not in response.cookies

    @override_auth_kit_settings(AUTH_TYPE="custom")
    def test_logout_custom_auth(self) -> None:
        """Test logout with custom authentication type"""
        get_logout_serializer.cache_clear()

        # Authenticate user
        self.client.force_authenticate(user=self.user)

        response: Response = self.client.post(self.url, format="json")

        assert response.status_code == status.HTTP_200_OK
        assert response.data["detail"] == "Successfully logged out."

    @override_auth_kit_settings(SESSION_LOGIN=True)
    def test_logout_with_session_login(self) -> None:
        """Test logout when session login is enabled"""
        # Authenticate user
        self.client.force_authenticate(user=self.user)

        # Create refresh token
        refresh_token = RefreshToken.for_user(self.user)

        # Set refresh token in cookie
        self.client.cookies["auth-refresh-jwt"] = str(refresh_token)

        response: Response = self.client.post(self.url, format="json")

        assert response.status_code == status.HTTP_200_OK
        assert response.data["detail"] == "Successfully logged out."

    def test_logout_get_method_not_allowed(self) -> None:
        """Test that GET method is not allowed"""
        # Authenticate user
        self.client.force_authenticate(user=self.user)

        response: Response = self.client.get(self.url)

        assert response.status_code == status.HTTP_405_METHOD_NOT_ALLOWED

    def test_logout_put_method_not_allowed(self) -> None:
        """Test that PUT method is not allowed"""
        # Authenticate user
        self.client.force_authenticate(user=self.user)

        response: Response = self.client.put(self.url, {}, format="json")

        assert response.status_code == status.HTTP_405_METHOD_NOT_ALLOWED

    @patch("auth_kit.views.logout.unset_jwt_cookies")
    def test_logout_jwt_unset_cookies_called(
        self, mock_unset_cookies: MagicMock
    ) -> None:
        """Test that JWT logout calls unset_jwt_cookies"""
        # Authenticate user
        self.client.force_authenticate(user=self.user)

        # Create refresh token
        refresh_token = RefreshToken.for_user(self.user)

        # Set refresh token in cookie
        self.client.cookies["auth-refresh-jwt"] = str(refresh_token)

        response: Response = self.client.post(self.url, format="json")

        assert response.status_code == status.HTTP_200_OK
        # Verify unset_jwt_cookies was called
        mock_unset_cookies.assert_called_once()

    @override_auth_kit_settings(AUTH_TYPE="token")
    @patch("auth_kit.views.logout.unset_token_cookie")
    def test_logout_token_unset_cookie_called(
        self, mock_unset_cookie: MagicMock
    ) -> None:
        """Test that token logout calls unset_token_cookie"""
        get_logout_serializer.cache_clear()

        # Create token for user
        token = Token.objects.create(user=self.user)

        # Authenticate user
        self.client.force_authenticate(user=self.user, token=token)

        response: Response = self.client.post(self.url, format="json")

        assert response.status_code == status.HTTP_200_OK
        # Verify unset_token_cookie was called
        mock_unset_cookie.assert_called_once()


class TestLogoutViewEdgeCases(APITestCase):
    """Test edge cases and error scenarios for logout view"""

    def setUp(self) -> None:
        self.user_data = {
            "username": "testuser",
            "email": "test@example.com",
            "password": "complexpass123",
        }
        self.user, _ = UserFactory.create_with_email_address(self.user_data)
        self.url = reverse("rest_logout")

    @patch("rest_framework_simplejwt.tokens.RefreshToken.blacklist")
    def test_logout_jwt_attribute_error(self, mock_blacklist: MagicMock) -> None:
        """Test JWT logout when blacklist raises AttributeError"""
        # Mock blacklist to raise AttributeError
        mock_blacklist.side_effect = AttributeError("No blacklist method")

        # Authenticate user
        self.client.force_authenticate(user=self.user)

        # Create refresh token
        refresh_token = RefreshToken.for_user(self.user)

        # Set refresh token in cookie
        self.client.cookies["auth-refresh-jwt"] = str(refresh_token)

        response: Response = self.client.post(self.url, format="json")

        assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
        assert "An error has occurred" in response.data["detail"]

    @patch("rest_framework_simplejwt.tokens.RefreshToken.blacklist")
    def test_logout_jwt_type_error(self, mock_blacklist: MagicMock) -> None:
        """Test JWT logout when blacklist raises TypeError"""
        # Mock blacklist to raise TypeError
        mock_blacklist.side_effect = TypeError("Invalid type")

        # Authenticate user
        self.client.force_authenticate(user=self.user)

        # Create refresh token
        refresh_token = RefreshToken.for_user(self.user)

        # Set refresh token in cookie
        self.client.cookies["auth-refresh-jwt"] = str(refresh_token)

        response: Response = self.client.post(self.url, format="json")

        assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
        assert "An error has occurred" in response.data["detail"]

    def test_logout_multiple_consecutive_calls(self) -> None:
        """Test multiple consecutive logout calls"""
        # Authenticate user
        self.client.force_authenticate(user=self.user)

        # Create refresh token
        refresh_token = RefreshToken.for_user(self.user)

        # Set refresh token in cookie
        self.client.cookies["auth-refresh-jwt"] = str(refresh_token)

        # First logout
        response: Response = self.client.post(self.url, format="json")
        assert response.status_code == status.HTTP_200_OK

        # Second logout (should handle gracefully)
        response2: Response = self.client.post(self.url, format="json")
        assert response2.status_code == status.HTTP_400_BAD_REQUEST
        assert response2.data["detail"] == "Token is invalid"

    @override_auth_kit_settings(AUTH_TYPE="token")
    def test_logout_token_user_without_auth_token_attribute(self) -> None:
        """Test token logout when user doesn't have auth_token attribute"""
        get_logout_serializer.cache_clear()

        # Create a mock user without auth_token attribute
        mock_user = MagicMock()
        mock_user.auth_token = MagicMock()
        mock_user.auth_token.delete.side_effect = AttributeError("No auth_token")

        self.client.force_authenticate(user=mock_user)

        response: Response = self.client.post(self.url, format="json")

        # Should still succeed even if token deletion fails
        assert response.status_code == status.HTTP_200_OK
        assert response.data["detail"] == "Successfully logged out."
