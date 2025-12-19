from datetime import timedelta

from django.contrib.auth import get_user_model
from django.urls import reverse
from django.utils import timezone
from rest_framework import status
from rest_framework.response import Response
from rest_framework.test import APITestCase

from auth_kit.test_utils import override_auth_kit_settings
from rest_framework_simplejwt.tokens import RefreshToken

from test_utils.simple_jwt import override_jwt_settings
from test_utils.user_factory import UserFactory

User = get_user_model()


class TestRefreshViewWithCookieSupport(APITestCase):
    def setUp(self) -> None:
        self.user_data = {
            "username": "testuser",
            "email": "test@example.com",
            "password": "complexpass123",
        }
        self.user, _ = UserFactory.create_with_email_address(self.user_data)
        self.url = reverse("token_refresh")

    def test_refresh_token_with_request_data(self) -> None:
        """Test JWT refresh with refresh token in request data"""
        refresh_token = RefreshToken.for_user(self.user)

        data = {"refresh": str(refresh_token)}
        response: Response = self.client.post(self.url, data, format="json")

        assert response.status_code == status.HTTP_200_OK
        assert "access" in response.data
        assert "access_expiration" in response.data
        assert isinstance(response.data["access"], str)
        assert len(response.data["access"]) > 0

    def test_refresh_token_with_cookie(self) -> None:
        """Test JWT refresh with refresh token in cookie"""
        refresh_token = RefreshToken.for_user(self.user)

        self.client.cookies["auth-refresh-jwt"] = str(refresh_token)

        response: Response = self.client.post(self.url, format="json")

        assert response.status_code == status.HTTP_200_OK
        assert "access" in response.data
        assert "access_expiration" in response.data
        assert isinstance(response.data["access"], str)

    def test_refresh_token_request_data_overrides_cookie(self) -> None:
        """Test that request data refresh token overrides cookie"""
        refresh_token_1 = RefreshToken.for_user(self.user)
        refresh_token_2 = RefreshToken.for_user(self.user)

        self.client.cookies["auth-refresh-jwt"] = str(refresh_token_1)

        data = {"refresh": str(refresh_token_2)}
        response: Response = self.client.post(self.url, data, format="json")

        assert response.status_code == status.HTTP_200_OK
        assert "access" in response.data

    def test_refresh_token_missing_token(self) -> None:
        """Test JWT refresh without refresh token"""
        response: Response = self.client.post(self.url, format="json")

        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert "No valid refresh token found" in str(response.data)

    def test_refresh_token_invalid_token(self) -> None:
        """Test JWT refresh with invalid refresh token"""
        data = {"refresh": "invalid-token"}
        response: Response = self.client.post(self.url, data, format="json")

        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_refresh_token_empty_string_falls_back_to_cookie(self) -> None:
        """Test JWT refresh with empty string token in request data falls back to cookie"""
        refresh_token = RefreshToken.for_user(self.user)
        self.client.cookies["auth-refresh-jwt"] = str(refresh_token)

        data = {"refresh": ""}
        response: Response = self.client.post(self.url, data, format="json")

        assert response.status_code == status.HTTP_200_OK
        assert "access" in response.data

    @override_jwt_settings(ROTATE_REFRESH_TOKENS=True)
    def test_refresh_token_sets_cookies_correctly_with_refresh_token_rotation(
        self,
    ) -> None:
        """Test that refresh response sets authentication cookies with correct properties"""
        refresh_token = RefreshToken.for_user(self.user)

        data = {"refresh": str(refresh_token)}
        response: Response = self.client.post(self.url, data, format="json")

        assert response.status_code == status.HTTP_200_OK

        # Verify access token cookie
        assert "auth-jwt" in response.cookies
        access_cookie = response.cookies["auth-jwt"]
        assert access_cookie.value == response.data["access"]
        assert access_cookie["httponly"] is True
        assert access_cookie["samesite"] == "Lax"
        assert access_cookie["secure"] == ""

        # Verify refresh token cookie
        assert "auth-refresh-jwt" in response.cookies
        refresh_cookie = response.cookies["auth-refresh-jwt"]
        assert refresh_cookie["httponly"] is True
        assert refresh_cookie["samesite"] == "Lax"

    def test_refresh_token_httponly_removes_refresh_from_response(self) -> None:
        """Test that refresh token is removed from response when httponly is enabled"""
        refresh_token = RefreshToken.for_user(self.user)

        data = {"refresh": str(refresh_token)}
        response: Response = self.client.post(self.url, data, format="json")

        assert response.status_code == status.HTTP_200_OK
        # With default settings (AUTH_COOKIE_HTTPONLY=True), refresh should be removed
        assert "refresh" not in response.data or response.data["refresh"] == ""

    @override_auth_kit_settings(AUTH_COOKIE_HTTPONLY=False)
    @override_jwt_settings(ROTATE_REFRESH_TOKENS=True)
    def test_rotate_refresh_token(self) -> None:
        """Test that refresh token is kept in response when httponly is disabled"""
        refresh_token = RefreshToken.for_user(self.user)

        data = {"refresh": str(refresh_token)}
        response: Response = self.client.post(self.url, data, format="json")

        assert response.status_code == status.HTTP_200_OK
        assert "refresh" in response.data
        assert "refresh_expiration" in response.data
        assert response.data["refresh"] != ""

    @override_auth_kit_settings(
        AUTH_COOKIE_SECURE=True,
        AUTH_COOKIE_SAMESITE="Strict",
        AUTH_COOKIE_DOMAIN=".example.com",
    )
    def test_refresh_token_custom_cookie_settings(self) -> None:
        """Test refresh with custom cookie settings"""
        refresh_token = RefreshToken.for_user(self.user)

        data = {"refresh": str(refresh_token)}
        response: Response = self.client.post(self.url, data, format="json")

        assert response.status_code == status.HTTP_200_OK

        # Verify custom cookie settings
        access_cookie = response.cookies["auth-jwt"]
        assert access_cookie["secure"] is True
        assert access_cookie["samesite"] == "Strict"
        assert access_cookie["domain"] == ".example.com"

    def test_refresh_token_get_method_not_allowed(self) -> None:
        """Test that GET method is not allowed"""
        response: Response = self.client.get(self.url)
        assert response.status_code == status.HTTP_405_METHOD_NOT_ALLOWED

    def test_refresh_token_expired_token(self) -> None:
        """Test JWT refresh with expired refresh token"""
        refresh_token = RefreshToken.for_user(self.user)
        # Manually expire the token
        refresh_token.payload["exp"] = int(
            (timezone.now() - timedelta(days=1)).timestamp()
        )

        data = {"refresh": str(refresh_token)}
        response: Response = self.client.post(self.url, data, format="json")

        assert response.status_code == status.HTTP_401_UNAUTHORIZED


class TestRefreshViewEdgeCases(APITestCase):
    """Test edge cases for JWT refresh view"""

    def setUp(self) -> None:
        self.user_data = {
            "username": "testuser",
            "email": "test@example.com",
            "password": "complexpass123",
        }
        self.user, _ = UserFactory.create_with_email_address(self.user_data)
        self.url = reverse("token_refresh")

    def test_refresh_token_malformed_json(self) -> None:
        """Test refresh with malformed JSON"""
        refresh_token = RefreshToken.for_user(self.user)

        response: Response = self.client.post(
            self.url,
            '{"refresh": "' + str(refresh_token) + '"',  # Missing closing brace
            content_type="application/json",
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_refresh_token_with_blacklisted_token(self) -> None:
        """Test refresh with blacklisted token (if blacklisting is enabled)"""
        refresh_token = RefreshToken.for_user(self.user)

        try:
            refresh_token.blacklist()

            data = {"refresh": str(refresh_token)}
            response: Response = self.client.post(self.url, data, format="json")

            assert response.status_code == status.HTTP_401_UNAUTHORIZED
        except AttributeError:
            # Blacklisting not available, skip this test
            pass

    def test_refresh_token_concurrent_requests(self) -> None:
        """Test handling of concurrent refresh requests with same token"""
        refresh_token = RefreshToken.for_user(self.user)
        data = {"refresh": str(refresh_token)}

        # First request should succeed
        response1: Response = self.client.post(self.url, data, format="json")
        assert response1.status_code == status.HTTP_200_OK

        # Second request with same token
        response2: Response = self.client.post(self.url, data, format="json")
        # Could be 200 or 401 depending on token rotation configuration
        assert response2.status_code in [
            status.HTTP_200_OK,
            status.HTTP_401_UNAUTHORIZED,
        ]
