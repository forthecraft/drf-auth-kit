from datetime import timedelta
from typing import Any

from django.contrib.auth import get_user_model
from django.utils import timezone
from rest_framework.authtoken.models import Token
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.test import APIRequestFactory, APITestCase

import pytest
from auth_kit.authentication import (
    AuthKitCookieAuthentication,
    JWTCookieAuthentication,
    TokenCookieAuthentication,
)
from auth_kit.test_utils import override_auth_kit_settings
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework_simplejwt.tokens import RefreshToken

from test_utils.user_factory import UserFactory

User = get_user_model()


class TestJWTCookieAuthentication(APITestCase):
    def setUp(self) -> None:
        self.user_data = {
            "username": "testuser",
            "email": "test@example.com",
            "password": "complexpass123",
        }
        self.user, _ = UserFactory.create_with_email_address(self.user_data)
        self.factory = APIRequestFactory()
        self.auth_class = JWTCookieAuthentication()

    def test_authenticate_with_valid_header(self) -> None:
        """Test authentication with valid JWT in Authorization header"""
        refresh_token = RefreshToken.for_user(self.user)
        access_token = refresh_token.access_token

        request = self.factory.get("/test/")
        request.META["HTTP_AUTHORIZATION"] = f"Bearer {access_token}"

        result = self.auth_class.authenticate(request)

        assert result is not None
        user, token = result
        assert user == self.user
        assert token is not None

    def test_authenticate_with_valid_cookie(self) -> None:
        """Test authentication with valid JWT in cookie"""
        refresh_token = RefreshToken.for_user(self.user)
        access_token = refresh_token.access_token

        request = self.factory.get("/test/")
        request.COOKIES = {"auth-jwt": str(access_token)}

        result = self.auth_class.authenticate(request)

        assert result is not None
        user, token = result
        assert user == self.user
        assert token is not None

    def test_authenticate_header_takes_priority_over_cookie(self) -> None:
        """Test that Authorization header takes priority over cookie"""
        # Create two different tokens
        refresh_token_1 = RefreshToken.for_user(self.user)
        access_token_1 = refresh_token_1.access_token

        refresh_token_2 = RefreshToken.for_user(self.user)
        access_token_2 = refresh_token_2.access_token

        request = self.factory.get("/test/")
        request.META["HTTP_AUTHORIZATION"] = f"Bearer {access_token_1}"
        request.COOKIES = {"auth-jwt": str(access_token_2)}

        result = self.auth_class.authenticate(request)

        assert result is not None
        user, token = result
        assert user == self.user
        # Should use token from header, not cookie
        assert str(token) == str(access_token_1)

    def test_authenticate_with_invalid_header_token(self) -> None:
        """Test authentication with invalid JWT in header raises exception"""
        request = self.factory.get("/test/")
        request.META["HTTP_AUTHORIZATION"] = "Bearer invalid-token"

        with pytest.raises((InvalidToken, TokenError)):
            self.auth_class.authenticate(request)

    def test_authenticate_with_invalid_cookie_token(self) -> None:
        """Test authentication with invalid JWT in cookie raises exception"""
        request = self.factory.get("/test/")
        request.COOKIES = {"auth-jwt": "invalid-token"}

        with pytest.raises((InvalidToken, TokenError)):
            self.auth_class.authenticate(request)

    def test_authenticate_with_no_token(self) -> None:
        """Test authentication with no token provided"""
        request = self.factory.get("/test/")

        result = self.auth_class.authenticate(request)

        assert result is None

    def test_authenticate_with_empty_cookie(self) -> None:
        """Test authentication with empty cookie value"""
        request = self.factory.get("/test/")
        request.COOKIES = {"auth-jwt": ""}

        result = self.auth_class.authenticate(request)

        assert result is None

    def test_authenticate_with_malformed_header(self) -> None:
        """Test authentication with malformed Authorization header"""
        request = self.factory.get("/test/")
        request.META["HTTP_AUTHORIZATION"] = "InvalidFormat token"

        result = self.auth_class.authenticate(request)

        assert result is None

    def test_authenticate_with_expired_token(self) -> None:
        """Test JWT authentication with expired token"""
        # Create an expired token
        refresh_token = RefreshToken.for_user(self.user)
        access_token = refresh_token.access_token
        # Manually expire the token
        access_token.payload["exp"] = str(
            (timezone.now() - timedelta(days=1)).timestamp()
        )

        request = self.factory.get("/test/")
        request.COOKIES = {"auth-jwt": str(access_token)}

        with pytest.raises((InvalidToken, TokenError)):
            self.auth_class.authenticate(request)


class TestTokenCookieAuthentication(APITestCase):
    def setUp(self) -> None:
        self.user_data = {
            "username": "testuser",
            "email": "test@example.com",
            "password": "complexpass123",
        }
        self.user, _ = UserFactory.create_with_email_address(self.user_data)
        self.factory = APIRequestFactory()
        self.auth_class = TokenCookieAuthentication()
        self.token = Token.objects.create(user=self.user)

    @override_auth_kit_settings(AUTH_TYPE="token")
    def test_authenticate_with_valid_header(self) -> None:
        """Test authentication with valid token in Authorization header"""
        request = self.factory.get("/test/")
        request.META["HTTP_AUTHORIZATION"] = f"Bearer {self.token.key}"

        result = self.auth_class.authenticate(request)

        assert result is not None
        user, token = result
        assert user == self.user
        assert token == self.token

    @override_auth_kit_settings(AUTH_TYPE="token")
    def test_authenticate_with_valid_cookie(self) -> None:
        """Test authentication with valid token in cookie"""
        request = self.factory.get("/test/")
        request.COOKIES = {"auth-token": self.token.key}

        result = self.auth_class.authenticate(request)

        assert result is not None
        user, token = result
        assert user == self.user
        assert token == self.token

    @override_auth_kit_settings(AUTH_TYPE="token")
    def test_authenticate_header_takes_priority_over_cookie(self) -> None:
        """Test that Authorization header takes priority over cookie"""
        # Create another token
        another_user_data = {
            "username": "anotheruser",
            "email": "another@example.com",
            "password": "password123",
        }
        another_user, _ = UserFactory.create_with_email_address(another_user_data)
        another_token = Token.objects.create(user=another_user)

        request = self.factory.get("/test/")
        request.META["HTTP_AUTHORIZATION"] = f"Bearer {self.token.key}"
        request.COOKIES = {"auth-token": another_token.key}

        result = self.auth_class.authenticate(request)

        assert result is not None
        user, token = result
        # Should authenticate with header token, not cookie
        assert user == self.user
        assert token == self.token

    @override_auth_kit_settings(AUTH_TYPE="token")
    def test_authenticate_with_invalid_header_token(self) -> None:
        """Test authentication with invalid token in header"""
        request = self.factory.get("/test/")
        request.META["HTTP_AUTHORIZATION"] = "Bearer invalid-token"

        with pytest.raises(AuthenticationFailed):
            self.auth_class.authenticate(request)

    def test_authenticate_with_invalid_cookie_token(self) -> None:
        """Test authentication with invalid token in cookie"""
        request = self.factory.get("/test/")
        request.COOKIES = {"auth-token": "invalid-token"}

        with pytest.raises(InvalidToken):
            self.auth_class.authenticate(request)

    @override_auth_kit_settings(AUTH_TYPE="token")
    def test_authenticate_with_no_token(self) -> None:
        """Test authentication with no token provided"""
        request = self.factory.get("/test/")

        result = self.auth_class.authenticate(request)

        assert result is None

    @override_auth_kit_settings(AUTH_TYPE="token")
    def test_authenticate_with_deleted_token(self) -> None:
        """Test token authentication after token is deleted"""
        token_key = str(self.token.key)  # pyright: ignore[reportUnknownArgumentType]

        # Delete the token
        self.token.delete()

        request = self.factory.get("/test/")
        request.COOKIES = {"auth-token": token_key}

        with pytest.raises(AuthenticationFailed):
            self.auth_class.authenticate(request)


class TestCustomAuthentication(APITestCase):
    def setUp(self) -> None:
        self.user_data = {
            "username": "testuser",
            "email": "test@example.com",
            "password": "complexpass123",
        }
        self.user, _ = UserFactory.create_with_email_address(self.user_data)
        self.factory = APIRequestFactory()
        self.auth_class = AuthKitCookieAuthentication()

    @override_auth_kit_settings(AUTH_TYPE="custom")
    def test_authenticate_custom_type(self) -> None:
        """Test _authenticate method with custom auth type"""
        request = self.factory.get("/test/")
        request.COOKIES = {"test-cookie": "custom-token"}

        # Mock custom_authenticate method
        def mock_custom_authenticate(token: str) -> tuple[Any, Any] | None:
            if token == "custom-token":
                return self.user, "custom-token"
            return None

        self.auth_class.custom_authenticate = mock_custom_authenticate  # type: ignore[method-assign]

        result = self.auth_class.authenticate_with_cookie(request, "test-cookie")

        assert result is not None
        user, token = result
        assert user == self.user
        assert token == "custom-token"
