"""Integration tests for cookie profiles through the HTTP view stack."""

from django.urls import reverse
from rest_framework import status
from rest_framework.response import Response
from rest_framework.test import APITestCase

from auth_kit.test_utils import override_auth_kit_settings
from rest_framework_simplejwt.tokens import RefreshToken

from test_utils.user_factory import UserFactory

APP_B_ORIGIN = "https://app-b.example.com"

APP_B_PROFILES = {
    APP_B_ORIGIN: {
        "AUTH_JWT_COOKIE_NAME": "app-b-auth-jwt",
        "AUTH_JWT_REFRESH_COOKIE_NAME": "app-b-auth-refresh-jwt",
        "AUTH_TOKEN_COOKIE_NAME": "app-b-auth-token",
    }
}


class TestRefreshProfile(APITestCase):
    def setUp(self) -> None:
        self.user, _ = UserFactory.create_with_email_address(
            {
                "username": "testuser",
                "email": "test@example.com",
                "password": "complexpass123",
            }
        )
        self.url = reverse("token_refresh")

    @override_auth_kit_settings(AUTH_COOKIE_PROFILES=APP_B_PROFILES)
    def test_app_b_refresh_sets_only_app_b_cookie(self) -> None:
        refresh_token = RefreshToken.for_user(self.user)
        self.client.cookies["app-b-auth-refresh-jwt"] = str(refresh_token)

        response: Response = self.client.post(
            self.url, format="json", HTTP_ORIGIN=APP_B_ORIGIN
        )

        assert response.status_code == status.HTTP_200_OK
        assert "app-b-auth-jwt" in response.cookies
        assert "auth-jwt" not in response.cookies

    @override_auth_kit_settings(AUTH_COOKIE_PROFILES=APP_B_PROFILES)
    def test_default_refresh_unaffected_by_profile_config(self) -> None:
        refresh_token = RefreshToken.for_user(self.user)
        self.client.cookies["auth-refresh-jwt"] = str(refresh_token)

        response: Response = self.client.post(self.url, format="json")

        assert response.status_code == status.HTTP_200_OK
        assert "auth-jwt" in response.cookies
        assert "app-b-auth-jwt" not in response.cookies


class TestLoginProfile(APITestCase):
    def setUp(self) -> None:
        UserFactory.create_with_email_address(
            {
                "username": "testuser",
                "email": "test@example.com",
                "password": "complexpass123",
            }
        )
        self.url = reverse("rest_login")
        self.login_data = {"username": "testuser", "password": "complexpass123"}

    @override_auth_kit_settings(AUTH_COOKIE_PROFILES=APP_B_PROFILES)
    def test_app_b_login_sets_app_b_cookies(self) -> None:
        response: Response = self.client.post(
            self.url, self.login_data, format="json", HTTP_ORIGIN=APP_B_ORIGIN
        )

        assert response.status_code == status.HTTP_200_OK
        assert "app-b-auth-jwt" in response.cookies
        assert "app-b-auth-refresh-jwt" in response.cookies
        assert "auth-jwt" not in response.cookies


class TestProfileApiIntegration(APITestCase):
    """End-to-end HTTP flow through the real DRF stack."""

    def setUp(self) -> None:
        UserFactory.create_with_email_address(
            {
                "username": "testuser",
                "email": "test@example.com",
                "password": "complexpass123",
            }
        )
        self.login_url = reverse("rest_login")
        self.logout_url = reverse("rest_logout")
        self.user_url = reverse("rest_user")
        self.login_data = {"username": "testuser", "password": "complexpass123"}

    @override_auth_kit_settings(AUTH_COOKIE_PROFILES=APP_B_PROFILES)
    def test_full_lifecycle_under_profile(self) -> None:
        login = self.client.post(
            self.login_url, self.login_data, format="json", HTTP_ORIGIN=APP_B_ORIGIN
        )
        assert login.status_code == status.HTTP_200_OK
        assert "app-b-auth-jwt" in login.cookies

        me = self.client.get(self.user_url, HTTP_ORIGIN=APP_B_ORIGIN)
        assert me.status_code == status.HTTP_200_OK
        assert me.data["username"] == "testuser"

        logout = self.client.post(self.logout_url, HTTP_ORIGIN=APP_B_ORIGIN)
        assert logout.status_code == status.HTTP_200_OK
        assert logout.cookies["app-b-auth-jwt"].value == ""

    @override_auth_kit_settings(AUTH_COOKIE_PROFILES=APP_B_PROFILES)
    def test_profile_cookie_is_isolated_from_default(self) -> None:
        self.client.post(
            self.login_url, self.login_data, format="json", HTTP_ORIGIN=APP_B_ORIGIN
        )

        # No Origin -> default profile, which reads the absent 'auth-jwt' cookie,
        # so the app-b cookie does not authenticate here.
        me = self.client.get(self.user_url)
        assert me.status_code == status.HTTP_401_UNAUTHORIZED
