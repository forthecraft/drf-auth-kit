"""Unit tests for cookie profile resolution and helpers."""

from rest_framework.response import Response
from rest_framework.test import APIRequestFactory, APITestCase

from auth_kit.authentication import JWTCookieAuthentication
from auth_kit.checks import check_cookie_profiles
from auth_kit.cookie_profiles import (
    CookieProfile,
    default_cookie_profile,
    resolve_cookie_profile,
)
from auth_kit.jwt_auth import unset_jwt_cookies, unset_token_cookie
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


class TestDefaultProfile(APITestCase):
    def test_default_profile_uses_top_level_settings(self) -> None:
        profile = default_cookie_profile()
        assert profile.jwt_cookie_name == "auth-jwt"
        assert profile.refresh_cookie_name == "auth-refresh-jwt"
        assert profile.token_cookie_name == "auth-token"
        assert profile.jwt_cookie_path == "/"


class TestProfileResolution(APITestCase):
    def setUp(self) -> None:
        self.factory = APIRequestFactory()

    @override_auth_kit_settings(AUTH_COOKIE_PROFILES=APP_B_PROFILES)
    def test_origin_match_applies_overrides_and_falls_back(self) -> None:
        request = self.factory.get("/test/", HTTP_ORIGIN=APP_B_ORIGIN)
        profile = resolve_cookie_profile(request)
        assert profile.jwt_cookie_name == "app-b-auth-jwt"
        assert profile.refresh_cookie_name == "app-b-auth-refresh-jwt"
        assert profile.token_cookie_name == "app-b-auth-token"
        assert profile.jwt_cookie_path == "/"
        assert profile.refresh_cookie_path == "/"

    @override_auth_kit_settings(AUTH_COOKIE_PROFILES=APP_B_PROFILES)
    def test_no_origin_uses_default(self) -> None:
        request = self.factory.get("/test/")
        assert resolve_cookie_profile(request).jwt_cookie_name == "auth-jwt"

    @override_auth_kit_settings(AUTH_COOKIE_PROFILES=APP_B_PROFILES)
    def test_unknown_origin_uses_default(self) -> None:
        request = self.factory.get("/test/", HTTP_ORIGIN="https://nope.example.com")
        assert resolve_cookie_profile(request).jwt_cookie_name == "auth-jwt"

    @override_auth_kit_settings(
        AUTH_COOKIE_PROFILES={
            APP_B_ORIGIN: {
                "AUTH_JWT_COOKIE_NAME": "app-b-auth-jwt",
                "BOGUS_KEY": "ignored",
            }
        }
    )
    def test_unknown_override_key_is_ignored_at_runtime(self) -> None:
        request = self.factory.get("/test/", HTTP_ORIGIN=APP_B_ORIGIN)
        profile = resolve_cookie_profile(request)
        assert profile.jwt_cookie_name == "app-b-auth-jwt"


class TestFoldedJWTAuthentication(APITestCase):
    def setUp(self) -> None:
        self.user, _ = UserFactory.create_with_email_address(
            {
                "username": "testuser",
                "email": "test@example.com",
                "password": "complexpass123",
            }
        )
        self.factory = APIRequestFactory()
        self.access_token = str(RefreshToken.for_user(self.user).access_token)

    @override_auth_kit_settings(AUTH_COOKIE_PROFILES=APP_B_PROFILES)
    def test_origin_selects_app_b_cookie_without_clobbering_default(self) -> None:
        auth = JWTCookieAuthentication()
        app_b_token = str(RefreshToken.for_user(self.user).access_token)

        request = self.factory.get("/test/", HTTP_ORIGIN=APP_B_ORIGIN)
        request.COOKIES = {
            "auth-jwt": self.access_token,
            "app-b-auth-jwt": app_b_token,
        }
        result = auth.authenticate(request)
        assert result is not None
        _, token = result
        assert str(token) == app_b_token

        request_default = self.factory.get("/test/")
        request_default.COOKIES = {
            "auth-jwt": self.access_token,
            "app-b-auth-jwt": app_b_token,
        }
        result_default = auth.authenticate(request_default)
        assert result_default is not None
        _, token_default = result_default
        assert str(token_default) == self.access_token


class TestUnsetCookies(APITestCase):
    def test_unset_jwt_default_profile(self) -> None:
        response = Response()
        unset_jwt_cookies(response, default_cookie_profile())
        assert "auth-jwt" in response.cookies
        assert "auth-refresh-jwt" in response.cookies

    def test_unset_jwt_named_profile_uses_paths(self) -> None:
        profile = CookieProfile(
            jwt_cookie_name="app-b-auth-jwt",
            jwt_cookie_path="/app-b/",
            refresh_cookie_name="app-b-auth-refresh-jwt",
            refresh_cookie_path="/app-b/refresh/",
            token_cookie_name="app-b-auth-token",
            token_cookie_path="/app-b/",
        )
        response = Response()
        unset_jwt_cookies(response, profile)

        assert "app-b-auth-jwt" in response.cookies
        assert "auth-jwt" not in response.cookies
        # Access cookie deletion carries the profile path so the browser
        # actually clears the cookie that login set under that path.
        assert response.cookies["app-b-auth-jwt"]["path"] == "/app-b/"
        assert response.cookies["app-b-auth-refresh-jwt"]["path"] == "/app-b/refresh/"

    def test_unset_token_named_profile(self) -> None:
        profile = CookieProfile(
            jwt_cookie_name="app-b-auth-jwt",
            jwt_cookie_path="/",
            refresh_cookie_name="app-b-auth-refresh-jwt",
            refresh_cookie_path="/",
            token_cookie_name="app-b-auth-token",
            token_cookie_path="/",
        )
        response = Response()
        unset_token_cookie(response, profile)
        assert "app-b-auth-token" in response.cookies
        assert "auth-token" not in response.cookies


class TestProfileChecks(APITestCase):
    @override_auth_kit_settings(AUTH_COOKIE_PROFILES=APP_B_PROFILES)
    def test_valid_profiles_produce_no_warning(self) -> None:
        assert check_cookie_profiles() == []

    def test_no_profiles_produce_no_warning(self) -> None:
        assert check_cookie_profiles() == []

    @override_auth_kit_settings(AUTH_COOKIE_PROFILES={APP_B_ORIGIN: {"BOGUS": "y"}})
    def test_unknown_key_warns(self) -> None:
        assert [w.id for w in check_cookie_profiles()] == ["auth_kit.W003"]
