from django.contrib.auth import get_user_model
from django.core.checks import Warning
from django.urls import reverse
from rest_framework import status
from rest_framework.response import Response
from rest_framework.test import APITestCase

from auth_kit.checks import check_partitioned_cookie_config
from auth_kit.test_utils import override_auth_kit_settings
from rest_framework_simplejwt.tokens import RefreshToken

from test_utils.user_factory import UserFactory

User = get_user_model()


class TestPartitionedCookieLogin(APITestCase):
    """Test that Partitioned attribute is set on cookies during login."""

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
        UserFactory.create_with_email_address(self.user_data)
        self.url = reverse("rest_login")

    @override_auth_kit_settings(
        AUTH_COOKIE_PARTITIONED=True,
        AUTH_COOKIE_SECURE=True,
        AUTH_COOKIE_SAMESITE="None",
    )
    def test_login_sets_partitioned_on_jwt_cookies(self) -> None:
        response: Response = self.client.post(self.url, self.login_data, format="json")

        assert response.status_code == status.HTTP_200_OK

        access_cookie = response.cookies["auth-jwt"]
        refresh_cookie = response.cookies["auth-refresh-jwt"]

        assert "Partitioned" in access_cookie.OutputString()
        assert "Partitioned" in refresh_cookie.OutputString()

    def test_login_no_partitioned_by_default(self) -> None:
        response: Response = self.client.post(self.url, self.login_data, format="json")

        assert response.status_code == status.HTTP_200_OK

        access_cookie = response.cookies["auth-jwt"]
        refresh_cookie = response.cookies["auth-refresh-jwt"]

        assert "Partitioned" not in access_cookie.OutputString()
        assert "Partitioned" not in refresh_cookie.OutputString()

    @override_auth_kit_settings(
        AUTH_TYPE="token",
        AUTH_COOKIE_PARTITIONED=True,
        AUTH_COOKIE_SECURE=True,
        AUTH_COOKIE_SAMESITE="None",
    )
    def test_login_sets_partitioned_on_token_cookie(self) -> None:
        from auth_kit.serializers import get_login_serializer

        get_login_serializer.cache_clear()

        response: Response = self.client.post(self.url, self.login_data, format="json")

        assert response.status_code == status.HTTP_200_OK

        token_cookie = response.cookies["auth-token"]
        assert "Partitioned" in token_cookie.OutputString()

        get_login_serializer.cache_clear()


class TestPartitionedCookieLogout(APITestCase):
    """Test that Partitioned attribute is set on cookies during logout."""

    def setUp(self) -> None:
        self.user_data = {
            "username": "testuser",
            "email": "test@example.com",
            "password": "complexpass123",
        }
        self.user, _ = UserFactory.create_with_email_address(self.user_data)
        self.url = reverse("rest_logout")

    @override_auth_kit_settings(
        AUTH_COOKIE_PARTITIONED=True,
        AUTH_COOKIE_SECURE=True,
        AUTH_COOKIE_SAMESITE="None",
    )
    def test_logout_sets_partitioned_on_cleared_jwt_cookies(self) -> None:
        self.client.force_authenticate(user=self.user)
        refresh_token = RefreshToken.for_user(self.user)
        self.client.cookies["auth-refresh-jwt"] = str(refresh_token)

        response: Response = self.client.post(self.url, format="json")

        assert response.status_code == status.HTTP_200_OK

        access_cookie = response.cookies["auth-jwt"]
        refresh_cookie = response.cookies["auth-refresh-jwt"]

        assert "Partitioned" in access_cookie.OutputString()
        assert "Partitioned" in refresh_cookie.OutputString()

    @override_auth_kit_settings(
        AUTH_TYPE="token",
        AUTH_COOKIE_PARTITIONED=True,
        AUTH_COOKIE_SECURE=True,
        AUTH_COOKIE_SAMESITE="None",
    )
    def test_logout_sets_partitioned_on_cleared_token_cookie(self) -> None:
        from rest_framework.authtoken.models import Token

        from auth_kit.serializers.logout import get_logout_serializer

        get_logout_serializer.cache_clear()

        token = Token.objects.create(user=self.user)
        self.client.force_authenticate(user=self.user, token=token)

        response: Response = self.client.post(self.url, format="json")

        assert response.status_code == status.HTTP_200_OK

        token_cookie = response.cookies["auth-token"]
        assert "Partitioned" in token_cookie.OutputString()


class TestPartitionedCookieRefresh(APITestCase):
    """Test that Partitioned attribute is set on cookies during JWT refresh."""

    def setUp(self) -> None:
        self.user_data = {
            "username": "testuser",
            "email": "test@example.com",
            "password": "complexpass123",
        }
        self.user, _ = UserFactory.create_with_email_address(self.user_data)
        self.url = reverse("token_refresh")

    @override_auth_kit_settings(
        AUTH_COOKIE_PARTITIONED=True,
        AUTH_COOKIE_SECURE=True,
        AUTH_COOKIE_SAMESITE="None",
    )
    def test_refresh_sets_partitioned_on_access_cookie(self) -> None:
        refresh_token = RefreshToken.for_user(self.user)

        data = {"refresh": str(refresh_token)}
        response: Response = self.client.post(self.url, data, format="json")

        assert response.status_code == status.HTTP_200_OK

        access_cookie = response.cookies["auth-jwt"]
        assert "Partitioned" in access_cookie.OutputString()


class TestPartitionedCookieSystemChecks(APITestCase):
    """Test Django system checks for Partitioned cookie configuration."""

    @override_auth_kit_settings(AUTH_COOKIE_PARTITIONED=False)
    def test_no_warnings_when_disabled(self) -> None:
        errors = check_partitioned_cookie_config()
        assert errors == []

    @override_auth_kit_settings(
        AUTH_COOKIE_PARTITIONED=True,
        AUTH_COOKIE_SAMESITE="None",
        AUTH_COOKIE_SECURE=True,
    )
    def test_no_warnings_with_correct_config(self) -> None:
        errors = check_partitioned_cookie_config()
        assert errors == []

    @override_auth_kit_settings(
        AUTH_COOKIE_PARTITIONED=True,
        AUTH_COOKIE_SAMESITE="Lax",
        AUTH_COOKIE_SECURE=True,
    )
    def test_warning_when_samesite_not_none(self) -> None:
        errors = check_partitioned_cookie_config()
        assert len(errors) == 1
        assert isinstance(errors[0], Warning)
        assert errors[0].id == "auth_kit.W001"

    @override_auth_kit_settings(
        AUTH_COOKIE_PARTITIONED=True,
        AUTH_COOKIE_SAMESITE="None",
        AUTH_COOKIE_SECURE=False,
    )
    def test_warning_when_not_secure(self) -> None:
        errors = check_partitioned_cookie_config()
        assert len(errors) == 1
        assert isinstance(errors[0], Warning)
        assert errors[0].id == "auth_kit.W002"

    @override_auth_kit_settings(
        AUTH_COOKIE_PARTITIONED=True,
        AUTH_COOKIE_SAMESITE="Lax",
        AUTH_COOKIE_SECURE=False,
    )
    def test_both_warnings_when_misconfigured(self) -> None:
        errors = check_partitioned_cookie_config()
        assert len(errors) == 2
        warning_ids = {e.id for e in errors}
        assert warning_ids == {"auth_kit.W001", "auth_kit.W002"}
