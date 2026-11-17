from django.test import RequestFactory, override_settings
from django.urls import reverse
from rest_framework import exceptions, status
from rest_framework.authtoken.models import Token
from rest_framework.response import Response
from rest_framework.test import APIRequestFactory, APITestCase

import pytest
from auth_kit.authentication import TokenCookieAuthentication
from auth_kit.checks import check_cookie_csrf_config
from auth_kit.csrf import is_cross_origin_request
from auth_kit.test_utils import override_auth_kit_settings
from rest_framework_simplejwt.tokens import RefreshToken

from test_utils.user_factory import UserFactory

CROSS_SITE = {"Sec-Fetch-Site": "cross-site", "Origin": "https://evil.example"}


@pytest.mark.parametrize(
    "method,headers,expected",
    [
        ("get", CROSS_SITE, False),
        ("post", {}, False),
        ("post", {"Sec-Fetch-Site": "same-origin"}, False),
        ("post", {"Sec-Fetch-Site": "none"}, False),
        ("post", {"Sec-Fetch-Site": "same-site"}, True),
        ("post", CROSS_SITE, True),
        ("post", {"Origin": "http://testserver"}, False),
        ("post", {"Origin": "https://testserver"}, True),
        ("post", {"Origin": "https://evil.example"}, True),
        ("post", {"Origin": "null"}, True),
    ],
)
def test_is_cross_origin_request(
    method: str, headers: dict[str, str], expected: bool
) -> None:
    request = getattr(RequestFactory(), method)("/", headers=headers)

    assert is_cross_origin_request(request) is expected


@override_settings(
    CSRF_TRUSTED_ORIGINS=["https://app.example.com", "https://*.trusted.example"]
)
@pytest.mark.parametrize(
    "origin,expected",
    [
        ("https://app.example.com", False),
        ("https://a.trusted.example", False),
        ("http://a.trusted.example", True),
        ("https://other.example.com", True),
    ],
)
def test_trusted_origins_bypass_fetch_metadata(origin: str, expected: bool) -> None:
    request = RequestFactory().post(
        "/", headers={"Sec-Fetch-Site": "cross-site", "Origin": origin}
    )

    assert is_cross_origin_request(request) is expected


class TestCookieCSRFEnforcement(APITestCase):
    """Cookie-authenticated unsafe requests from untrusted origins are rejected."""

    def setUp(self) -> None:
        self.user, _ = UserFactory.create_with_email_address(
            {
                "username": "testuser",
                "email": "test@example.com",
                "password": "complexpass123",
            }
        )
        self.access = str(RefreshToken.for_user(self.user).access_token)
        self.url = reverse("rest_user")

    def set_auth_cookie(self) -> None:
        self.client.cookies["auth-jwt"] = self.access

    def patch_user(self, first_name: str, **headers: str) -> Response:
        return self.client.patch(
            self.url, {"first_name": first_name}, format="json", headers=headers
        )

    def test_cross_site_cookie_request_rejected(self) -> None:
        self.set_auth_cookie()

        response = self.patch_user("Forged", **CROSS_SITE)

        assert response.status_code == status.HTTP_403_FORBIDDEN
        assert "CSRF Failed" in str(response.data["detail"])
        self.user.refresh_from_db()
        assert self.user.first_name != "Forged"

    def test_cross_site_form_post_rejected(self) -> None:
        self.set_auth_cookie()

        response: Response = self.client.post(
            reverse("rest_logout"),
            data="",
            content_type="application/x-www-form-urlencoded",
            headers=CROSS_SITE,
        )

        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_same_origin_cookie_request_allowed(self) -> None:
        self.set_auth_cookie()

        response = self.patch_user("Updated", **{"Sec-Fetch-Site": "same-origin"})

        assert response.status_code == status.HTTP_200_OK
        self.user.refresh_from_db()
        assert self.user.first_name == "Updated"

    @override_settings(CSRF_TRUSTED_ORIGINS=["https://app.example.com"])
    def test_trusted_origin_cookie_request_allowed(self) -> None:
        self.set_auth_cookie()

        response = self.patch_user(
            "Updated",
            **{"Sec-Fetch-Site": "same-site", "Origin": "https://app.example.com"},
        )

        assert response.status_code == status.HTTP_200_OK

    def test_non_browser_cookie_request_allowed(self) -> None:
        self.set_auth_cookie()

        response = self.patch_user("Native")

        assert response.status_code == status.HTTP_200_OK

    def test_cross_site_safe_request_allowed(self) -> None:
        self.set_auth_cookie()

        response: Response = self.client.get(self.url, headers=CROSS_SITE)

        assert response.status_code == status.HTTP_200_OK

    def test_header_auth_not_checked(self) -> None:
        response = self.patch_user(
            "Header", Authorization=f"Bearer {self.access}", **CROSS_SITE
        )

        assert response.status_code == status.HTTP_200_OK

    def test_invalid_cookie_token_rejected_as_unauthenticated(self) -> None:
        self.client.cookies["auth-jwt"] = "invalid"

        response = self.patch_user("Forged", **CROSS_SITE)

        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    @override_auth_kit_settings(AUTH_COOKIE_ENFORCE_CSRF=False)
    def test_enforcement_disabled(self) -> None:
        self.set_auth_cookie()

        response = self.patch_user("Allowed", **CROSS_SITE)

        assert response.status_code == status.HTTP_200_OK


@pytest.mark.django_db
@override_auth_kit_settings(AUTH_TYPE="token")
def test_token_cookie_authentication_rejects_cross_site() -> None:
    user, _ = UserFactory.create_with_email_address(
        {
            "username": "testuser",
            "email": "test@example.com",
            "password": "complexpass123",
        }
    )
    token = Token.objects.create(user=user)
    request = APIRequestFactory().post("/", {}, format="json", headers=CROSS_SITE)
    request.COOKIES["auth-token"] = token.key

    with pytest.raises(exceptions.PermissionDenied, match="CSRF Failed"):
        TokenCookieAuthentication().authenticate(request)


class TestCookieCSRFCheck(APITestCase):
    """System checks for cookie cross-origin protection."""

    def test_no_warnings_with_default_config(self) -> None:
        assert check_cookie_csrf_config() == []

    @override_auth_kit_settings(USE_AUTH_COOKIE=False, AUTH_COOKIE_SAMESITE="None")
    def test_no_warnings_without_auth_cookie(self) -> None:
        assert check_cookie_csrf_config() == []

    @override_auth_kit_settings(AUTH_COOKIE_ENFORCE_CSRF=False)
    def test_no_warning_when_disabled_with_lax(self) -> None:
        assert check_cookie_csrf_config() == []

    @override_auth_kit_settings(
        AUTH_COOKIE_ENFORCE_CSRF=False, AUTH_COOKIE_SAMESITE="None"
    )
    def test_warning_when_disabled_with_samesite_none(self) -> None:
        assert [e.id for e in check_cookie_csrf_config()] == ["auth_kit.W004"]

    @override_auth_kit_settings(AUTH_COOKIE_SAMESITE="None")
    @override_settings(CSRF_TRUSTED_ORIGINS=[])
    def test_warning_when_samesite_none_without_trusted_origins(self) -> None:
        assert [e.id for e in check_cookie_csrf_config()] == ["auth_kit.W005"]

    @override_auth_kit_settings(AUTH_COOKIE_SAMESITE="None")
    @override_settings(CSRF_TRUSTED_ORIGINS=["https://app.example.com"])
    def test_no_warning_when_samesite_none_with_trusted_origins(self) -> None:
        assert check_cookie_csrf_config() == []
