from django.contrib.auth import get_user_model
from django.http import HttpResponseRedirect
from django.test import override_settings
from django.urls import reverse
from rest_framework import status
from rest_framework.response import Response
from rest_framework.test import APITestCase

from auth_kit.serializers import get_login_serializer
from auth_kit.test_utils import override_auth_kit_settings

from test_utils.user_factory import UserFactory

User = get_user_model()


class TestLoginView(APITestCase):
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

    def test_login_default_case(self) -> None:
        UserFactory.create_with_email_address(self.user_data)

        url = reverse("rest_login")
        response: Response = self.client.post(url, self.login_data, format="json")

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
        assert response.data["user"]["username"] == "testuser"
        assert response.data["user"]["email"] == "test@example.com"

        # Verify tokens are strings
        assert isinstance(response.data["access"], str)
        assert isinstance(response.data["refresh"], str)

        # Verify refresh token is remove due because of moving to secure http only cookie
        assert response.data["refresh"] == ""

        client_cookies = response.cookies

        # Verify cookies
        assert client_cookies["auth-jwt"].value
        assert client_cookies["auth-jwt"]["httponly"]
        assert client_cookies["auth-jwt"]["samesite"] == "Lax"
        assert client_cookies["auth-refresh-jwt"].value
        assert client_cookies["auth-refresh-jwt"]["httponly"]
        assert client_cookies["auth-refresh-jwt"]["samesite"] == "Lax"

    @override_auth_kit_settings(USE_AUTH_COOKIE=False)
    def test_login_no_auth_cookie(self) -> None:
        UserFactory.create_with_email_address(self.user_data)

        url = reverse("rest_login")
        response: Response = self.client.post(url, self.login_data, format="json")

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
        assert response.data["user"]["username"] == "testuser"
        assert response.data["user"]["email"] == "test@example.com"

        # Verify tokens are strings
        assert isinstance(response.data["access"], str)
        assert isinstance(response.data["refresh"], str)

        # Verify refresh token is sent back because we do not use auth cookie
        assert response.data["refresh"] != ""

        assert not response.cookies

    @override_auth_kit_settings(SESSION_LOGIN=True)
    def test_login_with_session(self) -> None:
        UserFactory.create_with_email_address(self.user_data)

        url = reverse("rest_login")
        response: Response = self.client.post(url, self.login_data, format="json")

        assert response.status_code == status.HTTP_200_OK

        # Verify refresh token is remove due because of moving to secure http only cookie
        assert response.data["refresh"] == ""

        client_cookies = response.cookies

        assert client_cookies.keys() == {
            "auth-jwt",
            "auth-refresh-jwt",
            "csrftoken",
            "sessionid",
        }

    def test_login_invalid_credentials(self) -> None:
        UserFactory.create_with_email_address(self.user_data)

        url = reverse("rest_login")
        invalid_data = {
            "username": "testuser",
            "password": "wrongpass123",
        }

        response: Response = self.client.post(url, invalid_data, format="json")

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "Unable to log in" in str(response.data)

    def test_cannot_login_with_unactivated_email_if_not_configure(self) -> None:
        UserFactory.create_with_email_address(self.user_data, {"verified": False})

        url = reverse("rest_login")

        response: Response = self.client.post(url, self.login_data, format="json")

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "E-mail is not verified." in str(response.data)

    @override_settings(ACCOUNT_EMAIL_VERIFICATION="optional")
    def test_can_login_with_unactivated_email_if_configure_via_allauth(self) -> None:
        UserFactory.create_with_email_address(self.user_data, {"verified": False})

        url = reverse("rest_login")

        response: Response = self.client.post(url, self.login_data, format="json")

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

    @override_auth_kit_settings(AUTH_TYPE="token")
    def test_login_with_drf_token(self) -> None:
        get_login_serializer.cache_clear()
        UserFactory.create_with_email_address(self.user_data)

        url = reverse("rest_login")
        response: Response = self.client.post(url, self.login_data, format="json")

        assert response.status_code == status.HTTP_200_OK

        # Check drf token fields
        expected_fields = {"key", "user"}
        actual_fields = set(response.data.keys())
        assert expected_fields.issubset(actual_fields)

        # Check user data
        assert response.data["user"]["username"] == "testuser"
        assert response.data["user"]["email"] == "test@example.com"

        client_cookies = response.cookies

        # Verify cookies
        assert client_cookies["auth-token"].value
        assert client_cookies["auth-token"]["httponly"]
        assert client_cookies["auth-token"]["samesite"] == "Lax"
        get_login_serializer.cache_clear()

    def test_login_inactive_user(self) -> None:
        """Test login with inactive user account"""
        # Create user with verified email
        user, _ = UserFactory.create_with_email_address(self.user_data)

        # Deactivate the user
        user.is_active = False
        user.save()

        url = reverse("rest_login")
        response: Response = self.client.post(url, self.login_data, format="json")

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "Unable to log in with provided credentials." in str(response.data)

    @override_auth_kit_settings(ALLOW_LOGIN_REDIRECT=True)
    def test_login_redirect_with_next_param(self) -> None:
        """Test login redirect with 'next' query parameter"""
        UserFactory.create_with_email_address(self.user_data)
        redirect_url = "/dashboard/"

        url = reverse("rest_login") + f"?next={redirect_url}"
        response = self.client.post(url, self.login_data, format="json")

        assert isinstance(response, HttpResponseRedirect)
        assert response.url == redirect_url
        assert response.status_code == 302

    @override_auth_kit_settings(ALLOW_LOGIN_REDIRECT=True)
    def test_login_redirect_with_redirect_to_param(self) -> None:
        """Test login redirect with 'redirect_to' query parameter"""
        UserFactory.create_with_email_address(self.user_data)
        redirect_url = "/profile/"

        url = reverse("rest_login") + f"?redirect_to={redirect_url}"
        response = self.client.post(url, self.login_data, format="json")

        assert isinstance(response, HttpResponseRedirect)
        assert response.url == redirect_url
        assert response.status_code == 302

    @override_auth_kit_settings(ALLOW_LOGIN_REDIRECT=True)
    def test_login_redirect_next_takes_priority(self) -> None:
        """Test that 'next' parameter takes priority over 'redirect_to'"""
        UserFactory.create_with_email_address(self.user_data)
        next_url = "/dashboard/"
        redirect_to_url = "/profile/"

        url = reverse("rest_login") + f"?next={next_url}&redirect_to={redirect_to_url}"
        response = self.client.post(url, self.login_data, format="json")

        assert isinstance(response, HttpResponseRedirect)
        assert response.url == next_url
        assert response.status_code == 302

    @override_auth_kit_settings(ALLOW_LOGIN_REDIRECT=False)
    def test_login_no_redirect_when_disabled(self) -> None:
        """Test that redirect is disabled when ALLOW_LOGIN_REDIRECT is False"""
        UserFactory.create_with_email_address(self.user_data)
        redirect_url = "/dashboard/"

        url = reverse("rest_login") + f"?next={redirect_url}"
        response = self.client.post(url, self.login_data, format="json")

        assert not isinstance(response, HttpResponseRedirect)
        assert response.status_code == 200

    @override_auth_kit_settings(ALLOW_LOGIN_REDIRECT=True)
    def test_login_redirect_sets_jwt_cookies(self) -> None:
        """Test that redirect response includes JWT authentication cookies"""
        UserFactory.create_with_email_address(self.user_data)
        redirect_url = "/dashboard/"

        url = reverse("rest_login") + f"?next={redirect_url}"
        response = self.client.post(url, self.login_data, format="json")

        assert isinstance(response, HttpResponseRedirect)
        assert response.url == redirect_url
        # Check that JWT authentication cookies are set
        assert "auth-jwt" in response.cookies
        assert "auth-refresh-jwt" in response.cookies

    @override_auth_kit_settings(
        ALLOW_LOGIN_REDIRECT=True, USE_AUTH_COOKIE=True, AUTH_TYPE="token"
    )
    def test_login_redirect_sets_token_cookies(self) -> None:
        """Test that redirect response includes token authentication cookies"""
        get_login_serializer.cache_clear()
        UserFactory.create_with_email_address(self.user_data)
        redirect_url = "/dashboard/"

        url = reverse("rest_login") + f"?next={redirect_url}"
        response = self.client.post(url, self.login_data, format="json")

        assert isinstance(response, HttpResponseRedirect)
        assert response.url == redirect_url
        # Check that token authentication cookie is set
        assert "auth-token" in response.cookies
        get_login_serializer.cache_clear()

    @override_auth_kit_settings(ALLOW_LOGIN_REDIRECT=True, USE_AUTH_COOKIE=False)
    def test_login_redirect_without_cookies(self) -> None:
        """Test redirect when USE_AUTH_COOKIE is disabled"""
        UserFactory.create_with_email_address(self.user_data)
        redirect_url = "/dashboard/"

        url = reverse("rest_login") + f"?next={redirect_url}"
        response = self.client.post(url, self.login_data, format="json")

        assert isinstance(response, HttpResponseRedirect)
        assert response.url == redirect_url
        # No cookies should be set when USE_AUTH_COOKIE is False
        assert len(response.cookies) == 0

    @override_auth_kit_settings(ALLOW_LOGIN_REDIRECT=True)
    def test_login_redirect_with_invalid_credentials(self) -> None:
        """Test that redirect is not performed with invalid credentials"""
        UserFactory.create_with_email_address(self.user_data)
        redirect_url = "/dashboard/"
        invalid_login_data = {
            "username": self.user_data["username"],
            "password": "wrongpassword",
        }

        url = reverse("rest_login") + f"?next={redirect_url}"
        response = self.client.post(url, invalid_login_data, format="json")

        assert not isinstance(response, HttpResponseRedirect)
        assert response.status_code == 400
