"""
Schema tests for social authentication endpoints.

Tests the OpenAPI schema generation for social login, connect, and account management
endpoints with different authentication types and provider configurations.
"""

from django.test import TestCase
from django.urls import include, path

from auth_kit.test_utils import override_auth_kit_settings

from test_utils.drf_spectacular_utils import assert_schema, generate_schema
from test_utils.urls import reload_necessary_modules_and_get_social_urls


class SocialSchemaTests(TestCase):
    """Test social authentication schema generation."""

    @override_auth_kit_settings(USE_MFA=False)
    def test_social_jwt_auth_schema(self) -> None:
        """Test social authentication schema with JWT authentication."""
        urls = reload_necessary_modules_and_get_social_urls()
        urlpatterns = [
            path("auth/", include(urls)),
        ]
        schema = generate_schema(None, patterns=urlpatterns)
        assert_schema(schema, "test_schema/social_schema/social_jwt.yml")

    @override_auth_kit_settings(AUTH_TYPE="token", USE_MFA=False)
    def test_social_token_auth_schema(self) -> None:
        """Test social authentication schema with DRF Token authentication."""
        urls = reload_necessary_modules_and_get_social_urls()
        urlpatterns = [
            path("auth/", include(urls)),
        ]
        schema = generate_schema(None, patterns=urlpatterns)
        assert_schema(schema, "test_schema/social_schema/social_token.yml")

    @override_auth_kit_settings(USE_AUTH_COOKIE=False, USE_MFA=False)
    def test_social_no_auth_cookie_schema(self) -> None:
        """Test social authentication schema without auth cookies."""
        urls = reload_necessary_modules_and_get_social_urls()
        urlpatterns = [
            path("auth/", include(urls)),
        ]
        schema = generate_schema(None, patterns=urlpatterns)
        assert_schema(schema, "test_schema/social_schema/social_no_auth_cookie.yml")

    @override_auth_kit_settings(USE_MFA=False, SOCIAL_LOGIN_AUTH_TYPE="token")
    def test_social_token_auth_type_schema(self) -> None:
        """Test social authentication schema with token-based social login."""
        urls = reload_necessary_modules_and_get_social_urls()
        urlpatterns = [
            path("auth/", include(urls)),
        ]
        schema = generate_schema(None, patterns=urlpatterns)
        assert_schema(schema, "test_schema/social_schema/social_token_auth_type.yml")
