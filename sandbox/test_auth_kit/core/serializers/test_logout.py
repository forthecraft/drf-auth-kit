from django.test import SimpleTestCase
from rest_framework import serializers

from auth_kit.serializers.logout import (
    AuthKitLogoutSerializer,
    JWTLogoutSerializer,
    get_logout_serializer,
)
from auth_kit.test_utils import override_auth_kit_settings


class CustomLogoutSerializer(serializers.Serializer[dict[str, str]]):
    custom_field = serializers.CharField(read_only=True)


class TestGetLogoutSerializer(SimpleTestCase):
    """Test the get_logout_serializer function logic"""

    @override_auth_kit_settings(AUTH_TYPE="jwt")
    def test_get_logout_serializer_jwt_auth(self) -> None:
        """Test get_logout_serializer returns JWTLogoutSerializer for JWT auth"""
        get_logout_serializer.cache_clear()

        serializer_class = get_logout_serializer()
        assert serializer_class == JWTLogoutSerializer

    @override_auth_kit_settings(AUTH_TYPE="token")
    def test_get_logout_serializer_token_auth(self) -> None:
        """Test get_logout_serializer returns AuthKitLogoutSerializer for token auth"""
        get_logout_serializer.cache_clear()

        serializer_class = get_logout_serializer()
        assert serializer_class == AuthKitLogoutSerializer

    @override_auth_kit_settings(AUTH_TYPE="custom")
    def test_get_logout_serializer_custom_auth(self) -> None:
        """Test get_logout_serializer returns AuthKitLogoutSerializer for custom auth"""
        get_logout_serializer.cache_clear()

        serializer_class = get_logout_serializer()
        assert serializer_class == AuthKitLogoutSerializer

    @override_auth_kit_settings(
        AUTH_TYPE="custom",
        LOGOUT_SERIALIZER="test_auth_kit.core.serializers.test_logout.CustomLogoutSerializer",
    )
    def test_get_logout_serializer_custom_serializer_override(self) -> None:
        """Test get_logout_serializer returns custom serializer when LOGOUT_SERIALIZER is overridden"""
        get_logout_serializer.cache_clear()

        serializer_class = get_logout_serializer()

        # Compare by name since the modules will be different (imported vs local)
        assert serializer_class.__name__ == CustomLogoutSerializer.__name__

        # Verify it has the expected custom field by instantiating it
        serializer_instance = serializer_class()
        assert "custom_field" in serializer_instance.fields
        assert serializer_instance.fields["custom_field"].read_only is True
