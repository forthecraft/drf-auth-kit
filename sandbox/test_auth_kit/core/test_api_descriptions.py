"""Tests for API description functions with different settings."""

from django.test import TestCase, override_settings

from auth_kit.api_descriptions import (
    get_auth_cookie_description,
    get_auth_invalidation_description,
    get_auth_type_description,
    get_cookie_clearing_description,
    get_jwt_refresh_description,
    get_login_description,
    get_logout_description,
    get_register_description,
)
from auth_kit.mfa.mfa_api_descriptions import (
    get_mfa_method_delete_description,
    get_mfa_method_primary_description,
)
from auth_kit.test_utils import override_auth_kit_settings


class TestApiDescriptionsJWT(TestCase):
    """Test API descriptions with JWT auth type (default)."""

    def test_auth_type_description_jwt(self) -> None:
        assert "JWT" in str(get_auth_type_description())

    def test_auth_invalidation_jwt(self) -> None:
        assert "Blacklists" in str(get_auth_invalidation_description())

    def test_cookie_description_enabled(self) -> None:
        assert "cookies" in str(get_auth_cookie_description())

    def test_cookie_clearing_enabled(self) -> None:
        assert "Clears" in str(get_cookie_clearing_description())

    def test_login_description_with_cookies(self) -> None:
        desc = str(get_login_description())
        assert "JWT" in desc
        assert "cookies" in desc

    def test_logout_description_with_cookies(self) -> None:
        desc = str(get_logout_description())
        assert "Blacklists" in desc
        assert "Clears" in desc

    def test_jwt_refresh_with_cookies(self) -> None:
        desc = str(get_jwt_refresh_description())
        assert "HTTP cookies" in desc

    def test_register_description_mandatory_email(self) -> None:
        desc = str(get_register_description())
        assert "verify" in desc

    @override_settings(ACCOUNT_EMAIL_VERIFICATION="none")
    def test_register_description_no_email_verification(self) -> None:
        desc = str(get_register_description())
        assert "verify" not in desc
        assert "Register" in desc


class TestApiDescriptionsToken(TestCase):
    """Test API descriptions with Token auth type."""

    @override_auth_kit_settings(AUTH_TYPE="token")
    def test_auth_type_description_token(self) -> None:
        assert "DRF" in str(get_auth_type_description())

    @override_auth_kit_settings(AUTH_TYPE="token")
    def test_auth_invalidation_token(self) -> None:
        assert "Deletes" in str(get_auth_invalidation_description())

    @override_auth_kit_settings(AUTH_TYPE="custom")
    def test_auth_type_description_custom(self) -> None:
        assert "custom" in str(get_auth_type_description())

    @override_auth_kit_settings(AUTH_TYPE="custom")
    def test_auth_invalidation_custom(self) -> None:
        assert "Invalidates" in str(get_auth_invalidation_description())


class TestApiDescriptionsNoCookie(TestCase):
    """Test API descriptions without cookies."""

    @override_auth_kit_settings(USE_AUTH_COOKIE=False)
    def test_cookie_description_disabled(self) -> None:
        assert str(get_auth_cookie_description()) == ""

    @override_auth_kit_settings(USE_AUTH_COOKIE=False)
    def test_cookie_clearing_disabled(self) -> None:
        assert str(get_cookie_clearing_description()) == ""

    @override_auth_kit_settings(USE_AUTH_COOKIE=False)
    def test_login_description_no_cookies(self) -> None:
        desc = str(get_login_description())
        assert "cookies" not in desc

    @override_auth_kit_settings(USE_AUTH_COOKIE=False)
    def test_logout_description_no_cookies(self) -> None:
        desc = str(get_logout_description())
        assert "Clears" not in desc

    @override_auth_kit_settings(USE_AUTH_COOKIE=False)
    def test_jwt_refresh_no_cookies(self) -> None:
        desc = str(get_jwt_refresh_description())
        assert "must be provided in the request data" in desc


class TestMFAApiDescriptions(TestCase):
    """Test MFA API description functions with different settings."""

    @override_auth_kit_settings(MFA_UPDATE_PRIMARY_METHOD_REQUIRED_PRIMARY_CODE=True)
    def test_primary_update_with_code_required(self) -> None:
        desc = str(get_mfa_method_primary_description())
        assert "Requires verification code" in desc

    @override_auth_kit_settings(MFA_UPDATE_PRIMARY_METHOD_REQUIRED_PRIMARY_CODE=False)
    def test_primary_update_without_code_required(self) -> None:
        desc = str(get_mfa_method_primary_description())
        assert "Requires verification code" not in desc

    @override_auth_kit_settings(
        MFA_PREVENT_DELETE_ACTIVE_METHOD=True,
        MFA_PREVENT_DELETE_PRIMARY_METHOD=True,
        MFA_DELETE_ACTIVE_METHOD_REQUIRE_CODE=True,
    )
    def test_delete_description_all_restrictions(self) -> None:
        desc = str(get_mfa_method_delete_description())
        assert "Cannot delete active" in desc
        assert "Cannot delete primary" in desc
        assert "Requires verification code" in desc

    @override_auth_kit_settings(
        MFA_PREVENT_DELETE_ACTIVE_METHOD=False,
        MFA_PREVENT_DELETE_PRIMARY_METHOD=False,
        MFA_DELETE_ACTIVE_METHOD_REQUIRE_CODE=False,
    )
    def test_delete_description_no_restrictions(self) -> None:
        desc = str(get_mfa_method_delete_description())
        assert "Cannot delete" not in desc
        assert "Requires verification" not in desc
