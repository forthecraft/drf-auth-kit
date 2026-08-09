"""Tests for MFA method management ViewSet."""

from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework import status
from rest_framework.response import Response
from rest_framework.test import APITestCase

from auth_kit.mfa.handlers.base import MFAHandlerRegistry
from auth_kit.mfa.models import MFAMethod
from auth_kit.test_utils import override_auth_kit_settings
from freezegun import freeze_time

from test_utils.mfa_factory import MFAMethodFactory
from test_utils.user_factory import UserFactory

User = get_user_model()


class TestMFAMethodViewSet(APITestCase):

    def setUp(self) -> None:
        self.user, _ = UserFactory.create_with_email_address(
            {
                "username": "testuser",
                "email": "test@example.com",
                "password": "password123",
            }
        )
        self.client.force_authenticate(user=self.user)

    def test_list_methods_empty(self) -> None:
        """Test listing methods when user has none setup."""
        response: Response = self.client.get(reverse("mfa-list"))

        assert response.status_code == status.HTTP_200_OK
        assert len(response.data) >= 2  # at least app and email handlers

        for method in response.data:
            assert not method["is_setup"]
            assert not method["is_active"]
            assert not method["is_primary"]

    def test_list_methods_with_setup(self) -> None:
        """Test listing methods with user methods."""
        MFAMethodFactory.create_primary(user=self.user, name="app")
        MFAMethodFactory.create(user=self.user, name="email", is_active=True)

        response: Response = self.client.get(reverse("mfa-list"))

        assert response.status_code == status.HTTP_200_OK
        methods = {m["name"]: m for m in response.data}

        assert methods["app"]["is_setup"]
        assert methods["app"]["is_active"]
        assert methods["app"]["is_primary"]

        assert methods["email"]["is_setup"]
        assert methods["email"]["is_active"]
        assert not methods["email"]["is_primary"]

    def test_create_method_success(self) -> None:
        """Test creating new MFA method."""
        data = {"method": "app"}
        response: Response = self.client.post(reverse("mfa-list"), data)

        assert response.status_code == status.HTTP_201_CREATED
        assert response.data["method"] == "app"
        assert "backup_codes" in response.data
        assert "setup_data" in response.data
        assert len(response.data["backup_codes"]) > 0

    @override_auth_kit_settings(BACKUP_CODE_SECURE_HASH=True)
    def test_create_method_with_secure_hash_success(self) -> None:
        """Test creating new MFA method."""
        data = {"method": "app"}
        response: Response = self.client.post(reverse("mfa-list"), data)

        assert response.status_code == status.HTTP_201_CREATED
        assert response.data["method"] == "app"
        assert "backup_codes" in response.data
        assert "setup_data" in response.data
        backup_codes = response.data["backup_codes"]
        assert len(backup_codes) > 0

        mfa_method = MFAMethod.objects.first()
        assert mfa_method
        mfa_handler = MFAHandlerRegistry.get_handler(mfa_method)
        assert mfa_method
        code = backup_codes[0]
        assert code not in mfa_method.backup_codes
        assert mfa_handler.validate_backup_code(code)

    @override_auth_kit_settings(BACKUP_CODE_SECURE_HASH=False)
    def test_create_method_with_normal_hash_success(self) -> None:
        """Test creating new MFA method."""
        data = {"method": "app"}
        response: Response = self.client.post(reverse("mfa-list"), data)

        assert response.status_code == status.HTTP_201_CREATED
        assert response.data["method"] == "app"
        assert "backup_codes" in response.data
        assert "setup_data" in response.data
        backup_codes = response.data["backup_codes"]
        assert len(backup_codes) > 0

        mfa_method = MFAMethod.objects.first()
        assert mfa_method
        mfa_handler = MFAHandlerRegistry.get_handler(mfa_method)
        assert mfa_method
        code = backup_codes[0]
        assert code in mfa_method.backup_codes
        assert mfa_handler.validate_backup_code(code)

    def test_create_method_duplicate(self) -> None:
        """Test creating duplicate method fails."""
        MFAMethodFactory.create(user=self.user, name="app")

        data = {"method": "app"}
        response: Response = self.client.post(reverse("mfa-list"), data)

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "already exists" in str(response.data)

    @freeze_time("2012-01-14 12:00:01")
    def test_confirm_first_method_success(self) -> None:
        """Test confirming new method."""
        method = MFAMethodFactory.create(user=self.user, name="app", is_active=False)
        handler = MFAHandlerRegistry.get_handler(method)
        code = handler.get_otp_code()

        data = {"method": "app", "code": code}
        response: Response = self.client.post(reverse("mfa-confirm"), data)

        assert response.status_code == status.HTTP_200_OK
        assert "Activated" in response.data["detail"]

        method.refresh_from_db()
        assert method.is_active
        assert method.is_primary  # First method becomes primary

    @freeze_time("2012-01-14 12:00:01")
    def test_confirm_subsequence_method_success(self) -> None:
        """Test confirming new method."""
        MFAMethodFactory.create_primary(user=self.user, name="email")
        method = MFAMethodFactory.create(user=self.user, name="app", is_active=False)
        handler = MFAHandlerRegistry.get_handler(method)
        code = handler.get_otp_code()

        data = {"method": "app", "code": code}
        response: Response = self.client.post(reverse("mfa-confirm"), data)

        assert response.status_code == status.HTTP_200_OK
        assert "Activated" in response.data["detail"]

        method.refresh_from_db()
        assert method.is_active
        assert not method.is_primary  # First method becomes primary

    def test_confirm_method_invalid_code(self) -> None:
        """Test confirming with invalid code."""
        MFAMethodFactory.create(user=self.user, name="app", is_active=False)

        data = {"method": "app", "code": "invalid"}
        response: Response = self.client.post(reverse("mfa-confirm"), data)

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "Invalid" in str(response.data)

    def test_confirm_invalid_method(self) -> None:
        """Test confirming with invalid code."""
        MFAMethodFactory.create(user=self.user, name="app", is_active=False)

        data = {"method": "email", "code": "invalid"}
        response: Response = self.client.post(reverse("mfa-confirm"), data)

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "Requested MFA method does not exist." in str(response.data)

    @freeze_time("2012-01-14 12:00:01")
    def test_deactivate_method_success(self) -> None:
        """Test deactivating non-primary method."""
        MFAMethodFactory.create_primary(user=self.user, name="app")
        method = MFAMethodFactory.create(user=self.user, name="email", is_active=True)

        handler = MFAHandlerRegistry.get_handler(method)
        code = handler.get_otp_code()

        data = {"method": "email", "code": code}
        response: Response = self.client.post(reverse("mfa-deactivate"), data)

        assert response.status_code == status.HTTP_200_OK
        assert "Deactivated" in response.data["detail"]

        method.refresh_from_db()
        assert not method.is_active

    @freeze_time("2012-01-14 12:00:01")
    def test_deactivate_method_invalid_code_failed(self) -> None:
        """Test deactivating non-primary method."""
        MFAMethodFactory.create_primary(user=self.user, name="app")
        method = MFAMethodFactory.create(user=self.user, name="email", is_active=True)

        handler = MFAHandlerRegistry.get_handler(method)
        code = handler.get_otp_code()

        data = {"method": "email", "code": code + "1"}
        response: Response = self.client.post(reverse("mfa-deactivate"), data)

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "Invalid OTP code" in str(response.data)

        method.refresh_from_db()
        assert method.is_active

    def test_deactivate_primary_method_invalid_code_fails(self) -> None:
        """Deactivating the primary still requires a valid code."""
        MFAMethodFactory.create_primary(user=self.user, name="app")

        data = {"method": "app", "code": "123456"}
        response: Response = self.client.post(reverse("mfa-deactivate"), data)

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "Invalid OTP code" in str(response.data)

    @freeze_time("2012-01-14 12:00:01")
    def test_deactivate_primary_promotes_another_active_method(self) -> None:
        """Deactivating the primary must hand the flag to a remaining method."""
        method = MFAMethodFactory.create_primary(user=self.user, name="app")
        MFAMethodFactory.create(user=self.user, name="email", is_active=True)
        code = MFAHandlerRegistry.get_handler(method).get_otp_code()

        response: Response = self.client.post(
            reverse("mfa-deactivate"), {"method": "app", "code": code}
        )

        assert response.status_code == status.HTTP_200_OK
        method.refresh_from_db()
        assert not method.is_active
        assert not method.is_primary
        assert MFAMethod.objects.get(user=self.user, name="email").is_primary

    @freeze_time("2012-01-14 12:00:01")
    def test_deactivate_last_method_turns_mfa_off(self) -> None:
        """A single-method user must be able to switch MFA off."""
        method = MFAMethodFactory.create_primary(user=self.user, name="app")
        code = MFAHandlerRegistry.get_handler(method).get_otp_code()

        response: Response = self.client.post(
            reverse("mfa-deactivate"), {"method": "app", "code": code}
        )

        assert response.status_code == status.HTTP_200_OK
        assert not MFAMethod.objects.filter(user=self.user, is_active=True).exists()
        assert not MFAMethod.objects.filter(user=self.user, is_primary=True).exists()

    @freeze_time("2012-01-14 12:00:01")
    @override_auth_kit_settings(MFA_PREVENT_DELETE_ACTIVE_METHOD=True)
    def test_deactivate_blocked_when_active_removal_prevented(self) -> None:
        """
        Deactivation must not be a way around the removal policy.

        An operator who forbids removing an active factor means it, so
        deactivating it -- which drops it from the login flow just the same --
        has to be refused too.
        """
        method = MFAMethodFactory.create_primary(user=self.user, name="app")
        code = MFAHandlerRegistry.get_handler(method).get_otp_code()

        response: Response = self.client.post(
            reverse("mfa-deactivate"), {"method": "app", "code": code}
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "Cannot deactivate active" in str(response.data)
        method.refresh_from_db()
        assert method.is_active

    @freeze_time("2012-01-14 12:00:01")
    @override_auth_kit_settings(MFA_PREVENT_DELETE_PRIMARY_METHOD=True)
    def test_deactivate_primary_blocked_when_primary_removal_prevented(self) -> None:
        """The primary stays put when the policy protects it."""
        method = MFAMethodFactory.create_primary(user=self.user, name="app")
        MFAMethodFactory.create(user=self.user, name="email", is_active=True)
        code = MFAHandlerRegistry.get_handler(method).get_otp_code()

        response: Response = self.client.post(
            reverse("mfa-deactivate"), {"method": "app", "code": code}
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "Cannot deactivate primary" in str(response.data)
        method.refresh_from_db()
        assert method.is_active
        assert method.is_primary

    @freeze_time("2012-01-14 12:00:01")
    @override_auth_kit_settings(MFA_PREVENT_DELETE_PRIMARY_METHOD=True)
    def test_deactivate_non_primary_allowed_when_only_primary_protected(self) -> None:
        """Protecting the primary must not freeze the secondary methods."""
        MFAMethodFactory.create_primary(user=self.user, name="app")
        secondary = MFAMethodFactory.create(
            user=self.user, name="email", is_active=True
        )
        code = MFAHandlerRegistry.get_handler(secondary).get_otp_code()

        response: Response = self.client.post(
            reverse("mfa-deactivate"), {"method": "email", "code": code}
        )

        assert response.status_code == status.HTTP_200_OK
        secondary.refresh_from_db()
        assert not secondary.is_active

    def test_set_primary_method_success(self) -> None:
        """Test setting method as primary."""
        old_primary = MFAMethodFactory.create_primary(user=self.user, name="app")
        new_primary = MFAMethodFactory.create(
            user=self.user, name="email", is_active=True
        )

        data = {"method": "email"}
        response: Response = self.client.post(reverse("mfa-primary"), data)

        assert response.status_code == status.HTTP_200_OK
        assert "Updated primary" in response.data["detail"]

        old_primary.refresh_from_db()
        new_primary.refresh_from_db()
        assert not old_primary.is_primary
        assert new_primary.is_primary

    @override_auth_kit_settings(MFA_UPDATE_PRIMARY_METHOD_REQUIRED_PRIMARY_CODE=True)
    @freeze_time("2012-01-14 12:00:01")
    def test_set_primary_with_code_verification(self) -> None:
        """Test setting primary with code verification required."""
        old_primary = MFAMethodFactory.create_primary(user=self.user, name="app")
        MFAMethodFactory.create(user=self.user, name="email", is_active=True)

        handler = MFAHandlerRegistry.get_handler(old_primary)
        code = handler.get_otp_code()

        data = {"method": "email", "primary_code": code}
        response: Response = self.client.post(reverse("mfa-primary"), data)

        assert response.status_code == status.HTTP_200_OK

    @override_auth_kit_settings(MFA_UPDATE_PRIMARY_METHOD_REQUIRED_PRIMARY_CODE=True)
    @freeze_time("2012-01-14 12:00:01")
    def test_set_primary_with_code_verification_failed_due_to_invalid_code(
        self,
    ) -> None:
        """Test setting primary with code verification required."""
        old_primary = MFAMethodFactory.create_primary(user=self.user, name="app")
        MFAMethodFactory.create(user=self.user, name="email", is_active=True)

        handler = MFAHandlerRegistry.get_handler(old_primary)
        code = handler.get_otp_code()

        data = {"method": "email", "primary_code": code + "1"}
        response: Response = self.client.post(reverse("mfa-primary"), data)

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "Invalid primary method code" in str(response.data)

    @override_auth_kit_settings(MFA_UPDATE_PRIMARY_METHOD_REQUIRED_PRIMARY_CODE=True)
    def test_set_primary_without_required_code_is_rejected(self) -> None:
        """Omitting the required code must be a 400, not an unhandled 500."""
        MFAMethodFactory.create_primary(user=self.user, name="app")
        MFAMethodFactory.create(user=self.user, name="email", is_active=True)

        response: Response = self.client.post(
            reverse("mfa-primary"), {"method": "email"}
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "primary_code" in response.data

    def test_send_code_success(self) -> None:
        """Test sending verification code."""
        MFAMethodFactory.create(user=self.user, name="email", is_active=True)

        data = {"method": "email"}
        response: Response = self.client.post(reverse("mfa-send"), data)

        assert response.status_code == status.HTTP_200_OK
        assert "code sent" in response.data["detail"]

    def test_send_code_nonexistent_method(self) -> None:
        """Test sending code to nonexistent method."""
        data = {"method": "app"}
        response: Response = self.client.post(reverse("mfa-send"), data)

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_delete_method_success(self) -> None:
        """Test deleting MFA method."""
        MFAMethodFactory.create(user=self.user, name="app")

        data = {"method": "app"}
        response: Response = self.client.post(reverse("mfa-delete"), data)

        assert response.status_code == status.HTTP_204_NO_CONTENT
        assert not MFAMethod.objects.filter(name="app", user=self.user).exists()

    @override_auth_kit_settings(MFA_DELETE_ACTIVE_METHOD_REQUIRE_CODE=True)
    def test_delete_method_require_code_success(self) -> None:
        """Test deleting MFA method."""
        method = MFAMethodFactory.create(user=self.user, name="app")

        handler = MFAHandlerRegistry.get_handler(method)
        code = handler.get_otp_code()

        data = {"method": "app", "code": code}
        response: Response = self.client.post(reverse("mfa-delete"), data)

        assert response.status_code == status.HTTP_204_NO_CONTENT
        assert not MFAMethod.objects.filter(name="app", user=self.user).exists()

    @override_auth_kit_settings(MFA_DELETE_ACTIVE_METHOD_REQUIRE_CODE=True)
    def test_delete_method_require_code_failed_due_to_invalid_code(self) -> None:
        """Test deleting MFA method."""
        method = MFAMethodFactory.create(user=self.user, name="app")

        handler = MFAHandlerRegistry.get_handler(method)
        code = handler.get_otp_code()

        data = {"method": "app", "code": code + "1"}
        response: Response = self.client.post(reverse("mfa-delete"), data)

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert MFAMethod.objects.filter(name="app", user=self.user).exists()

    def test_delete_not_exist_method(self) -> None:
        """Test deleting MFA method."""
        data = {"method": "app"}
        response: Response = self.client.post(reverse("mfa-delete"), data)

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "Method does not exist" in str(response.data)

    @override_auth_kit_settings(MFA_PREVENT_DELETE_ACTIVE_METHOD=True)
    def test_delete_active_method_prevented(self) -> None:
        """Test deleting active method when prevented by settings."""
        MFAMethodFactory.create(user=self.user, name="app", is_active=True)

        data = {"method": "app"}
        response: Response = self.client.post(reverse("mfa-delete"), data)

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "Cannot delete active" in str(response.data)

    @override_auth_kit_settings(MFA_PREVENT_DELETE_PRIMARY_METHOD=True)
    def test_delete_primary_method_prevented(self) -> None:
        """Test deleting primary method when prevented by settings."""
        MFAMethodFactory.create_primary(user=self.user, name="app")

        data = {"method": "app"}
        response: Response = self.client.post(reverse("mfa-delete"), data)

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "Cannot delete primary" in str(response.data)

    def test_delete_primary_promotes_another_active_method(self) -> None:
        """
        Removing the primary must leave the user with a primary again.

        Otherwise the account is left with active methods but nothing marked
        primary, which used to make login skip MFA entirely.
        """
        MFAMethodFactory.create_primary(user=self.user, name="app")
        MFAMethodFactory.create(user=self.user, name="email", is_active=True)

        response: Response = self.client.post(reverse("mfa-delete"), {"method": "app"})

        assert response.status_code == status.HTTP_204_NO_CONTENT
        assert MFAMethod.objects.get(user=self.user, name="email").is_primary

    def test_delete_primary_skips_inactive_candidates(self) -> None:
        """An inactive method must not be promoted to primary."""
        MFAMethodFactory.create_primary(user=self.user, name="app")
        MFAMethodFactory.create(user=self.user, name="email", is_active=False)

        response: Response = self.client.post(reverse("mfa-delete"), {"method": "app"})

        assert response.status_code == status.HTTP_204_NO_CONTENT
        assert not MFAMethod.objects.filter(user=self.user, is_primary=True).exists()

    def test_delete_non_primary_leaves_primary_untouched(self) -> None:
        """Deleting a secondary method must not reshuffle the primary."""
        MFAMethodFactory.create_primary(user=self.user, name="app")
        MFAMethodFactory.create(user=self.user, name="email", is_active=True)

        self.client.post(reverse("mfa-delete"), {"method": "email"})

        assert MFAMethod.objects.get(user=self.user, name="app").is_primary

    def test_set_primary_recovers_when_none_is_set(self) -> None:
        """A user left without a primary must be able to designate one."""
        MFAMethodFactory.create(user=self.user, name="app", is_active=True)

        response: Response = self.client.post(reverse("mfa-primary"), {"method": "app"})

        assert response.status_code == status.HTTP_200_OK
        assert MFAMethod.objects.get(user=self.user, name="app").is_primary

    def test_challenge_returns_empty_payload_for_code_based_method(self) -> None:
        """Code-based methods have no challenge to answer."""
        MFAMethodFactory.create(user=self.user, name="app", is_active=True)

        response: Response = self.client.post(
            reverse("mfa-challenge"), {"method": "app"}
        )

        assert response.status_code == status.HTTP_200_OK
        assert response.data == {}

    def test_challenge_rejects_method_the_user_does_not_have(self) -> None:
        """A challenge must not be issued for someone else's method."""
        response: Response = self.client.post(
            reverse("mfa-challenge"), {"method": "app"}
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "does not exist" in str(response.data)

    def test_unauthenticated_access_denied(self) -> None:
        """Test all endpoints require authentication."""
        self.client.force_authenticate(user=None)

        endpoints = [
            ("mfa-list", "get"),
            ("mfa-list", "post"),
            ("mfa-confirm", "post"),
            ("mfa-deactivate", "post"),
            ("mfa-primary", "post"),
            ("mfa-send", "post"),
            ("mfa-delete", "post"),
            ("mfa-challenge", "post"),
        ]

        for name, method in endpoints:
            url = reverse(name)
            response = getattr(self.client, method)(url, {})
            assert response.status_code == status.HTTP_401_UNAUTHORIZED
