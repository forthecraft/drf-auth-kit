"""Tests for MFAMethod model and manager."""

from django.db import IntegrityError
from django.test import TestCase

from auth_kit.mfa.exceptions import MFAMethodDoesNotExistError
from auth_kit.mfa.models import MFAMethod

from test_utils.mfa_factory import MFAMethodFactory
from test_utils.user_factory import UserFactory


class TestMFAMethodModel(TestCase):

    def setUp(self) -> None:
        self.user = UserFactory.create()

    def test_str_representation(self) -> None:
        """Test string representation."""
        method = MFAMethodFactory.create(user=self.user, name="app")
        assert str(method) == f"app (User id: {self.user.pk})"

    def test_backup_codes_property(self) -> None:
        """Test backup codes property getter/setter."""
        method = MFAMethodFactory.create(user=self.user)

        # Test getter
        codes = method.backup_codes
        assert isinstance(codes, set)
        assert len(codes) > 0

        # Test setter
        new_codes = {"code1", "code2", "code3"}
        method.backup_codes = new_codes
        assert method.backup_codes == set(new_codes)

    def test_unique_user_method_constraint(self) -> None:
        """Test unique (user, name) constraint."""
        MFAMethodFactory.create(user=self.user, name="app")

        with self.assertRaises(IntegrityError):
            MFAMethodFactory.create(user=self.user, name="app")

    def test_unique_primary_constraint(self) -> None:
        """Test only one primary method per user."""
        MFAMethodFactory.create_primary(user=self.user, name="app")

        with self.assertRaises(IntegrityError):
            MFAMethodFactory.create_primary(user=self.user, name="email")

    def test_primary_must_be_active_constraint(self) -> None:
        """Test primary methods must be active."""
        with self.assertRaises(IntegrityError):
            MFAMethodFactory.create(
                user=self.user, name="app", is_primary=True, is_active=False
            )


class TestMFAMethodManager(TestCase):
    def setUp(self) -> None:
        self.user = UserFactory.create()

    def test_get_by_name_success(self) -> None:
        """Test successful method retrieval by name."""
        method = MFAMethodFactory.create(user=self.user, name="app", is_active=True)

        found = MFAMethod.objects.get_by_name(self.user.pk, "app")
        assert found == method

    def test_get_by_name_not_found(self) -> None:
        """Test exception when method not found."""
        with self.assertRaises(MFAMethodDoesNotExistError):
            MFAMethod.objects.get_by_name(self.user.pk, "nonexistent")

    def test_get_by_name_inactive(self) -> None:
        """Test filtering by active status."""
        MFAMethodFactory.create(user=self.user, name="app", is_active=False)

        with self.assertRaises(MFAMethodDoesNotExistError):
            MFAMethod.objects.get_by_name(self.user.pk, "app", is_active=True)

        # Should find when explicitly looking for inactive
        found = MFAMethod.objects.get_by_name(self.user.pk, "app", is_active=False)
        assert found.name == "app"

    def test_get_primary_active_success(self) -> None:
        """Test getting primary active method."""
        method = MFAMethodFactory.create_primary(user=self.user, name="app")

        found = MFAMethod.objects.get_primary_active(self.user.pk)
        assert found == method

    def test_get_primary_active_not_found(self) -> None:
        """Test exception when no primary active method."""
        MFAMethodFactory.create(user=self.user, name="app", is_active=True)

        with self.assertRaises(MFAMethodDoesNotExistError):
            MFAMethod.objects.get_primary_active(self.user.pk)

    def test_check_method_success(self) -> None:
        """Test method existence check."""
        MFAMethodFactory.create(user=self.user, name="app", is_active=True)

        # Should not raise
        MFAMethod.objects.check_method(self.user.pk, "app")

    def test_check_method_not_found(self) -> None:
        """Test method existence check failure."""
        with self.assertRaises(MFAMethodDoesNotExistError):
            MFAMethod.objects.check_method(self.user.pk, "nonexistent")

    def test_create_with_backup_codes(self) -> None:
        """Test creating method with backup codes."""
        method, raw_codes = MFAMethod.objects.create_with_backup_codes(
            user=self.user, name="app", secret="test_secret"
        )

        assert method.user == self.user
        assert method.name == "app"
        assert method.secret == "test_secret"
        assert len(raw_codes) > 0
        assert len(method.backup_codes) > 0
        assert isinstance(raw_codes, set)

    def test_multiple_users_same_method_name(self) -> None:
        """Test different users can have same method names."""
        user2 = UserFactory.create()

        method1 = MFAMethodFactory.create(user=self.user, name="app")
        method2 = MFAMethodFactory.create(user=user2, name="app")

        assert method1.user != method2.user
        assert method1.name == method2.name
