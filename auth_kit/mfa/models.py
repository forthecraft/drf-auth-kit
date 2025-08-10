"""
Multi-Factor Authentication models for Auth Kit.

This module provides the MFAMethod model and manager for storing and managing
user MFA configurations including secrets, backup codes, and method status.
"""

from collections.abc import Iterable
from typing import TYPE_CHECKING, Any, ClassVar

from django.conf import settings
from django.contrib.auth.hashers import make_password
from django.db.models import (
    CASCADE,
    CheckConstraint,
    Index,
    Manager,
    Model,
    Q,
    UniqueConstraint,
)
from django.db.models import (
    BooleanField as BaseBooleanField,
)
from django.db.models import (
    CharField as BaseCharField,
)
from django.db.models import (
    ForeignKey as BaseForeignKey,
)
from django.db.models import (
    JSONField as BaseJSONField,
)
from django.utils.translation import gettext_lazy as _

from typing_extensions import Self

from .exceptions import MFAMethodDoesNotExistError
from .mfa_settings import auth_kit_mfa_settings
from .services.backup_codes import generate_backup_codes

if TYPE_CHECKING:  # pragma: no cover
    from django.contrib.auth.models import User  # noqa

    # Type aliases for Django model fields to support type checking
    CharField = BaseCharField[str, str]
    BooleanField = BaseBooleanField[bool, bool]
    JSONField = BaseJSONField[Any, Any]
    UserForeignKey = BaseForeignKey["User", "User"]
else:
    CharField = BaseCharField
    BooleanField = BaseBooleanField
    JSONField = BaseJSONField
    UserForeignKey = BaseForeignKey


class MFAMethodManager(Manager["MFAMethod"]):
    """
    Manager for MFAMethod model providing convenience methods for MFA operations.

    Provides methods for retrieving MFA methods by name, checking primary methods,
    and creating methods with backup codes.
    """

    def get_by_name(
        self, user_id: int | str | None, name: str, is_active: bool = True
    ) -> "MFAMethod":
        """
        Retrieve MFA method by user and method name.

        Args:
            user_id: User identifier
            name: MFA method name
            is_active: Filter by active status

        Returns:
            MFA method instance

        Raises:
            MFAMethodDoesNotExistError: If method not found
        """
        try:
            return self.get(user_id=user_id, name=name, is_active=is_active)
        except self.model.DoesNotExist as e:
            raise MFAMethodDoesNotExistError() from e

    def get_primary_active(self, user_id: Any) -> "MFAMethod":
        """
        Retrieve user's primary active MFA method.

        Args:
            user_id: User identifier

        Returns:
            Primary active MFA method

        Raises:
            MFAMethodDoesNotExistError: If no primary active method found
        """
        try:
            return self.get(user_id=user_id, is_primary=True, is_active=True)
        except self.model.DoesNotExist as e:
            raise MFAMethodDoesNotExistError() from e

    def check_method(
        self, user_id: int | str | None, method_name: str, is_active: bool = True
    ) -> None:
        """
        Verify that a method exists for user.

        Args:
            user_id: User identifier
            method_name: MFA method name to check
            is_active: Filter by active status

        Raises:
            MFAMethodDoesNotExistError: If method not found
        """
        is_exists = self.filter(
            user_id=user_id, name=method_name, is_active=is_active
        ).exists()
        if not is_exists:
            raise MFAMethodDoesNotExistError()

    def create_with_backup_codes(self, **kwargs: Any) -> tuple["MFAMethod", set[str]]:
        """
        Create MFA method with generated backup codes.

        Args:
            **kwargs: Additional fields for method creation

        Returns:
            Tuple of (created method, raw backup codes)
        """
        backup_codes = raw_backup_codes = generate_backup_codes(
            auth_kit_mfa_settings.NUM_OF_BACKUP_CODES,
            auth_kit_mfa_settings.BACKUP_CODE_LENGTH,
            auth_kit_mfa_settings.BACKUP_CODE_ALLOWED_CHARS,
        )
        if auth_kit_mfa_settings.BACKUP_CODE_SECURE_HASH:
            backup_codes = {make_password(code) for code in backup_codes}

        kwargs["_backup_codes"] = list(backup_codes)
        instance = super().create(**kwargs)
        return instance, raw_backup_codes


class MFAMethod(Model):
    """
    Multi-Factor Authentication method configuration for users.

    Stores MFA method configuration including method name (e.g., 'app', 'email'),
    TOTP secret keys, backup codes, and status flags. Each method can be marked
    as primary (the default method) and active/inactive. Enforces constraints
    ensuring only one primary method per user and that primary methods must be active.

    Constraints:
        - Unique (user, name) combination
        - Only one primary method per user
        - Primary methods must be active
    """

    id: int | None
    user_id: int
    user = UserForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=CASCADE,
        verbose_name=_("user"),
        related_name="mfa_methods",
        help_text=_("User who owns this MFA method"),
    )
    name = CharField(
        _("name"),
        max_length=255,
        help_text=_("MFA method name (e.g., 'app', 'email')"),
    )
    secret = CharField(
        _("secret"),
        max_length=255,
        help_text=_("TOTP secret key for generating verification codes"),
    )
    is_primary = BooleanField(
        _("is primary"),
        default=False,
        help_text=_("Whether this is the user's primary MFA method"),
    )
    is_active = BooleanField(
        _("is active"),
        default=False,
        help_text=_("Whether this method is active and can be used"),
    )
    _backup_codes = JSONField(
        _("backup codes"),
        default=dict,
        blank=True,
        help_text=_("JSON field storing backup codes for account recovery"),
    )

    class Meta:
        """Database configuration and constraints for MFAMethod model."""

        verbose_name = _("MFA Method")
        verbose_name_plural = _("MFA Methods")
        constraints = (
            UniqueConstraint(
                fields=("user", "name"),
                name="unique_user_method_name",
            ),
            UniqueConstraint(
                condition=Q(is_primary=True),
                fields=("user",),
                name="unique_user_is_primary",
            ),
            CheckConstraint(
                condition=(Q(is_primary=True) & Q(is_active=True))
                | Q(is_primary=False),
                name="primary_is_active",
            ),
        )
        indexes = [
            Index(fields=["user", "is_active"], name="user_is_active_idx"),
            Index(fields=["user", "is_primary"], name="user_is_primary_idx"),
        ]

    objects: ClassVar[MFAMethodManager[Self]] = MFAMethodManager()  # type: ignore

    def __str__(self) -> str:
        """Return string representation of the MFA method."""
        return f"{self.name} (User id: {self.user_id})"

    @property
    def backup_codes(self) -> set[str]:
        """Get backup codes as a set."""
        return set(self._backup_codes)

    @backup_codes.setter
    def backup_codes(self, codes: Iterable[str]) -> None:
        """Set backup codes from an iterable."""
        self._backup_codes = list(codes)
