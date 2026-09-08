"""
WebAuthn credential models for Auth Kit.

This module provides the WebAuthnCredential model and manager for storing
and managing WebAuthn/FIDO2 credentials used for passwordless login
and multi-factor authentication.
"""

import sys
from typing import TYPE_CHECKING, Any, ClassVar

if sys.version_info >= (3, 11):
    from typing import Self
else:
    from typing_extensions import Self

from django.conf import settings
from django.db.models import (
    CASCADE,
    Index,
    Manager,
    Model,
    QuerySet,
)
from django.db.models import (
    BinaryField as BaseBinaryField,
)
from django.db.models import (
    BooleanField as BaseBooleanField,
)
from django.db.models import (
    CharField as BaseCharField,
)
from django.db.models import (
    DateTimeField as BaseDateTimeField,
)
from django.db.models import (
    ForeignKey as BaseForeignKey,
)
from django.db.models import (
    JSONField as BaseJSONField,
)
from django.db.models import (
    PositiveIntegerField as BasePositiveIntegerField,
)
from django.utils.translation import gettext_lazy as _

from auth_kit.webauthn.exceptions import WebAuthnCredentialDoesNotExistError

if TYPE_CHECKING:  # pragma: no cover
    from django.contrib.auth.models import User  # noqa

    CharField = BaseCharField[str, str]
    BooleanField = BaseBooleanField[bool, bool]
    JSONField = BaseJSONField[Any, Any]
    UserForeignKey = BaseForeignKey["User", "User"]
    BinaryField = BaseBinaryField[bytes | memoryview, bytes]
    DateTimeField = BaseDateTimeField[Any, Any]
    PositiveIntegerField = BasePositiveIntegerField[int, int]
else:
    CharField = BaseCharField
    BooleanField = BaseBooleanField
    JSONField = BaseJSONField
    UserForeignKey = BaseForeignKey
    BinaryField = BaseBinaryField
    DateTimeField = BaseDateTimeField
    PositiveIntegerField = BasePositiveIntegerField


class WebAuthnCredentialManager(Manager["WebAuthnCredential"]):
    """
    Manager for WebAuthnCredential model providing convenience methods.

    Provides methods for retrieving credentials by credential ID,
    user, and discoverability status.
    """

    def get_by_credential_id(self, credential_id: bytes) -> "WebAuthnCredential":
        """
        Retrieve credential by its unique credential ID.

        Args:
            credential_id: Raw credential ID bytes

        Returns:
            WebAuthn credential instance

        Raises:
            WebAuthnCredentialDoesNotExistError: If credential not found
        """
        try:
            return self.get(credential_id=credential_id)
        except self.model.DoesNotExist as e:
            raise WebAuthnCredentialDoesNotExistError() from e

    def get_for_user(self, user_id: int | str) -> QuerySet["WebAuthnCredential"]:
        """
        Retrieve all credentials for a user.

        Args:
            user_id: User identifier

        Returns:
            QuerySet of user's WebAuthn credentials
        """
        return self.filter(user_id=user_id)

    def get_discoverable_for_user(
        self, user_id: int | str
    ) -> QuerySet["WebAuthnCredential"]:
        """
        Retrieve discoverable (passkey) credentials for a user.

        Args:
            user_id: User identifier

        Returns:
            QuerySet of user's discoverable WebAuthn credentials
        """
        return self.filter(user_id=user_id, discoverable=True)


class WebAuthnCredential(Model):
    """
    WebAuthn/FIDO2 credential storage for users.

    Stores credential data from WebAuthn registration ceremonies including
    credential ID, public key, sign count for replay protection, and
    metadata about the authenticator. Used for both passwordless login
    and multi-factor authentication.
    """

    id: int | None
    user_id: int
    user = UserForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=CASCADE,
        verbose_name=_("user"),
        related_name="webauthn_credentials",
        help_text=_("User who owns this WebAuthn credential"),
    )
    credential_id = BinaryField(
        _("credential ID"),
        unique=True,
        help_text=_("Unique credential identifier from the authenticator"),
    )
    public_key = BinaryField(
        _("public key"),
        help_text=_("COSE public key bytes from registration"),
    )
    sign_count = PositiveIntegerField(
        _("sign count"),
        default=0,
        help_text=_("Signature counter for replay attack detection"),
    )
    transports = JSONField(
        _("transports"),
        default=list,
        blank=True,
        help_text=_("Supported transport methods (e.g., usb, nfc, ble, internal)"),
    )
    discoverable = BooleanField(
        _("discoverable"),
        default=False,
        help_text=_("Whether this is a discoverable (passkey) credential"),
    )
    aaguid = CharField(
        _("AAGUID"),
        max_length=36,
        blank=True,
        default="",
        help_text=_("Authenticator Attestation GUID identifying the device type"),
    )
    name = CharField(
        _("name"),
        max_length=255,
        blank=True,
        default="",
        help_text=_("User-assigned friendly name for this credential"),
    )
    created_at = DateTimeField(
        _("created at"),
        auto_now_add=True,
        help_text=_("When this credential was registered"),
    )
    last_used_at = DateTimeField(
        _("last used at"),
        null=True,
        blank=True,
        help_text=_("When this credential was last used for authentication"),
    )

    class Meta:
        """Database configuration for WebAuthnCredential model."""

        verbose_name = _("WebAuthn Credential")
        verbose_name_plural = _("WebAuthn Credentials")
        ordering = ["-created_at"]
        indexes = [
            Index(
                fields=["user", "discoverable"],
                name="webauthn_user_discoverable_idx",
            ),
        ]

    objects: ClassVar[WebAuthnCredentialManager[Self]] = (  # type: ignore
        WebAuthnCredentialManager()
    )

    def __str__(self) -> str:
        """Return string representation of the credential."""
        label = self.name or f"Credential {self.pk}"
        return f"{label} (User id: {self.user_id})"
