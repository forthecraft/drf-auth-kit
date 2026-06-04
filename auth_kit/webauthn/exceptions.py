"""
WebAuthn exceptions for Auth Kit.

This module provides custom exceptions for WebAuthn credential operations.
"""

from typing import TYPE_CHECKING

from django.utils.translation import gettext_lazy as _
from rest_framework.exceptions import ValidationError

if TYPE_CHECKING:  # pragma: no cover
    from django.utils.functional import _StrOrPromise
else:
    _StrOrPromise = str


class WebAuthnCredentialDoesNotExistError(ValidationError):
    """Raised when a requested WebAuthn credential cannot be found."""

    def __init__(self) -> None:
        """Initialize with a descriptive error message."""
        super().__init__(
            detail=_("Requested WebAuthn credential does not exist."),
            code="webauthn_credential_does_not_exist",
        )


class WebAuthnVerificationError(ValidationError):
    """Raised when WebAuthn verification fails."""

    def __init__(self, detail: _StrOrPromise | None = None) -> None:
        """Initialize with a descriptive error message."""
        super().__init__(
            detail=detail or _("WebAuthn verification failed."),
            code="webauthn_verification_failed",
        )
