"""WebAuthn models for Auth Kit."""

from auth_kit.webauthn.models.credential import (
    WebAuthnCredential,
    WebAuthnCredentialManager,
)

__all__ = ["WebAuthnCredential", "WebAuthnCredentialManager"]
