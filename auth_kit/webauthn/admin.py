"""
Django admin configuration for WebAuthn credentials.
"""

from typing import Any

from django.contrib import admin
from django.contrib.admin import ModelAdmin as AdminModel
from django.http import HttpRequest
from django.utils.html import format_html

from webauthn.helpers import bytes_to_base64url

from auth_kit.webauthn.models import WebAuthnCredential

_CREDENTIAL_ID_DISPLAY_LENGTH = 16


@admin.register(WebAuthnCredential)
class WebAuthnCredentialAdmin(AdminModel):  # type: ignore[type-arg]
    """Admin configuration for WebAuthnCredential model."""

    list_display = [
        "id",
        "user",
        "name",
        "credential_id_short",
        "discoverable",
        "sign_count",
        "created_at",
        "last_used_at",
    ]
    list_filter = ["discoverable", "created_at"]
    search_fields = ["user__email", "user__username", "name", "aaguid"]
    list_select_related = ["user"]
    readonly_fields = [
        "user",
        "credential_id_display",
        "public_key_display",
        "sign_count",
        "aaguid",
        "transports",
        "discoverable",
        "created_at",
        "last_used_at",
    ]
    fields = [
        "user",
        "name",
        "credential_id_display",
        "public_key_display",
        "sign_count",
        "aaguid",
        "transports",
        "discoverable",
        "created_at",
        "last_used_at",
    ]

    def has_add_permission(self, request: HttpRequest) -> bool:
        """Credentials can only be created via the WebAuthn browser API."""
        return False

    @admin.display(description="Credential ID")
    def credential_id_short(self, obj: WebAuthnCredential) -> str:
        """Show truncated base64url credential ID in list view."""
        b64 = bytes_to_base64url(bytes(obj.credential_id))
        n = _CREDENTIAL_ID_DISPLAY_LENGTH
        return f"{b64[:n]}..." if len(b64) > n else b64

    @admin.display(description="Credential ID")
    def credential_id_display(self, obj: WebAuthnCredential) -> Any:
        """Show full base64url credential ID in detail view."""
        b64 = bytes_to_base64url(bytes(obj.credential_id))
        return format_html(
            '<code style="word-break: break-all;">{value}</code>',
            value=b64,
        )

    @admin.display(description="Public Key")
    def public_key_display(self, obj: WebAuthnCredential) -> Any:
        """Show base64url public key with byte count."""
        raw = bytes(obj.public_key)
        b64 = bytes_to_base64url(raw)
        return format_html(
            '<code style="word-break: break-all;">{value}</code>'
            '<br><small style="color: #666;">{size} bytes</small>',
            value=b64,
            size=len(raw),
        )
