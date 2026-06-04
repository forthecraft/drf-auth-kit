# ruff: noqa: N815
"""
Serializers for WebAuthn ceremony options.

This module provides structured serializers for the JSON options
returned by py_webauthn's generate_registration_options and
generate_authentication_options, replacing generic JSONField usage.

Note: WebAuthn spec mandates camelCase field names in the JSON
exchanged with the browser. The N815 lint rule is suppressed for
this file because the field names MUST match the spec.
"""

from django.utils.translation import gettext_lazy as _
from rest_framework import serializers

from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticatorAttachment,
    AuthenticatorTransport,
    PublicKeyCredentialType,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from auth_kit.webauthn.types import (
    AuthenticatorSelection,
    PubKeyCredParam,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialUser,
    RelyingParty,
    WebAuthnAuthenticationOptions,
    WebAuthnRegistrationOptions,
)

# ============================================================
# Shared sub-serializers
# ============================================================


class PublicKeyCredentialDescriptorSerializer(
    serializers.Serializer[PublicKeyCredentialDescriptor]
):
    """A credential descriptor used in allowCredentials / excludeCredentials."""

    id = serializers.CharField(
        help_text=_("Base64URL-encoded credential ID"),
    )
    type = serializers.ChoiceField(
        choices=[e.value for e in PublicKeyCredentialType],
        default="public-key",
        help_text=_("Credential type"),
    )
    transports = serializers.ListField(
        child=serializers.ChoiceField(
            choices=[e.value for e in AuthenticatorTransport]
        ),
        required=False,
        help_text=_("Transport hints for reaching the authenticator"),
    )


class PubKeyCredParamSerializer(serializers.Serializer[PubKeyCredParam]):
    """A public-key credential parameter (algorithm)."""

    type = serializers.ChoiceField(
        choices=[e.value for e in PublicKeyCredentialType],
        default="public-key",
        help_text=_("Credential type"),
    )
    alg = serializers.IntegerField(
        help_text=_("COSE algorithm identifier (e.g., -7 for ES256)"),
    )


# ============================================================
# Registration options
# ============================================================


class RelyingPartySerializer(serializers.Serializer[RelyingParty]):
    """Relying Party identity."""

    name = serializers.CharField(help_text=_("Human-readable RP name"))
    id = serializers.CharField(help_text=_("RP ID (domain)"))


class PublicKeyCredentialUserSerializer(
    serializers.Serializer[PublicKeyCredentialUser]
):
    """User account information for credential creation."""

    id = serializers.CharField(help_text=_("Base64URL-encoded user handle"))
    name = serializers.CharField(help_text=_("User account name"))
    displayName = serializers.CharField(help_text=_("User display name"))


class AuthenticatorSelectionSerializer(serializers.Serializer[AuthenticatorSelection]):
    """Authenticator selection criteria."""

    residentKey = serializers.ChoiceField(
        choices=[e.value for e in ResidentKeyRequirement],
        required=False,
        help_text=_("Resident key requirement"),
    )
    requireResidentKey = serializers.BooleanField(
        required=False,
        help_text=_("Whether resident key is required (deprecated, use residentKey)"),
    )
    userVerification = serializers.ChoiceField(
        choices=[e.value for e in UserVerificationRequirement],
        required=False,
        help_text=_("User verification requirement"),
    )
    authenticatorAttachment = serializers.ChoiceField(
        choices=[e.value for e in AuthenticatorAttachment],
        required=False,
        help_text=_("Authenticator attachment"),
    )


class WebAuthnRegistrationOptionsSerializer(
    serializers.Serializer[WebAuthnRegistrationOptions]
):
    """
    Structured serializer for WebAuthn registration ceremony options.

    Returned by ``services.begin_registration()`` and consumed by
    the browser's ``navigator.credentials.create()`` API.
    """

    rp = RelyingPartySerializer(
        read_only=True,
        help_text=_("Relying Party identity"),
    )
    user = PublicKeyCredentialUserSerializer(
        read_only=True,
        help_text=_("User account information"),
    )
    challenge = serializers.CharField(
        read_only=True,
        help_text=_("Base64URL-encoded challenge"),
    )
    pubKeyCredParams = PubKeyCredParamSerializer(
        many=True,
        read_only=True,
        help_text=_("Supported public-key credential parameters"),
    )
    timeout = serializers.IntegerField(
        read_only=True,
        help_text=_("Ceremony timeout in milliseconds"),
    )
    excludeCredentials = PublicKeyCredentialDescriptorSerializer(
        many=True,
        read_only=True,
        required=False,
        help_text=_("Credentials to exclude (already registered)"),
    )
    authenticatorSelection = AuthenticatorSelectionSerializer(
        read_only=True,
        required=False,
        help_text=_("Authenticator selection criteria"),
    )
    attestation = serializers.ChoiceField(
        choices=[e.value for e in AttestationConveyancePreference],
        read_only=True,
        required=False,
        help_text=_("Attestation conveyance preference"),
    )


# ============================================================
# Authentication options
# ============================================================


class WebAuthnAuthenticationOptionsSerializer(
    serializers.Serializer[WebAuthnAuthenticationOptions]
):
    """
    Structured serializer for WebAuthn authentication ceremony options.

    Returned by ``services.begin_authentication()`` and consumed by
    the browser's ``navigator.credentials.get()`` API.
    """

    challenge = serializers.CharField(
        read_only=True,
        help_text=_("Base64URL-encoded challenge"),
    )
    timeout = serializers.IntegerField(
        read_only=True,
        help_text=_("Ceremony timeout in milliseconds"),
    )
    rpId = serializers.CharField(
        read_only=True,
        help_text=_("Relying Party ID (domain)"),
    )
    allowCredentials = PublicKeyCredentialDescriptorSerializer(
        many=True,
        read_only=True,
        required=False,
        help_text=_("Allowed credentials for this authentication"),
    )
    userVerification = serializers.ChoiceField(
        choices=[e.value for e in UserVerificationRequirement],
        read_only=True,
        required=False,
        help_text=_("User verification requirement"),
    )
    session_id = serializers.CharField(
        read_only=True,
        help_text=_("Opaque session token for the verify step"),
    )
