"""
WebAuthn service layer for Auth Kit.

This module wraps py_webauthn library functions to provide registration
and authentication ceremony helpers. Challenges are stored in Django's
cache framework with configurable TTL.
"""

import secrets
from typing import Any, cast

from django.contrib.auth.base_user import AbstractBaseUser
from django.core.cache import cache
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import (
    base64url_to_bytes,
    options_to_json_dict,
    parse_registration_credential_json,
)
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticatorAttachment,
    AuthenticatorSelectionCriteria,
    AuthenticatorTransport,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from auth_kit.webauthn.exceptions import WebAuthnVerificationError
from auth_kit.webauthn.models import WebAuthnCredential
from auth_kit.webauthn.types import (
    WebAuthnAuthenticationOptions,
    WebAuthnRegistrationOptions,
)
from auth_kit.webauthn.webauthn_settings import auth_kit_webauthn_settings


def _get_challenge_cache_key(purpose: str, identifier: str) -> str:
    """
    Build cache key for WebAuthn challenge storage.

    Args:
        purpose: Challenge purpose ('reg' or 'auth')
        identifier: User PK or session identifier

    Returns:
        Cache key string
    """
    return f"webauthn:{purpose}:{identifier}"


def _parse_transports(values: list[str]) -> list[AuthenticatorTransport]:
    """
    Convert stored transport strings into library enums.

    Values the installed py_webauthn no longer recognises are dropped rather
    than raised on, so one odd stored value cannot lock a user out of every
    WebAuthn ceremony.

    Args:
        values: Transport strings as stored on the credential

    Returns:
        List of recognised transports
    """
    transports = []
    for value in values:
        try:
            transports.append(AuthenticatorTransport(value))
        except ValueError:
            continue
    return transports


def _get_credential_descriptors(
    user: AbstractBaseUser,
) -> list[PublicKeyCredentialDescriptor]:
    """
    Get credential descriptors for a user's existing credentials.

    Args:
        user: User instance

    Returns:
        List of credential descriptors
    """
    credentials = WebAuthnCredential.objects.get_for_user(user.pk)
    return [
        PublicKeyCredentialDescriptor(
            id=bytes(cred.credential_id),
            transports=_parse_transports(cred.transports),
        )
        for cred in credentials
    ]


_TRANSPORT_NAMES: dict[AuthenticatorTransport, str] = {
    AuthenticatorTransport.USB: "USB Security Key",
    AuthenticatorTransport.NFC: "NFC Security Key",
    AuthenticatorTransport.BLE: "Bluetooth Security Key",
}

# Common passkey provider AAGUIDs
# Source: https://github.com/passkeydeveloper/passkey-authenticator-aaguids
_AAGUID_NAMES: dict[str, str] = {
    "adce0002-35bc-c60a-648b-0b25f1f05503": "Chrome on Mac",
    "08987058-cadc-4b81-b6e1-30de50dcbe96": "Windows Hello",
    "9ddd1817-af5a-4672-a2b9-3e3dd95000a9": "Windows Hello",
    "6028b017-b1d4-4c02-b4b3-afcdafc96bb2": "Windows Hello",
    "ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4": "Google Password Manager",
    "b5397571-f314-4b0f-b7a1-4768f4e3052b": "Google Password Manager (Wear OS)",
    "fbfc3007-154e-4ecc-8c0b-6e020557d7bd": "iCloud Keychain",
    "53414d53-554e-4700-0000-000000000000": "Samsung Pass",
    "bada5566-a7aa-401f-bd96-45619a55120d": "1Password",
    "b84e4048-15dc-4dd0-8640-f4f60813c8af": "NordPass",
    "0ea242b4-43c4-4a1b-8b17-dd6d0b6baec6": "Dashlane",
    "d548826e-79b4-db40-a3d8-11116f7e8349": "Bitwarden",
    "f3809540-7f14-49c1-a8b3-8f813b225541": "Enpass",
    "66a0ccb3-bd6a-191f-ee06-e375c50b9846": "Thales Bio iOS SDK",
    "8836336a-f590-0921-301d-46427531eee6": "Thales Bio Android SDK",
    "17290f1e-c212-34d0-1423-365d729f09d9": "Thales PIN Android SDK",
    "cd69adb5-3c7a-deb9-3177-6800ea6cb72a": "Thales PIN iOS SDK",
    "50726f74-6f6e-5061-7373-50726f746f6e": "Proton Pass",
    "fdb141b2-5d84-443e-8a35-4698c205a502": "KeePassXC",
    "771b48fd-d3d4-4f74-9232-fc157ab0507a": "Edge on Mac",
    "39a5647e-1853-446c-a1f6-a79bae9f5bc7": "IDmelon",
    "2fc0579f-8113-47ea-b116-bb5a8db9202a": "YubiKey 5 Series with NFC",
    "73bb0cd4-e502-49b8-9c6f-b59445bf720b": "YubiKey 5 FIPS Series",
    "c5ef55ff-ad9a-4b9f-b580-adebafe026d0": "YubiKey 5Ci FIPS",
    "cb69481e-8ff7-4039-93ec-0a2729a154a8": "YubiKey 5 Series",
    "ee882879-721c-4913-9775-3dfcce97072a": "YubiKey 5 Series",
    "fa2b99dc-9e39-4257-8f92-4a30d23c4118": "YubiKey 5 Series with NFC",
}


def _generate_credential_name(
    attachment: AuthenticatorAttachment | None,
    transports: list[AuthenticatorTransport],
    aaguid: str = "",
) -> str:
    """
    Generate a default credential name from authenticator metadata.

    Uses the AAGUID to identify the passkey provider (e.g., "Google
    Password Manager", "iCloud Keychain") when possible, falling
    back to transport-based names.

    Args:
        attachment: Authenticator attachment, if the client reported one
        transports: Transports the authenticator supports
        aaguid: Authenticator AAGUID string

    Returns:
        Human-readable credential name
    """
    # Try AAGUID lookup first (most specific)
    if aaguid and aaguid in _AAGUID_NAMES:
        return _AAGUID_NAMES[aaguid]

    if attachment == AuthenticatorAttachment.PLATFORM:
        return "Passkey"

    for transport, label in _TRANSPORT_NAMES.items():
        if transport in transports:
            return label

    return (
        "Security Key"
        if attachment == AuthenticatorAttachment.CROSS_PLATFORM
        else "Passkey"
    )


def begin_registration(
    user: AbstractBaseUser,
    existing_credentials: list[PublicKeyCredentialDescriptor] | None = None,
) -> WebAuthnRegistrationOptions:
    """
    Generate WebAuthn registration options for a user.

    Creates registration options and stores the challenge in cache
    for later verification.

    Args:
        user: User registering a new credential
        existing_credentials: Optional list of existing credential descriptors
            to exclude. If None, fetches from database.

    Returns:
        Registration options as a JSON-serializable dictionary
    """
    if existing_credentials is None:
        existing_credentials = _get_credential_descriptors(user)

    options = generate_registration_options(
        rp_id=auth_kit_webauthn_settings.WEBAUTHN_RP_ID,
        rp_name=auth_kit_webauthn_settings.WEBAUTHN_RP_NAME,
        user_id=str(user.pk).encode(),
        user_name=getattr(user, user.USERNAME_FIELD),  # type: ignore[attr-defined]
        user_display_name=str(user),
        exclude_credentials=existing_credentials,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement(
                auth_kit_webauthn_settings.WEBAUTHN_RESIDENT_KEY
            ),
            user_verification=UserVerificationRequirement(
                auth_kit_webauthn_settings.WEBAUTHN_USER_VERIFICATION
            ),
        ),
        attestation=AttestationConveyancePreference(
            auth_kit_webauthn_settings.WEBAUTHN_ATTESTATION
        ),
        timeout=auth_kit_webauthn_settings.WEBAUTHN_TIMEOUT,
        supported_pub_key_algs=[
            COSEAlgorithmIdentifier.ECDSA_SHA_256,
            COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,
        ],
    )

    # Store challenge in cache
    cache_key = _get_challenge_cache_key("reg", str(user.pk))
    cache.set(
        cache_key,
        options.challenge,
        timeout=auth_kit_webauthn_settings.WEBAUTHN_CHALLENGE_EXPIRY,
    )

    return cast(WebAuthnRegistrationOptions, options_to_json_dict(options))


def complete_registration(
    user: AbstractBaseUser,
    credential_json: dict[str, Any],
    name: str = "",
) -> WebAuthnCredential:
    """
    Verify WebAuthn registration response and store credential.

    Args:
        user: User completing registration
        credential_json: Registration response from the client
        name: User-friendly name for the credential

    Returns:
        Created WebAuthnCredential instance

    Raises:
        WebAuthnVerificationError: If verification fails
    """

    cache_key = _get_challenge_cache_key("reg", str(user.pk))
    expected_challenge = cache.get(cache_key)

    if not expected_challenge:
        raise WebAuthnVerificationError(
            _("Registration challenge expired or not found.")
        )

    try:
        parsed = parse_registration_credential_json(credential_json)
        verification = verify_registration_response(
            credential=parsed,
            expected_challenge=expected_challenge,
            expected_rp_id=auth_kit_webauthn_settings.WEBAUTHN_RP_ID,
            expected_origin=auth_kit_webauthn_settings.WEBAUTHN_ORIGIN,
            require_user_verification=(
                auth_kit_webauthn_settings.WEBAUTHN_USER_VERIFICATION == "required"
            ),
        )
    except Exception as e:
        raise WebAuthnVerificationError(str(e)) from e
    finally:
        cache.delete(cache_key)

    transports = parsed.response.transports or []
    aaguid = str(verification.aaguid) if verification.aaguid else ""

    # Auto-generate name from credential metadata if not provided
    if not name:
        name = _generate_credential_name(
            parsed.authenticator_attachment, transports, aaguid
        )

    credential = WebAuthnCredential.objects.create(
        user=user,
        credential_id=verification.credential_id,
        public_key=verification.credential_public_key,
        sign_count=verification.sign_count,
        aaguid=aaguid,
        discoverable=(
            verification.credential_device_type == "multi_device"
            if hasattr(verification, "credential_device_type")
            else False
        ),
        transports=[t.value for t in transports],
        name=name,
    )

    return credential


def begin_authentication(
    user: AbstractBaseUser | None = None,
) -> WebAuthnAuthenticationOptions:
    """
    Generate WebAuthn authentication options.

    If user is provided, filters allowed credentials to that user's credentials.
    If user is None, allows discoverable credential flow (passkeys).

    A unique opaque session token is returned as ``session_id`` to bind
    the challenge to the verification step without exposing internal
    cache keys.

    Args:
        user: Optional user for filtering credentials.
            If None, discoverable credential flow is used.

    Returns:
        Authentication options as a JSON-serializable dictionary,
        including ``session_id`` for the verify step.
    """
    allow_credentials: list[PublicKeyCredentialDescriptor] | None = None

    if user is not None:
        allow_credentials = _get_credential_descriptors(user)

    options = generate_authentication_options(
        rp_id=auth_kit_webauthn_settings.WEBAUTHN_RP_ID,
        allow_credentials=allow_credentials,
        user_verification=UserVerificationRequirement(
            auth_kit_webauthn_settings.WEBAUTHN_USER_VERIFICATION
        ),
        timeout=auth_kit_webauthn_settings.WEBAUTHN_TIMEOUT,
    )

    # Use an opaque session token so the client cannot manipulate cache keys
    session_id = secrets.token_urlsafe(32)
    cache_key = _get_challenge_cache_key("auth", session_id)
    cache.set(
        cache_key,
        options.challenge,
        timeout=auth_kit_webauthn_settings.WEBAUTHN_CHALLENGE_EXPIRY,
    )

    result = cast(WebAuthnAuthenticationOptions, options_to_json_dict(options))
    result["session_id"] = session_id
    return result


def complete_authentication(
    credential_json: dict[str, Any],
    session_id: str,
) -> tuple[AbstractBaseUser, WebAuthnCredential]:
    """
    Verify WebAuthn authentication response.

    Verifies the assertion, updates the credential's sign count and
    last_used_at timestamp, and returns the authenticated user.

    Args:
        credential_json: Authentication response from the client
        session_id: Opaque session token from begin_authentication

    Returns:
        Tuple of (authenticated user, WebAuthnCredential)

    Raises:
        WebAuthnVerificationError: If verification fails
    """

    cache_key = _get_challenge_cache_key("auth", session_id)
    expected_challenge = cache.get(cache_key)

    if not expected_challenge:
        raise WebAuthnVerificationError(
            _("Authentication challenge expired or not found.")
        )

    # Look up the credential
    raw_id = credential_json.get("rawId", "")
    if isinstance(raw_id, str):
        credential_id_bytes: bytes = base64url_to_bytes(raw_id)
    else:
        credential_id_bytes = bytes(raw_id)

    try:
        credential = WebAuthnCredential.objects.get_by_credential_id(
            credential_id_bytes
        )
    except Exception as e:
        cache.delete(cache_key)
        raise WebAuthnVerificationError(_("Credential not found.")) from e

    try:
        verification = verify_authentication_response(
            credential=credential_json,
            expected_challenge=expected_challenge,
            expected_rp_id=auth_kit_webauthn_settings.WEBAUTHN_RP_ID,
            expected_origin=auth_kit_webauthn_settings.WEBAUTHN_ORIGIN,
            credential_public_key=bytes(credential.public_key),
            credential_current_sign_count=credential.sign_count,
            require_user_verification=(
                auth_kit_webauthn_settings.WEBAUTHN_USER_VERIFICATION == "required"
            ),
        )
    except Exception as e:
        raise WebAuthnVerificationError(str(e)) from e
    finally:
        cache.delete(cache_key)

    # Update sign count and last used timestamp
    credential.sign_count = verification.new_sign_count
    credential.last_used_at = timezone.now()
    credential.save(update_fields=["sign_count", "last_used_at"])

    return credential.user, credential
