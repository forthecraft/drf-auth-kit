"""
Typed dictionaries describing WebAuthn ceremony options.

These mirror the JSON structures produced by py_webauthn's
``options_to_json_dict`` and consumed by the browser's
``navigator.credentials`` APIs.

Note: WebAuthn mandates camelCase key names in the JSON exchanged with
the browser, so the N815 lint rule is suppressed for this module.
"""

import sys
from typing import Literal

if sys.version_info >= (3, 11):
    from typing import NotRequired, TypedDict
else:
    from typing_extensions import NotRequired, TypedDict

AttestationPreference = Literal["none", "indirect", "direct", "enterprise"]
UserVerification = Literal["required", "preferred", "discouraged"]
ResidentKeyRequirement = Literal["required", "preferred", "discouraged"]
AuthenticatorAttachment = Literal["platform", "cross-platform"]


class PublicKeyCredentialDescriptor(TypedDict):
    """A credential reference used in allowCredentials / excludeCredentials."""

    id: str
    type: Literal["public-key"]
    transports: NotRequired[list[str]]


class PubKeyCredParam(TypedDict):
    """A supported public-key algorithm."""

    type: Literal["public-key"]
    alg: int


class RelyingParty(TypedDict):
    """Relying Party identity."""

    name: str
    id: str


class PublicKeyCredentialUser(TypedDict):
    """User account information for credential creation."""

    id: str
    name: str
    displayName: str


class AuthenticatorSelection(TypedDict):
    """Authenticator selection criteria."""

    residentKey: NotRequired[ResidentKeyRequirement]
    requireResidentKey: NotRequired[bool]
    userVerification: NotRequired[UserVerification]
    authenticatorAttachment: NotRequired[AuthenticatorAttachment]


class WebAuthnRegistrationOptions(TypedDict):
    """Options for the browser's ``navigator.credentials.create()`` call."""

    rp: RelyingParty
    user: PublicKeyCredentialUser
    challenge: str
    pubKeyCredParams: list[PubKeyCredParam]
    timeout: NotRequired[int]
    excludeCredentials: NotRequired[list[PublicKeyCredentialDescriptor]]
    authenticatorSelection: NotRequired[AuthenticatorSelection]
    attestation: NotRequired[AttestationPreference]
    hints: NotRequired[list[str]]


class WebAuthnAuthenticationOptions(TypedDict):
    """Options for the browser's ``navigator.credentials.get()`` call."""

    challenge: str
    timeout: NotRequired[int]
    rpId: NotRequired[str]
    allowCredentials: NotRequired[list[PublicKeyCredentialDescriptor]]
    userVerification: NotRequired[UserVerification]
    session_id: str
