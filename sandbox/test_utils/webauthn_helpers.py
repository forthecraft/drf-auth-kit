# ruff: noqa: PLR0913
# pyright: reportPrivateImportUsage=false
# mypy: disable-error-code=attr-defined, allow-untyped-calls
"""
WebAuthn test helpers for generating valid credentials without mocking.

Uses real cryptographic operations to create valid registration and
authentication responses that pass py_webauthn verification.
"""

import hashlib
import json
import os
import struct
from typing import Any

import cbor2
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDSA,
    SECP256R1,
    EllipticCurvePrivateKey,
    generate_private_key,
)
from cryptography.hazmat.primitives.hashes import SHA256
from webauthn.helpers import bytes_to_base64url


def generate_ec2_key_pair() -> tuple[EllipticCurvePrivateKey, bytes]:
    """
    Generate an EC2 P-256 key pair and return (private_key, cose_public_key_bytes).

    Returns:
        Tuple of (private key object, CBOR-encoded COSE public key bytes)
    """
    private_key = generate_private_key(SECP256R1())
    public_numbers = private_key.public_key().public_numbers()

    # COSE Key format for EC2 P-256
    # https://datatracker.ietf.org/doc/html/rfc8152#section-13.1.1
    cose_key = {
        1: 2,  # kty: EC2
        3: -7,  # alg: ES256 (ECDSA w/ SHA-256)
        -1: 1,  # crv: P-256
        -2: public_numbers.x.to_bytes(32, "big"),  # x coordinate
        -3: public_numbers.y.to_bytes(32, "big"),  # y coordinate
    }

    return private_key, cbor2.dumps(cose_key)


def build_authenticator_data(
    rp_id: str,
    sign_count: int = 0,
    credential_id: bytes | None = None,
    cose_public_key: bytes | None = None,
    flags: int = 0x45,  # UP + UV + AT
    aaguid: bytes | None = None,
) -> bytes:
    """
    Build authenticator data bytes.

    Args:
        rp_id: Relying Party ID
        sign_count: Signature counter
        credential_id: Credential ID bytes (required if AT flag set)
        cose_public_key: CBOR-encoded public key (required if AT flag set)
        flags: Authenticator data flags (default: UP + UV + AT)
        aaguid: Authenticator AAGUID (16 bytes, defaults to zeros)

    Returns:
        Authenticator data bytes
    """
    rp_id_hash = hashlib.sha256(rp_id.encode()).digest()
    auth_data = rp_id_hash + struct.pack("!BI", flags, sign_count)

    # Attested credential data (when AT flag is set)
    if credential_id is not None and cose_public_key is not None:
        if aaguid is None:
            aaguid = b"\x00" * 16
        auth_data += aaguid
        auth_data += struct.pack("!H", len(credential_id))
        auth_data += credential_id
        auth_data += cose_public_key

    return auth_data


def build_client_data_json(
    challenge: bytes,
    origin: str = "http://localhost:8000",
    type_: str = "webauthn.create",
) -> bytes:
    """
    Build client data JSON bytes.

    Args:
        challenge: Challenge bytes
        origin: Expected origin
        type_: Client data type ("webauthn.create" or "webauthn.get")

    Returns:
        Client data JSON as bytes
    """
    client_data = {
        "type": type_,
        "challenge": bytes_to_base64url(challenge),
        "origin": origin,
    }
    return json.dumps(client_data).encode()


def create_registration_response(
    rp_id: str = "localhost",
    origin: str = "http://localhost:8000",
    challenge: bytes | None = None,
    flags: int = 0x45,  # UP + UV + AT
) -> dict[str, Any]:
    """
    Create a complete, valid WebAuthn registration response.

    Generates a real key pair and builds a proper registration
    credential that will pass py_webauthn verification.

    Args:
        rp_id: Relying Party ID
        origin: Expected origin
        challenge: Challenge bytes (generated if not provided)
        flags: Authenticator data flags. Clear the UV bit (0x04) to simulate
            an authenticator that did not verify the user.

    Returns:
        Dictionary with:
            - credential: Registration credential dict (for verification)
            - private_key: EC private key (for creating authentication assertions)
            - credential_id: Raw credential ID bytes
            - public_key: CBOR-encoded COSE public key bytes
            - challenge: Challenge used
    """
    if challenge is None:
        challenge = os.urandom(32)

    private_key, cose_public_key = generate_ec2_key_pair()
    credential_id = os.urandom(32)

    auth_data = build_authenticator_data(
        rp_id=rp_id,
        sign_count=0,
        credential_id=credential_id,
        cose_public_key=cose_public_key,
        flags=flags,
    )

    client_data_json = build_client_data_json(
        challenge=challenge,
        origin=origin,
        type_="webauthn.create",
    )

    # Attestation object with "none" format (no attestation)
    attestation_object = cbor2.dumps(
        {
            "fmt": "none",
            "attStmt": {},
            "authData": auth_data,
        }
    )

    raw_id = credential_id
    credential = {
        "id": bytes_to_base64url(raw_id),
        "rawId": bytes_to_base64url(raw_id),
        "type": "public-key",
        "response": {
            "clientDataJSON": bytes_to_base64url(client_data_json),
            "attestationObject": bytes_to_base64url(attestation_object),
        },
        "authenticatorAttachment": "platform",
        "clientExtensionResults": {},
    }

    return {
        "credential": credential,
        "private_key": private_key,
        "credential_id": credential_id,
        "public_key": cose_public_key,
        "challenge": challenge,
    }


def create_authentication_response(
    private_key: EllipticCurvePrivateKey,
    credential_id: bytes,
    rp_id: str = "localhost",
    origin: str = "http://localhost:8000",
    challenge: bytes | None = None,
    sign_count: int = 1,
    flags: int = 0x05,  # UP + UV, no AT
) -> dict[str, Any]:
    """
    Create a complete, valid WebAuthn authentication assertion.

    Signs the assertion with the provided private key.

    Args:
        private_key: EC private key from registration
        credential_id: Credential ID from registration
        rp_id: Relying Party ID
        origin: Expected origin
        challenge: Challenge bytes (generated if not provided)
        sign_count: Signature counter
        flags: Authenticator data flags. Clear the UV bit (0x04) to simulate
            an authenticator that did not verify the user.

    Returns:
        Dictionary with:
            - credential: Authentication credential dict (for verification)
            - challenge: Challenge used
    """
    if challenge is None:
        challenge = os.urandom(32)

    auth_data = build_authenticator_data(
        rp_id=rp_id,
        sign_count=sign_count,
        flags=flags,
    )

    client_data_json = build_client_data_json(
        challenge=challenge,
        origin=origin,
        type_="webauthn.get",
    )

    # Sign: authenticatorData + SHA256(clientDataJSON)
    client_data_hash = hashlib.sha256(client_data_json).digest()
    signature_base = auth_data + client_data_hash
    signature = private_key.sign(signature_base, ECDSA(SHA256()))

    raw_id = credential_id
    credential = {
        "id": bytes_to_base64url(raw_id),
        "rawId": bytes_to_base64url(raw_id),
        "type": "public-key",
        "response": {
            "clientDataJSON": bytes_to_base64url(client_data_json),
            "authenticatorData": bytes_to_base64url(auth_data),
            "signature": bytes_to_base64url(signature),
            "userHandle": bytes_to_base64url(b""),
        },
        "authenticatorAttachment": "platform",
        "clientExtensionResults": {},
    }

    return {
        "credential": credential,
        "challenge": challenge,
    }
