# pyright: reportPrivateImportUsage=false
# mypy: disable-error-code=attr-defined, allow-untyped-calls
import os

import factory
from auth_kit.webauthn.models import WebAuthnCredential

from .model_factory import BaseModelFactory


class WebAuthnCredentialFactory(BaseModelFactory[WebAuthnCredential]):
    class Meta:
        model = WebAuthnCredential

    user = factory.SubFactory("test_utils.user_factory.UserFactory")
    credential_id = factory.LazyFunction(lambda: os.urandom(32))
    public_key = factory.LazyFunction(lambda: os.urandom(77))
    sign_count = 0
    transports = factory.LazyFunction(lambda: ["internal"])
    discoverable = True
    aaguid = "00000000-0000-0000-0000-000000000000"
    name = factory.Sequence(lambda n: f"Credential {n}")  # pyright: ignore
