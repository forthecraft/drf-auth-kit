# pyright: reportPrivateImportUsage=false
# mypy: disable-error-code=attr-defined, allow-untyped-calls
from typing import Any

from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password

import factory
from auth_kit.mfa.mfa_settings import auth_kit_mfa_settings
from auth_kit.mfa.models import MFAMethod
from auth_kit.mfa.services.backup_codes import generate_backup_codes
from pyotp import random_base32

from .model_factory import BaseModelFactory

User = get_user_model()


class MFAMethodFactory(BaseModelFactory[MFAMethod]):
    class Meta:
        model = MFAMethod

    user = factory.SubFactory("test_utils.user_factory.UserFactory")
    name = "app"
    # pyotp >= 2.12 requires secrets of at least 112 bits after base32 decode
    secret = factory.LazyFunction(lambda: random_base32(length=32))
    is_active = True
    is_primary = False

    _backup_codes = factory.LazyFunction(
        lambda: list(
            generate_backup_codes(
                auth_kit_mfa_settings.NUM_OF_BACKUP_CODES,
                auth_kit_mfa_settings.BACKUP_CODE_LENGTH,
                auth_kit_mfa_settings.BACKUP_CODE_ALLOWED_CHARS,
            )
        )
    )

    @classmethod
    def create_primary(cls, **kwargs: Any) -> MFAMethod:
        """Create primary MFA method (must be active)."""
        kwargs.update({"is_primary": True, "is_active": True})
        return cls.create(**kwargs)

    @classmethod
    def create_primary_with_raw_backup_codes(
        cls, **kwargs: Any
    ) -> tuple[MFAMethod, set[str]]:
        """Create method and return (instance, raw_backup_codes)."""
        raw_codes = generate_backup_codes(
            auth_kit_mfa_settings.NUM_OF_BACKUP_CODES,
            auth_kit_mfa_settings.BACKUP_CODE_LENGTH,
            auth_kit_mfa_settings.BACKUP_CODE_ALLOWED_CHARS,
        )

        if auth_kit_mfa_settings.BACKUP_CODE_SECURE_HASH:
            kwargs["_backup_codes"] = [make_password(code) for code in raw_codes]
        else:
            kwargs["_backup_codes"] = list(raw_codes)

        return cls.create_primary(**kwargs), raw_codes
