"""
Ephemeral token service for passwordless authentication flow.

This module provides secure token generation and validation for
maintaining state between passwordless authentication steps,
particularly for email magic link flows.
"""

import secrets
from typing import Any, cast

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import User
from django.core.cache import cache
from django.utils import timezone
from django.utils.crypto import constant_time_compare, salted_hmac
from django.utils.http import base36_to_int, int_to_base36

from auth_kit.passwordless.passwordless_settings import auth_kit_passwordless_settings


class PasswordlessEphemeralTokenService:
    """
    Service for managing ephemeral tokens in passwordless authentication.

    Provides secure token generation and validation with time-based expiry,
    user binding, single-use enforcement, and password-change invalidation
    to prevent token misuse and replay attacks.
    Used primarily for email magic link flows.

    Class Attributes:
        KEY_SALT: Salt for HMAC token generation
    """

    KEY_SALT = "auth_kit.passwordless.EphemeralTokenService"

    @property
    def _secret(self) -> str:
        """Read SECRET_KEY dynamically so test overrides work."""
        return str(settings.SECRET_KEY)

    @property
    def _expiry_time(self) -> int:
        """Read expiry time dynamically so test overrides work."""
        return auth_kit_passwordless_settings.PASSWORDLESS_EPHEMERAL_TOKEN_EXPIRY

    def make_token(self, user: User) -> str:
        """
        Generate ephemeral token for user.

        Creates a time-limited, single-use token that binds user identity
        for secure passwordless authentication.

        Args:
            user: User instance for token generation

        Returns:
            Signed ephemeral token string
        """
        return self._make_token_with_timestamp(user, int(timezone.now().timestamp()))

    def check_token(self, token: str) -> User | None:
        """
        Validate and decode ephemeral token.

        Verifies token signature, expiry time, single-use status,
        and extracts user information from valid tokens.

        Args:
            token: Ephemeral token string to validate

        Returns:
            User instance if valid, None if invalid
        """
        user_model = cast(User, get_user_model())
        try:
            token = str(token)
            user_pk, ts_b36, _token_hash = token.rsplit("-", 2)
            ts = base36_to_int(ts_b36)
            user = user_model.objects.get(pk=user_pk)
        except (ValueError, TypeError, user_model.DoesNotExist):
            return None

        if (timezone.now().timestamp() - ts) > self._expiry_time:
            return None

        if not constant_time_compare(self._make_token_with_timestamp(user, ts), token):
            return None

        # cache.add only succeeds if the key is absent, so two simultaneous
        # redemptions cannot both win the way a get-then-set pair would.
        used_key = f"passwordless:used:{_token_hash[:16]}"
        remaining_ttl = self._expiry_time - int(timezone.now().timestamp() - ts)
        if not cache.add(used_key, True, timeout=remaining_ttl):
            return None

        # Signed into the hash, so this invalidates the token. Must run after
        # the comparison above, which reads the old value.
        user.last_login = timezone.now()
        user.save(update_fields=["last_login"])

        return user

    def _make_hash_value(self, user: User, timestamp: int) -> str:
        """
        Create hash value for token generation.

        Includes user password hash so tokens are invalidated
        when the user changes their password.

        Args:
            user: User instance
            timestamp: Unix timestamp

        Returns:
            Hash value string for token signing
        """
        email_field = user.get_email_field_name()
        email = getattr(user, email_field, "") or ""
        password = user.password or ""
        login_timestamp = (
            ""
            if user.last_login is None
            else user.last_login.replace(microsecond=0, tzinfo=None).isoformat()
        )
        return f"{user.pk}:{timestamp}:{email}:{password}:{login_timestamp}"

    def _make_token_with_timestamp(
        self, user: User, timestamp: int, **kwargs: Any
    ) -> str:
        """
        Generate token with specific timestamp.

        Args:
            user: User instance
            timestamp: Unix timestamp for token generation
            **kwargs: Additional arguments (unused)

        Returns:
            Signed token string with format: user_pk-timestamp-hash
        """
        ts_b36 = int_to_base36(timestamp)
        token_hash = salted_hmac(
            self.KEY_SALT,
            self._make_hash_value(user, timestamp),
            secret=self._secret,
        ).hexdigest()
        return f"{user.pk}-{ts_b36}-{token_hash}"


class PasswordlessSignupTokenService:
    """
    Service for magic link tokens issued to addresses with no account yet.

    The ephemeral token service binds a token to an existing user row, which
    signup cannot do. These tokens are random and opaque, with the pending
    email held server side, so hitting the request endpoint never creates a
    user. The account is only made once the link is clicked.

    Class Attributes:
        CACHE_PREFIX: Cache key prefix for pending signups
    """

    CACHE_PREFIX = "passwordless:signup:"

    @property
    def _expiry_time(self) -> int:
        """Read expiry time dynamically so test overrides work."""
        return auth_kit_passwordless_settings.PASSWORDLESS_EPHEMERAL_TOKEN_EXPIRY

    def _cache_key(self, token: str) -> str:
        """Build the cache key holding a pending signup email."""
        return f"{self.CACHE_PREFIX}{token}"

    def make_token(self, email: str) -> str:
        """
        Issue a signup token for an address with no account.

        Args:
            email: Address the magic link will be sent to

        Returns:
            Opaque single-use token string
        """
        token = secrets.token_urlsafe(32)
        cache.set(self._cache_key(token), email, timeout=self._expiry_time)
        return token

    def consume_token(self, token: str) -> str | None:
        """
        Redeem a signup token and return its pending email.

        The token is deleted on read, so a link works exactly once.

        Args:
            token: Signup token string to redeem

        Returns:
            Pending email if the token is valid, None otherwise
        """
        cache_key = self._cache_key(token)
        email = cache.get(cache_key)
        if not email:
            return None
        cache.delete(cache_key)
        return str(email)


passwordless_token_service = PasswordlessEphemeralTokenService()
passwordless_signup_token_service = PasswordlessSignupTokenService()
