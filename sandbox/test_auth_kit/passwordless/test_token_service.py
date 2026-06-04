"""Tests for the passwordless ephemeral token service."""

from django.core.cache import cache
from django.test import TestCase

from auth_kit.passwordless.services.token import passwordless_token_service
from auth_kit.test_utils import settings_context

from test_utils.user_factory import UserFactory


class TestPasswordlessEphemeralTokenService(TestCase):
    """Test cases for magic link token single-use enforcement."""

    def setUp(self) -> None:
        self.user = UserFactory.create()

    def test_token_validates_once(self) -> None:
        token = passwordless_token_service.make_token(self.user)

        assert passwordless_token_service.check_token(token) is not None
        assert passwordless_token_service.check_token(token) is None

    def test_cache_marker_blocks_a_concurrent_second_use(self) -> None:
        """
        Two requests can both clear the signature check before either has
        written last_login, so the used-marker still has to catch the race.
        """
        token = passwordless_token_service.make_token(self.user)
        token_hash = token.rsplit("-", 2)[2]
        cache.set(f"passwordless:used:{token_hash[:16]}", True, timeout=60)

        assert passwordless_token_service.check_token(token) is None

    def test_consuming_a_token_invalidates_other_outstanding_tokens(self) -> None:
        first = passwordless_token_service.make_token(self.user)
        second = passwordless_token_service.make_token(self.user)

        assert passwordless_token_service.check_token(first) is not None

        cache.clear()
        assert passwordless_token_service.check_token(second) is None

    def test_unparseable_token_is_rejected(self) -> None:
        assert passwordless_token_service.check_token("garbage") is None

    def test_expired_token_is_rejected(self) -> None:
        """A token older than the configured expiry must not authenticate."""
        token = passwordless_token_service.make_token(self.user)

        with settings_context(PASSWORDLESS_EPHEMERAL_TOKEN_EXPIRY=-1):
            assert passwordless_token_service.check_token(token) is None

        # Still valid once the expiry window is back to normal
        assert passwordless_token_service.check_token(token) is not None

    def test_tampered_token_is_rejected(self) -> None:
        """Flipping the signature must fail the constant-time comparison."""
        token = passwordless_token_service.make_token(self.user)
        user_pk, ts_b36, token_hash = token.rsplit("-", 2)
        forged_hash = ("b" if token_hash[0] == "a" else "a") + token_hash[1:]

        assert (
            passwordless_token_service.check_token(f"{user_pk}-{ts_b36}-{forged_hash}")
            is None
        )
