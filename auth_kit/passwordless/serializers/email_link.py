"""
Email magic link serializers for passwordless authentication.

This module provides request and verify serializers for the email
magic link passwordless login flow.
"""

from typing import Any

from django.contrib.auth import get_user_model
from django.utils.translation import gettext_lazy as _
from rest_framework import serializers
from rest_framework.exceptions import ValidationError

from allauth.account.models import (  # pyright: ignore[reportMissingTypeStubs]
    EmailAddress,
)
from allauth.utils import (  # pyright: ignore[reportMissingTypeStubs]
    generate_unique_username,
)

from auth_kit.passwordless.passwordless_settings import auth_kit_passwordless_settings
from auth_kit.passwordless.services.token import (
    passwordless_signup_token_service,
    passwordless_token_service,
)
from auth_kit.utils import find_user_by_email

UserModel = get_user_model()


class EmailLinkInitiateSerializer(serializers.Serializer[dict[str, Any]]):
    """
    Serializer for the email magic link initiate step.

    Accepts the address to send the magic link to and returns the
    confirmation message.

    Attributes:
        email: Email address to send the magic link to
        detail: Confirmation message
    """

    email = serializers.EmailField(write_only=True)
    detail = serializers.CharField(read_only=True)

    def validate_email(self, value: str) -> str:
        """
        Validate that the email exists in the system.

        Note: For security, we don't reveal whether the email exists.
        The handler will silently succeed even for non-existent emails.

        Args:
            value: Email address

        Returns:
            Normalized email address
        """
        return value.lower()


class EmailLinkVerifySerializer(serializers.Serializer[dict[str, Any]]):
    """
    Serializer for verifying email magic link tokens.

    Accepts the token from the magic link and validates it.

    Attributes:
        token: The magic link token from the email
    """

    token = serializers.CharField(write_only=True)

    def validate(self, attrs: dict[str, Any]) -> dict[str, Any]:
        """
        Validate the magic link token.

        Decodes and verifies the ephemeral token, extracting
        the user identity.

        Args:
            attrs: Input attributes dictionary

        Returns:
            Validated attributes with user in context

        Raises:
            ValidationError: If token is invalid or expired
        """
        token = attrs["token"]
        user = passwordless_token_service.check_token(token)

        if not user and auth_kit_passwordless_settings.PASSWORDLESS_EMAIL_SIGNUP:
            user = self._signup_from_token(token)

        if not user:
            raise ValidationError(_("Invalid or expired token."))

        # Auto-verify email: clicking the magic link proves ownership
        self._auto_verify_email(user)

        self.context["user"] = user
        return attrs

    @staticmethod
    def _signup_from_token(token: str) -> Any:
        """
        Create an account for a redeemed signup token.

        Reaching here means the link was clicked, which proves the address
        belongs to whoever holds it, so the account can be created and its
        email marked verified in one step.

        Args:
            token: Signup token from the magic link

        Returns:
            Newly created user, or None if the token is unknown
        """
        email = passwordless_signup_token_service.consume_token(token)
        if not email:
            return None

        email_field = UserModel.get_email_field_name()
        username_field = UserModel.USERNAME_FIELD  # type: ignore[attr-defined]

        # A concurrent request may have created the account already
        existing = find_user_by_email(email)
        if existing:
            return existing

        fields: dict[str, Any] = {email_field: email}
        if username_field != email_field:
            fields[username_field] = generate_unique_username([email])

        user = UserModel(**fields)
        user.set_unusable_password()
        user.save()

        EmailAddress.objects.get_or_create(
            user=user,
            email=email,
            defaults={"verified": True, "primary": True},
        )
        return user

    @staticmethod
    def _auto_verify_email(user: Any) -> None:
        """
        Mark the user's email as verified if not already.

        Clicking a magic link sent to the user's email is proof of
        email ownership, equivalent to email verification.
        """
        try:
            email_field = user.get_email_field_name()
            email = getattr(user, email_field, None)
            if email:
                EmailAddress.objects.filter(
                    user=user, email=email, verified=False
                ).update(verified=True)
        except Exception:  # pragma: no cover
            pass  # allauth not installed or no email address record
