"""
Combined serializers for passwordless login flow.

This module provides factory functions that create combined serializers
for the two-step passwordless authentication process by composing
handler-specific request/response serializers with login response
serializers based on current settings.
"""

from typing import Any

from django.utils.translation import gettext_lazy as _
from rest_framework import serializers
from rest_framework.exceptions import ValidationError
from rest_framework.serializers import Serializer

from auth_kit.app_settings import auth_kit_settings
from auth_kit.passwordless.handlers.base import PasswordlessBaseHandler
from auth_kit.serializers.login_factors import get_login_response_serializer


def _set_handler_scoped_name(
    serializer_class: type[Serializer[dict[str, Any]]],
    handler_class: type[PasswordlessBaseHandler],
    suffix: str,
) -> None:
    """
    Give a generated serializer a name unique to its handler.

    Every handler generates classes from the same factory, so without this
    they all share one name and DRF Spectacular collapses them into a single
    component -- documenting one handler's payload for every endpoint.
    """
    prefix = handler_class.NAME.replace("_", " ").title().replace(" ", "")
    serializer_class.__name__ = f"Passwordless{prefix}{suffix}"
    serializer_class.__qualname__ = serializer_class.__name__


def get_passwordless_final_response_serializer(
    handler_class: type[PasswordlessBaseHandler],
) -> type[Serializer[dict[str, Any]]]:
    """
    Get the final response serializer for passwordless verification.

    This is the extension point for MFA interception. If the handler
    declares IS_MULTI_FACTOR=True, returns login tokens directly.
    Otherwise, if MFA is enabled, returns MFA first-step response
    (ephemeral token + method info) instead.

    Args:
        handler_class: The passwordless handler class

    Returns:
        Response serializer class
    """
    if handler_class.IS_MULTI_FACTOR or not auth_kit_settings.USE_MFA:
        return get_login_response_serializer()

    # MFA interception: import here to avoid circular dependency
    from auth_kit.mfa.mfa_settings import auth_kit_mfa_settings

    return auth_kit_mfa_settings.MFA_FIRST_STEP_RESPONSE_SERIALIZER


class RequireActiveUserMixin(serializers.Serializer[dict[str, Any]]):
    """
    Reject a resolved user whose account has been deactivated.

    Password login goes through ``authenticate()``, which applies this check.
    Passwordless resolves the user from a token or credential instead, so it
    has to apply the check itself. Sits between the handler's verify
    serializer and the response serializer so that a deactivated user is
    rejected before any token is minted.
    """

    def validate(self, attrs: dict[str, Any]) -> dict[str, Any]:
        """
        Run the handler's validation, then require an active user.

        Args:
            attrs: Input attributes dictionary

        Returns:
            Validated attributes

        Raises:
            ValidationError: If the resolved user is inactive
        """
        attrs = super().validate(attrs)

        user = self.context.get("user")
        if user is not None and not user.is_active:
            raise ValidationError(_("User account is disabled."))

        return attrs


def get_passwordless_verify_serializer(
    handler_class: type[PasswordlessBaseHandler],
) -> type[Serializer[dict[str, Any]]]:
    """
    Get combined serializer for passwordless verify step.

    Combines the handler's verify serializer with the appropriate
    response serializer (login tokens or MFA first-step response).

    Args:
        handler_class: The passwordless handler class

    Returns:
        Combined serializer class for the verify step
    """
    verify_cls = handler_class.get_verify_serializer_class()
    response_cls = get_passwordless_final_response_serializer(handler_class)

    class PasswordlessVerifySerializer(  # pyright: ignore[reportGeneralTypeIssues]
        response_cls,  # type: ignore
        RequireActiveUserMixin,
        verify_cls,  # type: ignore
    ):
        """Passwordless verify step serializer."""

        pass

    _set_handler_scoped_name(
        PasswordlessVerifySerializer, handler_class, "VerifySerializer"
    )
    return PasswordlessVerifySerializer
