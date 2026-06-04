"""
Login factor serializers for MFA authentication flow.

This module provides serializers for multi-step authentication including
first step response, second step verification, method switching, and
code resending functionality.
"""

from typing import Any, TypedDict, cast

from django.utils.translation import gettext_lazy as _
from rest_framework import serializers
from rest_framework.exceptions import ValidationError
from rest_framework.serializers import Serializer

from auth_kit.mfa.exceptions import MFAMethodDoesNotExistError
from auth_kit.mfa.fields import MFAMethodField
from auth_kit.mfa.handlers.base import MFAHandlerRegistry
from auth_kit.mfa.mfa_settings import auth_kit_mfa_settings
from auth_kit.mfa.services.user_token import ephemeral_token_service
from auth_kit.serializers.login_factors import get_login_response_serializer


def get_no_mfa_login_response_serializer() -> (
    type[serializers.Serializer[dict[str, Any]]]
):
    """
    Get login response serializer for users without MFA enabled.

    Returns:
        Serializer class with MFA disabled flag
    """
    serializer_class = get_login_response_serializer()

    class NoMFALoginResponseSerializer(serializer_class):  # type: ignore
        """Login response serializer with MFA disabled indicator."""

        mfa_enabled = serializers.BooleanField(default=False, read_only=True)

    return NoMFALoginResponseSerializer


class MFAFirstStepResponseSerializer(serializers.Serializer[dict[str, Any]]):
    """
    Serializer for first step MFA authentication response.

    Returns ephemeral token and method information for MFA verification,
    or complete authentication response if MFA is disabled for user.

    Attributes:
        ephemeral_token: Temporary token for MFA verification
        method: Selected MFA method name
        mfa_enabled: Boolean indicating if MFA is required
    """

    ephemeral_token = serializers.CharField(read_only=True)
    method = MFAMethodField(read_only=True)
    mfa_enabled = serializers.BooleanField(default=True, read_only=True)

    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self.no_mfa_serializer: None | Serializer[dict[str, Any]] = None

    def validate(self, attrs: dict[str, Any]) -> dict[str, Any]:
        """
        Process first step authentication and generate MFA response.

        Args:
            attrs: Input attributes dictionary

        Returns:
            Dictionary with ephemeral token and method info or complete auth response
        """
        super().validate(attrs)
        user = self.context["user"]

        try:
            mfa_method = auth_kit_mfa_settings.MFA_MODEL.objects.get_primary_active(
                user_id=user.id
            )
            handler = MFAHandlerRegistry.get_handler(mfa_method)
            handler.send_code()
            return {
                "ephemeral_token": ephemeral_token_service.make_token(
                    user, mfa_method.name
                ),
                "method": mfa_method.name,
                "mfa_enabled": True,
            }
        except MFAMethodDoesNotExistError:
            no_mfa_serializer_class = (
                auth_kit_mfa_settings.GET_NO_MFA_LOGIN_RESPONSE_SERIALIZER()
            )

            self.no_mfa_serializer = no_mfa_serializer_class(
                data={}, context={"user": user}
            )
            self.no_mfa_serializer.is_valid(raise_exception=True)

            return cast(dict[str, Any], self.no_mfa_serializer.validated_data)

    def to_representation(self, instance: dict[str, Any]) -> dict[str, Any]:
        """
        Convert validated data to response format.

        Args:
            instance: Validated data dictionary

        Returns:
            Properly formatted response data
        """
        if instance.get("mfa_enabled"):
            return super().to_representation(instance)
        else:
            assert self.no_mfa_serializer
            return self.no_mfa_serializer.to_representation(instance)


class MFASecondStepRequestSerializer(serializers.Serializer[dict[str, Any]]):
    """
    Serializer for second step MFA verification request.

    Validates ephemeral token and verification code to complete authentication.

    Attributes:
        ephemeral_token: Token from first step authentication
        code: MFA verification code (TOTP or backup code)
    """

    ephemeral_token = serializers.CharField(write_only=True)
    code = serializers.CharField(write_only=True)

    def validate_verification_code(
        self, user: Any, method_name: str, code: str
    ) -> None:
        """
        Validate MFA verification code.

        Args:
            user: User instance
            method_name: MFA method name
            code: Verification code to validate

        Raises:
            ValidationError: If code is invalid
        """
        mfa_method = auth_kit_mfa_settings.MFA_MODEL.objects.get_by_name(
            user.id, method_name
        )
        handler = MFAHandlerRegistry.get_handler(mfa_method)
        is_code_valid = handler.validate_code(code)
        if not is_code_valid:
            raise ValidationError(_("Invalid code"))

    def validate(self, attrs: dict[str, Any]) -> dict[str, Any]:
        """
        Validate ephemeral token and verification code.

        Args:
            attrs: Input attributes dictionary

        Returns:
            Validated attributes with user in context

        Raises:
            ValidationError: If token is invalid or code verification fails
        """
        ephemeral_token = attrs["ephemeral_token"]
        user_and_method = ephemeral_token_service.check_token(token=ephemeral_token)

        if not user_and_method:
            raise ValidationError(_("Invalid token"))

        user, method_name = user_and_method

        self.validate_verification_code(user, method_name, attrs["code"])

        self.context["user"] = user
        return attrs


class MFAChangeMethodAttrs(TypedDict):
    """
    Type definition for MFA method change request attributes.

    Defines the structure of data required when switching MFA methods
    during the authentication flow.
    """

    ephemeral_token: str
    new_method: str


class MFAChangeMethodSerializer(serializers.Serializer[MFAChangeMethodAttrs]):
    """
    Serializer for changing MFA method during authentication.

    Allows switching to a different MFA method using valid ephemeral token.

    Attributes:
        ephemeral_token: Current ephemeral token
        new_method: Name of new MFA method to switch to
    """

    ephemeral_token = serializers.CharField()
    new_method = MFAMethodField()

    def validate(self, attrs: MFAChangeMethodAttrs) -> MFAChangeMethodAttrs:
        """
        Validate method change request and generate new ephemeral token.

        Args:
            attrs: Input attributes dictionary

        Returns:
            Validated attributes with new ephemeral token

        Raises:
            ValidationError: If token is invalid or same method selected
        """
        ephemeral_token = attrs["ephemeral_token"]
        new_method_name = attrs["new_method"]
        user_and_method = ephemeral_token_service.check_token(token=ephemeral_token)

        if not user_and_method:
            raise ValidationError(_("Invalid token"))

        user, method_name = user_and_method
        if method_name == attrs["new_method"]:
            raise ValidationError(_("Please select a new method"))

        auth_kit_mfa_settings.MFA_MODEL.objects.check_method(
            user.pk, method_name=new_method_name
        )

        attrs["ephemeral_token"] = ephemeral_token_service.make_token(
            user, new_method_name
        )

        return attrs


class MFALoginChallengeSerializer(serializers.Serializer[dict[str, Any]]):
    """
    Serializer for fetching a login challenge for the current MFA method.

    Lets challenge-response methods such as WebAuthn obtain a
    server-issued challenge scoped to the pending MFA user.

    Attributes:
        ephemeral_token: Current ephemeral token
    """

    ephemeral_token = serializers.CharField(write_only=True)

    def validate(self, attrs: dict[str, Any]) -> dict[str, Any]:
        """
        Resolve the pending user and build the method's login challenge.

        Args:
            attrs: Input attributes dictionary

        Returns:
            Method-specific challenge data

        Raises:
            ValidationError: If token is invalid
        """
        user_and_method = ephemeral_token_service.check_token(
            token=attrs["ephemeral_token"]
        )

        if not user_and_method:
            raise ValidationError(_("Invalid token"))

        user, method_name = user_and_method
        mfa_method = auth_kit_mfa_settings.MFA_MODEL.objects.get_by_name(
            user.pk, method_name
        )
        handler = MFAHandlerRegistry.get_handler(mfa_method)
        return handler.get_login_challenge()


class MFAResendSerializer(serializers.Serializer[dict[str, Any]]):
    """
    Serializer for resending MFA verification code.

    Generates and sends new verification code for current method.

    Attributes:
        ephemeral_token: Current ephemeral token
    """

    ephemeral_token = serializers.CharField()

    def validate(self, attrs: dict[str, Any]) -> dict[str, Any]:
        """
        Validate resend request and send new verification code.

        Args:
            attrs: Input attributes dictionary

        Returns:
            Validated attributes with refreshed ephemeral token

        Raises:
            ValidationError: If token is invalid
        """
        ephemeral_token = attrs["ephemeral_token"]
        user_and_method = ephemeral_token_service.check_token(token=ephemeral_token)

        if not user_and_method:
            raise ValidationError(_("Invalid token"))

        user, method_name = user_and_method
        mfa_method = auth_kit_mfa_settings.MFA_MODEL.objects.get_by_name(
            user.pk, method_name
        )
        handler = MFAHandlerRegistry.get_handler(mfa_method)
        handler.send_code()

        attrs["ephemeral_token"] = ephemeral_token_service.make_token(user, method_name)

        return attrs
