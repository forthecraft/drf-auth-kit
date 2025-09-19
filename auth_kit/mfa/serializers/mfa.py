"""
Serializers for MFA method management operations.

This module provides serializers for creating, confirming, activating,
deactivating, and deleting MFA methods, as well as managing primary
method selection and sending verification codes.
"""

from typing import Any, cast

from django.db import transaction
from django.utils.translation import gettext_lazy as _
from rest_framework import serializers
from rest_framework.request import Request

from pyotp import random_base32

from auth_kit.mfa.exceptions import MFAMethodDoesNotExistError
from auth_kit.mfa.fields import MFAMethodField, MFAMethodSetupDataField
from auth_kit.mfa.handlers.base import MFAHandlerRegistry
from auth_kit.mfa.mfa_settings import auth_kit_mfa_settings
from auth_kit.mfa.models import MFAMethod


class MFAMethodGenericSerializer(serializers.Serializer[dict[str, Any]]):
    """
    Base serializer for MFA method operations.

    Provides common fields used across multiple MFA management operations.

    Attributes:
        method: MFA method name
        detail: Response message
    """

    method = MFAMethodField(write_only=True)
    detail = serializers.CharField(read_only=True)


class MFAMethodCreateSerializer(MFAMethodGenericSerializer):
    """
    Serializer for creating new MFA methods.

    Initializes a new MFA method with backup codes and setup instructions.
    Method must be confirmed before activation.

    Attributes:
        method: MFA method name to create
        backup_codes: Generated backup codes for the method
        setup_data: Method-specific setup data (e.g., QR code)
    """

    method = MFAMethodField()
    backup_codes = serializers.ListField(child=serializers.CharField(), read_only=True)
    detail = None  # type: ignore[assignment]
    setup_data = MFAMethodSetupDataField(read_only=True)

    def validate_method(self, value: str) -> str:
        """
        Validate that method doesn't already exist for user.

        Args:
            value: MFA method name

        Returns:
            Validated method name

        Raises:
            ValidationError: If method already exists
        """
        request = cast(Request, self.context.get("request"))
        method_exists = auth_kit_mfa_settings.MFA_MODEL.objects.filter(
            name=value, user_id=str(request.user.pk)
        ).exists()
        if method_exists:
            raise serializers.ValidationError(_("This method is already exists"))

        return value

    def create(self, validated_data: dict[str, Any]) -> dict[str, Any]:
        """
        Create new MFA method with backup codes and setup data.

        Args:
            validated_data: Validated input data

        Returns:
            Dictionary with method data, backup codes, and setup instructions
        """
        request = cast(Request, self.context.get("request"))
        method, backup_codes = (
            auth_kit_mfa_settings.MFA_MODEL.objects.create_with_backup_codes(
                name=validated_data["method"],
                user=request.user,
                secret=random_base32(length=32),
            )
        )
        handler = MFAHandlerRegistry.get_handler(method)
        handler_message = handler.initialize_method()
        handler_serializer_class = handler.get_initialize_method_serializer_class()
        serializer = handler_serializer_class(handler_message)

        return {
            "method": method.name,
            "backup_codes": backup_codes,
            "setup_data": serializer.data,
        }


class MFAMethodConfirmSerializer(MFAMethodGenericSerializer):
    """
    Serializer for confirming and activating new MFA methods.

    Validates TOTP code and activates the method. Sets as primary
    if no other primary method exists.

    Attributes:
        method: MFA method name to confirm
        code: TOTP verification code
    """

    code = serializers.CharField(write_only=True)

    def validate(self, attrs: dict[str, Any]) -> dict[str, Any]:
        """
        Validate confirmation code and activate method.

        Args:
            attrs: Input attributes dictionary

        Returns:
            Success message dictionary

        Raises:
            ValidationError: If method not found or code invalid
        """
        request = cast(Request, self.context.get("request"))

        method = auth_kit_mfa_settings.MFA_MODEL.objects.get_by_name(
            str(request.user.pk), attrs["method"], is_active=False
        )
        handler = MFAHandlerRegistry.get_handler(method)
        is_code_valid = handler.validate_otp_code(attrs["code"])
        if not is_code_valid:
            raise serializers.ValidationError(_("Invalid OTP code"))

        method.is_active = True
        if not auth_kit_mfa_settings.MFA_MODEL.objects.filter(
            user_id=str(request.user.pk), is_primary=True
        ).exists():
            method.is_primary = True
        method.save()

        return {
            "detail": _("Activated MFA method"),
        }


class MFAMethodDeactivateSerializer(MFAMethodGenericSerializer):
    """
    Serializer for deactivating active MFA methods.

    Deactivates non-primary MFA methods after code verification.
    Primary methods cannot be deactivated directly.

    Attributes:
        method: MFA method name to deactivate
        code: TOTP verification code
    """

    code = serializers.CharField(write_only=True)

    def validate(self, attrs: dict[str, Any]) -> dict[str, Any]:
        """
        Validate deactivation request and deactivate method.

        Args:
            attrs: Input attributes dictionary

        Returns:
            Success message dictionary

        Raises:
            ValidationError: If method is primary or code invalid
        """
        request = cast(Request, self.context.get("request"))

        method = auth_kit_mfa_settings.MFA_MODEL.objects.get_by_name(
            str(request.user.pk), attrs["method"]
        )

        if method.is_primary:
            raise serializers.ValidationError(
                _("You can only deactivate non-primary MFA method.")
            )

        handler = MFAHandlerRegistry.get_handler(method)
        is_code_valid = handler.validate_otp_code(attrs["code"])
        if not is_code_valid:
            raise serializers.ValidationError(_("Invalid OTP code"))

        method.is_active = False
        method.save()

        return {
            "detail": _("Deactivated MFA method"),
        }


class MFAMethodPrimaryUpdateSerializer(MFAMethodGenericSerializer):
    """
    Serializer for setting MFA method as primary.

    Updates the primary method designation. Optionally requires
    verification from current primary method based on settings.

    Attributes:
        method: MFA method name to set as primary
        primary_code: Verification code from current primary method (optional)
    """

    primary_code = serializers.CharField(write_only=True, required=False)

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """
        Initialize serializer with conditional primary_code field.

        Args:
            *args: Variable length argument list
            **kwargs: Arbitrary keyword arguments
        """
        super().__init__(*args, **kwargs)

        if not auth_kit_mfa_settings.MFA_UPDATE_PRIMARY_METHOD_REQUIRED_PRIMARY_CODE:
            self.fields.pop("primary_code")

    def validate(self, attrs: dict[str, Any]) -> dict[str, Any]:
        """
        Validate primary method update and perform the change.

        Args:
            attrs: Input attributes dictionary

        Returns:
            Success message dictionary

        Raises:
            ValidationError: If primary code is invalid when required
        """
        request = cast(Request, self.context.get("request"))
        method = auth_kit_mfa_settings.MFA_MODEL.objects.get_by_name(
            str(request.user.pk), attrs["method"]
        )
        primary_method = auth_kit_mfa_settings.MFA_MODEL.objects.get_primary_active(
            request.user.pk
        )

        if auth_kit_mfa_settings.MFA_UPDATE_PRIMARY_METHOD_REQUIRED_PRIMARY_CODE:
            handler = MFAHandlerRegistry.get_handler(primary_method)
            is_code_valid = handler.validate_code(attrs["primary_code"])
            if not is_code_valid:
                raise serializers.ValidationError(_("Invalid primary method code"))

        with transaction.atomic():
            user_methods = MFAMethod.objects.select_for_update().filter(
                user=self.context["request"].user
            )

            # Update in single query
            user_methods.update(is_primary=False)
            method.is_primary = True
            method.save(update_fields=["is_primary"])

        return {
            "detail": _("Updated primary MFA method"),
        }


class MFAMethodDeleteSerializer(MFAMethodGenericSerializer):
    """
    Serializer for deleting MFA methods.

    Permanently removes MFA method. Behavior controlled by settings
    for deleting active/primary methods and requiring verification codes.

    Attributes:
        method: MFA method name to delete
        code: Verification code (conditional based on settings)
    """

    code = serializers.CharField(write_only=True, required=False, allow_blank=True)

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """
        Initialize serializer with conditional code field.

        Args:
            *args: Variable length argument list
            **kwargs: Arbitrary keyword arguments
        """
        super().__init__(*args, **kwargs)

        if not auth_kit_mfa_settings.MFA_DELETE_ACTIVE_METHOD_REQUIRE_CODE:
            self.fields.pop("code")

    def validate(self, attrs: dict[str, Any]) -> dict[str, Any]:
        """
        Validate deletion request and delete method.

        Args:
            attrs: Input attributes dictionary

        Returns:
            Success message dictionary

        Raises:
            ValidationError: If deletion is prevented by settings or code invalid
        """
        try:
            request = cast(Request, self.context.get("request"))

            method: MFAMethod = auth_kit_mfa_settings.MFA_MODEL.objects.get(
                name=attrs["method"], user_id=str(request.user.pk)
            )

            if (
                auth_kit_mfa_settings.MFA_PREVENT_DELETE_ACTIVE_METHOD
                and method.is_active
            ):
                raise serializers.ValidationError(_("Cannot delete active MFA method"))

            if (
                auth_kit_mfa_settings.MFA_PREVENT_DELETE_PRIMARY_METHOD
                and method.is_primary
            ):
                raise serializers.ValidationError(_("Cannot delete primary MFA method"))

            if (
                auth_kit_mfa_settings.MFA_DELETE_ACTIVE_METHOD_REQUIRE_CODE
                and method.is_active
            ):
                handler = MFAHandlerRegistry.get_handler(method)
                is_code_valid = handler.validate_code(attrs["code"])
                if not is_code_valid:
                    raise serializers.ValidationError(_("Invalid OTP code"))

            method.delete()

        except auth_kit_mfa_settings.MFA_MODEL.DoesNotExist as e:
            raise serializers.ValidationError(_("Method does not exist")) from e
        return {
            "detail": _("Deleted MFA method"),
        }


class MFAMethodSendCodeSerializer(MFAMethodGenericSerializer):
    """
    Serializer for sending verification codes to MFA methods.

    Triggers code dispatch for methods that support it (e.g., email).
    Useful for testing method configuration.

    Attributes:
        method: MFA method name to send code to
    """

    def validate(self, attrs: dict[str, Any]) -> dict[str, Any]:
        """
        Validate send code request and dispatch verification code.

        Args:
            attrs: Input attributes dictionary

        Returns:
            Success message dictionary

        Raises:
            MFAMethodDoesNotExistError: If method not found
        """
        request = cast(Request, self.context.get("request"))

        try:
            method = auth_kit_mfa_settings.MFA_MODEL.objects.get(
                user_id=str(request.user.pk), name=attrs["method"]
            )
        except auth_kit_mfa_settings.MFA_MODEL.DoesNotExist as e:
            raise MFAMethodDoesNotExistError() from e
        handler = MFAHandlerRegistry.get_handler(method)
        handler.send_code()

        return {
            "detail": _("MFA code sent"),
        }


class MFAMethodConfigSerializer(serializers.Serializer[dict[str, Any]]):
    """
    Serializer for MFA method configuration display.

    Shows method status and setup information for management interfaces.

    Attributes:
        name: MFA method name
        is_active: Whether method is active
        is_primary: Whether method is set as primary
        is_setup: Whether method has been configured by user
    """

    name = serializers.CharField(read_only=True)
    is_active = serializers.BooleanField(read_only=True, default=False)
    is_primary = serializers.BooleanField(read_only=True, default=False)
    is_setup = serializers.BooleanField(read_only=True, default=False)
