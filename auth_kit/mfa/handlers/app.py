"""
Authenticator app-based MFA handler for Auth Kit.

This module provides TOTP-based multi-factor authentication using
authenticator applications like Google Authenticator, Authy, etc.
"""

from django.contrib.auth.base_user import AbstractBaseUser
from rest_framework import serializers

from ..mfa_settings import auth_kit_mfa_settings
from .base import MFABaseHandler, MFAHandlerRegistry


class AppSetupSerializer(serializers.Serializer[dict[str, str]]):
    """Serializer for authenticator app setup response."""

    qr_link = serializers.CharField(read_only=True)


class MFAAppHandler(MFABaseHandler):
    """
    Authenticator app-based MFA handler.

    Generates QR codes and provisioning URIs for setting up TOTP
    in authenticator applications. Does not require code dispatch
    as codes are generated locally on user's device.
    """

    NAME = "app"
    APPLICATION_ISSUER_NAME = auth_kit_mfa_settings.MFA_APPLICATION_NAME
    REQUIRES_DISPATCH = False

    def initialize_method(self) -> dict[str, str]:
        """
        Initialize authenticator app setup.

        Returns:
            Dictionary containing QR code provisioning URI
        """
        qr_link = self._create_qr_link(self.mfa_method.user)
        return {"qr_link": qr_link}

    @classmethod
    def get_initialize_method_serializer_class(cls) -> type[AppSetupSerializer]:
        """
        Get serializer for app setup response.

        Returns:
            Serializer class for app setup data
        """
        return AppSetupSerializer

    def _create_qr_link(self, user: AbstractBaseUser) -> str:
        """
        Create provisioning URI for authenticator app.

        Args:
            user: User instance for URI generation

        Returns:
            TOTP provisioning URI string
        """
        return self._get_otp().provisioning_uri(
            user.get_username(),
            self.APPLICATION_ISSUER_NAME,
        )


MFAHandlerRegistry.register(MFAAppHandler)
