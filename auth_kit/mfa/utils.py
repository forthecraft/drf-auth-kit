"""
Utility functions for MFA functionality.

This module provides helper functions for schema generation and
handler management in the MFA system.
"""

from typing import Any

from rest_framework.serializers import Serializer

from auth_kit.mfa.handlers.base import MFAHandlerRegistry
from auth_kit.mfa.mfa_settings import auth_kit_mfa_settings


def get_setup_data_schemas() -> list[type[Serializer[Any]]]:
    """
    Get serializer classes for all handler dispatch messages.

    Used for generating polymorphic OpenAPI schemas that show
    different response formats for various MFA method types.

    Returns:
        List of serializer classes for method setup responses
    """
    handlers = MFAHandlerRegistry.get_handlers()
    return [
        handler.get_initialize_method_serializer_class()
        for handler in handlers.values()
    ]


def get_login_challenge_schemas() -> list[type[Serializer[Any]]]:
    """
    Get serializer classes for all handler login challenges.

    Used for generating polymorphic OpenAPI schemas that show
    different challenge formats for various MFA method types.

    Returns:
        List of serializer classes for login challenge responses
    """
    handlers = MFAHandlerRegistry.get_handlers()
    return [
        handler.get_login_challenge_serializer_class() for handler in handlers.values()
    ]


def get_mfa_login_first_step_response_schemas() -> list[type[Serializer[Any]]]:
    """
    Get serializer classes for MFA login first step responses.

    Returns both MFA-enabled and no-MFA response serializers for
    OpenAPI schema generation.

    Returns:
       List of serializer classes for first step login responses
    """
    return [
        auth_kit_mfa_settings.MFA_FIRST_STEP_RESPONSE_SERIALIZER,
        auth_kit_mfa_settings.GET_NO_MFA_LOGIN_RESPONSE_SERIALIZER(),
    ]
