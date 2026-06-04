"""
Base classes and registry for passwordless handlers.

This module provides the base handler class that all passwordless methods
must inherit from, along with a registry system for managing available
passwordless handlers.
"""

import re
from typing import TYPE_CHECKING, Any

from rest_framework.serializers import Serializer

from auth_kit.passwordless.passwordless_settings import auth_kit_passwordless_settings

if TYPE_CHECKING:  # pragma: no cover
    from django.contrib.auth.base_user import AbstractBaseUser
    from django.utils.functional import (
        _StrPromise,  # pyright: ignore[reportPrivateUsage]
    )
else:
    _StrPromise = str


class PasswordlessBaseHandler:
    """
    Base class for all passwordless authentication handlers.

    Provides the interface for passwordless login flows. Subclasses must
    implement method-specific behavior for initiating and verifying
    passwordless authentication.

    Subclasses must define a NAME (snake_case method identifier) and
    optionally customize DISPLAY_NAME (human-readable name) and
    IS_MULTI_FACTOR flag (whether the method provides multi-factor
    assurance, allowing MFA to be skipped after verification).
    """

    NAME = ""
    DISPLAY_NAME: str | _StrPromise = ""
    IS_MULTI_FACTOR = False

    def __init_subclass__(cls, **kwargs: Any) -> None:
        """
        Validate subclass configuration.

        Args:
            **kwargs: Additional keyword arguments

        Raises:
            ValueError: If NAME is not set or invalid format
        """
        super().__init_subclass__(**kwargs)
        if not cls.NAME:
            raise ValueError(f"Class {cls.__name__} must define a non-empty NAME")

        if not re.match(r"^[a-z]+(_[a-z]+)*$", cls.NAME):
            raise ValueError(
                f"Class {cls.__name__} NAME must be in snake_case format "
                "(lowercase letters and underscores only)"
            )

        if not cls.DISPLAY_NAME:
            cls.DISPLAY_NAME = cls.NAME.replace("_", " ").upper()  # pyright: ignore

    @classmethod
    def get_initiate_serializer_class(cls) -> type[Serializer[Any]]:
        """
        Get serializer class for the initiate step.

        A single serializer carries both directions: write-only fields are
        the accepted input, read-only fields are the returned payload.

        Returns:
            Serializer class for the initiate step
        """
        raise NotImplementedError  # pragma: no cover

    @classmethod
    def get_verify_serializer_class(cls) -> type[Serializer[Any]]:
        """
        Get serializer class for the verify step.

        Returns:
            Serializer class for the verify step
        """
        raise NotImplementedError  # pragma: no cover

    @classmethod
    def handle_initiate(
        cls, validated_data: dict[str, Any], context: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Process the initiate step.

        Called after the initiate serializer validates input. Should
        initiate the passwordless flow (e.g., send magic link, generate
        challenge) and return data for the response.

        Args:
            validated_data: Validated initiate data
            context: Serializer context (includes 'request')

        Returns:
            Response data dictionary
        """
        raise NotImplementedError  # pragma: no cover

    @classmethod
    def handle_verify(
        cls, validated_data: dict[str, Any], context: dict[str, Any]
    ) -> "AbstractBaseUser":
        """
        Process the verification step.

        Called after the verify serializer validates input. Should
        verify the passwordless credential and return the authenticated user.

        Args:
            validated_data: Validated verification data
            context: Serializer context (includes 'request')

        Returns:
            Authenticated user instance
        """
        raise NotImplementedError  # pragma: no cover


class PasswordlessHandlerRegistry:
    """
    Registry for managing available passwordless handlers.

    Provides centralized registration and retrieval of passwordless
    handler classes. Handlers are automatically imported when first accessed.

    Class Attributes:
        _handlers: Dictionary mapping method names to handler classes
        imported_handler: Flag tracking whether handlers have been imported
    """

    _handlers: dict[str, type[PasswordlessBaseHandler]] = {}
    imported_handler = False

    @classmethod
    def register(cls, handler_class: type[PasswordlessBaseHandler]) -> None:
        """
        Register a handler class.

        Args:
            handler_class: Handler class to register
        """
        cls._handlers[handler_class.NAME] = handler_class

    @classmethod
    def _prefetch_handlers(cls) -> None:
        """Import all configured handlers if not already done."""
        if not cls.imported_handler:
            list(auth_kit_passwordless_settings.PASSWORDLESS_HANDLERS)
            cls.imported_handler = True

    @classmethod
    def get_handler_class(cls, handler_name: str) -> type[PasswordlessBaseHandler]:
        """
        Get handler class by method name.

        Args:
            handler_name: Name of the passwordless method

        Returns:
            Handler class for the method

        Raises:
            ValueError: If method name is not supported
        """
        cls._prefetch_handlers()

        handler_class = cls._handlers.get(handler_name.lower())
        if not handler_class:
            raise ValueError(f"Unsupported passwordless method: {handler_name}")
        return handler_class

    @classmethod
    def list_handler_names(cls) -> list[str]:
        """
        Get list of all registered handler names.

        Returns:
            List of handler names
        """
        cls._prefetch_handlers()
        return list(cls._handlers.keys())

    @classmethod
    def get_handlers(cls) -> dict[str, type[PasswordlessBaseHandler]]:
        """
        Get all registered handlers.

        Returns:
            Dictionary mapping names to handler classes
        """
        cls._prefetch_handlers()
        return cls._handlers
