"""Tests for passwordless base handler functionality."""

# pyright: reportUnusedClass=false

from django.test import TestCase

import pytest
from auth_kit.passwordless.handlers.base import (
    PasswordlessBaseHandler,
    PasswordlessHandlerRegistry,
)


class TestPasswordlessBaseHandler(TestCase):
    """Test cases for PasswordlessBaseHandler base class."""

    def test_invalid_name_handler(self) -> None:
        """Test that invalid NAME format raises ValueError."""
        with pytest.raises(ValueError):

            class InvalidNameHandler(PasswordlessBaseHandler):
                NAME = "Invalid-Name"

    def test_no_name_handler(self) -> None:
        """Test that missing NAME raises ValueError."""
        with pytest.raises(ValueError):

            class NoNameHandler(PasswordlessBaseHandler):
                NAME = ""

    def test_auto_display_name(self) -> None:
        """Test that DISPLAY_NAME is auto-generated from NAME."""

        class TestHandler(PasswordlessBaseHandler):
            NAME = "my_method"

        assert TestHandler.DISPLAY_NAME == "MY METHOD"

    def test_custom_display_name(self) -> None:
        """Test that custom DISPLAY_NAME is preserved."""

        class TestHandler(PasswordlessBaseHandler):
            NAME = "my_method"
            DISPLAY_NAME = "Custom Name"

        assert TestHandler.DISPLAY_NAME == "Custom Name"

    def test_default_is_multi_factor(self) -> None:
        """Test default IS_MULTI_FACTOR is False."""

        class TestHandler(PasswordlessBaseHandler):
            NAME = "test_method"

        assert TestHandler.IS_MULTI_FACTOR is False


class TestPasswordlessHandlerRegistry(TestCase):
    """Test cases for PasswordlessHandlerRegistry."""

    def setUp(self) -> None:
        """Save and restore registry state."""
        self._original_handlers = PasswordlessHandlerRegistry._handlers.copy()
        self._original_imported = PasswordlessHandlerRegistry.imported_handler

    def tearDown(self) -> None:
        """Restore registry state."""
        PasswordlessHandlerRegistry._handlers = self._original_handlers
        PasswordlessHandlerRegistry.imported_handler = self._original_imported

    def test_register_handler(self) -> None:
        """Test registering a handler."""

        class TestHandler(PasswordlessBaseHandler):
            NAME = "registry_test"

        PasswordlessHandlerRegistry.register(TestHandler)
        assert "registry_test" in PasswordlessHandlerRegistry._handlers

    def test_get_handler_class(self) -> None:
        """Test retrieving a registered handler."""

        class TestHandler(PasswordlessBaseHandler):
            NAME = "lookup_test"

        PasswordlessHandlerRegistry.register(TestHandler)
        found = PasswordlessHandlerRegistry.get_handler_class("lookup_test")
        assert found is TestHandler

    def test_get_handler_class_not_found(self) -> None:
        """Test error for unregistered handler."""
        with pytest.raises(ValueError):
            PasswordlessHandlerRegistry.get_handler_class("nonexistent")

    def test_list_handler_names(self) -> None:
        """Test listing registered handler names."""
        names = PasswordlessHandlerRegistry.list_handler_names()
        assert isinstance(names, list)
