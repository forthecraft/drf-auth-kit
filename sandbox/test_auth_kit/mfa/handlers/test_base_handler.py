"""Tests for MFA base handler functionality."""

# pyright: reportUnusedClass=false

from unittest.mock import Mock, patch

from django.test import TestCase

import pytest
from auth_kit.mfa.handlers.base import (
    MFABaseHandler,
    MFAHandlerRegistry,
    SetupMethodSerializer,
)
from auth_kit.test_utils import override_auth_kit_settings
from freezegun import freeze_time

from test_utils.mfa_factory import MFAMethodFactory
from test_utils.user_factory import UserFactory


class MFAHandlerSubclass(MFABaseHandler):
    """Test handler for testing base functionality."""

    NAME = "test_handler"
    DISPLAY_NAME = "Test Handler"
    REQUIRES_DISPATCH = True
    SETUP_RESPONSE_MESSAGE = "Test setup message"

    def send_code(self) -> None:
        """Mock send code implementation."""
        pass


class TestMFABaseHandler(TestCase):
    """Test cases for MFABaseHandler base class."""

    def setUp(self) -> None:
        """Set up test data."""
        self.user = UserFactory.create()
        self.mfa_method = MFAMethodFactory.create(
            user=self.user,
            name="test_handler",
            secret="JBSWY3DPEHPK3PXP",  # Base32 encoded secret
        )
        self.handler = MFAHandlerSubclass(self.mfa_method)

    def test_invalid_name_handler(self) -> None:
        with pytest.raises(ValueError):

            class InvalidNameHandler(MFABaseHandler):
                """Handler with invalid name for testing validation."""

                NAME = "Invalid-Name"  # Invalid format

    def test_no_name_handler(self) -> None:
        with pytest.raises(ValueError):

            class NoNameHandler(MFABaseHandler):
                """Handler without name for testing validation."""

                pass  # Missing NAME attribute

    def test_handler_initialization(self) -> None:
        """Test handler initialization with MFA method."""
        assert self.handler.mfa_method == self.mfa_method
        assert self.handler.NAME == "test_handler"
        assert self.handler.DISPLAY_NAME == "Test Handler"

    def test_subclass_validation_success(self) -> None:
        """Test successful subclass validation."""

        # Should not raise any exceptions
        class ValidHandler(MFABaseHandler):
            NAME = "valid_name"

        assert ValidHandler.NAME == "valid_name"
        assert ValidHandler.DISPLAY_NAME == "VALID NAME"  # Auto-generated

    def test_subclass_validation_invalid_name_format(self) -> None:
        """Test subclass validation with invalid name format."""
        with pytest.raises(ValueError) as exc_info:

            class InvalidHandler(MFABaseHandler):
                NAME = "Invalid-Name"

        assert "snake_case format" in str(exc_info.value)

    def test_subclass_validation_empty_name(self) -> None:
        """Test subclass validation with empty name."""
        with pytest.raises(ValueError) as exc_info:

            class EmptyNameHandler(MFABaseHandler):
                NAME = ""

        assert "must define a non-empty NAME" in str(exc_info.value)

    def test_subclass_validation_no_name(self) -> None:
        """Test subclass validation without NAME attribute."""
        with pytest.raises(ValueError) as exc_info:

            class NoNameHandler(MFABaseHandler):
                pass

        assert "must define a non-empty NAME" in str(exc_info.value)

    def test_auto_generated_display_name(self) -> None:
        """Test auto-generation of display name from snake_case."""

        class TestSnakeCaseHandler(MFABaseHandler):
            NAME = "snake_case_name"

        assert TestSnakeCaseHandler.DISPLAY_NAME == "SNAKE CASE NAME"

    @freeze_time("2012-01-14 12:00:01")
    def test_get_otp_code(self) -> None:
        """Test TOTP code generation."""
        code = self.handler.get_otp_code()

        assert isinstance(code, str)
        assert len(code) == 6  # Default TOTP length
        assert code.isdigit()

    @freeze_time("2012-01-14 12:00:01")
    def test_validate_otp_code_success(self) -> None:
        """Test successful TOTP code validation."""
        # Generate current code
        current_code = self.handler.get_otp_code()

        # Should validate successfully
        assert self.handler.validate_otp_code(current_code) is True

    @freeze_time("2012-01-14 12:00:01")
    def test_validate_otp_code_failure(self) -> None:
        """Test failed TOTP code validation."""
        # Invalid code
        assert self.handler.validate_otp_code("000000") is False
        assert self.handler.validate_otp_code("invalid") is False

    def test_validate_backup_code_failure_wrong_length(self) -> None:
        """Test backup code validation with wrong length."""
        # Code with wrong length should fail immediately
        assert self.handler.validate_backup_code("short") is False
        assert self.handler.validate_backup_code("toolongcode123") is False

    def test_validate_backup_code_failure_not_found(self) -> None:
        """Test backup code validation with non-existent code."""
        backup_codes = ["code123456", "code789012"]
        self.mfa_method._backup_codes = backup_codes
        self.mfa_method.save()

        # Non-existent code should fail
        assert self.handler.validate_backup_code("wrong12345") is False

        # Original codes should remain unchanged
        self.mfa_method.refresh_from_db()
        assert self.mfa_method.backup_codes == set(backup_codes)

    @freeze_time("2012-01-14 12:00:01")
    def test_validate_code_with_otp(self) -> None:
        """Test validate_code method with valid TOTP."""
        current_code = self.handler.get_otp_code()
        assert self.handler.validate_code(current_code) is True

    def test_validate_code_failure(self) -> None:
        """Test validate_code method with invalid code."""
        assert self.handler.validate_code("invalid123") is False

    def test_initialize_method(self) -> None:
        """Test method initialization."""
        with patch.object(self.handler, "send_code") as mock_send:
            result = self.handler.initialize_method()

            mock_send.assert_called_once()
            assert result == {"detail": "Test setup message"}

    def test_get_initialize_method_serializer_class(self) -> None:
        """Test getting serializer class for method setup."""
        serializer_class = self.handler.get_initialize_method_serializer_class()
        assert serializer_class == SetupMethodSerializer

    @override_auth_kit_settings(MFA_TOTP_DEFAULT_INTERVAL=60)
    def test_custom_totp_interval(self) -> None:
        """Test handler with custom TOTP interval."""

        class CustomIntervalHandler(MFABaseHandler):
            NAME = "custom_interval"
            TOTP_INTERVAL = 60

        handler = CustomIntervalHandler(self.mfa_method)
        totp = handler._get_otp()
        assert totp.interval == 60

    @override_auth_kit_settings(MFA_TOTP_DEFAULT_VALID_WINDOW=2)
    def test_custom_valid_window(self) -> None:
        """Test handler with custom valid window."""

        class CustomWindowHandler(MFABaseHandler):
            NAME = "custom_window"
            TOTP_VALID_WINDOW = 2

        handler = CustomWindowHandler(self.mfa_method)

        # Test that the window is used in validation
        with patch.object(handler, "_get_otp") as mock_totp:
            mock_totp_instance = Mock()
            mock_totp.return_value = mock_totp_instance

            handler.validate_otp_code("123456")
            mock_totp_instance.verify.assert_called_once_with(
                otp="123456", valid_window=2
            )


class TestMFAHandlerRegistry(TestCase):
    def test_get_invalid_handler_class(self) -> None:
        with pytest.raises(ValueError, match="Unsupported MFA method"):
            MFAHandlerRegistry.get_handler_class("invalid_method")
