"""Tests for email MFA handler."""

from django.test import TestCase

from auth_kit.mfa.handlers.email import MFAEmailHandler
from freezegun import freeze_time

from test_utils.mfa_factory import MFAMethodFactory


class TestMFAEmailHandler(TestCase):
    """Test cases for MFAEmailHandler code lifetime."""

    def setUp(self) -> None:
        """Set up test data."""
        self.handler = MFAEmailHandler(MFAMethodFactory.create(name="email"))

    def test_code_valid_for_two_minutes(self) -> None:
        """A code sent at the end of a window is still accepted 2 minutes later."""
        with freeze_time("2012-01-14 12:00:59"):
            code = self.handler.get_otp_code()

        with freeze_time("2012-01-14 12:02:59"):
            assert self.handler.validate_otp_code(code) is True

    def test_code_expires_after_three_minutes(self) -> None:
        """A code is rejected once it is more than 3 minutes old."""
        with freeze_time("2012-01-14 12:00:00"):
            code = self.handler.get_otp_code()

        with freeze_time("2012-01-14 12:03:00"):
            assert self.handler.validate_otp_code(code) is False
