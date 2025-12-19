"""
Tests for Auth Kit utility functions.

This module tests utility functions including form error conversion
and other helper functions used across the Auth Kit package.
"""

from typing import Any

from django import forms
from django.test import TestCase

from auth_kit.utils import convert_form_errors_to_drf


class MockForm(forms.Form):
    """Mock form class for testing form error conversion."""

    username = forms.CharField(max_length=100)
    email = forms.EmailField()
    password = forms.CharField(widget=forms.PasswordInput)


class ConvertFormErrorsToDRFTests(TestCase):
    """Tests for convert_form_errors_to_drf function."""

    def test_field_errors_conversion(self) -> None:
        """Test conversion of individual field errors to DRF format."""
        form = MockForm(
            data={
                "username": "",  # Required field - will cause error
                "email": "invalid-email",  # Invalid email format
                "password": "pass",  # Valid password
            }
        )

        # Form should be invalid
        assert not form.is_valid()

        # Convert errors to DRF format
        drf_errors = convert_form_errors_to_drf(form)

        # Check that errors are properly formatted
        assert "username" in drf_errors
        assert "email" in drf_errors
        assert "password" not in drf_errors  # No error for password

        # Check that error values are lists of strings
        assert isinstance(drf_errors["username"], list)
        assert isinstance(drf_errors["email"], list)
        assert all(isinstance(error, str) for error in drf_errors["username"])
        assert all(isinstance(error, str) for error in drf_errors["email"])

        # Check error messages
        assert drf_errors["username"][0] == "This field is required."
        assert drf_errors["email"][0] == "Enter a valid email address."

    def test_non_field_errors_conversion(self) -> None:
        """Test conversion of non-field errors to DRF format."""

        class FormWithNonFieldErrors(forms.Form):
            password1 = forms.CharField()
            password2 = forms.CharField()

            def clean(self) -> dict[str, Any]:
                cleaned_data = super().clean()
                if cleaned_data is None:
                    return {}

                password1 = cleaned_data.get("password1")
                password2 = cleaned_data.get("password2")

                if password1 and password2 and password1 != password2:
                    raise forms.ValidationError("Passwords don't match.")

                return cleaned_data

        form = FormWithNonFieldErrors(
            data={"password1": "pass123", "password2": "different123"}
        )

        # Form should be invalid due to non-field error
        assert not form.is_valid()

        # Convert errors to DRF format
        drf_errors = convert_form_errors_to_drf(form)

        # Check that non-field errors are converted to "non_field_errors" key
        assert "non_field_errors" in drf_errors
        assert isinstance(drf_errors["non_field_errors"], list)
        assert drf_errors["non_field_errors"][0] == "Passwords don't match."
