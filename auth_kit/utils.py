"""
Utility functions for Auth Kit.

This module provides helper functions for JWT token generation,
security decorators, type casting utilities, and user model references.
"""

from collections.abc import Sequence
from typing import Any, TypeAlias, cast
from urllib.parse import urlencode

from django.contrib.auth import get_user_model
from django.contrib.auth.models import AbstractBaseUser
from django.forms import Form
from django.urls import URLPattern, URLResolver
from django.utils.decorators import method_decorator
from django.views.decorators.debug import sensitive_post_parameters

import structlog

from auth_kit.app_settings import auth_kit_settings

UserModel: type[AbstractBaseUser] = get_user_model()  # type: ignore[assignment, unused-ignore]
UserNameField: str = UserModel.USERNAME_FIELD  # type: ignore[attr-defined]
UserModelType: TypeAlias = AbstractBaseUser

sensitive_post_parameters_m = method_decorator(
    sensitive_post_parameters(
        "password",
        "old_password",
        "new_password1",
        "new_password2",
        "password1",
        "password2",
    ),
)


def cast_dict(arg: Any) -> dict[str, Any]:
    """
    Cast an argument to a dictionary type.

    Args:
        arg: The argument to cast

    Returns:
        The argument cast as a dictionary
    """
    return cast(dict[str, Any], arg)


def filter_excluded_urls(
    patterns: Sequence[URLPattern | URLResolver],
) -> list[URLPattern | URLResolver]:
    """
    Filter out URL patterns that are in the EXCLUDED_URL_NAMES setting.

    Args:
        patterns: Sequence of URL patterns to filter

    Returns:
        Filtered list of URL patterns
    """
    if not auth_kit_settings.EXCLUDED_URL_NAMES:
        return list(patterns)

    excluded_names = set(auth_kit_settings.EXCLUDED_URL_NAMES)
    return [
        pattern
        for pattern in patterns
        if not (
            isinstance(pattern, URLPattern)
            and pattern.name is not None
            and pattern.name in excluded_names
        )
    ]


logger: structlog.stdlib.BoundLogger = structlog.get_logger("chanx")


def convert_form_errors_to_drf(form: Form) -> dict[str, list[str]]:
    """
    Convert Django form errors to DRF-compatible format.

    Args:
        form: Django form instance with errors

    Returns:
        Dictionary with field names as keys and lists of error messages as values
    """
    errors = {}

    # Convert field errors
    for field_name, field_errors in form.errors.items():
        if field_name == "__all__":
            # Non-field errors go to "non_field_errors" key (DRF convention)
            errors["non_field_errors"] = [str(error) for error in field_errors]
        else:
            errors[field_name] = [str(error) for error in field_errors]

    return errors


def build_frontend_url(base_url: str, path: str, query_params: dict[str, str]) -> str:
    """
    Build a complete frontend URL from base URL, path, and query parameters.

    Args:
        base_url: Frontend base URL
        path: URL path
        query_params: Query parameters dictionary

    Returns:
        Complete URL with query parameters
    """
    encoded_params = urlencode(query_params)
    base_url = base_url.rstrip("/")
    path = path.lstrip("/")
    return f"{base_url}/{path}?{encoded_params}"
