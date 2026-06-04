"""
Dynamic API descriptions for passwordless endpoints.

This module provides translatable description strings for passwordless
authentication API endpoints, using format_lazy for proper i18n support.
"""

from typing import TYPE_CHECKING

from django.utils.text import format_lazy
from django.utils.translation import gettext_lazy as _

from auth_kit.api_descriptions import (
    get_auth_cookie_description,
    get_auth_type_description,
)

if TYPE_CHECKING:  # pragma: no cover
    from django.utils.functional import _StrOrPromise
else:
    _StrOrPromise = str


def get_passwordless_initiate_description(
    handler_name: _StrOrPromise,
) -> _StrOrPromise:
    """
    Get description for passwordless initiate endpoint.

    Args:
        handler_name: Display name of the handler

    Returns:
        Lazy description string
    """
    return format_lazy(
        _(
            "Initiate passwordless authentication via {}. "
            "This is the first step of the passwordless login flow."
        ),
        handler_name,
    )


def get_passwordless_verify_description(
    handler_name: _StrOrPromise,
) -> _StrOrPromise:
    """
    Get description for passwordless verify endpoint.

    Args:
        handler_name: Display name of the handler

    Returns:
        Lazy description string
    """
    base = format_lazy(
        _(
            "Complete passwordless authentication via {}. "
            "Verify the credential/token from the initiate step."
        ),
        handler_name,
    )
    auth_part = get_auth_type_description()
    cookie_part = get_auth_cookie_description()

    if cookie_part:
        return format_lazy("{} {} {}", base, auth_part, cookie_part)
    else:
        return format_lazy("{} {}", base, auth_part)
