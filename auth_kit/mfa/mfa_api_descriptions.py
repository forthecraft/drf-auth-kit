"""
API descriptions for Auth Kit MFA endpoints.

This module provides dynamic descriptions for OpenAPI schema generation
of MFA-related endpoints based on Auth Kit configuration settings.
"""

from typing import TYPE_CHECKING

from django.utils.text import format_lazy
from django.utils.translation import gettext_lazy as _

from auth_kit.api_descriptions import (
    get_auth_cookie_description,
    get_auth_tokens_name,
    get_auth_type_description,
)
from auth_kit.mfa.mfa_settings import auth_kit_mfa_settings

if TYPE_CHECKING:  # pragma: no cover
    from django.utils.functional import _StrOrPromise
else:
    _StrOrPromise = str


def get_mfa_ephemeral_token_expiry_description() -> _StrOrPromise:
    """Get ephemeral token expiry description."""
    return format_lazy(
        _("MFA code expires in {} seconds."),
        auth_kit_mfa_settings.MFA_EPHEMERAL_TOKEN_EXPIRY,
    )


def get_mfa_login_first_step_description() -> _StrOrPromise:
    """Generate dynamic first step login description based on MFA settings."""
    base = _(
        "First step of MFA-enabled authentication. Validates credentials and initiates MFA flow."
    )

    auth_part = format_lazy(
        _(
            "Returns ephemeral token for MFA verification or complete {} if MFA is disabled."
        ),
        get_auth_tokens_name(),
    )

    mfa_part = get_mfa_ephemeral_token_expiry_description()

    return format_lazy("{} {} {}", base, auth_part, mfa_part)


def get_mfa_login_second_step_description() -> _StrOrPromise:
    """Generate dynamic second step login description based on authentication type."""
    base = _("Complete MFA authentication using verification code and ephemeral token.")

    # Reuse auth type and cookie descriptions from main api_descriptions
    auth_part = get_auth_type_description()
    cookie_part = get_auth_cookie_description()
    verification_part = _("Supports both TOTP codes and backup codes for verification.")

    if cookie_part:
        return format_lazy(
            "{} {} {} {}", base, auth_part, cookie_part, verification_part
        )
    else:
        return format_lazy("{} {} {}", base, auth_part, verification_part)


def get_mfa_login_change_method_description() -> _StrOrPromise:
    """Generate description for MFA method change during login."""
    base = _("Switch to a different MFA method during authentication flow.")

    requirements = _("Requires valid ephemeral token from first step authentication.")

    expiry_part = format_lazy(
        _("New ephemeral token expires in {} seconds."),
        auth_kit_mfa_settings.MFA_EPHEMERAL_TOKEN_EXPIRY,
    )

    return format_lazy("{} {} {}", base, requirements, expiry_part)


def get_mfa_login_resend_description() -> _StrOrPromise:
    """Generate description for MFA code resend functionality."""
    base = _("Resend MFA verification code using existing ephemeral token.")

    handlers_part = _(
        "Only applicable for methods that require code dispatch (e.g., email)."
    )

    expiry_part = format_lazy(
        _("New ephemeral token expires in {} seconds."),
        auth_kit_mfa_settings.MFA_EPHEMERAL_TOKEN_EXPIRY,
    )

    return format_lazy("{} {} {}", base, handlers_part, expiry_part)


# MFA Method Management Descriptions
MFA_METHOD_LIST_DESCRIPTION = _(
    "List all available MFA methods with their setup and activation status. "
    "Shows which methods are configured, active, and set as primary."
)

MFA_METHOD_CREATE_DESCRIPTION = _(
    "Initialize a new MFA method setup. Creates the method with backup codes "
    "and returns setup instructions (e.g., QR code for authenticator apps). "
    "Method must be confirmed before activation."
)

MFA_METHOD_CONFIRM_DESCRIPTION = _(
    "Confirm and activate a newly created MFA method using verification code. "
    "Automatically sets as primary method if no other primary method exists. "
    "Required before the method can be used for authentication."
)

MFA_METHOD_DEACTIVATE_DESCRIPTION = _(
    "Deactivate an active MFA method. Requires verification code from the method itself. "
    "Cannot deactivate primary methods - set another method as primary first."
)


def get_mfa_method_primary_description() -> _StrOrPromise:
    """Generate dynamic description for setting primary MFA method."""
    base = _(
        "Set an active MFA method as the primary authentication method. "
        "Primary method is used by default during login flow."
    )

    ending = _("Only one method can be primary at a time.")

    if auth_kit_mfa_settings.MFA_UPDATE_PRIMARY_METHOD_REQUIRED_PRIMARY_CODE:
        verification_part = _("Requires verification code from current primary method.")
        return format_lazy("{} {} {}", base, verification_part, ending)
    else:
        return format_lazy("{} {}", base, ending)


MFA_METHOD_SEND_CODE_DESCRIPTION = _(
    "Send verification code for methods that support code dispatch. "
    "Useful for testing method configuration or manual code requests."
)


def get_mfa_method_delete_description() -> _StrOrPromise:
    """Generate dynamic description for MFA method deletion."""
    base = _("Permanently delete an MFA method.")
    ending = _("This action cannot be undone.")

    restrictions = []

    if auth_kit_mfa_settings.MFA_PREVENT_DELETE_ACTIVE_METHOD:
        restrictions.append(_("Cannot delete active methods."))

    if auth_kit_mfa_settings.MFA_PREVENT_DELETE_PRIMARY_METHOD:
        restrictions.append(_("Cannot delete primary methods."))

    if auth_kit_mfa_settings.MFA_DELETE_ACTIVE_METHOD_REQUIRE_CODE:
        restrictions.append(_("Requires verification code for active methods."))

    if restrictions:
        # Build format string dynamically based on number of restrictions
        restrictions_format = " ".join(["{}" for _item in restrictions])
        restrictions_text = format_lazy(restrictions_format, *restrictions)
        return format_lazy("{} {} {}", base, restrictions_text, ending)
    else:
        return format_lazy("{} {}", base, ending)
