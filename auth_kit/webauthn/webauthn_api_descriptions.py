"""
API descriptions for WebAuthn credential management endpoints.
"""

from django.utils.translation import gettext_lazy as _

WEBAUTHN_CREDENTIAL_LIST_DESCRIPTION = _(
    "List all passkeys and security keys registered for the authenticated user."
)

WEBAUTHN_CREDENTIAL_CREATE_DESCRIPTION = _(
    "Register a new passkey or security key. "
    "Submit the credential from the browser after calling the register_options endpoint."
)

WEBAUTHN_CREDENTIAL_REGISTER_OPTIONS_DESCRIPTION = _(
    "Get registration options for adding a new passkey or security key. "
    "Returns a challenge for the browser to create the credential."
)

WEBAUTHN_CREDENTIAL_UPDATE_DESCRIPTION = _("Rename a passkey or security key.")

WEBAUTHN_CREDENTIAL_DELETE_DESCRIPTION = _(
    "Delete a passkey or security key. This action cannot be undone."
)
