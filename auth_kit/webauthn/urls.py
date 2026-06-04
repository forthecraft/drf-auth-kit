"""
URL configuration for WebAuthn credential management endpoints.

This module defines URL patterns for WebAuthn credential management
including listing, registering, renaming, and deleting credentials.
"""

from rest_framework import routers

from auth_kit.utils import filter_excluded_urls
from auth_kit.webauthn.webauthn_settings import auth_kit_webauthn_settings

webauthn_router = routers.SimpleRouter()
webauthn_router.register(
    "credentials",
    auth_kit_webauthn_settings.WEBAUTHN_CREDENTIAL_VIEW_SET,
    basename="webauthn-credential",
)

urlpatterns = [
    *webauthn_router.urls,
]

# Apply URL exclusion filtering
urlpatterns = filter_excluded_urls(urlpatterns)
