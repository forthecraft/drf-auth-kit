"""
URL configuration for MFA authentication endpoints.

This module defines URL patterns for multi-factor authentication including
login flow endpoints and MFA method management via ViewSet routing.
"""

from django.urls import re_path
from rest_framework import routers

from auth_kit.utils import filter_excluded_urls

from .mfa_settings import auth_kit_mfa_settings

mfa_router = routers.SimpleRouter()
mfa_router.register(
    "mfa", auth_kit_mfa_settings.LOGIN_MFA_METHOD_VIEW_SET, basename="mfa"
)

urlpatterns = [
    re_path(
        r"login/?$",
        auth_kit_mfa_settings.LOGIN_FIRST_STEP_VIEW.as_view(),
        name="rest_login",
    ),
    re_path(
        r"login/verify/?$",
        auth_kit_mfa_settings.LOGIN_SECOND_STEP_VIEW.as_view(),
        name="rest_login_verify",
    ),
    re_path(
        r"login/change-method/?$",
        auth_kit_mfa_settings.LOGIN_CHANGE_METHOD_VIEW.as_view(),
        name="rest_login_change_method",
    ),
    re_path(
        r"login/challenge/?$",
        auth_kit_mfa_settings.LOGIN_MFA_CHALLENGE_VIEW.as_view(),
        name="rest_login_mfa_challenge",
    ),
    re_path(
        r"login/resend/?$",
        auth_kit_mfa_settings.LOGIN_MFA_RESEND_VIEW.as_view(),
        name="rest_login_resend",
    ),
    *mfa_router.urls,
]

# Apply URL exclusion filtering
urlpatterns = filter_excluded_urls(urlpatterns)
