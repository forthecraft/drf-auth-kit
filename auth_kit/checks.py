"""
Django system checks for Auth Kit configuration.
"""

from typing import Any

from django.core.checks import Warning, register

from auth_kit.app_settings import auth_kit_settings


@register()
def check_partitioned_cookie_config(**kwargs: Any) -> list[Warning]:
    """
    Verify that AUTH_COOKIE_PARTITIONED is used with compatible settings.

    The CHIPS spec requires Partitioned cookies to also have
    SameSite=None and Secure=True. Without these, browsers will
    silently reject the cookie.
    """
    errors: list[Warning] = []

    if not auth_kit_settings.AUTH_COOKIE_PARTITIONED:
        return errors

    if auth_kit_settings.AUTH_COOKIE_SAMESITE != "None":
        errors.append(
            Warning(
                "AUTH_COOKIE_PARTITIONED is enabled but AUTH_COOKIE_SAMESITE "
                'is not set to "None".',
                hint=(
                    "The CHIPS specification requires Partitioned cookies to "
                    'use SameSite=None. Set AUTH_COOKIE_SAMESITE to "None".'
                ),
                id="auth_kit.W001",
            )
        )

    if not auth_kit_settings.AUTH_COOKIE_SECURE:
        errors.append(
            Warning(
                "AUTH_COOKIE_PARTITIONED is enabled but AUTH_COOKIE_SECURE "
                "is not set to True.",
                hint=(
                    "The CHIPS specification requires Partitioned cookies to "
                    "be Secure. Set AUTH_COOKIE_SECURE to True."
                ),
                id="auth_kit.W002",
            )
        )

    return errors
