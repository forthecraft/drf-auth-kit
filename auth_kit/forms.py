"""
Forms for Auth Kit authentication processes.

This module provides form classes for password reset functionality
using django-allauth integration.
"""

# pyright: reportMissingTypeStubs=false, reportUnknownVariableType=false
from typing import Any
from urllib.parse import urlencode

from django.contrib.auth.base_user import AbstractBaseUser
from django.http import HttpRequest
from django.urls import reverse
from django.utils.translation import gettext_lazy as _
from rest_framework.exceptions import ValidationError

from allauth.account.adapter import get_adapter
from allauth.account.forms import ResetPasswordForm as DefaultPasswordResetForm
from allauth.account.forms import default_token_generator
from allauth.account.utils import (
    filter_users_by_email,
    user_pk_to_url_str,
    user_username,
)
from allauth.utils import build_absolute_uri

from .app_settings import auth_kit_settings
from .utils import build_frontend_url


def password_reset_url_generator(
    request: HttpRequest, user: AbstractBaseUser, temp_key: str
) -> str:
    """
    Generate password reset URL with token and user ID.

    Args:
        request: The HTTP request object
        user: The user requesting password reset
        temp_key: Temporary token for password reset

    Returns:
        Complete password reset URL with query parameters
    """
    uid = user_pk_to_url_str(user)
    query_params: dict[str, str] = {"uid": uid, "token": temp_key}

    # Determine the path to use
    path = auth_kit_settings.PASSWORD_RESET_CONFIRM_PATH
    if not path:
        path = reverse(f"{auth_kit_settings.URL_NAMESPACE}rest_password_reset_confirm")

    # Build the full path with query params
    encoded_params = urlencode(query_params)
    path_with_params = f"{path}?{encoded_params}"

    # Check if we have a frontend base URL
    if auth_kit_settings.FRONTEND_BASE_URL:
        return build_frontend_url(
            auth_kit_settings.FRONTEND_BASE_URL, path, query_params
        )
    else:
        # Use build_absolute_uri with the backend path
        return str(build_absolute_uri(request, path_with_params))


class AllAuthPasswordResetForm(DefaultPasswordResetForm):  # type: ignore[misc]
    """
    Custom password reset form integrated with django-allauth.

    Extends the default allauth password reset form to support
    custom URL generation and Auth Kit settings.
    """

    def clean_email(self) -> str:
        """Validate email for password reset, preventing user enumeration if configured."""
        email = self.cleaned_data["email"].lower()
        email = get_adapter().clean_email(email)
        self.users: list[AbstractBaseUser] = filter_users_by_email(
            email, is_active=True, prefer_verified=True
        )
        if not self.users and not auth_kit_settings.PASSWORD_RESET_PREVENT_ENUMERATION:
            raise ValidationError(
                _("The email address is not assigned to any user account.")
            )
        return str(self.cleaned_data["email"])

    def save(self, request: HttpRequest, **kwargs: Any) -> str:
        """
        Save the password reset form and send reset email.

        Args:
            request: The HTTP request object
            **kwargs: Additional keyword arguments including token_generator and url_generator

        Returns:
            Email address that the reset email was sent to
        """
        email: str = self.cleaned_data["email"]
        token_generator = kwargs.get("token_generator", default_token_generator)

        users: list[AbstractBaseUser] = self.users

        for user in users:
            temp_key: str = token_generator.make_token(user)

            # send the password reset email
            url_generator = kwargs.get(
                "url_generator", auth_kit_settings.PASSWORD_RESET_URL_GENERATOR
            )
            url: str = url_generator(request, user, temp_key)
            uid: str = user_pk_to_url_str(user)

            context: dict[str, Any] = {
                "user": user,
                "password_reset_url": url,
                "request": request,
                "token": temp_key,
                "uid": uid,
                "username": user_username(user),
            }
            get_adapter(request).send_mail(
                "account/email/password_reset_key", email, context
            )
        return str(self.cleaned_data["email"])
