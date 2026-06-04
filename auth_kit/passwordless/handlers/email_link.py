"""
Email magic link handler for passwordless authentication.

This module provides the EmailLinkHandler that sends a time-limited
magic link to the user's email address for passwordless login.
"""

from typing import Any

from django.conf import settings as django_settings
from django.core.mail import send_mail
from django.template.loader import get_template
from django.utils.translation import gettext_lazy as _
from rest_framework.serializers import Serializer

from auth_kit.passwordless.handlers.base import (
    PasswordlessBaseHandler,
    PasswordlessHandlerRegistry,
)
from auth_kit.passwordless.passwordless_settings import auth_kit_passwordless_settings
from auth_kit.passwordless.serializers.email_link import (
    EmailLinkInitiateSerializer,
    EmailLinkVerifySerializer,
)
from auth_kit.passwordless.services.token import (
    passwordless_signup_token_service,
    passwordless_token_service,
)
from auth_kit.utils import find_user_by_email


class EmailLinkHandler(PasswordlessBaseHandler):
    """
    Passwordless authentication via email magic link.

    Sends a time-limited token via email that allows the user
    to authenticate without a password. Since this only proves
    access to the email inbox (single factor), MFA is still
    applied after verification if configured.
    """

    NAME = "email"
    DISPLAY_NAME = _("Email Magic Link")
    IS_MULTI_FACTOR = False

    @classmethod
    def get_initiate_serializer_class(cls) -> type[Serializer[Any]]:
        """Get serializer for the email initiate step."""
        return EmailLinkInitiateSerializer

    @classmethod
    def get_verify_serializer_class(cls) -> type[Serializer[Any]]:
        """Get serializer for the email verify step."""
        return EmailLinkVerifySerializer

    @classmethod
    def handle_initiate(
        cls, validated_data: dict[str, Any], context: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Send magic link email to the user.

        Looks up the user by email and sends a magic link.
        For security, always returns success even if the email
        doesn't exist (prevents email enumeration).

        Args:
            validated_data: Contains 'email' field
            context: Serializer context

        Returns:
            Detail message dictionary
        """
        email = validated_data["email"]

        user = find_user_by_email(email)
        if (
            user is None
            and not auth_kit_passwordless_settings.PASSWORDLESS_EMAIL_SIGNUP
        ):
            # Don't reveal whether the email exists
            return {"detail": str(_("A login link has been sent."))}

        if user is not None:
            token = passwordless_token_service.make_token(user)
        else:
            token = passwordless_signup_token_service.make_token(email)

        magic_link_url = auth_kit_passwordless_settings.PASSWORDLESS_MAGIC_LINK_URL
        if magic_link_url:
            link = f"{magic_link_url}?token={token}"
        else:
            link = token

        template_context = {
            "token": token,
            "link": link,
            "user": user,
        }

        plain_template = (
            auth_kit_passwordless_settings.PASSWORDLESS_EMAIL_PLAIN_TEMPLATE
        )
        html_template = auth_kit_passwordless_settings.PASSWORDLESS_EMAIL_HTML_TEMPLATE

        send_mail(
            subject=str(auth_kit_passwordless_settings.PASSWORDLESS_EMAIL_SUBJECT),
            message=get_template(plain_template).render(template_context),
            html_message=get_template(html_template).render(template_context),
            from_email=django_settings.DEFAULT_FROM_EMAIL,
            recipient_list=[email],
            fail_silently=False,
        )

        return {"detail": str(_("A login link has been sent."))}

    @classmethod
    def handle_verify(
        cls, validated_data: dict[str, Any], context: dict[str, Any]
    ) -> Any:
        """
        Verify the magic link token.

        The actual token validation is done in the serializer's
        validate() method, which sets context['user'].

        Args:
            validated_data: Validated data from serializer
            context: Serializer context with 'user' key

        Returns:
            Authenticated user instance
        """
        return context["user"]


PasswordlessHandlerRegistry.register(EmailLinkHandler)
