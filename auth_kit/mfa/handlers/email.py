"""
Email-based MFA handler for Auth Kit.

This module provides email-based multi-factor authentication by sending
TOTP codes via email to users.
"""

from django.conf import settings
from django.core.mail import send_mail
from django.template.loader import get_template
from django.utils.translation import gettext_lazy as _

from .base import MFABaseHandler, MFAHandlerRegistry


class MFAEmailHandler(MFABaseHandler):
    """
    Email-based MFA handler.

    Sends TOTP verification codes to user's email address. Codes stay valid
    for 2-3 minutes to allow for email delivery delays.
    """

    NAME = "email"
    # pyotp caps the interval at 120s; the window keeps codes valid 2-3 minutes.
    TOTP_INTERVAL = 60
    TOTP_VALID_WINDOW = 2
    EMAIL_PLAIN_TEMPLATE = "auth_kit/mfa/email/code.txt"
    EMAIL_HTML_TEMPLATE = "auth_kit/mfa/email/code.html"
    EMAIL_SUBJECT = "Your verification code"
    SETUP_RESPONSE_MESSAGE = _("Email message with MFA code has been sent.")

    def send_code(self) -> None:
        """
        Send TOTP code via email.

        Generates current TOTP code and sends it to user's email address
        using both plain text and HTML templates.
        """
        context = {"code": self.get_otp_code()}
        email_plain_template = self.EMAIL_PLAIN_TEMPLATE
        email_html_template = self.EMAIL_HTML_TEMPLATE
        send_mail(
            subject=self.EMAIL_SUBJECT,
            message=get_template(email_plain_template).render(context),
            html_message=get_template(email_html_template).render(context),
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=(
                self.mfa_method.user.email,
            ),  # pyright: ignore[reportUnknownArgumentType]
            fail_silently=False,
        )


MFAHandlerRegistry.register(MFAEmailHandler)
