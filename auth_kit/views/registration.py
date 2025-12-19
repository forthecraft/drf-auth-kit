"""
User registration views for Auth Kit.

This module provides views for user registration, email verification,
and email verification resend functionality.
"""

# pyright: reportMissingTypeStubs=false, reportUnknownVariableType=false
from typing import Any, NoReturn
from urllib.parse import urlencode

from django.contrib.auth.base_user import AbstractBaseUser
from django.db.models import QuerySet
from django.http import HttpResponseBase
from django.urls import reverse
from django.utils.translation import gettext_lazy as _
from rest_framework import status
from rest_framework.exceptions import MethodNotAllowed
from rest_framework.generics import CreateAPIView
from rest_framework.permissions import AllowAny
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from allauth.account import app_settings as allauth_account_settings
from allauth.account.adapter import get_adapter
from allauth.account.app_settings import EmailVerificationMethod
from allauth.account.models import EmailAddress, get_emailconfirmation_model
from allauth.account.views import ConfirmEmailView
from allauth.utils import build_absolute_uri
from drf_spectacular.utils import OpenApiResponse, extend_schema

from auth_kit.api_descriptions import (
    EMAIL_RESEND_DESCRIPTION,
    EMAIL_VERIFY_DESCRIPTION,
    get_register_description,
)
from auth_kit.app_settings import auth_kit_settings
from auth_kit.serializers import (
    ResendEmailVerificationSerializer,
    VerifyEmailSerializer,
)
from auth_kit.utils import build_frontend_url, sensitive_post_parameters_m


def get_email_verification_url(request: Request, emailconfirmation: Any) -> str:
    """
    Generate email verification URL with confirmation key.

    Args:
        request: The DRF request object
        emailconfirmation: Email confirmation instance

    Returns:
        Complete email verification URL with query parameters
    """
    query_params: dict[str, str] = {"key": str(emailconfirmation.key)}

    # Determine the path to use
    path = auth_kit_settings.REGISTER_EMAIL_CONFIRM_PATH
    if not path:
        path = reverse(f"{auth_kit_settings.URL_NAMESPACE}rest_verify_email")

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


def send_verify_email(request: Request, user: AbstractBaseUser) -> None:
    """
    Send email verification message to user.

    Args:
        request: The DRF request object
        user: User instance to send verification email to
    """
    if allauth_account_settings.EMAIL_VERIFICATION == EmailVerificationMethod.NONE:
        return

    email_template = "account/email/email_confirmation_signup"

    # getattr safely accesses email field which may vary across user models
    email_address = EmailAddress.objects.get_for_user(  # pyright: ignore
        user,
        getattr(user, "email"),  # noqa: B009
    )
    model = get_emailconfirmation_model()
    emailconfirmation = model.create(email_address)  # pyright: ignore
    adapter = get_adapter()

    ctx: dict[str, Any] = {
        "user": user,
        "key": emailconfirmation.key,
        "activate_url": auth_kit_settings.GET_EMAIL_VERIFICATION_URL_FUNC(
            request, emailconfirmation
        ),
    }
    adapter.send_mail(
        email_template, emailconfirmation.email_address.email, ctx  # pyright: ignore
    )


class RegisterView(CreateAPIView[Any]):
    """
    User Registration

    Create new user accounts with email verification.
    Users must verify their email address before the account is fully activated.
    """

    serializer_class = auth_kit_settings.REGISTER_SERIALIZER
    authentication_classes = []
    permission_classes = (AllowAny,)
    throttle_scope = "auth_kit"

    @sensitive_post_parameters_m
    def dispatch(self, *args: Any, **kwargs: Any) -> HttpResponseBase:
        """
        Dispatch the request with sensitive parameter protection.

        Args:
            *args: Variable length argument list
            **kwargs: Arbitrary keyword arguments

        Returns:
            HTTP response
        """
        return super().dispatch(*args, **kwargs)

    def get_response_data(self, user: AbstractBaseUser) -> dict[str, Any]:
        """
        Get response data for successful registration.

        Args:
            user: The newly registered user

        Returns:
            Dictionary containing response message
        """
        if (
            allauth_account_settings.EMAIL_VERIFICATION
            == allauth_account_settings.EmailVerificationMethod.MANDATORY
        ):
            return {"detail": _("Verification e-mail sent.")}
        return {"detail": _("Successfully registered.")}

    @extend_schema(description=get_register_description())
    def post(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        """
        Create a new user account.

        Args:
            request: The DRF request object
            *args: Variable length argument list
            **kwargs: Arbitrary keyword arguments

        Returns:
            DRF response with registration result
        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        auth_kit_settings.SEND_VERIFY_EMAIL_FUNC(self.request, user)
        headers = self.get_success_headers(serializer.data)
        data = self.get_response_data(user)

        response = Response(
            data,
            status=status.HTTP_201_CREATED,
            headers=headers,
        )

        return response


class VerifyEmailView(APIView, ConfirmEmailView):  # type: ignore[misc]
    """
    Email Verification

    Verify email addresses using confirmation keys sent via email.
    Required to activate user accounts after registration.
    """

    permission_classes = (AllowAny,)
    authentication_classes = []

    def get_serializer(self, *args: Any, **kwargs: Any) -> VerifyEmailSerializer:
        """
        Get the email verification serializer.

        Args:
            *args: Variable length argument list
            **kwargs: Arbitrary keyword arguments

        Returns:
            Email verification serializer instance
        """
        return VerifyEmailSerializer(*args, **kwargs)

    @extend_schema(responses={405: OpenApiResponse(description="Method not allowed")})
    def get(self, *args: Any, **kwargs: Any) -> NoReturn:
        """
        GET method not allowed for email verification.
        """
        raise MethodNotAllowed("GET")

    @extend_schema(description=EMAIL_VERIFY_DESCRIPTION)
    def post(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        """
        Verify email address using confirmation key.

        Args:
            request: The DRF request object
            *args: Variable length argument list
            **kwargs: Arbitrary keyword arguments

        Returns:
            DRF response with verification result
        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.kwargs["key"] = serializer.validated_data["key"]
        confirmation = self.get_object()
        confirmation.confirm(self.request)
        return Response({"detail": _("ok")}, status=status.HTTP_200_OK)


class ResendEmailVerificationView(CreateAPIView[Any]):
    """
    Resend Email Verification

    Request a new email verification message for unverified accounts.
    Useful when the original verification email was lost or expired.
    """

    authentication_classes = []
    permission_classes = (AllowAny,)
    serializer_class = ResendEmailVerificationSerializer

    def get_queryset(self) -> QuerySet[EmailAddress]:
        """
        Get queryset of email addresses for verification resend.

        Returns:
            QuerySet of EmailAddress objects for filtering and lookup
            during email verification resend operations
        """
        return EmailAddress.objects.get_queryset()  # type: ignore[no-any-return]

    @extend_schema(description=EMAIL_RESEND_DESCRIPTION)
    def post(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        """
        Send new email verification message.

        Args:
            request: The DRF request object
            *args: Variable length argument list
            **kwargs: Arbitrary keyword arguments

        Returns:
            DRF response with success message
        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = self.get_queryset().filter(**serializer.validated_data).first()
        if email and not email.verified:
            auth_kit_settings.SEND_VERIFY_EMAIL_FUNC(self.request, email.user)

        return Response({"detail": _("ok")}, status=status.HTTP_200_OK)
