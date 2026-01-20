"""
Serializers for social authentication login.

This module provides serializers for handling OAuth-based social login
flows with support for both token-based and authorization code flows.
"""

from typing import TYPE_CHECKING, Any, cast

from django.utils.translation import gettext_lazy as _
from rest_framework import serializers
from rest_framework.request import Request
from rest_framework.serializers import Serializer
from rest_framework.views import APIView

import structlog
from allauth.account.utils import (  # pyright: ignore[reportMissingTypeStubs]
    filter_users_by_email,
)
from allauth.socialaccount.models import (  # pyright: ignore[reportMissingTypeStubs]
    SocialApp,
    SocialToken,
)
from allauth.socialaccount.providers.oauth2.client import (  # pyright: ignore[reportMissingTypeStubs]
    OAuth2Client,
    OAuth2Error,
)

from auth_kit.allauth_enhanced import OpenIDConnectOAuth2Adapter, SocialLogin
from auth_kit.app_settings import auth_kit_settings
from auth_kit.serializer_fields import UnquoteStringField
from auth_kit.serializers.login_factors import get_login_response_serializer
from auth_kit.utils import UserModel

if TYPE_CHECKING:  # pragma: no cover
    from auth_kit.social.views import SocialLoginView
else:
    SocialLoginView = Any

logger = structlog.get_logger(__name__)


class SocialLoginWithTokenRequestSerializer(serializers.Serializer[dict[str, Any]]):
    """
    Base serializer for social login using access tokens.

    Handles OAuth flows where the client already has an access token
    from the social provider (e.g., from client-side OAuth flows).
    """

    access_token = UnquoteStringField(required=True, write_only=True)
    id_token = UnquoteStringField(required=False, allow_blank=True, write_only=True)

    def get_social_login(
        self,
        adapter: Any,
        app: SocialApp,
        token: SocialToken,
        response: dict[str, Any],
    ) -> SocialLogin:
        """
        Create a SocialLogin instance from the OAuth token.

        Args:
            adapter: The OAuth adapter for the provider
            app: The social application configuration
            token: The OAuth token
            response: Additional OAuth response data

        Returns:
            SocialLogin instance for the authenticated user

        Raises:
            ValidationError: If token validation or user info retrieval fails
        """
        request = cast(Request, self.context.get("request"))
        try:
            social_login: SocialLogin = adapter.complete_login(
                request, app, token, response=response
            )
        except OAuth2Error as e:
            logger.exception(str(e))
            err_msg: Any = str(e)
            if auth_kit_settings.SOCIAL_HIDE_AUTH_ERROR_DETAILS:
                err_msg = _("Failed to complete OAuth flow")
            raise serializers.ValidationError(err_msg) from e

        social_login.token = token
        return social_login

    def handle_social_login(self, request: Request, login: SocialLogin) -> None:
        """
        Process the social login and handle account connection.

        Args:
            request: The DRF request object
            login: The SocialLogin instance to process
        """
        login.lookup()

        # If allauth's lookup didn't find a user (e.g., because
        # SOCIALACCOUNT_EMAIL_AUTHENTICATION=False), do our own lookup
        # when auto-connect is enabled
        if auth_kit_settings.SOCIAL_LOGIN_AUTO_CONNECT_BY_EMAIL:
            if not login.user.pk and not login.account.pk:
                self._lookup_user_by_verified_email(login)

        self.check_social_login_account(login)
        self.set_login_user(login)
        login.save(request, connect=True)

    def _lookup_user_by_verified_email(self, login: SocialLogin) -> None:
        """
        Look up existing user by email from social provider.

        This enables SOCIAL_LOGIN_AUTO_CONNECT_BY_EMAIL to work independently
        of allauth's SOCIALACCOUNT_EMAIL_AUTHENTICATION setting.

        Security model: The user has explicitly enabled auto-connect by email,
        indicating they trust their configured social providers. We use the
        email from the provider to find and connect to existing accounts.

        This protects legitimate email owners: if an attacker registers with
        someone's email (unverified), the real owner can still reclaim the
        account by logging in via a trusted social provider.

        Args:
            login: The SocialLogin instance to update with found user
        """
        # Collect emails to check for existing users
        emails_to_check: list[str] = []

        # First, consider verified emails from email_addresses
        for ea in login.email_addresses:
            if ea.verified and ea.email:
                emails_to_check.append(cast(str, ea.email))

        # If no verified emails in email_addresses, use login.user.email
        # The user has enabled SOCIAL_LOGIN_AUTO_CONNECT_BY_EMAIL, indicating
        # they trust their configured providers. Major providers (Google,
        # Microsoft, etc.) only return emails they have verified.
        if not emails_to_check and login.user.email:
            emails_to_check.append(login.user.email)  # pyright: ignore

        for email in emails_to_check:
            users = filter_users_by_email(email, prefer_verified=True)
            if users:
                login.user = users[0]
                logger.info(
                    "social_login_email_match",
                    email=email,
                    user_id=login.user.pk,
                )
                return

    def check_social_login_account(self, login: SocialLogin) -> None:
        """
        Validate the social login account before processing.

        Checks if a user with the same email already exists and handles
        auto-connection based on configuration settings.

        Args:
            login: The SocialLogin instance to validate

        Raises:
            ValidationError: If user already exists and auto-connect is disabled
        """
        if not auth_kit_settings.SOCIAL_LOGIN_AUTO_CONNECT_BY_EMAIL:
            # Check if user already exists (either found by allauth or not)
            user_exists = login.user.pk is not None
            account_connected = login.account.pk is not None

            # If allauth didn't find a user, check manually by email
            if not user_exists and not account_connected and login.user.email:
                existing_users: list[str] = filter_users_by_email(
                    login.user.email, prefer_verified=True  # pyright: ignore
                )
                user_exists = len(existing_users) > 0

            if user_exists and not account_connected:
                raise serializers.ValidationError(
                    _("User is already registered with this e-mail address."),
                )

    def set_login_user(self, login: SocialLogin) -> None:
        """
        Set the appropriate user for the social login.

        If a user with the same email exists, use that user. Otherwise,
        ensure the new user has a proper username.

        Args:
            login: The SocialLogin instance to configure
        """
        if not login.user.username and getattr(UserModel, "USERNAME_FIELD", None):
            username_field = UserModel.USERNAME_FIELD
            setattr(
                login.user, username_field, login.user.email
            )  # pyright: ignore[reportUnknownArgumentType]

    def get_login_from_token(self, tokens_to_parse: dict[str, Any]) -> SocialLogin:
        """
        Create a SocialLogin from OAuth tokens.

        Args:
            tokens_to_parse: Dictionary containing OAuth tokens

        Returns:
            SocialLogin instance for the authenticated user
        """
        view = cast(SocialLoginView, self.context.get("view"))
        request = cast(Request, self.context.get("request"))

        adapter_class = view.adapter_class

        provider_id = view.kwargs.get("provider_id")
        if provider_id:
            adapter_class = cast(type[OpenIDConnectOAuth2Adapter], adapter_class)
            adapter = adapter_class(request, provider_id)
        else:
            adapter = adapter_class(request)

        app = adapter.get_provider().app

        social_token = adapter.parse_token(tokens_to_parse)
        social_token.app = app

        response = tokens_to_parse.copy()
        response.pop("access_token")

        login = self.get_social_login(adapter, app, social_token, response=response)

        self.handle_social_login(request, login)

        return login

    def validate(self, attrs: dict[str, Any]) -> dict[str, Any]:
        """
        Validate the social login with access token.

        Args:
            attrs: Input attributes dictionary

        Returns:
            Validated attributes dictionary
        """
        access_token = attrs.get("access_token")
        id_token = attrs.get("id_token")

        tokens_to_parse = {
            "access_token": access_token,
            "id_token": id_token,  # for apple login
        }
        tokens_to_parse = {k: v for k, v in tokens_to_parse.items() if v}

        login = self.get_login_from_token(tokens_to_parse)

        self.post_signup(login, attrs)

        self.context["user"] = login.account.user

        return attrs

    def post_signup(self, login: SocialLogin, attrs: dict[str, Any]) -> None:
        """
        Hook for custom behavior after social account signup.

        Override this method to inject custom behavior when a user
        signs up with a social account.

        Args:
            login: The SocialLogin instance being registered
            attrs: The serializer attributes
        """
        pass


class SocialLoginWithCodeRequestSerializer(SocialLoginWithTokenRequestSerializer):
    """
    Serializer for social login using OAuth authorization codes.

    Handles the standard OAuth authorization code flow where the client
    receives an authorization code and exchanges it for access tokens.
    """

    access_token = None  # type: ignore[assignment]
    id_token = None  # type: ignore[assignment]
    code = UnquoteStringField(required=True, write_only=True)

    def get_callback_url(
        self, request: Request, view: APIView, social_app: SocialApp
    ) -> str:
        """
        Get the OAuth callback URL for this login flow.

        Args:
            request: The DRF request object
            view: The API view handling the request
            social_app: The social application configuration

        Returns:
            OAuth callback URL for social login
        """
        return auth_kit_settings.SOCIAL_LOGIN_CALLBACK_URL_GENERATOR(
            request, view, social_app
        )

    def validate(self, attrs: dict[str, Any]) -> dict[str, Any]:
        """
        Validate the social login with authorization code.

        Exchanges the authorization code for access tokens and processes
        the social login.

        Args:
            attrs: Input attributes dictionary

        Returns:
            Validated attributes dictionary

        Raises:
            ValidationError: If code exchange or login processing fails
        """
        view = cast(SocialLoginView, self.context.get("view"))
        request = cast(Request, self.context.get("request"))

        adapter_class = view.adapter_class

        provider_id = view.kwargs.get("provider_id")
        if provider_id:
            adapter_class = cast(type[OpenIDConnectOAuth2Adapter], adapter_class)
            adapter = adapter_class(request, provider_id)
        else:
            adapter = adapter_class(request)

        app = adapter.get_provider().app

        code = attrs.get("code")

        callback_url = self.get_callback_url(request, view, app)
        client_class = getattr(view, "client_class", OAuth2Client)

        client = client_class(
            request,
            app.client_id,
            app.secret,
            adapter.access_token_method,
            adapter.access_token_url,
            callback_url,
            scope_delimiter=adapter.scope_delimiter,
            headers=adapter.headers,
            basic_auth=adapter.basic_auth,
        )

        try:
            token = client.get_access_token(code)
        except OAuth2Error as e:
            logger.exception(str(e))
            err_msg: Any = str(e)
            if auth_kit_settings.SOCIAL_HIDE_AUTH_ERROR_DETAILS:
                err_msg = _("Failed to exchange code for access token")
            raise serializers.ValidationError(err_msg) from e

        access_token = token["access_token"]

        tokens_to_parse = {"access_token": access_token}

        # If available we add additional data to the dictionary
        for key in ["refresh_token", "id_token", adapter.expires_in_key]:
            if key in token:
                tokens_to_parse[key] = token[key]

        login = self.get_login_from_token(tokens_to_parse)

        self.post_signup(login, attrs)

        self.context["user"] = login.account.user

        return attrs


def get_social_login_serializer(
    provider_name: str = "",
) -> type[Serializer[dict[str, Any]]]:
    """
    Get the social login serializer class based on current settings.

    Creates a serializer class dynamically by combining the appropriate
    request and response serializers based on current auth kit settings.

    Args:
        provider_name: The name of the social provider (e.g., "Google", "Github")

    Returns:
        The combined social login serializer class
    """
    # Get the serializer classes based on current settings
    response_serializer = get_login_response_serializer()
    if auth_kit_settings.SOCIAL_LOGIN_AUTH_TYPE == "token":
        social_login_request_serializer = SocialLoginWithTokenRequestSerializer
    else:
        social_login_request_serializer = SocialLoginWithCodeRequestSerializer

    # Create unique class name based on provider
    class_name = (
        f"{provider_name}SocialLoginSerializer"
        if provider_name
        else "SocialLoginSerializer"
    )

    # Create the combined serializer class
    SocialLoginSerializer = type(  # noqa
        class_name,
        (response_serializer, social_login_request_serializer),
        {
            "__doc__": (
                f"Social authentication with {provider_name} OAuth credentials response."
                if provider_name
                else "Social authentication with OAuth credentials response."
            ),
            "__module__": __name__,
        },
    )

    return SocialLoginSerializer
