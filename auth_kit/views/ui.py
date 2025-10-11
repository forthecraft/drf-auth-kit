"""
Template-based UI view for authentication features.

This module provides a comprehensive web interface view for all
authentication features including login, registration, password reset,
user management, and social authentication.
"""

import secrets
from typing import Any, cast
from urllib.parse import urlencode

from django.conf import settings
from django.http import HttpRequest, HttpResponse
from django.shortcuts import render
from rest_framework.views import APIView

from drf_spectacular.utils import extend_schema

from auth_kit.app_settings import auth_kit_settings
from auth_kit.utils import UserModel, UserNameField

# Conditional imports for social authentication
HAS_SOCIAL_AUTH = "allauth.socialaccount" in settings.INSTALLED_APPS

if HAS_SOCIAL_AUTH:  # pragma: no cover
    from allauth.socialaccount.adapter import (  # pyright: ignore
        get_adapter as get_social_adapter,
    )
    from allauth.socialaccount.models import (  # pyright: ignore
        SocialAccount,
        SocialApp,
    )
    from allauth.socialaccount.providers.openid_connect.provider import (  # pyright: ignore
        OpenIDConnectProvider,
    )
    from allauth.socialaccount.providers.openid_connect.views import (  # pyright: ignore
        OpenIDConnectOAuth2Adapter,
    )

# Provider icon mappings (FontAwesome classes)
PROVIDER_ICONS: dict[str, str] = {
    # Major providers
    "google": "fab fa-google",
    "facebook": "fab fa-facebook-f",
    "github": "fab fa-github",
    "twitter": "fab fa-twitter",
    "twitter_oauth2": "fab fa-twitter",
    "microsoft": "fab fa-microsoft",
    "apple": "fab fa-apple",
    "discord": "fab fa-discord",
    "linkedin": "fab fa-linkedin-in",
    "linkedin_oauth2": "fab fa-linkedin-in",
    "instagram": "fab fa-instagram",
    "reddit": "fab fa-reddit-alien",
    "spotify": "fab fa-spotify",
    "twitch": "fab fa-twitch",
    "youtube": "fab fa-youtube",
    "vimeo": "fab fa-vimeo-v",
    "vimeo_oauth2": "fab fa-vimeo-v",
    "pinterest": "fab fa-pinterest-p",
    "tumblr": "fab fa-tumblr",
    "tumblr_oauth2": "fab fa-tumblr",
    "soundcloud": "fab fa-soundcloud",
    "steam": "fab fa-steam",
    "amazon": "fab fa-amazon",
    "paypal": "fab fa-paypal",
    "stripe": "fab fa-stripe",
    "dropbox": "fab fa-dropbox",
    "gitlab": "fab fa-gitlab",
    "bitbucket": "fab fa-bitbucket",
    "bitbucket_oauth2": "fab fa-bitbucket",
    "slack": "fab fa-slack",
    "telegram": "fab fa-telegram-plane",
    "whatsapp": "fab fa-whatsapp",
    "snapchat": "fab fa-snapchat-ghost",
    "tiktok": "fab fa-tiktok",
    # Regional/Asian providers
    "line": "fab fa-line",
    "weibo": "fab fa-weibo",
    "weixin": "fab fa-weixin",
    "kakao": "fab fa-kickstarter-k",  # Using K as approximation
    "naver": "fas fa-n",  # Generic N
    "baidu": "fas fa-b",  # Generic B
    "qq": "fab fa-qq",
    "vk": "fab fa-vk",
    "yandex": "fab fa-yandex",
    "mailru": "fas fa-at",
    "odnoklassniki": "fab fa-odnoklassniki",
    # Business/Professional
    "salesforce": "fab fa-salesforce",
    "hubspot": "fas fa-briefcase",
    "mailchimp": "fab fa-mailchimp",
    "shopify": "fab fa-shopify",
    "atlassian": "fab fa-atlassian",
    "asana": "fas fa-tasks",
    "trello": "fab fa-trello",
    "notion": "fas fa-sticky-note",
    "zoom": "fas fa-video",
    "quickbooks": "fab fa-quickbooks",
    # Development/Tech
    "stackexchange": "fab fa-stack-overflow",
    "stackoverflow": "fab fa-stack-overflow",
    "digitalocean": "fab fa-digital-ocean",
    "heroku": "fas fa-cloud",
    "aws": "fab fa-aws",
    "gitea": "fab fa-git-alt",
    "jupyterhub": "fas fa-code",
    "docker": "fab fa-docker",
    # Finance/Trading
    "robinhood": "fas fa-chart-line",
    "questrade": "fas fa-chart-bar",
    "coinbase": "fab fa-bitcoin",
    "stocktwits": "fas fa-dollar-sign",
    # Gaming/Entertainment
    "battlenet": "fas fa-gamepad",
    "eveonline": "fas fa-rocket",
    "lichess": "fas fa-chess",
    # Health/Fitness
    "strava": "fab fa-strava",
    "fitbit": "fas fa-heartbeat",
    "wahoo": "fas fa-bicycle",
    "trainingpeaks": "fas fa-mountain",
    # Academic/Research
    "orcid": "fab fa-orcid",
    "globus": "fas fa-globe",
    "cilogon": "fas fa-university",
    "edx": "fas fa-graduation-cap",
    "edmodo": "fas fa-chalkboard-teacher",
    # Creative/Design
    "figma": "fab fa-figma",
    "behance": "fab fa-behance",
    "dribbble": "fab fa-dribbble",
    "deviantart": "fab fa-deviantart",
    "miro": "fas fa-palette",
    # Communication/Productivity
    "box": "fas fa-box",
    "nextcloud": "fas fa-cloud",
    "hubic": "fas fa-cloud-upload-alt",
    "basecamp": "fas fa-campground",
    "evernote": "fas fa-sticky-note",
    "pocket": "fab fa-get-pocket",
    # Authentication/Identity
    "auth0": "fas fa-key",
    "okta": "fas fa-shield-alt",
    "openid": "fas fa-id-card",
    "openid_connect": "fas fa-id-card",
    "saml": "fas fa-certificate",
    "oauth2": "fas fa-key",
    "fxa": "fab fa-firefox",  # Firefox Accounts
    # Dating/Social
    "meetup": "fab fa-meetup",
    "eventbrite": "fas fa-calendar-alt",
    "patreon": "fab fa-patreon",
    # Music/Audio
    "bandcamp": "fab fa-bandcamp",
    "lastfm": "fab fa-lastfm",
    # Travel/Maps
    "foursquare": "fab fa-foursquare",
    "untappd": "fas fa-beer",
    # Other services
    "angellist": "fab fa-angellist",
    "disqus": "fas fa-comments",
    "feedly": "fas fa-rss",
    "ynab": "fas fa-piggy-bank",
    "gumroad": "fas fa-shopping-cart",
    "sharefile": "fas fa-file-alt",
    "mailcow": "fas fa-cow",
    "lemonldap": "fas fa-lemon",
    "netiq": "fas fa-network-wired",
    "authentiq": "fas fa-fingerprint",
    "exist": "fas fa-chart-pie",
    "doximity": "fas fa-user-md",
    "clever": "fas fa-lightbulb",
    "dataporten": "fas fa-database",
    "dingtalk": "fas fa-bell",
    "feishu": "fas fa-feather-alt",
    "frontier": "fas fa-rocket",
    "mediawiki": "fab fa-wikipedia-w",
    "openstreetmap": "fas fa-map",
    "agave": "fas fa-leaf",
    "bitly": "fas fa-link",
    "draugiem": "fas fa-users",
    "drip": "fas fa-tint",
    "dwolla": "fas fa-money-check-alt",
    "fivehundredpx": "fas fa-camera",
    "flickr": "fab fa-flickr",
    "twentythreeandme": "fas fa-dna",
    "xing": "fab fa-xing",
    "yahoo": "fab fa-yahoo",
    "zoho": "fas fa-briefcase",
    "windowslive": "fab fa-windows",
    "amazon_cognito": "fab fa-amazon",
    "douban": "fas fa-book",
    "daum": "fas fa-search",
}

# Default fallback styles
DEFAULT_PROVIDER_STYLE: dict[str, str] = {
    "icon": "fas fa-sign-in-alt",
}

DISPLAY_NAME_OVERRIDES = {
    "github": "GitHub",
    "linkedin": "LinkedIn",
    "linkedin_oauth2": "LinkedIn",
    "paypal": "PayPal",
    "youtube": "YouTube",
    "openid": "OpenID",
    "oauth2": "OAuth 2.0",
    "battlenet": "Battle.net",
    "stackexchange": "Stack Exchange",
    "fivehundredpx": "500px",
    "twentythreeandme": "23andMe",
    "windowslive": "Microsoft Live",
}


def get_provider_icon(provider_id: str, provider_name: str | None = None) -> str:
    """Get FontAwesome icon class for a social provider."""
    # Direct match
    if provider_id in PROVIDER_ICONS:
        return PROVIDER_ICONS[provider_id]

    # Fallback
    return DEFAULT_PROVIDER_STYLE["icon"]  # pragma: no cover


def get_provider_display_name(social_app: "SocialApp") -> str:
    """Get clean display name for a social provider."""
    # Use custom name if set
    if social_app.name:
        return str(social_app.name)  # pyright: ignore

    # Determine the key to use
    provider_key = getattr(social_app, "provider_id", None) or social_app.provider

    # Check for override
    if provider_key in DISPLAY_NAME_OVERRIDES:
        return DISPLAY_NAME_OVERRIDES[provider_key]

    # Default: clean up provider name
    return cast(str, provider_key.replace("_oauth2", "").replace("_", " ").title())


@extend_schema(exclude=True)
class AuthKitUIView(APIView):
    """
    Comprehensive UI for Auth Kit features.

    Provides a web interface for all authentication features including:
    - Login (standard and social)
    - Registration
    - Password reset and change
    - User profile viewing and updating
    - Social account connections
    - Logout
    """

    template_name = "auth_kit/ui.html"
    permission_classes = ()

    def get(self, request: HttpRequest) -> HttpResponse:
        """
        Render the comprehensive test UI.

        Args:
            request: The Django HTTP request object

        Returns:
            Rendered HTML response with all authentication testing features
        """
        # Get username field value if user is authenticated
        username_field_value = ""
        if request.user.is_authenticated:
            username_field_value = getattr(request.user, UserNameField, "")

        context: dict[str, Any] = {
            "user": request.user,
            "is_authenticated": request.user.is_authenticated,
            "auth_type": auth_kit_settings.AUTH_TYPE,
            "use_auth_cookie": auth_kit_settings.USE_AUTH_COOKIE,
            "use_mfa": auth_kit_settings.USE_MFA,
            "has_social_auth": HAS_SOCIAL_AUTH,
            "username_field": UserNameField,
            "username_field_value": username_field_value,
            # For login: show only the username field (email is removed if UserNameField == "username")
            "login_uses_email": UserNameField == "email",
            "login_uses_username": UserNameField == "username",
            "login_uses_custom": UserNameField not in ["username", "email"],
            # For registration: always has email, but username is conditional
            "has_username_field": (
                UserNameField != "email"
            ),  # username field exists unless email is the username
            "has_first_name": hasattr(UserModel, "first_name"),
            "has_last_name": hasattr(UserModel, "last_name"),
        }

        # Add social providers if social auth is available
        if HAS_SOCIAL_AUTH:
            social_providers = self._get_social_providers(request)
            context["social_providers"] = social_providers
            # If user is authenticated, get their social connections
            if request.user.is_authenticated:
                context["social_connections"] = self._get_user_social_connections(
                    request
                )
            else:
                context["social_connections"] = []
        else:
            context["social_providers"] = []
            context["social_connections"] = []

        return render(request, self.template_name, context)

    def _get_social_providers(self, request: HttpRequest) -> list[dict[str, Any]]:
        """
        Get list of available social providers with OAuth URLs.

        Args:
            request: The Django HTTP request object

        Returns:
            List of provider dictionaries with connection information
        """
        if not HAS_SOCIAL_AUTH:  # pragma: no cover
            return []

        social_adapter = get_social_adapter()  # pyright: ignore

        social_apps = social_adapter.list_apps(request)

        if not social_apps:
            return []

        all_providers: list[dict[str, Any]] = []

        for social_app in social_apps:
            provider = social_app.get_provider(request)

            # Generate state for OAuth
            state = secrets.token_urlsafe(32)
            request.session[f"{social_app.provider}_oauth_state"] = state

            # Build OAuth URL
            default_scope = cast(list[str] | str, provider.get_default_scope())

            params = {
                "client_id": social_app.client_id,
                "redirect_uri": auth_kit_settings.SOCIAL_LOGIN_CALLBACK_URL_GENERATOR(
                    request, None, social_app
                ),
                "scope": (
                    " ".join(default_scope)
                    if isinstance(default_scope, list)
                    else str(default_scope)
                ),
                "response_type": "code",
                "state": state,
            }

            if isinstance(provider, OpenIDConnectProvider):  # pyright: ignore
                adapter = OpenIDConnectOAuth2Adapter(  # pyright: ignore
                    request, social_app.provider_id
                )
                oauth_url = f"{adapter.authorize_url}?{urlencode(params)}"
                provider_id = getattr(social_app, "provider_id", social_app.provider)
            else:
                oauth_url = (
                    f"{provider.oauth2_adapter_class.authorize_url}?{urlencode(params)}"
                )
                provider_id = social_app.provider

            # Generate connect state
            connect_state = secrets.token_urlsafe(32)
            request.session[f"{social_app.provider}_oauth_connect_state"] = (
                connect_state
            )

            connect_params = {
                **params,
                "state": connect_state,
                "redirect_uri": auth_kit_settings.SOCIAL_CONNECT_CALLBACK_URL_GENERATOR(
                    request, None, social_app
                ),
            }

            if isinstance(provider, OpenIDConnectProvider):  # pyright: ignore
                adapter = OpenIDConnectOAuth2Adapter(  # pyright: ignore
                    request, social_app.provider_id
                )
                connect_url = f"{adapter.authorize_url}?{urlencode(connect_params)}"
            else:
                connect_url = f"{provider.oauth2_adapter_class.authorize_url}?{urlencode(connect_params)}"

            display_name = get_provider_display_name(social_app)  # pyright: ignore
            icon_class = get_provider_icon(provider_id, display_name)  # pyright: ignore

            all_providers.append(
                {
                    "id": provider_id,
                    "provider": social_app.provider,
                    "name": display_name,
                    "login_url": oauth_url,
                    "connect_url": connect_url,
                    "icon_class": icon_class,
                }
            )

        # Sort providers by popularity
        def provider_sort_key(app: dict[str, Any]) -> int:
            """Sort providers by popularity."""
            priority_order = [
                "google",
                "facebook",
                "github",
                "microsoft",
                "apple",
                "twitter",
                "discord",
                "linkedin_oauth2",
                "instagram",
            ]
            try:
                return priority_order.index(app["id"])
            except ValueError:
                return len(priority_order)

        all_providers.sort(key=provider_sort_key)

        return all_providers

    def _get_user_social_connections(
        self, request: HttpRequest
    ) -> list[dict[str, Any]]:
        """
        Get user's connected social accounts.

        Args:
            request: The Django HTTP request object

        Returns:
            List of connected social account dictionaries
        """
        if not HAS_SOCIAL_AUTH or not request.user.is_authenticated:  # pragma: no cover
            return []

        user_social_accounts = SocialAccount.objects.filter(  # pyright: ignore
            user=request.user
        )

        connections: list[dict[str, Any]] = []
        for account in user_social_accounts:
            # Try to get the app to get display name
            try:
                social_app = SocialApp.objects.get(  # pyright: ignore
                    provider=account.provider
                )
                display_name = get_provider_display_name(social_app)
                provider_id = str(
                    getattr(
                        social_app,
                        "provider_id",
                        social_app.provider,  # pyright: ignore
                    )
                )
            except Exception:  # SocialApp.DoesNotExist or if imports failed
                display_name = account.provider.title()
                provider_id = account.provider

            icon_class = get_provider_icon(provider_id, display_name)  # pyright: ignore

            connections.append(
                {
                    "id": account.pk,
                    "provider": account.provider,
                    "provider_id": provider_id,
                    "name": display_name,
                    "uid": account.uid,
                    "icon_class": icon_class,
                    "last_login": account.last_login,
                    "date_joined": account.date_joined,
                }
            )

        return connections
