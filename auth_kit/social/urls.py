"""
URL configuration for social authentication endpoints.

This module dynamically generates URL patterns for all configured social
providers, creating login and account connection endpoints for each provider.
"""

import importlib
from typing import Any

from django.db import DatabaseError
from django.urls import URLPattern, URLResolver, path
from rest_framework import routers

from allauth.socialaccount.adapter import (  # pyright: ignore[reportMissingTypeStubs]
    get_adapter as get_social_adapter,
)
from drf_spectacular.utils import extend_schema, extend_schema_view

from auth_kit.app_settings import auth_kit_settings
from auth_kit.social.social_api_descriptions import (
    get_lazy_social_connect_description,
    get_lazy_social_login_description,
)
from auth_kit.social.utils import normalize_app_name
from auth_kit.social.views import SocialConnectView, SocialLoginView
from auth_kit.utils import filter_excluded_urls

router = routers.SimpleRouter()
router.register(
    r"accounts", auth_kit_settings.SOCIAL_ACCOUNT_VIEW_SET, basename="social-account"
)

urlpatterns = [
    *router.urls,
]


def create_social_provider_urls() -> list[Any]:
    """
    Create URL patterns for all installed social providers.

    Dynamically generates login and connect URL patterns for each configured
    social authentication provider in the system.

    Returns:
        List of URL patterns for social provider endpoints
    """
    social_urls: list[URLPattern | URLResolver] = []
    social_adapter = get_social_adapter()

    try:
        social_apps = social_adapter.list_apps(None)
    except DatabaseError:  # pragma: no cover
        # Database is not available or tables don't exist yet
        # (e.g., during migrations, initial setup, or when database is not ready)
        return social_urls

    for social_app in social_apps:
        # Import provider module
        module_path = f"allauth.socialaccount.providers.{social_app.provider}.provider"
        module = importlib.import_module(module_path)

        # Get provider class
        provider_classes = module.provider_classes

        provider_class = provider_classes[0]
        adapter_class = provider_class.oauth2_adapter_class

        # Create dynamic login class
        app_name, app_slug = normalize_app_name(social_app)

        # Generate social login view class with dynamic description
        social_login_class_name = f"{app_name}LoginView"
        social_login_class: type[SocialLoginView] = extend_schema_view(
            post=extend_schema(description=get_lazy_social_login_description(app_name))
        )(
            type(
                social_login_class_name,
                (auth_kit_settings.SOCIAL_LOGIN_VIEW,),
                {
                    "adapter_class": adapter_class,
                    "__module__": __name__,
                },
            )
        )

        # Create login URL pattern
        login_pattern = path(
            f"{app_slug}/",
            social_login_class.as_view(),
            {"provider_id": social_app.provider_id},
            name=f"rest_social_{app_slug}_login",
        )
        social_urls.append(login_pattern)

        # Generate social connect view class with dynamic description
        social_connect_class_name = f"{app_name}ConnectView"
        social_connect_class: type[SocialConnectView] = extend_schema_view(
            post=extend_schema(
                description=get_lazy_social_connect_description(app_name)
            )
        )(
            type(
                social_connect_class_name,
                (auth_kit_settings.SOCIAL_CONNECT_VIEW,),
                {
                    "adapter_class": adapter_class,
                    "__module__": __name__,
                },
            )
        )

        # Create connect URL pattern
        connect_pattern = path(
            f"{app_slug}/connect/",
            social_connect_class.as_view(),
            {"provider_id": social_app.provider_id},
            name=f"rest_social_{app_slug}_connect",
        )
        social_urls.append(connect_pattern)

    return social_urls


# Generate URL patterns for all social providers
urlpatterns += create_social_provider_urls()

# Apply URL exclusion filtering
urlpatterns = filter_excluded_urls(urlpatterns)
