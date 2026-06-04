"""
URL configuration for passwordless authentication endpoints.

This module dynamically generates URL patterns for each registered
passwordless handler, creating request and verify endpoints per method.
"""

from django.urls import URLPattern, URLResolver, re_path

from drf_spectacular.utils import extend_schema, extend_schema_view

from auth_kit.passwordless.handlers.base import PasswordlessHandlerRegistry
from auth_kit.passwordless.passwordless_api_descriptions import (
    get_passwordless_initiate_description,
    get_passwordless_verify_description,
)
from auth_kit.passwordless.passwordless_settings import auth_kit_passwordless_settings
from auth_kit.passwordless.serializers.login import (
    get_passwordless_verify_serializer,
)
from auth_kit.utils import filter_excluded_urls


def create_passwordless_urls() -> list[URLPattern | URLResolver]:
    """
    Dynamically create URL patterns for all registered passwordless handlers.

    Creates unique view subclasses per handler (via type()) to avoid
    extend_schema_view overwriting shared class attributes.

    Returns:
        List of URL patterns
    """
    PasswordlessHandlerRegistry._prefetch_handlers()
    passwordless_urls: list[URLPattern | URLResolver] = []

    for name, handler_class in PasswordlessHandlerRegistry.get_handlers().items():
        display_name = handler_class.DISPLAY_NAME
        class_name = name.replace("_", " ").title().replace(" ", "")

        # Build serializers for schema annotation
        initiate_serializer = handler_class.get_initiate_serializer_class()
        verify_serializer = get_passwordless_verify_serializer(handler_class)

        # Create unique initiate view subclass per handler
        initiate_view_class = extend_schema_view(
            post=extend_schema(
                description=get_passwordless_initiate_description(display_name),
                operation_id=f"passwordless_{name}_initiate",
                request=initiate_serializer,
                responses=initiate_serializer,
            )
        )(
            type(
                f"Passwordless{class_name}InitiateView",
                (auth_kit_passwordless_settings.PASSWORDLESS_INITIATE_VIEW,),
                {"__module__": __name__},
            )
        )

        passwordless_urls.append(
            re_path(
                rf"passwordless/{name}/initiate/?$",
                initiate_view_class.as_view(),  # type: ignore[attr-defined]
                {"handler_name": name},
                name=f"rest_passwordless_{name}_initiate",
            )
        )

        # Create unique verify view subclass per handler
        verify_view_class = extend_schema_view(
            post=extend_schema(
                description=get_passwordless_verify_description(display_name),
                operation_id=f"passwordless_{name}_verify",
                request=verify_serializer,
                responses=verify_serializer,
            )
        )(
            type(
                f"Passwordless{class_name}VerifyView",
                (auth_kit_passwordless_settings.PASSWORDLESS_VERIFY_VIEW,),
                {"__module__": __name__},
            )
        )

        passwordless_urls.append(
            re_path(
                rf"passwordless/{name}/verify/?$",
                verify_view_class.as_view(),  # type: ignore[attr-defined]
                {"handler_name": name},
                name=f"rest_passwordless_{name}_verify",
            )
        )

    return passwordless_urls


urlpatterns: list[URLPattern | URLResolver] = create_passwordless_urls()

# Apply URL exclusion filtering
urlpatterns = filter_excluded_urls(urlpatterns)
