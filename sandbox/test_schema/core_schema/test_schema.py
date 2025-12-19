from django.test import override_settings
from django.urls import include, path
from rest_framework.views import APIView

from _pytest.capture import CaptureFixture
from auth_kit.authentication import TokenCookieAuthentication
from auth_kit.serializers import get_login_serializer
from auth_kit.serializers.logout import get_logout_serializer
from auth_kit.test_utils import override_auth_kit_settings

from test_utils.drf_spectacular_utils import assert_schema, generate_schema
from test_utils.monkey_patch import temporary_class_attribute
from test_utils.urls import reload_necessary_modules_and_get_urls


@override_auth_kit_settings(USE_MFA=False)
def test_auth_kit_jwt_auth(no_warnings: CaptureFixture[str]) -> None:
    urls = reload_necessary_modules_and_get_urls()
    urlpatterns = [
        path("auth/", include(urls)),
    ]
    schema = generate_schema(None, patterns=urlpatterns)
    assert_schema(schema, "test_schema/core_schema/auth_kit_jwt.yml")


@override_auth_kit_settings(AUTH_TYPE="token", USE_MFA=False)
@override_settings(
    REST_FRAMEWORK={
        "DEFAULT_RENDERER_CLASSES": [
            "rest_framework.renderers.JSONRenderer",
            "rest_framework.renderers.BrowsableAPIRenderer",
        ],
        "DEFAULT_PARSER_CLASSES": (
            "rest_framework.parsers.JSONParser",
            "rest_framework.parsers.MultiPartParser",
        ),
        "DEFAULT_AUTHENTICATION_CLASSES": [
            "auth_kit.authentication.TokenCookieAuthentication"
        ],
        "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
    }
)
def test_auth_kit_token_auth(no_warnings: CaptureFixture[str]) -> None:
    with temporary_class_attribute(
        APIView, "authentication_classes", [TokenCookieAuthentication]
    ):
        urls = reload_necessary_modules_and_get_urls()

        get_login_serializer.cache_clear()
        get_logout_serializer.cache_clear()
        urlpatterns = [
            path("auth/", include(urls)),
        ]
        schema = generate_schema(None, patterns=urlpatterns)

        assert_schema(schema, "test_schema/core_schema/auth_kit_token.yml")


@override_auth_kit_settings(USE_AUTH_COOKIE=False, USE_MFA=False)
@override_settings(ACCOUNT_EMAIL_VERIFICATION="none")
def test_auth_kit_jwt_no_using_auth_cookie_and_no_verify_email(
    no_warnings: CaptureFixture[str],
) -> None:
    urls = reload_necessary_modules_and_get_urls()

    get_login_serializer.cache_clear()
    get_logout_serializer.cache_clear()
    urlpatterns = [
        path("auth/", include(urls)),
    ]
    schema = generate_schema(None, patterns=urlpatterns)
    assert_schema(schema, "test_schema/core_schema/auth_kit_no_auth_cookie.yml")
