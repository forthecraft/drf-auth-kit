"""
Django settings for your project.

For more information on this file, see
https://docs.djangoproject.com/en/5.2/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/5.2/ref/settings/
"""

import os
from datetime import timedelta
from pathlib import Path
from typing import Any

import django

import django_stubs_ext
import structlog
from environs import env

# =========================================================================
# STUB MONKEYPATCH FOR DJANGO MYPY
# =========================================================================
django_stubs_ext.monkeypatch()

# =========================================================================
# PATH CONFIGURATION
# =========================================================================

CONFIG_PATH = Path(__file__)
BASE_DIR = CONFIG_PATH.parent.parent.parent
ROOT_DIR = BASE_DIR.parent
PACKAGE_DIR = ROOT_DIR / "auth_kit"

# =========================================================================
# ENVIRONMENT SETTINGS
# =========================================================================

env_file = f"{ROOT_DIR}/.env.test"

if os.path.isfile(env_file):
    env.read_env(env_file, recurse=False)
    env.read_env(f"{ROOT_DIR}/.env", override=True)
else:
    env.read_env()

CURRENT_ENV = env.str("DJANGO_SETTINGS_MODULE").split(".")[-1]

# =========================================================================
# CORE SETTINGS
# =========================================================================
SECRET_KEY = "this-is-a-mock-secret-key"

DEBUG = True
TEST = False

ALLOWED_HOSTS = ["*"]
SERVER_URL = env.str("SERVER_URL", "http://localhost:8000")

# =========================================================================
# APPLICATION DEFINITION
# =========================================================================

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    "rest_framework.authtoken",
    "drf_spectacular",
    "drf_spectacular_extras",
    "django_cleanup.apps.CleanupConfig",
    "debug_toolbar",
    "django_extensions",
    "allauth",
    "allauth.account",
    "allauth.socialaccount",
    "allauth.socialaccount.providers.google",
    "allauth.socialaccount.providers.github",
    "allauth.socialaccount.providers.facebook",
    "allauth.socialaccount.providers.openid_connect",
    "auth_kit",
    "auth_kit.social",
    "auth_kit.mfa",
    "rest_framework_simplejwt.token_blacklist",
    "knox",
    "utils",
]

# =========================================================================
# MIDDLEWARE CONFIGURATION
# =========================================================================

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.middleware.gzip.GZipMiddleware",
    "django_structlog.middlewares.RequestMiddleware",
    "corsheaders.middleware.CorsMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.locale.LocaleMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "debug_toolbar.middleware.DebugToolbarMiddleware",
    "allauth.account.middleware.AccountMiddleware",
]

# =========================================================================
# URL CONFIGURATION
# =========================================================================

ROOT_URLCONF = "config.urls"
WSGI_APPLICATION = "config.wsgi.application"

# =========================================================================
# TEMPLATE CONFIGURATION
# =========================================================================

TEMPLATES: list[dict[str, Any]] = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

# =========================================================================
# DATABASE CONFIGURATION
# =========================================================================
# Pool option is only available in Django 5.1+
_db_options = {}
if django.VERSION >= (5, 1):
    _db_options["pool"] = True

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": env.str("POSTGRES_DB", ""),
        "USER": env.str("POSTGRES_USER", ""),
        "PASSWORD": env.str("POSTGRES_PASSWORD", ""),
        "HOST": env.str("POSTGRES_HOST", "localhost"),
        "PORT": env.int("POSTGRES_PORT", 5432),
        "OPTIONS": _db_options,
    }
}

# Default primary key field type
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"


# Email:

EMAIL_BACKEND = "django.core.mail.backends.console.EmailBackend"

# =========================================================================
# AUTHENTICATION CONFIGURATION
# =========================================================================

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": (
            "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"
        ),
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]

# =========================================================================
# INTERNATIONALIZATION
# =========================================================================

LANGUAGE_CODE = "en"

LANGUAGES = [
    ("af", "Afrikaans"),
    ("ar", "العربية"),
    ("az", "Azərbaycan"),
    ("be", "Беларуская"),
    ("bg", "Български"),
    ("bs", "Bosanski"),
    ("ca", "Català"),
    ("cs", "Čeština"),
    ("cy", "Cymraeg"),
    ("da", "Dansk"),
    ("de", "Deutsch"),
    ("el", "Ελληνικά"),
    ("en", "English"),
    ("es", "Español"),
    ("et", "Eesti"),
    ("fa", "فارسی"),
    ("fi", "Suomi"),
    ("fr", "Français"),
    ("gl", "Galego"),
    ("he", "עברית"),
    ("hi", "हिन्दी"),
    ("hr", "Hrvatski"),
    ("hu", "Magyar"),
    ("hy", "Հայերեն"),
    ("id", "Bahasa Indonesia"),
    ("is", "Íslenska"),
    ("it", "Italiano"),
    ("ja", "日本語"),
    ("kk", "Қазақ"),
    ("kn", "ಕನ್ನಡ"),
    ("ko", "한국어"),
    ("lt", "Lietuvių"),
    ("lv", "Latviešu"),
    ("mi", "Māori"),
    ("mk", "Македонски"),
    ("mr", "मराठी"),
    ("ms", "Bahasa Melayu"),
    ("ne", "नेपाली"),
    ("nl", "Nederlands"),
    ("no", "Norsk"),
    ("pl", "Polski"),
    ("pt", "Português"),
    ("ro", "Română"),
    ("ru", "Русский"),
    ("sk", "Slovenčina"),
    ("sl", "Slovenščina"),
    ("sr", "Српски"),
    ("sv", "Svenska"),
    ("sw", "Kiswahili"),
    ("ta", "தமிழ்"),
    ("th", "ไทย"),
    ("tl", "Tagalog"),
    ("tr", "Türkçe"),
    ("uk", "Українська"),
    ("ur", "اردو"),
    ("vi", "Tiếng Việt"),
    ("zh", "中文"),
]

APP_LOCALE = str(PACKAGE_DIR / "locale")
LOCALE_PATHS = [APP_LOCALE]

TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

# =========================================================================
# STATIC FILES CONFIGURATION
# =========================================================================

STATIC_ROOT = str(BASE_DIR / "static")
STATIC_URL = "static/"

MEDIA_ROOT = str(BASE_DIR / "media/")
MEDIA_URL = "media/"

# =========================================================================
# REST FRAMEWORK CONFIGURATION
# =========================================================================
REST_FRAMEWORK = {
    "DEFAULT_RENDERER_CLASSES": [
        "rest_framework.renderers.JSONRenderer",
        "rest_framework.renderers.BrowsableAPIRenderer",
    ],
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "auth_kit.authentication.JWTCookieAuthentication",
    ],
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
    "DEFAULT_PARSER_CLASSES": (
        "rest_framework.parsers.JSONParser",
        "rest_framework.parsers.MultiPartParser",
    ),
    "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.LimitOffsetPagination",
    "PAGE_SIZE": 20,
}

SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(days=30),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=30),
}


# =========================================================================
# AUTH-KIT CONFIGURATION
# =========================================================================
AUTH_KIT = {
    # "AUTH_TYPE": "custom",
    # "LOGIN_VIEW": "custom_auth.views.KnoxLoginView",
    # "LOGOUT_VIEW": "custom_auth.views.KnoxLogoutView",
    "AUTH_TYPE": "jwt",
    "USE_MFA": True,
}

# =========================================================================
# ALLAUTH CONFIGURATION
# =========================================================================

ACCOUNT_EMAIL_VERIFICATION = "mandatory"
ACCOUNT_SIGNUP_FIELDS = ["email*", "username*"]
SOCIALACCOUNT_EMAIL_AUTHENTICATION = True

SOCIALACCOUNT_PROVIDERS = {
    "google": {
        "SCOPE": [
            "profile",
            "email",
        ],
        "AUTH_PARAMS": {
            "access_type": "online",
        },
        "OAUTH_PKCE_ENABLED": True,
        "FETCH_USERINFO": True,
        "APP": {
            "client_id": env.str("GOOGLE_AUTH_CLIENT_ID", ""),
            "secret": env.str("GOOGLE_AUTH_CLIENT_SECRET", ""),
            "key": "",
        },
    },
    "github": {
        "SCOPE": [
            "user",
        ],
        "APPS": [
            {
                "client_id": env.str("GITHUB_AUTH_CLIENT_ID", ""),
                "secret": env.str("GITHUB_AUTH_CLIENT_SECRET", ""),
                "key": "",
            }
        ],
    },
    "facebook": {
        "METHOD": "oauth2",  # Set to 'js_sdk' to use the Facebook connect SDK
        "SCOPE": ["email", "public_profile"],
        "FIELDS": [
            "id",
            "first_name",
            "last_name",
            "name",
            "picture",
            "email",
        ],
        "EXCHANGE_TOKEN": True,
        "VERIFIED_EMAIL": False,
        "VERSION": "v13.0",
        "GRAPH_API_URL": "https://graph.facebook.com/v13.0",
        "APP": {
            "client_id": env.str("FACEBOOK_AUTH_CLIENT_ID", ""),
            "secret": env.str("FACEBOOK_AUTH_CLIENT_SECRET", ""),
            "key": "",
        },
    },
    "openid_connect": {
        "APPS": [
            {
                "provider_id": "linkedin",
                "name": "LinkedIn",
                "client_id": env.str("LINKED_IN_AUTH_CLIENT_ID", ""),
                "secret": env.str("LINKED_IN_AUTH_CLIENT_SECRET", ""),
                "settings": {
                    "server_url": "https://www.linkedin.com/oauth",
                },
            }
        ]
    },
}

# =========================================================================
# API DOCUMENTATION CONFIGURATION
# =========================================================================

SPECTACULAR_SETTINGS: dict[str, Any] = {
    "TITLE": "DRF Auth Kit API Documentation",
    "DESCRIPTION": "DRF Auth Kit OpenAPI specification",
    "VERSION": "1.0.0",
    "SERVE_INCLUDE_SCHEMA": False,
    "COMPONENT_SPLIT_REQUEST": True,
    "COMPONENT_NO_READ_ONLY_REQUIRED": True,
    "SCHEMA_COERCE_PATH_PK_SUFFIX": True,
    "DISABLE_ERRORS_AND_WARNINGS": False if CURRENT_ENV == "dev" else True,
    "SERVE_PERMISSIONS": [],
    "SERVE_AUTHENTICATION": [],
}

# =========================================================================
# CORS CONFIGURATION
# =========================================================================

CORS_ALLOWED_ORIGINS: list[str] = env.list("CORS_ALLOWED_ORIGINS", default=[])
CORS_ALLOW_CREDENTIALS = True
CSRF_TRUSTED_ORIGINS = env.list("CSRF_TRUSTED_ORIGINS", default=[SERVER_URL])

# =========================================================================
# LOGGING CONFIGURATION
# =========================================================================

pre_chain = [
    structlog.contextvars.merge_contextvars,
    structlog.processors.TimeStamper(fmt="iso"),
    structlog.stdlib.add_logger_name,
    structlog.stdlib.add_log_level,
    structlog.stdlib.PositionalArgumentsFormatter(),
]

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "plain_console": {
            "()": structlog.stdlib.ProcessorFormatter,
            "processors": [
                structlog.stdlib.ProcessorFormatter.remove_processors_meta,
                structlog.dev.ConsoleRenderer(
                    exception_formatter=structlog.dev.plain_traceback
                ),
            ],
            "foreign_pre_chain": pre_chain,
        },
        "json_formatter": {
            "()": structlog.stdlib.ProcessorFormatter,
            "processors": [
                structlog.processors.dict_tracebacks,
                structlog.stdlib.ProcessorFormatter.remove_processors_meta,
                structlog.processors.JSONRenderer(),
            ],
            "foreign_pre_chain": pre_chain,
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "plain_console",
        }
    },
    "loggers": {
        "": {
            "handlers": ["console"],
            "level": "INFO",
            "propagate": False,
        },
        "django_structlog": {
            "handlers": ["console"],
            "level": "INFO",
        },
        "django_structlog_auth_kit": {
            "handlers": ["console"],
            "level": "INFO",
        },
        "auth_kit": {
            "handlers": ["console"],
            "level": "INFO",
        },
    },
}

structlog.configure(
    processors=pre_chain  # type: ignore[arg-type]
    + [
        structlog.stdlib.filter_by_level,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.UnicodeDecoder(),
        structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
    ],
    logger_factory=structlog.stdlib.LoggerFactory(),
    cache_logger_on_first_use=True,
)

# =========================================================================
# DJANGO SHELL_PLUS
# =========================================================================
SHELL_PLUS = "ipython"
IPYTHON_ARGUMENTS = [
    "--ext",
    "autoreload",
]
