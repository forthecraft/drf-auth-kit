"""Per-request auth cookie name/path overrides (cookie profiles)."""

from dataclasses import dataclass
from typing import TypedDict

from django.http import HttpRequest

from auth_kit.app_settings import auth_kit_settings

PROFILE_OVERRIDE_KEYS = (
    "AUTH_JWT_COOKIE_NAME",
    "AUTH_JWT_COOKIE_PATH",
    "AUTH_JWT_REFRESH_COOKIE_NAME",
    "AUTH_JWT_REFRESH_COOKIE_PATH",
    "AUTH_TOKEN_COOKIE_NAME",
    "AUTH_TOKEN_COOKIE_PATH",
)


class CookieProfileConfig(TypedDict, total=False):
    """Cookie name/path overrides for one ``AUTH_COOKIE_PROFILES`` origin."""

    AUTH_JWT_COOKIE_NAME: str
    AUTH_JWT_COOKIE_PATH: str
    AUTH_JWT_REFRESH_COOKIE_NAME: str
    AUTH_JWT_REFRESH_COOKIE_PATH: str
    AUTH_TOKEN_COOKIE_NAME: str
    AUTH_TOKEN_COOKIE_PATH: str


@dataclass(frozen=True)
class CookieProfile:
    """Resolved cookie names and paths for one request."""

    jwt_cookie_name: str
    jwt_cookie_path: str
    refresh_cookie_name: str
    refresh_cookie_path: str
    token_cookie_name: str
    token_cookie_path: str


def _build_profile(overrides: CookieProfileConfig) -> CookieProfile:
    """Build a profile, filling omitted keys from the top-level settings."""
    values = {key: getattr(auth_kit_settings, key) for key in PROFILE_OVERRIDE_KEYS}
    values.update(overrides)
    return CookieProfile(
        jwt_cookie_name=values["AUTH_JWT_COOKIE_NAME"],
        jwt_cookie_path=values["AUTH_JWT_COOKIE_PATH"],
        refresh_cookie_name=values["AUTH_JWT_REFRESH_COOKIE_NAME"],
        refresh_cookie_path=values["AUTH_JWT_REFRESH_COOKIE_PATH"],
        token_cookie_name=values["AUTH_TOKEN_COOKIE_NAME"],
        token_cookie_path=values["AUTH_TOKEN_COOKIE_PATH"],
    )


def default_cookie_profile() -> CookieProfile:
    """Build the profile from the top-level auth cookie settings."""
    return _build_profile(CookieProfileConfig())


def resolve_cookie_profile(request: HttpRequest) -> CookieProfile:
    """Return the profile for the request's ``Origin``, else the default."""
    origin = request.META.get("HTTP_ORIGIN")
    if origin:
        overrides = auth_kit_settings.AUTH_COOKIE_PROFILES.get(origin)
        if overrides is not None:
            return _build_profile(overrides)
    return default_cookie_profile()
