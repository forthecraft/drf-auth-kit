"""Cross-origin request detection via ``Sec-Fetch-Site`` and ``Origin`` headers."""

from urllib.parse import urlsplit

from django.conf import settings
from django.http import HttpRequest
from django.utils.http import is_same_domain

SAFE_METHODS = ("GET", "HEAD", "OPTIONS", "TRACE")


def is_trusted_origin(origin: str) -> bool:
    """Match ``origin`` against ``CSRF_TRUSTED_ORIGINS``, as Django does."""
    if origin in settings.CSRF_TRUSTED_ORIGINS:
        return True

    parsed = urlsplit(origin)
    return any(
        is_same_domain(parsed.netloc, trusted.netloc.lstrip("*"))
        for trusted in map(urlsplit, settings.CSRF_TRUSTED_ORIGINS)
        if trusted.netloc.startswith("*") and trusted.scheme == parsed.scheme
    )


def is_cross_origin_request(request: HttpRequest) -> bool:
    """Return whether an unsafe request comes from an untrusted origin."""
    if request.method in SAFE_METHODS:
        return False

    origin = request.headers.get("Origin")
    if origin and is_trusted_origin(origin):
        return False

    sec_fetch_site = request.headers.get("Sec-Fetch-Site")
    if sec_fetch_site:
        return sec_fetch_site not in ("same-origin", "none")

    if not origin:
        # Browsers always send one of the headers; without them it's not CSRF.
        return False

    return origin != f"{request.scheme}://{request.get_host()}"
