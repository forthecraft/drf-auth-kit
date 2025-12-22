"""
URL configuration for my_app project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""

from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import include, path
from django.views.generic import RedirectView

from auth_kit.views import AuthKitUIView
from drf_spectacular.views import (
    SpectacularAPIView,
    SpectacularRedocView,
    SpectacularSwaggerView,
)
from drf_spectacular_extras.views import SpectacularScalarView  # type: ignore

from status.views import StatusView

api_urlpatterns = [
    path("schema/", SpectacularAPIView.as_view(), name="schema"),
    path(
        "schema/swg/",
        SpectacularSwaggerView.as_view(url_name="schema"),
        name="swagger-ui",
    ),
    path(
        "schema/redoc/",
        SpectacularRedocView.as_view(url_name="schema"),
        name="redoc",
    ),
    path(
        "schema/scalar/",
        SpectacularScalarView.as_view(url_name="schema"),
        name="scalar",
    ),
    path("auth/", include("auth_kit.urls")),
    path("auth/social/", include("auth_kit.social.urls")),
    path("status/", StatusView.as_view(), name="status"),
    # UI View for testing all auth features
    path("auth/ui/", AuthKitUIView.as_view(), name="auth_kit_ui"),
]


urlpatterns = [
    path("", RedirectView.as_view(url="admin/")),
    path("admin/", admin.site.urls),
    path("api/", include(api_urlpatterns)),
]


if settings.DEBUG:
    urlpatterns += [path("__debug__/", include("debug_toolbar.urls"))]

urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
