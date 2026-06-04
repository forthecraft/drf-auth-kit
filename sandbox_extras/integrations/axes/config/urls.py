from django.contrib import admin
from django.urls import include, path

api_urlpatterns = [
    path("auth/", include("auth_kit.urls")),
]

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/", include(api_urlpatterns)),
]
