"""
Django admin configuration for MFA models.

This module provides admin interface configuration for managing
MFA methods in the Django admin panel with optimized queries
and useful filtering options.
"""

from typing import TYPE_CHECKING

from django.contrib import admin

from .models import MFAMethod

if TYPE_CHECKING:
    AdminModel = admin.ModelAdmin[MFAMethod]
else:
    AdminModel = admin.ModelAdmin


@admin.register(MFAMethod)
class MFAMethodAdmin(AdminModel):
    """
    Admin interface for MFA method management.

    Provides list view with key fields, filtering capabilities,
    and optimized database queries for efficient admin operations.
    """

    list_display = ["id", "user", "name", "is_primary", "is_active"]
    list_filter = ["name", "is_active"]
    search_fields = ["user__email", "user__username"]
    list_select_related = ["user"]
