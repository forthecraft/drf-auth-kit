"""
Django admin configuration for MFA models.

This module provides admin interface configuration for managing
MFA methods in the Django admin panel with optimized queries
and useful filtering options.
"""

from typing import TYPE_CHECKING

from django.contrib import admin
from django.core.exceptions import FieldDoesNotExist

from auth_kit.utils import UserModel

from .models import MFAMethod

if TYPE_CHECKING:
    AdminModel = admin.ModelAdmin[MFAMethod]
else:
    AdminModel = admin.ModelAdmin


def _user_search_fields() -> list[str]:
    """Build admin search fields from fields present on the user model."""
    field_names = dict.fromkeys(
        [UserModel.USERNAME_FIELD, UserModel.get_email_field_name()]
    )
    search_fields: list[str] = []
    for name in field_names:
        try:
            UserModel._meta.get_field(name)
        except FieldDoesNotExist:
            continue
        search_fields.append(f"user__{name}")
    return search_fields


@admin.register(MFAMethod)
class MFAMethodAdmin(AdminModel):
    """
    Admin interface for MFA method management.

    Provides list view with key fields, filtering capabilities,
    and optimized database queries for efficient admin operations.
    """

    list_display = ["id", "user", "name", "is_primary", "is_active"]
    list_filter = ["name", "is_active"]
    search_fields = _user_search_fields()
    list_select_related = ["user"]
