"""
Views package for Auth Kit.

This module exports all authentication-related view classes
for login, logout, registration, password management, and JWT token handling.
"""

from .jwt import RefreshViewWithCookieSupport
from .login import LoginView
from .logout import LogoutView
from .password import PasswordChangeView, PasswordResetConfirmView, PasswordResetView
from .registration import RegisterView, ResendEmailVerificationView, VerifyEmailView
from .ui import AuthKitUIView
from .user import UserView

__all__ = [
    "RefreshViewWithCookieSupport",
    "LoginView",
    "LogoutView",
    "PasswordChangeView",
    "PasswordResetView",
    "PasswordResetConfirmView",
    "RegisterView",
    "ResendEmailVerificationView",
    "VerifyEmailView",
    "UserView",
    "AuthKitUIView",
]
