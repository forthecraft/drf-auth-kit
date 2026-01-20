Configuration
=============

DRF Auth Kit provides extensive configuration options through Django settings. All settings are defined under the ``AUTH_KIT`` dictionary in your Django settings file.

Quick Reference
---------------

Here's a complete list of all available AUTH_KIT settings with their defaults:

.. code-block:: python

    AUTH_KIT = {
        # ===================================================================
        # CORE AUTHENTICATION SETTINGS
        # ===================================================================
        'AUTH_TYPE': 'jwt',                    # 'jwt', 'token', or 'custom'
        'USE_AUTH_COOKIE': True,               # Enable cookie-based authentication
        'SESSION_LOGIN': False,                # Enable Django session login
        'ALLOW_LOGIN_REDIRECT': False,         # Allow login redirects

        # ===================================================================
        # COOKIE CONFIGURATION
        # ===================================================================
        'AUTH_COOKIE_SECURE': False,           # Require HTTPS for cookies
        'AUTH_COOKIE_HTTPONLY': True,          # Prevent JavaScript access
        'AUTH_COOKIE_SAMESITE': 'Lax',         # 'Lax', 'Strict', or 'None'
        'AUTH_COOKIE_DOMAIN': None,            # Cookie domain

        # ===================================================================
        # JWT AUTHENTICATION SETTINGS
        # ===================================================================
        'AUTH_JWT_COOKIE_NAME': 'auth-jwt',
        'AUTH_JWT_COOKIE_PATH': '/',
        'AUTH_JWT_REFRESH_COOKIE_NAME': 'auth-refresh-jwt',
        'AUTH_JWT_REFRESH_COOKIE_PATH': '/',

        # ===================================================================
        # TOKEN AUTHENTICATION SETTINGS
        # ===================================================================
        'AUTH_TOKEN_MODEL': 'rest_framework.authtoken.models.Token',
        'AUTH_TOKEN_COOKIE_NAME': 'auth-token',
        'AUTH_TOKEN_COOKIE_PATH': '/',
        'AUTH_TOKEN_COOKIE_EXPIRE_TIME': timedelta(days=1),

        # ===================================================================
        # LOGIN & LOGOUT SERIALIZERS & VIEWS
        # ===================================================================
        'LOGIN_REQUEST_SERIALIZER': 'auth_kit.serializers.login_factors.LoginRequestSerializer',
        'LOGIN_RESPONSE_SERIALIZER': 'auth_kit.serializers.login_factors.BaseLoginResponseSerializer',
        'LOGIN_SERIALIZER_FACTORY': 'auth_kit.serializers.login.get_login_serializer',
        'LOGIN_VIEW': 'auth_kit.views.LoginView',
        'LOGOUT_SERIALIZER': 'auth_kit.serializers.logout.AuthKitLogoutSerializer',
        'LOGOUT_VIEW': 'auth_kit.views.LogoutView',

        # ===================================================================
        # USER MANAGEMENT SERIALIZERS & VIEWS
        # ===================================================================
        'USER_SERIALIZER': 'auth_kit.serializers.user.UserSerializer',
        'USER_VIEW': 'auth_kit.views.UserView',

        # ===================================================================
        # REGISTRATION SERIALIZERS & VIEWS
        # ===================================================================
        'REGISTER_SERIALIZER': 'auth_kit.serializers.RegisterSerializer',
        'REGISTER_VIEW': 'auth_kit.views.RegisterView',
        'VERIFY_EMAIL_VIEW': 'auth_kit.views.VerifyEmailView',
        'RESEND_EMAIL_VERIFICATION_VIEW': 'auth_kit.views.ResendEmailVerificationView',
        'FRONTEND_BASE_URL': None,
        'REGISTER_EMAIL_CONFIRM_PATH': None,
        'GET_EMAIL_VERIFICATION_URL_FUNC': 'auth_kit.views.registration.get_email_verification_url',
        'SEND_VERIFY_EMAIL_FUNC': 'auth_kit.views.registration.send_verify_email',

        # ===================================================================
        # PASSWORD MANAGEMENT SERIALIZERS & VIEWS
        # ===================================================================
        'PASSWORD_CHANGE_SERIALIZER': 'auth_kit.serializers.PasswordChangeSerializer',
        'PASSWORD_CHANGE_VIEW': 'auth_kit.views.PasswordChangeView',
        'PASSWORD_RESET_SERIALIZER': 'auth_kit.serializers.PasswordResetSerializer',
        'PASSWORD_RESET_VIEW': 'auth_kit.views.PasswordResetView',
        'PASSWORD_RESET_CONFIRM_SERIALIZER': 'auth_kit.serializers.PasswordResetConfirmSerializer',
        'PASSWORD_RESET_CONFIRM_VIEW': 'auth_kit.views.PasswordResetConfirmView',
        'PASSWORD_RESET_CONFIRM_PATH': None,
        'PASSWORD_RESET_URL_GENERATOR': 'auth_kit.forms.password_reset_url_generator',
        'OLD_PASSWORD_FIELD_ENABLED': False,
        'PASSWORD_RESET_PREVENT_ENUMERATION': True,

        # ===================================================================
        # JWT SPECIFIC SETTINGS
        # ===================================================================
        'JWT_TOKEN_CLAIMS_SERIALIZER': 'rest_framework_simplejwt.serializers.TokenObtainPairSerializer',
        'JWT_REFRESH_VIEW': 'auth_kit.views.jwt.RefreshViewWithCookieSupport',

        # ===================================================================
        # SOCIAL AUTHENTICATION
        # ===================================================================
        'SOCIAL_LOGIN_AUTH_TYPE': 'code',      # 'code' or 'token'
        'SOCIAL_LOGIN_AUTO_CONNECT_BY_EMAIL': True,
        'SOCIAL_LOGIN_CALLBACK_BASE_URL': '',
        'SOCIAL_CONNECT_CALLBACK_BASE_URL': '',
        'SOCIAL_HIDE_AUTH_ERROR_DETAILS': True,
        'SOCIAL_CONNECT_REQUIRE_EMAIL_MATCH': True,
        'SOCIAL_LOGIN_VIEW': 'auth_kit.social.views.login.SocialLoginView',
        'SOCIAL_CONNECT_VIEW': 'auth_kit.social.views.connect.SocialConnectView',
        'SOCIAL_ACCOUNT_VIEW_SET': 'auth_kit.social.views.account.SocialAccountViewSet',
        'SOCIAL_LOGIN_SERIALIZER_FACTORY': 'auth_kit.social.serializers.get_social_login_serializer',
        'SOCIAL_LOGIN_CALLBACK_URL_GENERATOR': 'auth_kit.social.utils.get_social_login_callback_url',
        'SOCIAL_CONNECT_CALLBACK_URL_GENERATOR': 'auth_kit.social.utils.get_social_connect_callback_url',

        # ===================================================================
        # MULTI-FACTOR AUTHENTICATION
        # ===================================================================
        'USE_MFA': False,                      # Enable Multi-Factor Authentication

        # MFA Model & Handlers
        'MFA_MODEL': 'auth_kit.mfa.models.MFAMethod',
        'MFA_HANDLERS': [                      # Available MFA handlers
            'auth_kit.mfa.handlers.app.MFAAppHandler',
            'auth_kit.mfa.handlers.email.MFAEmailHandler',
        ],

        # Application Settings
        'MFA_APPLICATION_NAME': 'MyApplication',

        # TOTP Configuration
        'MFA_TOTP_DEFAULT_INTERVAL': 30,       # TOTP interval in seconds
        'MFA_TOTP_DEFAULT_VALID_WINDOW': 0,    # Clock skew tolerance

        # Token Expiry
        'MFA_EPHEMERAL_TOKEN_EXPIRY': 900,     # 15 minutes in seconds

        # Backup Code Settings
        'NUM_OF_BACKUP_CODES': 5,
        'BACKUP_CODE_LENGTH': 12,
        'BACKUP_CODE_ALLOWED_CHARS': '0123456789ABCDEFGHJKMNPQRSTVWXYZ',
        'BACKUP_CODE_SECURE_HASH': True,

        # MFA Security Constraints
        'MFA_UPDATE_PRIMARY_METHOD_REQUIRED_PRIMARY_CODE': False,
        'MFA_PREVENT_DELETE_ACTIVE_METHOD': False,
        'MFA_PREVENT_DELETE_PRIMARY_METHOD': False,
        'MFA_DELETE_ACTIVE_METHOD_REQUIRE_CODE': False,

        # MFA Views
        'LOGIN_FIRST_STEP_VIEW': 'auth_kit.mfa.views.LoginFirstStepView',
        'LOGIN_SECOND_STEP_VIEW': 'auth_kit.mfa.views.LoginSecondStepView',
        'LOGIN_CHANGE_METHOD_VIEW': 'auth_kit.mfa.views.LoginChangeMethodView',
        'LOGIN_MFA_RESEND_VIEW': 'auth_kit.mfa.views.LoginMFAResendView',
        'LOGIN_MFA_METHOD_VIEW_SET': 'auth_kit.mfa.views.MFAMethodViewSet',

        # MFA Response Serializers
        'MFA_FIRST_STEP_RESPONSE_SERIALIZER': 'auth_kit.mfa.serializers.login_factors.MFAFirstStepResponseSerializer',
        'MFA_SECOND_STEP_REQUEST_SERIALIZER': 'auth_kit.mfa.serializers.login_factors.MFASecondStepRequestSerializer',
        'MFA_CHANGE_METHOD_SERIALIZER': 'auth_kit.mfa.serializers.login_factors.MFAChangeMethodSerializer',
        'MFA_RESEND_SERIALIZER': 'auth_kit.mfa.serializers.login_factors.MFAResendSerializer',

        # MFA Serializer Factories
        'GET_NO_MFA_LOGIN_RESPONSE_SERIALIZER': 'auth_kit.mfa.serializers.login_factors.get_no_mfa_login_response_serializer',
        'MFA_FIRST_STEP_SERIALIZER_FACTORY': 'auth_kit.mfa.serializers.login.get_mfa_first_step_serializer',
        'MFA_SECOND_STEP_SERIALIZER_FACTORY': 'auth_kit.mfa.serializers.login.get_mfa_second_step_serializer',

        # MFA Management Serializers
        'MFA_METHOD_CONFIG_SERIALIZER': 'auth_kit.mfa.serializers.mfa.MFAMethodConfigSerializer',
        'MFA_METHOD_CONFIRM_SERIALIZER': 'auth_kit.mfa.serializers.mfa.MFAMethodConfirmSerializer',
        'MFA_METHOD_CREATE_SERIALIZER': 'auth_kit.mfa.serializers.mfa.MFAMethodCreateSerializer',
        'MFA_METHOD_DEACTIVATE_SERIALIZER': 'auth_kit.mfa.serializers.mfa.MFAMethodDeactivateSerializer',
        'MFA_METHOD_DELETE_SERIALIZER': 'auth_kit.mfa.serializers.mfa.MFAMethodDeleteSerializer',
        'MFA_METHOD_PRIMARY_UPDATE_SERIALIZER': 'auth_kit.mfa.serializers.mfa.MFAMethodPrimaryUpdateSerializer',
        'MFA_METHOD_SEND_CODE_SERIALIZER': 'auth_kit.mfa.serializers.mfa.MFAMethodSendCodeSerializer',

        # ===================================================================
        # URL & UTILITY SETTINGS
        # ===================================================================
        'URL_NAMESPACE': '',
        'EXCLUDED_URL_NAMES': [],
    }

Related Package Settings
-------------------------

**Django REST Framework Simple JWT**

.. code-block:: python

    SIMPLE_JWT = {
        'ACCESS_TOKEN_LIFETIME': timedelta(days=30),
        'REFRESH_TOKEN_LIFETIME': timedelta(days=30),
    }

See full configuration: https://django-rest-framework-simplejwt.readthedocs.io/en/latest/settings.html

**Django Allauth**

.. code-block:: python

    ACCOUNT_EMAIL_VERIFICATION = "mandatory"
    ACCOUNT_SIGNUP_FIELDS = ["email*", "username*"]

    # Note: SOCIALACCOUNT_EMAIL_AUTHENTICATION is NOT required for DRF Auth Kit.
    # Auth Kit handles email-based account linking independently via the
    # SOCIAL_LOGIN_AUTO_CONNECT_BY_EMAIL setting (default: True).

    SOCIALACCOUNT_PROVIDERS = {
        "google": {
            "SCOPE": ["profile", "email"],
            "AUTH_PARAMS": {"access_type": "online"},
            "OAUTH_PKCE_ENABLED": True,
            "FETCH_USERINFO": True,
            "APP": {
                "client_id": "your-google-client-id",
                "secret": "your-google-client-secret",
            },
        },
    }

See full configuration:

- Account settings: https://docs.allauth.org/en/latest/account/configuration.html
- Social account settings: https://docs.allauth.org/en/latest/socialaccount/configuration.html

**Email Configuration (for MFA and verification)**

.. code-block:: python

    EMAIL_BACKEND = "django.core.mail.backends.console.EmailBackend"  # For development
    # EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"  # For production

Basic Configuration
-------------------

Here's a basic configuration example:

.. code-block:: python

    # settings.py
    AUTH_KIT = {
        'AUTH_TYPE': 'jwt',          # Authentication type: 'jwt', 'token', or 'custom'
        'USE_AUTH_COOKIE': True,     # Enable cookie-based authentication
        'USE_MFA': False,            # Enable Multi-Factor Authentication
    }

Authentication Settings
-----------------------

Authentication Type
~~~~~~~~~~~~~~~~~~~

**AUTH_TYPE** (default: ``'jwt'``)
    Choose the authentication backend:

    - ``'jwt'`` - JWT token authentication (recommended)
    - ``'token'`` - DRF Token authentication
    - ``'custom'`` - Custom authentication backend

    **Note**: The authentication class you use in ``DEFAULT_AUTHENTICATION_CLASSES`` should match your ``AUTH_TYPE``:

    - For ``'jwt'``: use ``'auth_kit.authentication.JWTCookieAuthentication'``
    - For ``'token'``: use ``'auth_kit.authentication.TokenCookieAuthentication'``
    - For ``'custom'``: use your custom authentication class that inherits from ``AuthKitCookieAuthentication``

**USE_AUTH_COOKIE** (default: ``True``)
    Enable HTTP-only cookie-based authentication. When enabled, tokens are stored in secure cookies.

**SESSION_LOGIN** (default: ``False``)
    Enable Django session-based login alongside token authentication.

**ALLOW_LOGIN_REDIRECT** (default: ``False``)
    Allow login redirects with ``next`` and ``redirect_to`` parameters.

Cookie Configuration
~~~~~~~~~~~~~~~~~~~~

**AUTH_COOKIE_SECURE** (default: ``False``)
    Set to ``True`` in production to only send cookies over HTTPS.

**AUTH_COOKIE_HTTPONLY** (default: ``True``)
    Prevent JavaScript access to authentication cookies.

**AUTH_COOKIE_SAMESITE** (default: ``'Lax'``)
    SameSite cookie attribute. Options: ``'Lax'``, ``'Strict'``, ``'None'``.

**AUTH_COOKIE_DOMAIN** (default: ``None``)
    Domain for authentication cookies. Leave as ``None`` for current domain.

JWT-Specific Settings
~~~~~~~~~~~~~~~~~~~~~

**AUTH_JWT_COOKIE_NAME** (default: ``'auth-jwt'``)
    Name of the JWT access token cookie.

**AUTH_JWT_COOKIE_PATH** (default: ``'/'``)
    Path for JWT access token cookie.

**AUTH_JWT_REFRESH_COOKIE_NAME** (default: ``'auth-refresh-jwt'``)
    Name of the JWT refresh token cookie.

**AUTH_JWT_REFRESH_COOKIE_PATH** (default: ``'/'``)
    Path for JWT refresh token cookie.

Token-Specific Settings
~~~~~~~~~~~~~~~~~~~~~~~

**AUTH_TOKEN_COOKIE_NAME** (default: ``'auth-token'``)
    Name of the DRF token cookie.

**AUTH_TOKEN_COOKIE_PATH** (default: ``'/'``)
    Path for DRF token cookie.

**AUTH_TOKEN_COOKIE_EXPIRE_TIME** (default: ``timedelta(days=1)``)
    Expiration time for DRF token cookies.

Authentication Views & Serializers
-----------------------------------

Core Authentication Components
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**LOGIN_REQUEST_SERIALIZER** (default: :class:`~auth_kit.serializers.login_factors.LoginRequestSerializer`)
    Serializer for processing login requests with username/email and password.

**LOGIN_RESPONSE_SERIALIZER** (default: :class:`~auth_kit.serializers.login_factors.BaseLoginResponseSerializer`)
    Base serializer for login responses. Automatically selected based on AUTH_TYPE.

**LOGIN_SERIALIZER_FACTORY** (default: :func:`~auth_kit.serializers.login.get_login_serializer`)
    Factory function that returns the appropriate login serializer based on configuration.

**LOGIN_VIEW** (default: :class:`~auth_kit.views.LoginView`)
    View for handling user authentication requests.

**LOGOUT_SERIALIZER** (default: :class:`~auth_kit.serializers.logout.AuthKitLogoutSerializer`)
    Serializer for processing logout requests.

**LOGOUT_VIEW** (default: :class:`~auth_kit.views.LogoutView`)
    View for handling user logout requests.

User Management
~~~~~~~~~~~~~~~

**USER_SERIALIZER** (default: :class:`~auth_kit.serializers.user.UserSerializer`)
    Serializer for user profile information.

**USER_VIEW** (default: :class:`~auth_kit.views.UserView`)
    View for retrieving and updating user profile information.

Registration & Email Verification
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**REGISTER_SERIALIZER** (default: :class:`~auth_kit.serializers.RegisterSerializer`)
    Serializer for user registration.

**REGISTER_VIEW** (default: :class:`~auth_kit.views.RegisterView`)
    View for handling user registration.

**VERIFY_EMAIL_VIEW** (default: :class:`~auth_kit.views.VerifyEmailView`)
    View for email verification during registration.

**RESEND_EMAIL_VERIFICATION_VIEW** (default: :class:`~auth_kit.views.ResendEmailVerificationView`)
    View for resending email verification messages.

**GET_EMAIL_VERIFICATION_URL_FUNC** (default: :func:`~auth_kit.views.registration.get_email_verification_url`)
    Function for generating email verification URLs.

**SEND_VERIFY_EMAIL_FUNC** (default: :func:`~auth_kit.views.registration.send_verify_email`)
    Function for sending verification emails.

Password Management
~~~~~~~~~~~~~~~~~~~

**PASSWORD_CHANGE_SERIALIZER** (default: :class:`~auth_kit.serializers.PasswordChangeSerializer`)
    Serializer for password change requests.

**PASSWORD_CHANGE_VIEW** (default: :class:`~auth_kit.views.PasswordChangeView`)
    View for handling password changes.

**PASSWORD_RESET_SERIALIZER** (default: :class:`~auth_kit.serializers.PasswordResetSerializer`)
    Serializer for password reset requests.

**PASSWORD_RESET_VIEW** (default: :class:`~auth_kit.views.PasswordResetView`)
    View for initiating password reset flow.

**PASSWORD_RESET_CONFIRM_SERIALIZER** (default: :class:`~auth_kit.serializers.PasswordResetConfirmSerializer`)
    Serializer for password reset confirmation.

**PASSWORD_RESET_CONFIRM_VIEW** (default: :class:`~auth_kit.views.PasswordResetConfirmView`)
    View for confirming password reset with new password.

**PASSWORD_RESET_URL_GENERATOR** (default: :func:`~auth_kit.forms.password_reset_url_generator`)
    Function for generating password reset URLs.

JWT-Specific Components
~~~~~~~~~~~~~~~~~~~~~~~

**JWT_TOKEN_CLAIMS_SERIALIZER** (default: :class:`~rest_framework_simplejwt.serializers.TokenObtainPairSerializer`)
    Serializer for JWT token claims and generation.

**JWT_REFRESH_VIEW** (default: :class:`~auth_kit.views.jwt.RefreshViewWithCookieSupport`)
    View for refreshing JWT tokens with cookie support.

Social Authentication Components
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**SOCIAL_LOGIN_VIEW** (default: :class:`~auth_kit.social.views.login.SocialLoginView`)
    View for handling social authentication login.

**SOCIAL_CONNECT_VIEW** (default: :class:`~auth_kit.social.views.connect.SocialConnectView`)
    View for connecting social accounts to existing users.

**SOCIAL_ACCOUNT_VIEW_SET** (default: :class:`~auth_kit.social.views.account.SocialAccountViewSet`)
    ViewSet for managing connected social accounts.

**SOCIAL_LOGIN_SERIALIZER_FACTORY** (default: :func:`~auth_kit.social.serializers.get_social_login_serializer`)
    Factory function for social login serializers.

**SOCIAL_LOGIN_CALLBACK_URL_GENERATOR** (default: :func:`~auth_kit.social.utils.get_social_login_callback_url`)
    Function for generating social login callback URLs.

**SOCIAL_CONNECT_CALLBACK_URL_GENERATOR** (default: :func:`~auth_kit.social.utils.get_social_connect_callback_url`)
    Function for generating social connect callback URLs.

Multi-Factor Authentication (MFA)
----------------------------------

Basic MFA Settings
~~~~~~~~~~~~~~~~~~

**USE_MFA** (default: ``False``)
    Enable Multi-Factor Authentication. When enabled, login becomes a two-step process.

**MFA_MODEL** (default: ``'auth_kit.mfa.models.MFAMethod'``)
    Model class for storing MFA methods.

**MFA_HANDLERS** (default: ``['auth_kit.mfa.handlers.app.MFAAppHandler', 'auth_kit.mfa.handlers.email.MFAEmailHandler']``)
    List of available MFA handler classes.

**MFA_APPLICATION_NAME** (default: ``'MyApplication'``)
    Application name displayed in authenticator apps.

TOTP Configuration
~~~~~~~~~~~~~~~~~~

**MFA_TOTP_DEFAULT_INTERVAL** (default: ``30``)
    TOTP code validity interval in seconds.

**MFA_TOTP_DEFAULT_VALID_WINDOW** (default: ``0``)
    Number of previous/next intervals to accept for clock skew tolerance.

Backup Codes
~~~~~~~~~~~~

**NUM_OF_BACKUP_CODES** (default: ``5``)
    Number of backup codes to generate per user.

**BACKUP_CODE_LENGTH** (default: ``12``)
    Length of each backup code.

**BACKUP_CODE_ALLOWED_CHARS** (default: ``'0123456789ABCDEFGHJKMNPQRSTVWXYZ'``)
    Characters allowed in backup codes (Crockford Base32).

**BACKUP_CODE_SECURE_HASH** (default: ``True``)
    Use secure hashing for backup codes storage.

MFA Security Settings
~~~~~~~~~~~~~~~~~~~~~

**MFA_EPHEMERAL_TOKEN_EXPIRY** (default: ``900``)
    Expiry time in seconds for MFA ephemeral tokens (15 minutes).

**MFA_UPDATE_PRIMARY_METHOD_REQUIRED_PRIMARY_CODE** (default: ``False``)
    Require primary method code when updating primary MFA method.

**MFA_PREVENT_DELETE_ACTIVE_METHOD** (default: ``False``)
    Prevent deletion of active MFA methods.

**MFA_PREVENT_DELETE_PRIMARY_METHOD** (default: ``False``)
    Prevent deletion of the primary MFA method.

**MFA_DELETE_ACTIVE_METHOD_REQUIRE_CODE** (default: ``False``)
    Require MFA code when deleting active methods.

MFA Views & Serializers
~~~~~~~~~~~~~~~~~~~~~~~

**LOGIN_FIRST_STEP_VIEW** (default: :class:`~auth_kit.mfa.views.LoginFirstStepView`)
    View for the first step of MFA login (password verification).

**LOGIN_SECOND_STEP_VIEW** (default: :class:`~auth_kit.mfa.views.LoginSecondStepView`)
    View for the second step of MFA login (MFA code verification).

**LOGIN_CHANGE_METHOD_VIEW** (default: :class:`~auth_kit.mfa.views.LoginChangeMethodView`)
    View for changing MFA method during login.

**LOGIN_MFA_RESEND_VIEW** (default: :class:`~auth_kit.mfa.views.LoginMFAResendView`)
    View for resending MFA codes during login.

**LOGIN_MFA_METHOD_VIEW_SET** (default: :class:`~auth_kit.mfa.views.MFAMethodViewSet`)
    ViewSet for managing user MFA methods.

**MFA_FIRST_STEP_RESPONSE_SERIALIZER** (default: :class:`~auth_kit.mfa.serializers.login_factors.MFAFirstStepResponseSerializer`)
    Serializer for first step login responses.

**MFA_SECOND_STEP_REQUEST_SERIALIZER** (default: :class:`~auth_kit.mfa.serializers.login_factors.MFASecondStepRequestSerializer`)
    Serializer for second step login requests.

**MFA_CHANGE_METHOD_SERIALIZER** (default: :class:`~auth_kit.mfa.serializers.login_factors.MFAChangeMethodSerializer`)
    Serializer for changing MFA method during login.

**MFA_RESEND_SERIALIZER** (default: :class:`~auth_kit.mfa.serializers.login_factors.MFAResendSerializer`)
    Serializer for MFA code resend requests.

**GET_NO_MFA_LOGIN_RESPONSE_SERIALIZER** (default: :func:`~auth_kit.mfa.serializers.login_factors.get_no_mfa_login_response_serializer`)
    Factory function for login responses when MFA is disabled.

**MFA_FIRST_STEP_SERIALIZER_FACTORY** (default: :func:`~auth_kit.mfa.serializers.login.get_mfa_first_step_serializer`)
    Factory function for first step login serializers.

**MFA_SECOND_STEP_SERIALIZER_FACTORY** (default: :func:`~auth_kit.mfa.serializers.login.get_mfa_second_step_serializer`)
    Factory function for second step login serializers.

**MFA_METHOD_CONFIG_SERIALIZER** (default: :class:`~auth_kit.mfa.serializers.mfa.MFAMethodConfigSerializer`)
    Serializer for MFA method configuration.

**MFA_METHOD_CONFIRM_SERIALIZER** (default: :class:`~auth_kit.mfa.serializers.mfa.MFAMethodConfirmSerializer`)
    Serializer for confirming MFA method setup.

**MFA_METHOD_CREATE_SERIALIZER** (default: :class:`~auth_kit.mfa.serializers.mfa.MFAMethodCreateSerializer`)
    Serializer for creating new MFA methods.

**MFA_METHOD_DEACTIVATE_SERIALIZER** (default: :class:`~auth_kit.mfa.serializers.mfa.MFAMethodDeactivateSerializer`)
    Serializer for deactivating MFA methods.

**MFA_METHOD_DELETE_SERIALIZER** (default: :class:`~auth_kit.mfa.serializers.mfa.MFAMethodDeleteSerializer`)
    Serializer for deleting MFA methods.

**MFA_METHOD_PRIMARY_UPDATE_SERIALIZER** (default: :class:`~auth_kit.mfa.serializers.mfa.MFAMethodPrimaryUpdateSerializer`)
    Serializer for updating primary MFA method.

**MFA_METHOD_SEND_CODE_SERIALIZER** (default: :class:`~auth_kit.mfa.serializers.mfa.MFAMethodSendCodeSerializer`)
    Serializer for sending MFA verification codes.

Social Authentication
---------------------

**SOCIAL_LOGIN_AUTH_TYPE** (default: ``'code'``)
    OAuth2 flow type: ``'code'`` (authorization code) or ``'token'`` (implicit flow).

**SOCIAL_LOGIN_AUTO_CONNECT_BY_EMAIL** (default: ``True``)
    Automatically connect social accounts to existing users by email.

    When ``True``: If a user logs in with a social provider and their email matches an existing
    account, the social account is automatically linked to that user. This enables seamless
    multi-provider login (e.g., a user can log in with Google one day and Microsoft the next,
    using the same email).

    When ``False``: Users cannot social login if an account with their email already exists.
    They will receive an error message and must login with their existing credentials first,
    then manually connect the social account.

    **Note**: This setting works independently of Django Allauth's ``SOCIALACCOUNT_EMAIL_AUTHENTICATION``.
    You do not need to configure allauth's email authentication settings when using DRF Auth Kit.

**SOCIAL_LOGIN_CALLBACK_BASE_URL** (default: ``''``)
    Base URL for social login callbacks.

**SOCIAL_CONNECT_CALLBACK_BASE_URL** (default: ``''``)
    Base URL for social account connection callbacks.

**SOCIAL_HIDE_AUTH_ERROR_DETAILS** (default: ``True``)
    Hide detailed error messages for security.

**SOCIAL_CONNECT_REQUIRE_EMAIL_MATCH** (default: ``True``)
    Require email match when connecting social accounts.

Password Management
-------------------

**OLD_PASSWORD_FIELD_ENABLED** (default: ``False``)
    Require old password when changing password.

**PASSWORD_RESET_PREVENT_ENUMERATION** (default: ``True``)
    Prevent user enumeration in password reset flow.

**FRONTEND_BASE_URL** (default: ``None``)
    Base URL for frontend application. Used to generate URLs for email verification and password reset that redirect to your frontend instead of the API backend.

**REGISTER_EMAIL_CONFIRM_PATH** (default: ``None``)
    Custom path for email verification URLs. If not provided, uses the backend API path. Used in combination with ``FRONTEND_BASE_URL``.

**PASSWORD_RESET_CONFIRM_PATH** (default: ``None``)
    Custom path for password reset URLs. If not provided, uses the backend API path. Used in combination with ``FRONTEND_BASE_URL``.

Frontend URL Configuration
~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Frontend Integration Example**

When building a frontend application (React, Vue, Angular, etc.), you'll want email verification and password reset links to direct users to your frontend rather than the API backend:

.. code-block:: python

    AUTH_KIT = {
        # Redirect all email links to your frontend
        'FRONTEND_BASE_URL': 'https://myapp.com',
        'REGISTER_EMAIL_CONFIRM_PATH': '/auth/verify-email',
        'PASSWORD_RESET_CONFIRM_PATH': '/auth/reset-password',
    }

This configuration will generate URLs like:

- Email verification: ``https://myapp.com/auth/verify-email?key=abc123``
- Password reset: ``https://myapp.com/auth/reset-password?uid=xyz&token=def456``

**Flexible Path Configuration**

If you don't specify custom paths, the system uses backend API paths with your frontend base URL:

.. code-block:: python

    AUTH_KIT = {
        'FRONTEND_BASE_URL': 'https://myapp.com',
        # Paths default to backend API paths:
        # REGISTER_EMAIL_CONFIRM_PATH defaults to '/api/auth/registration/verify-email'
        # PASSWORD_RESET_CONFIRM_PATH defaults to '/api/auth/password/reset/confirm'
    }

This generates:

- Email verification: ``https://myapp.com/api/auth/registration/verify-email?key=abc123``
- Password reset: ``https://myapp.com/api/auth/password/reset/confirm?uid=xyz&token=def456``

**Backend-Only Configuration**

For API-only applications without a separate frontend:

.. code-block:: python

    AUTH_KIT = {
        # No FRONTEND_BASE_URL specified
        # All URLs will use Django's build_absolute_uri with backend paths
    }

This generates backend URLs like:

- Email verification: ``https://api.myapp.com/api/auth/registration/verify-email?key=abc123``
- Password reset: ``https://api.myapp.com/api/auth/password/reset/confirm?uid=xyz&token=def456``

URL Configuration
-----------------

**URL_NAMESPACE** (default: ``''``)
    URL namespace for Auth Kit endpoints.

**EXCLUDED_URL_NAMES** (default: ``[]``)
    List of URL names to exclude from automatic URL generation.

Advanced Customization
-----------------------

Custom Serializers
~~~~~~~~~~~~~~~~~~

You can override any serializer by providing the import path:

.. code-block:: python

    AUTH_KIT = {
        'LOGIN_REQUEST_SERIALIZER': 'myapp.serializers.CustomLoginSerializer',
        'LOGIN_RESPONSE_SERIALIZER': 'myapp.serializers.CustomLoginResponseSerializer',
        'REGISTER_SERIALIZER': 'myapp.serializers.CustomRegisterSerializer',
        'USER_SERIALIZER': 'myapp.serializers.CustomUserSerializer',
        'PASSWORD_CHANGE_SERIALIZER': 'myapp.serializers.CustomPasswordChangeSerializer',
        'PASSWORD_RESET_SERIALIZER': 'myapp.serializers.CustomPasswordResetSerializer',
        'PASSWORD_RESET_CONFIRM_SERIALIZER': 'myapp.serializers.CustomPasswordResetConfirmSerializer',
    }

**Default Serializers:**

- **LOGIN_REQUEST_SERIALIZER**: :class:`~auth_kit.serializers.login_factors.LoginRequestSerializer`
- **LOGIN_RESPONSE_SERIALIZER**: :class:`~auth_kit.serializers.login_factors.BaseLoginResponseSerializer`
- **REGISTER_SERIALIZER**: :class:`~auth_kit.serializers.RegisterSerializer`
- **USER_SERIALIZER**: :class:`~auth_kit.serializers.user.UserSerializer`
- **PASSWORD_CHANGE_SERIALIZER**: :class:`~auth_kit.serializers.PasswordChangeSerializer`
- **PASSWORD_RESET_SERIALIZER**: :class:`~auth_kit.serializers.PasswordResetSerializer`
- **PASSWORD_RESET_CONFIRM_SERIALIZER**: :class:`~auth_kit.serializers.PasswordResetConfirmSerializer`

Custom Views
~~~~~~~~~~~~

Override views with custom implementations:

.. code-block:: python

    AUTH_KIT = {
        'LOGIN_VIEW': 'myapp.views.CustomLoginView',
        'LOGOUT_VIEW': 'myapp.views.CustomLogoutView',
        'USER_VIEW': 'myapp.views.CustomUserView',
    }

**Default Views:**

- **LOGIN_VIEW**: :class:`~auth_kit.views.LoginView`
- **LOGOUT_VIEW**: :class:`~auth_kit.views.LogoutView`
- **USER_VIEW**: :class:`~auth_kit.views.UserView`
- **REGISTER_VIEW**: :class:`~auth_kit.views.RegisterView`
- **VERIFY_EMAIL_VIEW**: :class:`~auth_kit.views.VerifyEmailView`
- **RESEND_EMAIL_VERIFICATION_VIEW**: :class:`~auth_kit.views.ResendEmailVerificationView`
- **PASSWORD_CHANGE_VIEW**: :class:`~auth_kit.views.PasswordChangeView`
- **PASSWORD_RESET_VIEW**: :class:`~auth_kit.views.PasswordResetView`
- **PASSWORD_RESET_CONFIRM_VIEW**: :class:`~auth_kit.views.PasswordResetConfirmView`
- **JWT_REFRESH_VIEW**: :class:`~auth_kit.views.jwt.RefreshViewWithCookieSupport`

Custom Authentication
~~~~~~~~~~~~~~~~~~~~~

For custom authentication backends, set ``AUTH_TYPE`` to ``'custom'`` and override the base settings:

.. code-block:: python

    AUTH_KIT = {
        'AUTH_TYPE': 'custom',
        'LOGIN_RESPONSE_SERIALIZER': 'myapp.serializers.MyLoginResponseSerializer',
        'LOGIN_VIEW': 'myapp.views.MyLoginView',
        'LOGOUT_VIEW': 'myapp.views.MyLogoutView',
        # Override any other components as needed
        'USER_SERIALIZER': 'myapp.serializers.MyUserSerializer',
    }

**Example: Knox Token Authentication**

.. code-block:: python

    AUTH_KIT = {
        'AUTH_TYPE': 'custom',
        'LOGIN_RESPONSE_SERIALIZER': 'custom_auth.serializers.KnoxTokenResponseSerializer',
        'LOGIN_VIEW': 'custom_auth.views.KnoxLoginView',
        'LOGOUT_VIEW': 'custom_auth.views.KnoxLogoutView',
    }

MFA Custom Handlers
~~~~~~~~~~~~~~~~~~~

Add custom MFA handlers:

.. code-block:: python

    AUTH_KIT = {
        'USE_MFA': True,
        'MFA_HANDLERS': [
            'auth_kit.mfa.handlers.app.MFAAppHandler',
            'auth_kit.mfa.handlers.email.MFAEmailHandler',
            'myapp.mfa.CustomSMSHandler',  # Your custom handler
        ],
    }

Social Authentication Custom Views
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Override social authentication components:

.. code-block:: python

    AUTH_KIT = {
        'SOCIAL_LOGIN_VIEW': 'myapp.views.CustomSocialLoginView',
        'SOCIAL_CONNECT_VIEW': 'myapp.views.CustomSocialConnectView',
        'SOCIAL_ACCOUNT_VIEW_SET': 'myapp.viewsets.CustomSocialAccountViewSet',
    }

**Default Social Authentication Components:**

- **SOCIAL_LOGIN_VIEW**: :class:`~auth_kit.social.views.login.SocialLoginView`
- **SOCIAL_CONNECT_VIEW**: :class:`~auth_kit.social.views.connect.SocialConnectView`
- **SOCIAL_ACCOUNT_VIEW_SET**: :class:`~auth_kit.social.views.account.SocialAccountViewSet`

Complete Example Configuration
------------------------------

Here's a comprehensive configuration example:

.. code-block:: python

    from datetime import timedelta

    # settings.py
    AUTH_KIT = {
        # Authentication
        'AUTH_TYPE': 'jwt',
        'USE_AUTH_COOKIE': True,
        'ALLOW_LOGIN_REDIRECT': True,

        # Cookie Security
        'AUTH_COOKIE_SECURE': True,  # Set to False in development
        'AUTH_COOKIE_HTTPONLY': True,
        'AUTH_COOKIE_SAMESITE': 'Lax',
        'AUTH_COOKIE_DOMAIN': '.example.com',  # For subdomain sharing

        # MFA Configuration
        'USE_MFA': True,
        'MFA_APPLICATION_NAME': 'My App',
        'MFA_EPHEMERAL_TOKEN_EXPIRY': 600,  # 10 minutes
        'NUM_OF_BACKUP_CODES': 8,
        'BACKUP_CODE_LENGTH': 16,

        # Social Authentication
        'SOCIAL_LOGIN_AUTO_CONNECT_BY_EMAIL': True,
        'SOCIAL_CONNECT_REQUIRE_EMAIL_MATCH': True,
        'SOCIAL_HIDE_AUTH_ERROR_DETAILS': True,

        # Password Management
        'OLD_PASSWORD_FIELD_ENABLED': True,
        'PASSWORD_RESET_PREVENT_ENUMERATION': False,  # Allow enumeration in internal apps

        # Frontend Integration
        'FRONTEND_BASE_URL': 'https://myapp.com',
        'REGISTER_EMAIL_CONFIRM_PATH': '/auth/verify-email',
        'PASSWORD_RESET_CONFIRM_PATH': '/auth/reset-password',

        # URLs
        'URL_NAMESPACE': 'api:auth',
        'EXCLUDED_URL_NAMES': ['admin-login', 'health-check'],
    }

    # JWT Configuration (if using JWT)
    SIMPLE_JWT = {
        'ACCESS_TOKEN_LIFETIME': timedelta(minutes=30),
        'REFRESH_TOKEN_LIFETIME': timedelta(days=7),
        'ROTATE_REFRESH_TOKENS': True,
        'BLACKLIST_AFTER_ROTATION': True,
    }

    # Django Allauth Settings
    ACCOUNT_EMAIL_VERIFICATION = 'mandatory'
    ACCOUNT_SIGNUP_FIELDS = ['email', 'username']
    SOCIALACCOUNT_EMAIL_AUTHENTICATION = True

Environment-Specific Settings
-----------------------------

**Development**:

.. code-block:: python

    AUTH_KIT = {
        'AUTH_TYPE': 'jwt',
        'USE_AUTH_COOKIE': True,
        'AUTH_COOKIE_SECURE': False,  # HTTP allowed in development
        'USE_MFA': False,  # Disable MFA for easier testing
    }

**Production**:

.. code-block:: python

    AUTH_KIT = {
        'AUTH_TYPE': 'jwt',
        'USE_AUTH_COOKIE': True,
        'AUTH_COOKIE_SECURE': True,  # HTTPS required
        'USE_MFA': True,  # Enable MFA for security
        'SOCIAL_HIDE_AUTH_ERROR_DETAILS': True,  # Hide error details
        'PASSWORD_RESET_PREVENT_ENUMERATION': True,  # Prevent enumeration
    }

Internationalization
--------------------

DRF Auth Kit includes built-in support for internationalization (i18n) with translations for 57 languages.

**Supported Languages**

DRF Auth Kit supports the following major languages:

- **English** (en) - Default language
- **Spanish** (es) - Español
- **French** (fr) - Français
- **German** (de) - Deutsch
- **Chinese** (zh) - 中文
- **Japanese** (ja) - 日本語
- **Korean** (ko) - 한국어
- **Vietnamese** (vi) - Tiếng Việt
- **Russian** (ru) - Русский
- **Arabic** (ar) - العربية
- **Portuguese** (pt) - Português
- **Italian** (it) - Italiano
- **Dutch** (nl) - Nederlands
- **Hindi** (hi) - हिन्दी
- **And 43 more languages...**

**Django i18n Configuration**

To enable internationalization in your Django project:

.. code-block:: python

    # settings.py
    LANGUAGE_CODE = 'en'  # Default language

    # Enable Django's i18n system
    USE_I18N = True
    USE_L10N = True
    USE_TZ = True

    # Add LocaleMiddleware to process language preferences
    MIDDLEWARE = [
        # ... other middleware
        'django.middleware.locale.LocaleMiddleware',
        # ... other middleware
    ]

    # Optional: Specify supported languages
    LANGUAGES = [
        ('en', 'English'),
        ('es', 'Español'),
        ('fr', 'Français'),
        ('de', 'Deutsch'),
        ('zh', '中文'),
        ('ja', '日本語'),
        ('ko', '한국어'),
        ('vi', 'Tiếng Việt'),
        # Add more languages as needed
    ]

**Translation Coverage**

All DRF Auth Kit components include translations for:

- Authentication messages (login, logout, registration)
- Error messages and validation errors
- MFA setup and verification messages
- Social authentication responses
- Password reset and email verification messages
- User profile and account management messages

**Language Selection**

Users can select their preferred language through:

1. **HTTP Accept-Language Header**: Automatically detected by Django
2. **URL Language Prefix**: Using Django's i18n URL patterns
3. **Session/Cookie Language**: Persistent language preference
4. **User Profile Setting**: Custom language preference storage

**Example: URL Language Prefix**

.. code-block:: python

    # urls.py
    from django.conf.urls.i18n import i18n_patterns
    from django.urls import path, include

    urlpatterns = i18n_patterns(
        path('api/auth/', include('auth_kit.urls')),
        # ... other URLs
    )

    # Enables URLs like:
    # /en/api/auth/login/
    # /es/api/auth/login/
    # /fr/api/auth/login/

**Custom Translation Override**

You can override any translation by providing your own translation files:

.. code-block:: bash

    # Create locale directory structure
    mkdir -p locale/en/LC_MESSAGES/
    mkdir -p locale/es/LC_MESSAGES/

    # Generate translation files
    python manage.py makemessages -l en
    python manage.py makemessages -l es

    # Edit .po files to customize translations
    # Compile translations
    python manage.py compilemessages

Related Django Settings
------------------------

**REST Framework Configuration**:

.. code-block:: python

    REST_FRAMEWORK = {
        'DEFAULT_AUTHENTICATION_CLASSES': [
            'auth_kit.authentication.JWTCookieAuthentication',
        ],
        'DEFAULT_SCHEMA_CLASS': 'drf_spectacular.openapi.AutoSchema',
    }

**Email Configuration** (required for email MFA and password reset):

.. code-block:: python

    EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
    EMAIL_HOST = 'smtp.gmail.com'
    EMAIL_PORT = 587
    EMAIL_USE_TLS = True
    EMAIL_HOST_USER = 'your-email@gmail.com'
    EMAIL_HOST_PASSWORD = 'your-app-password'
    DEFAULT_FROM_EMAIL = 'Your App <noreply@yourapp.com>'

For more information on external library configurations, see:

- **Django REST Framework Simple JWT**: https://django-rest-framework-simplejwt.readthedocs.io/
- **Django Allauth**: https://docs.allauth.org/
- **DRF Spectacular**: https://drf-spectacular.readthedocs.io/
