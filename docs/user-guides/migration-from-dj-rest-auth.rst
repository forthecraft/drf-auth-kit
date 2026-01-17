Migration from dj-rest-auth
===========================

This guide helps you migrate from `dj-rest-auth <https://github.com/iMerica/dj-rest-auth>`_ to DRF Auth Kit. Both packages provide authentication for Django REST Framework using similar underlying libraries (django-allauth, djangorestframework-simplejwt). DRF Auth Kit offers full type safety, built-in MFA support, accurate OpenAPI schema generation, and more included i18n translations.

Why Migrate?
------------

**Advantages of DRF Auth Kit over dj-rest-auth:**

- **Full Type Safety**: Complete type hints with mypy and pyright compatibility (dj-rest-auth has none)
- **Built-in MFA**: Integrated multi-factor authentication with pluggable handlers (email, authenticator apps) - no extra setup required
- **Modern Django Support**: Actively maintained with Django 4.2 - 6.x support
- **Accurate OpenAPI Schema**: Full DRF Spectacular integration with accurate API documentation
- **Dynamic Configuration**: Settings-based customization without subclassing views
- **More i18n Languages**: Built-in translations for 57 languages

Quick Comparison
----------------

.. list-table::
   :header-rows: 1
   :widths: 30 35 35

   * - Feature
     - dj-rest-auth
     - DRF Auth Kit
   * - Type Hints
     - None
     - Full (mypy/pyright)
   * - MFA Support
     - Requires separate setup
     - Built-in with pluggable handlers
   * - Social Auth
     - Auto-generated URLs
     - Auto-generated URLs
   * - Configuration
     - Class-based overrides
     - Settings-based (dynamic imports)
   * - OpenAPI Schema
     - Partial (via drf-spectacular, less accurate)
     - Full (accurate schema generation)
   * - i18n Support
     - Partial (fewer languages)
     - 57 languages included

Migration Steps
---------------

Step 1: Update Dependencies
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Remove dj-rest-auth and install drf-auth-kit:

.. code-block:: bash

    # Remove old package
    pip uninstall dj-rest-auth

    # Install drf-auth-kit (choose one based on your needs)
    pip install drf-auth-kit              # Basic authentication
    pip install drf-auth-kit[mfa]         # With MFA support
    pip install drf-auth-kit[social]      # With social authentication
    pip install drf-auth-kit[all]         # All features

Step 2: Update INSTALLED_APPS
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Before (dj-rest-auth):**

.. code-block:: python

    INSTALLED_APPS = [
        # ...
        'rest_framework',
        'rest_framework.authtoken',  # For token auth
        'dj_rest_auth',
        'allauth',
        'allauth.account',
        'dj_rest_auth.registration',  # For registration
        'allauth.socialaccount',      # For social auth
        'allauth.socialaccount.providers.google',
    ]

**After (DRF Auth Kit):**

.. code-block:: python

    INSTALLED_APPS = [
        # ...
        'rest_framework',
        'allauth',
        'allauth.account',
        'auth_kit',                    # Core authentication
        # Optional: Add these based on your needs
        'auth_kit.mfa',                # For MFA support
        'allauth.socialaccount',       # For social auth
        'allauth.socialaccount.providers.google',
        'auth_kit.social',             # For social auth integration
    ]

.. note::

    ``rest_framework.authtoken`` is only needed if you use ``AUTH_TYPE = 'token'``.
    For JWT authentication (recommended), it's not required.

Step 3: Update URL Configuration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Before (dj-rest-auth):**

.. code-block:: python

    urlpatterns = [
        path('api/auth/', include('dj_rest_auth.urls')),
        path('api/auth/registration/', include('dj_rest_auth.registration.urls')),
        # Social auth (if used)
        path('api/auth/social/', include('allauth.socialaccount.urls')),
    ]

**After (DRF Auth Kit):**

.. code-block:: python

    urlpatterns = [
        path('api/auth/', include('auth_kit.urls')),
        # Social auth (if used) - automatically generates URLs for all providers
        path('api/auth/social/', include('auth_kit.social.urls')),
    ]

.. note::

    DRF Auth Kit includes registration endpoints in the main ``auth_kit.urls`` pattern.
    Social URLs are automatically generated for all installed providers.

Step 4: Update Settings
~~~~~~~~~~~~~~~~~~~~~~~

**Before (dj-rest-auth):**

.. code-block:: python

    REST_AUTH = {
        'USE_JWT': True,
        'JWT_AUTH_COOKIE': 'jwt-auth',
        'JWT_AUTH_REFRESH_COOKIE': 'jwt-refresh',
        'JWT_AUTH_HTTPONLY': True,
        'JWT_AUTH_SECURE': False,
        'JWT_AUTH_SAMESITE': 'Lax',
        'SESSION_LOGIN': False,
        'OLD_PASSWORD_FIELD_ENABLED': False,
        'LOGOUT_ON_PASSWORD_CHANGE': False,
        'REGISTER_SERIALIZER': 'myapp.serializers.CustomRegisterSerializer',
        'USER_DETAILS_SERIALIZER': 'myapp.serializers.CustomUserSerializer',
        'LOGIN_SERIALIZER': 'myapp.serializers.CustomLoginSerializer',
    }

**After (DRF Auth Kit):**

.. code-block:: python

    AUTH_KIT = {
        # Authentication type (replaces USE_JWT)
        'AUTH_TYPE': 'jwt',             # 'jwt', 'token', or 'custom'
        'USE_AUTH_COOKIE': True,

        # Cookie settings (replaces JWT_AUTH_* settings)
        'AUTH_JWT_COOKIE_NAME': 'auth-jwt',
        'AUTH_JWT_REFRESH_COOKIE_NAME': 'auth-refresh-jwt',
        'AUTH_COOKIE_HTTPONLY': True,
        'AUTH_COOKIE_SECURE': False,    # Set True in production
        'AUTH_COOKIE_SAMESITE': 'Lax',

        # Session and password settings
        'SESSION_LOGIN': False,
        'OLD_PASSWORD_FIELD_ENABLED': False,

        # Custom serializers
        'REGISTER_SERIALIZER': 'myapp.serializers.CustomRegisterSerializer',
        'USER_SERIALIZER': 'myapp.serializers.CustomUserSerializer',
        'LOGIN_REQUEST_SERIALIZER': 'myapp.serializers.CustomLoginSerializer',
    }

**Settings Mapping Reference:**

.. list-table::
   :header-rows: 1
   :widths: 45 55

   * - dj-rest-auth Setting
     - DRF Auth Kit Setting
   * - ``USE_JWT``
     - ``AUTH_TYPE = 'jwt'``
   * - ``JWT_AUTH_COOKIE``
     - ``AUTH_JWT_COOKIE_NAME``
   * - ``JWT_AUTH_REFRESH_COOKIE``
     - ``AUTH_JWT_REFRESH_COOKIE_NAME``
   * - ``JWT_AUTH_HTTPONLY``
     - ``AUTH_COOKIE_HTTPONLY``
   * - ``JWT_AUTH_SECURE``
     - ``AUTH_COOKIE_SECURE``
   * - ``JWT_AUTH_SAMESITE``
     - ``AUTH_COOKIE_SAMESITE``
   * - ``JWT_AUTH_COOKIE_DOMAIN``
     - ``AUTH_COOKIE_DOMAIN``
   * - ``JWT_AUTH_COOKIE_PATH``
     - ``AUTH_JWT_COOKIE_PATH``
   * - ``JWT_AUTH_REFRESH_COOKIE_PATH``
     - ``AUTH_JWT_REFRESH_COOKIE_PATH``
   * - ``SESSION_LOGIN``
     - ``SESSION_LOGIN``
   * - ``OLD_PASSWORD_FIELD_ENABLED``
     - ``OLD_PASSWORD_FIELD_ENABLED``
   * - ``USER_DETAILS_SERIALIZER``
     - ``USER_SERIALIZER``
   * - ``LOGIN_SERIALIZER``
     - ``LOGIN_REQUEST_SERIALIZER``
   * - ``REGISTER_SERIALIZER``
     - ``REGISTER_SERIALIZER``
   * - ``PASSWORD_RESET_SERIALIZER``
     - ``PASSWORD_RESET_SERIALIZER``
   * - ``PASSWORD_CHANGE_SERIALIZER``
     - ``PASSWORD_CHANGE_SERIALIZER``
   * - ``PASSWORD_RESET_CONFIRM_SERIALIZER``
     - ``PASSWORD_RESET_CONFIRM_SERIALIZER``
   * - ``TOKEN_SERIALIZER``
     - ``LOGIN_RESPONSE_SERIALIZER`` (for token auth)
   * - ``JWT_SERIALIZER``
     - ``LOGIN_RESPONSE_SERIALIZER`` (for JWT auth)
   * - ``TOKEN_CREATOR``
     - ``JWT_TOKEN_CLAIMS_SERIALIZER`` (for JWT)

Step 5: Update Authentication Classes
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Before (dj-rest-auth with JWT):**

.. code-block:: python

    REST_FRAMEWORK = {
        'DEFAULT_AUTHENTICATION_CLASSES': [
            'dj_rest_auth.jwt_auth.JWTCookieAuthentication',
        ],
    }

**After (DRF Auth Kit):**

.. code-block:: python

    REST_FRAMEWORK = {
        'DEFAULT_AUTHENTICATION_CLASSES': [
            'auth_kit.authentication.JWTCookieAuthentication',
        ],
    }

**Authentication Class Mapping:**

.. list-table::
   :header-rows: 1
   :widths: 50 50

   * - dj-rest-auth Class
     - DRF Auth Kit Class
   * - ``dj_rest_auth.jwt_auth.JWTCookieAuthentication``
     - ``auth_kit.authentication.JWTCookieAuthentication``
   * - ``rest_framework.authentication.TokenAuthentication``
     - ``auth_kit.authentication.TokenCookieAuthentication``

Step 6: Update URL Endpoints
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Most endpoints have the same paths, but some have changed:

**Endpoint Mapping:**

.. list-table::
   :header-rows: 1
   :widths: 45 55

   * - dj-rest-auth Endpoint
     - DRF Auth Kit Endpoint
   * - ``POST /login/``
     - ``POST /login/``
   * - ``POST /logout/``
     - ``POST /logout/``
   * - ``GET /user/``
     - ``GET /user/``
   * - ``PUT/PATCH /user/``
     - ``PUT/PATCH /user/``
   * - ``POST /password/change/``
     - ``POST /password/change/``
   * - ``POST /password/reset/``
     - ``POST /password/reset/``
   * - ``POST /password/reset/confirm/``
     - ``POST /password/reset/confirm/``
   * - ``POST /registration/``
     - ``POST /registration/``
   * - ``POST /registration/verify-email/``
     - ``POST /registration/verify-email/``
   * - ``POST /registration/resend-email/``
     - ``POST /registration/resend-email/``
   * - ``POST /token/verify/``
     - ``POST /token/verify/``
   * - ``POST /token/refresh/``
     - ``POST /token/refresh/``

**New Endpoints in DRF Auth Kit (when MFA is enabled):**

- ``POST /login/verify/`` - MFA code verification
- ``POST /login/change-method/`` - Change MFA method during login
- ``POST /login/resend/`` - Resend MFA code
- ``GET|POST /mfa/`` - MFA method management
- ``POST /mfa/confirm/`` - Confirm MFA method setup
- ``POST /mfa/primary/`` - Set primary MFA method
- ``POST /mfa/deactivate/`` - Deactivate MFA method
- ``POST /mfa/delete/`` - Delete MFA method
- ``POST /mfa/send/`` - Send MFA verification code

Step 7: Migrate Custom Serializers
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If you have custom serializers, update their base classes:

**Login Serializer:**

.. code-block:: python

    # Before (dj-rest-auth)
    from dj_rest_auth.serializers import LoginSerializer

    class CustomLoginSerializer(LoginSerializer):
        def validate(self, attrs):
            # custom logic
            return super().validate(attrs)

    # After (DRF Auth Kit)
    from auth_kit.serializers import LoginRequestSerializer

    class CustomLoginSerializer(LoginRequestSerializer):
        def validate(self, attrs):
            # custom logic
            return super().validate(attrs)

**Registration Serializer:**

.. code-block:: python

    # Before (dj-rest-auth)
    from dj_rest_auth.registration.serializers import RegisterSerializer

    class CustomRegisterSerializer(RegisterSerializer):
        first_name = serializers.CharField(required=True)

        def custom_signup(self, request, user):
            user.first_name = self.validated_data.get('first_name', '')
            user.save()

    # After (DRF Auth Kit)
    from auth_kit.serializers import RegisterSerializer

    class CustomRegisterSerializer(RegisterSerializer):
        first_name = serializers.CharField(required=True)

        def custom_signup(self, request, user):
            user.first_name = self.validated_data.get('first_name', '')
            user.save()

**User Serializer:**

.. code-block:: python

    # Before (dj-rest-auth)
    from dj_rest_auth.serializers import UserDetailsSerializer

    class CustomUserSerializer(UserDetailsSerializer):
        class Meta(UserDetailsSerializer.Meta):
            fields = UserDetailsSerializer.Meta.fields + ('phone_number',)

    # After (DRF Auth Kit)
    from auth_kit.serializers import UserSerializer

    class CustomUserSerializer(UserSerializer):
        class Meta(UserSerializer.Meta):
            fields = UserSerializer.Meta.fields + ('phone_number',)

**Password Reset Serializer:**

.. code-block:: python

    # Before (dj-rest-auth)
    from dj_rest_auth.serializers import PasswordResetSerializer

    class CustomPasswordResetSerializer(PasswordResetSerializer):
        def get_email_options(self):
            return {'html_email_template_name': 'email/password_reset.html'}

    # After (DRF Auth Kit)
    from auth_kit.serializers import PasswordResetSerializer

    class CustomPasswordResetSerializer(PasswordResetSerializer):
        # DRF Auth Kit uses allauth's email templates directly
        # Configure templates in your allauth settings
        pass

**Serializer Class Mapping:**

.. list-table::
   :header-rows: 1
   :widths: 50 50

   * - dj-rest-auth Serializer
     - DRF Auth Kit Serializer
   * - ``dj_rest_auth.serializers.LoginSerializer``
     - ``auth_kit.serializers.LoginRequestSerializer``
   * - ``dj_rest_auth.serializers.UserDetailsSerializer``
     - ``auth_kit.serializers.UserSerializer``
   * - ``dj_rest_auth.serializers.PasswordResetSerializer``
     - ``auth_kit.serializers.PasswordResetSerializer``
   * - ``dj_rest_auth.serializers.PasswordResetConfirmSerializer``
     - ``auth_kit.serializers.PasswordResetConfirmSerializer``
   * - ``dj_rest_auth.serializers.PasswordChangeSerializer``
     - ``auth_kit.serializers.PasswordChangeSerializer``
   * - ``dj_rest_auth.serializers.TokenSerializer``
     - ``auth_kit.serializers.TokenResponseSerializer``
   * - ``dj_rest_auth.serializers.JWTSerializer``
     - ``auth_kit.serializers.JWTResponseSerializer``
   * - ``dj_rest_auth.registration.serializers.RegisterSerializer``
     - ``auth_kit.serializers.RegisterSerializer``

Step 8: Migrate Custom Views
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If you have custom views, update their base classes:

.. code-block:: python

    # Before (dj-rest-auth)
    from dj_rest_auth.views import LoginView, LogoutView, UserDetailsView

    class CustomLoginView(LoginView):
        def post(self, request, *args, **kwargs):
            # custom logic
            return super().post(request, *args, **kwargs)

    # After (DRF Auth Kit)
    from auth_kit.views import LoginView, LogoutView, UserView

    class CustomLoginView(LoginView):
        def post(self, request, *args, **kwargs):
            # custom logic
            return super().post(request, *args, **kwargs)

Then register your custom views in settings:

.. code-block:: python

    AUTH_KIT = {
        'LOGIN_VIEW': 'myapp.views.CustomLoginView',
        'LOGOUT_VIEW': 'myapp.views.CustomLogoutView',
        'USER_VIEW': 'myapp.views.CustomUserView',
    }

**View Class Mapping:**

.. list-table::
   :header-rows: 1
   :widths: 50 50

   * - dj-rest-auth View
     - DRF Auth Kit View
   * - ``dj_rest_auth.views.LoginView``
     - ``auth_kit.views.LoginView``
   * - ``dj_rest_auth.views.LogoutView``
     - ``auth_kit.views.LogoutView``
   * - ``dj_rest_auth.views.UserDetailsView``
     - ``auth_kit.views.UserView``
   * - ``dj_rest_auth.views.PasswordChangeView``
     - ``auth_kit.views.PasswordChangeView``
   * - ``dj_rest_auth.views.PasswordResetView``
     - ``auth_kit.views.PasswordResetView``
   * - ``dj_rest_auth.views.PasswordResetConfirmView``
     - ``auth_kit.views.PasswordResetConfirmView``
   * - ``dj_rest_auth.registration.views.RegisterView``
     - ``auth_kit.views.RegisterView``
   * - ``dj_rest_auth.registration.views.VerifyEmailView``
     - ``auth_kit.views.VerifyEmailView``
   * - ``dj_rest_auth.jwt_auth.RefreshTokenView``
     - ``auth_kit.views.RefreshViewWithCookieSupport``

Step 9: Migrate Social Authentication
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If you're using social authentication:

**Before (dj-rest-auth):**

.. code-block:: python

    # settings.py
    INSTALLED_APPS = [
        # ...
        'dj_rest_auth',
        'dj_rest_auth.registration',
        'allauth.socialaccount',
        'allauth.socialaccount.providers.google',
    ]

    # urls.py
    urlpatterns = [
        path('api/auth/', include('dj_rest_auth.urls')),
        path('api/auth/registration/', include('dj_rest_auth.registration.urls')),
        path('api/auth/google/', GoogleLogin.as_view(), name='google_login'),
    ]

    # views.py
    from allauth.socialaccount.providers.google.views import GoogleOAuth2Adapter
    from dj_rest_auth.registration.views import SocialLoginView

    class GoogleLogin(SocialLoginView):
        adapter_class = GoogleOAuth2Adapter

**After (DRF Auth Kit):**

.. code-block:: python

    # settings.py
    INSTALLED_APPS = [
        # ...
        'auth_kit',
        'allauth.socialaccount',
        'allauth.socialaccount.providers.google',
        'auth_kit.social',
    ]

    AUTH_KIT = {
        'SOCIAL_LOGIN_AUTH_TYPE': 'code',  # 'code' or 'token'
        'SOCIAL_LOGIN_AUTO_CONNECT_BY_EMAIL': True,
    }

    # urls.py - URLs are auto-generated!
    urlpatterns = [
        path('api/auth/', include('auth_kit.urls')),
        path('api/auth/social/', include('auth_kit.social.urls')),
    ]

    # No custom view needed! URLs are automatically created:
    # POST /api/auth/social/google/ - Login with Google
    # POST /api/auth/social/google/connect/ - Connect Google account

**Social Authentication Settings Mapping:**

.. list-table::
   :header-rows: 1
   :widths: 50 50

   * - dj-rest-auth Pattern
     - DRF Auth Kit Setting
   * - Custom ``SocialLoginView`` subclass
     - Auto-generated, customize via ``SOCIAL_LOGIN_VIEW``
   * - Custom callback URL handling
     - ``SOCIAL_LOGIN_CALLBACK_BASE_URL``
   * - Manual URL patterns per provider
     - Automatic URL generation

Step 10: Run Migrations
~~~~~~~~~~~~~~~~~~~~~~~

After updating your configuration:

.. code-block:: bash

    python manage.py migrate

.. note::

    If you're enabling MFA (``USE_MFA = True``), the migration will create the ``MFAMethod`` model.
    Ensure ``auth_kit.mfa`` is in your ``INSTALLED_APPS`` before running migrations.

Response Format Changes
-----------------------

**Login Response:**

The login response format is similar but may have slight differences:

.. code-block:: json

    // dj-rest-auth JWT response
    {
        "access": "eyJ...",
        "refresh": "eyJ...",
        "user": {
            "pk": 1,
            "username": "user",
            "email": "user@example.com"
        }
    }

    // DRF Auth Kit JWT response
    {
        "access": "eyJ...",
        "refresh": "eyJ...",
        "access_expiration": "2024-01-15T12:00:00Z",
        "refresh_expiration": "2024-01-22T12:00:00Z"
    }

If you need user data in the login response, customize the ``LOGIN_RESPONSE_SERIALIZER``.

**With MFA enabled, first step returns:**

.. code-block:: json

    {
        "ephemeral_token": "abc123...",
        "method": {
            "name": "email",
            "is_primary": true
        }
    }

Frontend Updates
----------------

If your frontend relies on specific response formats, update accordingly:

**Token Storage:**

- Cookie names may change (``jwt-auth`` → ``auth-jwt`` by default)
- Update any JavaScript that references cookie names

**Login Flow with MFA:**

If you enable MFA, update your frontend to handle the two-step login:

1. First POST to ``/api/auth/login/`` returns ``ephemeral_token`` if MFA is required
2. Second POST to ``/api/auth/login/verify/`` with ``ephemeral_token`` and ``code``

.. code-block:: javascript

    // Example frontend flow
    async function login(username, password) {
        const response = await fetch('/api/auth/login/', {
            method: 'POST',
            body: JSON.stringify({ username, password }),
        });
        const data = await response.json();

        if (data.ephemeral_token) {
            // MFA required - show MFA input
            return { requiresMfa: true, ephemeralToken: data.ephemeral_token };
        }
        // No MFA - user is logged in
        return { requiresMfa: false, tokens: data };
    }

    async function verifyMfa(ephemeralToken, code) {
        const response = await fetch('/api/auth/login/verify/', {
            method: 'POST',
            body: JSON.stringify({ ephemeral_token: ephemeralToken, code }),
        });
        return await response.json();
    }

Migration Checklist
-------------------

Use this checklist to ensure a complete migration:

.. code-block:: text

    [ ] Remove dj-rest-auth from requirements
    [ ] Install drf-auth-kit with appropriate extras
    [ ] Update INSTALLED_APPS
    [ ] Update URL configuration
    [ ] Convert REST_AUTH settings to AUTH_KIT
    [ ] Update authentication classes in REST_FRAMEWORK
    [ ] Migrate custom serializers (if any)
    [ ] Migrate custom views (if any)
    [ ] Update social authentication setup (if used)
    [ ] Run migrations
    [ ] Update frontend token/cookie handling
    [ ] Update frontend for MFA flow (if enabling MFA)
    [ ] Test all authentication endpoints
    [ ] Update API documentation references

Common Issues
-------------

**Import Errors:**

If you see import errors, ensure you've removed all ``dj_rest_auth`` imports:

.. code-block:: bash

    # Find remaining dj_rest_auth imports
    grep -r "dj_rest_auth" --include="*.py" .

**Cookie Not Being Set:**

Check your cookie settings:

.. code-block:: python

    AUTH_KIT = {
        'USE_AUTH_COOKIE': True,  # Must be True
        'AUTH_COOKIE_SECURE': False,  # Set False for HTTP (dev only)
        'AUTH_COOKIE_SAMESITE': 'Lax',
    }

**JWT Token Issues:**

Ensure SimpleJWT is configured:

.. code-block:: python

    SIMPLE_JWT = {
        'ACCESS_TOKEN_LIFETIME': timedelta(minutes=30),
        'REFRESH_TOKEN_LIFETIME': timedelta(days=7),
    }

**Social Auth URLs Not Generated:**

Ensure the provider apps are in ``INSTALLED_APPS`` and configured in ``SOCIALACCOUNT_PROVIDERS``:

.. code-block:: python

    INSTALLED_APPS = [
        # ...
        'allauth.socialaccount.providers.google',  # Provider app
        'auth_kit.social',  # Must come after provider apps
    ]

    SOCIALACCOUNT_PROVIDERS = {
        'google': {
            'APP': {
                'client_id': 'your-client-id',
                'secret': 'your-secret',
            }
        }
    }

Getting Help
------------

- **Documentation**: https://drf-auth-kit.readthedocs.io/
- **GitHub Issues**: https://github.com/forthecraft/drf-auth-kit/issues
- **Configuration Reference**: :doc:`/configuration`
- **Basic Usage Guide**: :doc:`basic-usage`
