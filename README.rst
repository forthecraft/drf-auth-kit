DRF AUTH KIT
============

.. image:: https://img.shields.io/pypi/v/drf-auth-kit
   :target: https://pypi.org/project/drf-auth-kit/
   :alt: PyPI

.. image:: https://codecov.io/github/forthecraft/drf-auth-kit/graph/badge.svg?token=lpj7sFpe3F
   :target: https://codecov.io/github/forthecraft/drf-auth-kit
   :alt: Code Coverage

.. image:: https://github.com/forthecraft/drf-auth-kit/actions/workflows/test.yml/badge.svg?branch=main
   :target: https://github.com/forthecraft/drf-auth-kit/actions/workflows/test.yml
   :alt: Test

.. image:: https://www.mypy-lang.org/static/mypy_badge.svg
   :target: https://mypy-lang.org/
   :alt: Checked with mypy

.. image:: https://microsoft.github.io/pyright/img/pyright_badge.svg
   :target: https://microsoft.github.io/pyright/
   :alt: Checked with pyright

.. image:: https://drf-auth-kit.readthedocs.io/en/latest/_static/interrogate_badge.svg
   :target: https://github.com/forthecraft/drf-auth-kit
   :alt: Docstring

Modern Django REST Framework authentication toolkit with JWT cookies, social login, MFA, and comprehensive user management.

Built as a next-generation alternative to existing DRF authentication packages, DRF Auth Kit provides a complete authentication solution with modern developer experience, inspired by dj-rest-auth but enhanced with full type safety, automatic OpenAPI schema generation, and comprehensive MFA support inspired by django-trench.

Features
--------

- **Multiple Authentication Types**: JWT (default), DRF Token, or Custom
- **Cookie-Based Security**: HTTP-only cookies
- **Complete User Management**: Registration, password reset, email verification
- **Multi-Factor Authentication**: Support multiple MFAs with backup codes
- **Social Authentication**: Django Allauth integration with 50+ providers, support for both OAuth2 and OpenID connect.
- **Internationalization**: Built-in support for 57 languages including English, Spanish, French, German, Chinese, Japanese, Korean, Vietnamese, and more
- **Full Type Safety**: Complete type hints with mypy and pyright
- **OpenAPI Integration**: Auto-generated API documentation with DRF Spectacular
- **Flexible Configuration**: Customizable serializers, views, and authentication backends

Installation
------------

.. code-block:: bash

    pip install drf-auth-kit

**Optional Features:**

.. code-block:: bash

    # For MFA support
    pip install drf-auth-kit[mfa]

    # For social authentication
    pip install drf-auth-kit[social]

    # For both MFA and social
    pip install drf-auth-kit[all]

**Core Dependencies:** Django 5.0+, DRF 3.0+, Django Allauth, DRF SimpleJWT

Quick Start
-----------

1. Add to your Django settings:

.. code-block:: python

    INSTALLED_APPS = [
        # ... your apps
        'rest_framework',
        'allauth',  # Required for social auth
        'allauth.account',  # Required for social auth
        # 'allauth.socialaccount',  # For social login
        # 'allauth.socialaccount.providers.google',  # For Google login
        'auth_kit',
        # 'auth_kit.social',  # For social authentication
        # 'auth_kit.mfa',  # For MFA support
    ]

    REST_FRAMEWORK = {
        'DEFAULT_AUTHENTICATION_CLASSES': [
            'auth_kit.authentication.JWTCookieAuthentication',
        ],
    }

    # Override only if needed:
    # AUTH_KIT = {
    #     'USE_MFA': True,  # Enable MFA
    # }

    # Google OAuth2 settings (for social login)
    # SOCIALACCOUNT_PROVIDERS = {
    #     'google': {
    #         'SCOPE': ['profile', 'email'],
    #         'AUTH_PARAMS': {'access_type': 'online'},
    #         'OAUTH_PKCE_ENABLED': True,
    #         'APP': {
    #             'client_id': 'your-google-client-id',
    #             'secret': 'your-google-client-secret',
    #         }
    #     }
    # }

2. Include Auth Kit URLs:

.. code-block:: python

    from django.urls import path, include

    urlpatterns = [
        path('api/auth/', include('auth_kit.urls')),
        # path('api/auth/social/', include('auth_kit.social.urls')),  # For social auth
        # ... your other URLs
    ]

3. Run migrations (only needed if using MFA):

.. code-block:: bash

    python manage.py migrate

Authentication Types
--------------------

**JWT Authentication (Recommended)**
   - Access and refresh tokens
   - Token refresh support
   - Secure cookie storage

**DRF Token Authentication**
   - Simple token-based auth
   - Compatible with DRF TokenAuthentication
   - Cookie support available

**Custom Authentication**
   - Bring your own authentication backend
   - Full customization support
   - Integrate with third-party services

Documentation
-------------

Please visit `DRF Auth Kit docs <https://drf-auth-kit.readthedocs.io/>`_ for complete documentation, including:

- Detailed configuration options
- Custom serializer examples
- Advanced usage patterns
- Integration guides

Upcoming Features
-----------------

**Enhanced Multi-Factor Authentication**

- ☐ **Hardware Security Keys**: YubiKey and FIDO2/WebAuthn support
- ☐ **SMS & Voice**: Twilio integration for SMS and voice-based MFA
- ☐ **Authenticator Apps**: Enhanced TOTP support (Google Authenticator, Authy, etc.)
- ☐ **Trusted Devices**: Remember MFA verification for trusted browsers/sessions

**Passwordless Authentication**

- ☐ **WebAuthn**: Biometric and hardware key authentication
- ☐ **Magic Links**: Email-based passwordless login
- ☐ **SMS Login**: One-time password via SMS

**Advanced Security Features**

- ☐ **Rate Limiting**: Configurable rate limits for authentication endpoints
- ☐ **Account Lockout**: Progressive delays and temporary account locks
- ☐ **Audit Logging**: Comprehensive security event logging
- ☐ **Geographic Restrictions**: IP-based access controls and geo-blocking

Contributing
------------

Contributions are welcome! Please feel free to submit a Pull Request.

License
-------

This project is licensed under the MIT License - see the LICENSE file for details.
