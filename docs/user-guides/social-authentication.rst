Social Authentication
=====================

This guide covers how to set up and use social authentication with DRF Auth Kit. Social authentication allows users to log in using their accounts from providers like Google, Facebook, GitHub, and many others.

Prerequisites
-------------

**API Documentation Setup Required**

Before following this guide, complete the :doc:`api-setup` to configure interactive API documentation (Swagger UI, ReDoc, and DRF Browsable API). This setup is essential for testing the social authentication endpoints described below.

Overview
--------

DRF Auth Kit integrates with Django Allauth to provide comprehensive social authentication support. This integration provides:

- **Multiple Providers**: Support for 50+ social authentication providers
- **Protocol Support**: Both OAuth2 and OpenID Connect protocols
- **Automatic URL Generation**: URLs and views are automatically created for any installed social provider
- **Account Management**: Connect/disconnect social accounts to existing users
- **Unified API**: Consistent authentication flow for all providers
- **Interactive Documentation**: All endpoints automatically documented in your API schema
- **Template Support**: Optional HTML templates for browser-based flows
- **Secure by Default**: Uses Authorization Code Flow for maximum security and compatibility

**Key Advantage**: When you include ``auth_kit.social.urls``, the system automatically generates authentication endpoints for any installed Django Allauth social provider configured in your settings or database.

Installation
------------

Social authentication requires additional dependencies:

.. code-block:: bash

    pip install drf-auth-kit[social]

This installs **django-allauth[socialaccount]** (>=65.5.0) which includes support for 50+ social authentication providers.

Basic Configuration
-------------------

**Django Settings**

.. code-block:: python

    # settings.py
    INSTALLED_APPS = [
        # Core Django and DRF
        'django.contrib.admin',
        'django.contrib.auth',
        'django.contrib.contenttypes',
        'django.contrib.sessions',
        'django.contrib.messages',
        'rest_framework',

        # Allauth (required)
        'allauth',
        'allauth.account',
        'allauth.socialaccount',

        # Social Providers (add as needed)
        'allauth.socialaccount.providers.google',
        # Add other providers as needed - see Django Allauth documentation

        # DRF Auth Kit
        'auth_kit',
        'auth_kit.social',  # Social authentication integration
    ]

**Include Social URLs**

.. code-block:: python

    # urls.py
    urlpatterns = [
        path('api/auth/', include('auth_kit.urls')),
        path('api/auth/social/', include('auth_kit.social.urls')),  # Auto-generates provider endpoints
    ]

**Explore Social Endpoints**

Once configured, visit your API documentation to see the automatically generated social authentication endpoints (configured in the Prerequisites section above).

The system automatically creates endpoints for each configured provider. For example, with Google configured:

**Social Login Endpoints:**

- ``POST /api/auth/social/google/`` - Google login

**Social Connect Endpoints:**

- ``POST /api/auth/social/google/connect/`` - Connect Google account

**Account Management:**

- ``GET /api/auth/social/accounts/`` - List connected social accounts
- ``DELETE /api/auth/social/accounts/{id}/`` - Disconnect social account

**Note**: Similar endpoints are automatically created for each provider you configure (Facebook, GitHub, LinkedIn, etc.).

Google OAuth Setup
------------------

**Provider Configuration**

.. code-block:: python

    # settings.py
    SOCIALACCOUNT_PROVIDERS = {
        'google': {
            'SCOPE': ['profile', 'email'],
            'AUTH_PARAMS': {'access_type': 'online'},
            'OAUTH_PKCE_ENABLED': True,
            'FETCH_USERINFO': True,
            'APP': {
                'client_id': 'your-google-client-id',
                'secret': 'your-google-client-secret',
                'key': '',
            }
        },
    }

**Getting Google OAuth Credentials**

1. Go to `Google Cloud Console <https://console.cloud.google.com/>`_
2. Create a new project or select existing one
3. Enable Google+ API
4. Create OAuth 2.0 credentials
5. Add authorized redirect URIs for your domain

**Test Google Login**


Navigate to ``POST /api/auth/social/google/`` in your API documentation to test the integration.

Social Authentication Flow
--------------------------

DRF Auth Kit supports OAuth2 and OpenID Connect protocols with multiple flow types. However, **Authorization Code Flow is strongly recommended** and used by default for maximum compatibility and security.

**Authorization Code Flow (Recommended - Default)**


1. Frontend redirects user to Google OAuth URL
2. User authorizes your application
3. Google redirects back with authorization code
4. Frontend sends code to ``POST /api/auth/social/google/``
5. Backend exchanges code for tokens and returns user data

**Access Token Flow (Not Recommended)**


**Note**: This flow is provided for compatibility but is **not recommended** for most use cases due to:

- Limited provider support
- Security considerations with token handling in frontend
- Reduced functionality compared to authorization code flow

1. Frontend obtains access token directly from provider
2. Frontend sends token to ``POST /api/auth/social/google/``
3. Backend validates token and returns user data

**Flow Configuration (Keep Default)**

Authorization Code Flow is used by default. Only change this if you have specific requirements:

.. code-block:: python

    AUTH_KIT = {
        'SOCIAL_LOGIN_AUTH_TYPE': 'code',  # Default: 'code' (recommended)
        # 'SOCIAL_LOGIN_AUTH_TYPE': 'token',  # Not recommended for most cases
    }

Social Account Management
-------------------------

**Connect Social Account**


For logged-in users to connect additional social accounts:

1. User must be authenticated
2. Use the appropriate connect endpoint (e.g., ``POST /api/auth/social/google/connect/``)
3. Provide authorization code or access token
4. Account gets linked to current user

**List Connected Accounts**


Use ``GET /api/auth/social/accounts/`` to see all social accounts connected to the current user.

**Disconnect Social Account**


Remove social account connections using ``DELETE /api/auth/social/accounts/{id}/``.

Adding More Providers
----------------------

**Other Social Providers**

DRF Auth Kit supports any provider that Django Allauth supports (50+ providers) with both **OAuth2** and **OpenID Connect** protocols. To add other providers:

1. **Install Provider Package**: Add the provider app to ``INSTALLED_APPS``
2. **Configure Provider Settings**: Add provider configuration to ``SOCIALACCOUNT_PROVIDERS``
3. **Endpoints Auto-Generated**: DRF Auth Kit automatically creates endpoints for each configured provider

**Protocol Support:**

- **OAuth2**: Google, Facebook, GitHub, Twitter, and most traditional providers
- **OpenID Connect**: LinkedIn, Microsoft Azure AD, and other OIDC-compliant providers
- **Automatic Detection**: DRF Auth Kit handles both protocols transparently

**Example with GitHub:**

.. code-block:: python

    # settings.py
    INSTALLED_APPS = [
        # ... existing apps
        'allauth.socialaccount.providers.google',
        'allauth.socialaccount.providers.github',  # Add GitHub
    ]

    SOCIALACCOUNT_PROVIDERS = {
        'google': {
            # ... Google configuration (shown above)
        },
        'github': {
            'SCOPE': ['user:email'],
            'VERIFIED_EMAIL': True,
        },
    }

This automatically creates:

- ``POST /api/auth/social/github/`` - GitHub login
- ``POST /api/auth/social/github/connect/`` - Connect GitHub account

**Provider-Specific Setup**

For detailed setup instructions for specific providers, see the `Django Allauth Provider Documentation <https://docs.allauth.org/en/latest/socialaccount/providers/index.html>`_:

- `Facebook <https://docs.allauth.org/en/latest/socialaccount/providers/facebook.html>`_
- `GitHub <https://docs.allauth.org/en/latest/socialaccount/providers/github.html>`_
- `LinkedIn <https://docs.allauth.org/en/latest/socialaccount/providers/linkedin.html>`_
- `Twitter <https://docs.allauth.org/en/latest/socialaccount/providers/twitter.html>`_
- `And 50+ more providers <https://docs.allauth.org/en/latest/socialaccount/providers/index.html>`_

Testing Social Authentication
-----------------------------

**Using API Documentation**

1. **Setup Provider**: Configure OAuth app with provider
2. **Test Login Flow**: Use API documentation to test social login
3. **Test Account Management**: Try connecting/disconnecting accounts
4. **Error Scenarios**: Test with invalid tokens/codes

**Common Test Scenarios**

Test these flows in your API documentation:

- New user social registration
- Existing user social login
- Connecting social account to existing user
- Multiple social accounts per user
- Disconnecting social accounts
- Error handling (invalid tokens, provider errors)

Configuration Options
---------------------

**Social Authentication Settings**

.. code-block:: python

    AUTH_KIT = {
        # OAuth Flow Type
        'SOCIAL_LOGIN_AUTH_TYPE': 'code',              # 'code' or 'token'

        # Account Linking
        'SOCIAL_LOGIN_AUTO_CONNECT_BY_EMAIL': True,    # Auto-link by email
        'SOCIAL_CONNECT_REQUIRE_EMAIL_MATCH': True,    # Require email match for linking

        # Callback URLs
        'SOCIAL_LOGIN_CALLBACK_BASE_URL': '',          # Custom callback URL base
        'SOCIAL_CONNECT_CALLBACK_BASE_URL': '',        # Custom connect callback base

        # Security
        'SOCIAL_HIDE_AUTH_ERROR_DETAILS': True,        # Hide detailed error messages
    }

**Django Allauth Settings**

.. code-block:: python

    # Account linking behavior
    SOCIALACCOUNT_EMAIL_AUTHENTICATION = True
    SOCIALACCOUNT_EMAIL_AUTHENTICATION_AUTO_CONNECT = True
    SOCIALACCOUNT_AUTO_SIGNUP = True
    SOCIALACCOUNT_QUERY_EMAIL = True

Frontend Integration
--------------------

**Authorization Code Flow (Recommended)**

.. code-block:: javascript

    // Step 1: Redirect user to provider OAuth URL
    function redirectToGoogle() {
        const clientId = 'your-google-client-id';
        const redirectUri = 'http://localhost:3000/auth/callback';
        const scope = 'profile email';

        const authUrl = `https://accounts.google.com/oauth/authorize?` +
            `client_id=${clientId}&` +
            `redirect_uri=${redirectUri}&` +
            `scope=${scope}&` +
            `response_type=code&` +
            `access_type=online`;

        window.location.href = authUrl;
    }

    // Step 2: Handle callback and exchange code for tokens
    async function handleGoogleCallback(code) {
        const response = await fetch('/api/auth/social/google/', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ code: code })
        });

        const data = await response.json();

        if (response.ok) {
            // Login successful - store tokens if needed
            console.log('Social login successful:', data);
            return data;
        } else {
            throw new Error('Social login failed');
        }
    }

**Access Token Flow (Not Recommended - For Compatibility Only)**

.. code-block:: javascript

    // Note: This approach is not recommended for most applications
    // Use Authorization Code Flow instead for better security and compatibility

    // Using Google's JavaScript SDK (legacy approach)
    async function loginWithGoogleToken() {
        // Get token from Google SDK
        const authInstance = gapi.auth2.getAuthInstance();
        const googleUser = await authInstance.signIn();
        const accessToken = googleUser.getAuthResponse().access_token;

        // Send to DRF Auth Kit
        const response = await fetch('/api/auth/social/google/', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ access_token: accessToken })
        });

        return await response.json();
    }

**Connect Social Account**

.. code-block:: javascript

    // Connect social account to existing user
    async function connectGoogleAccount(authCode) {
        const response = await fetch('/api/auth/social/google/connect/', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${userAccessToken}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ code: authCode })
        });

        return await response.json();
    }

Advanced Topics
---------------

**Custom Social Views**

Override social authentication components:

.. code-block:: python

    AUTH_KIT = {
        'SOCIAL_LOGIN_VIEW': 'myapp.views.CustomSocialLoginView',
        'SOCIAL_CONNECT_VIEW': 'myapp.views.CustomSocialConnectView',
        'SOCIAL_ACCOUNT_VIEW_SET': 'myapp.viewsets.CustomSocialAccountViewSet',
    }

**Custom Provider Configuration**

For providers not included in django-allauth, or custom OAuth2 providers:

.. code-block:: python

    SOCIALACCOUNT_PROVIDERS = {
        'openid_connect': {
            'APPS': [
                {
                    'provider_id': 'your_custom_provider',
                    'name': 'Your Custom Provider',
                    'client_id': 'your-client-id',
                    'secret': 'your-client-secret',
                    'settings': {
                        'server_url': 'https://your-provider.com/oauth',
                    },
                }
            ]
        }
    }

**Error Handling**


Common error scenarios:

- Invalid authorization codes
- Expired access tokens
- Provider configuration errors
- Email linking conflicts
- Rate limiting

**Security Considerations**

- Always use HTTPS in production
- Validate redirect URIs properly
- Store client secrets securely
- Monitor for suspicious social login activity
- Consider rate limiting social authentication attempts

Next Steps
----------

Now that you understand social authentication:

- **Test Integration**: Use ``/api/docs/`` to test social authentication flows
- **Configure Providers**: Set up OAuth apps with your chosen social providers
- **Frontend Integration**: Implement social login in your frontend application
- **Account Management**: Build user interfaces for connecting/disconnecting social accounts
- **Multi-Factor Authentication**: :doc:`mfa` - Combine social auth with MFA for enhanced security
- **Customization**: :doc:`customization` - Customize social authentication behavior
- **Future Features**: :doc:`../upcoming` - See planned social authentication enhancements

**Provider Documentation**

For provider-specific OAuth setup and configuration:

- **Google**: `OAuth2 Setup Guide <https://developers.google.com/identity/protocols/oauth2>`_
- **All Other Providers**: `Django Allauth Provider Documentation <https://docs.allauth.org/en/latest/socialaccount/providers/index.html>`_

Each provider has detailed setup instructions including OAuth app creation, configuration parameters, and specific requirements.
