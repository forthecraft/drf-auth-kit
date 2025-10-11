Basic Usage
===========

This guide covers the basic authentication features of DRF Auth Kit, including user registration, login, logout, and profile management.

Prerequisites
-------------

**API Documentation Setup Required**

Before following this guide, complete the :doc:`api-setup` to configure interactive API documentation (Swagger UI, ReDoc, and DRF Browsable API). This setup is essential for testing the endpoints described below.

Authentication Flow Overview
----------------------------

DRF Auth Kit provides these core authentication endpoints:

**User Management**

- ``POST /api/auth/registration/`` - Create new user account
- ``POST /api/auth/registration/verify-email/`` - Verify email address
- ``POST /api/auth/registration/resend-email/`` - Resend verification email

**Authentication**

- ``POST /api/auth/login/`` - User login
- ``POST /api/auth/logout/`` - User logout
- ``POST /api/auth/token/refresh/`` - Refresh JWT tokens (JWT only)
- ``POST /api/auth/token/verify/`` - Verify JWT tokens (JWT only)

**User Profile**

- ``GET /api/auth/user/`` - Get current user profile
- ``PUT /api/auth/user/`` - Update user profile
- ``PATCH /api/auth/user/`` - Partial update user profile

**Password Management**

- ``POST /api/auth/password/change/`` - Change password (authenticated)
- ``POST /api/auth/password/reset/`` - Request password reset
- ``POST /api/auth/password/reset/confirm/`` - Confirm password reset

User Registration
-----------------

**Basic Registration**

Navigate to ``POST /api/auth/registration/`` in your API documentation or browsable API.


**Required Fields:**

- ``username`` - Unique username
- ``email`` - Email address
- ``password1`` - Password
- ``password2`` - Password confirmation

**Optional Fields:**

- ``first_name`` - User's first name
- ``last_name`` - User's last name

**Response:**
The API returns user details and confirmation that a verification email was sent (if email verification is enabled).


**Email Verification**

If ``ACCOUNT_EMAIL_VERIFICATION = "mandatory"`` in your settings:

1. User receives verification email
2. Use ``POST /api/auth/registration/verify-email/`` with the verification key
3. User can now log in

To resend verification emails, use ``POST /api/auth/registration/resend-email/``.

**Frontend URL Configuration**

By default, email verification links point to the API backend. For frontend applications, configure ``FRONTEND_BASE_URL`` and ``REGISTER_EMAIL_CONFIRM_PATH`` to redirect users to your frontend verification page. See :doc:`../configuration` for details.

User Login
----------

**Login Endpoint**

Use ``POST /api/auth/login/`` to authenticate users.


**Authentication Methods:**

- Username + password
- Email + password (if configured)

**Response Types:**


*JWT Authentication (default):*

- ``access_token`` - Short-lived access token
- ``refresh_token`` - Long-lived refresh token
- ``user`` - User profile data

*Token Authentication:*

- ``key`` - Authentication token
- ``user`` - User profile data

**Cookie vs Header Authentication**

DRF Auth Kit supports both authentication methods:

**Cookie Authentication (default):**

- Tokens stored in HTTP-only cookies
- Automatic handling by the browser
- CSRF protection included
- No manual token management needed

**Header Authentication:**

- Include token in ``Authorization`` header
- Format: ``Bearer <access_token>`` (JWT) or ``Token <token>`` (DRF Token)
- Manual token management required

Making Authenticated Requests
-----------------------------

**Using API Documentation**

When testing in the API documentation:

1. First login via ``POST /api/auth/login/``
2. Copy the access token from the response
3. Click "Authorize" in Swagger UI or use the token in subsequent requests
4. Test protected endpoints like ``GET /api/auth/user/``


**Understanding Authentication States**

*Unauthenticated Requests:*

- Return 401 Unauthorized for protected endpoints
- Public endpoints (registration, login, password reset) work normally

*Authenticated Requests:*

- Include valid tokens automatically (cookies) or manually (headers)
- Access to protected endpoints like user profile, logout
- Token refresh is available for both cookies and headers

User Profile Management
-----------------------

**Get Profile**

``GET /api/auth/user/`` returns the current user's profile information.


**Update Profile**

- ``PUT /api/auth/user/`` - Complete profile update (all fields required)
- ``PATCH /api/auth/user/`` - Partial update (only changed fields)


**Updatable Fields:**

- ``first_name``
- ``last_name``
- ``email`` (may require re-verification depending on settings)

Password Management
-------------------

**Change Password (Authenticated Users)**

Use ``POST /api/auth/password/change/`` when user is logged in.

**Required Fields:**

- ``old_password`` - Current password (if ``OLD_PASSWORD_FIELD_ENABLED = True``)
- ``new_password1`` - New password
- ``new_password2`` - New password confirmation

**Password Reset (Unauthenticated)**

For users who forgot their password:

1. ``POST /api/auth/password/reset/`` with user's email
2. User receives reset email with token
3. ``POST /api/auth/password/reset/confirm/`` with reset token and new password

**Frontend URL Configuration**

By default, password reset links point to the API backend. For frontend applications, configure ``FRONTEND_BASE_URL`` and ``PASSWORD_RESET_CONFIRM_PATH`` to redirect users to your frontend password reset page. See :doc:`../configuration` for details.

Token Management (JWT Only)
---------------------------

**Token Refresh**

To refresh expired access tokens, call ``POST /api/auth/token/refresh/`` to get a new access token. The refresh token can be provided via:

- **Cookie Authentication**: Refresh token is automatically read from the cookie
- **Header Authentication**: Include refresh token in the request body

Note: Token refresh requires an explicit API call and does not happen automatically.

**Token Verification**

``POST /api/auth/token/verify/`` checks if a token is valid and not expired.

User Logout
-----------

**Logout Process**

``POST /api/auth/logout/`` invalidates the user's session:

- Clears authentication cookies (cookie auth)
- Invalidates tokens on the server
- User must login again to access protected endpoints

Error Handling
--------------

**Common Response Patterns**

All endpoints return standard HTTP status codes and JSON error responses. View these in your API documentation to understand:

- Field validation errors (400 Bad Request)
- Authentication errors (401 Unauthorized)
- Permission errors (403 Forbidden)
- Not found errors (404 Not Found)

**Testing Error Scenarios**

Use your API documentation to test error conditions:

- Missing required fields
- Invalid credentials
- Expired tokens
- Unauthorized access attempts

UI Testing View (Development)
------------------------------

For development and testing, DRF Auth Kit provides a comprehensive UI view for testing all authentication features:

**Accessing the UI:**

.. code-block:: python

    # urls.py (Development only)
    from auth_kit.views import AuthKitUIView
    from django.conf import settings

    if settings.DEBUG:
        urlpatterns += [
            path('api/auth/ui/', AuthKitUIView.as_view(), name='auth_kit_ui'),
        ]

Visit ``/api/auth/ui/`` to access the testing interface which includes:

- Registration and login forms
- User profile management
- Password change and reset
- Social authentication (if configured)
- MFA enrollment (if enabled)
- Real-time API response viewer

**Important:** This UI view is designed for development and testing only. Use the ``DEBUG`` conditional to ensure it's not exposed in production.

Frontend Integration
--------------------

**Email Links Configuration**

For frontend applications, configure email verification and password reset links to redirect to your frontend pages instead of the API backend:

.. code-block:: python

    AUTH_KIT = {
        'FRONTEND_BASE_URL': 'https://myapp.com',
        'REGISTER_EMAIL_CONFIRM_PATH': '/auth/verify-email',
        'PASSWORD_RESET_CONFIRM_PATH': '/auth/reset-password',
    }

See :doc:`../configuration` for complete frontend URL configuration options.

**Cookie Authentication (Recommended)**

With cookie authentication enabled (``USE_AUTH_COOKIE: True``):

.. code-block:: javascript

    // Simple fetch example - cookies handled automatically
    async function getUserProfile() {
        const response = await fetch('/api/auth/user/', {
            credentials: 'include',  // Include cookies
            headers: {
                'Content-Type': 'application/json',
            }
        });

        if (response.ok) {
            return await response.json();
        }
        throw new Error('Failed to get profile');
    }

**Header Authentication**

For header-based authentication:

.. code-block:: javascript

    // Store token from login response
    const token = 'your-access-token';

    async function getUserProfile() {
        const response = await fetch('/api/auth/user/', {
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json',
            }
        });

        if (response.ok) {
            return await response.json();
        }
        throw new Error('Failed to get profile');
    }

**CSRF Protection**

When using cookie authentication, include CSRF tokens for state-changing requests:

.. code-block:: javascript

    // Get CSRF token from cookie or meta tag
    function getCSRFToken() {
        return document.querySelector('[name=csrfmiddlewaretoken]')?.value ||
               getCookie('csrftoken');
    }

    // Include in POST requests
    const response = await fetch('/api/auth/logout/', {
        method: 'POST',
        credentials: 'include',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': getCSRFToken(),
        }
    });

Next Steps
----------

Now that you understand the basic authentication flow:

- **Explore the API**: Use ``/api/docs/`` to test all endpoints interactively
- **Social Authentication**: :doc:`social-authentication` - Add social login providers
- **Multi-Factor Authentication**: :doc:`mfa` - Enable additional security
- **Customization**: :doc:`customization` - Customize behavior for your needs

**Development Tips**

- Use the browsable API during development for quick testing
- Set up API documentation early for better team collaboration
- Test both success and error scenarios using the interactive documentation
- Consider your authentication method (cookies vs headers) based on your frontend architecture
