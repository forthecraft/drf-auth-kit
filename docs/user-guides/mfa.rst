Multi-Factor Authentication (MFA)
==================================

This guide covers how to set up and use multi-factor authentication with DRF Auth Kit. MFA adds an extra layer of security by requiring users to provide a second form of verification in addition to their password.

Prerequisites
-------------

**API Documentation Setup Required**

Before following this guide, complete the :doc:`api-setup` to configure interactive API documentation (Swagger UI, ReDoc, and DRF Browsable API). This setup is essential for testing the MFA endpoints described below.

Overview
--------

DRF Auth Kit provides a comprehensive MFA system with:

- **Email-based MFA**: Send verification codes via email
- **Authenticator App MFA**: Generate QR codes for apps like Google Authenticator, Authy
- **Passkey MFA**: Passkeys and hardware security keys via WebAuthn
- **Backup Codes**: Recovery codes for account access when primary method unavailable
- **Extensible System**: Add custom MFA methods
- **User Management**: Users can enable/disable and manage multiple MFA methods
- **API Integration**: Full REST API for MFA operations with interactive documentation

The MFA system is inspired by django-trench but simplified and better integrated with DRF Auth Kit's architecture.

Installation
------------

MFA support requires additional dependencies:

.. code-block:: bash

    pip install drf-auth-kit[mfa]

This installs **pyotp** (>=2.9.0) for TOTP (Time-based One-Time Password) generation and validation.

Configuration
-------------

**Enable MFA in Django Settings**

.. code-block:: python

    # settings.py
    INSTALLED_APPS = [
        # ... your existing apps
        'auth_kit',
        'auth_kit.mfa',  # Add MFA support
    ]

    AUTH_KIT = {
        'USE_MFA': True,  # Enable MFA system
    }

**Optional: Passkey MFA**

Passkeys and hardware security keys are available as an MFA method, but are not
enabled by default. Install the extra, add the WebAuthn app, and register the
handler:

.. code-block:: bash

    pip install drf-auth-kit[webauthn]

.. code-block:: python

    INSTALLED_APPS = [
        # ...
        'auth_kit.mfa',
        'auth_kit.webauthn',
    ]

    AUTH_KIT = {
        'USE_MFA': True,
        'MFA_HANDLERS': [
            'auth_kit.mfa.handlers.app.MFAAppHandler',
            'auth_kit.mfa.handlers.email.MFAEmailHandler',
            'auth_kit.mfa.handlers.webauthn.MFAWebAuthnHandler',
        ],
    }

Unlike code-based methods, a passkey answers a server-issued challenge rather
than a dispatched code. Fetch it during the second step with the ephemeral
token from the first:

.. code-block:: bash

    POST /auth/login/challenge/
    {
        "ephemeral_token": "..."
    }

Pass the result to ``navigator.credentials.get()`` and submit the assertion as
the MFA ``code``. Methods that need no challenge return ``{}``, so a client can
call this for whichever method is active. See :doc:`webauthn` for the full
ceremony.

**Run Migrations**

.. code-block:: bash

    python manage.py migrate

This creates the necessary database tables for MFA methods and backup codes.

**Explore MFA Endpoints**

Once enabled, visit your API documentation to see the new MFA endpoints (configured in the Prerequisites section above).


MFA Authentication Flow
-----------------------

When MFA is enabled, the login process becomes a two-step flow:

**Step 1: Username/Password Authentication**


1. User submits username/password to ``POST /api/auth/login/``
2. If credentials are valid and MFA is enabled, response includes:
   - ``ephemeral_token`` - Temporary token for MFA verification
   - ``method`` - Primary MFA method name
   - ``mfa_enabled: true`` - Indicates MFA is required

**Step 2: MFA Code Verification**


1. User receives MFA code (email or generates from app)
2. Submit to ``POST /api/auth/login/verify/`` with:
   - ``ephemeral_token`` - From step 1
   - ``code`` - MFA verification code or backup code
3. Response includes final authentication tokens and user data

**Additional MFA Endpoints**

During the MFA flow, these endpoints are available:

- ``POST /api/auth/login/change-method/`` - Switch between MFA methods
- ``POST /api/auth/login/resend/`` - Resend MFA code (email method)

Setting Up MFA Methods
-----------------------

**MFA Management Endpoints**

Once logged in, users can manage their MFA methods via:

- ``GET /api/auth/mfa/`` - List user's MFA methods
- ``POST /api/auth/mfa/`` - Create new MFA method
- ``POST /api/auth/mfa/confirm/`` - Confirm/activate new MFA method
- ``POST /api/auth/mfa/primary/`` - Set primary MFA method
- ``POST /api/auth/mfa/deactivate/`` - Deactivate MFA method
- ``POST /api/auth/mfa/delete/`` - Delete MFA method
- ``POST /api/auth/mfa/send/`` - Send MFA verification code

**Email MFA Setup**


1. Navigate to ``POST /api/auth/mfa/`` in your API documentation
2. Set ``method`` to ``"email"`` in the request body
3. Response includes setup confirmation and backup codes
4. User receives verification email with TOTP code
5. Use ``POST /api/auth/mfa/confirm/`` with ``method`` and ``code`` to activate

**Authenticator App Setup**


1. Navigate to ``POST /api/auth/mfa/`` in your API documentation
2. Set ``method`` to ``"app"`` in the request body
3. Response includes:
   - ``setup_data.qr_link`` - QR code URI for scanning
   - ``backup_codes`` - Recovery codes array
4. Scan QR code with authenticator app (Google Authenticator, Authy, etc.)
5. Use ``POST /api/auth/mfa/confirm/`` with ``method`` and ``code`` to activate

**Backup Codes**


Backup codes are automatically generated when setting up MFA:

- Use when primary MFA method is unavailable
- Each code can only be used once
- Generate new codes if running low
- Store securely (password manager recommended)

Managing MFA Methods
--------------------

**View Current Methods**


Use ``GET /api/auth/mfa/`` to see:

- ``name`` - MFA method name (e.g., "email", "app")
- ``is_active`` - Whether method is active
- ``is_primary`` - Whether method is the primary method
- ``is_setup`` - Whether method has been configured

**Setting Primary Method**


When multiple MFA methods exist:

1. Use ``POST /api/auth/mfa/primary/``
2. Set ``method`` to the method name (e.g., "email")
3. Include ``primary_code`` if required by settings
4. This method will be used by default during login

**Deactivating Methods**


Temporarily disable a method without deletion:

1. Use ``POST /api/auth/mfa/deactivate/``
2. Set ``method`` to the method name
3. Include ``code`` for verification
4. Method remains configured but won't be used

**Deleting Methods**


Permanently remove an MFA method:

1. Use ``POST /api/auth/mfa/delete/``
2. Set ``method`` to the method name
3. Include ``code`` if required by settings
4. Cannot delete the last active method (configurable)

Testing MFA Flow
----------------

**Using API Documentation**

The interactive API documentation makes testing MFA flows easy:

1. **Setup**: Create MFA methods using ``POST /api/auth/mfa/``
2. **Login**: Test two-step login process
3. **Management**: Try enabling/disabling methods
4. **Recovery**: Test backup code usage

**Common Test Scenarios**


Test these scenarios in your API documentation:

- First-time MFA setup
- Login with different MFA methods
- Switching between methods during login
- Using backup codes
- Managing multiple methods
- Error handling (invalid codes, expired tokens)

Configuration Options
---------------------

**MFA Security Settings**

.. code-block:: python

    AUTH_KIT = {
        'USE_MFA': True,

        # TOTP Configuration
        'MFA_TOTP_DEFAULT_INTERVAL': 30,        # Code validity (seconds)
        'MFA_TOTP_DEFAULT_VALID_WINDOW': 0,     # Clock skew tolerance

        # Backup Codes
        'NUM_OF_BACKUP_CODES': 5,               # Number of backup codes
        'BACKUP_CODE_LENGTH': 12,               # Backup code length
        'BACKUP_CODE_SECURE_HASH': True,        # Secure storage

        # Token Expiry
        'MFA_EPHEMERAL_TOKEN_EXPIRY': 900,      # 15 minutes

        # App Settings
        'MFA_APPLICATION_NAME': 'My App',       # Shown in authenticator apps

        # Security Constraints
        'MFA_PREVENT_DELETE_ACTIVE_METHOD': False,
        'MFA_PREVENT_DELETE_PRIMARY_METHOD': False,
        'MFA_DELETE_ACTIVE_METHOD_REQUIRE_CODE': False,
    }

**Available MFA Handlers**

.. code-block:: python

    AUTH_KIT = {
        'MFA_HANDLERS': [
            'auth_kit.mfa.handlers.app.MFAAppHandler',      # Authenticator apps
            'auth_kit.mfa.handlers.email.MFAEmailHandler',  # Email codes
            # Add custom handlers here
        ],
    }

Frontend Integration
--------------------

**Two-Step Login Flow**

.. code-block:: javascript

    // Step 1: Initial login
    async function login(username, password) {
        const response = await fetch('/api/auth/login/', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });

        const data = await response.json();

        if (data.mfa_enabled) {
            // MFA required - show MFA form
            return { requiresMFA: true, ephemeralToken: data.ephemeral_token };
        } else {
            // No MFA - login complete
            return { requiresMFA: false, user: data.user };
        }
    }

    // Step 2: MFA verification
    async function verifyMFA(ephemeralToken, code) {
        const response = await fetch('/api/auth/login/verify/', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                ephemeral_token: ephemeralToken,
                code: code
            })
        });

        const data = await response.json();
        return data; // Contains final tokens and user data
    }

**MFA Method Management**

.. code-block:: javascript

    // Setup new MFA method
    async function setupMFA(method) {
        const response = await fetch('/api/auth/mfa/', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${accessToken}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ method: method })
        });

        const data = await response.json();

        if (method === 'app') {
            // Show QR code for scanning
            displayQRCode(data.qr_code);
        }

        return data;
    }

Advanced Topics
---------------

**Custom MFA Handlers**

You can create custom MFA methods by extending the base handler class. The MFA system uses a registry-based approach for managing handlers.

**Creating a Custom Handler**

.. code-block:: python

    from auth_kit.mfa.handlers.base import MFABaseHandler, MFAHandlerRegistry

    class SMSMFAHandler(MFABaseHandler):
        # Required: snake_case method identifier
        NAME = "sms"

        # Optional: human-readable display name (auto-generated if not provided)
        DISPLAY_NAME = "SMS Authentication"

        # Optional: whether this method requires code dispatch (default: True)
        REQUIRES_DISPATCH = True

        # Optional: message shown to user during setup
        SETUP_RESPONSE_MESSAGE = "SMS verification code has been sent to your phone."

        # Optional: TOTP timing configuration
        TOTP_INTERVAL = 30  # seconds
        TOTP_VALID_WINDOW = 0  # clock skew tolerance

        def send_code(self):
            """Send verification code to user via SMS."""
            code = self.get_otp_code()
            # Implement SMS sending logic here
            send_sms(self.mfa_method.user.phone_number, f"Your code: {code}")

        def initialize_method(self):
            """Initialize method setup and return setup data."""
            self.send_code()
            return {"detail": self.SETUP_RESPONSE_MESSAGE}

    # Register the handler with the registry
    MFAHandlerRegistry.register(SMSMFAHandler)

**Configure in Django Settings**

Add your custom handler to the ``MFA_HANDLERS`` setting to ensure it's imported and loaded:

.. code-block:: python

    # settings.py
    AUTH_KIT = {
        'USE_MFA': True,
        'MFA_HANDLERS': [
            'auth_kit.mfa.handlers.app.MFAAppHandler',      # Built-in
            'auth_kit.mfa.handlers.email.MFAEmailHandler',  # Built-in
            'myapp.mfa.handlers.SMSMFAHandler',             # Your custom handler
        ],
    }

**Handler Base Class Features**

The ``MFABaseHandler`` base class provides:

- **TOTP Generation**: ``get_otp_code()`` generates time-based codes
- **Code Validation**: ``validate_code()`` validates both TOTP and backup codes
- **Backup Code Support**: ``validate_backup_code()`` handles recovery codes
- **Method Initialization**: ``initialize_method()`` sets up the method
- **Serializer Integration**: ``get_initialize_method_serializer_class()`` for API responses

**Required Handler Attributes**

- ``NAME``: Snake_case method identifier (e.g., "sms", "phone_call")
- Must implement ``send_code()`` if ``REQUIRES_DISPATCH = True``

**Optional Handler Attributes**

- ``DISPLAY_NAME``: Human-readable name (auto-generated from NAME if not provided)
- ``REQUIRES_DISPATCH``: Whether method sends codes (default: True)
- ``SETUP_RESPONSE_MESSAGE``: User feedback during setup
- ``TOTP_INTERVAL``: Code validity period in seconds (default: 30)
- ``TOTP_VALID_WINDOW``: Clock skew tolerance in intervals (default: 0)

**Registering Custom Handlers**

Custom MFA handlers must be registered using **both** methods:

1. **Direct Registration** (in your handler module):

.. code-block:: python

    # At the bottom of your handler module (e.g., myapp/mfa/handlers.py)
    MFAHandlerRegistry.register(SMSMFAHandler)

2. **Settings Configuration** (required for handler discovery):

.. code-block:: python

    # settings.py
    AUTH_KIT = {
        'MFA_HANDLERS': [
            'auth_kit.mfa.handlers.app.MFAAppHandler',      # Built-in
            'auth_kit.mfa.handlers.email.MFAEmailHandler',  # Built-in
            'myapp.mfa.handlers.SMSMFAHandler',             # Custom
            'myapp.mfa.handlers.VoiceCallMFAHandler',       # Custom
        ],
    }

**Why Both Are Required:**

- **Settings Configuration**: Ensures your handler module is imported and loaded by Django
- **Registry Call**: Actually registers the handler class when the module is imported

The system imports handlers from the ``MFA_HANDLERS`` setting, which triggers the ``MFAHandlerRegistry.register()`` call in your handler module.

**Advanced Handler Customization**

For more complex handlers, you can override additional methods:

.. code-block:: python

    from rest_framework import serializers
    from auth_kit.mfa.handlers.base import MFABaseHandler

    class CustomSetupSerializer(serializers.Serializer):
        qr_code = serializers.CharField(read_only=True)
        phone_number = serializers.CharField(read_only=True)

    class AdvancedSMSHandler(MFABaseHandler):
        NAME = "advanced_sms"

        def initialize_method(self):
            """Custom initialization with additional setup data."""
            self.send_code()
            return {
                "detail": "SMS sent successfully",
                "phone_number": self.mfa_method.user.phone_number,
                "expires_in": self.TOTP_INTERVAL
            }

        @classmethod
        def get_initialize_method_serializer_class(cls):
            """Return custom serializer for setup responses."""
            return CustomSetupSerializer

        def validate_code(self, code):
            """Custom validation with additional checks."""
            # Add custom validation logic
            if not self.is_valid_phone_number():
                return False
            return super().validate_code(code)

**Handler Registry API**

The ``MFAHandlerRegistry`` provides methods for managing handlers:

.. code-block:: python

    from auth_kit.mfa.handlers.base import MFAHandlerRegistry

    # Get all registered handler names
    handler_names = MFAHandlerRegistry.list_handler_names()

    # Get handler class by name
    handler_class = MFAHandlerRegistry.get_handler_class("sms")

    # Get handler instance for an MFA method
    handler = MFAHandlerRegistry.get_handler(mfa_method_instance)

    # Get all handlers dictionary
    all_handlers = MFAHandlerRegistry.get_handlers()

**Testing Custom Handlers**

Test your custom handlers thoroughly:

.. code-block:: python

    from django.test import TestCase
    from auth_kit.mfa.models import MFAMethod
    from myapp.mfa.handlers import SMSMFAHandler

    class SMSHandlerTest(TestCase):
        def setUp(self):
            self.user = User.objects.create_user(username='test', phone_number='+1234567890')
            self.mfa_method = MFAMethod.objects.create(user=self.user, name='sms')
            self.handler = SMSMFAHandler(self.mfa_method)

        def test_code_generation(self):
            code = self.handler.get_otp_code()
            self.assertEqual(len(code), 6)  # Default TOTP length

        def test_code_validation(self):
            code = self.handler.get_otp_code()
            self.assertTrue(self.handler.validate_code(code))

        def test_send_code(self):
            # Mock SMS sending and test
            with patch('myapp.sms.send_sms') as mock_send:
                self.handler.send_code()
                mock_send.assert_called_once()

**Error Handling**

Common MFA error responses include:

- Invalid or expired ephemeral tokens
- Incorrect MFA codes
- Method setup failures
- Rate limiting errors

**Security Considerations**

- Use HTTPS in production for token security
- Set appropriate ephemeral token expiry times
- Educate users about backup code security
- Consider rate limiting for MFA attempts
- Monitor for suspicious MFA activity

Next Steps
----------

Now that you understand MFA implementation:

- **Test the Flow**: Use ``/api/docs/`` to test the complete MFA authentication flow
- **Customize Settings**: Adjust MFA configuration for your security requirements
- **User Education**: Help users understand MFA setup and backup codes
- **Monitor Usage**: Track MFA adoption and usage patterns
- **Social Authentication**: :doc:`social-authentication` - Combine with social login
- **Customization**: :doc:`customization` - Create custom MFA handlers
- **Future Features**: :doc:`../upcoming` - See planned MFA enhancements
