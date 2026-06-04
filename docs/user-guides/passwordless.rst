Passwordless Authentication
===========================

This guide covers passwordless login with DRF Auth Kit. Passwordless lets users
sign in without typing a password, using an email magic link or a passkey.

Prerequisites
-------------

**API Documentation Setup Required**

Before following this guide, complete the :doc:`api-setup` to configure
interactive API documentation (Swagger UI, ReDoc, and DRF Browsable API). This
setup is essential for testing the endpoints described below.

Overview
--------

DRF Auth Kit provides passwordless login through pluggable handlers:

- **Email Magic Link**: A one-time login link sent to the user's inbox
- **Passkey / WebAuthn**: Login with a platform passkey or a hardware key
- **Optional Signup**: Create the account on first magic link use
- **MFA Aware**: Single-factor methods still trigger MFA when it is enabled
- **Extensible System**: Add custom methods by registering a handler

Every handler exposes the same two-step shape:

.. code-block:: text

    POST /auth/passwordless/{method}/initiate/   -> send a link, or return a challenge
    POST /auth/passwordless/{method}/verify/     -> exchange the proof for tokens

Installation
------------

Email magic links need no extra dependency. Passkey login requires the
WebAuthn extra:

.. code-block:: bash

    pip install drf-auth-kit[webauthn]

Configuration
-------------

Enable passwordless and choose the handlers you want:

.. code-block:: python

    AUTH_KIT = {
        'USE_PASSWORDLESS': True,
        'PASSWORDLESS_HANDLERS': [
            'auth_kit.passwordless.handlers.email_link.EmailLinkHandler',
            # 'auth_kit.passwordless.handlers.webauthn.WebAuthnHandler',
        ],
        # Where the emailed link should point. The token is appended as ?token=
        'PASSWORDLESS_MAGIC_LINK_URL': 'https://example.com/auth/magic-link',
    }

Each registered handler gets its own endpoint pair, so enabling only the email
handler exposes only the email endpoints.

.. note::

    Passwordless keeps short-lived state in Django's cache. Configure a shared
    cache in production, see :doc:`../configuration`.

Email Magic Link Flow
---------------------

**Step 1: Request a link**

.. code-block:: bash

    POST /auth/passwordless/email/initiate/
    {
        "email": "user@example.com"
    }

.. code-block:: json

    {
        "detail": "A login link has been sent."
    }

The response is identical whether or not the address has an account, so it
cannot be used to discover which addresses are registered.

**Step 2: Verify the token**

The emailed link carries a token. Send it back to complete login:

.. code-block:: bash

    POST /auth/passwordless/email/verify/
    {
        "token": "1-tjgkry-72ed2dc9f768..."
    }

.. code-block:: json

    {
        "access": "eyJhbGciOiJIUzI1NiIs...",
        "refresh": "eyJhbGciOiJIUzI1NiIs...",
        "user": {"pk": 1, "email": "user@example.com", "username": "user"}
    }

Clicking the link proves the user controls the address, so their email is
marked verified at the same time.

Tokens are single use and expire after
``PASSWORDLESS_EPHEMERAL_TOKEN_EXPIRY`` seconds (15 minutes by default).

Signup on First Use
-------------------

By default an unknown address gets no email and no account. Set
``PASSWORDLESS_EMAIL_SIGNUP`` to also register new users:

.. code-block:: python

    AUTH_KIT = {
        'USE_PASSWORDLESS': True,
        'PASSWORDLESS_EMAIL_SIGNUP': True,
    }

The account is created only when the link is clicked, not when it is
requested, so hitting the initiate endpoint can never create user rows for
addresses that never confirm. The new account is created with an unusable
password and a verified email address.

Passkey Flow
------------

Register the WebAuthn handler to enable passkey login:

.. code-block:: python

    AUTH_KIT = {
        'USE_PASSWORDLESS': True,
        'PASSWORDLESS_HANDLERS': [
            'auth_kit.passwordless.handlers.webauthn.WebAuthnHandler',
        ],
    }

**Step 1: Get a challenge**

.. code-block:: bash

    POST /auth/passwordless/webauthn/initiate/
    {}

.. code-block:: json

    {
        "challenge": "Y2hhbGxlbmdl...",
        "rpId": "localhost",
        "timeout": 60000,
        "userVerification": "preferred",
        "allowCredentials": [],
        "session_id": "9Xa1..."
    }

Send an ``email`` to restrict the response to that user's credentials, which
suits hardware keys. Omit it for the discoverable credential flow, where the
browser offers whichever passkeys it holds for the site.

**Step 2: Verify the assertion**

Pass the options to ``navigator.credentials.get()``, then post the result back
along with the ``session_id`` from step 1:

.. code-block:: bash

    POST /auth/passwordless/webauthn/verify/
    {
        "credential": { "id": "...", "rawId": "...", "response": {...} },
        "session_id": "9Xa1..."
    }

See :doc:`webauthn` for credential management and browser integration.

MFA Interaction
---------------

A handler declares whether it already provides multi-factor assurance:

- **Email magic link** proves inbox access only, so when ``USE_MFA`` is enabled
  the verify step returns an MFA challenge instead of tokens
- **Passkey** combines possession with a local user check, so it completes
  login directly even when MFA is enabled

Custom Handlers
---------------

Subclass :class:`~auth_kit.passwordless.handlers.base.PasswordlessBaseHandler`
and register it:

.. code-block:: python

    from typing import Any

    from rest_framework import serializers
    from rest_framework.serializers import Serializer

    from auth_kit.passwordless.handlers.base import PasswordlessBaseHandler


    class SMSInitiateSerializer(serializers.Serializer):
        phone = serializers.CharField(write_only=True)
        detail = serializers.CharField(read_only=True)


    class SMSHandler(PasswordlessBaseHandler):
        NAME = "sms"
        DISPLAY_NAME = "SMS Code"
        IS_MULTI_FACTOR = False

        @classmethod
        def get_initiate_serializer_class(cls) -> type[Serializer[Any]]:
            return SMSInitiateSerializer

        @classmethod
        def get_verify_serializer_class(cls) -> type[Serializer[Any]]:
            return SMSVerifySerializer

        @classmethod
        def handle_initiate(cls, validated_data, context):
            send_code(validated_data["phone"])
            return {"detail": "Code sent."}

Then add it to ``PASSWORDLESS_HANDLERS``. The endpoints
``/auth/passwordless/sms/initiate/`` and ``/verify/`` are generated for you.

A single serializer covers both directions of a step: write-only fields are the
accepted input, read-only fields are the returned payload. DRF Spectacular
splits them into separate request and response schemas automatically.

Security Notes
--------------

- Magic link tokens are single use and time limited
- The initiate response never reveals whether an account exists
- Deactivated users are rejected at the verify step, matching password login
- Signup never creates an account until the link is clicked

Next Steps
----------

- :doc:`webauthn` for passkey registration and management
- :doc:`mfa` for combining passwordless with multi-factor authentication
- :doc:`../configuration` for the full settings reference
