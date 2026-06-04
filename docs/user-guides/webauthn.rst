WebAuthn and Passkeys
=====================

This guide covers WebAuthn in DRF Auth Kit. WebAuthn backs both passkey login
and the passkey MFA method, and it lets users manage their registered
credentials.

Prerequisites
-------------

**API Documentation Setup Required**

Before following this guide, complete the :doc:`api-setup` to configure
interactive API documentation (Swagger UI, ReDoc, and DRF Browsable API).

Overview
--------

WebAuthn replaces passwords with a key pair held by the user's device. The
private key never leaves the authenticator, which makes it resistant to
phishing and credential stuffing.

DRF Auth Kit uses it in two places:

- **Passwordless login**: sign in with a passkey instead of a password, see
  :doc:`passwordless`
- **Multi-factor**: use a passkey or hardware key as a second factor, see
  :doc:`mfa`

Both share one credential store, so a passkey registered once works for either.

Installation
------------

.. code-block:: bash

    pip install drf-auth-kit[webauthn]

This installs **webauthn** (>=2.0.0) for ceremony generation and verification.

Configuration
-------------

Add the app, run migrations, and point the relying party settings at your site:

.. code-block:: python

    INSTALLED_APPS = [
        # ...
        'auth_kit',
        'auth_kit.webauthn',
    ]

    AUTH_KIT = {
        'WEBAUTHN_RP_ID': 'example.com',            # Domain, no scheme or port
        'WEBAUTHN_RP_NAME': 'Example App',          # Shown in the browser prompt
        'WEBAUTHN_ORIGIN': 'https://example.com',   # str or list of origins
    }

.. code-block:: bash

    python manage.py migrate

Include the credential management URLs:

.. code-block:: python

    urlpatterns = [
        path('api/auth/', include('auth_kit.urls')),
        path('api/auth/webauthn/', include('auth_kit.webauthn.urls')),
    ]

.. warning::

    ``WEBAUTHN_RP_ID`` must match the domain serving the page, and
    ``WEBAUTHN_ORIGIN`` must match its full origin. A mismatch makes every
    ceremony fail verification. WebAuthn also requires HTTPS everywhere except
    ``localhost``.

.. note::

    Ceremony challenges are held in Django's cache. Configure a shared cache in
    production, see :doc:`../configuration`.

Registering a Credential
------------------------

**Step 1: Get registration options**

.. code-block:: bash

    POST /auth/webauthn/credentials/register_options/

.. code-block:: json

    {
        "rp": {"id": "example.com", "name": "Example App"},
        "user": {"id": "MQ", "name": "user", "displayName": "user"},
        "challenge": "Y2hhbGxlbmdl...",
        "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
        "excludeCredentials": [],
        "authenticatorSelection": {"residentKey": "preferred"}
    }

``excludeCredentials`` lists what the user already registered, so the browser
can stop them enrolling the same authenticator twice.

**Step 2: Create and submit the credential**

.. code-block:: javascript

    const credential = await navigator.credentials.create({
        publicKey: {
            ...options,
            challenge: base64urlToBuffer(options.challenge),
            user: {...options.user, id: base64urlToBuffer(options.user.id)},
        },
    });

.. code-block:: bash

    POST /auth/webauthn/credentials/
    {
        "credential": { "id": "...", "rawId": "...", "response": {...} },
        "name": "My Laptop"
    }

Omit ``name`` and one is derived from the authenticator, for example
"iCloud Keychain", "Windows Hello", or "USB Security Key".

Managing Credentials
--------------------

.. code-block:: text

    GET    /auth/webauthn/credentials/            List the user's credentials
    POST   /auth/webauthn/credentials/            Register a new credential
    PATCH  /auth/webauthn/credentials/{id}/rename/  Rename a credential
    DELETE /auth/webauthn/credentials/{id}/       Delete a credential

.. code-block:: json

    [
        {
            "id": 1,
            "name": "My Laptop",
            "discoverable": true,
            "transports": ["internal"],
            "aaguid": "fbfc3007-154e-4ecc-8c0b-6e020557d7bd",
            "created_at": "2025-01-01T12:00:00Z",
            "last_used_at": "2025-01-02T09:30:00Z"
        }
    ]

All endpoints are scoped to the authenticated user.

Using WebAuthn for MFA
----------------------

Register the MFA handler:

.. code-block:: python

    AUTH_KIT = {
        'USE_MFA': True,
        'MFA_HANDLERS': [
            'auth_kit.mfa.handlers.app.MFAAppHandler',
            'auth_kit.mfa.handlers.email.MFAEmailHandler',
            'auth_kit.mfa.handlers.webauthn.MFAWebAuthnHandler',
        ],
    }

During the second step, fetch a challenge scoped to the pending user with the
ephemeral token from the first step:

.. code-block:: bash

    POST /auth/login/challenge/
    {
        "ephemeral_token": "..."
    }

Pass the result to ``navigator.credentials.get()``, then submit the assertion
as the MFA ``code``. Methods that need no challenge, such as email or an
authenticator app, return ``{}`` from this endpoint.

Ceremony Options
----------------

``WEBAUTHN_USER_VERIFICATION`` controls whether the authenticator must check
the user locally with a PIN or biometric:

- ``'required'`` always verify, giving true two-factor assurance from one gesture
- ``'preferred'`` verify when the authenticator supports it (default)
- ``'discouraged'`` skip it for a faster prompt

``WEBAUTHN_RESIDENT_KEY`` controls discoverable credentials, which is what lets
a user sign in without first entering an email:

- ``'required'`` always store a discoverable credential
- ``'preferred'`` store one when supported (default)
- ``'discouraged'`` avoid storing one

Security Notes
--------------

- Challenges are single use and expire after ``WEBAUTHN_CHALLENGE_EXPIRY``
- Signature counters are checked to detect cloned authenticators
- Credentials are bound to the relying party, so a phishing site cannot use them
- Deactivated users are rejected even with a valid passkey

Next Steps
----------

- :doc:`passwordless` for passkey login
- :doc:`mfa` for using passkeys as a second factor
- :doc:`../configuration` for the full settings reference
