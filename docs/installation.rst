Installation
============

Dependencies
------------

DRF Auth Kit automatically installs these core dependencies:

**Core Dependencies**:

- **Django** (>=5.0) - Web framework
- **Django REST Framework** (>=3.0) - API framework
- **Django Allauth** (>=65.5.0) - User management and email verification
- **DRF SimpleJWT** (>=5.0) - JWT token authentication
- **DRF Spectacular** - OpenAPI schema generation
- **structlog** - Structured logging

**Optional Dependencies**:

- **pyotp** (>=2.9.0) - For MFA/TOTP support
- **django-allauth[socialaccount]** (>=65.5.0) - For social authentication

Installation Options
--------------------

Basic Installation
~~~~~~~~~~~~~~~~~~

Install DRF Auth Kit with core features:

.. code-block:: bash

    pip install drf-auth-kit

With MFA Support
~~~~~~~~~~~~~~~~

Install with Multi-Factor Authentication support:

.. code-block:: bash

    pip install drf-auth-kit[mfa]

With Social Authentication
~~~~~~~~~~~~~~~~~~~~~~~~~~

Install with social authentication support:

.. code-block:: bash

    pip install drf-auth-kit[social]

With WebAuthn / Passkeys
~~~~~~~~~~~~~~~~~~~~~~~~

Install with WebAuthn support, used for passkey login and as an MFA method:

.. code-block:: bash

    pip install drf-auth-kit[webauthn]

.. note::

    Passwordless email magic links need no extra dependency. Only the
    WebAuthn (passkey) parts require this install.

All Features
~~~~~~~~~~~~

Install with all features (MFA + Social Authentication + WebAuthn):

.. code-block:: bash

    pip install drf-auth-kit[all]

Install from Git
~~~~~~~~~~~~~~~~

Install the latest development version from GitHub:

.. code-block:: bash

    # Latest stable version
    pip install git+https://github.com/forthecraft/drf-auth-kit.git

    # With all features
    pip install git+https://github.com/forthecraft/drf-auth-kit.git[all]

    # Specific branch or tag
    pip install git+https://github.com/forthecraft/drf-auth-kit.git@main[all]

Verify Installation
-------------------

After installation, verify that DRF Auth Kit is properly installed:

.. code-block:: python

    # In Python shell or Django shell
    import auth_kit
    print(auth_kit.__version__)

    # Check available modules
    from auth_kit import authentication, serializers, views

Next Steps
----------

After installation, proceed to :doc:`getting-started` for configuration and setup instructions.
