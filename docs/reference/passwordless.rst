Passwordless Authentication
===========================

.. module:: auth_kit.passwordless

Passwordless login through pluggable handlers such as email magic links
and passkeys.

Views
-----

.. module:: auth_kit.passwordless.views.login

.. autoclass:: auth_kit.passwordless.views.PasswordlessInitiateView
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: auth_kit.passwordless.views.PasswordlessVerifyView
   :members:
   :undoc-members:
   :show-inheritance:

Serializers
-----------

Login Serializers
~~~~~~~~~~~~~~~~~

.. module:: auth_kit.passwordless.serializers.login

.. autofunction:: auth_kit.passwordless.serializers.login.get_passwordless_verify_serializer

.. autofunction:: auth_kit.passwordless.serializers.login.get_passwordless_final_response_serializer

.. autoclass:: auth_kit.passwordless.serializers.login.RequireActiveUserMixin
   :members:
   :undoc-members:
   :show-inheritance:

Email Magic Link Serializers
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. module:: auth_kit.passwordless.serializers.email_link

.. autoclass:: auth_kit.passwordless.serializers.email_link.EmailLinkInitiateSerializer
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: auth_kit.passwordless.serializers.email_link.EmailLinkVerifySerializer
   :members:
   :undoc-members:
   :show-inheritance:

WebAuthn Serializers
~~~~~~~~~~~~~~~~~~~~

.. module:: auth_kit.passwordless.serializers.webauthn

.. autoclass:: auth_kit.passwordless.serializers.webauthn.WebAuthnInitiateSerializer
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: auth_kit.passwordless.serializers.webauthn.WebAuthnVerifySerializer
   :members:
   :undoc-members:
   :show-inheritance:

Handlers
--------

Base Handler
~~~~~~~~~~~~

.. module:: auth_kit.passwordless.handlers.base

.. autoclass:: auth_kit.passwordless.handlers.base.PasswordlessBaseHandler
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: auth_kit.passwordless.handlers.base.PasswordlessHandlerRegistry
   :members:
   :undoc-members:
   :show-inheritance:

Email Magic Link Handler
~~~~~~~~~~~~~~~~~~~~~~~~

.. module:: auth_kit.passwordless.handlers.email_link

.. autoclass:: auth_kit.passwordless.handlers.email_link.EmailLinkHandler
   :members:
   :undoc-members:

WebAuthn Handler
~~~~~~~~~~~~~~~~

.. module:: auth_kit.passwordless.handlers.webauthn

.. autoclass:: auth_kit.passwordless.handlers.webauthn.WebAuthnHandler
   :members:
   :undoc-members:

Services
--------

Token Services
~~~~~~~~~~~~~~

.. module:: auth_kit.passwordless.services.token

.. autoclass:: auth_kit.passwordless.services.token.PasswordlessEphemeralTokenService
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: auth_kit.passwordless.services.token.PasswordlessSignupTokenService
   :members:
   :undoc-members:
   :show-inheritance:

.. autodata:: auth_kit.passwordless.services.token.passwordless_token_service

.. autodata:: auth_kit.passwordless.services.token.passwordless_signup_token_service

Settings
--------

.. module:: auth_kit.passwordless.passwordless_settings

.. autoclass:: auth_kit.passwordless.passwordless_settings.PasswordlessSetting
   :members:
   :undoc-members:
