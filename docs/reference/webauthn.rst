WebAuthn
========

.. module:: auth_kit.webauthn

WebAuthn credential storage and ceremony helpers, shared by passkey login
and the WebAuthn MFA method.

Models
------

.. module:: auth_kit.webauthn.models.credential

.. autoclass:: auth_kit.webauthn.models.WebAuthnCredential
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: auth_kit.webauthn.models.credential.WebAuthnCredentialManager
   :members:
   :undoc-members:
   :show-inheritance:

Views
-----

.. module:: auth_kit.webauthn.views.credential

.. autoclass:: auth_kit.webauthn.views.WebAuthnCredentialViewSet
   :members:
   :undoc-members:
   :show-inheritance:

Serializers
-----------

Credential Serializers
~~~~~~~~~~~~~~~~~~~~~~

.. module:: auth_kit.webauthn.serializers.credential

.. autoclass:: auth_kit.webauthn.serializers.credential.WebAuthnCredentialSerializer
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: auth_kit.webauthn.serializers.credential.WebAuthnCredentialCreateSerializer
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: auth_kit.webauthn.serializers.credential.WebAuthnCredentialUpdateSerializer
   :members:
   :undoc-members:
   :show-inheritance:

Ceremony Option Serializers
~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. module:: auth_kit.webauthn.serializers.options

.. autoclass:: auth_kit.webauthn.serializers.options.WebAuthnRegistrationOptionsSerializer
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: auth_kit.webauthn.serializers.options.WebAuthnAuthenticationOptionsSerializer
   :members:
   :undoc-members:
   :show-inheritance:

Services
--------

.. module:: auth_kit.webauthn.services

.. autofunction:: auth_kit.webauthn.services.begin_registration

.. autofunction:: auth_kit.webauthn.services.complete_registration

.. autofunction:: auth_kit.webauthn.services.begin_authentication

.. autofunction:: auth_kit.webauthn.services.complete_authentication

Types
-----

.. module:: auth_kit.webauthn.types

.. autoclass:: auth_kit.webauthn.types.WebAuthnRegistrationOptions
   :members:
   :undoc-members:

.. autoclass:: auth_kit.webauthn.types.WebAuthnAuthenticationOptions
   :members:
   :undoc-members:

Exceptions
----------

.. module:: auth_kit.webauthn.exceptions

.. autoexception:: auth_kit.webauthn.exceptions.WebAuthnCredentialDoesNotExistError
   :members:
   :undoc-members:
   :show-inheritance:

.. autoexception:: auth_kit.webauthn.exceptions.WebAuthnVerificationError
   :members:
   :undoc-members:
   :show-inheritance:

Settings
--------

.. module:: auth_kit.webauthn.webauthn_settings

.. autoclass:: auth_kit.webauthn.webauthn_settings.WebAuthnSetting
   :members:
   :undoc-members:
