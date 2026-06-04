Multi-Factor Authentication
===========================

.. module:: auth_kit.mfa

Multi-Factor Authentication (MFA) system for enhanced security.

Models
------

.. module:: auth_kit.mfa.models

.. autoclass:: auth_kit.mfa.models.MFAMethod
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: auth_kit.mfa.models.MFAMethodManager
   :members:
   :undoc-members:
   :show-inheritance:

Views
-----

Login Views
~~~~~~~~~~~

.. module:: auth_kit.mfa.views.login

.. autoclass:: auth_kit.mfa.views.LoginFirstStepView
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: auth_kit.mfa.views.LoginSecondStepView
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: auth_kit.mfa.views.LoginChangeMethodView
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: auth_kit.mfa.views.LoginMFAResendView
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: auth_kit.mfa.views.LoginMFAChallengeView
   :members:
   :undoc-members:
   :show-inheritance:

MFA Management Views
~~~~~~~~~~~~~~~~~~~~

.. module:: auth_kit.mfa.views.mfa

.. autoclass:: auth_kit.mfa.views.MFAMethodViewSet
   :members:
   :undoc-members:
   :show-inheritance:

Serializers
-----------

Login Serializers
~~~~~~~~~~~~~~~~~

.. module:: auth_kit.mfa.serializers.login

.. autofunction:: auth_kit.mfa.serializers.login.get_mfa_first_step_serializer

.. autofunction:: auth_kit.mfa.serializers.login.get_mfa_second_step_serializer

.. module:: auth_kit.mfa.serializers.login_factors

.. autoclass:: auth_kit.mfa.serializers.login_factors.MFAFirstStepResponseSerializer
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: auth_kit.mfa.serializers.login_factors.MFASecondStepRequestSerializer
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: auth_kit.mfa.serializers.login_factors.MFAChangeMethodSerializer
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: auth_kit.mfa.serializers.login_factors.MFAResendSerializer
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: auth_kit.mfa.serializers.login_factors.MFALoginChallengeSerializer
   :members:
   :undoc-members:
   :show-inheritance:

.. autofunction:: auth_kit.mfa.serializers.login_factors.get_no_mfa_login_response_serializer

MFA Management Serializers
~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. module:: auth_kit.mfa.serializers.mfa

.. autoclass:: auth_kit.mfa.serializers.mfa.MFAMethodConfigSerializer
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: auth_kit.mfa.serializers.mfa.MFAMethodConfirmSerializer
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: auth_kit.mfa.serializers.mfa.MFAMethodCreateSerializer
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: auth_kit.mfa.serializers.mfa.MFAMethodDeactivateSerializer
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: auth_kit.mfa.serializers.mfa.MFAMethodDeleteSerializer
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: auth_kit.mfa.serializers.mfa.MFAMethodPrimaryUpdateSerializer
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: auth_kit.mfa.serializers.mfa.MFAMethodSendCodeSerializer
   :members:
   :undoc-members:
   :show-inheritance:

Handlers
--------

Base Handler
~~~~~~~~~~~~

.. module:: auth_kit.mfa.handlers.base

.. autoclass:: auth_kit.mfa.handlers.base.MFABaseHandler
   :members:
   :undoc-members:
   :show-inheritance:

Email Handler
~~~~~~~~~~~~~

.. module:: auth_kit.mfa.handlers.email

.. autoclass:: auth_kit.mfa.handlers.email.MFAEmailHandler
   :members:
   :undoc-members:

App Handler
~~~~~~~~~~~

.. module:: auth_kit.mfa.handlers.app

.. autoclass:: auth_kit.mfa.handlers.app.MFAAppHandler
   :members:
   :undoc-members:

WebAuthn Handler
~~~~~~~~~~~~~~~~

.. module:: auth_kit.mfa.handlers.webauthn

.. autoclass:: auth_kit.mfa.handlers.webauthn.MFAWebAuthnHandler
   :members:
   :undoc-members:

Services
--------

Backup Codes Service
~~~~~~~~~~~~~~~~~~~~

.. module:: auth_kit.mfa.services.backup_codes

.. autofunction:: auth_kit.mfa.services.backup_codes.generate_backup_codes

User Token Service
~~~~~~~~~~~~~~~~~~

.. module:: auth_kit.mfa.services.user_token

.. autoclass:: auth_kit.mfa.services.user_token.EphemeralTokenService
   :members:
   :undoc-members:
   :show-inheritance:

.. autodata:: auth_kit.mfa.services.user_token.ephemeral_token_service

Utilities
---------

.. module:: auth_kit.mfa.utils

.. autofunction:: auth_kit.mfa.utils.get_setup_data_schemas

.. autofunction:: auth_kit.mfa.utils.get_mfa_login_first_step_response_schemas

.. autofunction:: auth_kit.mfa.utils.get_login_challenge_schemas

Exceptions
----------

.. module:: auth_kit.mfa.exceptions

.. autoexception:: auth_kit.mfa.exceptions.MFAMethodDoesNotExistError
   :members:
   :undoc-members:
   :show-inheritance:

Settings
--------

.. module:: auth_kit.mfa.mfa_settings

.. autoclass:: auth_kit.mfa.mfa_settings.MFASetting
   :members:
   :undoc-members:
