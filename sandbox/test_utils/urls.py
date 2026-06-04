from importlib import reload
from types import ModuleType


def reload_necessary_modules_and_get_urls() -> ModuleType:
    import auth_kit.utils

    reload(auth_kit.utils)

    import auth_kit.mfa.views.login

    reload(auth_kit.mfa.views.login)
    import auth_kit.mfa.views

    reload(auth_kit.mfa.views)
    import auth_kit.mfa.mfa_settings

    reload(auth_kit.mfa.mfa_settings)

    import auth_kit.utils

    reload(auth_kit.utils)
    import auth_kit.mfa.urls

    reload(auth_kit.mfa.urls)

    # passwordless URLs bake settings-dependent descriptions at import time,
    # so they must be rebuilt whenever auth settings change
    import auth_kit.passwordless.passwordless_settings

    reload(auth_kit.passwordless.passwordless_settings)
    import auth_kit.passwordless.urls

    reload(auth_kit.passwordless.urls)

    import auth_kit.urls

    reload(auth_kit.urls)

    return auth_kit.urls


def reload_necessary_modules_and_get_social_urls() -> ModuleType:
    import auth_kit.utils

    reload(auth_kit.utils)

    import auth_kit.social.utils

    reload(auth_kit.social.utils)

    import auth_kit.social.serializers.login

    reload(auth_kit.social.serializers.login)

    import auth_kit.social.views.login

    reload(auth_kit.social.views.login)

    import auth_kit.social.views.connect

    reload(auth_kit.social.views.connect)

    import auth_kit.social.views.account

    reload(auth_kit.social.views.account)

    import auth_kit.social.views

    reload(auth_kit.social.views)

    import auth_kit.social.urls

    reload(auth_kit.social.urls)

    return auth_kit.social.urls
