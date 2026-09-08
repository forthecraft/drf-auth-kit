"""Verify that auth_kit's declared runtime dependencies are sufficient.

Executed by the ``pkgcheck313`` tox env, which installs the built wheel with
only the dependencies declared in ``pyproject.toml``. A ``ModuleNotFoundError``
here points at an undeclared runtime dependency.
"""

import django


def main() -> None:
    """Import every module that carries a runtime dependency edge."""
    from django.conf import settings

    settings.configure(
        INSTALLED_APPS=[
            "django.contrib.contenttypes",
            "django.contrib.auth",
            "auth_kit",
            "auth_kit.mfa",
            "auth_kit.webauthn",
        ],
    )
    django.setup()

    import auth_kit.mfa.models  # noqa: F401
    import auth_kit.webauthn.models  # noqa: F401
    import auth_kit.webauthn.types  # noqa: F401

    print("all runtime imports OK")


if __name__ == "__main__":
    main()
