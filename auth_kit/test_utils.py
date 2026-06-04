"""
Test utilities for Auth Kit.

This module provides testing utilities for temporarily overriding Auth Kit
settings during test execution. Supports both synchronous and asynchronous
test functions with automatic cleanup of modified settings.
"""

import contextlib
import functools
import inspect
from collections.abc import Callable, Iterator
from typing import Any, TypeVar, cast

from auth_kit.app_settings import auth_kit_settings
from auth_kit.mfa.mfa_settings import auth_kit_mfa_settings
from auth_kit.passwordless.passwordless_settings import auth_kit_passwordless_settings
from auth_kit.webauthn.webauthn_settings import auth_kit_webauthn_settings

T = TypeVar("T", bound=Callable[..., Any])


def override_auth_kit_settings(**settings: Any) -> Callable[[T], T]:
    """
    Decorator for overriding auth kit settings for the duration of a test function.
    Works with both sync and async functions.

    Usage:
        @override_auth_kit_settings(SEND_COMPLETION=True)
        async def test_something_async():
            ...

        @override_auth_kit_settings(SEND_COMPLETION=True)
        def test_something_sync():
            ...
    """

    def decorator(func: T) -> T:
        """
        Inner decorator function that wraps the target function.

        Selects the appropriate wrapper based on whether the target function
        is synchronous or asynchronous. Both wrappers establish a settings context
        around the function execution.

        Args:
            func: The function to be wrapped, can be either sync or async

        Returns:
            A wrapped version of the function that applies temporary settings
        """
        if inspect.iscoroutinefunction(func):
            # Handle async functions
            @functools.wraps(func)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                """
                Wrapper for asynchronous functions.

                Creates a settings context and awaits the wrapped coroutine function.

                Args:
                    *args: Positional arguments to pass to the wrapped function
                    **kwargs: Keyword arguments to pass to the wrapped function

                Returns:
                    The result of the wrapped coroutine function
                """
                with settings_context(**settings):
                    return await func(*args, **kwargs)

            return cast(T, async_wrapper)
        else:
            # Handle synchronous functions
            @functools.wraps(func)
            def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                """
                Wrapper for synchronous functions.

                Creates a settings context and calls the wrapped function.

                Args:
                    *args: Positional arguments to pass to the wrapped function
                    **kwargs: Keyword arguments to pass to the wrapped function

                Returns:
                    The result of the wrapped function
                """
                with settings_context(**settings):
                    return func(*args, **kwargs)

            return cast(T, sync_wrapper)

    return decorator


@contextlib.contextmanager
def settings_context(**settings: Any) -> Iterator[None]:  # noqa
    """Context manager for overriding auth kit settings temporarily."""
    # Initialize user_settings if it doesn't exist

    all_settings = [
        auth_kit_settings,
        auth_kit_mfa_settings,
        auth_kit_passwordless_settings,
        auth_kit_webauthn_settings,
    ]

    for s in all_settings:
        if not hasattr(s, "user_settings"):
            s.user_settings = {}  # type: ignore[attr-defined]

    def _find_settings_obj(key: str) -> Any:
        for s in all_settings:
            if hasattr(s, key):
                return s
        return None

    # Save original settings
    old_settings: dict[str, tuple[Any, Any]] = {}
    for key in settings:
        obj = _find_settings_obj(key)
        if obj:
            old_settings[key] = (obj, obj.user_settings.get(key))

    # Apply new settings and clear cached properties
    for key, value in settings.items():
        obj = _find_settings_obj(key)
        if obj:
            obj.user_settings[key] = value
            with contextlib.suppress(AttributeError):
                delattr(obj, key)

    try:
        yield
    finally:
        # Restore original settings
        for key in settings:
            if key in old_settings:
                obj, old_value = old_settings[key]
                if old_value is not None:
                    obj.user_settings[key] = old_value
                else:
                    obj.user_settings.pop(key, None)
                with contextlib.suppress(AttributeError):
                    delattr(obj, key)
