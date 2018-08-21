"""
:mod:`gpgkeyring.decorators`
~~~~~~~~~~~~~~~~~~~~

GPG/Keychain related decorators.

:copyright: (c) 2018 by Joseph Black.
:license: MIT, see LICENSE for more details.

.. module:: gpgkeyring.decorators
.. moduleauthor:: Joseph Black <me@joeblack.nyc>
"""
from functools import wraps

from . import events


__all__ = ["expires_cache", "passthru"]


def expires_cache(func):
    """Automatically expire cache.

    :param typing.Callable func: the function to expire cache for.
    :returns: the wrapped function.
    :rtype: instance of :class:`typing.Callable`.
    :emits: :term:`event` of :class:`gpgkeyring.events.KeyCacheExpiry`.
    """

    @wraps(func)
    def _wrapper(self, *args, **kwargs):
        load_func = getattr(self, "_load", None)
        load_func.cache_clear()
        result = func(self, *args, **kwargs)
        load_func.cache_clear()
        return result

    return _wrapper


def passthru(func):
    """Return value of function by same name in proxied object.

    Proxied object is located as an attribute named `_wrapped` in proxy object.
    """

    @wraps(func)
    def _wrapper(self, *args, **kwargs):
        name = func.__name__
        return getattr(self._wrapped, func.__name__)(*args, **kwargs)

    return _wrapper
