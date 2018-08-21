"""
:mod:`gpgkeyring.util`
~~~~~~~~~~~~~~~~~~~~

GPG utility functions.

:copyright: (c) 2018 by Joseph Black.
:license: MIT, see LICENSE for more details.

.. module:: gpgkeyring.util
.. moduleauthor:: Joseph Black <me@joeblack.nyc>
"""

from datetime import datetime
import maya

__all__ = [
    "coerce_time",
    "coerce_int",
    "coerce_tuple",
    "key_type",
    "setdefaults",
    "pop_attr",
]


def coerce_time(obj):
    """Return maya datetime regardless of input.

    Expected inputs are instances of :class:`datetime.datetime`, iso formatted
        timestamps, or unix timestamp.

    .. Usage::

        >>> coerce_time(datetime.now())
        <MayaDT epoch=...>

        >>> coerce_time(maya.now())
        <MayaDT epoch=...>

        >>> coerce_time('2018-05-30T17:39:11.063311')
        <MayaDT epoch=1527701951.063311>
    """
    if isinstance(obj, maya.MayaDT):
        return obj
    elif isinstance(obj, datetime):
        return maya.MayaDT.from_datetime(obj)
    elif isinstance(obj, str) and obj:
        return maya.when(obj)


def coerce_int(obj):
    """Return string converted to integer.

    .. Usage::

        >>> coerce_int(49)
        49

        >>> coerce_int('49')
        49

        >>> coerce_int(43.22)
        43
    """
    try:
        return int(obj) if obj else obj
    except ValueError:
        return 0


def coerce_tuple(item):
    """Return item converted to tuple if not already tuple.

    :param Union[str, IKey, Iterable] item: item to coerce to tuple.
    :returns: coerced value of item as tuple.
    :rtype: Tuple[Any].

    .. Usage::

        >>> coerce_tuple('test')
        ('test',)

        >>> coerce_tuple(('test', 'two'))
        ('test', 'two')

    """
    if isinstance(item, (list, tuple)):
        return tuple(item)
    return (item,) if item is not None else None


def key_type(secret):
    """Return string value for keytype depending on passed secret bool.

    Possible values returned are: `secret`, `public`.

    .. Usage::

        >>> key_type(secret=True)
        'secret'

        >>> key_type(secret=False)
        'public'
    """
    return "secret" if secret else "public"


def setdefaults(options, defaults):
    """Return options dictionary with defaults set from defaults.

    .. Usage::

        >>> setdefaults(dict(one='one'), dict(one='two'))
        {'one': 'one'}
    """
    defaults = defaults.copy()
    defaults.update(options)
    return defaults


def pop_attr(obj, attr, default=None):
    """Pops and returns value of object attribute, similar to dictionary item pops.

    If attribute doesn't exist, returns value of 'default'.

    .. Usage::

        >>> pop_attr(obj, 'attribute')
        'value'
    """
    return obj.__dict__.pop(attr, default)


def parse_keyids(key):
    """Return parsed keyid string(s) or tuple of."""
    if isinstance(key, str):
        return key
    elif isinstance(key, (tuple, list)):
        return tuple(parse_keyids(keyid) for keyid in key)
    return getattr(key, "keyid")


def parse_fingerprints(key):
    """Return parsed fingerprint string(s) or tuple of."""
    if isinstance(key, str):
        return key
    elif isinstance(key, (tuple, list)):
        return tuple(parse_fingerprints(fp) for fp in key)
    return getattr(key, "fingerprint")


# def is_encrypted(blob):
#     """"Return whether value is an ascii-armored, encrypted message.

#     :param str blob: the text blob to check.
#     :returns: whether the blob is an encrypted message.
#     :rtype: :type:`bool`.

#     .. Usage::

#         >>> msg = gpg.encrypt('test', passphrase='test')
#         >>> is_encrypted(msg)
#         True
#     """
#     return "PGP MESSAGE" in blob


# def is_key(blob, kind="any"):
#     """"Return whether value is an ascii-armored, GPG key.

#     :param str blob: the text blob to check.
#     :keyword str kind: which kind of key to check for. (public, secret, any),
#         Optional (default: "any").

#     :returns: whether the blob is a key of kind `kind`.
#     :rtype: :type:`bool`.

#     .. Usage::

#         >>> keydata = gpg.keys.export()

#         >>> is_key(keydata)
#         True

#         >>> is_key(keydata, 'public')
#         True

#         >>> is_key(keydata, 'secret')
#         False

#     """
#     if kind == "secret":
#         return "PGP PRIVATE KEY" in blob
#     elif kind == "public":
#         return "PGP PUBLIC KEY" in blob
#     elif kind == "any":
#         return "PGP PRIVATE KEY" in blob or "PGP PUBLIC KEY" in blob


# def is_signed(blob):
#     """"Return whether value is an ascii-armored, signed GPG message.

#     :param str blob: the text blob to check.
#     :returns: whether the blob is a signed message.
#     :rtype: :type:`bool`.

#     .. Usage::

#         >>> signed = gpg.sign('message')
#         >>> is_signed(signed)
#         True
#     """
#     return "PGP SIGNED MESSAGE" in blob


# def is_signature(blob):
#     """"Return whether value is an ascii-armored, GPG signature.

#     :param str blob: the text blob to check.
#     :returns: whether the blob is a gpg signature.
#     :rtype: :type:`bool`.

#     .. Usage::

#         >>> signed = gpg.sign('message')
#         >>> is_signature(signed)
#         True
#     """
#     return "PGP SIGNATURE" in blob


# def reduce_result(obj):
#     """"Return first item if `obj` is an iterable with one item.

#     :param Any obj: the object to check.
#     :returns: first item if `obj` is an iterable with one item, else `obj` unchanged.
#     :rtype: Any.

#     .. Usage::

#         >>> reduce_result(['test'])
#         'test'
#     """
#     if isinstance(obj, (list, tuple)) and len(obj) == 1:
#         obj = obj[0]
#     return obj


# def coerce_fingerprints(item):
#     """Return tuple of fingerprint string(s) from input.

#     Expected inputs include: fingerprint string, Key object, or iterable
#     containing any mixture of.

#     :param Union[str, IKey, Iterable] item: item to parse fingerprints from.

#     :returns: tuple of fingerprint strings.
#     :rtype: Tuple[str].
#     """
#     return parse_fingerprints(coerce_tuple(item))


# def coerce_keyids(item):
#     """Return tuple of keyid string(s) from input.

#     Expected inputs include: keyid string, key object, or iterable
#     containing any mixture of.

#     :param Union[str, IKey, Iterable] item: item to parse keyids from.

#     :returns: tuple of keyids strings.
#     :rtype: Tuple[str].
#     """
#     return parse_keyids(coerce_tuple(item))
