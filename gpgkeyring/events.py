"""
:mod:`gpgkeyring.events`
~~~~~~~~~~~~~~~~~~~~

GPG/Key Management lifecycle events.

:copyright: (c) 2018 by Joseph Black.
:license: MIT, see LICENSE for more details.

.. module:: gpgkeyring.events
.. moduleauthor:: Joseph Black <me@joeblack.nyc>
"""

from typing import Union, Tuple

import gnupg
from . import interfaces as iface

__all__ = [
    "BeforeInitializeGPG",
    "AfterInitializeGPG",
    "MessageEncrypted",
    "MessageDecrypted",
    "MessageSigned",
    "MessageVerified",
    "KeysLoaded",
    "KeysExported",
    "KeysImported",
    "KeysTrusted",
    "KeysDeleted",
    "KeysSentToServer",
    "KeysReceivedFromServer",
    "BeforeGenerateKey",
    "AfterGenerateKey",
]


class BeforeInitializeGPG:
    """Emitted before GPG instance is initialized.

    All event arguments are parameters relavent to the construction of the
    GPG instance and its subsequent ZCA component registration.
    """

    options: dict = None
    name: str = ""

    def __init__(self, options, name):
        self.options = options
        self.name = name


class AfterInitializeGPG:
    """Emitted after GPG instance is initialized.

    Any modifications of `gpg` will be reflected in the instance emitting
    this event.
    """

    gpg: iface.IGPG = None
    name: str = ""

    def __init__(self, gpg, name):
        self.gpg = gpg
        self.name = name


class MessageEncrypted:
    """Emitted after a message is encrypted."""

    gpg: iface.IGPG = None
    result: gnupg.Crypt = None

    def __init__(self, gpg, result):
        self.gpg = gpg
        self.result = result


class MessageDecrypted:
    """Emitted after a message is decrypted."""

    gpg: iface.IGPG = None
    result: gnupg.Crypt = None
    key: iface.IKey = None

    def __init__(self, gpg, result, key=None):
        self.gpg = gpg
        self.result = result
        self.key = key


class MessageSigned:
    """Emitted after a message is signed."""

    gpg: iface.IGPG = None
    result: gnupg.Sign = None

    def __init__(self, gpg, result):
        self.gpg = gpg
        self.result = result


class MessageVerified:
    """Emitted after a message is verified."""

    gpg: iface.IGPG = None
    result: gnupg.Verify = None
    key: iface.IKey = None

    def __init__(self, gpg, result, key=None):
        self.gpg = gpg
        self.result = result
        self.key = key


# @attr.s
class KeysLoaded:
    """Emitted after keys are loaded in Keyring."""

    gpg: iface.IGPG = None
    type: str = ""
    keys: gnupg.ListKeys = None

    def __init__(self, gpg, type, keys):
        self.gpg = gpg
        self.type = type
        self.keys = keys


class KeysExported:
    """Emitted after key(s) exported."""

    gpg: iface.IGPG = None
    result: gnupg.ExportResult = None
    keys: Union[iface.IKey, Tuple[iface.IKey]] = None

    def __init__(self, gpg, result, keys):
        self.gpg = gpg
        self.result = result
        self.keys = keys


class KeysImported:
    """Emitted after key(s) imported."""

    gpg: iface.IGPG = None
    result: gnupg.ImportResult = None
    keys: Union[iface.IKey, Tuple[iface.IKey]] = None

    def __init__(self, gpg, result, keys):
        self.gpg = gpg
        self.result = result
        self.keys = keys


class KeysTrusted:
    """Emitted after key(s) trusted."""

    gpg: iface.IGPG = None
    result: gnupg.DeleteResult = None
    keys: Union[iface.IKey, Tuple[iface.IKey]] = None

    def __init__(self, gpg, result, keys):
        self.gpg = gpg
        self.result = result
        self.keys = keys


class KeysDeleted:
    """Emitted after key(s) deleted."""

    gpg: iface.IGPG = None
    result: gnupg.DeleteResult = None
    keys: Union[iface.IKey, Tuple[iface.IKey]] = None

    def __init__(self, gpg, result, keys):
        self.gpg = gpg
        self.result = result
        self.keys = keys


class KeysSentToServer:
    """Emitted after key(s) sent to keyserver."""

    gpg: iface.IGPG = None
    result: gnupg.SendResult = None
    keys: Union[iface.IKey, Tuple[iface.IKey]] = None

    def __init__(self, gpg, result, keys):
        self.gpg = gpg
        self.result = result
        self.keys = keys


class KeysReceivedFromServer:
    """Emitted after key(s) received from keyserver."""

    gpg: iface.IGPG = None
    result: gnupg.ImportResult = None
    keys: Union[iface.IKey, Tuple[iface.IKey]] = None

    def __init__(self, gpg, result, keys):
        self.gpg = gpg
        self.result = result
        self.keys = keys


class BeforeGenerateKey:
    """Emitted before a new key is generated.

    Modify `options` on event to modify the options passed to the key
    generation function.
    """

    gpg: iface.IGPG = None
    options: dict = None

    def __init__(self, gpg, options):
        self.gpg = gpg
        self.options = options


class AfterGenerateKey:
    """Emitted after a new key is generated.

    It might be useful to do something with the `key` object generated here
    such as update a setting or signing a payload..
    """

    gpg: iface.IGPG = None
    cmd: str = ""
    result: gnupg.GenKey = None
    key: iface.IKey = None

    def __init__(self, gpg, cmd, result, key):
        self.gpg = gpg
        self.cmd = cmd
        self.result = result
        self.key = key
