"""
:mod:`gpgkeyring.gpg`
~~~~~~~~~~~~~~~~~~~~

GPG Wrapper.

:copyright: (c) 2018 by Joseph Black.
:license: MIT, see LICENSE for more details.

.. module:: gpgkeyring.gpg
.. moduleauthor:: Joseph Black <me@joeblack.nyc>
"""

from os.path import expanduser
from typing import ClassVar

from zope.interface import implementer
import zope.component
from zope.component.interfaces import IFactory
from zope.component.factory import Factory

import cachetools.func
import gnupg
import attr
from attr.validators import instance_of

from . import util, events
from . import interfaces as iface
from . import exceptions as exc
from . import keys


__all__ = ["GPG", "create", "get"]

_DEFAULT_GPG_FACTORY_NAME = "{}.GPG".format(__package__)
_GSM = zope.component.getGlobalSiteManager()


@implementer(iface.IGPG)
@attr.s(hash=True)
class GPG:
    """An object wrapping a `gnupg.GPG` instance.

    :param dict options: the options to pass to gnupg.
    :keyword str name: the ZCA utility name. Optional (default: "").
    :keyword str event: whether to send an event during init. Optional
        (default: True).
    :keyword str register: whether to register instance in ZCA. Optional
        (default: True).
    :returns: the GPG object.
    :rtype: instance of :class:`.keys.GPG`.
    :emits:
        an :term:`event` of :class:`.events.BeforeInitializeGPG`
            before gpg initialization if `event` is True.
        an :term:`event` of :class:`.events.AfterInitializeGPG`
            after gpg initialization if `event` is True.
    
    :ivar str name: the name to register component as.
    :ivar tuple version: the version of the gpg binary.
    :ivar iface.IKeyring keys: an instance of keyring manager.

    .. Popular `options`:
        :keyword str gnupghome: the gpg home directory, default: "~/.gnupg".
        :keyword str gpgbinary: the gpg binary to use, can be name or full
            path, default: "gpg2".
        :keyword bool use_agent: whether to use gpg agent if loaded,
            default: True.
        :keyword bool keyserver: default keyserver to use,
            default: "pool.sks-keyservers.net".
        :keyword str encoding: the encoding to coerce things to,
            default: "utf-8".
        :pkeyword bool verbose: whether to print verbose information to the
            console, default: False.
        :keyword str keyring: the name of the keyring to use, can also accept a
            list of paths to keyring files. default: None.
        :keyword list options: if specified, this dictionary of values should
            be a list of command-line options to pass to GPG.

    Usage::

        >>> gpgkeyring.GPG(options=dict(gnupghome="/tmp/keyring"))
        GPG(name='', homedir='/tmp/keyring')
    """

    name: str = attr.ib(default="", validator=instance_of(str))
    options: dict = attr.ib(
        repr=False, factory=dict, validator=instance_of(dict), cmp=False
    )
    event: bool = attr.ib(default=True, repr=False, cmp=False)
    register: bool = attr.ib(default=True, repr=False, cmp=False)
    homedir: str = attr.ib(init=False, default="")

    _gpg_class = gnupg.GPG
    _keyring_class = keys.Keyring

    _default_options: dict = dict(
        gnupghome="~/.gnupg", gpgbinary="gpg2", use_agent=True, options=[]
    )
    _default_keyserver: str = "pool.sks-keyservers.net"
    _default_encoding: str = "utf-8"

    def __attrs_post_init__(self):
        options = util.setdefaults(
            util.pop_attr(self, "options"), self._default_options
        )
        fire_events = util.pop_attr(self, "event")
        register = util.pop_attr(self, "register")

        if fire_events:
            event = events.BeforeInitializeGPG(options, self.name)
            zope.component.handle(event)
            options = event.options
            self.name = event.name

        self._defaults = dict(
            keyserver=options.pop("keyserver", self._default_keyserver)
        )
        encoding = options.pop("encoding", self._default_encoding)

        options["gnupghome"] = expanduser(options["gnupghome"])
        self.homedir = options["gnupghome"]
        self._gpg = self._gpg_class(**options)
        self._gpg._wrapped = self
        if encoding:
            self._gpg.encoding = encoding

        try:
            self.keys = iface.IKeyring(self)
        except TypeError:
            self.keys = self._keyring_class(self)

        if fire_events:
            zope.component.handle(events.AfterInitializeGPG(self, self.name))
        if register:
            _GSM.registerUtility(self, name=self.name)

    @property
    def version(self):
        """A tuple of version for gpg binary."""
        return self._gpg.version

    def encrypt(
        self,
        message,
        key=None,
        symmetric=False,
        sign=True,
        event=True,
        **kwargs
    ):
        """Return encrypted message.

        :param str message: the message to encrypt.
        :keyword str key: the fingerprint or key object to encrypt message
            with, defaulting to current/default key. Optional (default: None).
        :keyword bool symmetric: whether to use symmetric encryption.
            Optional (default: False).
        :keyword bool sign: whether to sign the encrypted message.
            Optional (default: True).
        :keyword bool event: whether to send an event. Optional
            (default: True).
        :returns: the encrypted data.
        :rtype: :type:`str`
        :raises: :exc:`.exc.MessageEncryptError` if encryption encounters
            failure.
        :emits: an :term:`event` of :class:`.events.MessageEncrypted`.

        .. Usage::

            >>> gpg.encrypt('message', passphrase='test')
            '-----BEGIN PGP MESSAGE-----...'
        """
        key = util.parse_fingerprints(key or self.keys.secret.current)
        result = self._gpg.encrypt(
            message, key, symmetric=symmetric, sign=sign, **kwargs
        )
        if result.status != "encryption ok":
            raise exc.MessageEncryptError(
                "Error encrypting message, status: {} {}".format(
                    result.status, result.stderr
                )
            )
        result.data = result.data.decode(encoding=str(self._gpg.encoding))
        if event:
            event = events.MessageEncrypted(self, result)
            zope.component.handle(event)
        return result.data

    @cachetools.func.lru_cache()
    def decrypt(self, ciphertext, event=True, **kwargs):
        """Return decrypted ciphertext.

        :param str ciphertext: the ciphertext to decrypt.
        :keyword type coerce: the type to coerce result to.
            Optional (default: str).
        :keyword bool event: whether to send an event. Optional
            (default: True).
        :returns: decrypted payload.
        :rtype: decrypted payload coerced to type `.coerce`.
        :raises: :exc:`.exc.MessageDecryptError` if decryption encounters
            failure.
        :emits: an :term:`event` of :class:`.events.MessageDecrypted`.

        .. Usage::

            >>> data = gpg.encrypt('message', passphrase='test')
            >>> gpg.decrypt(data)
            'message'
        """
        result = self._gpg.decrypt(ciphertext, **kwargs)
        if result.status != "decryption ok":
            raise exc.MessageDecryptError(
                "Error decrypting message, status: {} {}".format(
                    result.status, result.stderr
                )
            )
        result.data = result.data.decode(encoding=str(self._gpg.encoding))
        key = self.keys.get(
            result.pubkey_fingerprint
        ) if result.pubkey_fingerprint else None
        if event:
            event = events.MessageDecrypted(self, result, key)
            zope.component.handle(event)
        return result.data

    def sign(self, message, key=None, event=True, **kwargs):
        """Return signed message.

        Message is signed using `key` if provided, otherwise key defaults to
        current/default key.

        :param str message: the message to sign.
        :keyword str key: the fingerprint or key object to sign message with,
            defaulting to current/default key, Optional (default: None)
        :keyword bool event: whether to send an event. Optional
            (default: True).
        :returns: the signature payload.
        :rtype: :type:`str`
        :raises: :exc:`.exc.MessageSignError` if signature fails.
        :emits: an :term:`event` of :class:`.events.MessageSigned`.

        .. Usage::

            >>> gpg.sign('message', passphrase='test')
            '-----BEGIN PGP SIGNED MESSAGE-----...'
        """
        keyids = util.parse_keyids(key or self.keys.secret.current)
        result = self._gpg.sign(message, keyid=keyids, **kwargs)
        if result.status != "signature created":
            raise exc.MessageSignError(
                "Error signing message, status: {} {}".format(
                    result.status, result.stderr
                )
            )
        result.data = result.data.decode(encoding=str(self._gpg.encoding))
        if event:
            event = events.MessageSigned(self, result)
            zope.component.handle(event)
        return result.data

    def verify(self, message, event=True, **kwargs):
        """Return whether message is signed properly.

        :param str message: the message to verify.
        :keyword bool event: whether to send an event. Optional
            (default: True).
        :returns: whether the signature is valid
        :rtype: :type:`bool`
        :raises: :exc:`.exc.MessageVerifyError` if verification encounters
            failure.
        :emits: an :term:`event` of :class:`.events.MessageVerified`.

        .. Usage::

            >>> data = gpg.sign('message', passphrase='test')
            >>> gpg.verify(data)
            True
        """
        result = self._gpg.verify(message, **kwargs)
        if result.status not in ("signature good", "signature valid"):
            raise exc.MessageVerifyError(
                "Error verifying message, status: {} {}".format(
                    result.status, result.stderr
                )
            )

        key = self.keys.get(
            result.pubkey_fingerprint
        ) if result.pubkey_fingerprint else None
        if event:
            event = events.MessageVerified(self, result, key)
            zope.component.handle(event)
        return result.valid


@implementer(iface.IGPGFactory)
def create(name="", **options):
    """A factory returning an instance providing :class:`iface.IGPG`.

    :keyword str name: the name to register utility as in ZCA.
        Optional (default: "").
    :keyword kwargs options: keywword arguments collections as :var:`options`.
    :returns: the gpg instance.
    :rtype: instance providing :class:`iface.IGPG`.

    .. Usage::

        >>> gpgkeyring.create(gnupghome='/tmp/keyring')
        GPG(name='', homedir='/tmp/keyring')
    """
    factory = _GSM.queryUtility(
        IFactory, name=_DEFAULT_GPG_FACTORY_NAME, default=_gpg_factory
    )
    return factory(name, options)


def get(name="", default=None):
    """Get gpg utility registered under :var:`name`.

    GPG utility is an instance providing :class:`iface.IGPG`.

    If utility query returns no results, returns `default` instead.

    :keyword str name: the name of the GPG utility to query from the ZCA.
        Optional (default: "").
    :keyword typing.Any default: the default to return if utility query fails.
    :returns: the queried gpg instance.
    :rtype: instance providing :class:`iface.IGPG`.

    .. Usage::

        >>> gpgkeyring.get()
        GPG(name='', homedir='...')
    """
    return _GSM.queryUtility(iface.IGPG, name=name, default=default)


_gpg_factory = Factory(GPG, _DEFAULT_GPG_FACTORY_NAME, "GPG default factory")
