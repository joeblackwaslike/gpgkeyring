"""
:mod:`gpgkeyring.keys`
~~~~~~~~~~~~~~~~~~~~

GPG KeyManager related classes.

:copyright: (c) 2018 by Joseph Black.
:license: MIT, see LICENSE for more details.

.. module:: gpgkeyring.keys
.. moduleauthor:: Joseph Black <me@joeblack.nyc>
"""

import enum
from typing import Union, Optional, Tuple, Dict

from maya import MayaDT
from zope.interface import implementer
import zope.component
from zope.component.factory import Factory
import gnupg
import cachetools.func
import attr
from attr.validators import instance_of, provides, optional

from . import util, events, trust
from . import exceptions as exc
from . import interfaces as iface
from .decorators import passthru, expires_cache
from .util import coerce_time, coerce_int, coerce_tuple
from .trust import coerce_trust, Levels

__all__ = ["Keyring", "Key", "SubKey", "Types", "Validity"]

_DEFAULT_KEY_FACTORY_NAME = "{}.Key".format(__package__)
_DEFAULT_SUBKEY_FACTORY_NAME = "{}.SubKey".format(__package__)
_GSM = zope.component.getGlobalSiteManager()


class Types(enum.Enum):
    """The types of GPG keys."""

    PUBLIC = "PUBLIC"
    SECRET = "SECRET"
    SUBKEY = "SUBKEY"
    SECRET_SUBKEY = "SECRET_SUBKEY"

    def __repr__(self):
        return "<{}: {}>".format(type(self).__name__, self.value)

    def __str__(self):
        return str(self.value)

    def __hash__(self):
        return hash(self.value)

    def __eq__(self, other):
        if isinstance(other, str):
            return bool(other in self.value)
        return enum.Enum.__eq__(self, other)

    def __lt__(self, other):
        if self.__class__ is other.__class__:
            return self.value < other.value
        return NotImplemented


_KEYTYPE_MAP = dict(
    sec=Types.SECRET,
    pub=Types.PUBLIC,
    sub=Types.SUBKEY,
    ssb=Types.SECRET_SUBKEY,
)


class Validity(enum.Enum):
    """The validity of a GPG Key."""

    UNKNOWN = "UNKNOWN"
    INVALID = "INVALID"
    REVOKED = "REVOKED"
    EXPIRED = "EXPIRED"

    def __repr__(self):
        return "<{}: {}>".format(type(self).__name__, self.value)

    def __str__(self):
        return str(self.value)

    def __hash__(self):
        return hash(self.value)

    def __eq__(self, other):
        if isinstance(other, str):
            return bool(other in self.value)
        return enum.Enum.__eq__(self, other)

    def __lt__(self, other):
        if self.__class__ is other.__class__:
            return self.value < other.value
        return NotImplemented


_VALIDITY_MAP = {
    "o": Validity.UNKNOWN,
    "-": Validity.UNKNOWN,
    "r": Validity.REVOKED,
    "e": Validity.EXPIRED,
}


def coerce_keytype(value):
    """"Return CONSTANT value to replace gpg2 raw value.

    :param Union[Types, str] value: the object to check.
    :returns: the Types constant for `value`.
    :rtype: an enum of :class:`Types`.

    Usage::

        >>> coerce_keytype('sec')
        <Types: SECRET>
    """
    if isinstance(value, Types):
        return value
    return _KEYTYPE_MAP[value]


def coerce_trust_validity(value):
    """"Return CONSTANT value to replace gpg2 raw value.

    :param Union[Validity, Levels, str] value: the object to coerce.
    :returns: the Validity or Levels constant for `value`.
    :rtype: an enum of :class:`Validity` or :class:`Levels`.

    Usage::

        >>> coerce_trust_validity('o')
        <Validity: UNKNOWN>
    """
    if isinstance(value, (Types, Validity)):
        return value
    try:
        return coerce_trust(value)
    except KeyError:
        return _VALIDITY_MAP[value]


@implementer(iface.ISubKey)
@attr.s(hash=True)
class SubKey:
    """A Subkey.

    :keyword Types type: the subkey type.
    :keyword Union[Levels, Validity] trust: the validity of the key.
    :keyword int length: the length of the subkey in bits.
    :keyword int algo: the public subkey algorithm number.
    :keyword str keyid: the subkey ID.
    :keyword maya.MayaDT date: the creation date as UTC timestamp.
    :keyword Optional[maya.MayaDT] expires: the expiry date as UTC timestamp,
        if specified.
    :keyword str dummy: the certificate serial number, UID hash or trust
        signature info.
    :keyword Union[Levels, Validity] ownertrust: the level of owner trust for
        the key. Optional (default: None).
    :keyword str uid: the key user ID.
    :keyword str sig: the signature class.
    :keyword str cap: the subkey capabilities.
    :keyword str issuer: the issuer information.
    :keyword str flag: the flag field.
    :keyword str token: the token serial number.
    :keyword str hash: the hash algorithm.
    :keyword str curve: the curve name if elliptic curve (ECC) key.
    :keyword str compliance: the compliance flags.
    :keyword Optional[maya.MayaDT] updated: the last updated date as UTC
        timestamp, if specified.
    :keyword str origin: the subkey origin.
    :returns: the Subkey object.
    :rtype: an instance of :class:`.SubKey`.
    :raises :exc:`TypeError`: if validation fails for param
    """

    type: Types = attr.ib(
        hash=False,
        default="",
        converter=coerce_keytype,
        validator=instance_of(Types),
    )
    trust: Union[Levels, Validity] = attr.ib(
        default="-",
        converter=coerce_trust_validity,
        validator=instance_of((Levels, Validity)),
    )
    length: int = attr.ib(
        default=0, converter=coerce_int, validator=instance_of(int)
    )
    algo: int = attr.ib(
        default=0, converter=coerce_int, validator=instance_of(int)
    )
    keyid: str = attr.ib(default="", validator=instance_of(str))
    date: MayaDT = attr.ib(
        default=None,
        converter=coerce_time,
        validator=optional(instance_of(MayaDT)),
    )
    expires: Optional[MayaDT] = attr.ib(
        default="",
        converter=coerce_time,
        validator=optional(instance_of(MayaDT)),
    )
    dummy: str = attr.ib(default="", validator=instance_of(str))
    _ownertrust: Union[Levels, Validity] = attr.ib(repr=False, default=None)
    uid: str = attr.ib(default="", validator=instance_of(str))
    sig: str = attr.ib(hash=False, default="", validator=instance_of(str))
    cap: str = attr.ib(default="", validator=instance_of(str))
    issuer: str = attr.ib(default="", validator=instance_of(str))
    flag: str = attr.ib(default="", validator=instance_of(str))
    token: str = attr.ib(default="", validator=instance_of(str))
    hash: str = attr.ib(default="", validator=instance_of(str))
    curve: str = attr.ib(default="", validator=instance_of(str))
    compliance: str = attr.ib(default="", validator=instance_of(str))
    updated: Optional[MayaDT] = attr.ib(
        default=None,
        converter=coerce_time,
        validator=optional(instance_of(MayaDT)),
    )
    origin: str = attr.ib(default="", validator=instance_of(str))


_subkey_factory = Factory(SubKey, _DEFAULT_SUBKEY_FACTORY_NAME)


@implementer(iface.IKey)
@attr.s(hash=True)
class Key:
    """Key and associated subkey(s).

    Subkeys accessed through the attribute `subkeys` which is implemented as a
    dictionary-like interface.

    :keyword Types type: the key type.
    :keyword Union[Levels, Validity] trust: the validity of the key.
    :keyword int length: the length of the key in bits.
    :keyword int algo: the subkey algorithm number.
    :keyword str keyid: the subkey ID.
    :keyword maya.MayaDT date: the creation date as UTC timestamp.
    :keyword Optional[maya.MayaDT] expires: the expiry date as UTC timestamp,
        if specified.
    :keyword str dummy: the certificate serial number, UID hash or trust
        signature info.
    :keyword Union[Levels, Validity] ownertrust: the level of owner trust for
        the key.
    :keyword str sig: the signature class.
    :keyword str cap: the subkey capabilities.
    :keyword str issuer: the issuer information.
    :keyword str flag: the flag field.
    :keyword str token: the token serial number.
    :keyword str hash: the hash algorithm.
    :keyword str curve: the curve name if elliptic curve (ECC) key.
    :keyword str compliance: the compliance flags.
    :keyword Optional[maya.MayaDT] updated: the last updated date as UTC
        timestamp, if specified.
    :keyword str origin: the subkey origin.
    :keyword Tuple[str] uids: the key user ID.
    :keyword Tuple[str] sigs: the key sigs.
    :keyword str fingerprint: the key fingerprint.

    :returns: the GPG Key object.
    :rtype: an instance of :class:`.Key`.
    :raises :exc:`TypeError`: if validation fails for params

    :ivar Dict[str, iface.ISubKey] subkeys: a dictionary of keyids mapped to
        associated subkeys.

    .. References::
        
        https://git.gnupg.org/cgi-bin/gitweb.cgi?p=gnupg.git;a=blob_plain;f=doc/DETAILS
    """

    type: str = attr.ib(
        default="", converter=coerce_keytype, validator=instance_of(Types)
    )
    trust: Union[Levels, Validity] = attr.ib(
        default="-",
        converter=coerce_trust_validity,
        validator=instance_of((Levels, Validity)),
    )
    length: int = attr.ib(
        default=0, converter=coerce_int, validator=instance_of(int)
    )
    algo: int = attr.ib(
        default=0, converter=coerce_int, validator=instance_of(int)
    )
    keyid: str = attr.ib(default="", validator=instance_of(str))
    date: MayaDT = attr.ib(
        default=None,
        converter=coerce_time,
        validator=optional(instance_of(MayaDT)),
    )
    expires: Optional[MayaDT] = attr.ib(
        default=None,
        converter=coerce_time,
        validator=optional(instance_of(MayaDT)),
    )
    dummy: str = attr.ib(default="", validator=instance_of(str))
    ownertrust: Union[Levels, Validity] = attr.ib(
        default="-",
        converter=coerce_trust_validity,
        validator=instance_of((Levels, Validity)),
    )
    sig: str = attr.ib(default="", validator=instance_of(str))
    cap: str = attr.ib(default="", validator=instance_of(str))
    issuer: str = attr.ib(default="", validator=instance_of(str))
    flag: str = attr.ib(default="", validator=instance_of(str))
    token: str = attr.ib(default="", validator=instance_of(str))
    hash: str = attr.ib(default="", validator=instance_of(str))
    curve: str = attr.ib(default="", validator=instance_of(str))
    compliance: int = attr.ib(default="", validator=instance_of(str))
    updated: Optional[MayaDT] = attr.ib(
        default=None,
        converter=coerce_time,
        validator=optional(instance_of(MayaDT)),
    )
    origin: str = attr.ib(default="", validator=instance_of(str))
    uids: Tuple[str, ...] = attr.ib(
        hash=False,
        factory=tuple,
        converter=coerce_tuple,
        validator=instance_of(tuple),
    )
    sigs: Tuple[str, ...] = attr.ib(
        hash=False,
        default=(),
        converter=coerce_tuple,
        validator=instance_of(tuple),
    )
    _subkeys: tuple = attr.ib(
        factory=list,
        repr=False,
        hash=False,
        converter=coerce_tuple,
        validator=instance_of(tuple),
    )
    fingerprint: str = attr.ib(
        hash=False, default="", validator=instance_of(str)
    )
    _subkey_info: dict = attr.ib(
        factory=dict, hash=False, repr=False, validator=instance_of(dict)
    )

    _subkey_class = SubKey

    def __bool__(self):
        return bool(self.fingerprint or self.keyid)

    def __contains__(self, key):
        """Test inclusion of subkey keyid in associated subkeys.

        Matches keyid values provided as `key`.
        """
        return key in list(self.subkeys.keys()) + list(self.subkeys.values())

    def __getitem__(self, key):
        """Return SubKey for fingerprint matching key in this keylist.

        If key not found, raise :exc:`IndexError`.
        """
        return self.subkeys[key]

    def __iter__(self):
        """Return generator yielding subkeys for this key."""
        return iter(self.subkeys.values())

    def __len__(self):
        """Return number of subkeys for this key."""
        return len(self.subkeys)

    @cachetools.func.ttl_cache(ttl=600)
    def _get_subkeys(self):
        return {key: self.get(key) for key in self._subkey_info}

    @property
    def subkeys(self):
        """Return subkeys for this key."""
        return self._get_subkeys()

    def get(self, key, default=None):
        """Return subkey for fingerprint matching key for this key.

        If no subkey found, return value of `default`.

        :param str key: the keyid of desired SubKey.
        :keyword Any default: the default to return if SubKey not found
            (optional default: None).
        :returns: the SubKey object, or default.
        :rtype: instance providing :class:`.iface.ISubKey` or type of
            `default`.

        .. Usage::

            >>> gpg.keys.public.current.subkeys.get('')
        """
        subkey = self._subkey_info.get(key, default)
        if not isinstance(subkey, dict):
            raise ValueError("no subkey for key: {}".format(key))
        try:
            return zope.component.createObject(
                _DEFAULT_SUBKEY_FACTORY_NAME, **subkey
            )
        except zope.component.ComponentLookupError:
            return self._subkey_class(**subkey)

    def keys(self):
        """Return generator yielding keyids of subkeys for this key.

        :returns: a generator yielding SubKey keyids.
        :rtype: :type:`generator`

        Usage::

            >>> gpg.keys.public.current.keys()
            <generator object Key.keys at 0x...>
        """
        for key in self._get_subkeys().keys():
            yield key

    def values(self):
        """Return generator yielding subkeys for this key.

        :returns: a generator yielding SubKey object values.`.
        :rtype: :type:`generator`

        Usage::

            >>> gpg.keys.public.current.values()
            <generator object Key.values at 0x...>
        """
        for value in self._get_subkeys().values():
            yield value

    def items(self):
        """Return generator yielding item tuples of subkeys for this key.

        Items returned are (keyid, SubKey) tuples.

        :returns: a generator yielding (keyid, SubKey) tuples.
        :rtype: :type:`generator`

        Usage::

            >>> gpg.keys.public.current.values()
            <generator object Key.values at 0x...>
        """
        for key, value in self._get_subkeys().items():
            yield key, value


_key_factory = Factory(Key, _DEFAULT_KEY_FACTORY_NAME)


@implementer(iface.IKeylist)
@zope.component.adapter(gnupg.ListKeys)
@attr.s(repr=False, hash=True)
class _Keylist:
    """
    List of keys from keyring.

    **List is exposed with a dictionary-like interface.**

    :param gnupg.ListKeys keylist: the raw keylist.
    :returns: the GPG Keylist object.
    :rtype: instance of :class:`._Keylist`.
    :raises: :exc:`TypeError`: if validation fails for params.
    """

    _keylist: gnupg.ListKeys = attr.ib(
        repr=False, hash=False, validator=instance_of(gnupg.ListKeys)
    )
    type: str = attr.ib(init=False, default="")

    _key_class: iface.IKey = Key
    _wrapped: dict = None
    _raise_on_none = object()

    def __attrs_post_init__(self):
        self._wrapped = self._keylist.keyonly_map = {
            key["fingerprint"]: key for key in self._keylist
        }

    def __repr__(self):
        current = getattr(self.current, "fingerprint", self.current)
        atts = dict(type=self.type, items=len(self._wrapped), current=current)
        atts = ", ".join(f"{k}={v!r}" for k, v in atts.items())
        return f"{type(self).__name__}({atts})"

    @property
    def current(self):
        """The current/default key in this keylist."""
        key = self._keylist.curkey or dict()
        fingerprint = key.get("fingerprint")
        return self.get(fingerprint, default=None) if fingerprint else None

    @property
    def fingerprints(self):
        """A list of all key fingerprints in this keylist."""
        return list(self._wrapped.keys())

    @cachetools.func.ttl_cache(ttl=600)
    def _get_keys(self):
        return {key: self.get(key) for key in self._wrapped}

    def get(self, key, default=None):
        """Return Key for fingerprint matching key in this keylist.

        If no key found, return value of `default`.

        :param str key: the fingerprint of the key to return.
        :keyword Any default: default to return if key not found in list.

        :returns: the Key object.
        :rtype: instance of class providing :class:`.iface.IKey`.

        .. Usage::

            >>> gpg.keys.public.get('8633FAEDE49860D8DF498C98C1B6DDBF7B750422')
            Key(..., fingerprint='8633FAEDE49860D8DF498C98C1B6DDBF7B750422')
        """
        keydata = self._wrapped.get(key, default)
        if keydata == self._raise_on_none:
            raise KeyError
        elif keydata == default:
            return keydata
        try:
            return zope.component.createObject(
                _DEFAULT_KEY_FACTORY_NAME, **keydata
            )
        except zope.component.ComponentLookupError:
            return self._key_class(**keydata)

    @passthru
    def __len__(self):
        """Return number of keys in this list."""

    @passthru
    def __contains__(self, key):
        """Test inclusion of key fingerprint matching key in this keylist."""

    def __getitem__(self, key):
        """Return Key for fingerprint matching key in this keylist.

        :param str key: the key fingerprint.
        :returns: the key matching fingerprint.
        :rtype: instance of class providing :class:`iface.IKey`.
        :raises: :exc:`IndexError` if key not found.
        """
        key = self._wrapped[key]
        return self.get(key["fingerprint"], default=self._raise_on_none)

    def __iter__(self):
        """Return generator yielding Key objects for all keys in this list."""
        return self.values()

    @passthru
    def keys(self):
        """Return generator yielding fingerprints of keys in this list.

        :returns: a generator yielding Key fingerprints.
        :rtype: :type:`generator`.

        .. Usage::

            >>> gpg.keys.public.keys()
            dict_keys([...])
        """
        pass

    def values(self):
        """Return generator yielding Keys of keys in this list.

        :returns: a generator yielding Key objects.
        :rtype: :type:`generator`.
        
        .. Usage::

            >>> gpg.keys.public.values()
            <generator object _Keylist.values at 0x...>
        """
        for value in self._get_keys().values():
            yield value

    def items(self):
        """Return generator yielding item tuples for keys in this list.

        Items returned are (fingerprint, Key) tuples.

        :returns: a generator yielding (fingerprint, Key object) tuples.
        :rtype: :type:`generator`.
        
        .. Usage::

            >>> gpg.keys.public.items()
            <generator object _Keylist.items at 0x...>
        """
        for key, val in self._get_keys().items():
            yield key, val


@implementer(iface.IKeyring)
@zope.component.adapter(iface.IGPG)
@attr.s(hash=True, repr=False)
class Keyring:
    """An object manager for a GPG Keyring."

    :param .iface.IGPG gpg: the current GPG instance.

    :returns: the keyring object.
    :rtype: instance of :class:`.Keyring`.
    :raises: :exc:`TypeError`: if validation fails for params.
    """
    _gpg: iface.IGPG = attr.ib(
        repr=False, hash=False, validator=provides(iface.IGPG)
    )

    _keylist_class = _Keylist

    _keygen_defaults = dict(
        key_type="RSA", subkey_type="RSA", expire_date=0, name_email="<None>"
    )

    def __repr__(self):
        atts = dict(
            public=f"{len(self.public)} keys",
            secret=f"{len(self.secret)} keys",
        )
        atts = ", ".join(f"{k}={v!r}" for k, v in atts.items())
        return f"{type(self).__name__}({atts})"

    @cachetools.func.ttl_cache(ttl=300)
    def _load(self, secret=False, event=True):
        """Return list of secret/public keys.

        :keyword bool secret: whether to return `secret` keys,
            (optional, default: False).

        :returns: a list of (secret/public) gpg keys.
        :rtype: an instance of :class:`gnupg.ListKeys`.
        :emits: an :term:`event` of :class:`.events.KeysLoaded`.

        .. note::

            Be sure to invalidate this cache when the underlying data is
            changed by emitting a :term:`event` of
            :class:`.events.KeyCacheExpiry`.
        """
        keys = self._gpg._gpg.list_keys(secret=secret)

        if event:
            event = events.KeysLoaded(self._gpg, util.key_type(secret), keys)
            zope.component.handle(event)
        return keys

    def _get_list(self, secret=False, event=True):
        keylist = self._load(secret=secret, event=event)
        try:
            result = iface.IKeylist(keylist)
        except TypeError:
            result = self._keylist_class(keylist)
        result.type = util.key_type(secret)
        return result

    def get(self, fingerprint=None, secret=False, event=True):
        """Return list of or requested secret/public key(s).

        If fingerprint provided, return that key, otherwise return entire
        secret/public keyring depending on value of `secret`

        :keyword Optional[str, Iterable[str]] fingerprint: the
            fingerprint/iterable of to return keys for, if provided.
            Optional (default: None).
        :keyword bool secret: whether to return secret keys or not. Optional
            (default: False).

        :returns: the key or iterable of keys requested.
        :rtype: instance providing :class:`.iface.IKey` or
            :class:`.iface.IKeylist`.

        .. Usage::

            >>> gpg.keys.get()
            _Keylist(type='public', items=1, current='...')
        """
        result = self._get_list(secret=secret, event=event)
        if fingerprint:
            if isinstance(fingerprint, (list, tuple)):
                result = [result[fp] for fp in fingerprint]
            else:
                result = result[fingerprint]
        return result

    @property
    def public(self):
        """Return keylist of all keys in public keyring."""
        return self.get(secret=False, event=False)

    @property
    def secret(self):
        """Return keylist of all keys in secret keyring."""
        return self.get(secret=True, event=False)

    @expires_cache
    def generate(self, passphrase=None, event=True, **kwargs):
        """Generate new keypair.

        Generates gpg key_input string using kwargs, then generates new
        keypair.

        :keyword Optional[str] passphrase: the passphrase to use for automated
            key generation. Optional (default: None).
        :returns: Key object for the generated keypair.
        :rtype: instance of :class:`.keys.Key`.
        :raises: :exc:`.exc.KeyGenerateError` if key generation encounters
            an error.
        :emits:
            an :term:`event` of :class:`.events.BeforeGenerateKey` before key
                generation.
            an :term:`event` of :class:`.events.AfterGenerateKey` after key
                generation.

        .. note::

            key_types: RSA, ECDSA, etc
            subkey_types: RSA, DSA, ECDH, ELG-E etc
            curves: nistp256, etc

        .. Usage::

            >>> gpg.keys.generate(passphrase='test')
            Key(...)

            >>> opts = dict(key_type='ECDSA', subkey_type='ECDH',
            ...             key_curve='nistp256', subkey_curve='nistp256')
            >>> gpg.keys.generate(passphrase='test', **opts)
            Key(..., algo=19, ..., curve='nistp256', ...)
        """
        options = util.setdefaults(kwargs, self._keygen_defaults)

        gpg_opts = self._gpg._gpg.options
        if passphrase:
            options["Passphrase"] = passphrase
        if "--debug-quick-random" in gpg_opts or "--quick-random" in gpg_opts:
            options["Name-Comment"] = "A test user (insecure!)"

        if event:
            event = events.BeforeGenerateKey(self._gpg, options)
            zope.component.handle(event)
            options = event.options

        cmd = self._gpg._gpg.gen_key_input(**options)
        result = self._gpg._gpg.gen_key(cmd)
        if not result.fingerprint and "KEY_CREATED" not in result.stderr:
            raise exc.KeyGenerateError(
                "Error generating key: %s" % result.stderr
            )
        key = self.get(result.fingerprint)
        if event:
            event = events.AfterGenerateKey(self._gpg, cmd, result, key)
            zope.component.handle(event)
        return key

    def export(self, keys=None, secret=False, event=True, **kwargs):
        """Export key(s).

        If `keys` not provided, defaults to current/default key.

        To export a secret key(s), `secret` must be True.
        Exported key(s) are directly returned as an ascii-armored string in
        pem format.

        :keyword Optional[str, Iterable[str]] keys: the fingerprint/key
            object or "iterable of" to export, if provided. Defaults to
            current/default key. Optional (default: None).
        :keyword bool secret: whether to export secret key/keys.
            Optional (default: False).

        :returns: pem encoded keydata.
        :rtype: :type:`str`.
        :raises: :exc:`.exc.KeysExportError` if key export encounters an error.
        :emits: an :term:`event` of :class:`.events.KeysExported`.

        .. Usage::

            >>> gpg.keys.export()
            '-----BEGIN PGP PUBLIC KEY BLOCK-----...'

            >>> gpg.keys.export(secret=True, passphrase='test',
            ...                 expect_passphrase=True)
            '-----BEGIN PGP PRIVATE KEY BLOCK-----...'
        """

        keys = util.parse_fingerprints(
            keys or (self.secret.current if secret else self.public.current)
        )
        kwargs = util.setdefaults(
            kwargs,
            dict(expect_passphrase=kwargs.get("passphrase", False) and secret),
        )
        result = self._gpg._gpg.export_keys(keys, secret=secret, **kwargs)
        if (
            "EXPORT_RES 1" not in result.stderr
            or "error" in result.stderr.lower()
        ):
            raise exc.KeysExportError(
                "Error exporting key {}".format(result.stderr)
            )
        if event:
            keys = self.get(keys, secret=secret)
            event = events.KeysExported(self._gpg, result, keys)
            zope.component.handle(event)
        return result.data

    @expires_cache
    def import_(self, keydata, trust=None, event=True, **kwargs):
        """Import key(s) from string.

        Provide keys to import as string `keydata`, in ascii-armored pem
        format.

        If `trust` is not None, mark imported keys with that trust level.

        :param str keydata: text blob with pem encode keydata to import.
        :keyword Optional[Union[Levels, str]] trust: trust level to assign
            imported keys. Optional (default: None).

        :returns: the key if successful, else False.
        :rtype: an instance providing :class:`.iface.IKey` if successful,
            else :type:`bool`.
        :raises: :exc:`.exc.KeysImportError` if key import encounters an error.
        :emits: an :term:`event` of :class:`.events.KeysImported`.

        .. note::

            Trust levels can either be strings such as 'TRUST_UNDEFINED' or
            constants from :mod:`gpgkeyring.trust` such as
            `gpgkeyring.trust.UNDEFINED`.

            Trust levels: 'UNDEFINED', 'NEVER', 'MARGINAL', 'FULLY', 'ULTIMATE'

        .. Usage::

            >>> gpg.keys.import_(keystring)
            Key(..., fingerprint='9AA5F22015C277FE95DF45922E597A662E2C9C9E')
        """
        result = self._gpg._gpg.import_keys(keydata, **kwargs)
        success = all([bool(int(r["ok"])) for r in result.results])
        if not success:
            errors = [r["text"] for r in result.results if r["ok"] != "1"]
            raise exc.KeysImportError(
                "Error import key(s), errors: {} {}".format(
                    errors, result.stderr
                )
            )

        result.fingerprints = list(set(result.fingerprints))
        if trust:
            result.trust = self.trust(result.fingerprints, level=trust)

        keys = self.get(result.fingerprints)
        if event:
            event = events.KeysImported(self._gpg, result, keys)
            zope.component.handle(event)
        return keys if success else success

    @expires_cache
    def trust(self, keys=None, level=trust.UNDEFINED, event=True, **kwargs):
        """Trust key(s) as given level.

        If `keys` not provided, defaults to current/default key.

        :param Optional[str, Iterable[str]] keys: the fingerprint/key object
            or "iterable of" to trust. Optional (default: None).
        :keyword str level: trust level to assign imported keys.
            (default: trust.UNDEFINED).

        :returns: an interable of Key objects if successful, else False.
        :rtype: an instance providing :class:`.iface.IKey` or iterable of if
            successful, else :type:`bool`.
        :raises: :exc:`.exc.KeysTrustError` if key trust operation encounters
            an error.
        :emits: an :term:`event` of :class:`.events.KeysTrusted`.

        .. note::

            Trust levels can either be strings such as 'TRUST_UNDEFINED' or
            constants from :mod:`gpgkeyring.trust` such as
            `gpgkeyring.trust.UNDEFINED`.

            Trust levels: 'UNDEFINED', 'NEVER', 'MARGINAL', 'FULLY', 'ULTIMATE'

        .. Usage::

            >>> gpg.keys.trust(gpg.keys.public.current, 'TRUST_UNDEFINED')
            Key(..., ownertrust=<Levels: UNDEFINED>, ...)
        """
        keys = util.parse_fingerprints(keys or self.public.current)
        try:
            result = self._gpg._gpg.trust_keys(keys, level, **kwargs)
        except ValueError as err:
            raise exc.KeysTrustError("Internal error: {}".format(err)) from err
        success = "error" not in result.stderr
        if not success:
            raise exc.KeysTrustError(
                "Error trusting key, status: {} {}".format(
                    result.status, result.stderr
                )
            )
        # have to expire cache here to get key with updated trust level
        self._load.cache_clear()
        keys = self.get(keys)
        if event:
            event = events.KeysTrusted(self._gpg, result, keys)
            zope.component.handle(event)
        return keys if success else success

    @expires_cache
    def delete(self, keys=None, secret=False, event=True, **kwargs):
        """Delete key(s).

        If `keys` not provided, defaults to current/default key.

        To delete a secret key, `secret` should be Trust.

        :param Optional[str, Iterable[str]] keys: fingerprint/key object or
            "iterable of" keys to delete. Defaults to current/default key.
            Optional (default: None).
        :keyword bool secret: whether to delete secret keys.
            Optional (default: False).

        :returns: whether key delete succeeded.
        :rtype: :type:`bool`
        :raises: :exc:`.exc.KeysDeleteError` if key delete encounters an error.
        :emits: an :term:`event` of :class:`.events.KeysDeleted`.

        .. note::

            * If both public and secret keys exist, secret must be deleted
              first.
            * Deleting secret key does not automatically delete the public key.

        .. Usage::

            >>> gpg.keys.delete(secret=True, passphrase='test')
            True

            >>> gpg.keys.delete()
            True
        """
        kwargs = util.setdefaults(
            kwargs,
            dict(expect_passphrase=kwargs.get("passphrase", False) and secret),
        )
        keys = util.parse_fingerprints(
            keys or (self.secret.current if secret else self.public.current)
        )
        if event:
            _old_keys = self.get(keys, secret=secret)
        result = self._gpg._gpg.delete_keys(keys, secret=secret, **kwargs)
        success = result.status == "ok" and "failed" not in result.stderr
        if not success:
            raise exc.KeysDeleteError(
                "Error deleting key, status: {} {}".format(
                    result.status, result.stderr
                )
            )
        if event:
            event = events.KeysDeleted(self._gpg, result, _old_keys)
            zope.component.handle(event)
        return success

    def send(self, keys=None, keyserver=None, event=True):
        """Send key(s) to keyserver.

        If `keys` not provided, defaults to current/default key.

        Sends key to keyserver `keyserver`

        :param Optional[str, Iterable[str]] keys: the fingerprint/key object
            or "iterable of" keys to delete. Optional (default: None).
        :keyword str keyserver: keyserver to send keys to.
            (default: "pool.sks-keyservers.net").

        :returns: whether key send operation succeeded.
        :rtype: :type:`bool`.
        :raises: :exc:`.exc.KeysSendError` if sending key encounters an error.
        :emits: an :term:`event` of :class:`.events.KeysSentToServer`.

        .. Usage::

            >>> gpg.keys.send()
            True
        """
        keys = util.parse_fingerprints(keys or self.public.current)
        keyserver = keyserver or self._gpg._defaults["keyserver"]
        result = self._gpg._gpg.send_keys(keyserver, keys)
        success = "sending key" in result.stderr
        if not success:
            raise exc.KeysSendError(
                "Error sending key to keyserver, server: {} {}".format(
                    keyserver, result.stderr
                )
            )
        if event:
            event = events.KeysSentToServer(self._gpg, result, self.get(keys))
            zope.component.handle(event)
        return success

    @expires_cache
    def receive(self, keys, keyserver=None, trust=None, event=True):
        """Receive key(s) from keyserver.

        Requests key(s) in `keys` from keyserver `keyserver` and adds to
        keyring.

        :param Optional[str, Iterable[str]] keys: the fingerprint/keyid
            or "iterable of" to receive.
        :keyword str keyserver: keyserver to request keys from.
            (default: "pool.sks-keyservers.net").
        :keyword Optional[str] trust: trust level to assign received keys.
            (default: gpgkeyring.trust.UNDEFINED).

        :returns: key or iterable of keys if successful, else False.
        :rtype: an instance providing :class:`.iface.IKey` or iterable of if
            successful, else :type:`bool`.
        :raises: :exc:`.exc.KeysReceiveError` if sending key encounters an
            error.
        :emits: an :term:`event` of :class:`.events.KeysReceivedFromServer`.

        .. note::

            Trust levels can either be strings such as 'TRUST_UNDEFINED' or
            constants from :mod:`gpgkeyring.trust` such as
            `gpgkeyring.trust.UNDEFINED`.

            Trust levels: 'UNDEFINED', 'NEVER', 'MARGINAL', 'FULLY', 'ULTIMATE'

        .. Usage::

            >>> gpg.keys.receive("FD431D51")
            Key(..., ownertrust=...UNKNOWN... fingerprint='...FD431D51')

            >>> gpg.keys.receive("FEEDCFCE", trust="TRUST_FULLY")
            Key(..., ownertrust=...FULLY... fingerprint='...FEEDCFCE')
        """
        keys = util.parse_fingerprints(keys)
        keyserver = keyserver or self._gpg._defaults["keyserver"]
        result = self._gpg._gpg.recv_keys(keyserver, keys)
        success = all(
            [int(r["ok"]) for r in result.results]
            + [len(result.results) == result.imported]
        )
        if not success:
            errors = [r["text"] for r in result.results if r["ok"] != "1"]
            raise exc.KeysReceiveError(
                "Error receiving key(s) from keyserver: {} {} {}".format(
                    keyserver, errors, result.stderr
                )
            )
        if trust:
            keys = self.trust(result.fingerprints, level=trust)
        else:
            keys = self.get(result.fingerprints)
        if event:
            event = events.KeysReceivedFromServer(self._gpg, result, keys)
            zope.component.handle(event)
        return keys if success else success
