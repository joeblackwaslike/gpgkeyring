"""
:mod:`gpgkeyring.configure`
~~~~~~~~~~~~~~~~~~~~

GPG/Keychain related decorators.

:copyright: (c) 2018 by Joseph Black.
:license: MIT, see LICENSE for more details.

.. module:: gpgkeyring.configure
.. moduleauthor:: Joseph Black <me@joeblack.nyc>
"""

import sys

import zope.component
from zope.component.factory import IFactory
from zope.configuration import xmlconfig
import gnupg

from . import interfaces, gpg, keys

__all__ = ["basic", "custom", "zcml"]
_GSM = zope.component.getGlobalSiteManager()


def basic():
    """Do configuration basic with defaults for all args.

    .. Usage::

        >>> gpgkeyring.configure.basic()

    """
    custom()


def custom(
    gpg_factory=gpg._gpg_factory,
    keyring_adapter=keys.Keyring,
    keylist_adapter=keys._Keylist,
    key_factory=keys._key_factory,
    subkey_factory=keys._subkey_factory,
):
    """Do configuration with custom factories and adapters.

    :keyword IFactory gpg_factory: the GPG factory providing
        :class:`gpgkeyring.interfaces.IGPG`. Optional
        (default: :attr:`gpgkeyring.gpg._gpg_factory`)
    :keyword IKeyring keyring_adapter: the keyring adapter implementing
        :class:`gpgkeyring.interfaces.IKeyring`. Optional
        (default: :class:`gpgkeyring.keys.Keyring`)
    :keyword IKeylist keylist_adapter: the keylist adapter implementing
        :class:`gpgkeyring.interfaces.IKeylist`. Optional
        (default: :class:`gpgkeyring.keys._Keylist`)
    :keyword IFactory key_factory: the key factory providing
        :class:`gpgkeyring.interfaces.Key`. Optional
        (default: :attr:`gpgkeyring.keys._key_factory`)
    :keyword IFactory subkey_factory: the subkey factory providing
        :class:`gpgkeyring.interfaces.SubKey`. Optional
        (default: :attr:`gpgkeyring.keys._subkey_factory`)
    :returns: nothing.
    :rtype: :type:`None`.

    .. Usage::

        >>> gpgkeyring.configure.custom(
        ...     gpg_factory=gpgkeyring.gpg._gpg_factory)
    """
    _GSM.registerAdapter(keyring_adapter)
    _GSM.registerAdapter(keylist_adapter)

    _GSM.registerUtility(gpg_factory, name=gpg._DEFAULT_GPG_FACTORY_NAME)
    _GSM.registerUtility(key_factory, name=keys._DEFAULT_KEY_FACTORY_NAME)
    _GSM.registerUtility(
        subkey_factory, name=keys._DEFAULT_SUBKEY_FACTORY_NAME
    )


def zcml(file="configure.zcml", package=sys.modules[__package__]):
    """Do configuration using zcml.

    :keyword str file: the xml file to use for configuration.
        Optional (default: "configure.zcml").
    :keyword module package: the package to use for configuration.
        Optional (default: sys.modules[__package__]).

    :returns: nothing.
    :rtype: :type:`None`.

    .. Usage::

        >>> gpgkeyring.configure.zcml(file="configure.zcml",
        ...                           package=gpgkeyring)
    """
    xmlconfig.file(file, package)


def reset():
    """Reset zope component configuration.

    :returns: nothing.
    :rtype: :type:`None`.

    .. Usage::

        >>> gpgkeyring.configure.reset()
    """
    for required, provided in (
        (interfaces.IGPG, interfaces.IKeyring),
        (gnupg.ListKeys, interfaces.IKeylist),
    ):
        _GSM.unregisterAdapter(
            None, required=(required,), provided=(provided,)
        )

    for name in [
        gpg._DEFAULT_GPG_FACTORY_NAME,
        keys._DEFAULT_KEY_FACTORY_NAME,
        keys._DEFAULT_SUBKEY_FACTORY_NAME,
    ]:
        _GSM.unregisterUtility(provided=IFactory, name=name)
