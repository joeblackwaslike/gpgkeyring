"""
gpgkeyring.metaconfigure
~~~~~~~~~~~~~~~~~~~

Custom ZCML directive processing.

:copyright: (c) 2018 by Joseph Black.
:license: MIT, see LICENSE for more details.

.. module:: gpgkeyring.metaconfigure
.. moduleauthor:: Joseph Black <me@joeblack.nyc>
"""

from zope.component import provideUtility
from zope.component.zcml import ComponentConfigurationError
from gpgkeyring.interfaces import IGPG


def _register_gpg_service(
    factory, name, gnupghome, verbose, useagent, keyring, gpgbinary, encoding
):
    options = dict(
        gnupghome=gnupghome,
        verbose=verbose,
        use_agent=useagent,
        keyring=keyring,
        gpgbinary=gpgbinary,
        encoding=encoding,
    )
    gpg = factory(options, name)
    provideUtility(gpg, IGPG, name=name)


def gpgKeyringHandler(
    _context,
    factory,
    name="",
    gnupghome="~/.gnupg",
    verbose=False,
    useagent=True,
    keyring=None,
    keyserver="pool.sks-keyservers.net",
    gpgbinary="gpg2",
    encoding="utf-8",
):

    factories = factory
    if len(factories) == 1:
        factory = factories[0]
    elif len(factories) < 1:
        raise ComponentConfigurationError("No factory specified")
    elif len(factories) > 1 and len(for_) != 1:
        raise ComponentConfigurationError(
            "Can't use multiple factories and multiple for"
        )
    else:
        factory = zope.component.zcml._rolledUpFactory(factories)

    _context.action(
        discriminator=("gpgService", factory, name),
        callable=_register_gpg_service,
        args=(
            factory,
            name,
            gnupghome,
            verbose,
            useagent,
            keyring,
            keyserver,
            gpgbinary,
            encoding,
        ),
    )

    _context.action(
        discriminator=None,
        callable=zope.component.provideInterface,
        args=("", provides),
    )
