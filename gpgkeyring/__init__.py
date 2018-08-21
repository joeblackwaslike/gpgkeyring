"""
gpgkeyring
~~~~

GnuPGKeys tools/components for humans.

Fully featured key-management, encrypt/decrypt and sign/verify workflows.
ZCA component architecture allows easy extension/customization without
the necessity of editing any code.

:copyright: (c) 2018 by Joseph Black.
:license: MIT, see LICENSE for more details.

.. module:: gpgkeyring
.. moduleauthor:: Joseph Black <me@joeblack.nyc>
"""

__version__ = "1.0.0"

from . import (
    patches,
    exceptions,
    trust,
    interfaces,
    util,
    events,
    decorators,
    keys,
    gpg,
    configure,
)
from .gpg import GPG, create, get
