"""
gpgkeyring.metadirectives
~~~~~~~~~~~~~~~~~~~~

Custom ZCML directive schemas.

:copyright: (c) 2018 by Joseph Black.
:license: MIT, see LICENSE for more details.

.. module:: gpgkeyring.metadirectives
.. moduleauthor:: Joseph Black <me@joeblack.nyc>
"""

from zope.interface import Interface
from zope import schema
from zope.configuration import fields


class IGPGKeyringDirective(Interface):
    '""Schema for GPGService directive.""'
    factory = fields.Tokens(
        title="Dotted Path to component factory/factories",
        required=True,
        value_type=fields.GlobalObject(),
    )
    name = schema.TextLine(title="GPG Name", default="", required=False)
    gnupghome = schema.TextLine(
        title="GnuPG Home Directory", default="~/.gnupg", required=False
    )
    verbose = schema.Bool(title="Verbose", default=False, required=False)
    useagent = schema.Bool(title="Use GPG Agent", default=True, required=False)
    keyring = schema.TextLine(
        title="Keyring filename", default=None, required=False
    )
    keyserver = schema.TextLine(
        title="Keyserver", required=False, default="pool.sks-keyservers.net"
    )
    gpgbinary = schema.TextLine(
        title="GPG Binary", default="gpg2", required=False
    )
    encoding = schema.TextLine(
        title="Default encoding", default="utf-8", required=False
    )
