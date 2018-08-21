"""
:mod:`gpgkeyring.exceptions`
~~~~~~~~~~~~~~~~~~~~

Exception and error classes.

:copyright: (c) 2018 by Joseph Black.
:license: MIT, see LICENSE for more details.

.. module:: gpgkeyring.exceptions
.. moduleauthor:: Joseph Black <me@joeblack.nyc>
"""

__all__ = [
    "GPGKeyringRootError",
    "MessageEncryptError",
    "MessageDecryptError",
    "MessageSignError",
    "MessageVerifyError",
    "KeyGenerateError",
    "KeysExportError",
    "KeysImportError",
    "KeysTrustError",
    "KeysDeleteError",
    "KeysSendError",
    "KeysReceiveError",
]


class GPGKeyringBaseError(Exception):
    """Root Exception class for package."""


class MessageEncryptError(RuntimeError, GPGKeyringBaseError):
    """Error encrypting a message."""


class MessageDecryptError(RuntimeError, GPGKeyringBaseError):
    """Error decrypting a message."""


class MessageSignError(RuntimeError, GPGKeyringBaseError):
    """Error signing a message."""


class MessageVerifyError(RuntimeError, GPGKeyringBaseError):
    """Error verifying a message."""


class KeyGenerateError(ValueError, GPGKeyringBaseError):
    """Error generating GPG Key."""


class KeysExportError(RuntimeError, GPGKeyringBaseError):
    """Error exporting a key."""


class KeysImportError(RuntimeError, GPGKeyringBaseError):
    """Error importing a key."""


class KeysTrustError(RuntimeError, GPGKeyringBaseError):
    """Error trusting a key."""


class KeysDeleteError(RuntimeError, GPGKeyringBaseError):
    """Error deleting a key."""


class KeysSendError(RuntimeError, GPGKeyringBaseError):
    """Error sending a key to keyserver."""


class KeysReceiveError(RuntimeError, GPGKeyringBaseError):
    """Error receiving a key from keyserver."""
