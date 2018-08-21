# pylint: disable=inherit-non-class,no-self-argument,no-method-argument
# pylint: disable=unexpected-special-method-signature,arguments-differ

"""
:mod:`gpgkeyring.interfaces`
~~~~~~~~~~~~~~~~~~~~

Zope interfaces and schemas.

:copyright: (c) 2018 by Joseph Black.
:license: MIT, see LICENSE for more details.

.. module:: gpgkeyring.interfaces
.. moduleauthor:: Joseph Black <me@joeblack.nyc>
"""

from zope.interface import Interface, Attribute

from . import trust

__all__ = ["IGPG", "IKeyring", "IKeylist", "IKey", "ISubKey"]


class IGPGFactory(Interface):
    """Creates an instance of a class implementing :class:`.IGPG`."""

    def __call__(name=""):
        """Return GPG instance."""


class IGPG(Interface):
    """An object wrapping `gnupg.GPG` instance."""

    name = Attribute("Name to register utility as in ZCA, (default: '')")
    keys = Attribute(
        "Instance of class implementing :class:`gpgkeyring.IKeyring`."
    )
    version = Attribute("A tuple of version for gpg binary.")

    def encrypt(
        message, key=None, symmetric=False, sign=True, event=True, **kwargs
    ):
        """Return encrypted message.

        Message is encrypted using `key`, with options: `symmetric`, `sign`,
        etc.
        """

    def decrypt(ciphertext, event=True, **kwargs):
        """Return decrypted ciphertext."""

    def sign(message, key=None, event=True, **kwargs):
        """Return signed message.

        Message is signed using `key` if provided, otherwise key defaults to
        current/default key.
        """

    def verify(message, event=True, **kwargs):
        """Return whether message is signed properly."""


class IKeyring(Interface):
    """An object manager for a GPG Keyring."""

    public = Attribute("The list of public keys in keyring.")
    secret = Attribute("The list of secret keys in keyring.")

    def _load(secret=False, event=True):
        """Return list of secret/public keys."""

    def get(fingerprint=None, secret=False):
        """Return list of or requested secret/public key(s).

        If fingerprint provided, return that key, otherwise return entire
        secret/public keyring depending on value of `secret`
        """

    def generate(event=True, **kwargs):
        """Generate new keypair.

        Generates gpg key_input string using kwargs, then generates new
        keypair.
        """

    def export(keys=None, secret=False, event=True, **kwargs):
        """Export key(s).

        If `keys` not provided, defaults to current/default key.

        To export a secret key(s), `secret` must be True.
        Exported key(s) are directly returned as an ascii-armored string in
        pem format.
        """

    def import_(keydata, trust=None, event=True, **kwargs):
        """Import key(s) from string.

        Provide keys to import as string `keydata`, in ascii-armored pem
        format.
        
        If `trust` is not None, mark imported keys with that trust level.
        
        .. note::

            Trust levels can either be strings such as 'TRUST_UNDEFINED' or
            constants from :mod:`gpgkeyring.trust` such as
            `gpgkeyring.trust.UNDEFINED`.
        """

    def trust(keys=None, level=trust.UNDEFINED, event=True, **kwargs):
        """Trust key(s) as given level.

        If `keys` not provided, defaults to current/default key.

        .. note::

            Trust levels can either be strings such as 'TRUST_UNDEFINED' or
            constants from :mod:`gpgkeyring.trust` such as
            `gpgkeyring.trust.UNDEFINED`.
        """

    def delete(keys=None, secret=False, event=True, **kwargs):
        """Delete key(s).

        If `keys` not provided, defaults to current/default key.

        To delete a secret key, `secret` should be Trust.

        .. note::

            * If both public and secret keys exist, secret must be deleted first.
            * Deleting secret key does not automatically delete the public key.
        """

    def send(keys=None, keyserver="pool.sks-keyservers.net", event=True):
        """Send key(s) to keyserver.

        If `keys` not provided, defaults to current/default key.

        Sends key to keyserver `keyserver`.
        """

    def receive(
        keys, keyserver="pool.sks-keyservers.net", trust=None, event=True
    ):
        """Receive key(s) from keyserver.

        Requests key(s) in `keys` from keyserver `keyserver` and adds to keyring.

        .. note::

            Trust levels can either be strings such as 'TRUST_UNDEFINED' or
            constants from :mod:`gpgkeyring.trust` such as
            `gpgkeyring.trust.UNDEFINED`.
        """

    def __hash__():
        """Return hashable identifier for object instance.

        This object must be hashable to be cachable.
        """


class IKeylist(Interface):
    """List of keys from keyring.

    List is exposed with a dictionary-like interface.
    """

    current = Attribute("The current/default key in this keylist.")
    fingerprints = Attribute("A list of all key fingerprints in this keylist.")

    def __contains__(key):
        """Test inclusion of key fingerprint matching key in this keylist."""

    def __getitem__(key):
        """Return Key for fingerprint matching key in this keylist.

        If key not found, raise :exc:`IndexError`.
        """

    def __iter__():
        """Return generator yielding Key objects for all keys in this list."""

    def __len__():
        """Return number of keys in this list."""

    def get(key, default=None):
        """Return Key for fingerprint matching key in this keylist.

        If no key found, return value of `default`.
        """

    def keys():
        """Return generator yielding fingerprints of keys in this list."""

    def values():
        """Return generator yielding Keys of keys in this list."""

    def items():
        """Return generator yielding item tuples for keys in this list.

        Items returned are (fingerprint, Key) tuples.
        """


class IKey(Interface):
    """Key and associated subkey(s).

    Subkeys accessed through the attribute `subkeys` which is implemented as a
    dictionary-like interface. """

    type = Attribute("The key type.")
    trust = Attribute("The validity of the key.")
    length = Attribute("The length of the key in bits.")
    algo = Attribute("The key algorithm number.")
    keyid = Attribute("The key ID.")
    date = Attribute("The creation date as UTC timestamp.")
    expires = Attribute("The expiry date as UTC timestamp, if specified")
    dummy = Attribute(
        "The certificate serial number, UID hash or trust signature info."
    )
    ownertrust = Attribute("The level of owner trust for the key.")
    sig = Attribute("The signature class.")
    cap = Attribute("The key capabilities.")
    issuer = Attribute("The issuer information.")
    flag = Attribute("The flag field.")
    token = Attribute("The token serial number.")
    hash = Attribute("the hash algorithm.")
    curve = Attribute("The curve name if elliptic curve (ECC) key.")
    compliance = Attribute("The compliance flags.")
    updated = Attribute(
        "The last updated date as UTC timestamp, if specified."
    )
    origin = Attribute("The key origin.")
    uids = Attribute("The key user ID.")
    sigs = Attribute("")
    fingerprint = Attribute("The key fingerprint.")

    subkeys = Attribute(
        """Associated Keys, exposed through as a dictionary-like interface,
        keyed by subkey keyid value."""
    )

    def __contains__(key):
        """Test inclusion of subkey keyid in associated subkeys.

        Matches keyid values provided as `key`.
        """

    def __getitem__(key):
        """Return SubKey for fingerprint matching key in this keylist.

        If key not found, raise :exc:`IndexError`.
        """

    def __iter__():
        """Return generator yielding subkeys for this key."""

    def __len__():
        """Return number of subkeys for this key."""

    def get(key, default=None):
        """Return subkey for fingerprint matching key for this key.

        If no subkey found, return value of `default`.
        """

    def keys():
        """Return generator yielding keyids of subkeys for this key."""

    def values():
        """Return generator yielding subkeys for this key."""

    def items():
        """Return generator yielding item tuples of subkeys for this key.

        Items returned are (keyid, SubKey) tuples.
        """


class ISubKey(Interface):
    """A Subkey."""

    type = Attribute("The subkey type.")
    trust = Attribute("The validity of the subkey.")
    length = Attribute("The length of the subkey in bits.")
    algo = Attribute("The subkey algorithm number.")
    keyid = Attribute("The subkey ID.")
    date = Attribute("The creation date as UTC timestamp.")
    expires = Attribute("The expiry date as UTC timestamp, if specified")
    dummy = Attribute(
        "The certificate serial number, UID hash or trust signature info."
    )
    # ownertrust = Attribute("The level of owner trust for the subkey.")
    uid = Attribute("The subkey user ID.")
    sig = Attribute("The signature class.")
    cap = Attribute("The subkey capabilities.")
    issuer = Attribute("The issuer information.")
    flag = Attribute("The flag field.")
    token = Attribute("The token serial number.")
    hash = Attribute("the hash algorithm.")
    curve = Attribute("The curve name if elliptic curve (ECC) subkey.")
    compliance = Attribute("The compliance flags.")
    updated = Attribute(
        "The last updated date as UTC timestamp, if specified."
    )
    origin = Attribute("The subkey origin.")


# class IFileBytes(Interface):
#     """A file like python object representing a byte stream."""

#     closed = Attribute("Returns true if the stream is closed.")
#     mode = Attribute("The mode as given in the constructor.")
#     name = Attribute(
#         "The file name. This is the file descriptor of the file when no name "
#         "is given in the constructor."
#     )
#     raw = Attribute("The underlying raw stream.")

#     def close():
#         """Flush and close this stream."""

#     def fileno():
#         """Return the underlying flile descriptor if exists, else raise
#         OSError."""

#     def flush():
#         """Flush the write buffers if applicable."""

#     def isatty():
#         """Return True if the stream is interactive, aka connected to a
#         terminal/tty device."""

#     def readable():
#         """Return True if the stream can be read from."""

#     def readline(size=-1):
#         """Read and return one line from the stream, if size is specified, at
#         most size bytes will be read."""

#     def readlines(hint=-1):
#         """Read and return a list of lines from the stream. hint can be
#         specified to control the number of lines read: no more lines will be
#         read if the total size (in bytes/characters) of all lines so far
#         exceeds hint."""

#     def seek(offset, whence=None):
#         """Change the stream position to the given byte offset.

#         Offset is interpreted relative to the position indicated by whence.
#         The default value for whence is SEEK_SET. Values for whence are:

#             SEEK_SET or 0 – start of the stream (the default); offset should be
#                 zero or positive
#             SEEK_CUR or 1 – current stream position; offset may be negative
#             SEEK_END or 2 – end of the stream; offset is usually negative

#         Return the new absolute position.
#         """

#     def seekable():
#         """Return True if the stream supports random access."""

#     def tell():
#         """Return the current stream position."""

#     def truncate(size=None):
#         """Resize the stream to the given size in bytes (or the current
#         position if size is not specified).

#         The current stream position isn’t changed. This resizing can extend or
#         reduce the current file size. In case of extension, the contents of the
#         new file area depend on the platform (on most systems, additional bytes
#         are zero-filled). The new file size is returned.
#         """

#     def writable():
#         """Return True if the stream supports writing."""

#     def writelines(lines):
#         """Write a list of lines to the stream. Line separators are not added,
#         so it is usual for each of the lines provided to have a line separator
#         at the end."""

#     def detach():
#         """Separate the underlying raw stream from the buffer and return it."""

#     def read(size=-1):
#         """Read and return up to size bytes.

#         If the argument is omitted, None, or negative, data is read and
#         returned until EOF is reached. An empty bytes object is returned if the
#         stream is already at EOF.
#         """

#     def read1(size=-1):
#         """Read and return up to size bytes, with at most one call to the
#         underlying raw stream’s read() (or readinto()) method."""

#     def readinto(b):
#         """Read bytes into a pre-allocated, writable bytes-like object b and
#         return the number of bytes read."""

#     def readinto1(b):
#         """Read bytes into a pre-allocated, writable bytes-like object b.

#         Read bytes into a pre-allocated, writable bytes-like object b, using at
#         most one call to the underlying raw stream’s read() (or readinto())
#         method.

#         Return the number of bytes read.
#         """

#     def write(b):
#         """Write the given bytes-like object, b, and return the number of bytes
#         written.

#         Write the given bytes-like object, b, and return the number of bytes
#         written (always equal to the length of b in bytes, since if the write
#         fails an OSError will be raised). Depending on the actual
#         implementation, these bytes may be readily written to the underlying
#         stream, or held in a buffer for performance and latency reasons.
#         """

#     def peek(size=None):
#         """Return bytes from the stream without advancing the position.

#         At most one single read on the raw stream is done to satisfy the call.
#         The number of bytes returned may be less or more than requested.
#         """

#     def read(size=None):
#         """Read and return size bytes, or if size is not given or negative,
#         until EOF or if the read call would block in non-blocking mode."""

#     def read1(size):
#         """Read and return up to size bytes with only one call on the raw stream.

#         If at least one byte is buffered, only buffered bytes are returned.
#         Otherwise, one raw stream read call is made.
#         """


# class IFileText(Interface):
#     """A file like python object representing a stream of utf-8 encoded bytes.
#     """

#     closed = Attribute("Returns true if the stream is closed.")
#     buffer = Attribute(
#         "The underlying binary buffer (a BufferedIOBase instance) that "
#         "TextIOBase deals with."
#     )
#     encoding = Attribute(
#         "The name of the encoding used to decode the stream’s bytes into "
#         "strings, and to encode strings into bytes."
#     )
#     errors = Attribute("The error setting of the decoder or encoder.")
#     line_buffering = Attribute("Whether line buffering is enabled.")
#     name = Attribute(
#         "The file name. This is the file descriptor of the file when no "
#         "name is given in the constructor."
#     )
#     newlines = Attribute(
#         "A string, a tuple of strings, or None, indicating the newlines "
#         "translated so far."
#     )

#     def close():
#         """Flush and close this stream."""

#     def fileno():
#         """Return the underlying flile descriptor if exists.  Else raise
#         OSError."""

#     def flush():
#         """Flush the write buffers if applicable."""

#     def isatty():
#         """Return True if the stream is interactive, aka connected to a
#         terminal/tty device."""

#     def readable():
#         """Return True if the stream can be read from."""

#     def readline(size=-1):
#         """Read and return one line from the stream, if size is specified, at
#         most size bytes will be read."""

#     def readlines(hint=-1):
#         """Read and return a list of lines from the stream. hint can be
#         specified to control the number of lines read: no more lines will be
#         read if the total size (in bytes/characters) of all lines so far
#         exceeds hint."""

#     def seek(offset, whence=None):
#         """Change the stream position to the given byte offset.

#         Offset is interpreted relative to the position indicated by whence. The
#         default value for whence is SEEK_SET. Values for whence are:

#             SEEK_SET or 0 – start of the stream (the default); offset should be
#                 zero or positive
#             SEEK_CUR or 1 – current stream position; offset may be negative
#             SEEK_END or 2 – end of the stream; offset is usually negative

#         Return the new absolute position.
#         """

#     def seekable():
#         """Return True if the stream supports random access."""

#     def tell():
#         """Return the current stream position."""

#     def truncate(size=None):
#         """Resize the stream to the given size in bytes (or the current
#         position if size is not specified).

#         The current stream position isn’t changed. This resizing can extend or
#         reduce the current file size. In case of extension, the contents of the
#         new file area depend on the platform (on most systems, additional bytes
#         are zero-filled). The new file size is returned.
#         """

#     def writable():
#         """Return True if the stream supports writing."""

#     def writelines(lines):
#         """Write a list of lines to the stream. Line separators are not added,
#         so it is usual for each of the lines provided to have a line separator
#         at the end."""

#     def detach():
#         """Separate the underlying binary buffer from the TextIOBase and return
#         it."""

#     def read(size=None):
#         """Read and return at most size characters from the stream as a single
#         str.

#         If size is negative or None, reads until EOF.
#         """

#     def write(s):
#         """Write the string s to the stream and return the number of characters
#         written."""
