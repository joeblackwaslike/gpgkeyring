"""
:mod:`gpgkeyring.patches`
~~~~~~~~~~~~~~~~~~~~

Necessary monkey-patches to mod `gnupg`.

:copyright: (c) 2018 by Joseph Black.
:license: MIT, see LICENSE for more details.

.. module:: gpgkeyring.patches
.. moduleauthor:: Joseph Black <me@joeblack.nyc>
"""

import gnupg


def patch_export_keys():
    """Patch :meth:`gnupg.GPG.export_keys`.

    Reason: Currently, it overwrites the result object with data.
    """

    def export_keys(
        self,
        keyids,
        secret=False,
        armor=True,
        minimal=False,
        passphrase=None,
        expect_passphrase=True,
    ):
        """
        Export the indicated keys. A 'keyid' is anything gpg accepts.

        Since GnuPG 2.1, you can't export secret keys without providing a
        passphrase. However, if you're expecting the passphrase to go to gpg
        via pinentry, you should specify expect_passphrase=False. (It's only
        checked for GnuPG >= 2.1).
        """

        which = ""
        if secret:
            which = "-secret-key"
            if (
                self.version >= (2, 1)
                and passphrase is None
                and expect_passphrase
            ):
                raise ValueError(
                    "For GnuPG >= 2.1, exporting secret keys "
                    "needs a passphrase to be provided"
                )
        if gnupg._is_sequence(keyids):
            keyids = [gnupg.no_quote(k) for k in keyids]
        else:
            keyids = [gnupg.no_quote(keyids)]
        args = ["--export%s" % which]
        if armor:
            args.append("--armor")
        if minimal:
            args.extend(["--export-options", "export-minimal"])
        args.extend(keyids)
        result = self.result_map["export"](self)
        if not secret or self.version < (2, 1):
            p = self._open_subprocess(args)
            self._collect_output(p, result, stdin=p.stdin)
        else:
            f = gnupg._make_binary_stream("", self.encoding)
            try:
                self._handle_io(
                    args, f, result, passphrase=passphrase, binary=True
                )
            finally:
                f.close()
        gnupg.logger.debug("export_keys result: %r", result.data)
        if armor:
            result.data = result.data.decode(self.encoding, self.decode_errors)
        return result

    gnupg.GPG.export_keys = export_keys


def patch_delete_keys():
    """Patch :meth:`gnupg.GPG.delete_keys`.

    Reason: currently its broken when deleting a secret key with passphrase.
    """

    def delete_keys(
        self,
        fingerprints,
        secret=False,
        passphrase=None,
        expect_passphrase=True,
    ):
        """
        Delete the indicated keys.

        Since GnuPG 2.1, you can't delete secret keys without providing a
        passphrase. However, if you're expecting the passphrase to go to gpg
        via pinentry, you should specify expect_passphrase=False. (It's only
        checked for GnuPG >= 2.1).
        """
        which = "key"
        if secret:  # pragma: no cover
            if (
                self.version >= (2, 1)
                and passphrase is None
                and expect_passphrase
            ):
                raise ValueError(
                    "For GnuPG >= 2.1, deleting secret keys "
                    "needs a passphrase to be provided"
                )
            which = "secret-key"
        if gnupg._is_sequence(fingerprints):  # pragma: no cover
            fingerprints = [gnupg.no_quote(s) for s in fingerprints]
        else:
            fingerprints = [gnupg.no_quote(fingerprints)]
        args = []
        if secret and passphrase and expect_passphrase:
            args = ["--yes"]
        args.append("--delete-%s" % which)
        args.extend(fingerprints)
        result = self.result_map["delete"](self)
        if not secret or self.version < (2, 1):
            p = self._open_subprocess(args)
            self._collect_output(p, result, stdin=p.stdin)
        else:
            # Need to send in a passphrase.
            f = gnupg._make_binary_stream("", self.encoding)
            try:
                self._handle_io(
                    args, f, result, passphrase=passphrase, binary=True
                )
            finally:
                f.close()
        return result

    gnupg.GPG.delete_keys = delete_keys


def patch_gen_key_input():
    """Patch :meth:`gnupg.GPG.gen_key_input`.

    Reason: to remove Key-Length from defaults in order to generate ECC keys.
    """
    import os
    import socket

    def gen_key_input(self, **kwargs):
        """
        Generate --gen-key input per gpg doc/DETAILS
        """
        parms = {}
        for key, val in list(kwargs.items()):
            key = key.replace("_", "-").title()
            if str(val).strip():  # skip empty strings
                parms[key] = val
        parms.setdefault("Key-Type", "RSA")
        # parms.setdefault("Key-Length", 2048)
        parms.setdefault("Name-Real", "Autogenerated Key")
        logname = (
            os.environ.get("LOGNAME")
            or os.environ.get("USERNAME")
            or "unspecified"
        )
        hostname = socket.gethostname()
        parms.setdefault(
            "Name-Email", "%s@%s" % (logname.replace(" ", "_"), hostname)
        )
        out = "Key-Type: %s\n" % parms.pop("Key-Type")
        for key, val in list(parms.items()):
            out += "%s: %s\n" % (key, val)
        out += "%commit\n"
        return out

    gnupg.GPG.gen_key_input = gen_key_input


def patch():
    """Apply all patches."""
    patch_export_keys()
    patch_delete_keys()
    patch_gen_key_input()


patch()
