from unittest import mock
from unittest.mock import sentinel

import gnupg


def patch_object(
    obj, method, return_value=None, side_effect=None, autospec=True
):
    return mock.patch.object(
        obj,
        method,
        autospec=autospec,
        return_value=return_value,
        side_effect=side_effect,
    )


def autospec(
    spec, spec_set=False, instance=None, _parent=None, _name=None, **kwargs
):
    if isinstance(spec, type) and not instance:
        instance = False
    elif spec.__class.__.__module__ == "builtins" and not instance:
        instance = True

    return mock.create_autospec(
        spec,
        spec_set=False,
        instance=False,
        _parent=None,
        _name=None,
        **kwargs
    )


def string(value, mocker=None):
    mocker = mocker or globals().get("mock") or __import__(
        "unittest.mock"
    ).mock

    def __str__():
        if isinstance(value, bytes):
            return value.decode()
        return str(value)

    return mocker.create_autospec(
        value, __str__=mocker.MagicMock(side_effect=__str__)
    )


class GPGDummy(gnupg.GPG):

    def __init__(
        self,
        gpgbinary="gpg",
        gnupghome=None,
        verbose=False,
        use_agent=False,
        keyring=None,
        options=None,
        secret_keyring=None,
    ):
        self.gpgbinary = gpgbinary
        self.gnupghome = gnupghome
        if keyring:
            if isinstance(keyring, (str, bytes)):
                keyring = [keyring]
        self.keyring = keyring
        if secret_keyring:
            if isinstance(secret_keyring, (str, bytes)):
                secret_keyring = [secret_keyring]
        self.secret_keyring = secret_keyring
        self.verbose = verbose
        self.use_agent = use_agent
        if isinstance(options, str):
            options = [options]
        self.options = options
        self.on_data = None
        self.encoding = "latin-1"
        self.version = (2, 2, 7)
