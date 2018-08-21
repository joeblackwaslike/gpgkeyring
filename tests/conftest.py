# pylint: disable=missing-docstring,redefined-outer-name,protected-access
# plint: disable=too-many-arguments

import sys

import pytest
import attr
import gpgkeyring

from .helpers import testdata, patching


@pytest.fixture
def undecorate_gpg(mocker):
    return mocker.patch(
        "gpgkeyring.gpg.GPG", patching.undecorate_class(gpgkeyring.gpg.GPG)
    )


@pytest.fixture
def undecorate_keyring(mocker):
    return mocker.patch(
        "gpgkeyring.keys.Keyring",
        patching.undecorate_class(gpgkeyring.keys.Keyring),
    )


@pytest.fixture
def undecorate_keylist(mocker):
    return mocker.patch(
        "gpgkeyring.keys._Keylist",
        patching.undecorate_class(gpgkeyring.keys._Keylist),
    )


@pytest.fixture
def undecorate_key(mocker):
    return mocker.patch(
        "gpgkeyring.keys.Key", patching.undecorate_class(gpgkeyring.keys.Key)
    )


@pytest.fixture
def undecorate_subkey(mocker):
    return mocker.patch(
        "gpgkeyring.keys.SubKey",
        patching.undecorate_class(gpgkeyring.keys.SubKey),
    )


@pytest.fixture(params=[True, False])
def secret(request):
    return request.param


@pytest.fixture(params=testdata.TRUST_LEVEL_VALUES + [None])
def trust_level(request):
    yield request.param


# @pytest.fixture(params=[True, False])
# def bools(request):
#     return request.param


# @pytest.fixture(params=[True, False])
# def bools2(request):
#     return request.param


# @pytest.fixture(params=[True, False])
# def bools3(request):
#     return request.param


@pytest.fixture
def mock_util_methods(mocker):
    for func in (
        "parse_keyids",
        "parse_fingerprints",
        "key_type",
        "setdefaults",
        "pop_attr",
    ):
        mocker.patch(
            "gpgkeyring.util.{}".format(func),
            autospec=getattr(gpgkeyring.util, func),
            side_effect=getattr(gpgkeyring.util, func),
        )
    for func in ("parse_fingerprints",):
        mocker.patch(
            "gpgkeyring.util.{}".format(func), side_effect=lambda x: x
        )


# @pytest.fixture
# def mock_zca(mocker, monkeypatch):
#     for pkg in ["gpg", "keys", "configure"]:
#         dotted_name = "gpgkeyring.{}".format(pkg)
#         zca_mock = mocker.MagicMock(sys.modules[dotted_name].zope.component)
#         monkeypatch.setattr(
#             sys.modules[dotted_name].zope, "component", zca_mock
#         )


@pytest.fixture
def disable_attr_validation():
    attr.set_run_validators(False)


@pytest.fixture(params=testdata.FINGERPRINTS)
def fingerprint(request):
    return request.param


@pytest.fixture(params=testdata.KEYIDS)
def keyid(request):
    return request.param


# @pytest.fixture(params=testdata.KEYS)
# def key(request):
#     return request.param


@pytest.fixture(params=testdata.KEY_DUMMIES)
def key_dummy(request):
    return request.param


@pytest.fixture(params=testdata.KEYSERVERS + [None])
def keyserver(request):
    return request.param
