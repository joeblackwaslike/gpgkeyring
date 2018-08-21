import pytest

import gpgkeyring

from tests.helpers.unit import testdata


@pytest.fixture()
def keydata():
    return testdata("testkey.pem")


@pytest.fixture()
def gpg():
    gpg = gpgkeyring.create(gnupghome=testdata_path("homedir"))
    version = gpg.version
    if version:
        if version >= (2,):
            gpg._gpg.options.append("--debug-quick-random")
        else:
            gpg._gpg.options.append("--quick-random")
    return gpg


@pytest.fixture()
def setup_doctest_namespace(gpg, doctest_namespace):
    doctest_namespace["gpg"] = gpg
    doctest_namespace["keystring"] = testdata_path("testkey.pem")
