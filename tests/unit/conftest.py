# pylint: disable=missing-docstring,redefined-outer-name,protected-access
# plint: disable=too-many-arguments

import os.path

import pytest
import zope.component
import gnupg

import gpgkeyring
from gpgkeyring import interfaces

from ..helpers import constants, mocks
from ..helpers.unit import testdata


@pytest.fixture(params=testdata.KEYGEN_SPECS)
def keygen_spec(request):
    return request.param


@pytest.fixture()
def gnupg_gpg_dummy():
    gpg = mocks.GPGDummy(
        gpgbinary=constants.GPGBINARY,
        gnupghome=constants.GNUPGHOME,
        use_agent=constants.USE_AGENT,
    )
    gpg.encoding = constants.GPG_ENCODING
    return gpg


@pytest.fixture()
def gnupg_gpg():
    gpg = gnupg.GPG(
        gpgbinary=constants.GPGBINARY,
        gnupghome=constants.GNUPGHOME,
        use_agent=constants.USE_AGENT,
    )
    gpg.encoding = constants.GPG_ENCODING
    return gpg


@pytest.fixture()
def gnupg_class_mock(gnupg_gpg_dummy, mocker):
    mock = mocker.create_autospec(
        mocks.GPGDummy,
        return_value=mocker.create_autospec(gnupg_gpg_dummy, instance=True),
    )
    mock.return_value.encoding = mocks.string(constants.GPG_ENCODING)
    for attr in ("gpgbinary", "gnupghome"):
        setattr(
            mock.return_value,
            attr,
            mocks.string(getattr(mock.return_value, attr)),
        )
    return mock


@pytest.fixture()
def gnupg_keylist_factory():

    def get_keylist(secret):
        return testdata.GNUPG_KEYLISTS["secret" if secret else "public"]

    yield get_keylist


@pytest.fixture()
def gnupg_mock(gnupg_class_mock, gnupg_keylist_factory):

    def list_keys(secret=False, keys=None, sigs=False):
        keylist = gnupg_keylist_factory(secret)
        if keys:
            keylist = [key for key in keylist if key["fingerprint"] in keys]
        return keylist

    gnupg_class_mock.return_value.list_keys.side_effect = list_keys
    return gnupg_class_mock()


@pytest.fixture()
def keyring_class_mock(mocker):
    yield mocker.create_autospec(gpgkeyring.keys.Keyring)


@pytest.fixture()
def gpg_factory(
    gnupg_class_mock,
    gnupg_mock,
    keyring_class_mock,
    disable_attr_validation,
    undecorate_gpg,
    undecorate_keyring,
    mock_util_methods,
    mocker,
    monkeypatch,
):
    mocker.patch.object(
        gpgkeyring.gpg,
        "expanduser",
        autospec=os.path.expanduser,
        side_effect=lambda p: p,
    )
    monkeypatch.setattr(gpgkeyring.gpg.GPG, "_gpg_class", gnupg_class_mock)
    monkeypatch.setattr(
        gpgkeyring.gpg.GPG, "_keyring_class", keyring_class_mock
    )

    def generate_gpg(event=False, register=False, **kwargs):

        gpg = gpgkeyring.gpg.GPG(
            options=dict(gnupghome=constants.GNUPGHOME),
            event=event,
            register=register,
            **kwargs
        )
        gpg.keys._gpg = gpg
        return gpg

    yield generate_gpg


@pytest.fixture()
def gpg(gpg_factory):
    yield gpg_factory()


@pytest.fixture()
def gpg_mock(gpg, gnupg_class_mock, keyring_class_mock, mocker):
    gpg_mock = mocker.create_autospec(
        gpg,
        _gpg=gpg._gpg,
        keys=gpg.keys,
        _keyring_class=keyring_class_mock,
        _gpg_class=gnupg_class_mock,
        instance=True,
    )
    gpg_mock._gpg.encoding = mocks.string("utf-8")
    gpg_mock._gpg._wrapped = gpg_mock
    gpg_mock.keys._gpg = gpg_mock
    yield gpg_mock


@pytest.fixture()
def keylist_class_mock(mocker):
    yield mocker.create_autospec(gpgkeyring.keys._Keylist)


@pytest.fixture()
def key_class_mock(mocker):
    yield mocker.create_autospec(gpgkeyring.keys.Key)


@pytest.fixture()
def keylist_factory(gnupg_keylist_factory, key_class_mock, undecorate_keylist):

    def gen_keylist(secret):
        type_ = "secret" if secret else "public"
        keysdata = gnupg_keylist_factory(type_)
        keylist = gpgkeyring.keys._Keylist(keysdata)
        keylist.type = type_
        keylist._key_class = key_class_mock
        return keylist

    return gen_keylist


@pytest.fixture()
def keylist_mock_factory(keylist_factory, mocker):

    def gen_keylist(secret):
        type_ = "secret" if secret else "public"
        keylist = keylist_factory(type_)
        keylist_mock = mocker.create_autospec(
            keylist,
            instance=True,
            _keylist=keylist._keylist,
            type=keylist.type,
            _wrapped=keylist._wrapped,
            _key_class=keylist._key_class,
        )
        keylist_mock._get_keys.side_effect = keylist._get_keys
        keylist_mock._get_keys.cache_clear = mocker.MagicMock()
        keylist_mock.get.side_effect = keylist.get
        return keylist_mock

    return gen_keylist


@pytest.fixture()
def keyring(gpg_mock, keylist_class_mock, mocker):
    keyring = gpgkeyring.keys.Keyring(gpg_mock)
    mocker.patch.object(keyring, "_keylist_class", keylist_class_mock)
    yield keyring


@pytest.fixture()
def keyring_mock(keyring, gnupg_keylist_factory, mocker):
    mock = mocker.create_autospec(
        keyring,
        instance=True,
        _gpg=keyring._gpg,
        _keylist_class=keyring._keylist_class,
    )
    mock._load = mocker.create_autospec(
        keyring._load, side_effect=keyring._load
    )
    mock._get_list = mocker.create_autospec(
        keyring._get_list, side_effect=keyring._get_list
    )
    mock.get = mocker.create_autospec(keyring.get, side_effect=keyring.get)
    # import pdb

    # pdb.set_trace()

    mock._load.cache_clear = mocker.MagicMock()
    mock._gpg.keys = mock
    mock._gpg._gpg.list_keys.reset_mock()
    yield mock


@pytest.fixture(
    params=testdata.GNUPG_KEYLISTS["public"]
    + testdata.GNUPG_KEYLISTS["secret"]
)
def gnupg_key(request):
    yield request.param


@pytest.fixture()
def subkey_class_mock(mocker):
    yield mocker.create_autospec(gpgkeyring.keys.SubKey)


@pytest.fixture()
def key(gnupg_key, subkey_class_mock, undecorate_key, mocker):
    key = gpgkeyring.keys.Key(**gnupg_key)
    key._subkey_class = subkey_class_mock
    yield key


@pytest.fixture()
def key_mock(key, mocker):
    mock = mocker.create_autospec(
        key,
        instance=True,
        _subkey_class=key._subkey_class,
        _subkey_info=key._subkey_info,
    )
    mock._get_subkeys.side_effect = key._get_subkeys

    subkey_mock = mocker.PropertyMock(return_value=key.subkeys)
    mock._subkey_mock = mocker.PropertyMock(return_value=key.subkeys)
    type(mock).subkeys = mock._subkey_mock
    return mock


@pytest.fixture(params=testdata.KEY_SUBKEYS)
def subkey(request):
    return request.param


@pytest.fixture(params=[True, False])
def event(request):
    yield request.param


@pytest.fixture
def registry():
    registry = zope.component.getGlobalSiteManager()
    assert registry.queryUtility(interfaces.IGPG, name="test") is None
    yield registry
    zope.component.globalregistry.base.__init__("base")


@pytest.fixture
def registry_mock(registry, mocker):
    yield mocker.create_autospec(registry, instance=True)


# @pytest.fixture()
# def subkey(subkeys):
#     return


# @pytest.fixture()
# def gnupg_mock(gnupg_class_mock, gnupg_keylist, mocker):
#     def list_keys(secret=False, keys=None, sigs=False):
#         keylist = gnupg_keylist(secret)
#         if keys:
#             keylist = [key for key in keylist if key["fingerprint"] in keys]
#         return keylist

#     gnupg_class_mock.return_value.list_keys.side_effect = list_keys
#     return gnupg_class_mock()

# from . import constants, helpers
# from .helpers import mocks.string


# keylist_testdata = pickle.loads(helpers.testdata("keys/data.dat", "rb"))

# dict(
#     public=pickle.loads(helpers.testdata("keylist_public.dat", "rb")),
#     secret=pickle.loads(helpers.testdata("keylist_secret.dat", "rb")),
# )

# keygen_testdata = [
#     dict(key_type="RSA", subkey_type="RSA"),
#     dict(
#         key_type="ECDSA",
#         subkey_type="ECDH",
#         key_curve="nistp256",
#         subkey_curve="nistp256",
#     ),
# ]


# class GPGDummy(gnupg.GPG):

#     def __init__(
#         self,
#         gpgbinary="gpg",
#         gnupghome=None,
#         verbose=False,
#         use_agent=False,
#         keyring=None,
#         options=None,
#         secret_keyring=None,
#     ):
#         self.gpgbinary = gpgbinary
#         self.gnupghome = gnupghome
#         if keyring:
#             if isinstance(keyring, string_types):
#                 keyring = [keyring]
#         self.keyring = keyring
#         if secret_keyring:
#             if isinstance(secret_keyring, string_types):
#                 secret_keyring = [secret_keyring]
#         self.secret_keyring = secret_keyring
#         self.verbose = verbose
#         self.use_agent = use_agent
#         if isinstance(options, str):
#             options = [options]
#         self.options = options
#         self.on_data = None
#         self.encoding = "latin-1"
#         self.version = (2, 2, 7)


# trust_levels = sorted(gpgkeyring.trust.Levels)


# @pytest.fixture(params=testdata.TRUST_LEVELS)
# def trust_level(request):
#     yield request.param


# @pytest.fixture()
# def gnupg_keylists():
#     yield copy.deepcopy(keylist_testdata)
# yield keylist_testdata


# @pytest.fixture()
# def fpkeysmap_testdata(gnupg_keylists):
#     yield {
#         type_: KeylistDataBuilder.use(data).as_mapping().for_gnupg()
#         for type_, data in gnupg_keylists.items()
#     }


# @pytest.fixture()
# def fpkeysmap_testdata(gnupg_keylists, request):


# class KeylistDataBuilder:

#     class _Context:
#         _key_factories = dict(gpgkeyring=gpgkeyring.keys._Keylist, gnupg=None)
#         _build_strategies = dict(list=list, mapping=dict)

#         def __init__(self, builder=None, data=None):
#             self.builder = builder
#             self.data = data
#             self.strategy = None
#             self.key_factory = None

#         def as_(self, strategy_name):
#             self.strategy = self._build_strategies[strategy_name]
#             return self

#         def as_list(self):
#             return self.as_("list")

#         def as_mapping(self):
#             return self.as_("mapping")

#         def _for(self, key_factory_name):
#             self.key_factory = self._key_factories[key_factory_name]
#             return self.builder.build(
#                 self.data, self.strategy, self.key_factory
#             )

#         def for_gnupg(self):
#             return self._for("gnupg")

#         def for_gpgkeyring(self):
#             return self._for("gpgkeyring")

#     @classmethod
#     def use(cls, data):
#         return cls._Context(builder=cls, data=data)

#     @classmethod
#     def build(cls, data=None, strategy=None, key_factory=None):
#         return cls._apply_strategy(
#             data, strategy=strategy, key_factory=key_factory
#         )

#     @classmethod
#     def _get_fingerprints(cls, data, getter=None):
#         getter = getter or cls._build_getter(name="fingerprint")
#         # import pdb

#         # pdb.set_trace()
#         return [getter(item) for item in data]
#         # return cls._extract(getter, data)

#     @classmethod
#     def _build_getter(cls, factory=None, **kwargs):
#         factory = factory or operator.itemgetter
#         if factory == operator.itemgetter:
#             return factory(kwargs["name"])
#         raise ValueError("Factory {} not supported")

#     # @classmethod
#     # def _extract(cls, getter, sequence):
#     #     return [getter(item) for item in sequence]

#     @classmethod
#     def _apply_strategy(cls, data, strategy=list, key_factory=None):

#         def for_each(items):
#             return [i for i in items if i in data.key_map]

#         def list_builder(fps):
#             return [maybe_wrap_key(data.key_map[fp]) for fp in for_each(fps)]

#         def dict_builder(fps):
#             return {
#                 fp: maybe_wrap_key(data.key_map[fp]) for fp in for_each(fps)
#             }

#         def maybe_wrap_key(raw_key):
#             return key_factory(raw_key) if key_factory else raw_key

#         build_strategy = {list: list_builder, dict: dict_builder}[strategy]
#         fingerprints = cls._get_fingerprints(data)
#         return build_strategy(fingerprints)


# @pytest.fixture()
# def gnupg_gpg_dummy(mocker):
#     gpg = GPGDummy(gpgbinary="gpg2", gnupghome="/tmp/keyring", use_agent=True)
#     gpg.encoding = "utf-8"
#     return gpg


# @pytest.fixture()
# def gnupg_gpg():
#     gpg = gnupg.GPG(gpgbinary="gpg2", gnupghome="/tmp/keyring", use_agent=True)
#     gpg.encoding = "utf-8"
#     return gpg


# @pytest.fixture()
# def gnupg_class_mock(gnupg_gpg_dummy, mocker):
#     m = mocker.create_autospec(
#         GPGDummy,
#         return_value=mocker.create_autospec(gnupg_gpg_dummy, instance=True),
#     )
#     m.return_value.encoding = mocks.string("utf-8")
#     for attr in ("gpgbinary", "gnupghome"):
#         setattr(
#             m.return_value, attr, mocks.string(getattr(m.return_value, attr))
#         )
#     return m


# @pytest.fixture()
# def gnupg_mock_keydata(gnupg_class_mock, gnupg_keylists, mocker):
#     list_mock = gnupg_class_mock.return_value.list_keys
#     list_mock.side_effect = (
#         lambda secret=False, keys=None, sigs=False: gnupg_keylists[
#             "secret" if secret else "public"
#         ]
#     )
#     return gnupg_class_mock()


# @pytest.fixture()
# def keylist_class_mock(mocker):
#     yield mocker.create_autospec(gpgkeyring.keys._Keylist)


# @pytest.fixture()
# def keyring(gpg_mock, keylist_class_mock, mocker):
#     keyring = gpgkeyring.keys.Keyring(gpg_mock)
#     mocker.patch.object(keyring, "_keylist_class", keylist_class_mock)
#     yield keyring


# @pytest.fixture()
# def keyring_mock(mocker, keyring, gnupg_keylist):
#     keyring_mock = mocker.create_autospec(
#         keyring,
#         instance=True,
#         _gpg=keyring._gpg,
#         _keylist_class=keyring._keylist_class,
#     )
#     keyring_mock._load.cache_clear = mocker.MagicMock()
#     keyring_mock._gpg.keys = keyring_mock
#     keyring_mock._get_list.return_value = mocker.create_autospec(
#         gpgkeyring.keys._Keylist,
#         instance=True,
#         type=mock_string("list-type"),
#         _keylist=mocker.create_autospec(gnupg.ListKeys, instance=True),
#     )
#     # gnupg_keylist
#     # keyring_mock._gpg._gpg.list_keys.side_effect = lambda secret: gnupg_keylists[
#     #     "secret" if secret else "public"
#     # ]
#     keyring_mock._gpg._gpg.list_keys.reset_mock()
#     yield keyring_mock


# @pytest.fixture()
# def gpg(
#     gnupg_class_mock,
#     keyring_class_mock,
#     disable_attr_validation,
#     undecorate_gpg,
#     undecorate_keyring,
#     mock_util_methods,
#     gnupg_mock_keydata,
#     mocker,
# ):
#     mocker.patch(
#         "gpgkeyring.gpg.expanduser", autospec=gpgkeyring.gpg.expanduser
#     )
#     gpgkeyring.gpg.GPG._gpg_class = gnupg_class_mock
#     gpgkeyring.gpg.GPG._keyring_class = keyring_class_mock
#     gpg = gpgkeyring.gpg.GPG(
#         options=dict(gnupghome=constants.GNUPGHOME),
#         event=False,
#         register=False,
#     )
#     gpg.keys._gpg = gpg
#     yield gpg


# @pytest.fixture()
# def gpg_mock(mocker, gpg, gnupg_class_mock, keyring_class_mock):
#     gpg_mock = mocker.create_autospec(
#         gpg,
#         _gpg=gpg._gpg,
#         keys=gpg.keys,
#         _keyring_class=keyring_class_mock,
#         _gpg_class=gnupg_class_mock,
#     )
#     gpg_mock._gpg.encoding = mocks.string("utf-8")
#     gpg_mock._gpg._wrapped = gpg_mock
#     gpg_mock.keys._gpg = gpg_mock

#     yield gpg_mock


# @pytest.fixture()
# def keymaps(mocker):
#     return {
#         mocker.sentinel.fingerprint_one: mocker.sentinel.key_one,
#         mocker.sentinel.fingerprint_two: mocker.sentinel.key_two,
#     }
