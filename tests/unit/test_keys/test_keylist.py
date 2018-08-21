import pytest
from zope.interface.verify import verifyClass, verifyObject

from gpgkeyring import interfaces
from gpgkeyring.keys import _Keylist, Key

from ...helpers.patching import undecorate_class


Key = undecorate_class(Key)
_Keylist = undecorate_class(_Keylist)


@pytest.fixture
def keylist(keylist_factory, secret):
    return keylist_factory(secret=secret)


@pytest.fixture
def keylist_mock(keylist_mock_factory, secret):
    return keylist_mock_factory(secret=secret)


class TestKeylistInitialization:

    def test_initialization(self, keylist):
        assert isinstance(keylist, _Keylist)
        assert keylist.type in ("secret", "public")
        assert isinstance(keylist.current, Key)


class TestKeylistInterface:

    def test_class_implements_interface(self):
        assert verifyClass(interfaces.IKeylist, _Keylist)

    def test_instance_provides_interface(self, keylist):
        assert verifyObject(interfaces.IKeylist, keylist)


class TestKeylistProperties:

    def test_current_property(self, keylist_mock):
        result = _Keylist.__dict__["current"].__get__(keylist_mock, _Keylist)
        curkey = keylist_mock._keylist.curkey or dict()
        keylist_mock.get.assert_called_with(
            curkey.get("fingerprint"), default=None
        )
        assert isinstance(result, Key)

    def test_current_property_handles_missing_current_key(
        self, keylist_mock, monkeypatch
    ):
        monkeypatch.setattr(keylist_mock._keylist, "curkey", dict())
        result = _Keylist.__dict__["current"].__get__(keylist_mock, _Keylist)
        assert result is None

    def test_fingerprints_property(self, keylist_mock, mocker):
        keylist_mock._wrapped = mocker.create_autospec(
            keylist_mock._wrapped, instance=True
        )

        result = _Keylist.__dict__["fingerprints"].__get__(
            keylist_mock, _Keylist
        )
        keylist_mock._wrapped.keys.assert_called_once_with()
        assert isinstance(result, list)


class TestKeylistGet:

    def test__get_keys(self, keylist_mock, mocker):
        results = _Keylist._get_keys(keylist_mock)
        keylist_mock.get.assert_has_calls(
            [mocker.call(key) for key in results], any_order=True
        )

        for key in results:
            assert isinstance(key, str)
            assert len(key) == 40
            assert isinstance(results[key], Key)

    def test_get(self, keylist_mock, mocker):
        for fingerprint in keylist_mock._keylist.fingerprints:
            result = _Keylist.get(keylist_mock, fingerprint)

            keylist_mock._key_class.assert_called_with(
                **keylist_mock._wrapped[fingerprint]
            )
            assert isinstance(result, Key)

    def test_get_with_bad_keyid_fingerprint_raises_error(
        self, keylist_mock, mocker
    ):
        with pytest.raises(KeyError):
            _Keylist.get(
                keylist_mock,
                "BAD_FINGERPRINT",
                default=keylist_mock._raise_on_none,
            )

    def test_get_with_bad_keyid_fingerprint_and_default_returns_default(
        self, keylist_mock, mocker
    ):
        result = _Keylist.get(
            keylist_mock, "BAD_FINGERPRINT", default="DEFAULT"
        )
        assert result is "DEFAULT"
