from zope.interface.verify import verifyClass, verifyObject

import pytest
from gpgkeyring import interfaces
from gpgkeyring.keys import Key, SubKey

from ...helpers.unit import testdata
from ...helpers.patching import undecorate_class


Key = undecorate_class(Key)


class TestKeyBasic:

    def test_init(self, key):
        assert isinstance(key, Key)

    def test_class_implements_interface(self):
        assert verifyClass(interfaces.IKey, Key)

    def test_instance_provides_interface(self, key):
        assert verifyObject(interfaces.IKey, key)

    def test_key_type_and_trust_are_enum_values(self, key):
        assert key.type in testdata.KEY_TYPES
        for attribute in ("trust", "ownertrust"):
            assert (
                getattr(key, attribute) in testdata.TRUST_LEVELS
                + testdata.KEY_VALIDITIES
            )

    def test_valid_key_is_true(self, key):
        assert bool(key) is True

    def test_invalid_key_is_false(self, key):
        key.keyid = None
        key.fingerprint = None
        assert bool(key) is False

    def test_subkeys_property(self, key_mock):
        result = Key.__dict__["subkeys"].__get__(key_mock)
        key_mock._get_subkeys.assert_called_once_with()
        for keyid, subkey in result.items():
            assert isinstance(subkey, SubKey)


class TestKeySubKeyInternals:

    @pytest.fixture
    def subkeys(self, key_mock):
        subkeys = Key.__dict__["subkeys"].__get__(key_mock)
        return list(subkeys.items())

    def test___contains___checks_for_subkeys(self, key_mock, subkeys):
        for keyid, subkey in subkeys:
            assert Key.__contains__(key_mock, keyid) is True
            assert Key.__contains__(key_mock, subkey) is True
            key_mock._subkey_mock.assert_called_with()
        key_mock._get_subkeys.assert_called_with()

    def test__get_subkeys(self, key_mock, mocker):
        result = Key._get_subkeys(key_mock)
        assert isinstance(result, dict)
        key_mock.assert_has_calls(
            [mocker.call.get(keyid) for keyid in result], any_order=False
        )


class TestKeyGetSubKey:

    @pytest.fixture
    def subkeys(self, key_mock):
        return list(key_mock._subkey_info.items())

    @pytest.fixture
    def mock_subkey_info(self, key_mock, mocker):
        key_mock._subkey_info = mocker.create_autospec(
            key_mock._subkey_info, instance=True
        )
        return key_mock._subkey_info

    def test_get_returns_correct_subkey(self, key_mock, subkeys):
        for keyid, subkey in subkeys:
            result = Key.get(key_mock, keyid)
            assert isinstance(result, SubKey)
            key_mock._subkey_class.assert_called_with(
                **key_mock._subkey_info[keyid]
            )

    def test_get_raises_error_when_subkey_not_dict(
        self, key_mock, mock_subkey_info
    ):
        mock_subkey_info.get.return_value = "NOT A DICT"
        with pytest.raises(ValueError):
            Key.get(key_mock, "KEY")
