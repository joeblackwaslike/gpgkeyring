import maya
import pytest

from gpgkeyring import util

from ..helpers import constants
from ..helpers.unit import testdata


class TestCoerceTime:

    @pytest.mark.parametrize("value", testdata.DATETIMES)
    def test_coercion(self, value):
        result = util.coerce_time(value)
        assert isinstance(result, maya.MayaDT)
        assert result.timezone == "UTC"
        assert result.epoch == constants.TIMESTAMP

    def test_coercion_returns_none_on_none(self):
        result = util.coerce_time(None)
        assert result is None


class TestCoerceInt:

    @pytest.mark.parametrize("value", testdata.INTS)
    def test_coercion(self, value):
        result = util.coerce_int(value)
        assert isinstance(result, int)
        try:
            assert result == int(value)
        except ValueError:
            assert result == 0

    def test_coercion_returns_none_on_none(self):
        result = util.coerce_int(None)
        assert result is None


class TestCoerceTuple:

    @pytest.mark.parametrize("value, expected", testdata.TUPLES)
    def test_coercion(self, value, expected):
        result = util.coerce_tuple(value)
        assert result == expected
        assert isinstance(result, tuple)

    def test_coercion_returns_none_on_none(self):
        result = util.coerce_tuple(None)
        assert result is None


class TestKeyType:

    @pytest.mark.parametrize("secret, expected", testdata.KEYLIST_TYPES)
    def test_key_type(self, secret, expected):
        result = util.key_type(secret)
        assert result == expected


class TestSetDefaults:

    @pytest.mark.parametrize(
        "options, defaults, expected", testdata.SETDEFAULTS
    )
    def test_setdefaults(self, options, defaults, expected):
        result = util.setdefaults(options, defaults)
        assert result == expected


class TestParseKeyIDs:

    @pytest.mark.parametrize("keyid, expected", testdata.PARSED_KEYIDS)
    def test_parse_keyids(self, keyid, expected):
        result = util.parse_keyids(keyid)
        assert result == expected


class TestParseFingerprints:

    @pytest.mark.parametrize(
        "fingerprint, expected", testdata.PARSED_FINGERPRINTS
    )
    def test_parse_fingerprints(self, fingerprint, expected):
        result = util.parse_fingerprints(fingerprint)
        assert result == expected


class TestPopAttr:

    class Dummy:

        def __init__(self):
            self.attribute = "value"

    def test_pop_attr(self):
        obj = self.Dummy()
        assert hasattr(obj, "attribute")
        value = util.pop_attr(obj, "attribute")
        assert value == "value"
        assert hasattr(obj, "attribute") is False

        value = util.pop_attr(obj, "attribute", "default")
        assert value == "default"


# class TestUtil:

# @pytest.mark.parametrize("dtval", testdata.DATETIMES)
# def test_coerce_time(self, dtval):
#     result = util.coerce_time(dtval)
#     assert isinstance(result, maya.MayaDT)
#     assert result.timezone == "UTC"
#     assert result.epoch == constants.TIMESTAMP

# def test_coerce_time_accepts_None(self):
#     result = util.coerce_time(None)
#     assert result is None

# @pytest.mark.parametrize("intval", testdata.INTS)
# def test_coerce_int(self, intval):
#     result = util.coerce_int(intval)
#     assert isinstance(result, int)
#     try:
#         assert result == int(intval)
#     except ValueError:
#         assert result == 0

# def test_coerce_int_accepts_None(self):
#     result = util.coerce_int(None)
#     assert result is None

# @pytest.mark.parametrize("val, expected", testdata.TUPLES)
# def test_coerce_tuple(self, val, expected):
#     result = util.coerce_tuple(val)
#     assert result == expected
#     assert isinstance(result, tuple)

# def test_coerce_tuple_accepts_None(self):
#     result = util.coerce_tuple(None)
#     assert result is None

# @pytest.mark.parametrize("secret, expected", testdata.KEYLIST_TYPES)
# def test_key_type(self, secret, expected):
#     result = util.key_type(secret)
#     assert result == expected

# @pytest.mark.parametrize(
#     "options, defaults, expected", testdata.SETDEFAULTS
# )
# def test_setdefaults(self, options, defaults, expected):
#     result = util.setdefaults(options, defaults)
#     assert result == expected

# @pytest.mark.parametrize("keyid, expected", testdata.PARSED_KEYIDS)
# def test_parse_keyids(self, keyid, expected):
#     result = util.parse_keyids(keyid)
#     assert result == expected

# @pytest.mark.parametrize(
#     "fingerprint, expected", testdata.PARSED_FINGERPRINTS
# )
# def test_parse_fingerprints(self, fingerprint, expected):
#     result = util.parse_fingerprints(fingerprint)
#     assert result == expected
