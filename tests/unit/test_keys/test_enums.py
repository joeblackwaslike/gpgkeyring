import itertools

import pytest
import gpgkeyring

from ...helpers.unit import testdata


class TestKeyTypes:
    type_values = gpgkeyring.keys._KEYTYPE_MAP.items()

    @pytest.fixture(params=testdata.KEY_TYPES)
    def key_type(self, request):
        yield request.param

    def test_key_type_value(self, key_type):
        assert getattr(gpgkeyring.keys.Types, key_type.name) == key_type

    def test_key_type_str(self, key_type):
        assert str(key_type) == key_type.value

    def test_key_type_eq_str(self, key_type):
        assert key_type == str(key_type)

    @pytest.mark.parametrize("raw, expected", type_values)
    def test_coerce_keytype(self, raw, expected):
        assert gpgkeyring.keys.coerce_keytype(raw) == expected


class TestKeyValidities:
    value_map = gpgkeyring.keys._VALIDITY_MAP
    trust_values = list(
        itertools.chain(value_map.items(), gpgkeyring.trust._TRUST_MAP.items())
    )

    @pytest.fixture(params=testdata.KEY_VALIDITIES)
    def validity(self, request):
        yield request.param

    def test_validity_value(self, validity):
        assert getattr(gpgkeyring.keys.Validity, validity.name) == validity

    def test_validity_str(self, validity):
        assert str(validity) == validity.value

    def test_validity_eq_str(self, validity):
        assert validity == str(validity)

    @pytest.mark.parametrize("raw, expected", trust_values)
    def test_coerce_trust_validity(self, raw, expected):
        assert gpgkeyring.keys.coerce_trust_validity(raw) == expected
