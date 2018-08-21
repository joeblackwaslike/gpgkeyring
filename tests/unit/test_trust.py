import pytest
import gpgkeyring

from ..helpers import testdata


TRUST_VALUE_MAP = gpgkeyring.trust._TRUST_MAP.items()


class TestEnum:

    @pytest.fixture(params=testdata.TRUST_LEVELS)
    def level(self, request):
        yield request.param

    def test_trust_level_value(self, level):
        assert getattr(gpgkeyring.trust.Levels, level.name) == level

    def test_trust_level_repr(self, level):
        assert (
            repr(level) == "<{}: {}>".format(type(level).__name__, level.name)
        )

    def test_trust_level_str(self, level):
        assert str(level) == level.value

    def test_trust_level_eq_str(self, level):
        assert level == str(level)


class TestCoerce:

    @pytest.mark.parametrize("raw, expected", TRUST_VALUE_MAP)
    def test_coerce_trust(self, raw, expected):
        assert gpgkeyring.trust.coerce_trust(raw) == expected
