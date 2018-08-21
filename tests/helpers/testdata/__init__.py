from os.path import join
import itertools

import gpgkeyring

from .factories import KeyDummy
from ..util import load_testdata
from ..builders import KeylistDataBuilder


TRUST_LEVELS = sorted(gpgkeyring.trust.Levels)

TRUST_LEVEL_VALUES = TRUST_LEVELS + [item.value for item in TRUST_LEVELS]

KEYGEN_SPECS = [
    dict(key_type="RSA", subkey_type="RSA"),
    dict(
        key_type="ECDSA",
        subkey_type="ECDH",
        key_curve="nistp256",
        subkey_curve="nistp256",
    ),
]

KEYSERVERS = ["keyserver.com"]

KEYIDS = ["F03759B9C959DC84", "C1DDC81D69FB5DAE", "1580F2FC700ADDB4"]

FINGERPRINTS = [
    "07A1F3D416C3CCAD27DC6E5F4607A5FC6A1ED3CA",
    "E9A5E81AA668EA161593219F62A970B3B4AD8227",
    "F8D1690A944C56DAA4942F6BC4462CD6B9C39742",
]

KEY_DUMMIES = [
    KeyDummy(fingerprint=fp, keyid=KEYIDS[idx])
    for idx, fp in enumerate(FINGERPRINTS)
]

KEY_TYPES = sorted(gpgkeyring.keys.Types)

KEYLIST_TYPES = [(True, "secret"), (False, "public")]

KEY_VALIDITIES = sorted(gpgkeyring.keys.Validity)

GNUPG_KEYLISTS = load_testdata(
    join("keys", "data.dat"), "rb", base=__file__, unpickle=True
)

GNUPG_KEYS = {
    type_: KeylistDataBuilder.use(keysdata).as_list().for_gnupg()
    for type_, keysdata in GNUPG_KEYLISTS.items()
}

KEYRING_KEYLISTS = {
    type_: KeylistDataBuilder.use(keysdata).as_list().for_gpgkeyring()
    for type_, keysdata in GNUPG_KEYLISTS.items()
}

KEY_SUBKEYS = list(
    set(
        itertools.chain.from_iterable(
            [
                list(key.subkeys.values())
                for key in itertools.chain.from_iterable(
                    KEYRING_KEYLISTS.values()
                )
            ]
        )
    )
)
