from datetime import datetime, timezone

import maya

import gpgkeyring

from ... import constants
from ...testdata.factories import KeyDummy
from ...testdata import (
    KEYIDS,
    FINGERPRINTS,
    KEY_DUMMIES,
    TRUST_LEVELS,
    KEY_TYPES,
    KEYLIST_TYPES,
    KEY_VALIDITIES,
    KEYGEN_SPECS,
    GNUPG_KEYLISTS,
    KEYRING_KEYLISTS,
    KEY_SUBKEYS,
)
from .factories import gen_keyimport_data, gen_keyexport_data


KEYGEN_SPECS += [dict()]

DATETIMES = (
    maya.MayaDT(constants.TIMESTAMP).datetime(),
    datetime.utcfromtimestamp(constants.TIMESTAMP).replace(
        tzinfo=timezone.utc
    ).isoformat(),
    maya.MayaDT(constants.TIMESTAMP).iso8601(),
    maya.MayaDT(constants.TIMESTAMP),
)

INTS = (1, 3000000, "3000000", 30.300, "thousand")

TUPLES = [
    (1, (1,)),
    ("string", ("string",)),
    (dict(), (dict(),)),
    (["value"], ("value",)),
    (("value",), ("value",)),
]
SETDEFAULTS = [
    (
        dict(one="newone"),
        dict(one="one", two="two"),
        dict(one="newone", two="two"),
    )
]

PARSED_KEYIDS = [
    (KEYIDS[0], KEYIDS[0]),
    (KeyDummy(keyid=KEYIDS[1]), KEYIDS[1]),
    ((KEYIDS[2], KeyDummy(keyid=KEYIDS[2])), (KEYIDS[2], KEYIDS[2])),
]

PARSED_FINGERPRINTS = [
    (FINGERPRINTS[0], FINGERPRINTS[0]),
    (KeyDummy(fingerprint=FINGERPRINTS[1]), FINGERPRINTS[1]),
    (
        (FINGERPRINTS[2], KeyDummy(fingerprint=FINGERPRINTS[2])),
        (FINGERPRINTS[2], FINGERPRINTS[2]),
    ),
]


KEYEXPORTS = [gen_keyexport_data(fp) for fp in FINGERPRINTS]

KEYIMPORTS = [gen_keyimport_data(fp) for fp in FINGERPRINTS] + [
    gen_keyimport_data(fp) for fp in FINGERPRINTS[1:]
]
