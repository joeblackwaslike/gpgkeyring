"""
:mod:`gpgkeyring.trust`
~~~~~~~~~~~~~~~~~~~~

GPG KeyManager trust utilities.

:copyright: (c) 2018 by Joseph Black.
:license: MIT, see LICENSE for more details.

.. module:: gpgkeyring.trust
.. moduleauthor:: Joseph Black <me@joeblack.nyc>
"""

import enum


__all__ = ["UNDEFINED", "NEVER", "MARGINAL", "FULLY", "ULTIMATE"]


class Levels(enum.Enum):
    """The levels of trust for a GPG key."""

    UNDEFINED = "TRUST_UNDEFINED"
    NEVER = "TRUST_NEVER"
    MARGINAL = "TRUST_MARGINAL"
    FULLY = "TRUST_FULLY"
    ULTIMATE = "TRUST_ULTIMATE"

    def __lt__(self, other):
        if self.__class__ is other.__class__:
            return self.value < other.value
        return NotImplemented

    def __repr__(self):
        return "<{}: {}>".format(type(self).__name__, self.name)

    def __str__(self):
        return str(self.value)

    def __hash__(self):
        return hash(self.value)

    def __eq__(self, other):
        if isinstance(other, str):
            return bool(other in self.value)
        return enum.Enum.__eq__(self, other)


UNDEFINED = Levels.UNDEFINED
NEVER = Levels.NEVER
MARGINAL = Levels.MARGINAL
FULLY = Levels.FULLY
ULTIMATE = Levels.ULTIMATE

_TRUST_MAP = dict(n=NEVER, m=MARGINAL, f=FULLY, u=ULTIMATE, q=UNDEFINED)


def coerce_trust(value):
    """"Return trust CONSTANT value to replace a gpg raw trust value.

    :param Union[Levels, str] value: the object to check.
    :returns: a trust Level enum member.
    :rtype: member of enum :class:`.Levels`.

    Usage::

        >>> coerce_trust('n')
        <Levels: NEVER>
    """
    if isinstance(value, Levels):
        return
    return _TRUST_MAP[value]
