"""Availability checking -- interface only.

Deliberately unimplemented. The entire design rests on keeping two ideas apart:

* a domain leaving the DNS zone is an **observation about delegation**;
* a domain being registrable is a **fact about the registry**.

``REMOVED_FROM_ZONE`` means the first. It does not mean the second, and a registered
domain can sit undelegated indefinitely. Shipping a checker before the monitoring core is
solid would invite exactly the conflation the state names exist to prevent.

When a concrete checker arrives it should run only on domains that already matter -- a
``REMOVED_FROM_ZONE`` event that matched a rule -- rather than on every disappearance, and
it must be rate limited against the registry.

A working RDAP checker for `.ch`/`.li` exists elsewhere in this repository
(``src/wiederfrei/rdap.py``), verified against the live registry: ``HEAD`` on
``rdap.nic.ch/domain/<name>`` returns 200 for registered and 404 for available, and the
response *body* is redacted for anonymous callers -- ``events`` is empty and
``nameservers`` is empty even for a delegated domain -- so only the status code carries
information. Worth reading before writing this from scratch.
"""

from __future__ import annotations

import enum
from abc import ABC, abstractmethod


class AvailabilityStatus(enum.StrEnum):
    AVAILABLE = "AVAILABLE"
    REGISTERED_NOT_DELEGATED = "REGISTERED_NOT_DELEGATED"
    UNKNOWN = "UNKNOWN"


class AvailabilityChecker(ABC):
    """Decide whether a name is actually registrable.

    Implementations must return :attr:`AvailabilityStatus.UNKNOWN` on any failure --
    timeout, rate limit, malformed response. Reporting a name as available when the
    check merely failed is the one error this system must never make.
    """

    @abstractmethod
    def check(self, domain: str) -> AvailabilityStatus:
        raise NotImplementedError
