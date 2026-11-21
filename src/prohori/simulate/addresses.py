# SPDX-License-Identifier: LicenseRef-PolyForm-Strict-1.0.0
# Copyright (c) 2026 Utsha Basak
"""Addresses for simulated activity: documentation ranges only, never a real network.

RFC 5737 reserves ``192.0.2.0/24``, ``198.51.100.0/24`` and ``203.0.113.0/24`` and RFC 3849
reserves ``2001:db8::/32`` for documentation. Every address a scenario writes comes from
:class:`AddressPool`, which can return nothing else.
"""

import ipaddress
import random
from typing import Final

#: The address model in use, recorded in every manifest and results file: 1 put every customer
#: in one /24; numbers measured on one model are not comparable with another's.
ADDRESS_MODEL: Final = 1

DOCUMENTATION_NETWORKS: Final = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("2001:db8::/32"),
)

#: Which range plays which role. Rules never look at these ranges; the split only keeps logs
#: readable (customers and staff in 192.0.2.0/24, other internet hosts elsewhere).
CUSTOMERS: Final = "192.0.2.0/24"
INTERNET: Final = "198.51.100.0/24"
HOSTILE: Final = "203.0.113.0/24"
IPV6: Final = "2001:db8::/32"


def is_documentation(address: str) -> bool:
    """Whether ``address`` lies inside one of the documentation ranges."""
    ip = ipaddress.ip_address(address)
    return any(ip.version == net.version and ip in net for net in DOCUMENTATION_NETWORKS)


class AddressPool:
    """Hands out distinct documentation addresses from a named range."""

    def __init__(self, rng: random.Random) -> None:
        self._rng = rng
        self._used: set[str] = set()

    def take(self, network: str) -> str:
        net = ipaddress.ip_network(network)
        if net not in DOCUMENTATION_NETWORKS:
            msg = f"{network} is not a documentation range"
            raise ValueError(msg)
        for _ in range(1000):
            if net.version == 4:
                address = str(net.network_address + self._rng.randrange(1, 255))
            else:
                address = str(net.network_address + self._rng.randrange(1, 2**32))
            if address not in self._used:
                self._used.add(address)
                return address
        msg = f"no free address left in {network}"
        raise ValueError(msg)

    def take_many(self, network: str, count: int) -> list[str]:
        return [self.take(network) for _ in range(count)]

    def take_spread(self, count: int) -> list[str]:
        """Distinct addresses spread over every documentation network, in turn: the hostile and
        internet /24s, and IPv6 addresses each in a /48 of its own (inside 2001:db8::/32).

        For attacks that rotate through many providers, so that no single network holds them.
        """
        found: list[str] = []
        v6 = ipaddress.ip_network(IPV6)
        while len(found) < count:
            turn = len(found) % 3
            if turn < 2:
                found.append(self.take((HOSTILE, INTERNET)[turn]))
                continue
            address = str(
                v6.network_address
                + (self._rng.randrange(1, 2**16) << 80)  # bits 32-47: the /48
                + self._rng.randrange(1, 2**32)
            )
            if address not in self._used:
                self._used.add(address)
                found.append(address)
        return found
