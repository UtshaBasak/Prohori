# SPDX-License-Identifier: LicenseRef-PolyForm-Strict-1.0.0
# Copyright (c) 2026 Utsha Basak
"""Addresses for simulated activity: documentation ranges only, never a real network.

RFC 5737 reserves ``192.0.2.0/24``, ``198.51.100.0/24`` and ``203.0.113.0/24`` and RFC 3849
reserves ``2001:db8::/32`` for documentation. Every address a scenario writes comes from
:class:`AddressPool`, which can return nothing else.

**Address model 2** (ADR-0038). A real site's customers come from many networks, so the
per-network rule (PRH-AUTH-007) must be measured against a background spread the same way:

* Each customer, visitor and member of staff has one stable home address
  (:meth:`AddressPool.household`). A share of them, :data:`IPV6_SHARE`, is on IPv6 with a /48
  of their own inside ``2001:db8::/32`` (65,536 documentation /48s exist); the rest are on IPv4
  in :data:`CUSTOMER_NETWORKS`. Only three IPv4 documentation /24s exist, so IPv4 customers are
  far more concentrated than on a real site: per-network counts measured here are an upper
  bound.
* A few customers also sign in through one shared address (an office or carrier NAT), so the
  per-network rule's stated false positive still appears in the background.
* Other benign internet hosts (SSH background probes) are spread the same way
  (:meth:`AddressPool.internet_host`).
* Attackers keep their scenario's semantics: one address, several addresses inside one provider
  network (:data:`HOSTILE`, which holds no benign address), or addresses spread over every
  network (:meth:`AddressPool.take_spread`). Each scenario says which.
"""

import ipaddress
import random
from typing import Final

#: The address model in use, recorded in every manifest and results file: 1 put every customer
#: in one /24 (and every IPv6 address in one /48); 2 spreads them over many networks. Numbers
#: measured on one model are not comparable with another's.
ADDRESS_MODEL: Final = 2
#: The share of a site's users on IPv6. The simulated shop is in Bangladesh (its admins work in
#: Asia/Dhaka time); APNIC Labs measured IPv6 use there at 18.3 % in 2025 ("Bangladesh's Internet
#: transformation", blog.apnic.net, 3 November 2025). Fixed before any rule was scored on it.
IPV6_SHARE: Final = 0.18

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
#: Where benign IPv4 hosts live: every IPv4 documentation /24 except the attackers' provider.
CUSTOMER_NETWORKS: Final = (CUSTOMERS, INTERNET)


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

    def take_v6_network(self) -> str:
        """An IPv6 address in a /48 of its own inside ``2001:db8::/32``."""
        v6 = ipaddress.ip_network(IPV6)
        while True:
            address = str(
                v6.network_address
                + (self._rng.randrange(1, 2**16) << 80)  # bits 32-47: the /48
                + self._rng.randrange(1, 2**32)
            )
            network = str(ipaddress.ip_network((address, 48), strict=False))
            if address not in self._used and network not in self._used:
                self._used.update((address, network))
                return address

    def household(self) -> str:
        """A benign home address: IPv6 in a /48 of its own (:data:`IPV6_SHARE` of the time), or
        IPv4 in one of the benign /24s."""
        if self._rng.random() < IPV6_SHARE:
            return self.take_v6_network()
        return self.take(self._rng.choice(CUSTOMER_NETWORKS))

    def internet_host(self) -> str:
        """Some other benign host on the internet, spread like the customers."""
        return self.household()

    def take_spread(self, count: int) -> list[str]:
        """Distinct addresses spread over every documentation network, in turn: the hostile and
        internet /24s, and IPv6 addresses each in a /48 of its own (inside 2001:db8::/32).

        For attacks that rotate through many providers, so that no single network holds them.
        """
        found: list[str] = []
        while len(found) < count:
            turn = len(found) % 3
            found.append(
                self.take((HOSTILE, INTERNET)[turn]) if turn < 2 else self.take_v6_network()
            )
        return found
