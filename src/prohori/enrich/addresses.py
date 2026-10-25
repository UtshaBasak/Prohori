"""Which IP addresses may be sent to external enrichment services.

Private, reserved, loopback, link-local, multicast, shared, benchmarking and documentation ranges
are never sent anywhere. The list is explicit rather than relying on ``ipaddress.is_global``,
whose answers changed between Python patch releases. IPv6 addresses that embed an IPv4 address
(IPv4-mapped, 6to4 and NAT64) are checked against the IPv4 list too.
"""

import ipaddress
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network

IPAddress = IPv4Address | IPv6Address

_NOT_PUBLIC_V4 = tuple(
    IPv4Network(net)
    for net in (
        "0.0.0.0/8",  # "this network"
        "10.0.0.0/8",  # private
        "100.64.0.0/10",  # carrier-grade NAT (shared address space)
        "127.0.0.0/8",  # loopback
        "169.254.0.0/16",  # link-local
        "172.16.0.0/12",  # private
        "192.0.0.0/24",  # IETF protocol assignments
        "192.0.2.0/24",  # documentation (TEST-NET-1)
        "192.88.99.0/24",  # deprecated 6to4 relay anycast
        "192.168.0.0/16",  # private
        "198.18.0.0/15",  # benchmarking
        "198.51.100.0/24",  # documentation (TEST-NET-2)
        "203.0.113.0/24",  # documentation (TEST-NET-3)
        "224.0.0.0/4",  # multicast
        "240.0.0.0/4",  # reserved, including broadcast
    )
)

_NOT_PUBLIC_V6 = tuple(
    IPv6Network(net)
    for net in (
        "::/128",  # unspecified
        "::1/128",  # loopback
        "100::/64",  # discard-only
        "2001::/32",  # Teredo and other IETF protocol assignments
        "2001:db8::/32",  # documentation
        "3fff::/20",  # documentation (RFC 9637)
        "fc00::/7",  # unique local
        "fe80::/10",  # link-local
        "ff00::/8",  # multicast
    )
)

_MAPPED = IPv6Network("::ffff:0:0/96")
_SIX_TO_FOUR = IPv6Network("2002::/16")
_NAT64 = IPv6Network("64:ff9b::/96")


def parse_ip(text: str) -> IPAddress:
    """Parse and normalise an IP address typed by a user or found in a log.

    Raises:
        ValueError: if ``text`` is not an IPv4 or IPv6 address, or carries a zone id (``%eth0``).
    """
    value = text.strip()
    if "%" in value:
        raise ValueError(f"IP addresses with a zone id are not accepted: {text!r}")
    return ipaddress.ip_address(value)


def embedded_ipv4(address: IPv6Address) -> IPv4Address | None:
    """Return the IPv4 address embedded in an IPv4-mapped, 6to4 or NAT64 address, if any."""
    if address in _MAPPED or address in _NAT64:
        return IPv4Address(int(address) & 0xFFFFFFFF)
    if address in _SIX_TO_FOUR:
        return IPv4Address((int(address) >> 80) & 0xFFFFFFFF)
    return None


def is_public(address: IPAddress) -> bool:
    """Return whether ``address`` may be sent to an external service."""
    if isinstance(address, IPv4Address):
        return not any(address in net for net in _NOT_PUBLIC_V4)
    if address.scope_id is not None:
        return False
    if any(address in net for net in _NOT_PUBLIC_V6):
        return False
    inner = embedded_ipv4(address)
    return inner is None or is_public(inner)
