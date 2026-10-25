"""Tests for the "may this address leave the machine?" check."""

from ipaddress import IPv4Address, IPv6Address, ip_address

import pytest

from prohori.enrich.addresses import canonical, embedded_ipv4, is_public, parse_ip


@pytest.mark.parametrize(
    "address",
    [
        "0.0.0.0",  # noqa: S104 - an address under test, not a bind
        "0.255.255.255",
        "10.0.0.1",
        "10.255.255.255",
        "100.64.0.0",
        "100.127.255.255",
        "127.0.0.1",
        "169.254.169.254",
        "172.16.0.1",
        "172.31.255.255",
        "192.0.0.8",
        "192.0.2.1",
        "192.88.99.1",
        "192.168.1.1",
        "198.18.0.1",
        "198.19.255.255",
        "198.51.100.23",
        "203.0.113.7",
        "224.0.0.1",
        "239.255.255.250",
        "240.0.0.1",
        "255.255.255.255",
        "::",
        "::1",
        "100::1",
        "2001::1",
        "2001:2::1",  # benchmarking
        "2001:20::1",  # ORCHIDv2
        "2001:1ff:ffff::1",
        "64:ff9b:1::1",  # local-use NAT64
        "2001:db8::1",
        "2001:db8:abcd::17",
        "3fff::1",
        "fc00::1",
        "fd12:3456::1",
        "fe80::1",
        "ff02::1",
        "::ffff:10.0.0.1",
        "::ffff:203.0.113.7",
        "64:ff9b::10.1.2.3",
        "2002:c0a8:0101::1",  # 6to4 for 192.168.1.1
    ],
)
def test_not_public(address: str) -> None:
    assert not is_public(ip_address(address))


@pytest.mark.parametrize(
    "address",
    [
        "1.1.1.1",
        "8.8.8.8",
        "9.255.255.255",
        "11.0.0.0",
        "100.63.255.255",
        "100.128.0.0",
        "172.15.255.255",
        "172.32.0.0",
        "192.0.3.1",
        "192.169.0.1",
        "198.17.255.255",
        "198.20.0.0",
        "198.51.101.1",
        "203.0.114.1",
        "223.255.255.255",
        "2606:4700:4700::1111",
        "2001:200::1",  # first block after 2001::/23
        "2a00:1450:4001::200e",
        "::ffff:8.8.8.8",
        "64:ff9b::8.8.8.8",
        "2002:0808:0808::1",  # 6to4 for 8.8.8.8
    ],
)
def test_public(address: str) -> None:
    assert is_public(ip_address(address))


def test_scoped_ipv6_is_never_public() -> None:
    assert not is_public(IPv6Address("2606:4700::1%eth0"))


def test_canonical_form() -> None:
    assert canonical(IPv6Address("::ffff:8.8.8.8")) == IPv4Address("8.8.8.8")
    assert canonical(IPv6Address("2606:4700::1")) == IPv6Address("2606:4700::1")
    assert canonical(IPv4Address("8.8.8.8")) == IPv4Address("8.8.8.8")


def test_embedded_ipv4() -> None:
    assert embedded_ipv4(IPv6Address("::ffff:1.2.3.4")) == IPv4Address("1.2.3.4")
    assert embedded_ipv4(IPv6Address("64:ff9b::1.2.3.4")) == IPv4Address("1.2.3.4")
    assert embedded_ipv4(IPv6Address("2002:0102:0304::1")) == IPv4Address("1.2.3.4")
    assert embedded_ipv4(IPv6Address("2606:4700::1")) is None


@pytest.mark.parametrize(
    ("text", "expected"),
    [(" 8.8.8.8 ", "8.8.8.8"), ("2001:DB8::0001", "2001:db8::1")],
)
def test_parse_ip_normalises(text: str, expected: str) -> None:
    assert str(parse_ip(text)) == expected


@pytest.mark.parametrize(
    "text", ["example.com", "", "1.2.3", "8.8.8.8/32", "fe80::1%eth0", "01.2.3.4"]
)
def test_parse_ip_rejects(text: str) -> None:
    with pytest.raises(ValueError, match=r"does not appear|zone id"):
        parse_ip(text)
