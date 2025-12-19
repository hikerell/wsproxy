import struct
import ipaddress


def pack_addr(host, port):
    """
    Pack host and port into SOCKS5 address format (ATYP | ADDR | PORT).
    Returns bytes.
    """
    try:
        # Try IPv4
        addr = ipaddress.IPv4Address(host)
        return b"\x01" + addr.packed + struct.pack("!H", port)
    except ipaddress.AddressValueError:
        try:
            # Try IPv6
            addr = ipaddress.IPv6Address(host)
            return b"\x04" + addr.packed + struct.pack("!H", port)
        except ipaddress.AddressValueError:
            # Domain name
            encoded = host.encode("utf-8")
            if len(encoded) > 255:
                raise ValueError("Domain name too long")
            return (
                b"\x03"
                + struct.pack("!B", len(encoded))
                + encoded
                + struct.pack("!H", port)
            )


def unpack_addr(data):
    """
    Unpack SOCKS5 address format from bytes.
    Returns (host, port, consumed_bytes).
    """
    if not data:
        raise ValueError("Empty data")

    atyp = data[0]
    if atyp == 0x01:  # IPv4
        if len(data) < 7:
            raise ValueError("Insufficient data for IPv4")
        host = str(ipaddress.IPv4Address(data[1:5]))
        port = struct.unpack("!H", data[5:7])[0]
        return host, port, 7
    elif atyp == 0x03:  # Domain
        if len(data) < 2:
            raise ValueError("Insufficient data for Domain")
        addr_len = data[1]
        if len(data) < 2 + addr_len + 2:
            raise ValueError("Insufficient data for Domain")
        host = data[2 : 2 + addr_len].decode("utf-8")
        port = struct.unpack("!H", data[2 + addr_len : 2 + addr_len + 2])[0]
        return host, port, 2 + addr_len + 2
    elif atyp == 0x04:  # IPv6
        if len(data) < 19:
            raise ValueError("Insufficient data for IPv6")
        host = str(ipaddress.IPv6Address(data[1:17]))
        port = struct.unpack("!H", data[17:19])[0]
        return host, port, 19
    else:
        raise ValueError(f"Unknown address type: {atyp}")
