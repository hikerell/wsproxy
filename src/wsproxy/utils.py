import struct
import ipaddress

TCP_FRAME_OPEN = 1
TCP_FRAME_OPEN_ACK = 2
TCP_FRAME_DATA = 3
TCP_FRAME_CLOSE = 4
TCP_FRAME_ERROR = 5

TCP_FRAME_HEADER = struct.Struct("!BII")


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
    Unpack SOCKS5 address format from bytes or memoryview.
    Returns (host, port, consumed_bytes).
    """
    if not data:
        raise ValueError("Empty data")

    atyp = data[0]
    if atyp == 0x01:  # IPv4
        if len(data) < 7:
            raise ValueError("Insufficient data for IPv4")
        # Convert memoryview slice to bytes for ipaddress
        addr_bytes = bytes(data[1:5])
        host = str(ipaddress.IPv4Address(addr_bytes))
        port = struct.unpack("!H", data[5:7])[0]
        return host, port, 7
    elif atyp == 0x03:  # Domain
        if len(data) < 2:
            raise ValueError("Insufficient data for Domain")
        addr_len = data[1]
        if len(data) < 2 + addr_len + 2:
            raise ValueError("Insufficient data for Domain")
        # Convert memoryview slice to bytes for decode
        host_bytes = bytes(data[2 : 2 + addr_len])
        host = host_bytes.decode("utf-8")
        port = struct.unpack("!H", data[2 + addr_len : 2 + addr_len + 2])[0]
        return host, port, 2 + addr_len + 2
    elif atyp == 0x04:  # IPv6
        if len(data) < 19:
            raise ValueError("Insufficient data for IPv6")
        # Convert memoryview slice to bytes for ipaddress
        addr_bytes = bytes(data[1:17])
        host = str(ipaddress.IPv6Address(addr_bytes))
        port = struct.unpack("!H", data[17:19])[0]
        return host, port, 19
    else:
        raise ValueError(f"Unknown address type: {atyp}")


def normalize_host(host):
    """
    Normalize host literals for connection use.
    - Convert IPv4-mapped IPv6 (::ffff:x.x.x.x) to plain IPv4.
    - Keep regular IPv4/IPv6/domain unchanged.
    """
    if not host:
        return host

    # Some callers may pass bracketed IPv6 literals.
    h = host[1:-1] if host.startswith("[") and host.endswith("]") else host
    try:
        ip = ipaddress.ip_address(h)
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            return str(ip.ipv4_mapped)
        return str(ip)
    except ValueError:
        return host


def pack_tcp_frame(frame_type, sid, payload=b""):
    """
    Pack one TCP tunnel frame:
    | type(1) | sid(4) | len(4) | payload(len) |
    """
    if payload is None:
        payload = b""
    if not isinstance(payload, (bytes, bytearray, memoryview)):
        raise TypeError("payload must be bytes-like")
    if isinstance(payload, memoryview):
        payload = payload.tobytes()
    elif isinstance(payload, bytearray):
        payload = bytes(payload)
    return TCP_FRAME_HEADER.pack(frame_type, sid, len(payload)) + payload


def iter_tcp_frames(data):
    """
    Iterate frames from one decrypted websocket payload.
    Returns (frame_type, sid, payload_memoryview).
    """
    mv = memoryview(data)
    offset = 0
    total = len(mv)
    hsize = TCP_FRAME_HEADER.size

    while offset < total:
        if total - offset < hsize:
            raise ValueError("truncated tcp frame header")
        frame_type, sid, payload_len = TCP_FRAME_HEADER.unpack_from(mv, offset)
        offset += hsize
        if payload_len < 0 or total - offset < payload_len:
            raise ValueError("truncated tcp frame payload")
        payload = mv[offset : offset + payload_len]
        offset += payload_len
        yield frame_type, sid, payload

def hexdump(data):
    """
    将字节序列以十六进制和可打印字符形式输出，类似 hexdump -C 的效果。
    返回字符串，每行格式：
    00000000  00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f  |................|
    """
    if not data:
        return ""
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hex_parts = []
        ascii_parts = []
        for j, b in enumerate(chunk):
            hex_parts.append(f"{b:02x}")
            ascii_parts.append(chr(b) if 32 <= b <= 126 else ".")
        hex_line = " ".join(hex_parts[:8]) + "  " + " ".join(hex_parts[8:]) if len(hex_parts) > 8 else " ".join(hex_parts)
        ascii_line = "".join(ascii_parts)
        lines.append(f"{i:08x}  {hex_line:<47}  |{ascii_line}|")
    return "\n".join(lines)
