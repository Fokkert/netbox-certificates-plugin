"""Opt-in TLS certificate inspection. No HTTP requests or credentials are sent."""
import hashlib
import socket
import ssl
import struct
from urllib.parse import urlsplit


DIRECT_TLS = {"https", "tls", "ssl", "ldaps", "smtps", "imaps", "pop3s", "mqtts"}
SUPPORTED_PROTOCOLS = DIRECT_TLS | {"postgresql", "mysql"}


def endpoint(service):
    parsed = urlsplit(service.primary_url or "")
    host = parsed.hostname or service.hostname
    if not host:
        raise ValueError("A URL or hostname is required for certificate checks.")
    return host, parsed.port or service.port


def _receive(connection, size):
    data = bytearray()
    while len(data) < size:
        chunk = connection.recv(size - len(data))
        if not chunk:
            raise OSError("Endpoint closed the connection before TLS negotiation.")
        data.extend(chunk)
    return bytes(data)


def _negotiate(connection, protocol):
    if protocol == "postgresql":
        connection.sendall(struct.pack("!II", 8, 80877103))
        if _receive(connection, 1) != b"S":
            raise OSError("PostgreSQL endpoint does not accept TLS.")
    elif protocol == "mysql":
        header = _receive(connection, 4)
        size = int.from_bytes(header[:3], "little")
        if not 1 <= size <= 65536:
            raise OSError("Invalid MySQL greeting size.")
        greeting = _receive(connection, size)
        if greeting[0] != 10:
            raise OSError("Unsupported MySQL greeting.")
        offset = greeting.find(b"\0", 1)
        if offset < 0 or len(greeting) < offset + 19:
            raise OSError("Invalid MySQL greeting.")
        capabilities = int.from_bytes(greeting[offset + 14:offset + 16], "little")
        if not capabilities & 0x0800:
            raise OSError("MySQL endpoint does not advertise TLS.")
        # Protocol 4.1 SSLRequest, without user names or authentication data.
        payload = struct.pack("<IIB23s", 0x0200 | 0x0800, 16777216, 45, b"")
        connection.sendall(len(payload).to_bytes(3, "little") + b"\x01" + payload)


def certificate_fingerprint(service, timeout=5):
    protocol = service.protocol.lower()
    if protocol not in SUPPORTED_PROTOCOLS:
        raise ValueError("This protocol does not support automatic certificate checks.")
    host, port = endpoint(service)
    # Inspect the presented certificate even when expired or privately issued.
    # This is identity comparison, not a CA trust or hostname validation test.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as connection:
        connection.settimeout(timeout)
        _negotiate(connection, protocol)
        with context.wrap_socket(connection, server_hostname=service.sni_name or host) as secured:
            der = secured.getpeercert(binary_form=True)
            if not der:
                raise OSError("Endpoint did not present a certificate.")
            return hashlib.sha256(der).hexdigest()


def normalize_fingerprint(value):
    return str(value or "").replace(":", "").strip().lower()
