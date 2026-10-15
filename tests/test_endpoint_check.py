"""Protocol tests use fake sockets; never contact a real endpoint."""
import hashlib
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

spec = importlib.util.spec_from_file_location("endpoint_check", Path(__file__).resolve().parents[1] / "netbox_certificates/services/endpoint_check.py")
endpoint_check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(endpoint_check)


class EndpointCheckTests(unittest.TestCase):
    def service(self, **kwargs):
        values = dict(primary_url="https://example.com:8443/path", hostname="fallback.example.com",
                      port=443, protocol="https", sni_name="tls.example.com")
        return SimpleNamespace(**(values | kwargs))

    def test_url_host_and_port_take_precedence(self):
        self.assertEqual(endpoint_check.endpoint(self.service()), ("example.com", 8443))
        self.assertEqual(endpoint_check.endpoint(self.service(primary_url="")), ("fallback.example.com", 443))

    @patch.object(endpoint_check.socket, "create_connection")
    @patch.object(endpoint_check.ssl, "SSLContext")
    def test_leaf_certificate_hash_and_sni(self, context, connect):
        secured = context.return_value.wrap_socket.return_value.__enter__.return_value
        secured.getpeercert.return_value = b"DER certificate"
        result = endpoint_check.certificate_fingerprint(self.service())
        self.assertEqual(result, hashlib.sha256(b"DER certificate").hexdigest())
        connect.assert_called_once_with(("example.com", 8443), timeout=5)
        self.assertEqual(context.return_value.wrap_socket.call_args.kwargs["server_hostname"], "tls.example.com")

    def test_postgresql_tls_negotiation(self):
        sock = MagicMock()
        sock.recv.return_value = b"S"
        endpoint_check._negotiate(sock, "postgresql")
        sock.sendall.assert_called_once_with(bytes.fromhex("0000000804d2162f"))
        sock.recv.return_value = b"N"
        with self.assertRaises(OSError):
            endpoint_check._negotiate(sock, "postgresql")

    def test_mysql_ssl_request(self):
        greeting = b"\x0a8.0\0" + b"\0" * 13 + b"\x00\x0a" + b"\x2d\x00\x00"
        sock = MagicMock()
        sock.recv.side_effect = [len(greeting).to_bytes(3, "little") + b"\0", greeting]
        endpoint_check._negotiate(sock, "mysql")
        packet = sock.sendall.call_args.args[0]
        self.assertEqual(packet[:4], b"\x20\0\0\x01")
        self.assertEqual(len(packet), 36)

    @patch.object(endpoint_check.socket, "create_connection")
    def test_unknown_protocol_never_connects(self, connect):
        with self.assertRaises(ValueError):
            endpoint_check.certificate_fingerprint(self.service(protocol="http"))
        connect.assert_not_called()

    def test_truncated_greeting_fails(self):
        sock = MagicMock()
        sock.recv.return_value = b""
        with self.assertRaises(OSError):
            endpoint_check._negotiate(sock, "mysql")
