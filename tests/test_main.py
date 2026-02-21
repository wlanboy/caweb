import pytest
from fastapi import HTTPException
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec

from main import validate_safe_name, parse_san_entry, generate_key


class TestValidateSafeName:
    def test_valid_hostname(self):
        assert validate_safe_name("example.com") is True

    def test_valid_with_dash_and_underscore(self):
        assert validate_safe_name("my-host_01") is True

    def test_empty_string(self):
        assert validate_safe_name("") is False

    def test_path_traversal_dotdot(self):
        assert validate_safe_name("..") is False

    def test_path_traversal_embedded(self):
        assert validate_safe_name("foo/../bar") is False

    def test_slash(self):
        assert validate_safe_name("foo/bar") is False

    def test_space(self):
        assert validate_safe_name("foo bar") is False

    def test_semicolon(self):
        assert validate_safe_name("foo;bar") is False

    def test_wildcard(self):
        assert validate_safe_name("foo*bar") is False


class TestParseSanEntry:
    def test_ipv4(self):
        result = parse_san_entry("192.168.1.1")
        assert isinstance(result, x509.IPAddress)

    def test_ipv6(self):
        result = parse_san_entry("::1")
        assert isinstance(result, x509.IPAddress)

    def test_dns_name(self):
        result = parse_san_entry("example.com")
        assert isinstance(result, x509.DNSName)

    def test_wildcard_dns(self):
        result = parse_san_entry("*.example.com")
        assert isinstance(result, x509.DNSName)


class TestGenerateKey:
    def test_rsa2048(self):
        key = generate_key("rsa2048")
        assert isinstance(key, rsa.RSAPrivateKey)
        assert key.key_size == 2048

    def test_rsa4096(self):
        key = generate_key("rsa4096")
        assert isinstance(key, rsa.RSAPrivateKey)
        assert key.key_size == 4096

    def test_secp256r1(self):
        key = generate_key("secp256r1")
        assert isinstance(key, ec.EllipticCurvePrivateKey)
        assert key.curve.name == "secp256r1"

    def test_secp384r1(self):
        key = generate_key("secp384r1")
        assert isinstance(key, ec.EllipticCurvePrivateKey)
        assert key.curve.name == "secp384r1"

    def test_secp521r1(self):
        key = generate_key("secp521r1")
        assert isinstance(key, ec.EllipticCurvePrivateKey)
        assert key.curve.name == "secp521r1"

    def test_invalid_key_type_raises(self):
        with pytest.raises(HTTPException) as exc_info:
            generate_key("invalid")
        assert exc_info.value.status_code == 400
