"""Tests for the CA bundle shipped with pip's vendored certifi."""

from __future__ import annotations

import hashlib
import ssl

from pip._vendor import certifi

# SHA-256 fingerprint of "emSign ECC Root CA - G3", distrusted (CVE-2026-133949).
EMSIGN_ECC_ROOT_CA_G3_SHA256 = (
    "86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b"
)

# Number of certificates in the pip 26.2.1 bundle, minus the removed root.
EXPECTED_CERT_COUNT = 118 - 1


def _bundle_der_certs() -> list[bytes]:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(cafile=certifi.where())
    return ctx.get_ca_certs(binary_form=True)


def test_emsign_ecc_root_ca_g3_removed() -> None:
    fingerprints = {hashlib.sha256(der).hexdigest() for der in _bundle_der_certs()}
    assert EMSIGN_ECC_ROOT_CA_G3_SHA256 not in fingerprints


def test_bundle_loads_with_expected_cert_count() -> None:
    assert len(_bundle_der_certs()) == EXPECTED_CERT_COUNT


def test_pem_cert_count_matches_loaded_count() -> None:
    content = certifi.contents()
    assert "emSign ECC Root CA - G3" not in content
    assert content.count("-----BEGIN CERTIFICATE-----") == EXPECTED_CERT_COUNT
