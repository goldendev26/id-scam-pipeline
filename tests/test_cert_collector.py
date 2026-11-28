"""Unit tests for src.cert_collector"""

import base64
from datetime import datetime, timedelta, timezone
import json
import struct
import unittest

from src.cert_collector import (
    classify_domain,
    extract_domains_from_ct_entry,
    is_official_domain,
    parse_certstream_message,
    parse_crtsh_entries,
    parse_ct_entries,
)


def _make_fake_x509_ct_entry(dns_names):
    """Build a valid RFC 6962 X509LogEntry using a self-signed test cert."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, dns_names[0])])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(hours=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(name) for name in dns_names]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    der = cert.public_bytes(serialization.Encoding.DER)
    ts_ms = int(now.timestamp() * 1000)
    # RFC 6962 MerkleTreeLeaf: version(1) + leaf_type(1) + timestamp(8) + entry_type(2) + len(3) + der
    leaf = b"\x00\x00" + struct.pack("!QH", ts_ms, 0) + len(der).to_bytes(3, "big") + der
    return {"leaf_input": base64.b64encode(leaf).decode("ascii")}


class TestDomainClassification(unittest.TestCase):
    def test_matches_judol_and_pinjol_domains(self):
        judol_cases = [
            ("*.slotgacor99.xyz", "slotgacor99.xyz", "judol"),
            ("www.MaxWin88.id", "maxwin88.id", "judol"),
            ("bandar-togel-resmi.com", "bandar-togel-resmi.com", "judol"),
            ("sabung-ayam-live.net", "sabung-ayam-live.net", "judol"),
        ]
        for raw, expected_norm, expected_cat in judol_cases:
            with self.subTest(raw=raw):
                hit = classify_domain(raw)
                self.assertIsNotNone(hit)
                norm, cat, _rule = hit
                self.assertEqual(norm, expected_norm)
                self.assertEqual(cat, expected_cat)

        pinjol_cases = [
            ("pinjolcepat-id.xyz", "pinjolcepat-id.xyz", "pinjol"),
            ("*.dana-kilat-cair.my.id", "dana-kilat-cair.my.id", "pinjol"),
            ("pinjaman-online-ktp.shop", "pinjaman-online-ktp.shop", "pinjol"),
        ]
        for raw, expected_norm, expected_cat in pinjol_cases:
            with self.subTest(raw=raw):
                hit = classify_domain(raw)
                self.assertIsNotNone(hit)
                norm, cat, _rule = hit
                self.assertEqual(norm, expected_norm)
                self.assertEqual(cat, expected_cat)

    def test_matches_indonesian_phishing_brand_plus_lure(self):
        phish_cases = [
            "brimo-tarif-baru.my.id",
            "verifikasi-akun-bca.xyz",
            "klaim-bansos-resmi.shop",
            "update-livin-mandiri.com",
            "cek-resi-jne-paket.my.id",
        ]
        for raw in phish_cases:
            with self.subTest(raw=raw):
                hit = classify_domain(raw)
                self.assertIsNotNone(hit, f"Expected phishing hit for {raw}")
                norm, cat, _rule = hit
                self.assertEqual(norm, raw)
                self.assertEqual(cat, "phishing")

    def test_ignores_official_domains_and_benign_substrings(self):
        benign = [
            "bri.co.id",
            "ib.bri.co.id",
            "www.bca.co.id",
            "dana.id",
            "kemensos.go.id",
            "imphnen.dev",
            "my-library-update.com",
            "banana-promo-shop.com",
            "localhost",
            "103.21.44.5",
        ]
        for raw in benign:
            with self.subTest(raw=raw):
                self.assertIsNone(classify_domain(raw), f"False positive on {raw}")

        self.assertTrue(is_official_domain("promo.bri.co.id"))
        self.assertFalse(is_official_domain("bri-promo.co.id"))


class TestCTLogParsers(unittest.TestCase):
    def test_extract_and_parse_rfc6962_ct_entry(self):
        entry = _make_fake_x509_ct_entry(
            ["*.234togel.org", "www.234togel.org", "bri.co.id", "normal.example.com"]
        )
        domains, issued_at = extract_domains_from_ct_entry(entry)
        self.assertEqual(len(domains), 4)
        self.assertIsNotNone(issued_at)

        hits, dom_count = parse_ct_entries([entry])
        self.assertEqual(dom_count, 4)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].normalized_url, "234togel.org")
        self.assertEqual(hits[0].category_hint, "judol")
        self.assertEqual(hits[0].source, "ct_log")

    def test_parse_crtsh_entries_dedupes_and_enforces_max_age(self):
        now = datetime(2026, 12, 6, 12, 0, tzinfo=timezone.utc)
        rows = [
            {
                "entry_timestamp": "2026-12-05T10:00:00",
                "common_name": "*.slotgacor77.xyz",
                "name_value": "*.slotgacor77.xyz\nslotgacor77.xyz\nwww.slotgacor77.xyz",
            },
            {
                "entry_timestamp": "2026-11-01T10:00:00",
                "common_name": "old-slotgacor.xyz",
                "name_value": "old-slotgacor.xyz",
            },
            {
                "entry_timestamp": "2026-12-06T08:00:00",
                "common_name": "brimo-verifikasi-tarif.my.id",
                "name_value": "brimo-verifikasi-tarif.my.id\nwww.bri.co.id",
            },
        ]

        items = parse_crtsh_entries(rows, max_age_days=7, now=now)
        urls = [i.normalized_url for i in items]
        self.assertEqual(urls, ["slotgacor77.xyz", "brimo-verifikasi-tarif.my.id"])
        self.assertEqual(items[0].category_hint, "judol")
        self.assertEqual(items[0].source, "crtsh")
        self.assertEqual(items[1].category_hint, "phishing")

    def test_parse_certstream_message_extracts_valid_threats_only(self):
        frame = json.dumps(
            {
                "message_type": "certificate_update",
                "data": {
                    "seen": 1796520000.0,
                    "leaf_cert": {
                        "all_domains": [
                            "*.pinjol-cair-cepat.xyz",
                            "www.pinjol-cair-cepat.xyz",
                            "normal-blog.example.org",
                            "*.bri.co.id",
                            "klaim-hadiah-dana.my.id",
                        ]
                    },
                },
            }
        )
        items = parse_certstream_message(frame)
        self.assertEqual(
            [(i.normalized_url, i.category_hint) for i in items],
            [
                ("pinjol-cair-cepat.xyz", "pinjol"),
                ("klaim-hadiah-dana.my.id", "phishing"),
            ],
        )
        self.assertTrue(all(i.source == "certstream" for i in items))
        self.assertTrue(all(i.issued_at is not None for i in items))

    def test_parse_certstream_ignores_heartbeats_and_invalid_json(self):
        self.assertEqual(parse_certstream_message('{"message_type":"heartbeat"}'), [])
        self.assertEqual(parse_certstream_message("not-json"), [])


if __name__ == "__main__":
    unittest.main()
