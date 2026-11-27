"""Unit tests for src.normalizer (FR-NORM-001)."""

import unittest

from src.normalizer import MAX_BATCH_ITEMS, MAX_URL_LENGTH, normalize_batch, normalize_url


class TestNormalizeUrlOfficialExamples(unittest.TestCase):
    def test_official_examples_from_site(self):
        cases = [
            ("https://www.TokoBudi.id/", "tokobudi.id"),
            ("tokobudi.id", "tokobudi.id"),
            ("http://TOKOBUDI.id/?utm=ig#promo", "tokobudi.id"),
            ("tokobudi.id/produk", "tokobudi.id/produk"),
            ("blog.tokobudi.id", "blog.tokobudi.id"),
        ]
        for raw, expected in cases:
            with self.subTest(raw=raw):
                res = normalize_url(raw)
                self.assertTrue(res.ok, f"Expected OK for {raw}, got {res}")
                self.assertEqual(res.normalized, expected)
                self.assertEqual(res.display, expected)


class TestNormalizeUrlEdgeCases(unittest.TestCase):
    def test_strips_only_one_www(self):
        self.assertEqual(normalize_url("https://www.example.com").normalized, "example.com")
        self.assertEqual(normalize_url("https://www.www.example.com").normalized, "www.example.com")
        self.assertEqual(normalize_url("https://m.example.com").normalized, "m.example.com")

    def test_path_is_case_sensitive(self):
        lower = normalize_url("https://tokobudi.id/produk")
        upper = normalize_url("https://tokobudi.id/Produk")
        self.assertTrue(lower.ok and upper.ok)
        self.assertEqual(lower.normalized, "tokobudi.id/produk")
        self.assertEqual(upper.normalized, "tokobudi.id/Produk")
        self.assertNotEqual(lower.normalized, upper.normalized)

    def test_trailing_slashes_query_and_fragment_stripped(self):
        self.assertEqual(normalize_url("tokobudi.id///").normalized, "tokobudi.id")
        self.assertEqual(normalize_url("https://tokobudi.id/slot///?ref=wa#top").normalized, "tokobudi.id/slot")
        self.assertEqual(normalize_url("  https://SLOT.ID/daftar/?a=1  ").normalized, "slot.id/daftar")

    def test_default_ports_allowed_non_default_ports_forbidden(self):
        self.assertEqual(normalize_url("https://tokobudi.id:443/slot").normalized, "tokobudi.id/slot")
        self.assertEqual(normalize_url("http://tokobudi.id:80/slot").normalized, "tokobudi.id/slot")

        for raw in ("https://tokobudi.id:8080", "http://tokobudi.id:443", "tokobudi.id:3000/login"):
            with self.subTest(raw=raw):
                res = normalize_url(raw)
                self.assertFalse(res.ok)
                self.assertEqual(res.error_code, "ERR_FORBIDDEN")
                self.assertEqual(res.site_code, "terlarang")

    def test_empty_and_too_long(self):
        for raw in ("", "   ", "\t\n"):
            res = normalize_url(raw)
            self.assertFalse(res.ok)
            self.assertEqual(res.error_code, "ERR_EMPTY")
            self.assertEqual(res.site_code, "kosong")

        exact_300 = "https://a.id/" + "x" * (MAX_URL_LENGTH - len("https://a.id/"))
        self.assertEqual(len(exact_300), 300)
        self.assertTrue(normalize_url(exact_300).ok)

        over_300 = exact_300 + "y"
        self.assertEqual(len(over_300), 301)
        res = normalize_url(over_300)
        self.assertFalse(res.ok)
        self.assertEqual(res.error_code, "ERR_TOO_LONG")
        self.assertEqual(res.site_code, "kepanjangan")

    def test_forbidden_hosts_and_credentials(self):
        forbidden = [
            "http://103.21.44.5/slot",
            "192.168.1.1",
            "http://127.1/admin",
            "http://2130706433/",
            "http://[::1]/slot",
            "http://localhost/test",
            "https://sub.localhost/test",
            "https://user:pass@tokobudi.id",
            "https://user@tokobudi.id",
            "https://@tokobudi.id",
        ]
        for raw in forbidden:
            with self.subTest(raw=raw):
                res = normalize_url(raw)
                self.assertFalse(res.ok, f"Expected failure for {raw}")
                self.assertEqual(res.error_code, "ERR_FORBIDDEN")
                self.assertEqual(res.site_code, "terlarang")

    def test_invalid_formats_and_schemes(self):
        invalid = [
            "javascript:alert(1)",
            "mailto:test@example.com",
            "ftp://files.example.com/app.apk",
            "data:text/html,<h1>hi</h1>",
            "not-a-domain",
            "example.c",
            "bad_underscore.example.com",
            "https://tokobudi.id:abc/slot",
            "https://tokobudi.id:99999/slot",
        ]
        for raw in invalid:
            with self.subTest(raw=raw):
                res = normalize_url(raw)
                self.assertFalse(res.ok, f"Expected format error for {raw}")
                self.assertEqual(res.error_code, "ERR_FORMAT")
                self.assertEqual(res.site_code, "format")

    def test_idn_punycode_and_dot_segments(self):
        res_idn = normalize_url("https://münchen.de/promo/")
        self.assertTrue(res_idn.ok)
        self.assertEqual(res_idn.normalized, "xn--mnchen-3ya.de/promo")

        res_dots = normalize_url("https://tokobudi.id/a/b/../c/")
        self.assertTrue(res_dots.ok)
        self.assertEqual(res_dots.normalized, "tokobudi.id/a/c")

    def test_batch_mode_caps_at_20_and_skips_blank_lines(self):
        lines = [""] + [f"https://www.site{i}.id/" for i in range(1, 26)]
        parsed = normalize_batch("\n".join(lines))
        self.assertEqual(len(parsed), MAX_BATCH_ITEMS)
        self.assertEqual(parsed[0].line, 2)
        self.assertEqual(parsed[0].result.normalized, "site1.id")
        self.assertEqual(parsed[-1].line, 21)
        self.assertEqual(parsed[-1].result.normalized, "site20.id")


if __name__ == "__main__":
    unittest.main()
