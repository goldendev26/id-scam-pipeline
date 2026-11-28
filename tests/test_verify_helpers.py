"""Unit tests for page text extraction and dead/parked/Trust+ detection (FR-VERIF-001)."""

import unittest

from src.config import (
    ERR_HTTP_ERROR,
    PAGE_TEXT_MAX_CHARS,
    STATUS_DEAD_OR_BLOCKED,
    STATUS_VERIFIED,
)
from src.verify import (
    REASON_HTTP_ERROR,
    REASON_PARKED,
    REASON_SUSPENDED,
    REASON_TRUST_POSITIF,
    assess_page,
    extract_clean_text,
)


class TestExtractCleanText(unittest.TestCase):
    def test_removes_scripts_styles_and_head(self):
        html = (
            "<html><head><title>Judul</title><style>.a{color:red}</style></head>"
            "<body><script>alert(1)</script><noscript>no js</noscript>"
            "<h1>Slot   Gacor</h1><p>Daftar\n sekarang</p></body></html>"
        )
        self.assertEqual(extract_clean_text(html), "Slot Gacor Daftar sekarang")

    def test_caps_at_2000_chars(self):
        html = "<body>" + ("kata " * 1000) + "</body>"
        text = extract_clean_text(html)
        self.assertLessEqual(len(text), PAGE_TEXT_MAX_CHARS)
        self.assertEqual(len(text), PAGE_TEXT_MAX_CHARS - 1)

    def test_custom_limit_and_empty_input(self):
        self.assertEqual(extract_clean_text("<p>abcdefghij</p>", max_chars=5), "abcde")
        self.assertEqual(extract_clean_text(""), "")
        self.assertEqual(extract_clean_text(None), "")

    def test_strips_invisible_characters(self):
        self.assertEqual(extract_clean_text("<p>sl\u200bot</p>"), "slot")


class TestAssessPage(unittest.TestCase):
    def assess(self, text="", *, url="https://slot.id/", status=200, title=None):
        return assess_page(final_url=url, http_status=status, title=title, text=text)

    def test_normal_page_is_verified(self):
        res = self.assess("Daftar slot gacor hari ini bonus new member")
        self.assertEqual(res.status, STATUS_VERIFIED)
        self.assertIsNone(res.reason)
        self.assertFalse(res.is_dead_or_blocked)

    def test_trust_positif_by_host(self):
        res = self.assess("", url="http://internetpositif.id/blocked?u=slot.id")
        self.assertEqual(res.status, STATUS_DEAD_OR_BLOCKED)
        self.assertEqual(res.reason, REASON_TRUST_POSITIF)

    def test_trust_positif_by_subdomain_host(self):
        res = self.assess("", url="https://block.trustpositif.komdigi.go.id/x")
        self.assertEqual(res.reason, REASON_TRUST_POSITIF)

    def test_trust_positif_by_text(self):
        res = self.assess("Internet Positif. Situs ini diblokir oleh Komdigi.")
        self.assertEqual(res.status, STATUS_DEAD_OR_BLOCKED)
        self.assertEqual(res.reason, REASON_TRUST_POSITIF)

    def test_trust_positif_by_title(self):
        res = self.assess("Akses ditolak", title="Internet Positif")
        self.assertEqual(res.reason, REASON_TRUST_POSITIF)

    def test_long_page_mentioning_internet_positif_is_not_flagged(self):
        res = self.assess("Berita tentang Internet Positif. " + "isi berita " * 300)
        self.assertEqual(res.status, STATUS_VERIFIED)

    def test_parked_by_text(self):
        res = self.assess("This domain is for sale. Contact the owner.")
        self.assertEqual(res.status, STATUS_DEAD_OR_BLOCKED)
        self.assertEqual(res.reason, REASON_PARKED)

    def test_parked_by_host(self):
        res = self.assess("", url="https://sedoparking.com/slot.id")
        self.assertEqual(res.reason, REASON_PARKED)

    def test_default_server_page_counts_as_parked(self):
        res = self.assess("Welcome to nginx! If you see this page, nginx is working.")
        self.assertEqual(res.reason, REASON_PARKED)

    def test_suspended_account(self):
        res = self.assess("This Account Has Been Suspended")
        self.assertEqual(res.reason, REASON_SUSPENDED)

    def test_http_error(self):
        res = self.assess("Not found", status=404)
        self.assertEqual(res.status, STATUS_DEAD_OR_BLOCKED)
        self.assertEqual(res.reason, REASON_HTTP_ERROR)
        self.assertEqual(res.error_code, ERR_HTTP_ERROR)
        self.assertEqual(res.detail, "HTTP 404")

    def test_missing_http_status_and_url_are_tolerated(self):
        res = assess_page(final_url=None, http_status=None, title=None, text="halaman biasa")
        self.assertEqual(res.status, STATUS_VERIFIED)

    def test_end_to_end_with_html(self):
        html = "<html><body><h1>Internet Positif</h1><p>Situs ini diblokir.</p></body></html>"
        res = self.assess(extract_clean_text(html))
        self.assertEqual(res.reason, REASON_TRUST_POSITIF)


if __name__ == "__main__":
    unittest.main()