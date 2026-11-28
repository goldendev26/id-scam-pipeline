"""Unit tests for src.discover (OpenPhish, PhishingDB, and CSV/TXT dork importer)."""

import unittest

from src.discover import classify_feed_url, parse_dork_text, parse_feed_lines


class TestDiscoverClassifierAndParsers(unittest.TestCase):
    def test_classify_feed_url_catches_hacked_ac_id_and_indo_phish(self):
        hacked = classify_feed_url(
            "https://kampuscontoh.ac.id/wp-content/uploads/slot-gacor/?ref=1",
            source="dork_import",
        )
        self.assertIsNotNone(hacked)
        self.assertEqual(hacked.normalized_url, "kampuscontoh.ac.id/wp-content/uploads/slot-gacor")
        self.assertEqual(hacked.category_hint, "judol")

        phish = classify_feed_url(
            "https://brimo-tarif-baru.my.id/login/",
            source="openphish",
        )
        self.assertIsNotNone(phish)
        self.assertEqual(phish.normalized_url, "brimo-tarif-baru.my.id/login")
        self.assertEqual(phish.category_hint, "phishing")

        self.assertIsNone(classify_feed_url("https://www.bri.co.id/", source="openphish"))

    def test_parse_feed_lines_filters_indonesia_and_dedupes(self):
        lines = [
            "# feed comment",
            "https://slotgacor99.xyz/daftar",
            "http://www.slotgacor99.xyz/daftar?utm=1",
            "https://unrelated-us-malware.example.org/payload.exe",
            "https://scam-toko.my.id/promo",
            "http://192.168.1.1/bad",
        ]
        indo_only = parse_feed_lines(lines, source="openphish", indonesia_only=True)
        self.assertEqual(
            [c.normalized_url for c in indo_only],
            ["slotgacor99.xyz/daftar", "scam-toko.my.id/promo"],
        )

        with_global = parse_feed_lines(lines, source="openphish", indonesia_only=False)
        self.assertEqual(len(with_global), 3)

    def test_parse_dork_text_supports_csv_and_plain_lines(self):
        csv_text = (
            "title,url,snippet\n"
            "Slot Gacor,https://sekolah.sch.id/slot-maxwin/?a=1,desc\n"
            "Dup,http://www.sekolah.sch.id/slot-maxwin/,desc\n"
            "Pinjol,https://pinjol-cepat.xyz/apk,desc\n"
        )
        from_csv = parse_dork_text(csv_text)
        self.assertEqual(
            [c.normalized_url for c in from_csv],
            ["sekolah.sch.id/slot-maxwin", "pinjol-cepat.xyz/apk"],
        )
        self.assertEqual(from_csv[0].category_hint, "judol")
        self.assertEqual(from_csv[1].category_hint, "pinjol")

        txt = "# dork results\nhttps://desa-contoh.desa.id/togel-hk\nslot88-resmi.id\n"
        from_txt = parse_dork_text(txt)
        self.assertEqual(
            [c.normalized_url for c in from_txt],
            ["desa-contoh.desa.id/togel-hk", "slot88-resmi.id"],
        )


if __name__ == "__main__":
    unittest.main()
