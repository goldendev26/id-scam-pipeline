"""Unit tests for src.dns_pivot (FR-PIVOT-001, Task #33)."""

import unittest

from src.dns_pivot import (
    DnsProfile,
    cluster_by_infra,
    compare_infra,
    expand_from_seed,
    generate_sibling_candidates,
    is_cloudflare_ip,
    is_shared_nameserver,
    split_domain_stem_and_tld,
)


class TestDnsPivotHelpers(unittest.TestCase):
    def test_split_domain_stem_and_tld_handles_indonesian_suffixes(self):
        self.assertEqual(split_domain_stem_and_tld("gacor12.bet"), ("", "gacor12", "bet"))
        self.assertEqual(split_domain_stem_and_tld("brimo-tarif.my.id"), ("", "brimo-tarif", "my.id"))
        self.assertEqual(split_domain_stem_and_tld("m.slot88.co.id"), ("m", "slot88", "co.id"))

    def test_cdn_and_shared_ns_detection(self):
        self.assertTrue(is_cloudflare_ip("104.21.15.88"))
        self.assertTrue(is_cloudflare_ip("172.67.140.10"))
        self.assertFalse(is_cloudflare_ip("203.194.112.50"))

        self.assertTrue(is_shared_nameserver("alice.ns.cloudflare.com"))
        self.assertFalse(is_shared_nameserver("ns1.custombandar.net"))

    def test_generate_sibling_candidates_sequences_and_tlds(self):
        cands = generate_sibling_candidates("https://www.gacor12.bet/slot", number_window=2, max_candidates=30)
        doms = {d for d, _t in cands}
        self.assertNotIn("gacor12.bet", doms)
        self.assertIn("gacor10.bet", doms)
        self.assertIn("gacor11.bet", doms)
        self.assertIn("gacor13.bet", doms)
        self.assertIn("gacor14.bet", doms)
        self.assertIn("gacor12.com", doms)
        self.assertIn("gacor12.xyz", doms)

    def test_generate_sibling_candidates_leading_number_and_official_skip(self):
        cands = generate_sibling_candidates("234togel.org", number_window=1, max_candidates=10)
        doms = {d for d, _t in cands}
        self.assertIn("233togel.org", doms)
        self.assertIn("235togel.org", doms)
        self.assertEqual(generate_sibling_candidates("bri.co.id"), [])

    def test_compare_infra_and_cluster_by_infra(self):
        p1 = DnsProfile(
            domain="slot1.xyz",
            a_records=("203.194.112.50",),
            ns_records=("ns1.operator.net", "ns2.operator.net"),
        )
        p2 = DnsProfile(
            domain="slot2.xyz",
            a_records=("203.194.112.50",),
            ns_records=("ns1.operator.net", "ns2.operator.net"),
        )
        p3 = DnsProfile(
            domain="other.xyz",
            a_records=("104.21.15.88",),
            ns_records=("alice.ns.cloudflare.com", "bob.ns.cloudflare.com"),
            behind_shared_cdn=True,
        )

        match, signals = compare_infra(p1, p2)
        self.assertTrue(match)
        self.assertIn("ip:203.194.112.50", signals)
        self.assertIn("ns:ns1.operator.net", signals)

        clusters = cluster_by_infra([p1, p2, p3])
        self.assertEqual(clusters["ip:203.194.112.50"], ["slot1.xyz", "slot2.xyz"])
        self.assertNotIn("ip:104.21.15.88", clusters)


class TestExpandFromSeedAsync(unittest.IsolatedAsyncioTestCase):
    async def test_expand_returns_only_live_siblings_and_ranks_infra_matches_first(self):
        fake_dns = {
            ("gacor12.bet", "A"): ("203.194.112.50",),
            ("gacor12.bet", "NS"): ("ns1.bandar.net",),
            ("gacor13.bet", "A"): ("203.194.112.50",),
            ("gacor13.bet", "NS"): ("ns1.bandar.net",),
            ("gacor12.com", "A"): ("198.51.100.7",),
            ("gacor12.com", "NS"): ("ns1.unrelated.org",),
        }

        def fake_query(domain: str, rdtype: str, timeout_s: float):
            return fake_dns.get((domain, rdtype), ())

        results = await expand_from_seed(
            "gacor12.bet",
            number_window=2,
            max_candidates=20,
            query_fn=fake_query,
            verbose=False,
        )
        self.assertEqual([r.normalized_url for r in results], ["gacor13.bet", "gacor12.com"])
        self.assertTrue(results[0].infra_match)
        self.assertIn("ip:203.194.112.50", results[0].matched_signals)
        self.assertFalse(results[1].infra_match)


if __name__ == "__main__":
    unittest.main()
