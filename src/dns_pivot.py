"""Passive DNS pivoter and sibling mirror expander (FR-PIVOT-001, Task #33).

Takes confirmed illegal domains and uses passive public DNS queries (`dnspython`)
to fingerprint infrastructure (A, AAAA, NS, CNAME, MX), cluster domains operated
by the same actor, and discover live sibling mirror domains (numeric sequences,
common mirror TLDs, and optional passive reverse-IP lookup).

Strictly passive and read-only: only performs standard public DNS lookups and
optional public passive API reads; never connects to or scans target hosts.
"""

from __future__ import annotations

import argparse
import asyncio
from dataclasses import asdict, dataclass, field
import ipaddress
import json
from pathlib import Path
import re
import sys
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from src.cert_collector import is_official_domain
from src.normalizer import normalize_url

DEFAULT_DNS_TIMEOUT_S = 3.0
DEFAULT_CONCURRENCY = 10
DEFAULT_NUMBER_WINDOW = 5
DEFAULT_MAX_CANDIDATES = 40

MIRROR_TLDS: Tuple[str, ...] = (
    "com",
    "net",
    "org",
    "xyz",
    "id",
    "my.id",
    "site",
    "online",
    "vip",
    "live",
    "bet",
    "shop",
    "pro",
    "top",
    "co",
)

# Shared CDN / major DNS providers whose IPs or NS records are too broad for clustering.
SHARED_CDN_NS_SUFFIXES: Tuple[str, ...] = (
    "cloudflare.com",
    "awsdns-",
    "googledomains.com",
    "google.com",
    "azure-dns.com",
    "azure-dns.net",
    "azure-dns.org",
    "azure-dns.info",
    "akamai.net",
    "akam.net",
    "fastly.net",
    "vercel-dns.com",
    "netlify.com",
    "domaincontrol.com",
    "registrar-servers.com",
    "hostinger.com",
    "dns-parking.com",
    "wixdns.net",
)

# Cloudflare public IPv4 ranges (used to avoid noisy reverse-IP pivots on CDN IPs).
_CLOUDFLARE_IPV4_CIDRS = tuple(
    ipaddress.ip_network(cidr)
    for cidr in (
        "173.245.48.0/20",
        "103.21.244.0/22",
        "103.22.200.0/22",
        "103.31.4.0/22",
        "141.101.64.0/18",
        "108.162.192.0/18",
        "190.93.240.0/20",
        "188.114.96.0/20",
        "197.234.240.0/22",
        "198.41.128.0/17",
        "162.158.0.0/15",
        "104.16.0.0/13",
        "104.24.0.0/14",
        "172.64.0.0/13",
        "131.0.72.0/22",
    )
)

# Multi-part public suffixes common in Indonesia so we split stem vs TLD accurately.
_MULTI_PART_TLDS: Tuple[str, ...] = (
    "co.id",
    "my.id",
    "biz.id",
    "web.id",
    "or.id",
    "ac.id",
    "sch.id",
    "go.id",
    "desa.id",
    "com.sg",
    "com.my",
    "co.uk",
)

_TRAILING_NUM_RE = re.compile(r"^(.*?)(\d{1,3})$")
_LEADING_NUM_RE = re.compile(r"^(\d{1,3})([a-z][a-z0-9-]*)$")


@dataclass(frozen=True)
class DnsProfile:
    domain: str
    a_records: Tuple[str, ...] = ()
    aaaa_records: Tuple[str, ...] = ()
    ns_records: Tuple[str, ...] = ()
    cname_records: Tuple[str, ...] = ()
    mx_records: Tuple[str, ...] = ()
    behind_shared_cdn: bool = False

    @property
    def resolves(self) -> bool:
        return bool(self.a_records or self.aaaa_records or self.cname_records)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["resolves"] = self.resolves
        return data


@dataclass(frozen=True)
class PivotCandidate:
    normalized_url: str
    seed_domain: str
    pivot_type: str
    source: str = "dns_pivot"
    infra_match: bool = False
    matched_signals: Tuple[str, ...] = ()
    a_records: Tuple[str, ...] = ()
    ns_records: Tuple[str, ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def extract_host(raw_url: str) -> Optional[str]:
    """Normalize input and extract its bare domain host (stripping any path)."""
    norm = normalize_url(raw_url)
    if not norm.ok or not norm.normalized:
        return None
    return norm.normalized.split("/", 1)[0]


def split_domain_stem_and_tld(domain: str) -> Tuple[str, str, str]:
    """Split `sub.stem.my.id` into `(prefix, stem, tld)`."""
    host = domain.lower().strip(".")
    tld = ""
    rest = host
    for multi in _MULTI_PART_TLDS:
        if host.endswith(f".{multi}"):
            tld = multi
            rest = host[: -(len(multi) + 1)]
            break
    if not tld:
        parts = host.rsplit(".", 1)
        if len(parts) != 2:
            return "", host, ""
        rest, tld = parts[0], parts[1]

    if "." in rest:
        prefix, stem = rest.rsplit(".", 1)
        return prefix, stem, tld
    return "", rest, tld


def is_cloudflare_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    if not isinstance(ip, ipaddress.IPv4Address):
        return False
    return any(ip in net for net in _CLOUDFLARE_IPV4_CIDRS)


def is_shared_nameserver(ns: str) -> bool:
    cleaned = ns.lower().rstrip(".")
    return any(
        cleaned == suf or cleaned.endswith(f".{suf}") or suf in cleaned
        for suf in SHARED_CDN_NS_SUFFIXES
    )


def _is_behind_shared_cdn(a_records: Sequence[str], ns_records: Sequence[str]) -> bool:
    if any(is_cloudflare_ip(ip) for ip in a_records):
        return True
    if ns_records and all(is_shared_nameserver(ns) for ns in ns_records):
        return True
    return False


def _query_dns_sync(domain: str, rdtype: str, timeout_s: float) -> Tuple[str, ...]:
    import dns.exception
    import dns.resolver

    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout_s
    resolver.lifetime = timeout_s
    try:
        answer = resolver.resolve(domain, rdtype, raise_on_no_answer=False)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
        return ()
    except Exception:
        return ()

    if answer.rrset is None:
        return ()

    out: List[str] = []
    for rdata in answer:
        if rdtype == "MX":
            val = str(rdata.exchange).rstrip(".").lower()
        elif rdtype in ("NS", "CNAME"):
            val = str(rdata.target).rstrip(".").lower()
        else:
            val = rdata.to_text().strip().lower()
        if val and val not in out:
            out.append(val)
    return tuple(sorted(out))


DnsQueryFn = Callable[[str, str, float], Tuple[str, ...]]


async def resolve_dns_profile(
    raw_url: str,
    timeout_s: float = DEFAULT_DNS_TIMEOUT_S,
    query_fn: Optional[DnsQueryFn] = None,
) -> Optional[DnsProfile]:
    """Passively resolve A, AAAA, NS, CNAME, and MX records for a domain."""
    host = extract_host(raw_url)
    if not host:
        return None

    fn = query_fn or _query_dns_sync

    async def _run(rdtype: str) -> Tuple[str, ...]:
        return await asyncio.to_thread(fn, host, rdtype, timeout_s)

    a_rec, aaaa_rec, ns_rec, cname_rec, mx_rec = await asyncio.gather(
        _run("A"),
        _run("AAAA"),
        _run("NS"),
        _run("CNAME"),
        _run("MX"),
    )
    return DnsProfile(
        domain=host,
        a_records=a_rec,
        aaaa_records=aaaa_rec,
        ns_records=ns_rec,
        cname_records=cname_rec,
        mx_records=mx_rec,
        behind_shared_cdn=_is_behind_shared_cdn(a_rec, ns_rec),
    )


def generate_sibling_candidates(
    seed_domain: str,
    number_window: int = DEFAULT_NUMBER_WINDOW,
    max_candidates: int = DEFAULT_MAX_CANDIDATES,
) -> List[Tuple[str, str]]:
    """Generate polite mirror candidates `(domain, pivot_type)` from a confirmed domain.

    Covers sequential mirror numbers (e.g. `gacor12.bet` -> `gacor11.bet`, `gacor13.bet`)
    and common Indonesian mirror TLDs (e.g. `gacor12.net`, `gacor12.xyz`).
    """
    host = extract_host(seed_domain)
    if not host or is_official_domain(host):
        return []

    prefix, stem, tld = split_domain_stem_and_tld(host)
    if not stem or not tld or len(stem) < 3:
        return []

    seen: Set[str] = {host}
    candidates: List[Tuple[str, str]] = []

    def _add(domain: str, pivot_type: str) -> None:
        if len(candidates) >= max_candidates:
            return
        norm = normalize_url(domain)
        if not norm.ok or not norm.normalized:
            return
        clean = norm.normalized
        if clean in seen or is_official_domain(clean):
            return
        seen.add(clean)
        candidates.append((clean, pivot_type))

    def _compose(new_stem: str, new_tld: str) -> str:
        return f"{prefix}.{new_stem}.{new_tld}" if prefix else f"{new_stem}.{new_tld}"

    # 1. Trailing number sequence (e.g. gacor12.bet -> gacor10..gacor17.bet)
    m_trail = _TRAILING_NUM_RE.match(stem)
    if m_trail and len(m_trail.group(1)) >= 3:
        base, num_str = m_trail.group(1), m_trail.group(2)
        width = len(num_str)
        num = int(num_str)
        for delta in range(-number_window, number_window + 1):
            nxt = num + delta
            if delta == 0 or nxt < 0:
                continue
            formatted = str(nxt).zfill(width) if num_str.startswith("0") else str(nxt)
            _add(_compose(f"{base}{formatted}", tld), "seq_suffix")

    # 2. Leading number sequence (e.g. 234togel.org -> 230togel..239togel.org)
    m_lead = _LEADING_NUM_RE.match(stem)
    if m_lead and len(m_lead.group(2)) >= 3:
        num_str, base = m_lead.group(1), m_lead.group(2)
        width = len(num_str)
        num = int(num_str)
        for delta in range(-number_window, number_window + 1):
            nxt = num + delta
            if delta == 0 or nxt < 0:
                continue
            formatted = str(nxt).zfill(width) if num_str.startswith("0") else str(nxt)
            _add(_compose(f"{formatted}{base}", tld), "seq_prefix")

    # 3. Mirror TLD swaps (e.g. gacor12.bet -> gacor12.com / .net / .xyz / .id)
    for alt_tld in MIRROR_TLDS:
        if alt_tld == tld:
            continue
        _add(_compose(stem, alt_tld), "tld_swap")

    return candidates


def compare_infra(seed: DnsProfile, candidate: DnsProfile) -> Tuple[bool, Tuple[str, ...]]:
    """Return `(infra_match, signals)` when two domains share non-CDN IP or NS records."""
    signals: List[str] = []

    shared_ips = sorted(set(seed.a_records) & set(candidate.a_records))
    for ip in shared_ips:
        if not is_cloudflare_ip(ip):
            signals.append(f"ip:{ip}")

    shared_ns = sorted(set(seed.ns_records) & set(candidate.ns_records))
    for ns in shared_ns:
        if not is_shared_nameserver(ns):
            signals.append(f"ns:{ns}")
        elif not signals and len(shared_ns) >= 2:
            # Matching exact pair of Cloudflare assigned nameservers (e.g. bob+alice)
            # is still a useful weak signal because CF assigns pairs per account.
            signals.append(f"ns_pair:{'+'.join(shared_ns[:2])}")
            break

    return bool(signals), tuple(signals)


async def expand_from_seed(
    seed_url: str,
    number_window: int = DEFAULT_NUMBER_WINDOW,
    max_candidates: int = DEFAULT_MAX_CANDIDATES,
    timeout_s: float = DEFAULT_DNS_TIMEOUT_S,
    concurrency: int = DEFAULT_CONCURRENCY,
    query_fn: Optional[DnsQueryFn] = None,
    verbose: bool = True,
) -> List[PivotCandidate]:
    """Expand a confirmed domain into live resolving sibling domains via passive DNS."""
    seed_profile = await resolve_dns_profile(seed_url, timeout_s=timeout_s, query_fn=query_fn)
    if seed_profile is None:
        return []

    raw_candidates = generate_sibling_candidates(
        seed_profile.domain,
        number_window=number_window,
        max_candidates=max_candidates,
    )
    if verbose:
        print(
            f"[dns-pivot] seed={seed_profile.domain} (A={list(seed_profile.a_records)}, "
            f"NS={list(seed_profile.ns_records)}) -> checking {len(raw_candidates)} siblings",
            file=sys.stderr,
            flush=True,
        )

    sem = asyncio.Semaphore(max(1, concurrency))

    async def _check(dom: str, ptype: str) -> Optional[PivotCandidate]:
        async with sem:
            prof = await resolve_dns_profile(dom, timeout_s=timeout_s, query_fn=query_fn)
        if prof is None or not prof.resolves:
            return None
        infra_match, signals = compare_infra(seed_profile, prof)
        return PivotCandidate(
            normalized_url=prof.domain,
            seed_domain=seed_profile.domain,
            pivot_type=ptype,
            infra_match=infra_match,
            matched_signals=signals,
            a_records=prof.a_records,
            ns_records=prof.ns_records,
        )

    checked = await asyncio.gather(*(_check(d, t) for d, t in raw_candidates))
    live = [item for item in checked if item is not None]
    # Put high-confidence infrastructure matches first.
    live.sort(key=lambda item: (not item.infra_match, item.normalized_url))

    if verbose:
        infra_hits = sum(1 for x in live if x.infra_match)
        print(
            f"[dns-pivot] seed={seed_profile.domain} -> {len(live)} live siblings ({infra_hits} infra matches)",
            file=sys.stderr,
            flush=True,
        )
    return live


def cluster_by_infra(profiles: Sequence[DnsProfile]) -> Dict[str, List[str]]:
    """Group domains that share a non-CDN IP or custom nameserver into operator clusters."""
    buckets: Dict[str, Set[str]] = {}
    for prof in profiles:
        for ip in prof.a_records:
            if not is_cloudflare_ip(ip):
                buckets.setdefault(f"ip:{ip}", set()).add(prof.domain)
        custom_ns = [ns for ns in prof.ns_records if not is_shared_nameserver(ns)]
        for ns in custom_ns:
            buckets.setdefault(f"ns:{ns}", set()).add(prof.domain)
        if not custom_ns and len(prof.ns_records) >= 2:
            key = "ns_pair:" + "+".join(prof.ns_records[:2])
            buckets.setdefault(key, set()).add(prof.domain)

    return {
        key: sorted(domains)
        for key, domains in sorted(buckets.items())
        if len(domains) >= 2
    }


async def _run_profile_cli(domains: Sequence[str], timeout_s: float) -> int:
    profiles = await asyncio.gather(
        *(resolve_dns_profile(d, timeout_s=timeout_s) for d in domains)
    )
    for prof in profiles:
        if prof is not None:
            print(json.dumps(prof.to_dict(), ensure_ascii=False))
    return 0


async def _run_expand_cli(args: argparse.Namespace) -> int:
    out_fp = args.out_file.open("a", encoding="utf-8") if args.out_file else None
    seen: Set[str] = set()
    try:
        for seed in args.domains:
            items = await expand_from_seed(
                seed,
                number_window=args.window,
                max_candidates=args.max_candidates,
                timeout_s=args.timeout,
                concurrency=args.concurrency,
                verbose=not args.quiet,
            )
            for item in items:
                if item.normalized_url in seen:
                    continue
                seen.add(item.normalized_url)
                line = json.dumps(item.to_dict(), ensure_ascii=False)
                print(line, flush=True)
                if out_fp is not None:
                    out_fp.write(line + "\n")
                    out_fp.flush()
    finally:
        if out_fp is not None:
            out_fp.close()
    return 0


async def _run_cluster_cli(domains: Sequence[str], timeout_s: float) -> int:
    profiles = await asyncio.gather(
        *(resolve_dns_profile(d, timeout_s=timeout_s) for d in domains)
    )
    valid_profiles = [p for p in profiles if p is not None and p.resolves]
    clusters = cluster_by_infra(valid_profiles)
    print(json.dumps(clusters, ensure_ascii=False, indent=2))
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python3 -m src.dns_pivot",
        description="Passive DNS profiler, sibling mirror expander, and infra clusterer.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_prof = sub.add_parser("profile", help="Resolve passive DNS records (A, AAAA, NS, CNAME, MX).")
    p_prof.add_argument("domains", nargs="+")
    p_prof.add_argument("--timeout", type=float, default=DEFAULT_DNS_TIMEOUT_S)

    p_exp = sub.add_parser("expand", help="Find live sibling mirror domains via passive DNS.")
    p_exp.add_argument("domains", nargs="+", help="One or more confirmed valid seed domains.")
    p_exp.add_argument("--window", type=int, default=DEFAULT_NUMBER_WINDOW)
    p_exp.add_argument("--max-candidates", type=int, default=DEFAULT_MAX_CANDIDATES)
    p_exp.add_argument("--timeout", type=float, default=DEFAULT_DNS_TIMEOUT_S)
    p_exp.add_argument("--concurrency", type=int, default=DEFAULT_CONCURRENCY)
    p_exp.add_argument("--out-file", type=Path, default=None)
    p_exp.add_argument("--quiet", action="store_true")

    p_clu = sub.add_parser("cluster", help="Cluster domains sharing non-CDN IP or NS records.")
    p_clu.add_argument("domains", nargs="+")
    p_clu.add_argument("--timeout", type=float, default=DEFAULT_DNS_TIMEOUT_S)

    args = parser.parse_args(argv)
    if args.command == "profile":
        return asyncio.run(_run_profile_cli(args.domains, timeout_s=args.timeout))
    if args.command == "expand":
        return asyncio.run(_run_expand_cli(args))
    return asyncio.run(_run_cluster_cli(args.domains, timeout_s=args.timeout))


if __name__ == "__main__":
    raise SystemExit(main())
