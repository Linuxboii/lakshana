"""Heuristic URL scoring. Pure functions, no network access."""

from __future__ import annotations

import codecs
import ipaddress
import math
import re
import urllib.parse
from collections import Counter
from dataclasses import dataclass, field

from .data import (ASCII_SUBS, BAIT_KEYWORDS, BRANDS, FREE_HOSTING, HOMOGLYPHS,
                   MULTI_SUFFIXES, SHORTENERS, SUSPICIOUS_TLDS)

LOW, MEDIUM, HIGH = 20, 50, 100


@dataclass
class Signal:
    id: str
    weight: int
    detail: str


@dataclass
class Analysis:
    url: str
    host: str
    registered_domain: str
    score: int = 0
    verdict: str = "low"
    signals: list[Signal] = field(default_factory=list)
    error: str | None = None

    def add(self, sid: str, weight: int, detail: str) -> None:
        self.signals.append(Signal(sid, weight, detail))

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "host": self.host,
            "registered_domain": self.registered_domain,
            "score": self.score,
            "verdict": self.verdict,
            "signals": [s.__dict__ for s in self.signals],
            "error": self.error,
        }


def verdict_for(score: int) -> str:
    if score >= MEDIUM:
        return "high"
    if score >= LOW:
        return "suspicious"
    return "low"


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def decode_label(label: str) -> str:
    if label.startswith("xn--"):
        try:
            return codecs.decode(label[4:].encode("ascii"), "punycode")
        except (UnicodeError, ValueError):
            return label
    return label


def skeleton(text: str) -> str:
    """Fold confusable characters and common ASCII substitutions."""
    folded = "".join(HOMOGLYPHS.get(ch, ch) for ch in text.lower())
    folded = folded.replace("-", "").replace("_", "")
    for src, dst in ASCII_SUBS:
        folded = folded.replace(src, dst)
    return folded


def split_domain(host: str) -> tuple[str, str, str]:
    """Return (subdomain, registrable label, suffix)."""
    labels = host.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_SUFFIXES:
        suffix = ".".join(labels[-2:])
        rest = labels[:-2]
    elif len(labels) >= 2:
        suffix = labels[-1]
        rest = labels[:-1]
    else:
        return "", host, ""
    return ".".join(rest[:-1]), rest[-1], suffix


def parse_ip_host(host: str):
    h = host.strip("[]")
    try:
        return ipaddress.ip_address(h)
    except ValueError:
        pass
    if re.fullmatch(r"\d{8,10}", h):
        value = int(h)
        if value <= 0xFFFFFFFF:
            return ipaddress.IPv4Address(value)
    if re.fullmatch(r"0x[0-9a-fA-F]{1,8}", h):
        return ipaddress.IPv4Address(int(h, 16))
    parts = h.split(".")
    if len(parts) == 4 and all(re.fullmatch(r"(0x[0-9a-fA-F]+|0[0-7]*|\d+)", p) for p in parts):
        try:
            octets = [int(p, 16) if p.lower().startswith("0x")
                      else int(p, 8) if p.startswith("0") and len(p) > 1 else int(p)
                      for p in parts]
            if all(0 <= o <= 255 for o in octets):
                return ipaddress.IPv4Address(".".join(map(str, octets)))
        except ValueError:
            pass
    return None


def legit_for(registered: str) -> set[str]:
    """Brands whose legitimate domains include this registered domain."""
    return {b for b, domains in BRANDS.items() if registered in domains}


def analyze(raw_url: str) -> Analysis:
    url = raw_url.strip()
    lowered = url.lower()
    if lowered.startswith(("javascript:", "data:", "vbscript:")):
        a = Analysis(url, "", "")
        a.add("dangerous_scheme", 60, f"uses the {lowered.split(':', 1)[0]}: scheme, which runs "
                                      "or embeds content instead of navigating to a site")
        return finish(a)
    if "://" not in url:
        url_for_parse = "http://" + url
    else:
        url_for_parse = url
    try:
        parts = urllib.parse.urlsplit(url_for_parse)
        host = (parts.hostname or "").rstrip(".")
        port = parts.port
    except ValueError as e:
        a = Analysis(url, "", "")
        a.error = f"unparseable URL: {e}"
        a.add("unparseable", 20, "the URL could not be parsed; malformed URLs are a common "
                                 "trick to confuse filters")
        return finish(a)

    if not host:
        a = Analysis(url, "", "")
        a.error = "no host in URL"
        return finish(a)

    a = Analysis(url, host, "")
    scheme = parts.scheme.lower()

    # --- host is an IP address -------------------------------------------------
    ip = parse_ip_host(host)
    if ip is not None:
        a.registered_domain = str(ip)
        shown = "" if str(ip) == host.strip("[]") else f" (written as {host})"
        a.add("ip_host", 25, f"host is a raw IP address {ip}{shown}; real brands use domain names")
        if not ip.is_global:
            a.signals[-1].detail += "; address is private/reserved"
    else:
        analyze_domain(a, host)

    # --- userinfo trick ---------------------------------------------------------
    if "@" in parts.netloc:
        before = parts.netloc.rsplit("@", 1)[0]
        a.add("at_sign", 25, f"'@' in the authority: everything before it ('{before}') is "
                             f"ignored by the browser, the real host is {host}")
    elif "@" in url_for_parse.split("://", 1)[1]:
        a.add("at_sign_path", 5, "'@' appears in the path or query")

    # --- scheme / port ----------------------------------------------------------
    if scheme == "http" and url_for_parse is url:
        a.add("no_tls", 5, "plain http: credentials typed here are sent unencrypted")
    if port and port not in (80, 443):
        a.add("odd_port", 8, f"non-standard port {port}")

    # --- length -----------------------------------------------------------------
    if len(url) > 200:
        a.add("very_long", 10, f"URL is {len(url)} characters long; long URLs hide the real host")
    elif len(url) > 100:
        a.add("long", 5, f"URL is {len(url)} characters long")

    # --- keyword bait -----------------------------------------------------------
    rest = (parts.path + "?" + parts.query).lower()
    official = bool(legit_for(a.registered_domain))
    haystack = ("" if official else host.lower()) + " " + rest
    hits = sorted({k for k in BAIT_KEYWORDS if k in haystack}, key=haystack.index)
    # collapse overlaps such as auth / authenticate
    hits = [k for k in hits if not any(k != o and k in o for o in hits)]
    if official:
        hits = []  # lure words on the brand's own domain are normal
    if hits:
        weight = min(15, 5 * len(hits))
        a.add("bait_keywords", weight, "lure words: " + ", ".join(hits[:6]))

    # --- embedded URL / redirect ------------------------------------------------
    if re.search(r"(https?:/|https?%3a%2f|//)", rest[1:] if rest.startswith("/") else rest):
        a.add("embedded_url", 10, "another URL is embedded in the path or query "
                                  "(open redirect or hidden destination)")

    # --- encoding tricks --------------------------------------------------------
    pct = len(re.findall(r"%[0-9a-fA-F]{2}", parts.path + parts.netloc))
    if pct >= 6:
        a.add("heavy_encoding", 8, f"{pct} percent-encoded bytes in host/path")

    return finish(a)


def analyze_domain(a: Analysis, host: str) -> None:
    raw_labels = host.lower().split(".")
    decoded_labels = [decode_label(l) for l in raw_labels]
    decoded_host = ".".join(decoded_labels)
    sub, label, suffix = split_domain(host.lower())
    registered = f"{label}.{suffix}" if suffix else label
    a.registered_domain = registered
    d_sub, d_label, _ = split_domain(decoded_host)
    legit_brands = legit_for(registered)

    # punycode / non-ascii
    if any(l.startswith("xn--") for l in raw_labels) or not host.isascii():
        a.add("punycode", 15, f"internationalised domain; displays as '{decoded_host}'")

    if not legit_brands:
        brand_signals(a, d_label, d_sub, registered)

    if registered in FREE_HOSTING or f"{label}.{suffix}" in FREE_HOSTING or suffix in FREE_HOSTING:
        a.add("free_hosting", 10, f"hosted on a free platform ({suffix if suffix in FREE_HOSTING else registered}) "
                                  "where anyone can register a subdomain")

    # subdomain depth
    depth = len(sub.split(".")) if sub else 0
    if depth >= 4:
        a.add("many_subdomains", 15, f"{depth} subdomain levels before {registered}")
    elif depth == 3:
        a.add("many_subdomains", 8, f"{depth} subdomain levels before {registered}")

    tld = suffix.rsplit(".", 1)[-1]
    if tld in SUSPICIOUS_TLDS:
        a.add("suspicious_tld", 15 if tld in ("zip", "mov", "tk", "ml", "ga", "cf", "gq") else 10,
              f".{tld} is a TLD frequently abused for phishing")

    if registered in SHORTENERS or host.lower() in SHORTENERS:
        a.add("shortener", 10, f"{host} is a URL shortener; the final destination is hidden")

    if d_label.count("-") >= 3:
        a.add("many_hyphens", 5, f"{d_label.count('-')} hyphens in the domain name")

    ent_target = d_label.replace("-", "")
    if len(ent_target) >= 12:
        ent = shannon_entropy(ent_target)
        digits = sum(c.isdigit() for c in ent_target)
        vowels = sum(c in "aeiou" for c in ent_target)
        if ent >= 3.5 and (digits >= 3 or vowels / len(ent_target) < 0.25):
            a.add("high_entropy", 10,
                  f"domain label '{ent_target}' looks random (entropy {ent:.2f} bits/char)")


def match_brand(candidate: str) -> tuple[str, str] | None:
    """Compare one domain token against the brand list.

    Returns (kind, brand) where kind is exact, homoglyph, lookalike or typosquat.
    """
    plain = candidate.replace("-", "").lower()
    if len(plain) < 3:
        return None
    if plain in BRANDS:
        return "exact", plain
    sk = skeleton(candidate)
    for brand in BRANDS:
        if sk == skeleton(brand):
            return ("homoglyph" if not candidate.isascii() else "lookalike"), brand
    for brand in BRANDS:
        if len(brand) >= 6 and abs(len(sk) - len(brand)) <= 1 and levenshtein(sk, skeleton(brand)) == 1:
            return "typosquat", brand
    return None


def brand_signals(a: Analysis, d_label: str, d_sub: str, registered: str) -> None:
    def legit(brand: str) -> str:
        return ", ".join(BRANDS[brand])

    whole = match_brand(d_label)
    if whole:
        kind, brand = whole
        if kind == "exact":
            a.add("brand_wrong_domain", 30, f"uses brand '{brand}' on {registered}, which is not "
                                            f"an official {brand} domain ({legit(brand)})")
        elif kind == "typosquat":
            a.add("brand_typosquat", 30, f"'{d_label}' is one edit away from '{brand}' (legit: {legit(brand)})")
        else:
            a.add("brand_" + kind, 35, f"'{d_label}' imitates '{brand}' (legit: {legit(brand)})")
        return

    tokens = [t for t in re.split(r"[-_]", d_label) if t]
    if len(tokens) > 1:
        for tok in tokens:
            m = match_brand(tok)
            if not m:
                continue
            kind, brand = m
            if kind == "exact":
                a.add("brand_in_domain", 25, f"'{brand}' appears inside {registered}, which "
                                             f"{brand} does not own ({legit(brand)})")
            elif kind == "typosquat":
                a.add("brand_typosquat", 25, f"'{tok}' in {registered} is one edit away from '{brand}'")
            else:
                a.add("brand_" + kind, 35, f"'{tok}' in {registered} imitates '{brand}' (legit: {legit(brand)})")
            return
    plain = d_label.replace("-", "")
    for brand in BRANDS:
        if len(brand) >= 6 and brand in plain:
            a.add("brand_in_domain", 25, f"'{brand}' is embedded in {registered}, which "
                                         f"{brand} does not own ({legit(brand)})")
            return

    if d_sub:
        for tok in (t for t in re.split(r"[-_.]", d_sub) if t):
            m = match_brand(tok)
            if m and m[0] != "typosquat":
                a.add("brand_in_subdomain", 25, f"'{tok}' looks like {m[1]} but is only a subdomain; "
                                                f"the site actually belongs to {registered}")
                return


def finish(a: Analysis) -> Analysis:
    a.score = min(100, sum(s.weight for s in a.signals))
    a.verdict = verdict_for(a.score)
    return a
