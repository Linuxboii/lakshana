import contextlib
import io
import json
import os
import tempfile
import unittest

from lakshana.analyzer import (analyze, levenshtein, parse_ip_host, shannon_entropy,
                                      skeleton, split_domain)
from lakshana.cli import main


def ids(url):
    return {s.id for s in analyze(url).signals}


class LegitTests(unittest.TestCase):
    def test_official_domains_are_clean(self):
        for url in ("https://www.paypal.com/signin", "https://accounts.google.com/ServiceLogin",
                    "https://github.com/login", "https://www.amazon.co.uk/ap/signin",
                    "https://example.org/", "stream.com", "https://news.ycombinator.com/"):
            with self.subTest(url=url):
                a = analyze(url)
                self.assertEqual(a.verdict, "low", a.to_dict())
                self.assertFalse(any(s.id.startswith("brand") for s in a.signals))


class SignalTests(unittest.TestCase):
    def test_ip_hosts(self):
        self.assertIn("ip_host", ids("http://192.168.1.10/login"))
        self.assertIn("ip_host", ids("http://[2001:db8::1]/"))
        a = analyze("http://3232235777/")
        self.assertIn("192.168.1.1", a.signals[0].detail)
        self.assertEqual(str(parse_ip_host("0xC0A80101")), "192.168.1.1")
        self.assertEqual(str(parse_ip_host("0300.0250.01.01")), "192.168.1.1")
        self.assertIsNone(parse_ip_host("example.com"))

    def test_punycode_homoglyph(self):
        a = analyze("https://xn--pple-43d.com/")
        s = {x.id for x in a.signals}
        self.assertIn("punycode", s)
        self.assertIn("brand_homoglyph", s)
        self.assertEqual(a.verdict, "high")

    def test_raw_unicode_homoglyph(self):
        self.assertIn("brand_homoglyph", ids("https://pаypal.com/"))  # Cyrillic a

    def test_ascii_lookalike_and_typosquat(self):
        self.assertIn("brand_lookalike", ids("http://paypa1.com/"))
        self.assertIn("brand_lookalike", ids("https://rnicrosoft.com/"))
        self.assertIn("brand_typosquat", ids("https://goggle.com/"))
        self.assertIn("brand_lookalike", ids("https://amaz0n-billing.xyz/"))

    def test_brand_in_wrong_places(self):
        self.assertIn("brand_wrong_domain", ids("https://paypal.net/"))
        self.assertIn("brand_in_domain", ids("https://paypal-secure-login.com/"))
        self.assertIn("brand_in_subdomain", ids("https://paypal.com.evil.net/"))

    def test_subdomains(self):
        a = analyze("http://a.b.c.d.example.com/")
        self.assertIn("many_subdomains", {s.id for s in a.signals})

    def test_tld_shortener_at(self):
        self.assertIn("suspicious_tld", ids("https://free-prize.tk/"))
        self.assertIn("shortener", ids("https://bit.ly/abc"))
        a = analyze("https://www.google.com@198.51.100.4/")
        self.assertEqual(a.host, "198.51.100.4")
        self.assertIn("at_sign", {s.id for s in a.signals})

    def test_length_keywords_entropy(self):
        self.assertIn("very_long", ids("https://example.com/" + "a" * 220))
        self.assertIn("long", ids("https://example.com/" + "a" * 90))
        a = analyze("https://example.com/verify/account/login")
        bait = [s for s in a.signals if s.id == "bait_keywords"][0]
        self.assertEqual(bait.weight, 15)
        self.assertIn("high_entropy", ids("https://k3j9x2qz7wplm4.top/"))
        self.assertNotIn("high_entropy", ids("https://stackoverflow.com/"))

    def test_embedded_url_and_scheme(self):
        self.assertIn("embedded_url", ids("https://example.com/redirect?to=https://evil.com"))
        self.assertIn("dangerous_scheme", ids("javascript:alert(1)"))
        self.assertIn("no_tls", ids("http://example.com/"))
        self.assertNotIn("no_tls", ids("example.com"))

    def test_score_capped(self):
        a = analyze("http://paypal.com.verify-account.secure.login.xn--pypal-4ve.tk:8080/"
                    "webscr/login?redirect=http://x.y/" + "z" * 200)
        self.assertEqual(a.score, 100)
        self.assertEqual(a.verdict, "high")


class HelperTests(unittest.TestCase):
    def test_helpers(self):
        self.assertEqual(levenshtein("kitten", "sitting"), 3)
        self.assertEqual(skeleton("PayPa1"), skeleton("paypal"))
        self.assertEqual(split_domain("a.b.example.co.uk"), ("a.b", "example", "co.uk"))
        self.assertEqual(split_domain("www.example.com"), ("www", "example", "com"))
        self.assertAlmostEqual(shannon_entropy("abcd"), 2.0)


class CliTests(unittest.TestCase):
    def run_cli(self, argv):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = main(argv)
        return code, buf.getvalue()

    def test_single_json(self):
        code, out = self.run_cli(["--json", "http://paypa1.com/webscr/login"])
        data = json.loads(out)
        self.assertEqual(data["verdict"], "high")
        self.assertEqual(code, 1)

    def test_batch_file(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as f:
            f.write("# comment\nhttps://github.com/\n\nhttps://bit.ly/x\n")
        try:
            code, out = self.run_cli(["-f", f.name, "--no-color"])
        finally:
            os.unlink(f.name)
        self.assertEqual(code, 0)
        self.assertIn("2 URLs: 0 high, 0 suspicious, 2 low", out)
        code, out = self.run_cli(["--json", "https://github.com/", "https://bit.ly/x"])
        self.assertEqual(len(json.loads(out)), 2)

    def test_no_input(self):
        with contextlib.redirect_stderr(io.StringIO()):
            code, _ = self.run_cli([])
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
