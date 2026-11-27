# lakshana

An offline phishing URL analyzer. It scores a URL on a set of well-known heuristics and tells you exactly why.

## The name

*Lakshana* (लक्षण) is Sanskrit for a characteristic, symptom or telltale feature. The tool reads the telltale signs in a URL.

## Features

Each URL gets a score from 0 to 100 and a verdict (`low` < 20, `suspicious` 20-49, `high` 50+). Every point is backed by a named signal and a plain-English explanation:

| signal | weight | what it means |
|---|---|---|
| `brand_homoglyph` | 35 | domain uses Cyrillic/Greek/accented look-alikes of a brand (`аpple.com`) |
| `brand_lookalike` | 35 | ASCII substitutions: `paypa1`, `rnicrosoft`, `amaz0n` |
| `brand_typosquat` | 30 | one edit away from a brand (`goggle`) |
| `brand_wrong_domain` | 30 | exact brand name on a TLD the brand does not use (`paypal.net`) |
| `brand_in_domain` | 25 | brand inside a longer domain (`paypal-secure-login.com`) |
| `brand_in_subdomain` | 25 | brand used as a subdomain of an unrelated site (`paypal.com.evil.net`) |
| `ip_host` | 25 | raw IPv4/IPv6 host, including decimal, hex and octal forms (`http://3232235777/`) |
| `at_sign` | 25 | `user@host` trick (`https://apple.com@203.0.113.9/`) |
| `punycode` | 15 | internationalised (`xn--`) domain, shown decoded |
| `suspicious_tld` | 10-15 | TLDs frequently abused for phishing (`.tk`, `.zip`, `.xyz`, ...) |
| `many_subdomains` | 8-15 | three or more subdomain levels |
| `bait_keywords` | 5-15 | lure words such as `login`, `verify`, `wallet`, `suspend` |
| `shortener` | 10 | known URL shortener hiding the destination |
| `free_hosting` | 10 | free subdomain platforms (`azurewebsites.net`, `pages.dev`, ...) |
| `embedded_url` | 10 | a second URL in the path or query (redirect chains) |
| `high_entropy` | 10 | random-looking domain label (DGA style) |
| `very_long` / `long` | 10 / 5 | URL over 200 / 100 characters |
| `heavy_encoding` | 8 | lots of percent-encoding in host or path |
| `odd_port` | 8 | non-standard port |
| `many_hyphens` | 5 | three or more hyphens in the domain |
| `no_tls` | 5 | explicit `http://` |
| `dangerous_scheme` | 60 | `javascript:`, `data:` or `vbscript:` |

The brand list (about 50 brands with their real domains), suspicious TLDs, shorteners and homoglyph table are bundled in `lakshana/data.py`. Nothing is fetched; the URL is never visited.

Standard library only. Python 3.10+.

## Install

```sh
git clone https://github.com/Linuxboii/lakshana.git
cd lakshana
pip install .
```

Or run in place with `python -m lakshana`.

## Usage

Single URL, full explanation:

```
$ lakshana "https://apple.com@203.0.113.9/icloud/verify"
URL       https://apple.com@203.0.113.9/icloud/verify
Host      203.0.113.9
Domain    203.0.113.9
Score     55/100  HIGH

  +25  ip_host        host is a raw IP address 203.0.113.9; real brands use domain names; address is private/reserved
  +25  at_sign        '@' in the authority: everything before it ('apple.com') is ignored by the browser, the real host is 203.0.113.9
  +5   bait_keywords  lure words: verify
```

Batch mode (`-f file`, one URL per line, `#` comments allowed, `-` for stdin):

```
$ lakshana -f examples/urls.txt
SCORE  VERDICT     URL                                                           TOP SIGNALS
-----  ----------  ------------------------------------------------------------  -----------
    0  LOW         https://www.paypal.com/signin                                 -
    0  LOW         https://accounts.google.com/ServiceLogin                      -
    0  LOW         https://github.com/Linuxboii                                  -
   50  HIGH        http://paypa1.com/webscr?cmd=login                            brand_lookalike, bait_keywords, no_tls
   50  HIGH        https://xn--pple-43d.com/                                     brand_homoglyph, punycode
   40  SUSPICIOUS  http://192.168.4.20/secure/login.php                          ip_host, bait_keywords, no_tls
   75  HIGH        http://www.paypal.com.account-verify.secure-login.example...  brand_in_subdomain, many_subdomains, suspicious_tld
   10  LOW         https://bit.ly/3xYz9Ab                                        shortener
   55  HIGH        https://apple.com@203.0.113.9/icloud/verify                   ip_host, at_sign, bait_keywords
   60  HIGH        https://amaz0n-billing-support.xyz/invoice/refund             brand_lookalike, bait_keywords, suspicious_tld
   55  HIGH        https://micros0ft-office.azurewebsites.net/auth/login         brand_lookalike, free_hosting, bait_keywords
   20  SUSPICIOUS  https://k3j9x2qz7wplm4.top/                                   suspicious_tld, high_entropy
   35  SUSPICIOUS  http://3232235777/login                                       ip_host, no_tls, bait_keywords

13 URLs: 6 high, 3 suspicious, 4 low
```

JSON:

```
$ lakshana --json "http://paypa1.com/webscr?cmd=login"
{
  "url": "http://paypa1.com/webscr?cmd=login",
  "host": "paypa1.com",
  "registered_domain": "paypa1.com",
  "score": 50,
  "verdict": "high",
  "signals": [
    {
      "id": "brand_lookalike",
      "weight": 35,
      "detail": "'paypa1' imitates 'paypal' (legit: paypal.com, paypal.me)"
    },
    {
      "id": "no_tls",
      "weight": 5,
      "detail": "plain http: credentials typed here are sent unencrypted"
    },
    {
      "id": "bait_keywords",
      "weight": 10,
      "detail": "lure words: webscr, login"
    }
  ],
  "error": null
}
```

Other options:

```
--detail        full explanation for every URL in batch mode
--min-score N   only show URLs scoring N or more
--fail-at N     exit 1 if any URL scores N or more (default 50); handy in scripts
--no-color      plain output (also honours NO_COLOR)
```

Exit codes: `0` nothing at or above `--fail-at`, `1` at least one URL did, `2` usage error.

## Limits

These are heuristics. A brand-new phishing domain with no look-alike tricks will score low, and an unusual legitimate URL can score high. Use the score to triage, not as a verdict on its own.

## Tests

```sh
python -m unittest -v
```

## License

MIT, see [LICENSE](LICENSE).
