"""Bundled reference data. Everything is offline; nothing is fetched."""

# brand label -> legitimate registrable domains
BRANDS: dict[str, tuple[str, ...]] = {
    "paypal": ("paypal.com", "paypal.me"),
    "google": ("google.com", "google.co.uk", "google.co.in", "google.de", "goo.gl"),
    "gmail": ("gmail.com", "google.com"),
    "apple": ("apple.com",),
    "icloud": ("icloud.com", "apple.com"),
    "microsoft": ("microsoft.com", "microsoftonline.com"),
    "office": ("office.com", "office365.com", "microsoft.com"),
    "outlook": ("outlook.com", "live.com", "microsoft.com"),
    "amazon": ("amazon.com", "amazon.co.uk", "amazon.in", "amazon.de", "amazonaws.com"),
    "facebook": ("facebook.com", "fb.com", "fb.me"),
    "instagram": ("instagram.com",),
    "whatsapp": ("whatsapp.com", "whatsapp.net", "wa.me"),
    "netflix": ("netflix.com",),
    "linkedin": ("linkedin.com", "lnkd.in"),
    "twitter": ("twitter.com", "x.com", "t.co"),
    "github": ("github.com", "github.io", "githubusercontent.com"),
    "dropbox": ("dropbox.com",),
    "adobe": ("adobe.com",),
    "docusign": ("docusign.com", "docusign.net"),
    "ebay": ("ebay.com", "ebay.co.uk"),
    "yahoo": ("yahoo.com",),
    "spotify": ("spotify.com",),
    "steam": ("steampowered.com", "steamcommunity.com"),
    "steampowered": ("steampowered.com",),
    "steamcommunity": ("steamcommunity.com",),
    "telegram": ("telegram.org", "t.me"),
    "discord": ("discord.com", "discord.gg", "discordapp.com"),
    "coinbase": ("coinbase.com",),
    "binance": ("binance.com",),
    "metamask": ("metamask.io",),
    "blockchain": ("blockchain.com",),
    "chase": ("chase.com",),
    "wellsfargo": ("wellsfargo.com",),
    "bankofamerica": ("bankofamerica.com",),
    "citibank": ("citibank.com", "citi.com"),
    "hsbc": ("hsbc.com", "hsbc.co.uk"),
    "barclays": ("barclays.co.uk", "barclays.com"),
    "americanexpress": ("americanexpress.com",),
    "dhl": ("dhl.com",),
    "fedex": ("fedex.com",),
    "usps": ("usps.com",),
    "walmart": ("walmart.com",),
    "irs": ("irs.gov",),
    "hdfcbank": ("hdfcbank.com",),
    "icicibank": ("icicibank.com",),
    "onlinesbi": ("onlinesbi.sbi", "sbi.co.in"),
    "paytm": ("paytm.com",),
    "flipkart": ("flipkart.com",),
}

# Multi-label public suffixes we know about (a compact subset of the PSL).
MULTI_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "com.au", "net.au", "org.au",
    "co.in", "net.in", "org.in", "gov.in", "ac.in", "co.jp", "ne.jp", "or.jp",
    "com.br", "com.cn", "com.mx", "com.ar", "com.tr", "co.za", "co.nz", "co.kr",
    "com.sg", "com.hk", "com.tw", "co.id", "com.my", "com.pk", "com.ng", "co.il",
    "github.io", "herokuapp.com", "netlify.app", "vercel.app", "pages.dev",
    "web.app", "firebaseapp.com", "blogspot.com", "azurewebsites.net",
    "000webhostapp.com", "weebly.com", "wixsite.com", "glitch.me", "repl.co",
}

# TLDs heavily abused in phishing/abuse feeds, or confusable with file names.
SUSPICIOUS_TLDS = {
    "zip", "mov", "tk", "ml", "ga", "cf", "gq", "xyz", "top", "click", "country",
    "work", "support", "rest", "fit", "loan", "men", "cam", "icu", "buzz", "monster",
    "sbs", "cfd", "quest", "lol", "bond", "mom", "beauty", "hair", "skin", "boats",
    "autos", "yachts", "makeup", "zone", "kim", "date", "faith", "racing", "review",
    "stream", "download", "gdn", "bid", "win", "party", "trade", "webcam", "science",
    "accountant", "cricket", "su", "pw", "cyou", "live", "shop", "online", "site",
}

# Hosting platforms where anyone can get a subdomain.
FREE_HOSTING = {
    "github.io", "herokuapp.com", "netlify.app", "vercel.app", "pages.dev", "web.app",
    "firebaseapp.com", "blogspot.com", "azurewebsites.net", "000webhostapp.com",
    "weebly.com", "wixsite.com", "glitch.me", "repl.co", "ngrok.io", "ngrok-free.app",
    "duckdns.org", "trycloudflare.com",
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly",
    "rebrand.ly", "shorturl.at", "tiny.cc", "rb.gy", "s.id", "bl.ink", "v.gd",
    "t.ly", "shorte.st", "adf.ly", "bitly.com", "lnkd.in", "tr.im", "qr.ae",
    "soo.gd", "clck.ru", "u.to", "x.co", "short.io", "tiny.one",
}

BAIT_KEYWORDS = (
    "login", "log-in", "signin", "sign-in", "verify", "verification", "secure",
    "account", "update", "banking", "confirm", "password", "passwd", "wallet",
    "suspend", "suspended", "unlock", "webscr", "billing", "invoice", "recover",
    "recovery", "authenticate", "auth", "credential", "validate", "restore",
    "unusual", "limited", "payment", "refund", "claim", "prize", "gift", "bonus",
    "airdrop", "seed", "kyc",
)

# Visually confusable characters -> ASCII skeleton.
HOMOGLYPHS = {
    # Cyrillic
    "а": "a", "в": "b", "е": "e", "ё": "e", "к": "k", "м": "m", "н": "h", "о": "o",
    "р": "p", "с": "c", "т": "t", "у": "y", "х": "x", "ѕ": "s", "і": "i", "ї": "i",
    "ј": "j", "ԁ": "d", "ԛ": "q", "ԝ": "w", "ӏ": "l", "һ": "h", "ɡ": "g", "ո": "n",
    # Greek
    "α": "a", "β": "b", "ε": "e", "η": "n", "ι": "i", "κ": "k", "ν": "v", "ο": "o",
    "ρ": "p", "τ": "t", "υ": "u", "χ": "x", "ω": "w",
    # Latin look-alikes
    "ı": "i", "ł": "l", "ɩ": "i", "ʟ": "l", "ɑ": "a", "ǝ": "e", "ⅼ": "l", "ⅰ": "i",
    "à": "a", "á": "a", "â": "a", "ã": "a", "ä": "a", "å": "a", "ç": "c", "è": "e",
    "é": "e", "ê": "e", "ë": "e", "ì": "i", "í": "i", "î": "i", "ï": "i", "ñ": "n",
    "ò": "o", "ó": "o", "ô": "o", "õ": "o", "ö": "o", "ù": "u", "ú": "u", "û": "u",
    "ü": "u", "ý": "y", "ÿ": "y", "ś": "s", "ș": "s", "ț": "t", "ğ": "g", "ż": "z",
}

# ASCII substitutions used in typosquats (applied after homoglyph folding).
ASCII_SUBS = (("rn", "m"), ("vv", "w"), ("cl", "d"), ("0", "o"), ("1", "l"),
              ("3", "e"), ("4", "a"), ("5", "s"), ("7", "t"), ("8", "b"), ("@", "a"))
