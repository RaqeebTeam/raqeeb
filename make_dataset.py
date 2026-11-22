"""Builds a synthetic labelled URL dataset -> data/synthetic_urls.csv
Used only as a fallback when you have no real dataset (this sandbox has no internet).
For your final submission, drop a real Kaggle/PhishTank CSV at data/urls.csv (see README)."""
import csv
import random

random.seed(42)

POPULAR = """google.com youtube.com facebook.com wikipedia.org amazon.com twitter.com instagram.com linkedin.com
netflix.com microsoft.com apple.com github.com stackoverflow.com reddit.com whatsapp.com paypal.com ebay.com
bbc.com cnn.com nytimes.com medium.com quora.com spotify.com adobe.com dropbox.com zoom.us slack.com
sharjah.ac.ae uos.ac.ae emirates.com etisalat.ae dewa.gov.ae mashreqbank.com adcb.com emiratesnbd.com
aramex.com dhl.com fedex.com booking.com airbnb.com tripadvisor.com coursera.org udemy.com khanacademy.org
mozilla.org python.org kaggle.com colab.research.google.com w3schools.com geeksforgeeks.org bing.com yahoo.com
twitch.tv pinterest.com tumblr.com wordpress.com blogger.com cloudflare.com ikea.com nike.com adidas.com
walmart.com target.com bestbuy.com alibaba.com aliexpress.com noon.com careem.com talabat.com binance.com
chase.com visa.com mastercard.com alrajhibank.com.sa gov.uk nasa.gov who.int un.org imdb.com""".split()

BRANDS = ["paypal", "apple", "google", "microsoft", "amazon", "netflix", "facebook", "instagram",
          "whatsapp", "binance", "dhl", "fedex", "aramex", "emiratesnbd", "mashreq", "adcb",
          "alrajhi", "etisalat", "emirates", "visa", "mastercard", "chase", "dewa"]
KEYWORDS = ["login", "signin", "verify", "secure", "account", "update", "confirm", "password",
            "wallet", "billing", "support", "alert", "refund", "unlock", "otp", "payment"]
WORDS = ["news", "blog", "shop", "docs", "help", "about", "contact", "products", "search", "events",
         "careers", "team", "pricing", "download", "learn", "tutorial", "article", "story", "photos",
         "video", "sports", "weather", "music", "recipes", "travel", "forum", "faq", "terms", "privacy"]
BAD_TLDS = ["xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "link", "work", "icu", "buzz", "cam", "cyou"]
OK_TLDS = ["com", "net", "org", "info", "co", "online", "site", "app"]
SHORT = ["bit.ly", "tinyurl.com", "t.co", "cutt.ly", "rb.gy", "is.gd", "shorturl.at"]
LEET = {"a": "4", "o": "0", "l": "1", "e": "3", "i": "1"}


def rnd(n, alphabet="abcdefghijklmnopqrstuvwxyz0123456789"):
    return "".join(random.choice(alphabet) for _ in range(n))


def ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))


def leet(word):
    chars = list(word)
    idx = [i for i, c in enumerate(chars) if c in LEET]
    if idx:
        i = random.choice(idx)
        chars[i] = LEET[chars[i]]
    return "".join(chars)


def benign():
    dom = random.choice(POPULAR)
    r = random.random()
    host = dom
    if r < 0.45:
        host = "www." + dom
    elif r < 0.60:
        host = random.choice(["mail", "accounts", "login", "support", "docs", "shop", "my", "secure", "m"]) + "." + dom
    scheme = "https" if random.random() < 0.93 else "http"
    path = ""
    for _ in range(random.choice([0, 0, 1, 1, 2, 3])):
        path += "/" + random.choice(WORDS + KEYWORDS[:4] + [rnd(random.randint(3, 8))])
    if random.random() < 0.15:
        path += "/" + random.choice(WORDS) + "." + random.choice(["html", "php", "aspx"])
    if random.random() < 0.25:
        path += "?" + "&".join(f"{random.choice(['id','q','ref','lang','page','utm_source'])}={rnd(random.randint(1,8))}"
                               for _ in range(random.randint(1, 3)))
    # some small/personal benign sites too
    if random.random() < 0.12:
        host = random.choice(["my-", "the-", "best-", ""]) + random.choice(WORDS) + random.choice(["-shop", "-blog", "hub", ""]) + "." + random.choice(OK_TLDS)
    return f"{scheme}://{host}{path}"


def phishing():
    b = random.choice(BRANDS)
    k = random.choice(KEYWORDS)
    k2 = random.choice(KEYWORDS)
    bad = random.choice(BAD_TLDS)
    ok = random.choice(OK_TLDS)
    scheme = "https" if random.random() < 0.55 else "http"
    path = random.choice(["", "/", f"/{k}", f"/{k}/{b}", f"/{k}.php", f"/{b}/{k}/index.html",
                          f"/wp-content/{k}.php", f"/{rnd(8)}/{k}?id={rnd(10)}", f"/{k}?session={rnd(16)}&user={rnd(6)}"])
    t = random.randint(1, 10)
    if t == 1:
        host = f"{b}-{k}.{random.choice([bad, ok])}"
    elif t == 2:
        host = f"{b}.{k}.{rnd(random.randint(5, 9))}.{random.choice([bad, ok])}"
    elif t == 3:
        return f"http://{ip()}{random.choice([':8080', '', ':8000'])}/{k}/{b}.php"
    elif t == 4:
        host = f"{rnd(random.randint(8, 14))}.{bad}"
    elif t == 5:
        return f"https://{random.choice(SHORT)}/{rnd(random.randint(5, 8), 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789')}"
    elif t == 6:
        host = f"{b}.com@{rnd(random.randint(6, 10))}.{bad}"
        return f"{scheme}://{host}{path}"
    elif t == 7:
        host = f"secure.{b}.com.{rnd(random.randint(5, 9))}.{random.choice([bad, ok])}"
    elif t == 8:
        host = f"{leet(b)}.{random.choice([ok, 'com'])}"
    elif t == 9:
        host = f"{b}{k}{random.randint(1, 999)}.{random.choice([bad, ok])}"
    else:
        host = f"{rnd(random.randint(6, 12))}-{k}-{k2}.{random.choice([bad, ok])}"
        path = path or f"/{k}"
    return f"{scheme}://{host}{path}"


def main(n=12000):
    rows = [(benign(), 0) for _ in range(n)] + [(phishing(), 1) for _ in range(n)]
    random.shuffle(rows)
    with open("data/synthetic_urls.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["url", "label"])
        w.writerows(rows)
    print(f"Wrote {len(rows)} rows to data/synthetic_urls.csv")


if __name__ == "__main__":
    main()
