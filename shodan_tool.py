import re
import ssl
import urllib.request
import urllib.error

class C:
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    GREY   = "\033[90m"

def bold(t):  return f"{C.BOLD}{t}{C.RESET}"
def ok(t):    return f"{C.GREEN}{t}{C.RESET}"
def warn(t):  return f"{C.YELLOW}{t}{C.RESET}"
def err(t):   return f"{C.RED}{t}{C.RESET}"
def info(t):  return f"{C.CYAN}{t}{C.RESET}"
def grey(t):  return f"{C.GREY}{t}{C.RESET}"

def check_hsts(host: str):
    host = re.sub(r"^https?://", "", host).strip().rstrip("/")

    ctx = ssl.create_default_context()
    req = urllib.request.Request(
        f"https://{host}",
        headers={"User-Agent": "Mozilla/5.0 (compatible; HSTSChecker/1.0)"}
    )

    try:
        with urllib.request.urlopen(req, timeout=8, context=ctx) as resp:
            headers = {k.lower(): v for k, v in dict(resp.headers).items()}
    except urllib.error.HTTPError as e:
        headers = {k.lower(): v for k, v in dict(e.headers).items()}
    except Exception as e:
        return host, None, None, str(e)

    hsts = headers.get("strict-transport-security")
    if not hsts:
        return host, False, None, None

    match = re.search(r"max-age\s*=\s*(\d+)", hsts, re.IGNORECASE)
    max_age = int(match.group(1)) if match else 0

    if max_age >= 31536000:
        strength = "STRONG"
    elif max_age >= 15768000:
        strength = "GOOD"
    elif max_age >= 86400:
        strength = "WEAK"
    else:
        strength = "MISCONFIGURED"

    return host, True, strength, hsts

STRENGTH_COLOR = {
    "STRONG":        ok,
    "GOOD":          info,
    "WEAK":          warn,
    "MISCONFIGURED": err,
}

def print_result(host, present, strength, detail):
    print()
    if present is None:
        print(f"  HSTS    : {err('ERROR - ' + str(detail)[:60])}")
    elif not present:
        print(f"  HSTS    : {err('NO')}")
        print(f"  Strength: {err('NONE')}")
    else:
        color = STRENGTH_COLOR.get(strength, warn)
        print(f"  HSTS    : {ok('YES')}")
        print(f"  Strength: {color(strength)}")
    print()

def main():
    url = input("  Enter URL: ").strip()
    if not url:
        print(err("  [!] No input provided. Exiting."))
        return

    host, present, strength, detail = check_hsts(url)
    print_result(host, present, strength, detail)

if __name__ == "__main__":
    main()