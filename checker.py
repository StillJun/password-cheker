#!/usr/bin/env python3
"""
Password Breach Checker
by StillJun

Checks whether a password has appeared in known data breaches, using the
HaveIBeenPwned "Pwned Passwords" API — without ever sending your actual
password anywhere.

Usage:
    python checker.py                  # interactive prompt, hidden input
    python checker.py --file list.txt  # check multiple passwords from a file
    python checker.py --stdin          # read a single password from stdin (for piping)
"""

import argparse
import getpass
import hashlib
import sys
import time
import urllib.error
import urllib.request

API_URL = "https://api.pwnedpasswords.com/range/{prefix}"
USER_AGENT = "password-checker-by-StillJun"
REQUEST_TIMEOUT = 10


def sha1_hash(password: str) -> str:
    """Returns the uppercase SHA-1 hex digest of a password."""
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()


def query_hibp_range(prefix: str) -> str:
    """
    Queries the HIBP range API for a 5-character SHA-1 prefix.
    Returns the raw response body (a list of suffix:count pairs).

    This is the k-anonymity trick: we only ever send the first 5 characters
    of the hash. The API returns every suffix that shares that prefix —
    typically several hundred — and we check locally whether our exact
    suffix is among them. The real password, or even its full hash, never
    leaves the machine.
    """
    url = API_URL.format(prefix=prefix)
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})

    try:
        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT) as response:
            return response.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"HIBP API returned HTTP {e.code}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(f"Could not reach HIBP API: {e.reason}") from e


def check_password(password: str) -> dict:
    """
    Checks a single password against the HIBP database.
    Returns {'breached': bool, 'count': int}.
    'count' is how many times this exact password has been seen in breaches.
    """
    full_hash = sha1_hash(password)
    prefix, suffix = full_hash[:5], full_hash[5:]

    response_text = query_hibp_range(prefix)

    for line in response_text.splitlines():
        if ":" not in line:
            continue
        returned_suffix, count_str = line.split(":")
        if returned_suffix == suffix:
            return {"breached": True, "count": int(count_str)}

    return {"breached": False, "count": 0}


def describe_risk(count: int) -> str:
    """Turns a raw breach count into a human-readable risk level."""
    if count == 0:
        return "Not found in known breaches"
    if count < 100:
        return "Seen in breaches — change it"
    if count < 100_000:
        return "Commonly breached — change it now"
    return "Extremely common breached password — change it immediately"


def check_single_interactive() -> None:
    password = getpass.getpass("Enter password to check (input hidden): ")
    if not password:
        print("No password entered.")
        return

    print("Checking against HaveIBeenPwned...")
    try:
        result = check_password(password)
    except RuntimeError as e:
        print(f"Error: {e}")
        sys.exit(1)

    print_result(password_label="Password", result=result)


def check_single_stdin() -> None:
    password = sys.stdin.readline().rstrip("\n")
    if not password:
        print("No password received on stdin.")
        return

    try:
        result = check_password(password)
    except RuntimeError as e:
        print(f"Error: {e}")
        sys.exit(1)

    print_result(password_label="Password", result=result)


def check_file(path: str) -> None:
    try:
        with open(path, "r") as f:
            passwords = [line.rstrip("\n") for line in f if line.strip()]
    except FileNotFoundError:
        print(f"File not found: {path}")
        sys.exit(1)

    if not passwords:
        print("File is empty.")
        return

    print(f"Checking {len(passwords)} password(s) from {path}...\n")

    breached_count = 0
    for i, pw in enumerate(passwords, start=1):
        try:
            result = check_password(pw)
        except RuntimeError as e:
            print(f"[{i}] Error checking password: {e}")
            continue

        if result["breached"]:
            breached_count += 1

        print_result(password_label=f"[{i}] Password", result=result, mask=True)

        # Be a polite API citizen — avoid hammering the endpoint on large lists
        time.sleep(0.2)

    print(f"\nSummary: {breached_count}/{len(passwords)} password(s) found in breaches.")


def print_result(password_label: str, result: dict, mask: bool = False) -> None:
    status = "BREACHED" if result["breached"] else "CLEAN"
    risk = describe_risk(result["count"])

    print(f"{password_label}: [{status}]")
    if result["breached"]:
        print(f"  Seen in breaches: {result['count']:,} time(s)")
    print(f"  {risk}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Check passwords against known data breaches via HaveIBeenPwned.",
        epilog="by StillJun",
    )
    parser.add_argument(
        "--file", metavar="PATH",
        help="Check a list of passwords from a text file, one per line",
    )
    parser.add_argument(
        "--stdin", action="store_true",
        help="Read a single password from stdin instead of an interactive prompt",
    )

    args = parser.parse_args()

    print("=" * 50)
    print("  Password Breach Checker — by StillJun")
    print("  Uses HaveIBeenPwned k-anonymity API")
    print("=" * 50)
    print()

    if args.file:
        check_file(args.file)
    elif args.stdin:
        check_single_stdin()
    else:
        check_single_interactive()


if __name__ == "__main__":
    main()
