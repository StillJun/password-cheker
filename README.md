# Password Breach Checker

*by StillJun*

A command-line tool that checks whether a password has appeared in known data breaches, using the [HaveIBeenPwned](https://haveibeenpwned.com/Passwords) Pwned Passwords API — without ever sending the actual password, or even its full hash, over the network.

## Why this matters

Checking a password against a breach database sounds simple, but doing it carelessly would mean sending your real password to a third-party server. This tool uses HIBP's **k-anonymity model** instead:

1. The password is hashed locally with SHA-1.
2. Only the **first 5 characters** of the hash are sent to the API.
3. The API responds with every known breached password hash that shares that same 5-character prefix — usually several hundred of them.
4. The full match is done **locally**, comparing the remaining hash characters against the list returned.

This means the API never sees your actual password, and statistically can't even be sure which of the ~800 hashes sharing that prefix you were checking.

## Features

- Single password check with hidden input (no echoing to the terminal)
- Bulk check from a text file, one password per line
- Stdin mode for piping passwords from other tools/scripts
- Risk classification based on how many times a password has appeared in breaches, not just yes/no
- Polite rate limiting when checking multiple passwords from a file

## Usage

```bash
# Interactive single check (input is hidden while typing)
python checker.py

# Check a list of passwords from a file
python checker.py --file passwords.txt

# Pipe a password in (useful for scripting / other tools)
echo "mypassword123" | python checker.py --stdin
```

## Example output

```
==================================================
  Password Breach Checker — by StillJun
  Uses HaveIBeenPwned k-anonymity API
==================================================

Enter password to check (input hidden):
Checking against HaveIBeenPwned...
Password: [BREACHED]
  Seen in breaches: 9,545,824 time(s)
  Extremely common breached password — change it immediately
```

## Requirements

- Python 3.8+
- No external dependencies — uses only the standard library (`hashlib`, `urllib.request`, `getpass`)
- Internet connection (to query the HIBP API)

## Limitations

- Checks against known *breach* data, not password strength in general — a password could be unbreached but still weak (e.g. `Wroclaw2026!` might not show up in breaches yet but is still guessable).
- HIBP's database only contains passwords from breaches that have actually been disclosed and added — absence from the list isn't a guarantee of safety, just a guarantee it hasn't shown up in a known breach yet.

## Possible improvements

- Combine breach checking with local strength heuristics (length, entropy, common patterns) for a more complete picture
- Add a `--generate` flag to suggest a strong replacement password when a breached one is found
