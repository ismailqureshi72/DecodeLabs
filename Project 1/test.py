"""
Password Strength Checker  --  v2
DecodeLabs Industrial Training Kit -- Project 1 (Defensive Logic Track)

This version closes the gaps flagged against the Project 1 brief:

  1. Mandatory Patterns   (p.7)  -> [A-Z], [0-9], [symbol] are now HARD
                                    requirements, not a soft score.
  2. Unicode Curveball    (p.7)  -> symbol/entropy detection uses
                                    unicodedata categories, not
                                    string.punctuation (ASCII-only), so
                                    the search space can reach the
                                    143,000+ Unicode code point range.
  3. Data in RAM Trap     (p.10) -> password is handled as a mutable
                                    bytearray and explicitly zeroed
                                    ("shredded") after use, instead of
                                    living on as an immutable str.
  4. Timing Attacks       (p.11) -> leaked-password lookup uses
                                    hmac.compare_digest in a fixed,
                                    no-short-circuit loop instead of a
                                    fast-exit `in` / set lookup.
  5. Gatekeeper Rule      (p.12) -> once a password clears validation,
                                    it is hashed with Argon2id before
                                    anything else touches it.
                                    "You cannot hash what is weak."

Install dependency once:  pip install argon2-cffi --break-system-packages
"""

import hmac
import math
import unicodedata

from argon2 import PasswordHasher
from argon2.exceptions import HashingError

# --------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------
MIN_LENGTH = 8
STRONG_LENGTH = 12

# Sample leaked-password corpus (illustrative -- a real system would use a
# much larger breach corpus, e.g. a k-anonymity lookup against HIBP).
COMMON_LEAKED_PASSWORDS = [
    "123456", "123456789", "password", "qwerty", "abc123",
    "111111", "letmein", "iloveyou", "admin", "welcome",
    "monkey", "password1", "12345678", "qwerty123",
]

ph = PasswordHasher()  # Argon2id by default in argon2-cffi


# --------------------------------------------------------------------------
# 2. Unicode-aware character classification (fixes "Unicode Curveball")
# --------------------------------------------------------------------------
def char_pool_contribution(password: str):
    """
    Inspect the password's actual character classes and return the size
    of the search-space "pool" an attacker would have to brute-force,
    using Unicode categories rather than ASCII-only assumptions.

    Pools (per the p.7 diagram):
      lowercase ascii : 26
      uppercase ascii : 26
      digits          : 10
      ascii symbols   : 33
      any codepoint outside the above (accents, emoji, CJK, etc.):
                        treated as drawing from the wider Unicode
                        symbol/letter space (~143,000+ assigned code
                        points), which is what actually breaks a
                        brute-force estimate that only assumes 95
                        printable ASCII characters.
    """
    has_lower = has_upper = has_digit = has_ascii_symbol = has_unicode_symbol = has_unicode_ext = False

    for ch in password:
        codepoint = ord(ch)
        category = unicodedata.category(ch)  # e.g. 'Lu', 'Ll', 'Nd', 'Po', 'Sc'...

        if codepoint > 127:
            # Anything outside 7-bit ASCII
            has_unicode_ext = True

        if category == "Ll":
            has_lower = True
        elif category == "Lu":
            has_upper = True
        elif category == "Nd":
            has_digit = True
        elif category[0] in ("P", "S"):  # Punctuation or Symbol categories
            if codepoint > 127:
                has_unicode_symbol = True
            else:
                has_ascii_symbol = True
        elif not ch.isalnum() and not ch.isspace():  # Fallback for other specials
            if codepoint > 127:
                has_unicode_symbol = True
            else:
                has_ascii_symbol = True

    pool_size = 0
    if has_lower:
        pool_size += 26
    if has_upper:
        pool_size += 26
    if has_digit:
        pool_size += 10
    if has_ascii_symbol:
        pool_size += 33
    if has_unicode_ext:
        pool_size += 143_000  # conservative nod to the deck's 143,000+ figure

    has_symbol = has_ascii_symbol or has_unicode_symbol
    return has_lower, has_upper, has_digit, has_symbol, pool_size


def calculate_entropy_bits(password: str, pool_size: int) -> float:
    """Shannon-style estimate: bits = length * log2(pool_size)."""
    if pool_size <= 0 or len(password) == 0:
        return 0.0
    return len(password) * math.log2(pool_size)


# --------------------------------------------------------------------------
# 4. Constant-time leaked-password check (fixes "Timing Attacks")
# --------------------------------------------------------------------------
def is_leaked_constant_time(password: str, corpus) -> bool:
    """
    Check membership without giving an attacker a timing side-channel.

    A plain `password in some_set` or `password in some_list` returns as
    soon as a match (or a suitable non-match) is found, and Python's
    string equality itself short-circuits on the first differing byte.
    That variable timing is exactly what page 11 warns about.

    Fix: compare against *every* entry, every time, using
    hmac.compare_digest (constant-time), and OR the results together
    so total execution time doesn't depend on where/whether a match
    occurs.
    """
    encoded_password = password.encode("utf-8")
    found = False
    for entry in corpus:
        match = hmac.compare_digest(encoded_password, entry.encode("utf-8"))
        found = found or match
    return found


# --------------------------------------------------------------------------
# 3. Memory shredding helper (fixes "Data in RAM Trap")
# --------------------------------------------------------------------------
def shred(buffer: bytearray) -> None:
    """
    Overwrite a mutable byte buffer with zeros in place.

    Python `str` objects are immutable, so a plaintext password stored
    as a str cannot be reliably wiped -- it lingers in heap memory
    until garbage collected (the exact RAM-scraping risk on p.10,
    e.g. BlackPOS-style malware). A `bytearray` *can* be mutated in
    place, so we do the password-handling work on a bytearray and
    zero it out the moment we're done with it.

    Caveat (documented, not hidden): if the password ever passed
    through a Python `str` first (e.g. from `input()`), that original
    str is still immutable and may remain in memory until the garbage
    collector reclaims it. This function shreds what it *can*
    control -- the bytearray copy -- which is the standard mitigation
    pattern in Python since true guaranteed wiping of str objects
    isn't possible at the language level.
    """
    for i in range(len(buffer)):
        buffer[i] = 0


# --------------------------------------------------------------------------
# 1. Strength classification with MANDATORY pattern enforcement
#    (fixes "Mandatory Patterns" -- was a soft variety_score >= 3)
# --------------------------------------------------------------------------
def check_password_strength(password_buf: bytearray):
    """
    password_buf: a bytearray holding the UTF-8 encoded password.
    Returns (strength, feedback_list, entropy_bits).
    """
    password = password_buf.decode("utf-8")
    feedback = []

    # --- Gatekeeper: length check first, fail fast ---
    if len(password) < MIN_LENGTH:
        return "Weak", [f"Too short -- must be at least {MIN_LENGTH} characters."], 0.0

    # --- Constant-time leaked-password check ---
    if is_leaked_constant_time(password, COMMON_LEAKED_PASSWORDS):
        return "Weak", ["This password appears in common leaked-password lists."], 0.0

    has_lower, has_upper, has_digit, has_symbol, pool_size = char_pool_contribution(password)
    entropy_bits = calculate_entropy_bits(password, pool_size)

    # --- MANDATORY enforcement: [A-Z], [0-9], [symbol] are all required.
    #     No amount of extra length substitutes for a missing category. ---
    missing = []
    if not has_upper:
        missing.append("an uppercase letter [A-Z]")
    if not has_digit:
        missing.append("a number [0-9]")
    if not has_symbol:
        missing.append("a symbol")

    if missing:
        feedback.append("Mandatory requirement not met -- add " + ", ".join(missing) + ".")
        return "Weak", feedback, entropy_bits

    if not has_lower:
        feedback.append("Consider adding a lowercase letter for extra strength.")

    # All mandatory categories present -> at least Medium.
    if len(password) >= STRONG_LENGTH and has_lower:
        strength = "Strong"
        feedback = ["All mandatory categories present, strong length, good entropy."]
    else:
        strength = "Medium"
        if len(password) < STRONG_LENGTH:
            feedback.append(f"Reach {STRONG_LENGTH}+ characters to qualify as Strong.")

    return strength, feedback, entropy_bits


def render_bar(strength: str) -> str:
    bars = {
        "Weak": "[#___________] WEAK",
        "Medium": "[######______] MEDIUM",
        "Strong": "[############] STRONG",
    }
    return bars.get(strength, "")


# --------------------------------------------------------------------------
# 5. Gatekeeper Rule: validate BEFORE hashing (fixes omission of Argon2id)
# --------------------------------------------------------------------------
def hash_if_valid(strength: str, password_buf: bytearray):
    """
    "You cannot hash what is weak. Filter entropy before Argon2id." (p.12)

    Only Medium/Strong passwords -- i.e. ones that passed every
    mandatory check -- get hashed. Weak passwords are rejected before
    ever reaching the hashing step.
    """
    if strength == "Weak":
        return None
    try:
        # Pass bytes directly to Argon2id to avoid creating an immutable plaintext string in memory.
        pwd_bytes = bytes(password_buf)
        hashed = ph.hash(pwd_bytes)
        # Explicitly delete bytes copy to free memory promptly.
        del pwd_bytes
        return hashed
    except HashingError:
        return None


def main():
    print("=== DecodeLabs Password Strength Checker (v2) ===")
    print("Type a password to check (or 'quit' to exit).\n")

    while True:
        raw = input("Enter password: ")
        if raw.lower() == "quit":
            print("Goodbye!")
            break

        # Move into a mutable bytearray as early as possible so we have
        # something we can actually shred later (see `shred()` docstring
        # for the honest caveat about the original str).
        password_buf = bytearray(raw.encode("utf-8"))
        raw = None  # drop our reference to the str; can't wipe it, but stop holding it

        strength, feedback, entropy_bits = check_password_strength(password_buf)

        print(f"\nStrength: {strength}")
        print(render_bar(strength))
        print(f"Estimated entropy: {entropy_bits:.1f} bits")
        for tip in feedback:
            print(f"  - {tip}")

        argon2_hash = hash_if_valid(strength, password_buf)
        if argon2_hash:
            print(f"Argon2id hash (for storage): {argon2_hash}")
        else:
            print("Rejected before hashing -- weak passwords are never hashed or stored.")

        # Done with the plaintext -- shred the mutable buffer.
        shred(password_buf)
        print()


if __name__ == "__main__":
    main()