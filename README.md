# DecodeLabs Cybersecurity Internship (Batch 2026)

This repository houses the projects and defensive security tools completed during the DecodeLabs Cybersecurity Internship program.

---

## Repository Structure

```text
DecodeLabs/
│
├── Project 1/
│   ├── Cyber security p1.pdf  # Project specifications and guidelines
│   └── test.py                # Self-contained Password Strength Checker CLI
│
└── README.md                  # Project documentation (this file)
```

---

## Project 1: Password Strength Checker

A secure, efficient, and Pythonic Password Strength Checker implemented in `test.py` that evaluates credentials based on length, entropy, and complexity rules.

### Key Security & Design Implementations:
1. **Length Verification (Gatekeeper Check)**:
   * Enforces an immediate fail-fast policy for any password under **8 characters** (preventing brute force risk).
2. **Mandatory Pattern Recognition**:
   * Enforces hard requirements for uppercase letters `[A-Z]`, digits `[0-9]`, and symbols.
3. **Unicode Curveball Support**:
   * Leverages `unicodedata` categories to check character sets.
   * Dynamically scales the estimated brute-force search space from **95 (ASCII)** to **143,000+ (Unicode)** if non-ASCII characters or emojis are detected.
4. **Data in RAM (Immutability Trap Mitigation)**:
   * Handled using mutable `bytearray` buffers that are overwritten with zeros ("shredded") in heap memory immediately after validation is completed.
5. **Timing Attack Protection**:
   * Checks for leaked passwords using constant-time comparison via `hmac.compare_digest` in a non-short-circuiting loop.
6. **Gatekeeper Hashing Rule**:
   * Enforces validation before storage hashing. Only valid Medium/Strong passwords are encrypted/hashed using **Argon2id** (via `argon2-cffi`). Weak passwords are rejected before ever reaching the hashing step.

### Requirements:
* Python 3.3+
* `argon2-cffi` dependency:
  ```bash
  pip install argon2-cffi --break-system-packages
  ```

### Usage:
Run the interactive CLI tool:
```bash
python "Project 1/test.py"
```
