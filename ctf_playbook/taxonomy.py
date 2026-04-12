"""CTF technique taxonomy — the canonical list of categories and techniques.

This module is the single source of truth for technique classification.
It drives folder generation, classifier prompts, and category inference.

Structure: category -> technique -> {description, sub_techniques?}
Max depth is 3: category / technique / sub-technique.
"""

# ── Taxonomy ───────────────────────────────────────────────────────────────
# Top-level categories, their techniques, and optional sub-techniques.
# Iterating info["techniques"] yields technique slugs (dict keys).

TAXONOMY = {
    "binary-exploitation": {
        "description": "Exploiting compiled binaries",
        "techniques": {
            "buffer-overflow": {
                "description": "Stack-based buffer overflow attacks",
            },
            "format-string": {
                "description": "Format string read/write vulnerabilities",
            },
            "heap-exploitation": {
                "description": "Exploiting heap allocator internals",
                "sub_techniques": [
                    "tcache-poisoning",
                    "fastbin-attack",
                    "house-of-force",
                    "unsorted-bin-attack",
                ],
            },
            "rop-chains": {
                "description": "Return-oriented programming chains",
            },
            "race-condition": {
                "description": "Exploiting time-of-check to time-of-use gaps",
            },
            "integer-overflow": {
                "description": "Integer overflow and underflow bugs",
            },
            "use-after-free": {
                "description": "Dangling pointer dereference after free",
            },
            "double-free": {
                "description": "Freeing the same memory region twice",
            },
            "shellcode": {
                "description": "Injecting and executing custom machine code",
            },
            "kernel-exploitation": {
                "description": "Exploiting OS kernel vulnerabilities",
            },
            "sigreturn-oriented-programming": {
                "description": "Abusing sigreturn to control registers",
            },
            "got-overwrite": {
                "description": "Overwriting Global Offset Table entries",
            },
            "stack-canary-bypass": {
                "description": "Circumventing stack canary protections",
            },
            "privilege-escalation": {
                "description": "Gaining higher privileges on the system",
            },
        },
    },
    "web": {
        "description": "Web application vulnerabilities",
        "techniques": {
            "sql-injection": {
                "description": "Injecting SQL into application queries",
                "sub_techniques": [
                    "union-based",
                    "blind-boolean",
                    "blind-time",
                    "error-based",
                    "second-order",
                ],
            },
            "xss": {
                "description": "Cross-site scripting attacks",
                "sub_techniques": [
                    "reflected-xss",
                    "stored-xss",
                    "dom-xss",
                ],
            },
            "ssrf": {
                "description": "Server-side request forgery",
            },
            "deserialization": {
                "description": "Exploiting unsafe object deserialization",
            },
            "path-traversal": {
                "description": "Accessing files outside intended directories",
            },
            "command-injection": {
                "description": "Injecting OS commands via application input",
            },
            "authentication-bypass": {
                "description": "Circumventing authentication mechanisms",
            },
            "jwt-attacks": {
                "description": "Exploiting JSON Web Token weaknesses",
            },
            "xxe": {
                "description": "XML external entity injection",
            },
            "prototype-pollution": {
                "description": "Polluting JavaScript object prototypes",
            },
            "race-condition-web": {
                "description": "Web-layer race conditions and TOCTOU",
            },
            "template-injection": {
                "description": "Server-side template injection (SSTI)",
            },
            "file-upload": {
                "description": "Exploiting file upload functionality",
            },
            "request-smuggling": {
                "description": "HTTP request smuggling attacks",
            },
            "file-inclusion": {
                "description": "Local/remote file inclusion (LFI/RFI)",
            },
            "header-injection": {
                "description": "Injecting malicious HTTP headers",
            },
        },
    },
    "cryptography": {
        "description": "Breaking or misusing cryptographic primitives",
        "techniques": {
            "rsa-attacks": {
                "description": "Attacks on RSA encryption and signatures",
                "sub_techniques": [
                    "coppersmith",
                    "wiener",
                    "hastad",
                    "small-exponent",
                    "factoring",
                ],
            },
            "block-cipher-attacks": {
                "description": "Attacking block cipher modes and implementations",
            },
            "hash-collisions": {
                "description": "Finding or exploiting hash function collisions",
            },
            "padding-oracle": {
                "description": "Decrypting via padding validation leaks",
            },
            "stream-cipher-reuse": {
                "description": "Exploiting keystream reuse in stream ciphers",
            },
            "elliptic-curve-attacks": {
                "description": "Attacking elliptic curve cryptography",
            },
            "diffie-hellman-attacks": {
                "description": "Attacking Diffie-Hellman key exchange",
            },
            "lattice-based": {
                "description": "Lattice reduction attacks (LLL, BKZ)",
            },
            "classical-ciphers": {
                "description": "Breaking substitution, transposition, Vigenere, etc.",
            },
            "prng-prediction": {
                "description": "Predicting pseudorandom number generator output",
            },
            "homomorphic-misuse": {
                "description": "Exploiting misuse of homomorphic encryption",
            },
            "differential-cryptanalysis": {
                "description": "Differential analysis of cipher internals",
            },
            "chosen-plaintext-attack": {
                "description": "Attacks using chosen plaintext queries",
            },
            "known-plaintext-attack": {
                "description": "Attacks using known plaintext-ciphertext pairs",
            },
            "cbc-bit-flipping": {
                "description": "Flipping bits in CBC mode ciphertext",
            },
            "side-channel-attacks": {
                "description": "Extracting secrets via side channels",
            },
            "timing-attack": {
                "description": "Exploiting timing differences to leak information",
            },
        },
    },
    "reverse-engineering": {
        "description": "Analyzing compiled or obfuscated code",
        "techniques": {
            "static-analysis": {
                "description": "Analyzing binaries without executing them",
            },
            "dynamic-analysis": {
                "description": "Analyzing binaries at runtime with debuggers",
            },
            "deobfuscation": {
                "description": "Removing obfuscation from code or data",
            },
            "anti-debugging-bypass": {
                "description": "Bypassing anti-debugging protections",
            },
            "vm-cracking": {
                "description": "Reversing custom VM or bytecode interpreters",
            },
            "firmware-analysis": {
                "description": "Extracting and analyzing firmware images",
            },
            "android-reversing": {
                "description": "Reversing Android APKs and native libraries",
            },
            "dotnet-java-reversing": {
                "description": "Decompiling .NET and Java applications",
            },
            "constraint-solving": {
                "description": "Using SAT/SMT solvers (z3, angr) to find inputs",
            },
            "patching": {
                "description": "Binary patching to bypass checks",
            },
        },
    },
    "forensics": {
        "description": "Recovering or analyzing digital evidence",
        "techniques": {
            "file-carving": {
                "description": "Extracting embedded files from data blobs",
            },
            "memory-forensics": {
                "description": "Analyzing memory dumps (Volatility, etc.)",
            },
            "disk-forensics": {
                "description": "Analyzing disk images and filesystems",
            },
            "network-capture-analysis": {
                "description": "Analyzing packet captures (Wireshark, tshark)",
            },
            "log-analysis": {
                "description": "Parsing and analyzing system or application logs",
            },
            "steganography": {
                "description": "Finding data hidden in images, audio, or files",
                "sub_techniques": [
                    "lsb-steganography",
                    "audio-steganography",
                    "image-steganography",
                ],
            },
            "metadata-extraction": {
                "description": "Extracting metadata from files (EXIF, etc.)",
            },
            "registry-analysis": {
                "description": "Analyzing Windows registry hives",
            },
            "timeline-reconstruction": {
                "description": "Reconstructing event timelines from artifacts",
            },
        },
    },
    "misc": {
        "description": "Challenges that cross categories or don't fit neatly",
        "techniques": {
            "osint": {
                "description": "Open-source intelligence gathering",
            },
            "jail-escape": {
                "description": "Escaping restricted execution environments",
            },
            "programming-challenge": {
                "description": "Algorithmic or programming puzzles",
            },
            "blockchain": {
                "description": "Smart contract and blockchain exploits",
            },
            "hardware": {
                "description": "Hardware and embedded device challenges",
            },
            "ai-ml-exploitation": {
                "description": "Attacking AI/ML models and pipelines",
            },
            "game-hacking": {
                "description": "Exploiting game logic or memory",
            },
            "signal-processing": {
                "description": "RF, audio, and signal analysis challenges",
            },
            "ppc": {
                "description": "Professional programming and coding tasks",
            },
        },
    },
}


# ── Lookup helpers ─────────────────────────────────────────────────────────

# Reverse lookup: technique slug -> top-level category
TECHNIQUE_TO_CATEGORY: dict[str, str] = {}
for _cat, _info in TAXONOMY.items():
    for _tech in _info["techniques"]:
        TECHNIQUE_TO_CATEGORY[_tech] = _cat

# Reverse lookup: sub-technique slug -> parent technique slug
SUB_TECHNIQUE_TO_TECHNIQUE: dict[str, str] = {}
for _cat, _info in TAXONOMY.items():
    for _tech, _tech_info in _info["techniques"].items():
        for _sub in _tech_info.get("sub_techniques", []):
            SUB_TECHNIQUE_TO_TECHNIQUE[_sub] = _tech


def get_category(slug: str) -> str | None:
    """Return the top-level category for a technique slug, or None."""
    return TECHNIQUE_TO_CATEGORY.get(slug)


def get_techniques(category: str) -> list[str]:
    """Return the list of technique slugs for a category."""
    info = TAXONOMY.get(category)
    return list(info["techniques"]) if info else []


def get_technique_info(slug: str) -> dict | None:
    """Return the info dict for a technique slug, or None."""
    for _cat, _info in TAXONOMY.items():
        if slug in _info["techniques"]:
            return _info["techniques"][slug]
    return None


def get_sub_techniques(technique: str) -> list[str]:
    """Return sub-technique slugs for a technique, or empty list."""
    info = get_technique_info(technique)
    if info:
        return list(info.get("sub_techniques", []))
    return []


def get_parent_technique(sub_slug: str) -> str | None:
    """Return the parent technique for a sub-technique slug, or None."""
    return SUB_TECHNIQUE_TO_TECHNIQUE.get(sub_slug)


def all_slugs() -> set[str]:
    """Return the set of all known technique slugs."""
    return set(TECHNIQUE_TO_CATEGORY.keys())


def all_sub_slugs() -> set[str]:
    """Return the set of all known sub-technique slugs."""
    return set(SUB_TECHNIQUE_TO_TECHNIQUE.keys())


def categories() -> list[str]:
    """Return the list of all category names."""
    return list(TAXONOMY.keys())
