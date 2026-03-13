"""
Wordlist_generator — Core Generation Engine
Shared between CLI and Flask webapp (app.py)
"""

SPECIALS = ['@', '#', '$']


# ─── Date Token Builders ──────────────────────────────────────────────────────

def build_years(year_from, year_to):
    return [str(y) for y in range(year_from, year_to + 1)]

def build_ddmm():
    return [f"{d:02d}{m:02d}" for d in range(1, 32) for m in range(1, 13)]

def build_mmdd():
    return [f"{m:02d}{d:02d}" for m in range(1, 13) for d in range(1, 32)]

def build_dddd():
    return [f"{d1:02d}{d2:02d}" for d1 in range(1, 32) for d2 in range(1, 32)]

def build_mmmm():
    return [f"{m1:02d}{m2:02d}" for m1 in range(1, 13) for m2 in range(1, 13)]


# ─── Pattern Generators ───────────────────────────────────────────────────────

def date_patterns(name, cap, tokens):
    """
    For each token generates 8 variants:
      name+token, Name+token
      name+@+token, Name+@+token  (x3 specials)
      name+token+@, Name+token+@  (x3 specials)
    """
    entries = []
    for t in tokens:
        entries.append(name + t)
        entries.append(cap  + t)
        for sp in SPECIALS:
            entries.append(name + sp + t)
            entries.append(cap  + sp + t)
            entries.append(name + t  + sp)
            entries.append(cap  + t  + sp)
    return entries


def brute_patterns(name, cap):
    """4-digit brute force 0000-9999 with specials."""
    entries = []
    for sp in SPECIALS:
        for i in range(10000):
            n = f"{i:04d}"
            entries.append(name + sp + n)
            entries.append(cap  + sp + n)
    for i in range(10000):
        entries.append(name + f"{i:04d}")
    for sp in SPECIALS:
        for i in range(10000):
            entries.append(name + f"{i:04d}" + sp)
    return entries


# ─── Main Generator ───────────────────────────────────────────────────────────

def generate(names, year_from, year_to, include_brute=True):
    """
    Returns a deduplicated list in priority order:
      1. YYYY   — top
      2. DDMM, MMDD, DDDD, MMMM
      3. Brute  — bottom
    """
    seen   = set()
    result = []

    def add(entries):
        for w in entries:
            if w not in seen:
                seen.add(w)
                result.append(w)

    years = build_years(year_from, year_to)
    ddmm  = build_ddmm()
    mmdd  = build_mmdd()
    dddd  = build_dddd()
    mmmm  = build_mmmm()

    for name in names:
        cap = name.capitalize()
        add(date_patterns(name, cap, years))
        add(date_patterns(name, cap, ddmm))
        add(date_patterns(name, cap, mmdd))
        add(date_patterns(name, cap, dddd))
        add(date_patterns(name, cap, mmmm))
        if include_brute:
            add(brute_patterns(name, cap))

    return result


def validate_names(names):
    """Returns list of error strings, empty if all valid."""
    errors = []
    for name in names:
        if not name:
            continue
        if not name.isalpha() or name != name.lower():
            errors.append(f"'{name}' must be lowercase letters only (a-z)")
    return errors
