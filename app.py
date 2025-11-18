import asyncio
import json
try:
    # Use the full unicodedata2 library if installed
    import unicodedata2 as unicodedata
    print("Using full unicodedata2 library.")
except ImportError:
    # Fall back to Pyodide's built-in (incomplete) version
    import unicodedata
    print("Warning: unicodedata2 not found. Falling back to built-in unicodedata (normalization may be incomplete).")
from pyodide.ffi import create_proxy, to_js
from pyodide.http import pyfetch
from pyscript import document, window
import hashlib
import re


# ---
# 1. CATEGORY & REGEX DEFINITIONS
# ---

# We only use "Honest" mode, so we only need the 29 categories
# (Cn is calculated mathematically)
MINOR_CATEGORIES_29 = {
    # Letters
    "Lu": r"\p{Lu}", "Ll": r"\p{Ll}", "Lt": r"\p{Lt}", "Lm": r"\p{Lm}", "Lo": r"\p{Lo}",
    # Marks
    "Mn": r"\p{Mn}", "Mc": r"\p{Mc}", "Me": r"\p{Me}",
    # Numbers
    "Nd": r"\p{Nd}", "Nl": r"\p{Nl}", "No": r"\p{No}",
    # Punctuation
    "Pc": r"\p{Pc}", "Pd": r"\p{Pd}", "Ps": r"\p{Ps}", "Pe": r"\p{Pe}",
    "Pi": r"\p{Pi}", "Pf": r"\p{Pf}", "Po": r"\p{Po}",
    # Symbols
    "Sm": r"\p{Sm}", "Sc": r"\p{Sc}", "Sk": r"\p{Sk}", "So": r"\p{So}",
    # Separators
    "Zs": r"\p{Zs}", "Zl": r"\p{Zl}", "Zp": r"\p{Zp}",
    # Other (excl. Cn)
    "Cc": r"\p{Cc}", "Cf": r"\p{Cf}", "Cs": r"\p{Cs}", "Co": r"\p{Co}"
}

# Regexes for finding *all* matches and their indices (must be 'gu')
REGEX_MATCHER = {
    "Whitespace": window.RegExp.new(r"\p{White_Space}", "gu"),
    "Marks": window.RegExp.new(r"\p{M}", "gu"),
    
    # Forensic Properties (for Module 2.C)
    # "Noncharacter" and "Deceptive Spaces" are now handled in Python
    "Ignorables (Invisible)": window.RegExp.new(r"\p{Default_Ignorable_Code_Point}", "gu"),
    
    # UAX #44 Properties (for Module 2.D)
    "Dash": window.RegExp.new(r"\p{Dash}", "gu"),
    "Alphabetic": window.RegExp.new(r"\p{Alphabetic}", "gu"),
    "Script: Cyrillic": window.RegExp.new(r"\p{Script=Cyrillic}", "gu"),
    "Script: Greek": window.RegExp.new(r"\p{Script=Greek}", "gu"),
    "Script: Han": window.RegExp.new(r"\p{Script=Han}", "gu"),
    "Script: Arabic": window.RegExp.new(r"\p{Script=Arabic}", "gu"),
    "Script: Hebrew": window.RegExp.new(r"\p{Script=Hebrew}", "gu"),
    "Script: Latin": window.RegExp.new(r"\p{Script=Latin}", "gu"),
    "Script: Common": window.RegExp.new(r"\p{Script=Common}", "gu"),
    "Script: Inherited": window.RegExp.new(r"\p{Script=Inherited}", "gu"),

    # Confusable runs (for Module 3)
    "LNPS_Runs": window.RegExp.new(r"\p{L}+|\p{N}+|\p{P}+|\p{S}+", "gu"),
}

# ---
# 1.B. INVISIBLE CHARACTER MAPPING (For Deobfuscator)
# ---
INVISIBLE_MAPPING = {
    0x00AD: "[SHY]",           # Soft Hyphen
    0x034F: "[CGJ]",           # Combining Grapheme Joiner
    0x061C: "[ALM]",           # Arabic Letter Mark
    0x200B: "[ZWSP]",          # Zero Width Space
    0x200C: "[ZWNJ]",          # Zero Width Non-Joiner
    0x200D: "[ZWJ]",           # Zero Width Joiner
    0x200E: "[LRM]",           # Left-To-Right Mark
    0x200F: "[RLM]",           # Right-To-Left Mark
    0x202A: "[LRE]",           # Left-To-Right Embedding
    0x202B: "[RLE]",           # Right-To-Left Embedding
    0x202C: "[PDF]",           # Pop Directional Formatting
    0x202D: "[LRO]",           # Left-To-Right Override
    0x202E: "[RLO]",           # Right-To-Left Override
    0x2060: "[WJ]",            # Word Joiner
    0x2061: "[FA]",            # Function Application
    0x2062: "[IT]",            # Invisible Times
    0x2063: "[IS]",            # Invisible Separator
    0x2066: "[LRI]",           # Left-To-Right Isolate
    0x2067: "[RLI]",           # Right-To-Left Isolate
    0x2068: "[FSI]",           # First Strong Isolate
    0x2069: "[PDI]",           # Pop Directional Isolate
    0xFEFF: "[BOM]",           # Byte Order Mark
    0x180E: "[MVS]",           # Mongolian Vowel Separator
}
# Add Tag Characters (E0001, E0020-E007F) if you want, but this covers the main threats.


# Valid base characters for U+20E3 (Combining Enclosing Keycap)
VALID_KEYCAP_BASES = frozenset({
    0x0030, 0x0031, 0x0032, 0x0033, 0x0034, 0x0035, 0x0036, 0x0037, 0x0038, 0x0039, # Digits 0-9
    0x0023, # Hash
    0x002A  # Asterisk
})

# Pre-compiled testers for single characters

# Sequences that modify intent but are not RGI
# (This is just an example list, you would need to curate this)
INTENT_MODIFYING_ZWJ_SEQUENCES = {
    "🏃‍➡️": "Directional ZWJ (Runner + Right Arrow)",
    "➡️‍⬛": "Color ZWJ (Right Arrow + Black Square)",
    # Add other sequences here, like Hand + ZWJ + Holding...
}

# Also create a set for fast lookup
INTENT_MODIFYING_ZWJ_SET = frozenset(INTENT_MODIFYING_ZWJ_SEQUENCES.keys())
INTENT_MODIFYING_MAX_LEN = max((len(s) for s in INTENT_MODIFYING_ZWJ_SET), default=0)

TEST_MINOR = {key: window.RegExp.new(f"^{val}$", "u") for key, val in MINOR_CATEGORIES_29.items()}
TEST_MAJOR = {
    "L (Letter)": window.RegExp.new(r"^\p{L}$", "u"),
    "M (Mark)": window.RegExp.new(r"^\p{M}$", "u"),
    "N (Number)": window.RegExp.new(r"^\p{N}$", "u"),
    "P (Punctuation)": window.RegExp.new(r"^\p{P}$", "u"),
    "S (Symbol)": window.RegExp.new(r"^\p{S}$", "u"),
    "Z (Separator)": window.RegExp.new(r"^\p{Z}$", "u"),
    "C (Other)": window.RegExp.new(r"^\p{C}$", "u")
}


ALIASES = {
    "Lu": "Uppercase Letter", "Ll": "Lowercase Letter", "Lt": "Titlecase Letter", "Lm": "Modifier Letter", "Lo": "Other Letter",
    "Mn": "Nonspacing Mark", "Mc": "Spacing Mark", "Me": "Enclosing Mark",
    "Nd": "Decimal Number", "Nl": "Letter Number", "No": "Other Number",
    "Pc": "Connector Punct.", "Pd": "Dash Punct.", "Ps": "Open Punct.", "Pe": "Close Punct.",
    "Pi": "Initial Punct.", "Pf": "Final Punct.", "Po": "Other Punct.",
    "Sm": "Math Symbol", "Sc": "Currency Symbol", "Sk": "Modifier Symbol", "So": "Other Symbol",
    "Zs": "Space Separator", "Zl": "Line Separator", "Zp": "Paragraph Separator",
    "Cc": "Control", "Cf": "Format", "Cs": "Surrogate", "Co": "Private Use", "Cn": "Unassigned"
}

CCC_ALIASES = {
    # Full list is long, these are the most common "Zalgo" ones
    "1": "Overlay",
    "218": "Double Below",
    "220": "Attached Below",
    "222": "Attached Below Left",
    "228": "Attached Above Right",
    "230": "Attached Above",
    "232": "Attached Above Left",
    "233": "Below",
    "234": "Above",
}

# 1.C. UAX #31 IDENTIFIER STATUS DEFINITIONS# ---
# We must define all categories to correctly implement the "default-to-restricted" rule.# Source: https://www.unicode.org/reports/tr31/
# These are explicitly "Allowed" or "Recommended"
UAX31_ALLOWED_STATUSES = {
    "Allowed",
    "Recommended",
    "Limited_Use",
}

# These are the various "Restricted" types.
UAX31_RESTRICTED_STATUSES = {
    "Restricted",
    "Technical",
    "Uncommon_Use",
    "Deprecated",
    "Obsolete",
}

# ------------------------------------------------------------
#  PATCH B: Robust Normalization Layer for Pyodide/PyScript
# ------------------------------------------------------------

# Tier 1: Attempt to import unicodedata2 (full Unicode)
try:
    import unicodedata2 as _ud
    NORMALIZER = "unicodedata2"
    print("Using full unicodedata2 library.")
except Exception:
    import unicodedata as _ud
    NORMALIZER = "unicodedata"
    # We already print a warning for this during startup

# Tier 3: Manual expansions Pyodide fails to handle
# Enclosed Alphanumerics → ASCII (⓼ → 8, ⓐ → a, ① → 1, etc.)
# Covers U+2460–U+24FF (Full set)

ENCLOSED_MAP = {}

# Build mapping for numbers ①–⑳ etc.
def _build_enclosed():
    """Populates the ENCLOSED_MAP with manual normalization rules."""
    try:
        # Build mapping for numbers ①–⑳ etc. (U+2460 to U+2473)
        for codepoint in range(0x2460, 0x2474):
            ENCLOSED_MAP[chr(codepoint)] = str(codepoint - 0x245F)
        
        # Build mapping for circled numbers ⓵–⓾ (U+24F5 to U+24FE)
        for i in range(1, 11):
            ENCLOSED_MAP[chr(0x24F4 + i)] = str(i) # 0x24F5 is 1
            
        # Build mapping for circled Latin letters ⓐ–ⓩ (U+24D0 to U+24E9)
        for i in range(26):
            ENCLOSED_MAP[chr(0x24D0 + i)] = chr(ord('a') + i)
            
        # Build mapping for circled capital letters Ⓐ–Ⓩ (U+24B6 to U+24CF)
        for i in range(26):
            ENCLOSED_MAP[chr(0x24B6 + i)] = chr(ord('A') + i)
            
        print(f"Built manual ENCLOSED_MAP with {len(ENCLOSED_MAP)} rules.")
    except Exception as e:
        print(f"Error building ENCLOSED_MAP: {e}")

# --- THIS IS THE FIX ---
# Call the function once at startup to populate the map.
_build_enclosed()
# --- END OF FIX ---


def normalize_extended(text: str) -> str:
    """
    Extended normalization pipeline:
    Tier 1: NFKC via unicodedata2 if available
    Tier 2: fallback Pyodide NFKC
    Tier 3: manually expand enclosed alphanumerics & width-forms
    """
    if not text:
        return ""
        
    # Base normalization (Tier 1 or 2)
    try:
        s = _ud.normalize("NFKC", text)
    except Exception:
        s = text # Failsafe

    # Manual Enclosed Alphanumerics (fixes ⓼ → 8)
    s = "".join(ENCLOSED_MAP.get(ch, ch) for ch in s)

    # Normalize Fullwidth ASCII (Ｆ → F)
    # (U+FF01 to U+FF5E)
    s = "".join(
        chr(ord(ch) - 0xFEE0) if 0xFF01 <= ord(ch) <= 0xFF5E else ch
        for ch in s
    )

    # Remove default emoji variation selectors (FE0F)
    # This makes '❤️' (U+2764 FE0F) normalize to '❤' (U+2764)
    s = re.sub(r"[\uFE0E\uFE0F]", "", s)

    return s

# Grapheme Segmenter (UAX #29)
GRAPHEME_SEGMENTER = window.Intl.Segmenter.new("en", {"granularity": "grapheme"})

# ---
# 1.A. PRE-COMPILE ALL MINOR CATEGORY REGEXES
# ---
# This is the fix: We pre-compile all 29 regexes into REGEX_MATCHER
# to use the proven-correct 'matchAll' method, just like the
# 'Provenance' module does.

for key, regex_str in MINOR_CATEGORIES_29.items():
    # Add to the main matcher dict
    REGEX_MATCHER[key] = window.RegExp.new(regex_str, "gu")

# ---
# 2. GLOBAL DATA STORES & ASYNC LOADING
# ---

LOADING_STATE = "PENDING"  # PENDING, LOADING, READY, FAILED

DATA_STORES = {
    "Blocks": {"ranges": [], "starts": [], "ends": []},
    "Age": {"ranges": [], "starts": [], "ends": []},
    "Discouraged": {"ranges": [], "starts": [], "ends": []}, # For manual security overrides
    "IdentifierType": {"ranges": [], "starts": [], "ends": []},
    "IdentifierStatus": {"ranges": [], "starts": [], "ends": []},
    "IntentionalPairs": set(),
    "ScriptExtensions": {"ranges": [], "starts": [], "ends": []},
    "LineBreak": {"ranges": [], "starts": [], "ends": []},
    "BidiControl": {"ranges": [], "starts": [], "ends": []},
    "JoinControl": {"ranges": [], "starts": [], "ends": []},
    "Extender": {"ranges": [], "starts": [], "ends": []},
    "WhiteSpace": {"ranges": [], "starts": [], "ends": []},
    "OtherDefaultIgnorable": {"ranges": [], "starts": [], "ends": []},
    "Deprecated": {"ranges": [], "starts": [], "ends": []},
    "VariationSelector": {"ranges": [], "starts": [], "ends": []},
    "Scripts": {"ranges": [], "starts": [], "ends": []},
    "Dash": {"ranges": [], "starts": [], "ends": []},
    "QuotationMark": {"ranges": [], "starts": [], "ends": []},
    "TerminalPunctuation": {"ranges": [], "starts": [], "ends": []},
    "SentenceTerminal": {"ranges": [], "starts": [], "ends": []},
    "Alphabetic": {"ranges": [], "starts": [], "ends": []},
    "WordBreak": {"ranges": [], "starts": [], "ends": []},
    "SentenceBreak": {"ranges": [], "starts": [], "ends": []},
    "GraphemeBreak": {"ranges": [], "starts": [], "ends": []},
    "DoNotEmit": {"ranges": [], "starts": [], "ends": []},
    "CombiningClass": {"ranges": [], "starts": [], "ends": []},
    "DecompositionType": {"ranges": [], "starts": [], "ends": []},
    "NumericType": {"ranges": [], "starts": [], "ends": []},
    "BidiMirrored": {"ranges": [], "starts": [], "ends": []},
    "LogicalOrderException": {"ranges": [], "starts": [], "ends": []},
    "Confusables": {},

    "EastAsianWidth": {"ranges": [], "starts": [], "ends": []},
    "VerticalOrientation": {"ranges": [], "starts": [], "ends": []},
    "BidiBracketType": {"ranges": [], "starts": [], "ends": []},
    "CompositionExclusions": {"ranges": [], "starts": [], "ends": []},
    "ChangesWhenNFKCCasefolded": {"ranges": [], "starts": [], "ends": []},
    "BidiMirroring": {}, # This will be a simple dict {cp: mirrored_cp}
    
    "VariantBase": set(),
    "VariantSelectors": set()
}

def _parse_and_store_ranges(txt: str, store_key: str):
    """Generic parser for Unicode range data files (Blocks, Age, etc.)"""
    store = DATA_STORES[store_key]
    store["ranges"].clear()
    store["starts"].clear()
    store["ends"].clear()
    
    ranges_list = []
    for raw in txt.splitlines():
        line = raw.split('#', 1)[0].strip()
        if not line:
            continue
        
        parts = line.split(';', 1)
        if len(parts) < 2:
            continue
        code_range, value = parts[0].strip(), parts[1].strip()
        
        if '..' in code_range:
            a, b = code_range.split('..', 1)
            ranges_list.append((int(a, 16), int(b, 16), value))
        else:
            cp = int(code_range, 16)
            ranges_list.append((cp, cp, value))
    
    ranges_list.sort()
    
    for s, e, v in ranges_list:
        store["ranges"].append((s, e, v))
        store["starts"].append(s)
        store["ends"].append(e)
    
    print(f"Loaded {len(ranges_list)} ranges for {store_key}.")

def _parse_confusables(txt: str):
    """Parses confusables.txt into the CONFUSABLES_MAP."""
    store = DATA_STORES["Confusables"]
    store.clear()
    count = 0
    for raw in txt.splitlines():
        line = raw.split('#', 1)[0].strip()
        if not line or line.startswith(';'):
            continue
        
        parts = line.split(';', 2)
        if len(parts) < 2:
            continue
        
        try:
            source_hex = parts[0].strip()
            skeleton_hex_list = parts[1].strip().split()
            source_cp = int(source_hex, 16)
            skeleton_str = "".join([chr(int(hex_val, 16)) for hex_val in skeleton_hex_list])
            
            # Add to map
            store[source_cp] = skeleton_str
            count += 1
        except Exception:
            pass # Ignore malformed lines
    print(f"Loaded {count} confusable mappings.")

def _parse_standardized_variants(txt: str):
    """Parses StandardizedVariants.txt into two sets."""
    # Create new, local sets instead of modifying the global one
    base_set = set()
    selector_set = set()
    
    for raw in txt.splitlines():
        line = raw.split('#', 1)[0].strip()
        if not line:
            continue
            
        parts = line.split(';', 1)
        if len(parts) < 2:
            continue
        
        hex_codes = parts[0].strip().split()
        if len(hex_codes) == 2:
            try:
                base_cp = int(hex_codes[0], 16)
                selector_cp = int(hex_codes[1], 16)
                base_set.add(base_cp)
                selector_set.add(selector_cp)
            except ValueError:
                pass
                
    print(f"Loaded {len(base_set)} variant base chars and {len(selector_set)} unique selectors.")
    # Return the new local sets
    return base_set, selector_set

def _parse_emoji_variants(txt: str):
    """Parses emoji-variation-sequences.txt to find emoji base chars."""
    # Create a new, local set
    base_set = set()
    count = 0
    for raw in txt.splitlines():
        line = raw.split('#', 1)[0].strip()
        if not line:
            continue
            
        parts = line.split(';', 1)
        if len(parts) < 2:
            continue
            
        hex_codes = parts[0].strip().split()
        
        try:
            # The base char is always the first one (e.g., '0023' from '0023 FE0E')
            if hex_codes:
                base_cp = int(hex_codes[0], 16)
                if base_cp not in base_set:
                    base_set.add(base_cp)
                    count += 1
        except Exception:
            pass # Ignore malformed lines
            
    print(f"Loaded {count} new emoji base chars from emoji-variation-sequences.")
    # Return the new local set
    return base_set

def _parse_emoji_test(txt: str) -> dict:
    """
    Parses emoji-test.txt to build a map of {sequence: qualification_status}
    
    Format:
    # group: fully-qualified
    1F600 ; fully-qualified # 😀 grinning face
    ...
    # group: unqualified
    00A9 ; unqualified # © copyright
    """
    qualification_map = {}
    current_group = "unknown"
    
    for raw in txt.splitlines():
        line = raw.split('#', 1)[0].strip()
        if not line:
            continue
            
        # Check if this is a group header
        if line.startswith("# group:"):
            current_group = line.split(":", 1)[-1].strip()
            continue
            
        try:
            parts = line.split(';', 1)
            if len(parts) < 2:
                continue
                
            hex_codes_str = parts[0].strip()
            status = parts[1].strip()
            
            # Use the status from the line if available, otherwise from the group
            final_status = status if status in {"fully-qualified", "minimally-qualified", "unqualified", "component"} else current_group
            
            # We only care about these statuses
            if final_status not in {"fully-qualified", "minimally-qualified", "unqualified", "component"}:
                continue

            hex_codes = hex_codes_str.split()
            sequence_str = "".join([chr(int(h, 16)) for h in hex_codes])
            
            if sequence_str:
                qualification_map[sequence_str] = final_status

        except Exception as e:
            # print(f"Skipping malformed TEST line: {line} | Error: {e}")
            pass
            
    print(f"Loaded {len(qualification_map)} emoji qualification statuses from emoji-test.txt.")
    return qualification_map

def _define_emoji_property_map() -> dict:
    """
    Returns the property map for parsing emoji-data.txt.
    We will create new DATA_STORES buckets for these.
    """
    # Create new store entries for these properties
    DATA_STORES["Emoji"] = {"ranges": [], "starts": [], "ends": []}
    DATA_STORES["Emoji_Presentation"] = {"ranges": [], "starts": [], "ends": []}
    DATA_STORES["Emoji_Modifier"] = {"ranges": [], "starts": [], "ends": []}
    DATA_STORES["Emoji_Modifier_Base"] = {"ranges": [], "starts": [], "ends": []}
    DATA_STORES["Emoji_Component"] = {"ranges": [], "starts": [], "ends": []}
    DATA_STORES["Extended_Pictographic"] = {"ranges": [], "starts": [], "ends": []}
    
    return {
        "Emoji": "Emoji",
        "Emoji_Presentation": "Emoji_Presentation",
        "Emoji_Modifier": "Emoji_Modifier",
        "Emoji_Modifier_Base": "Emoji_Modifier_Base",
        "Emoji_Component": "Emoji_Component",
        "Extended_Pictographic": "Extended_Pictographic"
    }

def _parse_donotemit(txt: str):
    """
    Parses DoNotEmit.txt for single chars and ranges.
    (Applies 80/20 rule: IGNORES sequences like '0340 0341').
    """
    store_key = "DoNotEmit"
    store = DATA_STORES[store_key]
    store["ranges"].clear()
    store["starts"].clear()
    store["ends"].clear()
    
    ranges_list = []
    for raw in txt.splitlines():
        line = raw.split('#', 1)[0].strip()
        if not line:
            continue
            
        parts = line.split(';', 1)
        if len(parts) < 2:
            continue
            
        code_range = parts[0].strip()
        
        # --- THIS IS THE 80/20 RULE ---
        # If there's a space, it's a sequence. Ignore it.
        if ' ' in code_range:
            continue
        # --- END 80/20 RULE ---
            
        try:
            if '..' in code_range:
                a, b = code_range.split('..', 1)
                ranges_list.append((int(a, 16), int(b, 16), "DoNotEmit"))
            else:
                cp = int(code_range, 16)
                ranges_list.append((cp, cp, "DoNotEmit"))
        except Exception:
            pass # Ignore malformed lines

    ranges_list.sort()
    
    for s, e, v in ranges_list:
        store["ranges"].append((s, e, v))
        store["starts"].append(s)
        store["ends"].append(e)
        
    print(f"Loaded {len(ranges_list)} single-char/range rules for {store_key}.")

def _parse_bidi_mirroring(txt: str):
    """Parses BidiMirroring.txt into a simple dict."""
    store = DATA_STORES["BidiMirroring"]
    store.clear()
    count = 0
    for raw in txt.splitlines():
        line = raw.split('#', 1)[0].strip()
        if not line:
            continue
        
        parts = line.split(';', 1)
        if len(parts) < 2:
            continue
            
        try:
            source_hex = parts[0].strip()
            mirror_hex = parts[1].strip()
            source_cp = int(source_hex, 16)
            mirror_cp = int(mirror_hex, 16)
            store[source_cp] = mirror_cp
            count += 1
        except Exception:
            pass # Ignore malformed lines
            
    print(f"Loaded {count} bidi mirroring pairs.")

def _parse_bidi_brackets(txt: str):
    """Parses BidiBrackets.txt for open/close types."""
    store_key = "BidiBracketType"
    store = DATA_STORES[store_key]
    store["ranges"].clear()
    store["starts"].clear()
    store["ends"].clear()
    
    ranges_list = []
    for raw in txt.splitlines():
        line = raw.split('#', 1)[0].strip()
        if not line:
            continue
        
        parts = line.split(';', 2) # Format is: CP; Type; Mirrored_CP
        if len(parts) < 3:
            continue
            
        code_range = parts[0].strip()
        bracket_type = parts[1].strip() # 'o' (Open) or 'c' (Close)
        
        try:
            # We only care about ranges, not single code points
            if '..' in code_range:
                a, b = code_range.split('..', 1)
                ranges_list.append((int(a, 16), int(b, 16), bracket_type))
            else:
                cp = int(code_range, 16)
                ranges_list.append((cp, cp, bracket_type))
        except Exception:
            pass # Ignore malformed lines

    ranges_list.sort()
    
    for s, e, v in ranges_list:
        store["ranges"].append((s, e, v))
        store["starts"].append(s)
        store["ends"].append(e)
        
    print(f"Loaded {len(ranges_list)} bidi bracket ranges.")

def _parse_composition_exclusions(txt: str):
    """Parses CompositionExclusions.txt."""
    store_key = "CompositionExclusions"
    store = DATA_STORES[store_key]
    store["ranges"].clear()
    store["starts"].clear()
    store["ends"].clear()
    
    ranges_list = []
    for raw in txt.splitlines():
        line = raw.split('#', 1)[0].strip()
        if not line:
            continue
            
        try:
            # The format is just the code point, e.g., "00A0"
            code_range = line.split(None, 1)[0]
            if '..' in code_range:
                a, b = code_range.split('..', 1)
                ranges_list.append((int(a, 16), int(b, 16), "Full_Composition_Exclusion"))
            else:
                cp = int(code_range, 16)
                ranges_list.append((cp, cp, "Full_Composition_Exclusion"))
        except Exception:
            pass # Ignore malformed lines

    ranges_list.sort()
    
    for s, e, v in ranges_list:
        store["ranges"].append((s, e, v))
        store["starts"].append(s)
        store["ends"].append(e)
        
    print(f"Loaded {len(ranges_list)} composition exclusion ranges.")

def _parse_emoji_zwj_sequences(txt: str) -> set:
    """
    Parse emoji-zwj-sequences.txt into a set of ZWJ emoji strings.

    Supports two formats:

    1) Old UTR #51-style (what you actually have now):
       1F441 200D 1F5E8                            # (👁‍🗨) eye, zwj, left speech bubble

    2) Newer TR51-style:
       1F468 200D 2695 FE0F ; RGI_Emoji_ZWJ_Sequence ; man health worker # 👨‍⚕️
    """
    sequences: set[str] = set()

    for raw in txt.splitlines():
        # Strip trailing comment
        before_hash = raw.split('#', 1)[0]
        line = before_hash.strip()
        if not line:
            continue

        try:
            # --- Case A: newer semicolon-based format ---
            if ';' in line:
                parts = [p.strip() for p in line.split(';')]
                if not parts:
                    continue

                hex_codes_str = parts[0]
                type_field = parts[1] if len(parts) > 1 else ""

                hex_codes = hex_codes_str.split()
                # Need at least 2 code points to be a sequence
                if len(hex_codes) <= 1:
                    continue
                # Must contain ZWJ (200D)
                if "200D" not in hex_codes_str:
                    continue

                type_field_lower = type_field.lower()
                # Be tolerant: accept the usual Unicode-style labels
                is_rgi = (
                    "rgi_emoji_zwj_sequence" in type_field_lower
                    or "emoji_zwj_sequence" in type_field_lower
                    or "fully-qualified" in type_field_lower
                )
                if not is_rgi:
                    continue

            # --- Case B: old UTR #51-style (your current file) ---
            else:
                # Entire line is just hex codes
                hex_codes = line.split()
                if len(hex_codes) <= 1:
                    continue
                # Heuristic: Must contain ZWJ (U+200D) to be a ZWJ sequence
                if "200D" not in hex_codes:
                    continue
            
            # Build the actual Unicode string (applies to both cases)
            seq = "".join(chr(int(h, 16)) for h in hex_codes)
            sequences.add(seq)

        except Exception:
            # Ignore malformed lines, don't kill the whole parse
            continue

    print(f"Loaded {len(sequences)} RGI ZWJ sequences.")
    return sequences

def _parse_emoji_sequences(txt: str) -> set:
    """
    Parses emoji-sequences.txt for RGI sequences.
    We ONLY want RGI sequences (Flags, Modifiers, Keycaps), not Basic_Emoji.
    """
    sequences = set()
    rgi_types = {
        "RGI_Emoji_Flag_Sequence",
        "RGI_Emoji_Tag_Sequence",
        "RGI_Emoji_Modifier_Sequence",
        "Emoji_Keycap_Sequence"
    }
    
    for raw in txt.splitlines():
        line = raw.split('#', 1)[0].strip()
        if not line:
            continue
            
        try:
            parts = line.split(';', 2)
            if len(parts) < 2:
                continue
                
            hex_codes_str = parts[0].strip()
            type_field = parts[1].strip()
            
            # We only care about RGI *sequence* types
            if type_field in rgi_types:
                
                # --- THIS IS THE FIX ---
                # Ensure it's a space-delimited sequence
                # AND not a range (which this parser doesn't handle)
                if ' ' in hex_codes_str and '..' not in hex_codes_str:
                    hex_codes = hex_codes_str.split()
                    sequence_str = "".join([chr(int(h, 16)) for h in hex_codes])
                    sequences.add(sequence_str)
                # --- END FIX ---
        except Exception as e:
            # print(f"Skipping malformed SEQ line: {line} | Error: {e}")
            pass # Ignore malformed lines
            
    print(f"Loaded {len(sequences)} RGI non-ZWJ sequences (Flags, Modifiers, etc.).")
    return sequences

def _parse_emoji_variation_sequences(txt: str) -> set:
    """
    Parses emoji-variation-sequences.txt for *emoji-style* (FE0F) sequences.
    Format: 0023 FE0E  ; text style;  ...
            0023 FE0F  ; emoji style; ...
    """
    sequences = set()
    for raw in txt.splitlines():
        line = raw.split('#', 1)[0].strip()
        if not line:
            continue
            
        try:
            parts = line.split(';', 2)
            if len(parts) < 2:
                continue
            
            # We only care about emoji-style sequences
            if "emoji style" in parts[1]:
                hex_codes = parts[0].strip().split()
                if len(hex_codes) == 2: # Should be <base> <FE0F>
                    sequence_str = "".join([chr(int(h, 16)) for h in hex_codes])
                    sequences.add(sequence_str)
        except Exception:
            pass # Ignore malformed lines
            
    print(f"Loaded {len(sequences)} RGI emoji-style variation sequences.")
    return sequences

def _add_manual_data_overrides():
    """
    Manually injects security-related data that isn't in the UCD files.
    This flags broad "compatibility" blocks as "Discouraged" for security analysis.
    """
    print("Adding manual security overrides...")
    store_key = "Discouraged"
    store = DATA_STORES[store_key]
    
    # Ranges defined by Unicode blocks known to be problematic
    # (e.g., CJK Compat, Half/Fullwidth, Presentation Forms)
    discouraged_ranges = [
        (0x2F00, 0x2FDF, "Kangxi Radicals"),
        (0x2FF0, 0x2FFF, "Ideographic Description"),
        (0x31C0, 0x31EF, "CJK Strokes"),
        (0x3200, 0x32FF, "Enclosed CJK Letters and Months"),
        (0x3300, 0x33FF, "CJK Compatibility"),
        (0xF900, 0xFAFF, "CJK Compatibility Ideographs"),
        (0xFB00, 0xFB4F, "Alphabetic Presentation Forms"), # Ligatures
        (0xFB50, 0xFDFF, "Arabic Presentation Forms-A"),
        (0xFE10, 0xFE1F, "Vertical Forms"),
        (0xFE20, 0xFE2F, "Combining Half Marks"),
        (0xFE30, 0xFE4F, "CJK Compatibility Forms"),
        (0xFE50, 0xFE6F, "Small Form Variants"),
        (0xFE70, 0xFEFF, "Arabic Presentation Forms-B"), # Excludes BOM
        (0xFF00, 0xFFEF, "Halfwidth and Fullwidth Forms"),
        (0x1F100, 0x1F1FF, "Enclosed Alphanumeric Supplement"),
        (0x1F200, 0x1F2FF, "Enclosed Ideographic Supplement"),
        (0x2F800, 0x2FA1F, "CJK Compatibility Ideographs Supplement"),
    ]

    ranges_list = []
    for s, e, v in discouraged_ranges:
        ranges_list.append((s, e, v))

    ranges_list.sort()
    
    for s, e, v in ranges_list:
        store["ranges"].append((s, e, v))
        store["starts"].append(s)
        store["ends"].append(e)
    
    print(f"Loaded {len(ranges_list)} manual 'Discouraged' ranges.")

def _find_in_ranges(cp: int, store_key: str):
    """Generic range finder using bisect."""
    import bisect
    store = DATA_STORES[store_key]
    starts_list = store["starts"]
    
    if not starts_list:
        return None
    
    i = bisect.bisect_right(starts_list, cp) - 1
    if i >= 0 and cp <= store["ends"][i]:
        return store["ranges"][i][2] # Return the value
    return None

def _get_char_script_id(char, cp: int):
    """Helper for the RLE engine. Returns a single string ID for a char's script."""
    # 1. Check ScriptExtensions first (for '·', '(', etc.)
    script_ext_val = _find_in_ranges(cp, "ScriptExtensions")
    if script_ext_val:
        # 'Latn Grek' becomes one "state"
        return f"Script-Ext: {script_ext_val}"

    # 2. Fall back to primary Script property (using our new data store)
    script_val = _find_in_ranges(cp, "Scripts")
    if script_val:
        return f"Script: {script_val}"

    return "Script: Unknown"

def _parse_intentional(txt: str):
    """Parses intentional.txt into a set of frozenset pairs."""
    store = DATA_STORES["IntentionalPairs"]
    store.clear()
    count = 0
    for raw in txt.splitlines():
        line = raw.split('#', 1)[0].strip()
        if not line:
            continue
        
        parts = line.split(';', 1)
        if len(parts) < 2:
            continue
            
        try:
            cp1_hex = parts[0].strip()
            cp2_hex_list = parts[1].strip().split() # Can be one or more
            
            cp1 = int(cp1_hex, 16)
            for cp2_hex in cp2_hex_list:
                cp2 = int(cp2_hex, 16)
                # Store as a frozenset so {A, B} is the same as {B, A}
                pair = frozenset([cp1, cp2])
                store.add(pair)
                count += 1
        except Exception:
            pass # Ignore malformed lines
    print(f"Loaded {count} intentional pairs.")
    # Convert to frozenset for immutability after loading
    DATA_STORES["IntentionalPairs"] = frozenset(store)

async def load_unicode_data():
    """Fetches, parses, and then triggers a UI update."""
    global LOADING_STATE
    
    async def fetch_file(filename):
        try:
            # Use "./" prefix for all files (no subdirectories)
            response = await pyfetch(f"./{filename}")
            if response.ok:
                return await response.string()
            else:
                print(f"Failed to load {filename}: {response.status}")
                return None
        except Exception as e:
            print(f"Error loading {filename}: {e}")
            return None

    LOADING_STATE = "LOADING"
    render_status(f"Loading Unicode data files...")
    print("Unicode data loading started.")
    
    try:
        # --- MODIFIED (Feature 2 Expanded) ---
        files_to_fetch = [
            "Blocks.txt", "DerivedAge.txt", "IdentifierType.txt", "IdentifierStatus.txt", "intentional.txt",
            "confusables.txt", "StandardizedVariants.txt", "ScriptExtensions.txt", 
            "LineBreak.txt", "PropList.txt", "DerivedCoreProperties.txt",
            "Scripts.txt",
            "emoji-variation-sequences.txt",
            "WordBreakProperty.txt",
            "SentenceBreakProperty.txt",
            "GraphemeBreakProperty.txt",
            "DoNotEmit.txt",
            "DerivedCombiningClass.txt",
            "DerivedDecompositionType.txt",
            "DerivedBinaryProperties.txt",
            "DerivedNumericType.txt",
            "EastAsianWidth.txt",
            "VerticalOrientation.txt",
            "BidiBrackets.txt",
            "BidiMirroring.txt",
            "DerivedNormalizationProps.txt",
            "CompositionExclusions.txt",
            "emoji-sequences.txt",
            "emoji-zwj-sequences.txt",
            "emoji-data.txt",
            "emoji-test.txt"
        ]
        results = await asyncio.gather(*[fetch_file(f) for f in files_to_fetch])
    
        # --- MODIFIED (Feature 2 Expanded) ---
        (blocks_txt, age_txt, id_type_txt, id_status_txt, intentional_txt, confusables_txt, variants_txt, 
         script_ext_txt, linebreak_txt, proplist_txt, derivedcore_txt, 
         scripts_txt, emoji_variants_txt, word_break_txt, 
         sentence_break_txt, grapheme_break_txt, donotemit_txt, ccc_txt, 
         decomp_type_txt, derived_binary_txt, num_type_txt, 
         ea_width_txt, vert_orient_txt, bidi_brackets_txt,
         bidi_mirroring_txt, norm_props_txt, comp_ex_txt, emoji_seq_txt, emoji_zwj_seq_txt, emoji_data_txt, emoji_test_txt) = results
    
        # Parse each file
        if blocks_txt: _parse_and_store_ranges(blocks_txt, "Blocks")
        if age_txt: _parse_and_store_ranges(age_txt, "Age")
        if id_type_txt: _parse_and_store_ranges(id_type_txt, "IdentifierType")
        if id_status_txt: _parse_and_store_ranges(id_status_txt, "IdentifierStatus")
        if intentional_txt: _parse_intentional(intentional_txt)
        if confusables_txt: _parse_confusables(confusables_txt)
        
        # --- Feature 1 Logic (FROZENSET Fix, Reversed) ---
        std_base_set = set()
        std_selector_set = set()
        emoji_base_set = set()
        
        if variants_txt: 
            std_base_set, std_selector_set = _parse_standardized_variants(variants_txt)
        else:
            print("--- WARNING: StandardizedVariants.txt SKIPPED (file was empty or failed to load)")
            
        if emoji_variants_txt: 
            emoji_base_set = _parse_emoji_variants(emoji_variants_txt)
        else:
            print("--- WARNING: emoji-variation-sequences.txt SKIPPED (file was empty or failed to load)")
        
        # 1. Create a new, temporary combined set, starting with the emoji set
        combined_base_set = emoji_base_set.union(std_base_set)
        
        # 2. Store it as an IMMUTABLE frozenset
        DATA_STORES["VariantBase"] = frozenset(combined_base_set)
        DATA_STORES["VariantSelectors"] = frozenset(std_selector_set) # Make this one immutable too
        
        print(f"--- DIAGNOSTIC: Final combined 'VariantBase' frozenset size: {len(DATA_STORES['VariantBase'])}")
        # --- End Feature 1 Logic ---

        # --- NEW (Phase 1: Emoji Bugfix - Optimized) ---
        # Build the RGI Sequence Set from Tiers 1-3
        set_zwj = set()
        set_non_zwj = set()
        set_variations = set()
        
        if emoji_zwj_seq_txt:
            set_zwj = _parse_emoji_zwj_sequences(emoji_zwj_seq_txt)
        
        if emoji_seq_txt:
            set_non_zwj = _parse_emoji_sequences(emoji_seq_txt)
            
        if emoji_variants_txt:
            # We re-use the file we already loaded for variants
            set_variations = _parse_emoji_variation_sequences(emoji_variants_txt)
            
        # Combine all sequences into one master set
        combined_rgi_sequences = set_zwj.union(set_non_zwj).union(set_variations)
        
        # --- THIS IS THE OPTIMIZATION ---
        # Store as a set (fast membership) + max length (for sliding window)
        DATA_STORES["RGISequenceSet"] = combined_rgi_sequences
        DATA_STORES["RGISequenceMaxLen"] = max((len(s) for s in combined_rgi_sequences), default=0)
        # --- END OPTIMIZATION ---
        
        # Store the sorted list (optional, but good for debugging)
        DATA_STORES["RGISequenceList"] = sorted(
            list(combined_rgi_sequences),
            key=len,
            reverse=True
        )
        
        print(
            f"--- Emoji Engine: Created RGISequenceSet with "
            f"{len(DATA_STORES['RGISequenceSet'])} total sequences; "
            f"max length = {DATA_STORES['RGISequenceMaxLen']}."
        )
        # --- END (Phase 1: Emoji Bugfix) ---

        # --- NEW (Phase 2: Emoji Powerhouse) ---
        # Load single-char properties from emoji-data.txt
        if emoji_data_txt:
            emoji_prop_map = _define_emoji_property_map()
            _parse_property_file(emoji_data_txt, emoji_prop_map)
        
        # Load qualification status for sequences
        if emoji_test_txt:
            DATA_STORES["EmojiQualificationMap"] = _parse_emoji_test(emoji_test_txt)
        else:
            DATA_STORES["EmojiQualificationMap"] = {}
        # --- END (Phase 2: Emoji Powerhouse) ---
        
        if script_ext_txt: _parse_script_extensions(script_ext_txt)
        if linebreak_txt: _parse_and_store_ranges(linebreak_txt, "LineBreak")
        if scripts_txt: _parse_and_store_ranges(scripts_txt, "Scripts")
        
        # --- NEW (Feature 2 Expanded) ---
        if word_break_txt: _parse_and_store_ranges(word_break_txt, "WordBreak")
        if sentence_break_txt: _parse_and_store_ranges(sentence_break_txt, "SentenceBreak")
        if grapheme_break_txt: _parse_and_store_ranges(grapheme_break_txt, "GraphemeBreak")

        # --- NEW (Feature 3) ---
        if donotemit_txt: _parse_donotemit(donotemit_txt)

        # New ones
        if ccc_txt: _parse_and_store_ranges(ccc_txt, "CombiningClass")
        if decomp_type_txt: _parse_and_store_ranges(decomp_type_txt, "DecompositionType")
        if num_type_txt: _parse_and_store_ranges(num_type_txt, "NumericType")

        if ea_width_txt: _parse_and_store_ranges(ea_width_txt, "EastAsianWidth")
        if vert_orient_txt: _parse_and_store_ranges(vert_orient_txt, "VerticalOrientation")
        if bidi_brackets_txt: _parse_bidi_brackets(bidi_brackets_txt)
        if bidi_mirroring_txt: _parse_bidi_mirroring(bidi_mirroring_txt)
        if comp_ex_txt: _parse_composition_exclusions(comp_ex_txt)
        
        # Use the multi-property parser for DerivedBinaryProperties.txt
        if derived_binary_txt:
            _parse_property_file(derived_binary_txt, {
                "Bidi_Mirrored": "BidiMirrored",
                "Logical_Order_Exception": "LogicalOrderException"
                # We can add more properties here later
            })

        # Parse DerivedNormalizationProps.txt
        if norm_props_txt:
            _parse_property_file(norm_props_txt, {
                "Changes_When_NFKC_Casefolded": "ChangesWhenNFKCCasefolded"
                # This file also contains Changes_When_Casemapped, etc.
                # We can add more properties here later as needed.
            })
        
        if proplist_txt:
            _parse_property_file(proplist_txt, {
                "Bidi_Control": "BidiControl",
                "Join_Control": "JoinControl",
                "Extender": "Extender",
                "White_Space": "WhiteSpace",
                "Deprecated": "Deprecated",
                "Dash": "Dash",
                "Quotation_Mark": "QuotationMark",
                "Terminal_Punctuation": "TerminalPunctuation",
                "Sentence_Terminal": "SentenceTerminal",
                "Variation_Selector": "VariationSelector",
                "Bidi_Mirrored": "BidiMirrored"
            })
        if derivedcore_txt:
            _parse_property_file(derivedcore_txt, {
                "Other_Default_Ignorable_Code_Point": "OtherDefaultIgnorable",
                "Alphabetic": "Alphabetic", "Logical_Order_Exception": "LogicalOrderException"
            })
        # --- Add Manual Security Overrides ---
        _add_manual_data_overrides()    
        
        LOADING_STATE = "READY"
        print("Unicode data loaded successfully.")
        render_status("Ready.")
        update_all() # Re-render with ready state
        
    except Exception as e:
        LOADING_STATE = "FAILED"
        print(f"CRITICAL: Unicode data loading failed. Error: {e}")
        render_status("Error: Failed to load Unicode data. Please refresh.", is_error=True)

def compute_emoji_analysis(text: str) -> dict:
    """
    Scans the text and returns a full report on RGI sequences,
    single-character emoji, and qualification status.

    This is a robust, multi-tier scanner:
    - Tiers 1-3: Greedy RGI ZWJ/Flag/Modifier sequence scan.
    - Tier 4: Single-character scan, which correctly handles:
        - Forced Text Presentation (e.g., ❤️︎)
        - RGI Singles (e.g., 😀)
        - Qualification Status (Fully, Minimally, Unqualified, Component)
        - Anomalies (e.g., lone IVS)
    """
    # --- 1. Get Data Stores ---
    rgi_set = DATA_STORES.get("RGISequenceSet", set())
    max_len = DATA_STORES.get("RGISequenceMaxLen", 0)
    qual_map = DATA_STORES.get("EmojiQualificationMap", {})
    
    # --- 2. Initialize Accumulators ---
    rgi_sequences_count = 0
    rgi_singles_count = 0
    
    # For the V2 "Emoji Qualification Profile" table
    emoji_details_list = []

    # For the T3 "Structural Integrity" flags
    flag_unqualified = []
    flag_minimally_qualified = []
    flag_component = []
    flag_forced_text = []
    flag_fully_qualified = []
    flag_illegal_modifier = []
    flag_illformed_tag = []
    flag_invalid_ri = []
    flag_broken_keycap = []
    flag_forced_emoji = []
    flag_intent_mod_zwj = [] # <-- ADDED FOR V2
    
    # --- 3. Start Scan Loop ---
    js_array = window.Array.from_(text)
    n = len(js_array)
    i = 0
    
    # --- NEW: Create a "consumed" set ---
    # We must mark indices as "consumed" so the RGI scanner
    # doesn't re-process parts of an intent-modifying sequence.
    consumed_indices = set()

    # --- NEW: Tier 0 - Intent-Modifying ZWJ Scan ---
    if INTENT_MODIFYING_MAX_LEN > 1:
        # Note: We loop to n-1 because we need at least 2 chars
        for k in range(n - 1):
            if k in consumed_indices: continue
            
            max_window = min(INTENT_MODIFYING_MAX_LEN, n - k)
            # We need L > 1 for sequences
            for L in range(max_window, 1, -1):
                candidate = "".join(js_array[k : k + L])
                if candidate in INTENT_MODIFYING_ZWJ_SET:
                    flag_intent_mod_zwj.append(f"#{k}")
                    
                    # Mark all indices in this sequence as consumed
                    for j in range(k, k + L):
                        consumed_indices.add(j)
                    
                    # Add to V2 details list (optional)
                    emoji_details_list.append({
                        "sequence": candidate,
                        "status": "Intent-Modifying",
                        "index": k
                    })
                    break # Stop inner (L) loop
    
    # --- Main Loop ---
    while i < n:
        # --- NEW: Skip consumed indices ---
        if i in consumed_indices:
            i += 1
            continue
            
        matched_sequence = False
        
        # --- Tiers 1-3: Greedy RGI Sequence Scan (e.g., 👨‍👩‍👧‍👦, 👍🏾, 🇺🇦) ---
        if max_len > 1:
            max_window = min(max_len, n - i)
            for L in range(max_window, 1, -1): # From max_len down to 2
                candidate_chars = js_array[i : i + L]
                candidate = "".join(candidate_chars)
                
                if candidate in rgi_set:
                    matched_sequence = True
                    rgi_sequences_count += 1
                    
                    # Get status (default to FQ for RGI sequences not in test file)
                    status = qual_map.get(candidate, "fully-qualified")

                    # Add to V2 details list
                    emoji_details_list.append({
                        "sequence": candidate,
                        "status": status,
                        "index": i
                    })
                    
                    # Add to T3 flag lists
                    if status == "unqualified":
                        flag_unqualified.append(f"#{i}")
                    elif status == "minimally-qualified":
                        flag_minimally_qualified.append(f"#{i}")
                    elif status == "component":
                        flag_component.append(f"#{i}")
                    elif status == "fully-qualified":
                        flag_fully_qualified.append(f"#{i}")
                        # --- Check for Forced-Emoji Presentation (e.g., © + FE0F) ---
                        # candidate_chars is the JS array of chars in the sequence
                        if L == 2 and ord(candidate_chars[1]) == 0xFE0F:
                            base_cp = ord(candidate_chars[0])
                            # If the base char is NOT default-emoji, this is a "forced-emoji" flag
                            if not _find_in_ranges(base_cp, "Emoji_Presentation"):
                                flag_forced_emoji.append(f"#{i}")
                        # --- End Check ---
                    i += L  # Consume the entire sequence
                    break # Exit the `for L` loop

        # --- Tier 4: Single Character Scan (if no sequence was found) ---
        if not matched_sequence:
            char = js_array[i]
            cp = ord(char)
            consumed = 1 # Default to consuming 1 char
            final_status = "unknown" # Default status
        
            # This surgically adds the lone ZWJ to the emoji table
            #if cp == 0x200D:
            #    emoji_details_list.append({
            #        "sequence": char,
            #        "status": "component", # Manually assign status
            #        "index": i,
            #    })
            #    i += 1
            #    continue # Skip all other Tier 4 logic for this char
            
            # --- A: Check for Forced Text (VS15) ---
            # This is a 2-char sequence that isn't in the RGI set.
            if i + 1 < n and ord(js_array[i+1]) == 0xFE0E: # Text Selector
                if _find_in_ranges(cp, "Emoji"): # Base is an emoji
                    # 1. Add to the main "Forced Text" flag
                    flag_forced_text.append(f"#{i}")
                    
                    # 2. Set the status and consume *both* chars
                    consumed = 2
                    final_status = "forced-text" # Give it a special status
                    
                    # 3. Also add this sequence to the V2 details list
                    # (This was the missing piece of logic)
                    sequence_str = char + js_array[i+1]
                    emoji_details_list.append({
                        "sequence": sequence_str,
                        "status": final_status,
                        "index": i
                    })
            
            # --- B: If not Forced Text, analyze the single char ---
            if final_status == "unknown":
                final_status = qual_map.get(char, "unknown")
                is_rgi_single = _find_in_ranges(cp, "Emoji_Presentation")
                is_ivs = 0xE0100 <= cp <= 0xE01EF # Steganography
                is_modifier = _find_in_ranges(cp, "Emoji_Modifier")
                is_ri = window.RegExp.new(r"^\p{Regional_Indicator}$", "u").test(char)

                if is_ri:
                    # This char is a Regional_Indicator but was NOT part of a valid
                    # RGI sequence, making it an anomaly.
                    flag_invalid_ri.append(f"#{i}")
                    if final_status == "unknown": final_status = "component"
                # 3. Check for broken keycap sequence
                elif cp == 0x20E3: # Combining Enclosing Keycap
                    is_valid_attachment = False
                    if i > 0:
                        prev_cp = ord(js_array[i-1])
                        if prev_cp in VALID_KEYCAP_BASES:
                            is_valid_attachment = True
                    
                    if not is_valid_attachment:
                        flag_broken_keycap.append(f"#{i}")
                    if final_status == "unknown": final_status = "component"

           # --- NEW: Parallel checks for new flags ---
                # We run these checks *separately* from the is_rgi_single logic
                
            # 1. Check for illegal modifier attachment
            if is_modifier:
                is_valid_attachment = False
                if i > 0:
                    prev_cp = ord(js_array[i-1])
                    if _find_in_ranges(prev_cp, "Emoji_Modifier_Base"):
                        is_valid_attachment = True
                
                if not is_valid_attachment:
                    flag_illegal_modifier.append(f"#{i}")
                    if final_status == "unknown": final_status = "component"
                        
            # 2. Check for ill-formed tag sequence
            elif cp == 0x1F3F4: # 🏴 (Black Flag)
                j = i + 1
                # Check if there is at least one tag modifier following
                if j < n and (0xE0020 <= ord(js_array[j]) <= 0xE007E):
                    k = j
                    # Scan forward to find the end of the tag modifiers
                    while k < n and (0xE0020 <= ord(js_array[k]) <= 0xE007E):
                        k += 1
                    
                    # Now, check what terminated the loop
                    # It's ill-formed if it's out of bounds OR not a CANCEL tag
                    if k == n or ord(js_array[k]) != 0xE007F:
                        flag_illformed_tag.append(f"#{i}")
                        # Consume the entire bad sequence (🏴 + modifiers)
                        consumed = k - i 
                        final_status = "ill-formed-tag"
                        
                        # Also add this to the emoji list as a component
                        sequence_str = "".join(js_array[i:k])
                        emoji_details_list.append({
                            "sequence": sequence_str,
                            "status": "component",
                            "index": i
                        })

            if is_rgi_single:
                rgi_singles_count += 1
                if final_status == "unknown": # Upgrade status
                    final_status = "fully-qualified"
            
            if is_ivs:
                # Treat lone IVS as a "component"
                if final_status == "unknown":
                    final_status = "component"
                # Add to flag list (even if it's also in qual_map)
                if f"#{i}" not in flag_component:
                    flag_component.append(f"#{i}")

            # Add to V2 details list
            if final_status in {"fully-qualified", "minimally-qualified", "unqualified", "component"}:
                emoji_details_list.append({
                    "sequence": char,
                    "status": final_status,
                    "index": i
                })
            
            # Add to T3 flag lists
            if final_status == "unqualified":
                flag_unqualified.append(f"#{i}")
            elif final_status == "minimally-qualified":
                flag_minimally_qualified.append(f"#{i}")
            elif final_status == "component" and not is_ivs: # (IVS is already added)
                flag_component.append(f"#{i}")
            elif final_status == "fully-qualified":
                flag_fully_qualified.append(f"#{i}")

            # Advance the loop
            i += consumed

    # --- 4. Return the Full Report ---
    return {
        "counts": {
            "RGI Emoji Sequences": rgi_sequences_count + rgi_singles_count,
        },
        "flags": {
            "Flag: Unqualified Emoji": {'count': len(flag_unqualified), 'positions': flag_unqualified},
            "Flag: Minimally-Qualified Emoji": {'count': len(flag_minimally_qualified), 'positions': flag_minimally_qualified},
            "Flag: Standalone Emoji Component": {'count': len(flag_component), 'positions': flag_component},
            "Flag: Forced Text Presentation": {'count': len(flag_forced_text), 'positions': flag_forced_text},
            "Prop: Fully-Qualified Emoji": {'count': len(flag_fully_qualified), 'positions': flag_fully_qualified},
            "Flag: Illegal Emoji Modifier": {'count': len(flag_illegal_modifier), 'positions': flag_illegal_modifier},
            "Flag: Ill-formed Tag Sequence": {'count': len(flag_illformed_tag), 'positions': flag_illformed_tag},
            "Flag: Invalid Regional Indicator": {'count': len(flag_invalid_ri), 'positions': flag_invalid_ri},
            "Flag: Broken Keycap Sequence": {'count': len(flag_broken_keycap), 'positions': flag_broken_keycap},
            "Flag: Forced Emoji Presentation": {'count': len(flag_forced_emoji), 'positions': flag_forced_emoji},
            "Flag: Intent-Modifying ZWJ": {'count': len(flag_intent_mod_zwj), 'positions': flag_intent_mod_zwj}
        },
        "emoji_list": emoji_details_list
    }

def _parse_script_extensions(txt: str):
    """Custom parser for ScriptExtensions.txt (which uses ';')."""
    store_key = "ScriptExtensions"
    store = DATA_STORES[store_key]
    store["ranges"].clear()
    store["starts"].clear()
    store["ends"].clear()

    ranges_list = []
    for raw in txt.splitlines():
        # 1. Remove comments
        line = raw.split('#', 1)[0]
        # 2. Find the semicolon
        parts = line.split(';', 1)

        if len(parts) < 2:
            continue # Not a data line

        code_range = parts[0].strip()
        value = parts[1].strip()

        if not value or not code_range:
            continue

        if '..' in code_range:
            a, b = code_range.split('..', 1)
            ranges_list.append((int(a, 16), int(b, 16), value))
        else:
            cp = int(code_range, 16)
            ranges_list.append((cp, cp, value))

    ranges_list.sort()

    for s, e, v in ranges_list:
        store["ranges"].append((s, e, v))
        store["starts"].append(s)
        store["ends"].append(e)

    print(f"Loaded {len(ranges_list)} ranges for {store_key}.")

def _parse_property_file(txt: str, property_map: dict):
    """
    Generic parser for property files like PropList.txt.
    It iterates a file once and sorts properties into *multiple* DATA_STORES buckets based on the property_map.
    
    property_map = {"FilePropertyName": "DataStoreKey"}
    """
    # A temp dict to hold lists of ranges before sorting
    temp_ranges = {store_key: [] for store_key in property_map.values()}
    
    for raw in txt.splitlines():
        line = raw.split('#', 1)[0].strip()
        if not line: continue
        
        parts = line.split(';', 1)
        if len(parts) < 2: continue
        
        code_range, prop_name = parts[0].strip(), parts[1].strip()
        
        # Check if this is one of the properties we're looking for
        if prop_name in property_map:
            store_key = property_map[prop_name]
            
            try:
                if '..' in code_range:
                    a, b = code_range.split('..', 1)
                    temp_ranges[store_key].append((int(a, 16), int(b, 16), prop_name))
                else:
                    cp = int(code_range, 16)
                    temp_ranges[store_key].append((cp, cp, prop_name))
            except Exception:
                pass # Ignore malformed lines
    
    # Now, populate the real DATA_STORES
    for store_key, ranges_list in temp_ranges.items():
        if not ranges_list: continue
        
        store = DATA_STORES[store_key]
        store["ranges"].clear()
        store["starts"].clear()
        store["ends"].clear()
        
        ranges_list.sort()
        
        for s, e, v in ranges_list:
            store["ranges"].append((s, e, v))
            store["starts"].append(s)
            store["ends"].append(e)
        
        print(f"Loaded {len(ranges_list)} ranges for {store_key} from property file.")

# ---
# 3. COMPUTATION FUNCTIONS
# ---

def _find_matches_with_indices(regex_key: str, text: str):
    """Uses matchAll to find all matches and their indices."""
    regex = REGEX_MATCHER.get(regex_key)
    if not regex:
        return [], 0
    
    try:
        matches_iter = window.String.prototype.matchAll.call(text, regex)
        matches = window.Array.from_(matches_iter)
        # Use segmenter-aware indices for \p{RGI_Emoji}
        if regex_key == "RGI Emoji":
            indices = [m.index for m in matches]
        else:
            # For code-point based regex, we must use JS-style indices
            indices = [m.index for m in matches]
        return indices, len(indices)
    except Exception as e:
        print(f"Error in _find_matches_with_indices for {regex_key}: {e}")
        return [], 0

# Note the new argument: emoji_counts
def compute_code_point_stats(t: str, emoji_counts: dict):
    """Module 1 (Code Point): Runs the 3-Tier analysis."""

# 1. Get derived stats (from full string)
    code_points_array = window.Array.from_(t)
    total_code_points = len(code_points_array)
    # This is robust and avoids all formatting/JS bridge errors.
    epsilon = 1e-9 # Avoid division by zero on empty string
    
    # 1. Initialize counters
    ascii_count = 0
    latin1_count = 0
    bmp_count = 0
    supplementary_count = 0
    
    # 2. Iterate and count in a single pass
    for char in t:
        cp = ord(char)
        if cp <= 0x7F:
            ascii_count += 1
        if cp <= 0xFF:
            latin1_count += 1
        if cp <= 0xFFFF:
            bmp_count += 1
        else:
            supplementary_count += 1
            
    # 3. Build the repertoire stats dictionary
    repertoire_stats = {
        "ASCII-Compatible": {
            "count": ascii_count,
            "pct": round((ascii_count / (total_code_points + epsilon)) * 100, 2),
            "is_full": ascii_count == total_code_points and total_code_points > 0
        },
        "Latin-1-Compatible": {
            "count": latin1_count,
            "pct": round((latin1_count / (total_code_points + epsilon)) * 100, 2),
            "is_full": latin1_count == total_code_points and total_code_points > 0
        },
        "BMP Coverage": {
            "count": bmp_count,
            "pct": round((bmp_count / (total_code_points + epsilon)) * 100, 2),
            "is_full": supplementary_count == 0 and total_code_points > 0
        },
        "Supplementary Planes": {
            "count": supplementary_count,
            "pct": round((supplementary_count / (total_code_points + epsilon)) * 100, 2),
            "is_full": False # This badge doesn't make sense here
        }
    }
   # We get the count directly from the emoji engine's report
    emoji_total_count = emoji_counts.get("RGI Emoji Sequences", 0)
    
    _, whitespace_count = _find_matches_with_indices("Whitespace", t)
    
    derived_stats = {
        "Total Code Points": total_code_points,
        "RGI Emoji Sequences": emoji_total_count,
        "Whitespace (Total)": whitespace_count
    }

    # 2. Get 29 minor categories (Honest Mode)
    # --- THIS IS THE FIX ---
    # We now use our proven-correct helper function for all 29 categories.
    minor_stats = {}
    sum_of_29_cats = 0
    for key in MINOR_CATEGORIES_29.keys():
        _, count = _find_matches_with_indices(key, t)
        minor_stats[key] = count
        sum_of_29_cats += count
    # --- END OF FIX ---

    # 3. Calculate 'Cn' as the remainder
    minor_stats["Cn"] = total_code_points - sum_of_29_cats

    # 4. Aggregate Major Categories
    major_stats = {
        "L (Letter)": minor_stats.get("Lu", 0) + minor_stats.get("Ll", 0) + minor_stats.get("Lt", 0) + minor_stats.get("Lm", 0) + minor_stats.get("Lo", 0),
        "M (Mark)": minor_stats.get("Mn", 0) + minor_stats.get("Mc", 0) + minor_stats.get("Me", 0),
        "N (Number)": minor_stats.get("Nd", 0) + minor_stats.get("Nl", 0) + minor_stats.get("No", 0),
        "P (Punctuation)": minor_stats.get("Pc", 0) + minor_stats.get("Pd", 0) + minor_stats.get("Ps", 0) + minor_stats.get("Pe", 0) + minor_stats.get("Pi", 0) + minor_stats.get("Pf", 0) + minor_stats.get("Po", 0),
        "S (Symbol)": minor_stats.get("Sm", 0) + minor_stats.get("Sc", 0) + minor_stats.get("Sk", 0) + minor_stats.get("So", 0),
        "Z (Separator)": minor_stats.get("Zs", 0) + minor_stats.get("Zl", 0) + minor_stats.get("Zp", 0),
        "C (Other)": minor_stats.get("Cc", 0) + minor_stats.get("Cf", 0) + minor_stats.get("Cs", 0) + minor_stats.get("Co", 0) + minor_stats.get("Cn", 0)
    }

    # 5. Build Summary (for Meta-Analysis cards)
    summary_stats = {
        **derived_stats,
        **repertoire_stats,
        "L (Letter)": major_stats["L (Letter)"],
        "N (Number)": major_stats["N (Number)"],
        "P (Punctuation)": major_stats["P (Punctuation)"],
        "S (Symbol)": major_stats["S (Symbol)"]
    }

    return summary_stats, major_stats, minor_stats

def compute_grapheme_stats(t: str):
    """Module 1 (Grapheme): Runs analysis on Grapheme Clusters."""
    
    segments_iterable = GRAPHEME_SEGMENTER.segment(t)
    segments = window.Array.from_(segments_iterable)
    total_graphemes = len(segments)

    minor_stats = {key: 0 for key in MINOR_CATEGORIES_29}
    minor_stats["Cn"] = 0 # Initialize Cn
    
    # Module 1.5 Grapheme Forensic stats
    single_cp_count = 0
    multi_cp_count = 0
    total_mark_count = 0
    max_marks = 0

    for segment in segments:
        grapheme_str = segment.segment
        if not grapheme_str:
            continue
        
        # --- Module 1.5 Logic (Forensics) ---
        cp_array = window.Array.from_(grapheme_str)
        cp_count = len(cp_array)
        
        if cp_count == 1:
            single_cp_count += 1
        elif cp_count > 1:
            multi_cp_count += 1
        
        _, mark_count = _find_matches_with_indices("Marks", grapheme_str)
        total_mark_count += mark_count
        if mark_count > max_marks:
            max_marks = mark_count

        # --- Module 1 Logic (Classification) ---
        first_char = cp_array[0]
        
        classified = False
        for key, regex in TEST_MINOR.items():
            if regex.test(first_char):
                minor_stats[key] += 1
                classified = True
                break
        
        if not classified:
            # Test for Cn explicitly
            if window.RegExp.new(r"^\p{Cn}$", "u").test(first_char):
                 minor_stats["Cn"] += 1

    # Aggregate Major Categories
    major_stats = {
        "L (Letter)": minor_stats["Lu"] + minor_stats["Ll"] + minor_stats["Lt"] + minor_stats["Lm"] + minor_stats["Lo"],
        "M (Mark)": minor_stats["Mn"] + minor_stats["Mc"] + minor_stats["Me"],
        "N (Number)": minor_stats["Nd"] + minor_stats["Nl"] + minor_stats["No"],
        "P (Punctuation)": minor_stats["Pc"] + minor_stats["Pd"] + minor_stats["Ps"] + minor_stats["Pe"] + minor_stats["Pi"] + minor_stats["Pf"] + minor_stats["Po"],
        "S (Symbol)": minor_stats["Sm"] + minor_stats["Sc"] + minor_stats["Sk"] + minor_stats["So"],
        "Z (Separator)": minor_stats["Zs"] + minor_stats["Zl"] + minor_stats["Zp"],
        "C (Other)": minor_stats["Cc"] + minor_stats["Cf"] + minor_stats["Cs"] + minor_stats["Co"] + minor_stats["Cn"]
    }

    # Build Summary (for Meta-Analysis cards)
    summary_stats = {"Total Graphemes": total_graphemes}
    
    # Build Grapheme Forensics (Module 1.5)
    avg_marks = (total_mark_count / total_graphemes) if total_graphemes > 0 else 0
    grapheme_forensic_stats = {
        "Single-Code-Point": single_cp_count,
        "Multi-Code-Point": multi_cp_count,
        "Total Combining Marks": total_mark_count,
        "Max Marks in one Grapheme": max_marks,
        "Avg. Marks per Grapheme": round(avg_marks, 2)
    }

    return summary_stats, major_stats, minor_stats, grapheme_forensic_stats

def compute_combining_class_stats(t: str):
    """Module 1.C: Runs Combining Class Profile."""
    counters = {}
    if not t or LOADING_STATE != "READY":
        return counters

    for char in t:
        cp = ord(char)
        ccc_class = _find_in_ranges(cp, "CombiningClass")
        
        # We only care about combining marks (class 0 is "Spacing")
        if ccc_class and ccc_class != "0":
            key = f"ccc={ccc_class}"
            counters[key] = counters.get(key, 0) + 1
            
    return counters

def compute_sequence_stats(t: str):
    """Module 2.B: Runs the Token Shape Analysis (Major Categories only)."""
    counters = {key: 0 for key in TEST_MAJOR}
    if not t:
        return counters

    current_state = "NONE"
    for char in t:
        new_state = "NONE"
        for key, regex in TEST_MAJOR.items():
            if regex.test(char):
                new_state = key
                break
        
        if new_state != current_state:
            if current_state in counters:
                counters[current_state] += 1
            current_state = new_state
            
    if current_state in counters:
        counters[current_state] += 1
        
    return counters

def compute_minor_sequence_stats(t: str):
    """Module 2.B-Minor: Runs the Token Shape Analysis (Minor Categories)."""
    counters = {key: 0 for key in TEST_MINOR}
    if not t:
        return counters

    current_state = "NONE"
    
    # We must use the 30 Minor Category testers
    category_testers = TEST_MINOR 
    
    for char in t:
        new_state = "NONE"
        for key, regex in category_testers.items():
            if regex.test(char):
                new_state = key
                break
        
        # If the char is Cn, it won't match TEST_MINOR (which has 29)
        # We must test for it separately.
        if new_state == "NONE":
             # We use the full \p{Cn} test
             if window.RegExp.new(r"^\p{Cn}$", "u").test(char):
                 new_state = "Cn"
                 if "Cn" not in counters:
                     counters["Cn"] = 0 # Ensure Cn is in the dict
        
        if new_state != current_state:
            if current_state in counters:
                counters[current_state] += 1
            current_state = new_state
            
    if current_state in counters:
        counters[current_state] += 1
        
    return counters

def compute_linebreak_analysis(t: str):
    """Module 2.B-LineBreak: Runs Token Shape Analysis (UAX #14)."""
    counters = {}
    if not t or LOADING_STATE != "READY":
        return counters

    current_state = "NONE"
    
    # --- START: CORRECT RLE LOGIC ---
    for char in t:
        cp = ord(char)
        lb_class = _find_in_ranges(cp, "LineBreak")
        new_state = lb_class if lb_class else "XX"
        
        if new_state != current_state:
            if current_state != "NONE": # Don't count the initial "NONE"
                if current_state in counters:
                    counters[current_state] += 1
                else:
                    counters[current_state] = 1
            current_state = new_state
    
    # Add the final run
    if current_state != "NONE":
        if current_state in counters:
            counters[current_state] += 1
        else:
            counters[current_state] = 1
    # --- END: CORRECT RLE LOGIC ---
            
    return counters

def compute_bidi_class_analysis(t: str):
    """Module 2.B-BidiClass: Runs Token Shape Analysis (UAX #9)."""
    counters = {}
    if not t:
        return counters

    current_state = "NONE"
    
    # --- START: CORRECT RLE LOGIC ---
    js_array = window.Array.from_(t)
    for char in js_array:
        try:
            new_state = unicodedata.bidirectional(char)
            if not new_state: # If the class is an empty string
                new_state = "Unknown" # Assign a default label
        except Exception as e:
            print(f"Bidi class error: {e}")
            new_state = "XX" # Failsafe
        
        if new_state != current_state:
            if current_state != "NONE":
                if current_state in counters:
                    counters[current_state] += 1
                else:
                    counters[current_state] = 1
            current_state = new_state
    
    # Add the final run
    if current_state != "NONE":
        if current_state in counters:
            counters[current_state] += 1
        else:
            counters[current_state] = 1
    # --- END: CORRECT RLE LOGIC ---
            
    return counters

def compute_script_run_analysis(t: str):
    """Module 2.D-Script: Runs Token Shape Analysis (Script Properties) (with positions)."""
    final_stats = {}
    if not t or LOADING_STATE != "READY":
        return final_stats

    current_state = "NONE"
    current_run_start_index = 0

    # Helper to add a completed run to the stats
    def _add_run(state, start_index):
        if state == "NONE": return
        if state not in final_stats:
            final_stats[state] = {'count': 0, 'positions': []}
        final_stats[state]['count'] += 1
        final_stats[state]['positions'].append(f"#{start_index}")

    js_array = window.Array.from_(t)
    for i, char in enumerate(js_array):
        try:
            cp = ord(char)
            new_state = _get_char_script_id(char, cp)
        except Exception:
            new_state = "Script: Unknown" # Failsafe
        
        if new_state != current_state:
            # End the previous run
            _add_run(current_state, current_run_start_index)
            # Start the new run
            current_state = new_state
            current_run_start_index = i
    
    # Add the final run
    _add_run(current_state, current_run_start_index)
    
    return final_stats

def compute_wordbreak_analysis(t: str):
    """Module 2.B-WordBreak: Runs Token Shape Analysis (UAX #29)."""
    counters = {}
    if not t or LOADING_STATE != "READY":
        return counters

    current_state = "NONE"
    
    for char in t:
        cp = ord(char)
        wb_class = _find_in_ranges(cp, "WordBreak")
        # --- Alignment: The default property is "Other" ---
        new_state = wb_class if wb_class else "Other"
        
        if new_state != current_state:
            if current_state != "NONE":
                if current_state in counters:
                    counters[current_state] += 1
                else:
                    counters[current_state] = 1
            current_state = new_state
    
    # Add the final run
    if current_state != "NONE":
        if current_state in counters:
            counters[current_state] += 1
        else:
            counters[current_state] = 1
            
    return counters

def compute_sentencebreak_analysis(t: str):
    """Module 2.B-SentenceBreak: Runs Token Shape Analysis (UAX #29)."""
    counters = {}
    if not t or LOADING_STATE != "READY":
        return counters

    current_state = "NONE"
    
    for char in t:
        cp = ord(char)
        sb_class = _find_in_ranges(cp, "SentenceBreak")
        new_state = sb_class if sb_class else "Other"
        
        if new_state != current_state:
            if current_state != "NONE":
                if current_state in counters:
                    counters[current_state] += 1
                else:
                    counters[current_state] = 1
            current_state = new_state
    
    # Add the final run
    if current_state != "NONE":
        if current_state in counters:
            counters[current_state] += 1
        else:
            counters[current_state] = 1
            
    return counters

def compute_graphemebreak_analysis(t: str):
    """Module 2.B-GraphemeBreak: Runs Token Shape Analysis (UAX #29)."""
    counters = {}
    if not t or LOADING_STATE != "READY":
        return counters

    current_state = "NONE"
    
    for char in t:
        cp = ord(char)
        gb_class = _find_in_ranges(cp, "GraphemeBreak")
        new_state = gb_class if gb_class else "Other"
        
        if new_state != current_state:
            if current_state != "NONE":
                if current_state in counters:
                    counters[current_state] += 1
                else:
                    counters[current_state] = 1
            current_state = new_state
    
    # Add the final run
    if current_state != "NONE":
        if current_state in counters:
            counters[current_state] += 1
        else:
            counters[current_state] = 1
            
    return counters


def compute_eastasianwidth_analysis(t: str):
    """Module 2.B-EastAsianWidth: Runs Token Shape Analysis."""
    counters = {}
    if not t or LOADING_STATE != "READY":
        return counters

    current_state = "NONE"
    
    for char in t:
        cp = ord(char)
        eaw_class = _find_in_ranges(cp, "EastAsianWidth")
        # --- FIX: The default for non-listed chars is 'Na' (Narrow), not 'N' (Neutral) ---
        new_state = eaw_class if eaw_class else "Na"
        
        if new_state != current_state:
            if current_state != "NONE":
                if current_state in counters:
                    counters[current_state] += 1
                else:
                    counters[current_state] = 1
            current_state = new_state
    
    # Add the final run
    if current_state != "NONE":
        if current_state in counters:
            counters[current_state] += 1
        else:
            counters[current_state] = 1
            
    return counters

def compute_verticalorientation_analysis(t: str):
    """Module 2.B-VerticalOrientation: Runs Token Shape Analysis."""
    counters = {}
    if not t or LOADING_STATE != "READY":
        return counters

    current_state = "NONE"
    
    for char in t:
        cp = ord(char)
        vo_class = _find_in_ranges(cp, "VerticalOrientation")
        new_state = vo_class if vo_class else "R" # 'R' (Rotated) is the default
        
        if new_state != current_state:
            if current_state != "NONE":
                if current_state in counters:
                    counters[current_state] += 1
                else:
                    counters[current_state] = 1
            current_state = new_state
    
    # Add the final run
    if current_state != "NONE":
        if current_state in counters:
            counters[current_state] += 1
        else:
            counters[current_state] = 1
            
    return counters

def _get_codepoint_properties(t: str):
    """
    A fast, single-pass helper to get the UAX properties needed for Stage 2.
    This iterates by code point, not grapheme.
    """
    if LOADING_STATE != "READY":
        return [], []

    word_break_props = []
    sentence_break_props = []
    
    # We must iterate by code point (char)
    for char in t:
        cp = ord(char)
        
        # 1. Get Word Break Property
        wb_prop = _find_in_ranges(cp, "WordBreak")
        word_break_props.append(wb_prop if wb_prop else "Other")
        
        # 2. Get Sentence Break Property
        sb_prop = _find_in_ranges(cp, "SentenceBreak")
        sentence_break_props.append(sb_prop if sb_prop else "Other")

    return word_break_props, sentence_break_props



def compute_forensic_stats_with_positions(t: str, cp_minor_stats: dict):
    """Module 2.C: Runs Forensic Analysis and finds positions."""

    # --- Re-initialize all lists to prevent stale state ---
    deceptive_space_indices = []
    nonchar_indices = []
    private_use_indices = []
    surrogate_indices = []
    unassigned_indices = []
    bidi_control_indices = []
    join_control_indices = []
    true_ignorable_indices = []
    other_ignorable_indices = []
    extender_indices = []
    deprecated_indices = []
    donotemit_indices = []
    discouraged_indices = []
    dash_indices = []
    quote_indices = []
    terminal_punct_indices = []
    sentence_terminal_indices = []
    alphabetic_indices = []
    decomp_type_stats = {}
    bidi_mirrored_indices = []
    loe_indices = []
    bidi_bracket_open_indices = []
    bidi_bracket_close_indices = []
    bidi_mirroring_map = {}
    norm_exclusion_indices = []
    norm_nfkc_casefold_indices = []
    deceptive_ls_indices = []
    deceptive_ps_indices = []
    deceptive_nel_indices = []
    id_type_stats = {} # For IdentifierType
    ext_pictographic_indices = []
    emoji_modifier_indices = []
    emoji_modifier_base_indices = []
    invalid_vs_indices = []
    variation_selector_indices = []
    # --- End Initialization ---

    # --- Alias map for noisy IdentifierType labels (defined once outside the loop) ---
    ID_TYPE_ALIASES = {
        "Technical Not_XID": "Technical (Not_XID)",
        "Exclusion Not_XID": "Exclusion (Not_XID)",
        "Obsolete Not_XID": "Obsolete (Not_XID)",
        "Deprecated Not_XID": "Deprecated (Not_XID)",
        "Not_NFKC Not_XID": "Not_NFKC (Not_XID)",
        "Default_Ignorable Not_XID": "Default_Ignorable (Not_XID)"
    }
    
    if LOADING_STATE == "READY":
        js_array = window.Array.from_(t)
        for i, char in enumerate(js_array):
            try:
                category = unicodedata.category(char)
                cp = ord(char)
                
                # --- Deceptive Newline Check ---
                if cp == 0x2028: deceptive_ls_indices.append(f"#{i}")
                elif cp == 0x2029: deceptive_ps_indices.append(f"#{i}")
                elif cp == 0x0085: deceptive_nel_indices.append(f"#{i}")

                if _find_in_ranges(cp, "BidiControl"): bidi_control_indices.append(f"#{i}")
                if _find_in_ranges(cp, "JoinControl"): join_control_indices.append(f"#{i}")
                if category == "Cf" and not _find_in_ranges(cp, "BidiControl") and not _find_in_ranges(cp, "JoinControl"):
                    true_ignorable_indices.append(f"#{i}") 

                if _find_in_ranges(cp, "OtherDefaultIgnorable"): other_ignorable_indices.append(f"#{i}")

        
                # --- 4. Other Properties (from data) ---
                if _find_in_ranges(cp, "Extender"): extender_indices.append(f"#{i}")
                
                # --- BUG FIX for 'Deprecated' ---
                deprecated_val = _find_in_ranges(cp, "Deprecated")
                if deprecated_val and "Deprecated" in deprecated_val:
                    deprecated_indices.append(f"#{i}")
                # --- END FIX ---
                    
                if _find_in_ranges(cp, "DoNotEmit"): donotemit_indices.append(f"#{i}")
                if _find_in_ranges(cp, "Discouraged"): discouraged_indices.append(f"#{i}")
                if _find_in_ranges(cp, "Dash"): dash_indices.append(f"#{i}")
                if _find_in_ranges(cp, "QuotationMark"): quote_indices.append(f"#{i}")
                if _find_in_ranges(cp, "TerminalPunctuation"): terminal_punct_indices.append(f"#{i}")
                if _find_in_ranges(cp, "SentenceTerminal"): sentence_terminal_indices.append(f"#{i}")
                if _find_in_ranges(cp, "Alphabetic"): alphabetic_indices.append(f"#{i}")
                
                # --- 5. General Category checks ---
                if category == "Zs" and cp != 0x0020:
                    deceptive_space_indices.append(f"#{i}")
                elif _find_in_ranges(cp, "WhiteSpace") and cp != 0x0020 and category not in ("Zl", "Zp", "Cc"):
                        if f"#{i}" not in deceptive_space_indices:
                            deceptive_space_indices.append(f"#{i}")
                
                if category == "Co": private_use_indices.append(f"#{i}")
                if category == "Cs": surrogate_indices.append(f"#{i}")
                if category == "Cn": unassigned_indices.append(f"#{i}")

                if (cp >= 0xFDD0 and cp <= 0xFDEF) or (cp & 0xFFFF) in (0xFFFE, 0xFFFF):
                    nonchar_indices.append(f"#{i}")

                # --- 6. Derived Properties (from data) ---
                decomp_type = _find_in_ranges(cp, "DecompositionType")
                if decomp_type and decomp_type != "Canonical":
                    key = f"Decomposition (Derived): {decomp_type.title()}"
                    if key not in decomp_type_stats: decomp_type_stats[key] = {'count': 0, 'positions': []}
                    decomp_type_stats[key]['count'] += 1
                    decomp_type_stats[key]['positions'].append(f"#{i}")
                
                if _find_in_ranges(cp, "BidiMirrored"): bidi_mirrored_indices.append(f"#{i}")
                if _find_in_ranges(cp, "LogicalOrderException"): loe_indices.append(f"#{i}")

                # --- 7. GEM properties (from data) ---
                bracket_type = _find_in_ranges(cp, "BidiBracketType")
                if bracket_type == "o": bidi_bracket_open_indices.append(f"#{i}")
                elif bracket_type == "c": bidi_bracket_close_indices.append(f"#{i}")
                
                if cp in DATA_STORES["BidiMirroring"]:
                    mirrored_cp = DATA_STORES["BidiMirroring"][cp]
                    bidi_mirroring_map[i] = f"'{char}' → '{chr(mirrored_cp)}'"
                
                if _find_in_ranges(cp, "CompositionExclusions"): norm_exclusion_indices.append(f"#{i}")
                if _find_in_ranges(cp, "ChangesWhenNFKCCasefolded"): norm_nfkc_casefold_indices.append(f"#{i}")

                
                # --- 8/9. Identifier Status & Type (UAX #31) ---

                # 1. IdentifierStatus (UAX #31)
                id_status_val = _find_in_ranges(cp, "IdentifierStatus")
                status_key = ""

                if id_status_val:
                    # Explicit status from IdentifierStatus.txt
                    if id_status_val not in UAX31_ALLOWED_STATUSES:
                        status_key = f"Flag: Status: {id_status_val}"
                else:
                    # No explicit status → treat as "Default Restricted" (except Cn/Co/Cs)
                    if category not in ("Cn", "Co", "Cs"):
                        status_key = "Flag: Identifier Status: Default Restricted"

                if status_key:
                    if status_key not in id_type_stats:
                        id_type_stats[status_key] = {'count': 0, 'positions': []}
                    id_type_stats[status_key]['count'] += 1
                    id_type_stats[status_key]['positions'].append(f"#{i}")

                # 2. IdentifierType (UAX #31)
                specific_id_type = _find_in_ranges(cp, "IdentifierType")
                if specific_id_type and specific_id_type not in ("Recommended", "Inclusion"):
                    # Use the alias map defined at the top of the function
                    clean_label = ID_TYPE_ALIASES.get(specific_id_type, specific_id_type)
                    key = f"Flag: Type: {clean_label}"
                    if key not in id_type_stats:
                        id_type_stats[key] = {'count': 0, 'positions': []}
                    id_type_stats[key]['count'] += 1
                    id_type_stats[key]['positions'].append(f"#{i}")
                # --- END (UAX #31 Logic) ---

                if _find_in_ranges(cp, "Extended_Pictographic"): ext_pictographic_indices.append(f"#{i}")
                if _find_in_ranges(cp, "Emoji_Modifier_Base"): emoji_modifier_base_indices.append(f"#{i}")
                if _find_in_ranges(cp, "Emoji_Modifier"): emoji_modifier_indices.append(f"#{i}")
                if _find_in_ranges(cp, "VariationSelector"): variation_selector_indices.append(f"#{i}")

                # --- 10. Variation Selector (VS) Sanity Check ---
                is_vs = _find_in_ranges(cp, "VariationSelector")
                if is_vs:
                    # It's a selector. Now check if it's valid.
                    is_valid_vs = False
                    if i > 0:
                        prev_cp = ord(js_array[i-1])
                        # Check the master set of all valid bases (from emoji + std)
                        if prev_cp in DATA_STORES["VariantBase"]:
                            is_valid_vs = True
                    
                    if not is_valid_vs:
                        # It's either at index 0 or follows an invalid base (like 'a')
                        invalid_vs_indices.append(f"#{i}")

            except Exception as e:
                print(f"Error processing char at index {i} ('{char}'): {e}")

    # --- Build final report ---
    forensic_stats = {}
    forensic_stats["Bidi Control (UAX #9)"] = {'count': len(bidi_control_indices), 'positions': bidi_control_indices}
    forensic_stats["Join Control (Structural)"] = {'count': len(join_control_indices), 'positions': join_control_indices}
    forensic_stats["True Ignorable (Format/Cf)"] = {'count': len(true_ignorable_indices), 'positions': true_ignorable_indices}
    forensic_stats["Other Default Ignorable"] = {'count': len(other_ignorable_indices), 'positions': other_ignorable_indices}
    forensic_stats["Prop: Extender"] = {'count': len(extender_indices), 'positions': extender_indices}
    forensic_stats["Prop: Deprecated"] = {'count': len(deprecated_indices), 'positions': deprecated_indices}
    forensic_stats["Prop: Discouraged (DoNotEmit)"] = {'count': len(donotemit_indices), 'positions': donotemit_indices}
    forensic_stats["Flag: Security Discouraged (Compatibility)"] = {'count': len(discouraged_indices), 'positions': discouraged_indices}
    forensic_stats["Prop: Dash"] = {'count': len(dash_indices), 'positions': dash_indices}
    forensic_stats["Prop: Quotation Mark"] = {'count': len(quote_indices), 'positions': quote_indices}
    forensic_stats["Prop: Terminal Punctuation"] = {'count': len(terminal_punct_indices), 'positions': terminal_punct_indices}
    forensic_stats["Prop: Sentence Terminal"] = {'count': len(sentence_terminal_indices), 'positions': sentence_terminal_indices}
    forensic_stats["Prop: Alphabetic"] = {'count': len(alphabetic_indices), 'positions': alphabetic_indices}

    forensic_stats.update(decomp_type_stats)
    
    forensic_stats["Prop: Bidi Mirrored"] = {'count': len(bidi_mirrored_indices), 'positions': bidi_mirrored_indices}
    forensic_stats["Prop: Logical Order Exception"] = {'count': len(loe_indices), 'positions': loe_indices}

    forensic_stats["Flag: Deceptive Newline (LS)"] = {'count': len(deceptive_ls_indices), 'positions': deceptive_ls_indices}
    forensic_stats["Flag: Deceptive Newline (PS)"] = {'count': len(deceptive_ps_indices), 'positions': deceptive_ps_indices}
    forensic_stats["Flag: Deceptive Newline (NEL)"] = {'count': len(deceptive_nel_indices), 'positions': deceptive_nel_indices}
    
    forensic_stats["Flag: Bidi Paired Bracket (Open)"] = {'count': len(bidi_bracket_open_indices), 'positions': bidi_bracket_open_indices}
    forensic_stats["Flag: Bidi Paired Bracket (Close)"] = {'count': len(bidi_bracket_close_indices), 'positions': bidi_bracket_close_indices}

    mirror_count = len(bidi_mirroring_map)
    if mirror_count > 0:
        mirror_positions = [f"#{idx} ({mapping})" for idx, mapping in bidi_mirroring_map.items()]
        forensic_stats["Flag: Bidi Mirrored Mapping"] = {'count': mirror_count, 'positions': mirror_positions}
    
    forensic_stats["Flag: Full Composition Exclusion"] = {'count': len(norm_exclusion_indices), 'positions': norm_exclusion_indices}
    forensic_stats["Flag: Changes on NFKC Casefold"] = {'count': len(norm_nfkc_casefold_indices), 'positions': norm_nfkc_casefold_indices}
    
    forensic_stats["Deceptive Spaces"] = {'count': len(deceptive_space_indices), 'positions': deceptive_space_indices}
    forensic_stats["Noncharacter"] = {'count': len(nonchar_indices), 'positions': nonchar_indices}
    forensic_stats["Private Use"] = {'count': len(private_use_indices), 'positions': private_use_indices}
    forensic_stats["Surrogates (Broken)"] = {'count': len(surrogate_indices), 'positions': surrogate_indices}
    forensic_stats["Unassigned (Void)"] = {'count': len(unassigned_indices), 'positions': unassigned_indices}

    forensic_stats["Prop: Extended Pictographic"] = {'count': len(ext_pictographic_indices), 'positions': ext_pictographic_indices}
    forensic_stats["Prop: Emoji Modifier"] = {'count': len(emoji_modifier_indices), 'positions': emoji_modifier_indices}
    forensic_stats["Prop: Emoji Modifier Base"] = {'count': len(emoji_modifier_base_indices), 'positions': emoji_modifier_base_indices}
    forensic_stats["Flag: Invalid Variation Selector"] = {'count': len(invalid_vs_indices), 'positions': invalid_vs_indices}
    forensic_stats["Prop: Variation Selector"] = {'count': len(variation_selector_indices), 'positions': variation_selector_indices}
    
    # Add Variant Stats
    # variant_stats = compute_variant_stats_with_positions(t)
    # forensic_stats.update(variant_stats)

    # Add IdentifierType Stats (which now includes IdentifierStatus)
    forensic_stats.update(id_type_stats)
    
    return forensic_stats


def compute_provenance_stats(t: str):
    """Module 2.D: Runs UAX #44 and Deep Scan analysis (with positions)."""

    # 1. Deep Scan Stats (if data is loaded)
    if LOADING_STATE != "READY":
        return {} # Return empty if data isn't ready

    numeric_total_value = 0
    number_script_zeros = set()
    final_stats = {} # This will now hold the dicts

    # Helper to add to our new structure
    def _add_stat(key, index):
        if key not in final_stats:
            final_stats[key] = {'count': 0, 'positions': []}
        final_stats[key]['count'] += 1
        final_stats[key]['positions'].append(f"#{index}")

    # We loop char-by-char with index
    js_array = window.Array.from_(t)
    for i, char in enumerate(js_array):
        cp = ord(char)

        # --- Script and Script-Extension ---
        script_ext_val = _find_in_ranges(cp, "ScriptExtensions")
        if script_ext_val:
            scripts = script_ext_val.split()
            for script in scripts:
                _add_stat(f"Script-Ext: {script}", i)
        else:
            script_val = _find_in_ranges(cp, "Scripts")
            if script_val:
                _add_stat(f"Script: {script_val}", i)

        # --- Block, Age, Type ---
        block_name = _find_in_ranges(cp, "Blocks")
        if block_name:
            _add_stat(f"Block: {block_name}", i)

        age = _find_in_ranges(cp, "Age")
        if age:
            _add_stat(f"Age: {age}", i)

        num_type = _find_in_ranges(cp, "NumericType")
        if num_type:
            _add_stat(f"Numeric Type: {num_type}", i)

        # --- Numeric Properties (Non-positional) ---
        try:
            value = unicodedata.numeric(char)
            numeric_total_value += value
            gc = unicodedata.category(char)
            if gc == "Nd":
                zero_code_point = ord(char) - int(value)
                number_script_zeros.add(zero_code_point)
        except (ValueError, TypeError):
            pass

    # --- Add the non-positional stats (which don't need 'positions') ---
    if numeric_total_value > 0:
        final_stats["Total Numeric Value"] = {
            'count': round(numeric_total_value, 4), 
            'positions': ["(N/A)"]
        }
    if len(number_script_zeros) > 1:
        final_stats["Mixed-Number Systems"] = {
            'count': len(number_script_zeros), 
            'positions': ["(N/A)"]
        }

    return final_stats


def _generate_uts39_skeleton(t: str):
    """Generates the UTS #39 'skeleton' for a string."""
    if LOADING_STATE != "READY":
        return ""
        
    confusables_map = DATA_STORES.get("Confusables", {})
    
    try:
        # We will loop over the raw string 't'
        mapped_chars = []
        for char in t: # Loop over 't' directly
            cp = ord(char)
            
            # --- THIS IS THE FIX ---
            # We map *all* confusables. The 'intentional' logic was flawed.
            skeleton_char_str = confusables_map.get(cp)
            
            if skeleton_char_str:
                mapped_chars.append(skeleton_char_str)
            else:
                mapped_chars.append(char)
            # --- END FIX ---
        
        final_skeleton = "".join(mapped_chars)
        
        return final_skeleton
    except Exception as e:
        print(f"Error generating skeleton: {e}")
        return "" # Return empty string on failure

def _escape_html(s: str):
    """Escapes basic HTML characters."""
    s = s.replace("&", "&amp;")
    s = s.replace("<", "&lt;")
    s = s.replace(">", "&gt;")
    return s

def _build_confusable_span(char: str, cp: int, confusables_map: dict) -> str:
    """
    Helper to build the <span class="confusable" title="...">...</span> HTML.
    This logic is extracted from the original compute_threat_analysis loop.
    """
    try:
        skeleton_char_str = confusables_map[cp]
        skeleton_cp_hex = f"U+{ord(skeleton_char_str[0]):04X}"
        skeleton_cp = ord(skeleton_char_str[0])
        source_script = _find_in_ranges(cp, "Scripts") or "Unknown"
        target_script = _find_in_ranges(skeleton_cp, "Scripts") or "Common"

        if (source_script != target_script and 
            target_script != "Common" and 
            source_script != "Unknown"):
            risk_label = f"{source_script}–{target_script} Confusable"
        else:
            risk_label = f"{source_script} Confusable"

        title = (
            f"Appears as: '{char}' (U+{cp:04X})\n"
            f"Script: {source_script}\n"
            f"Maps to: '{skeleton_char_str}' ({skeleton_cp_hex})\n"
            f"Risk: {risk_label}"
        )
        return (
            f'<span class="confusable" title="{_escape_html(title)}">'
            f"{_escape_html(char)}</span>"
        )
    except Exception:
        # Failsafe
        return f'<span class="confusable" title="Confusable">{_escape_html(char)}</span>'

def _tokenize_for_pvr(text: str) -> list:
    """
    Tokenizes the text into a list of 'word' and 'gap' tokens
    for the Perception vs. Reality view.
    
    This is a pure-Python tokenizer that avoids JS proxy errors.
    
    Implementation detail:
      - We work over window.Array.from_(text), so indices are in
        codepoint space (the same as confusable_indices).
      - A 'word' is a maximal run of NON-WHITESPACE.
      - A 'gap' is a maximal run of WHITESPACE.
    """
    tokens = []
    js_array = window.Array.from_(text)

    if not js_array:
        return tokens

    current_type = None    # 'word' or 'gap'
    current_start = 0

    for i, ch in enumerate(js_array):
        # Python's str.isspace() is Unicode-aware and handles
        # basic spaces, tabs, and newlines (Zl, Zp, Zs).
        # This is the correct logic for this tokenizer.
        is_gap_char = ch.isspace()
        token_type = 'gap' if is_gap_char else 'word'

        if current_type is None:
            # First character
            current_type = token_type
            current_start = i
            continue

        if token_type != current_type:
            # Flush the previous run
            segment_text = "".join(js_array[current_start:i])
            
            if segment_text:
                if current_type == 'gap':
                    tokens.append({
                        'type': 'gap',
                        'text': segment_text,
                    })
                else: # 'word'
                    tokens.append({
                        'type': 'word',
                        'text': segment_text,
                        'start': current_start,
                        'end': i,
                    })

            # Start new run
            current_type = token_type
            current_start = i

    # Flush the final run
    end_index = len(js_array)
    segment_text = "".join(js_array[current_start:end_index])
    
    if segment_text:
        if current_type == 'gap':
            tokens.append({
                'type': 'gap',
                'text': segment_text,
            })
        else: # 'word'
            tokens.append({
                'type': 'word',
                'text': segment_text,
                'start': current_start,
                'end': end_index,
            })

    return tokens

def _render_confusable_summary_view(
    t: str,
    confusable_indices: set[int],
    confusables_map: dict
) -> str:
    """
    Renders the "Perception vs. Reality" HTML, collapsing "usual"
    words into [...] blocks using the "hot token + neighbours"
    algorithm.

    IMPORTANT: This version detects "hot" tokens purely by checking
    code points against `confusables_map`, so it does not depend
    on any external index bookkeeping.
    """
    tokens = _tokenize_for_pvr(t)
    if not tokens:
        return ""

    # --- Build a set of "hot" code points from the pre-filtered indices ---
    # This is the correct logic: we build our "hot" set ONLY
    # from the confusable_indices that were passed in.
    hot_cps: set[int] = set()
    js_array = window.Array.from_(t) # Use JS array for correct indexing
    text_len = len(js_array)

    if confusable_indices:
        for idx in confusable_indices:
            try:
                i = int(idx)
            except Exception:
                continue # Skip malformed indices

            if 0 <= i < text_len:
                ch = js_array[i] # Use index on the JS array
                if ch:
                    hot_cps.add(ord(ch))

    # If there are no confusable code points at all, there is
    # nothing interesting to show – return empty so the caller
    # can display "No confusable runs detected."
    if not hot_cps:
        return ""

    # --- Pass 1: figure out which tokens are "hot" ---
    hot_token_indices: set[int] = set()
    for i, token in enumerate(tokens):
        token_text = token.get("text") or ""
        # A token is "hot" if any of its characters has a code point
        # present in the confusables map.
        if any(ord(ch) in hot_cps for ch in token_text):
            hot_token_indices.add(i)

    # --- Pass 2: The "Keep Set" is *only* the hot tokens ---
    # We no longer add any neighbours, per the new requirement.
    keep_indices: set[int] = hot_token_indices
    num_tokens = len(tokens) # Get token count once

    # --- Pass 3: Render with Ellipsis ---
    final_html: list[str] = []

    # If, for some reason, we still have nothing to keep, bail out.
    # This prevents the "pure [...]" output.
    if not keep_indices:
        # This fallback should now be rarely, if ever, used.
        return _escape_html(t)

    # --- Pass 3: render, collapsing everything else into [...] ---
    final_html_parts: list[str] = []
    ellipsis_open = False

    for i, token in enumerate(tokens):
        token_type = token.get("type")
        token_text = token.get("text", "")

        # Always preserve tokens that contain a newline so that
        # line structure stays recognizable.
        if token_type == "gap" and "\n" in token_text:
            final_html_parts.append(_escape_html(token_text))
            ellipsis_open = False  # newline resets the condenser
            continue

        if i in keep_indices:
            # This token (or its neighbour) is interesting: render fully.
            ellipsis_open = False

            if token_type == "gap":
                # For gaps we don't try to highlight characters, just escape.
                final_html_parts.append(_escape_html(token_text))

            elif token_type == "word":
                # For word tokens, walk character-by-character so we can
                # wrap the confusable ones in <span> with metadata.
                for ch in token_text:
                    cp = ord(ch)
                    if cp in hot_cps:
                        final_html_parts.append(
                            _build_confusable_span(ch, cp, confusables_map)
                        )
                    else:
                        final_html_parts.append(_escape_html(ch))
            else:
                # Any unexpected token type – just escape.
                final_html_parts.append(_escape_html(token_text))
        else:
            # Boring token – compress it into a single [...]
            if not ellipsis_open:
                final_html_parts.append(" [...] ")
                ellipsis_open = True

    return "".join(final_html_parts)

def compute_threat_analysis(t: str):
    """Module 3: Runs Threat-Hunting Analysis (UTS #39, etc.)."""
    
    # --- 0. Initialize defaults ---
    threat_flags = {}
    threat_hashes = {}
    confusable_indices = []
    found_confusable = False
    
    # --- We use lists/sets to gather data first ---
    bidi_danger_indices = []
    scripts_in_use = set() # Use ONE global set

    # Initialize output variables with safe defaults
    nf_string = ""
    nf_casefold_string = ""
    skeleton_string = ""
    final_html_report = ""

    # --- 1. Early Exit for Empty Input ---
    if not t:
        return {
            'flags': {}, 'hashes': {}, 'html_report': "", 'bidi_danger': False,
            'raw': "", 'nfkc': "", 'nfkc_cf': "", 'skeleton': ""
        }

    def _get_hash(s: str):
        if not s: return ""
        return hashlib.sha256(s.encode('utf-8')).hexdigest()

    try:
        # --- 2. Generate Normalized States (using Extended Normalizer) ---
        nf_string = normalize_extended(t)
        nf_casefold_string = nf_string.casefold() # Use the already-normalized string

        # --- 3. Run checks on the RAW string 't' ---
        confusables_map = DATA_STORES.get("Confusables", {})

        if LOADING_STATE == "READY":
            js_array_raw = window.Array.from_(t)
            lnps_regex = REGEX_MATCHER.get("LNPS_Runs")

            # --- LOOP: Single, "Per-Char" Analysis (Robust and Correct) ---
            # This is the original, reliable loop from your first app.py
            for i, char in enumerate(js_array_raw):
                cp = ord(char)
                
                # --- A. Bidi Check ---
                # This will find the RLO (U+202E) from Test 2
                if (0x202A <= cp <= 0x202E) or (0x2066 <= cp <= 0x2069):
                    bidi_danger_indices.append(f"#{i}")

                # --- B. Mixed-Script Detection (Refined) ---
                # Only check scripts for "visible" L, N, or S categories
                try:
                    category = unicodedata.category(char)[0] # Get 'L', 'N', 'S', 'C', etc.
                    if category in ("L", "N", "S"):
                        # This global set will find 'Latin' and 'Cyrillic' from Test 1
                        script_ext_val = _find_in_ranges(cp, "ScriptExtensions")
                        if script_ext_val:
                            scripts_in_use.update(script_ext_val.split())
                        else:
                            script_val = _find_in_ranges(cp, "Scripts")
                            if script_val:
                                scripts_in_use.add(script_val)
                except Exception:
                    pass # Failsafe
                
                # --- C. Confusable HTML Report Builder ---
                # We no longer build HTML here. We just collect "hot" indices.
                if cp in confusables_map and window.RegExp.new(r"\p{L}|\p{N}|\p{P}|\p{S}", "u").test(char):
                    found_confusable = True
                    confusable_indices.append(i)
                

            # --- 4. Populate Threat Flags (This fixes the TypeError) ---
            # We build the flags *after* the loop, all as dicts.
            
            # Add Bidi flag
            if bidi_danger_indices:
                threat_flags["DANGER: Malicious Bidi Control"] = {
                    'count': len(bidi_danger_indices),
                    'positions': bidi_danger_indices
                }
            
            # Add Mixed-Script flag (from the global set)
            scripts_in_use.discard("Common")
            scripts_in_use.discard("Inherited")
            scripts_in_use.discard("Zzzz")
            if len(scripts_in_use) > 1:
                key = f"High-Risk: Mixed Scripts ({', '.join(sorted(scripts_in_use))})"
                threat_flags[key] = {
                    'count': 1,
                    'positions': ["(See Provenance Profile for details)"]
                }
            # --- End of TypeError fix ---

        # --- 5. Implement UTS #39 Skeleton ---
        skeleton_string = _generate_uts39_skeleton(nf_casefold_string)

        # --- 6. Generate Hashes ---
        threat_hashes["State 1: Forensic (Raw)"] = _get_hash(t)
        threat_hashes["State 2: NFKC"] = _get_hash(nf_string)
        threat_hashes["State 3: NFKC-Casefold"] = _get_hash(nf_casefold_string)
        threat_hashes["State 4: UTS #39 Skeleton"] = _get_hash(skeleton_string)

        # --- NEW: Call the new summary renderer ---
        if found_confusable:
            # Pass the map so the helper can build the spans
            final_html_report = _render_confusable_summary_view(
                t, set(confusable_indices), confusables_map
            )
        else:
            final_html_report = ""

    except Exception as e:
        print(f"Error in compute_threat_analysis: {e}")
        if not nf_string: nf_string = t 
        if not nf_casefold_string: nf_casefold_string = t.casefold()
        if not skeleton_string: skeleton_string = t
        final_html_report = "<p class='placeholder-text'>Error generating confusable report.</p>"

    # --- 7. Return Final Report ---
    return {
        'flags': threat_flags,
        'hashes': threat_hashes,
        'html_report': final_html_report,
        'bidi_danger': bool(bidi_danger_indices), # Return True if the list is not empty
        'raw': t,
        'nfkc': nf_string,
        'nfkc_cf': nf_casefold_string,
        'skeleton': skeleton_string
    }
    
def render_threat_analysis(threat_results):
    """Renders the Group 3 Threat-Hunting results."""
    
    # 1. Render Flags
    flags = threat_results.get('flags', {})
    # render_cards(flags, "threat-report-cards") # We can re-use render_cards!
    # We can re-use the "integrity" matrix renderer!
    render_matrix_table(flags, "threat-report-body", has_positions=True)
    
    # 2. Render Hashes
    hashes = threat_results.get('hashes', {})
    hash_html = []
    if hashes:
        for k, v in hashes.items():
            hash_html.append(f'<tr><th scope="row">{k}</th><td>{v}</td></tr>')
        document.getElementById("threat-hash-report-body").innerHTML = "".join(hash_html)
    else:
        document.getElementById("threat-hash-report-body").innerHTML = '<tr><td colspan="2" class="placeholder-text">No data.</td></tr>'

    # 3. Render Confusable Report
    html_report = threat_results.get('html_report', "")
    report_el = document.getElementById("confusable-diff-report")
    if html_report:
        report_el.innerHTML = html_report
    else:
        report_el.innerHTML = '<p class="placeholder-text">No confusable runs detected.</p>'
    

    # 4. Render Banner
    banner_el = document.getElementById("threat-banner")
    if banner_el:
        bidi_danger = threat_results.get('bidi_danger', False)
        if bidi_danger:
            banner_el.innerText = "WARNING: This text contains malicious Bidi control characters (like RLO) designed to reverse text order. This is a vector for 'Trojan Source' attacks."
            banner_el.removeAttribute("hidden")
        else:
            banner_el.setAttribute("hidden", "true")

# ---
# 4. DOM RENDERER FUNCTIONS
# ---

def render_status(message):
    """Updates the status line with text and CSS class."""
    status_line = document.getElementById("status-line")
    if status_line:
        # Use .innerText for safety and to let the CSS handle styling
        status_line.innerText = message
        
        # Determine the new class by *inferring* the state from the message
        if message.startswith("Error:"):
            new_class = "status-error"
        elif message.startswith("Ready"):
            new_class = "status-ready"
        else:
            new_class = "status-loading"
        
        # Update the class list
        status_line.classList.remove("status-loading", "status-ready", "status-error")
        status_line.classList.add(new_class)
        
        # Clear any old inline styles
        status_line.style.color = ""

def render_emoji_qualification_table(emoji_list: list):
    """Renders the new Emoji Qualification Profile table."""
    element = document.getElementById("emoji-qualification-body")
    if not element:
        return

    if not emoji_list:
        element.innerHTML = "<tr><td colspan='4' class='placeholder-text'>No RGI emoji sequences detected.</td></tr>"
        return

    # 1. Aggregate the list by (sequence, status)
    grouped = {}
    for item in emoji_list:
        seq = item.get("sequence", "?")
        # Format status: "fully-qualified" -> "Fully Qualified"
        status = item.get("status", "unknown").replace("-", " ").title()
        index = item.get("index", 0)
        
        key = (seq, status)
        if key not in grouped:
            grouped[key] = []
        grouped[key].append(f"#{index}")

    # 2. Build HTML string
    html = []
    
    # Sort by the first index to keep them in order of appearance
    try:
        # Sort the keys by the numeric value of their first position
        sorted_keys = sorted(grouped.keys(), key=lambda k: int(grouped[k][0][1:]))
    except Exception:
        # Failsafe sort (alphabetical by sequence)
        sorted_keys = sorted(grouped.keys())

    for key in sorted_keys:
        # Unpack the key, AND LOOK UP the value from the dict
        seq, status = key
        positions = grouped[key]
        
        count = len(positions)
        
        # Use <details> for long position lists
        POSITION_THRESHOLD = 5
        if count > POSITION_THRESHOLD:
            visible_positions = ", ".join(positions[:POSITION_THRESHOLD])
            hidden_positions = ", ".join(positions[POSITION_THRESHOLD:])
            pos_html = (
                f'<details style="cursor: pointer;">'
                f'<summary>{visible_positions} ... ({count} total)</summary>'
                f'<div style="padding-top: 8px; user-select: all;">{hidden_positions}</div>'
                f'</details>'
            )
        else:
            pos_html = ", ".join(positions)

        html.append(
            f'<tr>'
            # Use mono font for emoji to prevent weird spacing
            # 1. Sequence Column (unchanged style)
            f'<th scope="row" style="font-family: var(--font-mono); font-size: 1.1rem;">{seq}</th>'
            # 2. Status Column
            f'<td style="color: var(--color-text); font-weight: normal;">{status}</td>'
            # 3. Count Column
            f'<td>{count}</td>'
            # 4. Positions Column
            f'<td>{pos_html}</td>'
            f'</tr>'
        )
    
    element.innerHTML = "".join(html)

def render_emoji_summary(emoji_counts, emoji_list):
    """
    Render a one-line summary like:
    'RGI Emoji Sequences: 12 • Emoji Components: 6'
    """
    summary_el = document.getElementById("emoji-summary")
    if not summary_el:
        return

    # RGI total comes directly from the emoji_counts dict
    rgi_total = emoji_counts.get("RGI Emoji Sequences", 0)

    # The emoji_list is a raw list of *every* occurrence.
    # We just need to iterate it and increment a counter for
    # every item that has the "component" status.
    component_total = 0
    if emoji_list:
        for item in emoji_list:
            if item.get("status", "").lower() == "component":
                component_total += 1


    summary_el.innerText = (
        f"RGI Emoji Sequences: {rgi_total} • "
        f"Emoji Components: {component_total}"
    )


def render_cards(stats_dict, element_id, key_order=None):
    """Generates and injects HTML for standard stat cards."""
    html = []
    
    # --- NEW: Smart Rendering Loop for Repertoire Cards ---

    # Define the keys for our new complex cards
    REPERTOIRE_KEYS = {
        "ASCII-Compatible",
        "Latin-1-Compatible",
        "BMP Coverage",
        "Supplementary Planes"
    }
    
    keys_to_render = key_order if key_order else sorted(stats_dict.keys())
    
    for k in keys_to_render:
        # Failsafe: if key_order has a key not in the dict, skip it
        if k not in stats_dict or stats_dict[k] is None:
            continue
    
        v = stats_dict[k]
    
        # --- RENDER PATH 1: New Repertoire Cards (Complex) ---
        if k in REPERTOIRE_KEYS:
            # 'v' is the dict {'count': ..., 'pct': ..., 'is_full': ...}
            count = v.get("count", 0)
    
            # Only render the card if the count is > 0
            if count > 0:
                pct = v.get("pct", 0)
                is_full = v.get("is_full", False)
    
                if k == "Supplementary Planes":
                    # Special case: "Fully" badge doesn't apply
                    badge_html = f'<div class="card-percentage">{pct}%</div>'
                else:
                    badge_html = (
                        f'<div class="card-badge-full">Fully</div>'
                        if is_full
                        else f'<div class="card-percentage">{pct}%</div>'
                    )
    
                # Build the complex card HTML
                html.append(
                    f'<div class="card card-repertoire">'
                    f'<strong>{k}</strong>'
                    f'<div class="card-main-value">{count}</div>'
                    f'{badge_html}'
                    f'</div>'
                )
    
        # --- RENDER PATH 2: Grapheme Forensic Cards (Dict) ---
        elif isinstance(v, dict):
            count = v.get('count', 0)
            if count > 0:
                html.append(f'<div class="card"><strong>{k}</strong><div>{count}</div></div>')
    
        # --- RENDER PATH 3: Simple Cards (Int/Float) ---
        elif isinstance(v, (int, float)):
            count = v
            # Always render 0-count for these key totals
            if count > 0 or (k in ["Total Graphemes", "Total Code Points", "RGI Emoji Sequences", "Whitespace (Total)"]):
                html.append(f'<div class="card"><strong>{k}</strong><div>{count}</div></div>')
    
        else:
            # Skip unknown data types
            continue
    
    element = document.getElementById(element_id)
    if element:
        element.innerHTML = "".join(html) if html else "<p class='placeholder-text' style='grid-column: 1 / -1;'>No data.</p>"

def render_parallel_table(cp_stats, gr_stats, element_id, aliases=None):
    """Renders the side-by-side Code Point vs. Grapheme table."""
    html = []
    all_keys = sorted(set(cp_stats.keys()) | set(gr_stats.keys()))
    
    for key in all_keys:
        cp_val = cp_stats.get(key, 0)
        gr_val = gr_stats.get(key, 0)
        
        if cp_val > 0 or gr_val > 0:
            label = aliases.get(key, key) if aliases else key
            html.append(
                f'<tr><th scope="row">{label}</th><td>{cp_val}</td><td>{gr_val}</td></tr>'
            )
            
    element = document.getElementById(element_id)
    if element:
        element.innerHTML = "".join(html)

def render_matrix_table(stats_dict, element_id, has_positions=False, aliases=None):
    """Renders a generic "Matrix of Facts" table."""
    html = []
    
    # Sort the dictionary keys so the output is stable and alphabetical
    sorted_keys = sorted(stats_dict.keys())
    
    for key in sorted_keys: # Iterate over sorted keys
        data = stats_dict[key]
        if not data:
            continue
            
        # --- THIS IS THE FIX ---
        # If aliases are provided and the key is in them, use the alias.
        # Otherwise, just use the key itself.
        if aliases and key in aliases:
            label = aliases[key]
        else:
            label = key
        # --- END OF FIX ---
        
        if has_positions:
            # Data is a dict: {'count': 1, 'positions': ['#42']}
            count = data.get('count', 0)
            if count == 0:
                continue
            
            position_list = data.get('positions', [])
            total_positions = len(position_list)
            
            # --- New Logic: Use <details> for long lists ---
            POSITION_THRESHOLD = 5 
            
            if total_positions > POSITION_THRESHOLD:
                visible_positions = ", ".join(position_list[:POSITION_THRESHOLD])
                # We put the rest of the list in a simple <div> inside <details>
                # It will be hidden by default but still copied
                hidden_positions = ", ".join(position_list[POSITION_THRESHOLD:])
                
                position_html = (
                    f'<details style="cursor: pointer;">'
                    f'<summary>{visible_positions} ... ({total_positions} total)</summary>'
                    f'<div style="padding-top: 8px; user-select: all;">{hidden_positions}</div>'
                    f'</details>'
                )
            else:
                position_html = ", ".join(position_list)
            # --- End of New Logic ---

            html.append(
                f'<tr><th scope="row">{label}</th><td>{count}</td><td>{position_html}</td></tr>'
            )
        else:
            # Data is a simple value: 11
            count = data
            if count == 0:
                continue
            html.append(
                f'<tr><th scope="row">{label}</th><td>{count}</td></tr>'
            )
            
    element = document.getElementById(element_id)
    if element:
        element.innerHTML = "".join(html) if html else "<tr><td colspan='3' class='placeholder-text'>No data.</td></tr>"

def render_ccc_table(stats_dict, element_id):
    """Renders the 3-column Canonical Combining Class table."""
    html = []
    element = document.getElementById(element_id)
    if not element: return

    sorted_keys = sorted(stats_dict.keys())
    
    if not sorted_keys:
        element.innerHTML = "<tr><td colspan='3' class='placeholder-text'>No data.</td></tr>"
        return

    for key in sorted_keys:
        count = stats_dict[key]
        if count == 0:
            continue
        
        # key is "ccc=220", extract "220"
        class_num = key.split('=')[-1]
        # Get the description, or a simple dash as a fallback
        description = CCC_ALIASES.get(class_num, "N/A")
        
        # Add inline style to 3rd column to override blue color
        html.append(
            f'<tr>'
            f'<th scope="row">{key}</th>'
            f'<td>{count}</td>'
            f'<td style="color: var(--color-text-muted); font-weight: normal; font-family: var(--font-sans);">{description}</td>'
            f'</tr>'
        )
    
    element.innerHTML = "".join(html)

def render_toc_counts(counts):
    """Updates the counts in the sticky Table of Contents."""
    document.getElementById("toc-dual-count").innerText = f"({counts.get('dual', 0)})"
    document.getElementById("toc-shape-count").innerText = f"({counts.get('shape', 0)})"
    document.getElementById("toc-integrity-count").innerText = f"({counts.get('integrity', 0)})"
    document.getElementById("toc-prov-count").innerText = f"({counts.get('prov', 0)})"
    document.getElementById("toc-emoji-count").innerText = f"({counts.get('emoji', 0)})"
    document.getElementById("toc-threat-count").innerText = f"({counts.get('threat', 0)})"

# ---
# 5. MAIN ORCHESTRATOR
# ---
    
@create_proxy
def inspect_character(event):
    """
    Called on 'selectionchange'. Inspects the character under the cursor.
    """
    try:
        text_input = document.getElementById("text-input")
        pos = text_input.selectionStart
        
        # Only run if selection is a single cursor (not a range)
        if pos != text_input.selectionEnd:
            return

        text = text_input.value
        if pos >= len(text):
            # Cursor is at the end, nothing to inspect
            render_inspector_panel(None)
            return
            
        char = text[pos]
        cp = ord(char)

        # Handle astral plane characters (surrogate pairs)
        if 0xD800 <= cp <= 0xDBFF and pos + 1 < len(text):
            cp_low = ord(text[pos+1])
            if 0xDC00 <= cp_low <= 0xDFFF:
                cp = 0x10000 + (((cp - 0xD800) << 10) | (cp_low - 0xDC00))
                char = char + text[pos+1] # The character is the pair

        # --- FIXES APPLIED HERE ---
        minor_cat_abbr = unicodedata.category(char)
        
        data = {
            "char": char,
            "cp_hex": f"U+{cp:04X}",
            "cp_dec": cp,
            "name": unicodedata.name(char, "No Name Found"),
            "block": _find_in_ranges(cp, "Blocks") or "N/A",
            "age": _find_in_ranges(cp, "Age") or "N/A", # <--- FIX 1: Changed "DerivedAge" to "Age"
            "script": _find_in_ranges(cp, "Scripts") or "N/A",
            "category_minor": ALIASES.get(minor_cat_abbr, minor_cat_abbr), # <--- FIX 2: Using ALIASES for minor category name
            "bidi_class": unicodedata.bidirectional(char) or "N/A", # <--- FIX 3: Using standard Python func for bidi
            "line_break": _find_in_ranges(cp, "LineBreak") or "N/A",
            "word_break": _find_in_ranges(cp, "WordBreak") or "N/A",
            "sentence_break": _find_in_ranges(cp, "SentenceBreak") or "N/A",
            "grapheme_break": _find_in_ranges(cp, "GraphemeBreak") or "N/A",
        }
        # --- END FIXES ---
        
        render_inspector_panel(data)
        
    except Exception as e:
        print(f"Inspector Error: {e}")
        render_inspector_panel({"error": str(e)})

def render_inspector_panel(data):
    """
    Renders the HTML for the Character Inspector panel.
    """
    panel = document.getElementById("inspector-panel-content")
    if not panel:
        return

    if data is None:
        panel.innerHTML = "<p>Click within the text input. Properties will be shown for the character immediately to the right of the cursor.</p>"
        return
        
    if "error" in data:
        panel.innerHTML = f"<p>Error: {data['error']}</p>"
        return

    html = [
        f'<h2>{data["char"]}</h2>',
        '<dl class="inspector-grid">',
        f'<dt>Code Point</dt><dd>{data["cp_hex"]} (Decimal: {data["cp_dec"]})</dd>',
        f'<dt>Name</dt><dd>{data["name"]}</dd>',
        f'<dt>Block</dt><dd>{data["block"]}</dd>',
        f'<dt>Age</dt><dd>{data["age"]}</dd>',
        f'<dt>Script</dt><dd>{data["script"]}</dd>',
        f'<dt>Category</dt><dd>{data["category_minor"]}</dd>',
        f'<dt>Bidi Class</dt><dd>{data["bidi_class"]}</dd>',
        f'<dt>Line Break</dt><dd>{data["line_break"]}</dd>',
        f'<dt>Word Break</dt><dd>{data["word_break"]}</dd>',
        f'<dt>Sentence Break</dt><dd>{data["sentence_break"]}</dd>',
        f'<dt>Grapheme Break</dt><dd>{data["grapheme_break"]}</dd>',
        '</dl>'
    ]
    panel.innerHTML = "".join(html)

@create_proxy
def update_all(event=None):
    """The main function called on every input change."""

    from js import console
    try:
        # We will check two things:
        # 1. A store that loads early (Blocks)
        # 2. A store that loads late (Confusables)
        blocks_len = len(DATA_STORES.get("Blocks", {}).get("ranges", []))
        confusables_len = len(DATA_STORES.get("Confusables", {}))
        
        console.log(f"--- DEBUG (update_all) ---")
        console.log(f"Interpreter ID: {id(DATA_STORES)}")
        console.log(f"Live 'Blocks' range count: {blocks_len}")
        console.log(f"Live 'Confusables' map count: {confusables_len}")
        console.log(f"----------------------------")
    except Exception as e:
        console.log(f"--- DEBUG ERROR ---: {e}")
    
    """The main function called on every input change."""
    
    t = document.getElementById("text-input").value
    
    if not t:
        # Render empty state
        render_cards({}, "meta-totals-cards")
        render_cards({}, "grapheme-integrity-cards")
        render_matrix_table({}, "ccc-matrix-body")
        render_parallel_table({}, {}, "major-parallel-body")
        render_parallel_table({}, {}, "minor-parallel-body", ALIASES)
        render_matrix_table({}, "shape-matrix-body")
        render_matrix_table({}, "integrity-matrix-body", has_positions=True)
        render_matrix_table({}, "provenance-matrix-body")
        render_matrix_table({}, "linebreak-run-matrix-body")
        render_matrix_table({}, "bidi-run-matrix-body")
        render_matrix_table({}, "wordbreak-run-matrix-body")
        render_matrix_table({}, "sentencebreak-run-matrix-body")
        render_matrix_table({}, "graphemebreak-run-matrix-body")
        render_matrix_table({}, "eawidth-run-matrix-body")
        render_matrix_table({}, "vo-run-matrix-body")
        render_emoji_qualification_table([])
        render_emoji_summary({}, [])
        render_threat_analysis({}) 
        
        render_toc_counts({})
        return

    # --- 1. Run All Computations ---

    emoji_report = compute_emoji_analysis(t)
    emoji_counts = emoji_report.get("counts", {})
    emoji_flags = emoji_report.get("flags", {})
    emoji_list = emoji_report.get("emoji_list", [])
    
    # Module 2.A: Dual-Atom Fingerprint
    cp_summary, cp_major, cp_minor = compute_code_point_stats(t, emoji_counts)
    gr_summary, gr_major, gr_minor, grapheme_forensics = compute_grapheme_stats(t)
    ccc_stats = compute_combining_class_stats(t)
    
    # Module 2.B: Structural Shape
    major_seq_stats = compute_sequence_stats(t)
    minor_seq_stats = compute_minor_sequence_stats(t)
    lb_run_stats = compute_linebreak_analysis(t)
    bidi_run_stats = compute_bidi_class_analysis(t)
    wb_run_stats = compute_wordbreak_analysis(t)
    sb_run_stats = compute_sentencebreak_analysis(t)
    gb_run_stats = compute_graphemebreak_analysis(t)
    eaw_run_stats = compute_eastasianwidth_analysis(t)
    vo_run_stats = compute_verticalorientation_analysis(t)

    # --- NEW: DIAGNOSTIC LOGGING ---
    # print("--- DEBUGGING BIDI ---")
    # print(f"BIDI STATS: {bidi_run_stats}")
    # print(f"BIDI ELEMENT EXISTS: {bool(document.getElementById('bidi-run-matrix-body'))}")
    # print("------------------------")

   
    # Module 2.C: Forensic Integrity
    # Module 2.C: Forensic Integrity
    forensic_stats = compute_forensic_stats_with_positions(t, cp_minor)
    # NOTE:
    # - We no longer inject lone ZWJ into the Emoji Qualification table here.
    # - We also keep emoji_flags separate from the forensic integrity matrix.
    
    # Module 2.D: Provenance & Context
    provenance_stats = compute_provenance_stats(t)
    script_run_stats = compute_script_run_analysis(t)

    # Module 3: Threat-Hunting
    threat_results = compute_threat_analysis(t)

    # --- NEW: Pass the full data object to JavaScript ---
    # This allows ui-glue.js to read the raw/skeleton strings directly
    window.latest_threat_data = threat_results
    
    # --- 2. Prepare Data for Renderers ---
    
    # 2.A
    meta_cards = {
        "Total Code Points": cp_summary.get("Total Code Points", 0),
        "Total Graphemes": gr_summary.get("Total Graphemes", 0),
        "RGI Emoji Sequences": emoji_counts.get("RGI Emoji Sequences", 0),
        "Whitespace (Total)": cp_summary.get("Whitespace (Total)", 0),
        # --- NEW: Repertoire Stats ---
        # We pass the whole dict, render_cards will handle it
        "ASCII-Compatible": cp_summary.get("ASCII-Compatible"),
        "Latin-1-Compatible": cp_summary.get("Latin-1-Compatible"),
        "BMP Coverage": cp_summary.get("BMP Coverage"),
        "Supplementary Planes": cp_summary.get("Supplementary Planes"),
    }
    # Define the exact display order for the cards
    meta_cards_order = [
        "Total Code Points",
        "Total Graphemes",
        "RGI Emoji Sequences",
        "Whitespace (Total)",
        # --- NEW: Repertoire Order ---
        "ASCII-Compatible",
        "Latin-1-Compatible",
        "BMP Coverage",
        "Supplementary Planes"
    ]
    grapheme_cards = grapheme_forensics
    
    # 2.B
    shape_matrix = major_seq_stats
    
    # 2.C
    forensic_matrix = forensic_stats
    
    # 2.D
    prov_matrix = provenance_stats

    threat_flags = threat_results.get('flags', {})

    # 1) Invalid variation selectors come from forensic (structural) analysis
    invalid_vs_flag = forensic_matrix.get("Flag: Invalid Variation Selector", {})
    if invalid_vs_flag.get("count", 0) > 0:
        threat_flags["Suspicious: Invalid Variation Selectors"] = invalid_vs_flag
    
    # 2) Unqualified emoji comes from the emoji engine (emoji_flags)
    unqualified_emoji_flag = emoji_flags.get("Flag: Unqualified Emoji", {})
    if unqualified_emoji_flag.get("count", 0) > 0:
        threat_flags["Suspicious: Unqualified Emoji"] = unqualified_emoji_flag
    
    # 3) Lone ZWJ still comes from the structural integrity profile
    zwj_flag = forensic_matrix.get("Join Control (Structural)", {})
    if zwj_flag.get("count", 0) > 0:
        threat_flags["Suspicious: Join Control Present (ZWJ)"] = zwj_flag

    # --- NEW: Manually add our new emoji flags to the Threat table ---
    new_emoji_flags = {
        "Flag: Broken Keycap Sequence": "Suspicious: Broken Keycap",
        "Flag: Invalid Regional Indicator": "Suspicious: Invalid Regional Indicator",
        "Flag: Forced Emoji Presentation": "Suspicious: Forced Emoji",
        "Flag: Intent-Modifying ZWJ": "Suspicious: Intent-Modifying ZWJ"
    }

    for flag_key, threat_label in new_emoji_flags.items():
        flag_data = emoji_flags.get(flag_key, {})
        if flag_data.get("count", 0) > 0:
            threat_flags[threat_label] = flag_data

    
    # TOC Counts (count non-zero entries)
    toc_counts = {
        'dual': sum(1 for v in meta_cards.values() if (isinstance(v, (int, float)) and v > 0) or (isinstance(v, dict) and v.get('count', 0) > 0)) + sum(1 for v in grapheme_cards.values() if v > 0) + sum(1 for k in set(cp_major.keys()) | set(gr_major.keys()) if cp_major.get(k, 0) > 0 or gr_major.get(k, 0) > 0),
        'shape': sum(1 for v in shape_matrix.values() if v > 0) + sum(1 for v in minor_seq_stats.values() if v > 0) + sum(1 for v in lb_run_stats.values() if v > 0) + sum(1 for v in bidi_run_stats.values() if v > 0) + sum(1 for v in wb_run_stats.values() if v > 0) + sum(1 for v in sb_run_stats.values() if v > 0) + sum(1 for v in gb_run_stats.values() if v > 0) + sum(1 for v in eaw_run_stats.values() if v > 0) + sum(1 for v in vo_run_stats.values() if v > 0),
        'integrity': sum(1 for v in forensic_matrix.values() if v.get('count', 0) > 0),
        'prov': sum(1 for v in prov_matrix.values() if v.get('count', 0) > 0) + sum(1 for v in script_run_stats.values() if v.get('count', 0) > 0),
        'emoji': meta_cards.get("RGI Emoji Sequences", 0),
        'threat': sum(1 for v in threat_results.get('flags', {}).values() if (isinstance(v, dict) and v.get('count', 0) > 0) or (isinstance(v, int) and v > 0))
    }
    
    # --- 3. Call All Renderers ---
    
    # Render 2.A
    render_cards(meta_cards, "meta-totals-cards", key_order=meta_cards_order)
    render_cards(grapheme_cards, "grapheme-integrity-cards")
    render_ccc_table(ccc_stats, "ccc-matrix-body")
    render_parallel_table(cp_major, gr_major, "major-parallel-body")
    render_parallel_table(cp_minor, gr_minor, "minor-parallel-body", ALIASES)
    
    # Render 2.B
    render_matrix_table(shape_matrix, "shape-matrix-body")
    render_matrix_table(minor_seq_stats, "minor-shape-matrix-body", aliases=ALIASES)
    render_matrix_table(lb_run_stats, "linebreak-run-matrix-body")
    render_matrix_table(bidi_run_stats, "bidi-run-matrix-body")
    render_matrix_table(wb_run_stats, "wordbreak-run-matrix-body")
    render_matrix_table(sb_run_stats, "sentencebreak-run-matrix-body")
    render_matrix_table(gb_run_stats, "graphemebreak-run-matrix-body")
    render_matrix_table(eaw_run_stats, "eawidth-run-matrix-body")
    render_matrix_table(vo_run_stats, "vo-run-matrix-body")
    
    # Render 2.C
    render_matrix_table(forensic_matrix, "integrity-matrix-body", has_positions=True)
    
    # Render 2.D
    render_matrix_table(prov_matrix, "provenance-matrix-body", has_positions=True)
    render_matrix_table(script_run_stats, "script-run-matrix-body", has_positions=True)
    #render_matrix_table(emoji_qualification_stats, "emoji-qualification-body", has_positions=True)

    render_emoji_qualification_table(emoji_list)
    render_emoji_summary(emoji_counts, emoji_list)

    # Render 3
    render_threat_analysis(threat_results)
    
    # Render TOC
    render_toc_counts(toc_counts)

# --- NEW: Package data for Stage 2 ---
    try:
        # 1. Get grapheme segments (for segmentation)
        segments_iterable = GRAPHEME_SEGMENTER.segment(t)
        grapheme_list = [seg.segment for seg in window.Array.from_(segments_iterable)]
        
        # 2. Get forensic flags (for threat counting)
        all_flags = forensic_stats
        all_flags.update(emoji_flags) # Combine structural and emoji flags

        # 3. Get normalized text (for TTR)
        nfkc_cf_text = threat_results.get('nfkc_cf', "")
        
        # 4. ***NEW*** Get UAX Break properties (for word/sentence counting)
        wb_props, sb_props = _get_codepoint_properties(t)
        
        # 5. Expose all core data to the JavaScript window
        core_data = {
            "raw_text": t,
            "grapheme_list": grapheme_list,
            "grapheme_lengths_codepoints": [len(g) for g in grapheme_list], # Crucial for mapping
            "forensic_flags": all_flags,
            "nfkc_casefold_text": nfkc_cf_text,
            # Stage 2 loads its own WB/SB properties, so we don't send them
            "timestamp": window.Date.new().toISOString()
        }

        # Convert the Python dict to a true JavaScript object (deep conversion)
        core_data_js = to_js(core_data, dict_converter=window.Object.fromEntries)
        window.TEXTTICS_CORE_DATA = core_data_js

        print("Stage 1 data exported for Stage 2.")
    except Exception as e:
        print(f"Error packaging data for Stage 2: {e}")
    # --- End of new block ---

@create_proxy
def reveal_invisibles(event=None):
    """
    Replaces invisible/control characters in the input with visible tags.
    Triggered by the 'Reveal Invisibles' button.
    """
    element = document.getElementById("text-input")
    if not element: return
    
    raw_text = element.value
    if not raw_text: return

    # Build the new string
    new_chars = []
    replaced_count = 0
    
    for char in raw_text:
        cp = ord(char)
        
        # Check explicit mapping
        if cp in INVISIBLE_MAPPING:
            new_chars.append(INVISIBLE_MAPPING[cp])
            replaced_count += 1
            
        # Check Variation Selectors (VS1 - VS16)
        elif 0xFE00 <= cp <= 0xFE0F:
            vs_num = cp - 0xFE00 + 1
            new_chars.append(f"[VS{vs_num}]")
            replaced_count += 1
            
        # Check Variation Selectors Supplement (VS17 - VS256)
        elif 0xE0100 <= cp <= 0xE01EF:
            vs_num = cp - 0xE0100 + 17
            new_chars.append(f"[VS{vs_num}]")
            replaced_count += 1
            
        # Check Tag Characters (Plane 14)
        elif 0xE0000 <= cp <= 0xE007F:
             new_chars.append(f"[TAG:U+{cp:04X}]")
             replaced_count += 1
             
        else:
            new_chars.append(char)
            
    if replaced_count > 0:
        new_text = "".join(new_chars)
        element.value = new_text
        
        # Update the status line to confirm action
        render_status(f"Deobfuscation complete. Revealed {replaced_count} invisible characters.")
        
        # TRIGGER A RE-ANALYSIS manually
        # This is crucial so the metrics update to reflect the "safe" text
        update_all(None)
    else:
        render_status("No invisible characters found to reveal.")

# ---
# 6. INITIALIZATION
# ---

# [THIS IS IN app.py]

async def main():
    """Main entry point: Loads data, then hooks the input."""
    
    # --- FIX 1: Get element first ---
    text_input_element = document.getElementById("text-input")
    
    # Start loading the external data and wait for it to finish.
    await load_unicode_data()
    
    # --- FIX 2: Bind listener *after* await ---
    # This ensures the listener is bound in the SAME interpreter
    # that just loaded the data.
    text_input_element.addEventListener("input", update_all)
    
    # --- NEW: Hook the Inspector Panel ---
    # We listen on the *document* because 'selectionchange' fires on the document
    document.addEventListener("selectionchange", create_proxy(inspect_character))

    # --- NEW: Hook the Reveal Button ---
    reveal_btn = document.getElementById("btn-reveal")
    if reveal_btn:
        reveal_btn.addEventListener("click", reveal_invisibles)
    
    # --- FIX 3: Un-gate the UI ---
    # Now that the listener is bound and data is loaded,
    # enable the text area for the user.
    text_input_element.disabled = False
    text_input_element.placeholder = "Paste or type here..."
    print("Text...tics is ready.") # A good sign to see in the console

# Start the main asynchronous task
asyncio.ensure_future(main())
