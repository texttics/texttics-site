import asyncio
import json
import unicodedata
from pyodide.ffi import create_proxy, to_js
from pyodide.http import pyfetch
from pyscript import document, window
import hashlib
import re
import math
import collections
from collections import Counter
import urllib.parse
import base64
import binascii
import difflib
import bisect
import html
from html.parser import HTMLParser
from typing import List, Dict, Set, Optional, Tuple, Any
from js import window, document

# ==========================================
# BLOCK 1. GLOBAL CONFIG & ENVIRONMENT
# ==========================================

LOADING_LOCK = False
LOADING_STATE = "PENDING"  # PENDING, LOADING, READY, FAILED

# --- DEBUG FLAGS ---
TEXTTICS_DEBUG_THREAT_BRIDGE = True

# --- NORMALIZATION LIBRARY SETUP (Tier 1 vs Tier 2) ---
# We check this ONCE at startup, not every time we normalize a string.
try:
    import unicodedata2 as _ud
    NORMALIZER = "unicodedata2"
    print("LOG: Using full 'unicodedata2' library (C-Optimized).")
except Exception:
    import unicodedata as _ud
    NORMALIZER = "unicodedata"
    print("LOG: Using standard 'unicodedata' library (Fallback).")

# Defining the 'ud' alias globally so functions using it don't crash
ud = _ud

def _debug_threat_bridge(t: str, hit: tuple):
    """
    Non-invasive auditor for the Python->DOM selection bridge.
    Checks if logical indices (from Registry) map validly to DOM UTF-16 offsets.
    Logs failures to console but DOES NOT modify state.
    """
    log_start, log_end = hit[0], hit[1]
    log_len = len(t)
    
    # 1. Check Logical Bounds
    if log_start < 0 or log_end > log_len:
        print(f"[ThreatBridge-AUDIT] FAIL: Logical Hit {log_start}-{log_end} out of bounds (len={log_len})")
        return

    # 2. Simulate Mapping
    dom_start = -1
    dom_end = -1
    acc = 0
    
    # Iterate full string to validate mapping
    for i, char in enumerate(t):
        if i == log_start: dom_start = acc
        if i == log_end: dom_end = acc
        acc += (2 if ord(char) > 0xFFFF else 1)
    
    # Handle end-of-string edge case
    if dom_end == -1 and log_end == log_len:
        dom_end = acc
        
    dom_len = acc

    # 3. Report Findings
    if dom_start == -1 or dom_end == -1:
        print(f"[ThreatBridge-AUDIT] FAIL: Mapping failed for {log_start}-{log_end}. DOM len={dom_len}.")
    else:
        # Valid mapping
        snippet = t[log_start:min(log_start+5, log_len)]
        # Optional: Print snippet hex to verify content identity
        hex_snip = " ".join(f"{ord(c):04X}" for c in snippet)
        print(f"[ThreatBridge-AUDIT] OK: Log {log_start}-{log_end} -> DOM {dom_start}-{dom_end}. Snip: '{snippet}' ({hex_snip})")

# ===============================================
# BLOCK 2. THE PHYSICS (BITMASKS & CONSTANTS)
# ===============================================

# The "Persian Defense" Whitelist (Complex Orthography Scripts)
# These scripts legitimately use ZWJ/ZWNJ for shaping.
# We must NOT flag "Token Fracture" in these contexts.
COMPLEX_ORTHOGRAPHY_SCRIPTS = {
    "Arabic", "Syriac", "Nko", "Thaana", "Mandaic",
    "Mongolian", "Phags_Pa", "Devanagari", "Bengali", 
    "Gurmukhi", "Gujarati", "Oriya", "Tamil", "Telugu", 
    "Kannada", "Malayalam", "Sinhala", "Thai", "Lao", 
    "Tibetan", "Myanmar", "Khmer", "Adlam", "Rohingya"
}

# Injection Pattern RegEx (Source 1: Web Search Exfiltration)
# High-fidelity patterns for "System Prompt Override" and "Tool Chaining"
INJECTION_PATTERNS = {
    "OVERRIDE": re.compile(
        r"(ignore|forget)\s+(all\s+)?(previous|prior)\s+(instructions|commands|directions)|"
        r"you\s+are\s+now\s+(configured|in|acting\s+as)|"
        r"system\s+prompt\s+override", 
        re.IGNORECASE
    ),
    "TOOL_CHAIN": re.compile(
        r"(use|call|invoke)\s+(the\s+)?(web\s+search|browser|http|curl|wget).*(then|and)\s+(send|upload|post|exfiltrate)",
        re.IGNORECASE
    ),
    "ANSI_ESCAPE": re.compile(
        r"\x1b\[[0-9;]*[a-zA-Z]" 
    )
}

# Contextual Lure Patterns (Source: Trust No AI - Exfiltration & Persistence)
CONTEXT_LURE_PATTERNS = {
    # Detects automatic data exfiltration via image rendering: ![alt](url)
    "MARKDOWN_IMAGE": re.compile(r"!\[.*?\]\(.*?\)"),
    
    # Detects ChatML/Llama/Alpaca special tokens used to fake conversation history
    "CHAT_HEADER": re.compile(
        r"(<\|im_start\|>|<\|im_end\|>|\[INST\]|\[/INST\]|<\|system\|>|<\|user\|>|<\|assistant\|>)",
        re.IGNORECASE
    ),
    
    # Detects instructions targeting Long-Term Memory (SpAIware)
    "MEMORY_DIRECTIVE": re.compile(
        r"(remember\s+that|add\s+to\s+(my\s+)?bio|store\s+in\s+memory|always\s+reply\s+with|core\s+memory)",
        re.IGNORECASE
    )
}

# Domain Spoofing Artifacts (Source 2: IDN Masquerading)
# Characters that mimic structural delimiters (Dots, Slashes, At-signs)
PSEUDO_DELIMITERS = {
    0x2024: "One Dot Leader",
    0x2025: "Two Dot Leader",
    0x2026: "Ellipsis",
    0x3002: "Ideographic Full Stop",
    0xFF0E: "Fullwidth Full Stop",
    0x0589: "Armenian Full Stop",
    0x06D4: "Arabic Full Stop",
    0x2044: "Fraction Slash",
    0x2215: "Division Slash",
    0xFF0F: "Fullwidth Solidus",
    0xFF20: "Fullwidth Commercial At"
}

# 4. Plane 14 Tag Block (Source 1 & 3: Phantom Text)
TAG_BLOCK_START = 0xE0000
TAG_BLOCK_END = 0xE007F

# --- INVISIBILITY BITMASKS (Forensic Grade) ---
INVIS_DEFAULT_IGNORABLE  = 1 << 0
INVIS_JOIN_CONTROL       = 1 << 1
INVIS_ZERO_WIDTH_SPACING = 1 << 2  # ZWSP, WJ, BOM
INVIS_BIDI_CONTROL       = 1 << 3
INVIS_TAG                = 1 << 4
INVIS_VARIATION_STANDARD = 1 << 5
INVIS_VARIATION_IDEOG    = 1 << 6
INVIS_DO_NOT_EMIT        = 1 << 7
INVIS_SOFT_HYPHEN        = 1 << 8
INVIS_NON_ASCII_SPACE    = 1 << 9
INVIS_NONSTANDARD_NL     = 1 << 10

# 1. A new bit flag for Critical Controls
INVIS_CRITICAL_CONTROL   = 1 << 11

INVIS_VARIATION_SELECTOR = INVIS_VARIATION_STANDARD | INVIS_VARIATION_IDEOG

# Aggregates
INVIS_ANY_MASK = (
    INVIS_DEFAULT_IGNORABLE | INVIS_JOIN_CONTROL | INVIS_ZERO_WIDTH_SPACING |
    INVIS_BIDI_CONTROL | INVIS_TAG | INVIS_VARIATION_STANDARD |
    INVIS_VARIATION_IDEOG | INVIS_DO_NOT_EMIT | INVIS_SOFT_HYPHEN |
    INVIS_NON_ASCII_SPACE | INVIS_NONSTANDARD_NL | INVIS_CRITICAL_CONTROL
)
INVIS_HIGH_RISK_MASK = INVIS_BIDI_CONTROL | INVIS_TAG | INVIS_DO_NOT_EMIT

# The O(1) Lookup Table (Populated in load_unicode_data)
INVIS_TABLE = [0] * 1114112  # Covers all of Unicode (0x110000)

# --- FORENSIC ENCODING PROFILES ---
# Tier 0 (Modern) + Tier 1 (Legacy)
FORENSIC_ENCODINGS = [
    # --- TIER 0: MODERN ANCHORS (Reference) ---
    ("UTF-8", "utf_8", "Universal Web Standard"),
    ("UTF-16", "utf_16", "Windows/JavaScript Native"),
    ("UTF-32", "utf_32", "True Code Point Storage"),
    
    # --- TIER 1: LEGACY FILTERS (Provenance) ---
    ("ASCII", "ascii", "Universal Baseline (7-bit)"),
    ("Win-1252", "cp1252", "Western / Windows (ANSI)"),
    ("ISO-8859-1", "latin_1", "Western / Strict Protocol"),
    ("MacRoman", "mac_roman", "Legacy Apple / Classic Mac"),
    ("CP437", "cp437", "DOS / Terminal / Warez Art"),
    ("Win-1251", "cp1251", "Cyrillic Legacy"),
    ("Win-1256", "cp1256", "Arabic Legacy"),
    ("Win-1253", "cp1253", "Greek Legacy"),
    ("Win-1255", "cp1255", "Hebrew Legacy"),
    ("Shift_JIS", "shift_jis", "Japanese Legacy"),
    ("Big5", "big5", "Traditional Chinese"),
    ("EUC-KR", "euc_kr", "Korean Legacy"),
    ("GBK", "gbk", "Simp. Chinese Legacy")
]

# --- FORENSIC THREAT VOCABULARY (Seed List) ---
# Derived from SecLists, FuzzDB, and LLM Jailbreak research.
# Used to detect re-assembled fragmentation attacks (e.g. "s h e l l").

THREAT_VOCAB = {
    "EXECUTION": {
        "sh", "bash", "zsh", "ksh", "cmd", "powershell", "pwsh", "shell", "webshell",
        "python", "python3", "php", "perl", "ruby", "node", "java", "javac", "dotnet",
        "system", "exec", "execute", "spawn", "eval", "compile", "popen", "subprocess",
        "runtime", "processbuilder", "nc", "netcat", "telnet", "ssh", "sftp", 
        "curl", "wget", "invoke-webrequest", "iex", "iwr"
    },
    "AUTH": {
        "admin", "administrator", "root", "sudo", "user", "username", "login", "logon",
        "signin", "signup", "password", "passwd", "passphrase", "pin", "token", 
        "access_token", "refresh_token", "apikey", "secret", "client_secret", 
        "session", "sessionid", "cookie", "jwt", "bearer", "credential", "auth"
    },
    "INJECTION": {
        "script", "javascript", "alert", "onerror", "onclick", "onload", "iframe", 
        "document.cookie", "innerhtml", "select", "insert", "update", "delete", 
        "drop", "truncate", "union", "load_file", "xp_cmdshell"
    },
    "JAILBREAK": {
        "ignore", "previous", "instructions", "forget", "override", "bypass", 
        "developer", "mode", "uncensored", "dan", "jailbreak", "guidelines",
        "constraints", "ethical", "rules"
    },
    "SYSTEM": {
        "bin", "sbin", "usr", "var", "tmp", "etc", "passwd", "shadow", "hosts",
        "boot", "ini", "cfg", "config", "registry", "regedit"
    }
}

# Flatten for O(1) lookup
ALL_THREAT_TERMS = set().union(*THREAT_VOCAB.values())


# CATEGORY & REGEX DEFINITIONS. We only use "Honest" mode, so we only need the 29 categories
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

    # [PATCH] Missing Structural Invisible (Zanabazar)
    0x11A3E: "[ZAN:INIT]",     # Zanabazar Square Cluster Initial

    # [PATCH] Missing Specials (Reserved Sentinels)
    0xFFF0: "[RSV:FFF0]", 0xFFF1: "[RSV:FFF1]", 0xFFF2: "[RSV:FFF2]",
    0xFFF3: "[RSV:FFF3]", 0xFFF4: "[RSV:FFF4]", 0xFFF5: "[RSV:FFF5]",
    0xFFF6: "[RSV:FFF6]", 0xFFF7: "[RSV:FFF7]", 0xFFF8: "[RSV:FFF8]",

    # --- Missing Egyptian Hieroglyph Format Controls (Extended) ---
    0x1343C: "[EGY:C1]",       # Egyptian Control 1
    0x1343D: "[EGY:C2]",       # Egyptian Control 2
    0x1343E: "[EGY:C3]",       # Egyptian Control 3
    0x1343F: "[EGY:C4]",       # Egyptian Control 4

    # --- Missing Shorthand Format Controls (Extended) ---
    0x1BCA4: "[SHORT:STEP]",   # Shorthand Format Step
    0x1BCA5: "[SHORT:MIN]",    # Shorthand Format Minus
    0x1BCA6: "[SHORT:DBL]",    # Shorthand Format Double
    0x1BCA7: "[SHORT:CONT]",   # Shorthand Format Continued
    0x1BCA8: "[SHORT:DOWN]",   # Shorthand Format Down
    0x1BCA9: "[SHORT:UP]",     # Shorthand Format Up
    0x1BCAA: "[SHORT:HIGH]",   # Shorthand Format High
    0x1BCAB: "[SHORT:LOW]",    # Shorthand Format Low
    0x1BCAC: "[SHORT:MED]",    # Shorthand Format Medium
    0x1BCAD: "[SHORT:VAR1]",   # Shorthand Format Variation 1
    0x1BCAE: "[SHORT:VAR2]",   # Shorthand Format Variation 2

    # --- Unicode "Specials" (Process-Internal Noncharacters) ---
    0xFFFE: "[BAD:BOM]",       # Reversed Byte Order Mark (Endian mismatch)
    0xFFFF: "[NON:MAX]",       # Max Value (Process internal)

    # --- Missing Arabic & Syriac Format Controls ---
    0x0600: "[ARB:NUM]",       # Arabic Number Sign
    0x0601: "[ARB:YEAR]",      # Arabic Sign Sanah
    0x0602: "[ARB:FOOT]",      # Arabic Footnote Marker
    0x0603: "[ARB:PAGE]",      # Arabic Sign Safha
    0x0604: "[ARB:SAMV]",      # Arabic Sign Samvat
    0x0605: "[ARB:ABV]",       # Arabic Number Mark Above
    0x06DD: "[ARB:AYAH]",      # Arabic End of Ayah
    0x08E2: "[ARB:DISP]",      # Arabic Disputed End of Ayah
    0x070F: "[SYR:SAM]",       # Syriac Abbreviation Mark

    # --- Missing Duployan Format Controls ---
    0x1BC9D: "[DUP:THICK]",    # Duployan Thick Letter Selector
    0x1BC9E: "[DUP:DBL]",      # Duployan Double Mark

    # --- Missing Egyptian Hieroglyph Extensions ---
    0x13439: "[EGY:INS_S]",    # Insertion Joiner Start
    0x1343A: "[EGY:INS_E]",    # Insertion Joiner End
    0x1343B: "[EGY:MID]",      # Stack Middle

    # --- Historic Script Fillers & Joiners (Format Controls) ---
    0x11C40: "[BHAIK:GAP]",    # Bhaiksuki Gap Filler
    0x11A47: "[ZAN:SUB]",      # Zanabazar Square Subjoiner (Invisible Glue)
    0x11A99: "[SOY:SUB]",      # Soyombo Subjoiner (Invisible Glue)
    0x1107F: "[BRAH:NJ]",      # Brahmi Number Joiner
    0x110BD: "[KAI:NS]",       # Kaithi Number Sign
    0x110CD: "[KAI:NSA]",      # Kaithi Number Sign Above
    0x11446: "[NEWA:SAN]",     # Newa Sandhi Mark (Invisible Elision)
    
    # --- System & Control Risks ---
    0x0000: "[NUL]",           # Null Byte (Critical)
    0x001B: "[ESC]",           # Escape (Terminal Injection)
    0x00AD: "[SHY]",           # Soft Hyphen
    
    # --- Bidi Controls (Trojan Source) ---
    0x061C: "[ALM]",           # Arabic Letter Mark
    0x200E: "[LRM]",           # Left-To-Right Mark
    0x200F: "[RLM]",           # Right-To-Left Mark
    0x202A: "[LRE]",           # Left-To-Right Embedding
    0x202B: "[RLE]",           # Right-To-Left Embedding
    0x202C: "[PDF]",           # Pop Directional Formatting
    0x202D: "[LRO]",           # Left-To-Right Override
    0x202E: "[RLO]",           # Right-To-Left Override
    0x2066: "[LRI]",           # Left-To-Right Isolate
    0x2067: "[RLI]",           # Right-To-Left Isolate
    0x2068: "[FSI]",           # First Strong Isolate
    0x2069: "[PDI]",           # Pop Directional Isolate

    # --- Joiners & Separators ---
    0x034F: "[CGJ]",           # Combining Grapheme Joiner
    0x180E: "[MVS]",           # Mongolian Vowel Separator
    0x200B: "[ZWSP]",          # Zero Width Space
    0x200C: "[ZWNJ]",          # Zero Width Non-Joiner
    0x200D: "[ZWJ]",           # Zero Width Joiner
    0x2060: "[WJ]",            # Word Joiner
    
    # --- Missing Mongolian FVS4 ---
    0x180F: "[FVS4]",          # Mongolian Free Variation Selector 4

    # --- Missing Khitan Filler (Critical Spoofing Vector) ---
    0x16FE4: "[KSSF]",         # Khitan Small Script Filler
    
    # --- Byte Order Mark ---
    0xFEFF: "[BOM]",           # Zero Width No-Break Space
    
    # --- Interlinear Annotation (Rare Format) ---
    0xFFF9: "[IAA]",           # Anchor
    0xFFFA: "[IAS]",           # Separator
    0xFFFB: "[IAT]",           # Terminator

    # --- Exotic Spaces (Visual Spoofing) ---
    0x00A0: "[NBSP]",          # No-Break Space
    0x2002: "[ENSP]",          # En Space
    0x2003: "[EMSP]",          # Em Space
    0x2004: "[3/EM]",          # Three-Per-Em Space
    0x2005: "[4/EM]",          # Four-Per-Em Space
    0x2006: "[6/EM]",          # Six-Per-Em Space
    0x2007: "[FIGSP]",         # Figure Space
    0x2008: "[PUNCSP]",        # Punctuation Space
    0x2009: "[THIN]",          # Thin Space
    0x200A: "[HAIR]",          # Hair Space
    0x202F: "[NNBSP]",         # Narrow No-Break Space
    0x205F: "[MMSP]",          # Medium Mathematical Space
    0x3000: "[IDSP]",          # Ideographic Space
    
    # --- Line Breaks ---
    0x2028: "[LS]",            # Line Separator
    0x2029: "[PS]",            # Paragraph Separator

    # --- Tags (Special) ---
    0xE0001: "[TAG:LANG]",     # Language Tag
    0xE007F: "[TAG:CANCEL]",   # Cancel Tag

    # 1. C0 Control Codes (Legacy/Obfuscation)
    0x0001: "[CTL:0x01]", 0x0002: "[CTL:0x02]", 0x0003: "[CTL:0x03]", 0x0004: "[CTL:0x04]",
    0x0005: "[CTL:0x05]", 0x0006: "[CTL:0x06]", 0x0007: "[CTL:0x07]", 0x0008: "[CTL:0x08]",
    0x000B: "[CTL:0x0B]", 0x000C: "[CTL:0x0C]", 0x000E: "[CTL:0x0E]", 0x000F: "[CTL:0x0F]",
    0x0010: "[CTL:0x10]", 0x0011: "[CTL:0x11]", 0x0012: "[CTL:0x12]", 0x0013: "[CTL:0x13]",
    0x0014: "[CTL:0x14]", 0x0015: "[CTL:0x15]", 0x0016: "[CTL:0x16]", 0x0017: "[CTL:0x17]",
    0x0018: "[CTL:0x18]", 0x0019: "[CTL:0x19]", 0x001A: "[CTL:0x1A]", 0x001C: "[CTL:0x1C]",
    0x001D: "[CTL:0x1D]", 0x001E: "[CTL:0x1E]", 0x001F: "[CTL:0x1F]",
    
    # 2. C1 Control Codes (Legacy/Obfuscation)
    0x007F: "[DEL]",      # Delete (Common mutation particle)
    0x0085: "[NEL]",      # Next Line (Often breaks parsers)
    # Range 0x80-0x9F
    0x0080: "[CTL:0x80]", 0x0081: "[CTL:0x81]", 0x0082: "[CTL:0x82]", 0x0083: "[CTL:0x83]",
    0x0084: "[CTL:0x84]", 0x0086: "[CTL:0x86]", 0x0087: "[CTL:0x87]", 0x0088: "[CTL:0x88]",
    0x0089: "[CTL:0x89]", 0x008A: "[CTL:0x8A]", 0x008B: "[CTL:0x8B]", 0x008C: "[CTL:0x8C]",
    0x008D: "[CTL:0x8D]", 0x008E: "[CTL:0x8E]", 0x008F: "[CTL:0x8F]", 0x0090: "[CTL:0x90]",
    0x0091: "[CTL:0x91]", 0x0092: "[CTL:0x92]", 0x0093: "[CTL:0x93]", 0x0094: "[CTL:0x94]",
    0x0095: "[CTL:0x95]", 0x0096: "[CTL:0x96]", 0x0097: "[CTL:0x97]", 0x0098: "[CTL:0x98]",
    0x0099: "[CTL:0x99]", 0x009A: "[CTL:0x9A]", 0x009B: "[CTL:0x9B]", 0x009C: "[CTL:0x9C]",
    0x009D: "[CTL:0x9D]", 0x009E: "[CTL:0x9E]", 0x009F: "[CTL:0x9F]",

    # Invisible Khmer Vowels (Fillers)
    0x17B4: "[KHM:AQ]",        # Khmer Vowel Inherent AQ
    0x17B5: "[KHM:AA]",        # Khmer Vowel Inherent AA
    
    # Invisible Math Operators
    0x2061: "[FA]",            # Function Application
    0x2062: "[IT]",            # Invisible Times
    0x2063: "[IS]",            # Invisible Separator
    # (U+2064 Invisible Plus was added in Wave 1)

    # The "Rich Text Ghost"
    0xFFFC: "[OBJ]",           # Object Replacement Character
    
    # Table 1: The "False Vacuums" (Hangul & Braille)
    # These characters are often rendered as invisible but possess width or distinct properties.
    0x3164: "[HF]",            # Hangul Filler (Critical ID spoofer)
    0xFFA0: "[HHF]",           # Halfwidth Hangul Filler
    0x115F: "[HCF]",           # Hangul Choseong Filler
    0x1160: "[HJF]",           # Hangul Jungseong Filler
    0x2800: "[BRAILLE]",       # Braille Pattern Blank (Critical Trim Bypass)

    # Table 2: Anomalous Spaces & Quads (Visual Alignment Spoofing)
    0x1680: "[OSM]",           # Ogham Space Mark
    0x2000: "[EQ]",            # En Quad
    0x2001: "[MQ]",            # Em Quad (M is standardized abbr)
    0x2007: "[FIGSP]",         # Figure Space (Non-breaking)
    # (Note: 0x2002-0x200A are often handled by general whitespace logic, but 2007/EQ/MQ are specific)

    # Table 3: The "Glue" Class (Layout Locking / Non-Breaking Punctuation)
    0x2011: "[NBH]",           # Non-Breaking Hyphen
    0x2024: "[ODL]",           # One Dot Leader
    0x0F08: "[TIB:SS]",        # Tibetan Mark Sbrul Shad
    0x0F0C: "[TIB:DT]",        # Tibetan Mark Delimiter Tsheg
    0x0F12: "[TIB:RGS]",       # Tibetan Mark Rgya Gram Shad
    0x1802: "[MNG:C]",         # Mongolian Comma
    0x1803: "[MNG:FS]",        # Mongolian Full Stop
    0x1808: "[MNG:MC]",        # Mongolian Manchu Comma
    0x1809: "[MNG:MFS]",       # Mongolian Manchu Full Stop

    # --- Missing Mongolian Free Variation Selectors ---
    0x180B: "[FVS1]",          # Mongolian Free Variation Selector 1
    0x180C: "[FVS2]",          # Mongolian Free Variation Selector 2
    0x180D: "[FVS3]",          # Mongolian Free Variation Selector 3

    # --- Missing Egyptian Hieroglyph Format Controls ---
    0x13430: "[EGY:VJ]",       # Vertical Joiner
    0x13431: "[EGY:HJ]",       # Horizontal Joiner
    0x13432: "[EGY:TOP]",      # Top Joiner
    0x13433: "[EGY:BOT]",      # Bottom Joiner
    0x13434: "[EGY:OVR]",      # Overlay Middle
    0x13435: "[EGY:START]",    # Segment Start
    0x13436: "[EGY:END]",      # Segment End

    # --- Missing Musical Symbol ---
    0x1D159: "[MUS:NULL]",     # Musical Symbol Null Notehead

    # --- Standard Whitespace & Structure (Explicit Tags) ---
    0x0009: "[TAB]",           # Character Tabulation
    0x000A: "[LF]",            # Line Feed
    0x000B: "[VT]",            # Line Tabulation (Vertical Tab)
    0x000C: "[FF]",            # Form Feed
    0x000D: "[CR]",            # Carriage Return

    # --- Missing Egyptian Exploits ---
    0x133FC: "[EGY:Z015B]",    # Egyptian Hieroglyph Z015B (Font Exploit)

    # --- Undefined / Reserved ---
    0x2065: "[RSV:2065]",      # Unassigned (Reserved for future format)

    # Table 4: Invisible Operators & Scoping Containers
    0x2064: "[INV+]",          # Invisible Plus (Mathematical Ghost)
    0x13437: "[EGY:BS]",       # Egyptian Hieroglyph Begin Segment
    0x13438: "[EGY:ES]",       # Egyptian Hieroglyph End Segment
    0x1BCA0: "[SHORT:LO]",     # Shorthand Format Letter Overlap
    0x1BCA1: "[SHORT:CO]",     # Shorthand Format Continuing Overlap
    0x1BCA2: "[SHORT:DS]",     # Shorthand Format Down Step
    0x1BCA3: "[SHORT:US]",     # Shorthand Format Up Step

    # Table 5: Musical Scoping (The "Ghost" Structures)
    0x1D173: "[MUS:BB]",       # Musical Symbol Begin Beam
    0x1D174: "[MUS:EB]",       # Musical Symbol End Beam
    0x1D175: "[MUS:BT]",       # Musical Symbol Begin Tie
    0x1D176: "[MUS:ET]",       # Musical Symbol End Tie
    0x1D177: "[MUS:BS]",       # Musical Symbol Begin Slur
    0x1D178: "[MUS:ES]",       # Musical Symbol End Slur
    0x1D179: "[MUS:BP]",       # Musical Symbol Begin Phrase
    0x1D17A: "[MUS:EP]",       # Musical Symbol End Phrase

    # 5. Visual Control Pictures (Obfuscation / Social Engineering)
    # These are VISIBLE glyphs that mimic control codes (e.g., ␀ vs NUL).
    # We tag them as [PIC:...] to distinguish them from real controls.
    0x2400: "[PIC:NUL]", 0x2401: "[PIC:SOH]", 0x2402: "[PIC:STX]", 0x2403: "[PIC:ETX]",
    0x2404: "[PIC:EOT]", 0x2405: "[PIC:ENQ]", 0x2406: "[PIC:ACK]", 0x2407: "[PIC:BEL]",
    0x2408: "[PIC:BS]",  0x2409: "[PIC:HT]",  0x240A: "[PIC:LF]",  0x240B: "[PIC:VT]",
    0x240C: "[PIC:FF]",  0x240D: "[PIC:CR]",  0x240E: "[PIC:SO]",  0x240F: "[PIC:SI]",
    0x2410: "[PIC:DLE]", 0x2411: "[PIC:DC1]", 0x2412: "[PIC:DC2]", 0x2413: "[PIC:DC3]",
    0x2414: "[PIC:DC4]", 0x2415: "[PIC:NAK]", 0x2416: "[PIC:SYN]", 0x2417: "[PIC:ETB]",
    0x2418: "[PIC:CAN]", 0x2419: "[PIC:EM]",  0x241A: "[PIC:SUB]", 0x241B: "[PIC:ESC]",
    0x241C: "[PIC:FS]",  0x241D: "[PIC:GS]",  0x241E: "[PIC:RS]",  0x241F: "[PIC:US]",
    0x2420: "[PIC:SP]",  0x2421: "[PIC:DEL]", 0x2422: "[PIC:BLANK]", 0x2423: "[PIC:OB]",
    0x2424: "[PIC:NL]",  0x2425: "[PIC:DEL2]", 0x2426: "[PIC:SUB2]",

    # --- Phase 1 Update: Control Picture Overrides (Cleaner Visuals) ---
    # We map the actual critical controls to their Unicode Picture representations.
    # This reduces visual length from [NUL] (5 chars) to ␀ (1 char).
    0x0000: "\u2400",  # ␀ (Null)
    0x001B: "\u241B",  # ␛ (Escape)
    0x007F: "\u2421",  # ␡ (Delete)

    # --- Phase 1 Update: Spacing Specifics ---
    # These often look like spaces but have specific typographic widths/roles.
    0x2000: "[NQSP]",  # En Quad
    0x2001: "[MQSP]",  # Em Quad

   

    # --- Invisible Khmer Vowels ---
    0x17B4: "[KHM:AQ]",        # Khmer Vowel Inherent AQ
    0x17B5: "[KHM:AA]",        # Khmer Vowel Inherent AA
    
    # --- Rich Text Ghost ---
    0xFFFC: "[OBJ]",           # Object Replacement Character

    # --- Zombie Controls (Deprecated Format) ---
    0x206A: "[ISS]",           # Inhibit Symmetric Swapping
    0x206B: "[ASS]",           # Activate Symmetric Swapping
    0x206C: "[IAFS]",          # Inhibit Arabic Form Shaping
    0x206D: "[AAFS]",          # Activate Arabic Form Shaping
    0x206E: "[NDS]",           # National Digit Shapes
    0x206F: "[NODS]",          # Nominal Digit Shapes

    # --- Interlinear Annotation Controls ---
    0xFFF9: "[IAA]",  # Interlinear Annotation Anchor
    0xFFFA: "[IAS]",  # Interlinear Annotation Separator
    0xFFFB: "[IAT]",  # Interlinear Annotation Terminator
}

# Valid base characters for U+20E3 (Combining Enclosing Keycap)
VALID_KEYCAP_BASES = frozenset({
    0x0030, 0x0031, 0x0032, 0x0033, 0x0034, 0x0035, 0x0036, 0x0037, 0x0038, 0x0039, # Digits 0-9
    0x0023, # Hash
    0x002A  # Asterisk
})

# Sequences that modify intent (Direction, Color, Prohibition).
# Some are RGI (Emoji 15.1+), others are non-RGI but semantically distinct.
INTENT_MODIFYING_ZWJ_SEQUENCES = {
    # --- 1. DIRECTIONAL (Facing Right) ---
    # RGI in Emoji 15.1, but structurally intent-modifying
    "🏃‍➡️": "Person running facing right",
    "🏃‍♂️‍➡️": "Man running facing right",
    "🏃‍♀️‍➡️": "Woman running facing right",
    "🚶‍➡️": "Person walking facing right",
    "🚶‍♂️‍➡️": "Man walking facing right",
    "🚶‍♀️‍➡️": "Woman walking facing right",
    "🧍‍➡️": "Person standing facing right",
    "🧍‍♂️‍➡️": "Man standing facing right",
    "🧍‍♀️‍➡️": "Woman standing facing right",
    "🧎‍➡️": "Person kneeling facing right",
    "🧎‍♂️‍➡️": "Man kneeling facing right",
    "🧎‍♀️‍➡️": "Woman kneeling facing right",
    "🧑‍🦯‍➡️": "Person with cane facing right",
    "👨‍🦯‍➡️": "Man with cane facing right",
    "👩‍🦯‍➡️": "Woman with cane facing right",
    "🧑‍🦽‍➡️": "Person in manual wheelchair facing right",
    "👨‍🦽‍➡️": "Man in manual wheelchair facing right",
    "👩‍🦽‍➡️": "Woman in manual wheelchair facing right",
    "🧑‍🦼‍➡️": "Person in motorized wheelchair facing right",
    "👨‍🦼‍➡️": "Man in motorized wheelchair facing right",
    "👩‍🦼‍➡️": "Woman in motorized wheelchair facing right",

    # --- 2. COLORIZATION (Base + ZWJ + Color Square) ---
    "🍋‍🟩": "Lime (Lemon + Green Square)",
    "🍄‍🟫": "Brown Mushroom (Mushroom + Brown Square)",
    "➡️‍⬛": "Black Arrow (Right Arrow + Black Square)",
    "⬅️‍⬛": "Black Left Arrow",
    "⬆️‍⬛": "Black Up Arrow",
    "⬇️‍⬛": "Black Down Arrow",
    "🐦‍🔥": "Phoenix (Bird + Fire)",
    "🙂‍↔️": "Head Shaking Horizontally (Smile + Arrows)",
    "🙂‍↕️": "Head Shaking Vertically (Smile + Arrows)",

    # --- 3. PROHIBITION (No + ZWJ + Object) ---
    # Common non-RGI patterns for "No [Thing]"
    "🚫‍🚗": "No Cars",
    "🚫‍🚙": "No Vehicles",
    "🚫‍🏍️": "No Motorcycles",
    "🚫‍🚲": "No Bicycles",
    "🚫‍✈️": "No Airplanes",
    "🚫‍🚬": "No Smoking (Sequence Variant)",
    "🚫‍🔞": "No Under 18"
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
    # --- General Reordering Classes ---
    "0": "Not Reordered",
    "1": "Overlay",
    "7": "Nukta",
    "8": "Kana Voicing",
    "9": "Virama",

    # --- Fixed Position Range Markers (UAX #44) ---
    "10": "Start of fixed-position classes",
    "199": "End of fixed-position classes",
    
    # --- Attached / Reordering Classes (The "Zalgo" Reservoir) ---
    "200": "Attached Below Left",
    "202": "Attached Below",
    "214": "Attached Above",
    "216": "Attached Above Right",
    "218": "Below Left",
    "220": "Below",
    "222": "Below Right",
    "224": "Left",
    "226": "Right",
    "228": "Above Left",
    "230": "Above",
    "232": "Above Right",
    "233": "Double Below",
    "234": "Double Above",
    "240": "Iota Subscript"
}

# --- THREAT PENALTY CONSTANTS (The "Weaponization Code") ---
# Tier 1: COMPILER / EXECUTION ATTACKS (Target: Machine)
THR_BASE_EXECUTION = 40

# Tier 2: IDENTITY SPOOFING (Target: Human)
THR_BASE_SPOOFING = 25
THR_MULT_SPOOFING = 1.0 # Capped at +25 extra

# Tier 3: OBFUSCATION & STEGO (Target: Filter/Scanner)
THR_BASE_OBFUSCATION = 15
THR_MULT_OBFUSCATION = 0.5

# Tier 4: SUSPICIOUS CONTEXT (Target: Ambiguity)
THR_BASE_SUSPICIOUS = 10

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

# --- INTEGRITY PENALTY CONSTANTS (The "Health Code") ---
# Tier 1: FATAL (Irreversible Data Loss)
INT_BASE_FATAL = 40
INT_MULT_FATAL = 2.0 

# Tier 2: FRACTURE (Logic/Physics Break)
INT_BASE_FRACTURE = 25
INT_MULT_FRACTURE = 1.0

# Tier 3: RISK (Protocol Violation / Interchange Risk)
INT_BASE_RISK = 15
INT_MULT_RISK = 0.5

# Tier 4: DECAY (Hygiene / Artifacts)
INT_BASE_DECAY = 5
INT_MULT_DECAY = 0.2

# FORENSIC HAZARD SETS (Global Definition) Characters that represent structural syntax in backend systems.
# Used by the "Syntax Predator" engine to detect Normalization Injection.
HAZARD_SQL = frozenset({"'", '"', "-", "/", ";", "%"})
HAZARD_HTML = frozenset({"<", ">", "&"})
HAZARD_SYSTEM = frozenset({"/", "\\", ".", "|", "$", "`"})

# Union set for fast initial filtering
HAZARD_ALL = HAZARD_SQL | HAZARD_HTML | HAZARD_SYSTEM

# Simple SVG paths for the Forensic Metric Pack
METRIC_ICONS = {
    "eye": '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>',
    "hash": '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="4" y1="9" x2="20" y2="9"></line><line x1="4" y1="15" x2="20" y2="15"></line><line x1="10" y1="3" x2="8" y2="21"></line><line x1="16" y1="3" x2="14" y2="21"></line></svg>',
    "code": '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="16 18 22 12 16 6"></polyline><polyline points="8 6 2 12 8 18"></polyline></svg>',
    "save": '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"></path><polyline points="17 21 17 13 7 13 7 21"></polyline><polyline points="7 3 7 8 15 8"></polyline></svg>'
}

# Forensic Icon Set (Vector Paths for SVG)
ICONS = {
    # --- HEADERS ---
    "shield_ok": '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path><path d="M9 12l2 2 4-4"></path>',
    "shield_warn": '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line>',
    "octagon_crit": '<polygon points="7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2"></polygon><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line>',

    # --- FACETS (SENSORS) ---
    # 1. Visibility (Eye)
    "eye": '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle>',
    "eye_off": '<path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path><line x1="1" y1="1" x2="23" y2="23"></line>',
    
    # 2. Structure (Cube/Grid)
    "cube": '<path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"></path><polyline points="3.27 6.96 12 12.01 20.73 6.96"></polyline><line x1="12" y1="22.08" x2="12" y2="12"></line>',
    "layers": '<polygon points="12 2 2 7 12 12 22 7 12 2"></polygon><polyline points="2 17 12 22 22 17"></polyline><polyline points="2 12 12 17 22 12"></polyline>',
    
    # 3. Identity (Fingerprint)
    "fingerprint": '<path d="M2 12C2 6.5 6.5 2 12 2a10 10 0 0 1 8 6"></path><path d="M5 15.1a7 7 0 0 0 10.88-1.66"></path><path d="M19 16c-1.7 2-4 4-7 4-3.3 0-6-2.7-6-6a6 6 0 0 1 12 0"></path><path d="M8 12.5a4 4 0 0 1 8 0"></path><path d="M10.5 12.5a1.5 1.5 0 0 1 3 0"></path>',
    "clone": '<rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>'
}

# We pre-compile all 29 regexes into REGEX_MATCHER
# to use the proven-correct 'matchAll' method, just like the 'Provenance' module does.
for key, regex_str in MINOR_CATEGORIES_29.items():
    # Add to the main matcher dict
    REGEX_MATCHER[key] = window.RegExp.new(regex_str, "gu")

# These constants define the "Immutable Laws" of the Metadata Forensic Engine.
# They are derived from CSEMiner (ESORICS 2025), WCAG 2.1, and A11Y Project standards.

class METADATA_PHYSICS:
    """
    Defines the physical thresholds for 'Invisibility' and 'Obfuscation'.
    Source: CSEMiner Taxonomy of Hiding Techniques.
    """
    
    # 1. VISIBILITY THRESHOLDS (The "Event Horizon")
    # -------------------------------------------------------------------------
    # Values below these thresholds are mathematically treated as "Invisible".
    MIN_VISIBLE_OPACITY = 0.05        # Below 5% is effectively invisible
    MIN_VISIBLE_FONT_SIZE = 1.0       # Pixels. <1px is CSEMiner 'H5' category
    MIN_VISIBLE_DIMENSION = 1.0       # Pixels (Width/Height). Zero-area checks.
    
    # 2. POSITIONING THRESHOLDS (The "Off-Screen" Void)
    # -------------------------------------------------------------------------
    # Offsets considered "Far Off-Screen" for absolute positioning exploits.
    MAX_OFFSCREEN_OFFSET = 1000       # Pixels (e.g., left: -1000px)
    MIN_TEXT_INDENT = -999            # Pixels (e.g., text-indent: -9999px)

    # 3. CRITICAL HIDING VALUES (Computed Style Signatures)
    # -------------------------------------------------------------------------
    # Hard-coded values that trigger immediate "HIDDEN" state flags.
    HARD_DISPLAY_VALUES = {
        "none", "contents" 
    }
    HARD_VISIBILITY_VALUES = {
        "hidden", "collapse" 
    }
    HARD_CLIP_VALUES = {
        "rect(0,0,0,0)", "rect(0 0 0 0)", "rect(0px,0px,0px,0px)", "inset(50%)"
    }

    # 4. COLOR PHYSICS (Contrast & Transparency)
    # -------------------------------------------------------------------------
    # Colors that indicate active hiding when paired with matching backgrounds.
    TRANSPARENT_ALIASES = {
        "transparent", "rgba(0,0,0,0)", "hsla(0,0%,0%,0)", "#00000000"
    }
    # Common "Paper White" values used in White-on-White attacks
    WHITE_ALIASES = {
        "white", "#fff", "#ffffff", "rgb(255,255,255)", "rgba(255,255,255,1)"
    }


class METADATA_POLICY:
    """
    Defines the Judgment Logic (White/Blacklists).
    Source: WebAIM Accessibility Patterns & SEO Spam Research.
    """

    # 1. ACCESSIBILITY WHITELIST (The "Safe Harbor")
    # -------------------------------------------------------------------------
    # Class names that signal legitimate Screen Reader utility usage.
    # Detection of these downgrades severity from CRITICAL to INFO (if context matches).
    A11Y_CLASS_WHITELIST = {
        "sr-only",
        "visually-hidden",
        "screen-reader-text",
        "u-visually-hidden",
        "accessible-text",
        "skip-link"
    }

    # 2. SAFE VOCABULARY (Context Validation)
    # -------------------------------------------------------------------------
    # If text is hidden but contains ONLY these words, it is likely UI navigation.
    A11Y_SAFE_VOCAB = {
        "skip", "content", "jump", "navigation", "menu", "sidebar", 
        "close", "open", "expand", "collapse", "breadcrumb", "dialog"
    }

    # 3. OBFUSCATION BLACKLIST (The "Known Bad")
    # -------------------------------------------------------------------------
    # Class names associated with Black Hat SEO or Bootstrap hacks (deprecated).
    SUSPICIOUS_CLASS_SIGNATURES = {
        "text-hide",        # Bootstrap 4 deprecated mixin (often abused)
        "invisible",        # Generic hiding
        "opacity-0",        # Tailwind utility (often abused for cloaking)
        "d-none",           # Bootstrap display:none
        "hidden",           # HTML5 attribute or utility
        "cloak",
        "spoiler"
    }

    # 4. PAYLOAD TRIGGERS (The "Red Line")
    # -------------------------------------------------------------------------
    # If hidden text contains these patterns, the A11Y Whitelist is REVOKED.
    # Source: Prompt Injection Research.
    PAYLOAD_KEYWORDS = {
        "ignore previous", "system prompt", "you are", "gpt", 
        "password", "admin", "login", "key", "token"
    }


class METADATA_PATTERNS:
    """
    Pre-compiled Regex for robust CSS parsing.
    Replaces simple string splitting to handle edge cases like url(';') or comments.
    """
    
    # Matches individual CSS declarations: "property : value ;"
    # Handles whitespace and missing trailing semicolons.
    CSS_DECLARATION_SPLIT = re.compile(
        r'(?P<prop>[\w-]+)\s*:\s*(?P<val>[^;]+)(?:;|$)', 
        re.IGNORECASE | re.DOTALL
    )

    # Matches "Important" flags to respect CSS cascade rules (rudimentary).
    CSS_IMPORTANT = re.compile(r'!\s*important', re.IGNORECASE)

    # Matches specific dangerous value patterns in raw strings.
    # Used for "Fast Scan" heuristics before full parsing.
    REGEX_CRITICAL_PATTERNS = {
        "OFFSCREEN": re.compile(r'left\s*:\s*-\d{3,4}px'),
        "TEXT_INDENT": re.compile(r'text-indent\s*:\s*-\d{3,4}px'),
        "ZERO_SIZE": re.compile(r'(width|height|font-size)\s*:\s*0(?![0-9\.])'),
        "OPACITY_ZERO": re.compile(r'opacity\s*:\s*0(?![0-9\.])')
    }

class METADATA_SCORING_CONFIG:
    """
    [SOTA] Forensic Impact & Sophistication (FIS) Model Weights.
    Derived from CVSS v3.1 and CSEMiner Risk Models.
    """
    # 1. BASE SEVERITY (Impact Sub-Score)
    # -------------------------------------------------------------------------
    # 'CRITICAL': Active Payload / System Compromise Vector
    # 'HIGH':     Definite Obfuscation / SEO Spam / Phishing Lure
    # 'MEDIUM':   Ambiguous Hiding / Legacy Hacks
    # 'INFO':     Accessibility / Layout
    W_CRITICAL = 60.0 
    W_HIGH     = 25.0
    W_MEDIUM   = 10.0
    W_INFO     = 0.0

    # 2. SOPHISTICATION MULTIPLIERS (Exploitability Sub-Score)
    # -------------------------------------------------------------------------
    # "Polymorphism": Using distinct vectors (e.g. Opacity + Clip + Z-Index)
    # suggests an advanced cloaking tool, not manual CSS.
    MULTI_VECTOR_FACTOR = 1.5  # 2+ Distinct Vectors detected
    POLYMORPHIC_FACTOR  = 2.2  # 4+ Distinct Vectors (High Sophistication)
    
    # "Deep Nesting": Hiding content 5+ levels deep implies intent to evade
    # shallow scrapers or parsers.
    NESTING_PENALTY_THRESHOLD = 5
    NESTING_FACTOR = 1.2

    # 3. SATURATION LIMITS (The "Ceiling")
    # -------------------------------------------------------------------------
    # Prevents alert fatigue. A score of 100 means "Certain Malice."
    MAX_SCORE = 100
    
    # 4. INSTANT KILL TRIGGERS
    # -------------------------------------------------------------------------
    # If these conditions are met, score is forced to 100 regardless of math.
    FATAL_CONDITIONS = {
        "PAYLOAD_IN_A11Y",   # Injection hidden inside .sr-only
        "OFFSCREEN_PHISHING" # Login form hidden off-screen
    }


class METADATA_POLICY:
    """
    [SOTA] Judgment Logic (White/Blacklists).
    Expanded with 'Jailbroken' prompt vocabularies and Phishing Kit signatures.
    """

    # 1. ACCESSIBILITY WHITELIST (The "Safe Harbor")
    # Source: WebAIM, Bootstrap, Tailwind, HTML5 Boilerplate
    A11Y_CLASS_WHITELIST = {
        "sr-only", "visually-hidden", "screen-reader-text", 
        "u-visually-hidden", "accessible-text", "skip-link", 
        "offscreen", "element-invisible"
    }

    # 2. SAFE VOCABULARY (Context Validation)
    # If hidden text contains ONLY these, it is UI plumbing.
    A11Y_SAFE_VOCAB = {
        "skip", "content", "jump", "navigation", "menu", "sidebar", 
        "close", "open", "expand", "collapse", "breadcrumb", "dialog",
        "toggle", "previous", "next", "search", "main"
    }

    # 3. OBFUSCATION BLACKLIST (The "Known Bad")
    # Signatures from Phishing Kits (16Shop, LogoKit) and SEO Spam.
    SUSPICIOUS_CLASS_SIGNATURES = {
        "text-hide", "invisible", "opacity-0", "d-none", "hidden", 
        "cloak", "spoiler", "hide-text", "transparent", "f0", 
        "w-0", "h-0", "z-negative", "absolute-hide"
    }

    # 4. PAYLOAD TRIGGERS (The "Red Line")
    # Comprehensive Threat Vocabulary
    PAYLOAD_KEYWORDS = {
        # A. Prompt Injection / Jailbreak
        "ignore previous", "system prompt", "you are", "gpt", 
        "developer mode", "do not reveal", "hypothetical response",
        " DAN ", "jailbreak", "override",

        # B. Credentials / PII
        "password", "admin", "login", "key", "token", "cvv", 
        "ssn", "credit card", "billing", "signin",

        # C. Exfiltration / Command & Control
        "shell", "exec", "curl", "wget", "powershell", "cmd.exe",
        "eval(", "document.cookie", "base64"
    }

# --- 1. UTS #39 RESTRICTION LEVELS (The "Security Clearance") ---
# These integers represent the hierarchy of safety for mixed-script strings.
# Used by: analyze_restriction_level()
RESTRICTION_LEVELS = {
    "ASCII": 0,            # Pure ASCII (a-z, 0-9). The baseline for protocols.
    "SINGLE_SCRIPT": 1,    # Single Script + Common/Inherited (e.g., pure Cyrillic).
    "HIGHLY_RESTRICTIVE": 2, # Latin + {Han, Hiragana, Katakana, Hangul} (Safe East Asian mix).
    "MODERATELY_RESTRICTIVE": 3, # Latin + {Cyrillic, Greek, etc.} (Covered by script profile).
    "MINIMALLY_RESTRICTIVE": 4, # Arbitrary mixes found in widespread use.
    "UNRESTRICTIVE": 5     # Contains "Unknown" scripts or invalid mixes. High Risk.
}

# --- 2. VERIFICATION VERDICTS (The "Judgment") ---
# Standardized enums for the Zero-Trust Comparator results.
VERDICT_TYPES = {
    "IDENTITY_MATCH": "IDENTITY_MATCH",           # Bitwise Equal
    "NORMALIZATION_EQ": "NORMALIZATION_EQ",       # NFKC/Casefold Equal (Format Drift)
    "VISUAL_CLONE": "VISUAL_CLONE",               # Skeleton Equal (Homoglyph Attack)
    "TARGET_CONTAINED": "TARGET_CONTAINED",       # Trusted is a subset of Suspect (Hidden)
    "PARTIAL_THREAT": "PARTIAL_OVERLAP_THREATS",  # Partial Match + Residual Risk
    "VISUAL_OVERLAP": "VISUAL_OVERLAP",           # Benign Partial Match
    "DISTINCT": "DISTINCT"                        # No Correlation
}

# --- 3. CONFUSABLE TAXONOMY (The "Spoof Class") ---
# Used to classify the mechanism of a Homograph Attack (VP-09).
CONFUSABLE_CLASS = {
    "SINGLE_SCRIPT": "SINGLE_SCRIPT_SPOOF",       # e.g., '1' vs 'l' (Typosquatting)
    "CROSS_SCRIPT": "CROSS_SCRIPT_SPOOF",         # e.g., Cyrillic 'a' vs Latin 'a'
    "WHOLE_SCRIPT": "WHOLE_SCRIPT_SPOOF",         # Entire string is a different script
    "NONE": "N/A"
}

# --- 4. UAX #31 IDENTIFIER PROFILES (The "Gatekeeper") ---
# Deterministic Regex patterns to enforce Identifier Syntax.
# We use "Negative Matching" (Forbidden Chars) to be lightweight and fast.

# Profile A: STRICT ASCII (IETF / System Identifiers)
# Allowed: a-z, A-Z, 0-9, underscore.
# Forbidden: Everything else.
REGEX_ID_ASCII_STRICT = re.compile(r"^\w+$", re.ASCII)

# Profile B: GENERAL SECURITY PROFILE (UAX #31 Baseline)
# Replaces the broken \p{} regex with a standard Python equivalent.
# Pattern: ^\w+$
# Matches: Unicode Alphanumeric (L, N) + Underscore (Pc) + Marks (M).
# Rejects: Whitespace (Z), Control (C), Symbols (S), Punctuation (P) (excl. _).
REGEX_ID_GENERAL_SAFE = re.compile(r"^\w+$")

# [NEW] Diagnostic Tuples (The "Why" Definitions)
# Used by the Logic Engine to explain *why* a string failed the regex.
# We define the forbidden physics here, not inside the function.
ID_VIOLATION_MAP = {
    "WHITESPACE": ("Z",),          # Separators
    "CONTROL":    ("C",),          # Control/Format
    "SYMBOL":     ("S",),          # Math, Emoji, Currency
    "PUNCTUATION": ("P",)          # Punctuation (logic handles '_' exception)
}

# Profile C: DOMAIN LABEL (RFC 1035 + IDNA)
# Allowed: Alphanumeric + Hyphen (strictly internal).
# Rejects: Leading/Trailing hyphens, Symbols.
REGEX_ID_DOMAIN_LABEL = re.compile(r"^(?!-)[a-zA-Z0-9-]{1,63}(?<!-)$")

# --- 5. RESIDUAL RISK MASKS (The "Cold Zone" Scanners) ---
# Bitmasks used to scan the unmatched tails of verified strings.
# Combines multiple flags from INVIS_TABLE for efficiency.
MASK_RESIDUAL_RISK = (
    INVIS_BIDI_CONTROL | 
    INVIS_TAG | 
    INVIS_ZERO_WIDTH_SPACING | 
    INVIS_DEFAULT_IGNORABLE |
    INVIS_JOIN_CONTROL
)

# --- 6. SCRIPT SAFETY TIERS (For Restriction Level Logic) ---
# Defines which script combinations are "Authorized" for High Restriction levels.
# Based on UTS #39 Identifier Profile guidelines.
SAFE_SCRIPT_MIXES = {
    # Latin is allowed to mix with these CJK scripts in "Highly Restrictive" profiles
    "Latin": {"Han", "Hiragana", "Katakana", "Hangul", "Bopomofo"}
}

# Scripts that are generally discouraged in identifiers (Limited Use)
# Source: UAX #31 Table 7
ASPIRATIONAL_SCRIPTS = {
    "Canadian_Aboriginal", "Yi", "Mongolian", "Tifinagh", "Miao"
}

# ===============================================
# BLOCK 3. GLOBAL STATE & DATA STORES
# ===============================================

# Tier 3: Manual expansions Pyodide fails to handle
# Enclosed Alphanumerics → ASCII (⓼ → 8, ⓐ → a, ① → 1, etc.)
ENCLOSED_MAP = {}

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
            
        print(f"LOG: Built manual ENCLOSED_MAP with {len(ENCLOSED_MAP)} rules.")
    except Exception as e:
        print(f"ERROR: Failed building ENCLOSED_MAP: {e}")

# Execute once at startup
_build_enclosed()

# --- THE MASSIVE DATA STORE ---
DATA_STORES = {
    "Blocks": {"ranges": [], "starts": [], "ends": []},
    "Age": {"ranges": [], "starts": [], "ends": []},
    "Discouraged": {"ranges": [], "starts": [], "ends": []},
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
    "InverseConfusables": {}, # Loaded from JSON
    "EastAsianWidth": {"ranges": [], "starts": [], "ends": []},
    "VerticalOrientation": {"ranges": [], "starts": [], "ends": []},
    "BidiBracketType": {"ranges": [], "starts": [], "ends": []},
    "CompositionExclusions": {"ranges": [], "starts": [], "ends": []},
    "ChangesWhenNFKCCasefolded": {"ranges": [], "starts": [], "ends": []},
    "BidiMirroring": {}, 
    "VariantBase": set(),
    "VariantSelectors": set(),
    # Buckets for Emoji Data
    "Emoji": {"ranges": [], "starts": [], "ends": []},
    "Emoji_Presentation": {"ranges": [], "starts": [], "ends": []},
    "Emoji_Modifier": {"ranges": [], "starts": [], "ends": []},
    "Emoji_Modifier_Base": {"ranges": [], "starts": [], "ends": []},
    "Emoji_Component": {"ranges": [], "starts": [], "ends": []},
    "Extended_Pictographic": {"ranges": [], "starts": [], "ends": []},
    # IDNA Buckets
    "Idna2008": {},
    "IdnaMap": {"deviation": set(), "ignored": set(), "disallowed": set(), "mapped": set(), "nv8": set(), "xv8": set()}
}

# ===============================================
# BLOCK 4. DATA PARSERS & LOADERS
# ===============================================

# The Range Parsers
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

# The Specific Logic Parsers

def _parse_confusables(txt: str):
    """Parses confusables.txt into the CONFUSABLES_MAP."""
    store = DATA_STORES["Confusables"]
    store.clear()
    count = 0
    lines = txt.split('\n')
    for raw in lines:
        # 1. Strip comments immediately (Fixes "MA # Comment" issues)
        line = raw.split('#', 1)[0].strip()
        if not line or line.startswith(';'):
            continue
        
        # 2. Split by semicolon
        parts = line.split(';')
        if len(parts) < 3:
            continue
        
        try:
            source_hex = parts[0].strip()
            tgt_hex = parts[1].strip().split()
            # Strict Tag Extraction (MA, ML, SA, SL)
            tag = parts[2].strip().split()[0] 
            
            source_cp = int(source_hex, 16)
            target_str = "".join([chr(int(h, 16)) for h in tgt_hex])
            
            # Store as tuple. We allow length > 2 for future extensibility (e.g. comments)
            # but the logic engine will now handle it safely.
            store[source_cp] = (target_str, tag)
            count += 1
        except Exception:
            pass 
            
    print(f"Loaded {count} confusable mappings with Forensic Types.")

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

# The Emoji Parsers (The "Powerhouse")

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
    Includes RGI_Emoji_*, Emoji_Keycap_Sequence, AND Basic_Emoji.
    """
    sequences = set()
    rgi_types = {
        "RGI_Emoji_Flag_Sequence",
        "RGI_Emoji_Tag_Sequence",
        "RGI_Emoji_Modifier_Sequence",
        "Emoji_Keycap_Sequence",
        "Basic_Emoji" # <--- ADDED THIS
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
            
            if type_field in rgi_types:
                # Ensure it's a space-delimited sequence
                # AND not a range (which this parser doesn't handle)
                if '..' not in hex_codes_str:
                    hex_codes = hex_codes_str.split()
                    sequence_str = "".join([chr(int(h, 16)) for h in hex_codes])
                    sequences.add(sequence_str)
                
                # [PATCH] Handle ranges for Basic_Emoji (e.g., 1F1E6..1F1FF)
                elif type_field == "Basic_Emoji":
                    # Ranges are common in Basic_Emoji
                    range_parts = hex_codes_str.split('..')
                    start = int(range_parts[0], 16)
                    end = int(range_parts[1], 16) if len(range_parts) > 1 else start
                    
                    for cp in range(start, end + 1):
                        sequences.add(chr(cp))

        except Exception as e:
            pass 
            
    print(f"Loaded {len(sequences)} RGI sequences (including Basic_Emoji).")
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

# The Protocol Parsers

# --- IDNA2008 PARSER (Strict RFC 5892) ---
def _parse_idna2008(txt: str):
    """
    Parses Idna2008.txt (RFC 5892).
    Stores: PVALID, CONTEXTJ, CONTEXTO, DISALLOWED, UNASSIGNED.
    """
    store = DATA_STORES["Idna2008"] = {}
    for line in txt.splitlines():
        if '#' in line: line = line.split('#')[0]
        if not line.strip(): continue
        parts = [p.strip() for p in line.split(';')]
        if len(parts) < 2: continue
        
        code_range = parts[0]
        category = parts[1].strip()
        
        if '..' in code_range:
            start, end = map(lambda x: int(x, 16), code_range.split('..'))
        else:
            start = end = int(code_range, 16)
            
        for cp in range(start, end + 1):
            store[cp] = category

# --- UTS #46 PARSER (Compatibility & NV8) ---
def _parse_idna_mapping(txt: str):
    """
    Parses UTS #46 IdnaMappingTable.txt.
    Stores Status, Mappings, NV8/XV8 flags.
    """
    store = DATA_STORES["IdnaMap"] = {
        "deviation": set(), "ignored": set(), "disallowed": set(), 
        "mapped": set(), "nv8": set(), "xv8": set()
    }
    
    for line in txt.splitlines():
        # Parsing 4-column format: Code; Status; Mapping; IDNA2008_Status
        raw_line = line.split('#')[0]
        if not raw_line.strip(): continue
        
        parts = [p.strip() for p in raw_line.split(';')]
        if len(parts) < 2: continue
        
        code_range = parts[0]
        status = parts[1].strip()
        
        # Check for NV8/XV8 in column 4 (index 3)
        idna08_status = parts[3] if len(parts) > 3 else ""
        is_nv8 = "NV8" in idna08_status
        is_xv8 = "XV8" in idna08_status
        
        if '..' in code_range:
            start, end = map(lambda x: int(x, 16), code_range.split('..'))
        else:
            start = end = int(code_range, 16)
            
        target_set = store.get(status)
        if target_set is not None:
            for cp in range(start, end + 1):
                target_set.add(cp)
                if is_nv8: store["nv8"].add(cp)
                if is_xv8: store["xv8"].add(cp)

# The Builders & Overrides

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

def build_invis_table():
    """
    Populates the global INVIS_TABLE with forensic bitmasks.
    """
    global INVIS_TABLE
    
    def apply_mask(ranges, mask):
        if not ranges: return
        for item in ranges:
            start = item[0]
            end = item[1]
            start, end = max(0, start), min(1114111, end)
            for cp in range(start, end + 1):
                INVIS_TABLE[cp] |= mask

    # Interlinear Annotation Controls
    apply_mask([(0xFFF9, 0xFFFB)], INVIS_DEFAULT_IGNORABLE)

    # In build_invis_table:
    apply_mask([(0x11A3E, 0x11A3E)], INVIS_DEFAULT_IGNORABLE)

    # Manual Patch for New List Items & Historic Controls
    # Comprehensive coverage for Unicode 14.0/15.0+ and script-specific invisibles
    # that might not be flagged in older UCD DefaultIgnorable files.
    apply_mask([
        (0x180B, 0x180F),  # Mongolian FVS 1-4 (Inc. 180F)
        (0x2065, 0x2065),  # Reserved / Invisible Operator
        (0x1D159, 0x1D159),# Musical Null Notehead
        (0x133FC, 0x133FC),# Egyptian Z015B (Font Exploit)
        (0x16FE4, 0x16FE4),# Khitan Small Script Filler
        (0x13439, 0x1343F),# Egyptian Hieroglyph Format Controls (Extended)
        (0x1BCA4, 0x1BCAE),# Shorthand Format Controls (Extended)
        (0x11C40, 0x11C40),# Bhaiksuki Gap Filler
        (0x11A47, 0x11A47),# Zanabazar Square Subjoiner
        (0x11A99, 0x11A99),# Soyombo Subjoiner
        (0x1107F, 0x1107F),# Brahmi Number Joiner
        (0x110BD, 0x110BD),# Kaithi Number Sign
        (0x110CD, 0x110CD),# Kaithi Number Sign Above
        (0x11446, 0x11446),# Newa Sandhi Mark
        (0x0600, 0x0605),  # Arabic Number Signs (0600-0605)
        (0x06DD, 0x06DD),  # Arabic End of Ayah
        (0x08E2, 0x08E2),  # Arabic Disputed End of Ayah
        (0x070F, 0x070F),  # Syriac Abbreviation Mark
        (0x1BC9D, 0x1BC9E) # Duployan Shorthand Controls
    ], INVIS_DEFAULT_IGNORABLE)

    # Noncharacters (Process-Internal)
    # Includes FFFE, FFFF, and the FDD0-FDEF block.
    # These trigger "Red/Critical" flags in the Atlas.
    apply_mask([
        (0xFFFE, 0xFFFF),      # End-of-plane nonchars
        (0xFDD0, 0xFDEF)       # Process-internal block
    ], INVIS_CRITICAL_CONTROL)

    # Manual Patch for New List Items & Historic Controls
    # Ensures detection in Stats/Atlas/Threat Score
    apply_mask([
        (0x180B, 0x180F),  # Mongolian FVS 1-4
        (0x2065, 0x2065),  # Reserved
        (0x1D159, 0x1D159),# Musical Null
        (0x133FC, 0x133FC),# Egyptian Z015B
        (0x16FE4, 0x16FE4),# Khitan Filler
        (0x13439, 0x1343B),# Egyptian Insertions
        (0x11C40, 0x11C40),# Bhaiksuki Gap Filler
        (0x11A47, 0x11A47),# Zanabazar Subjoiner
        (0x11A99, 0x11A99),# Soyombo Subjoiner
        (0x1107F, 0x1107F),# Brahmi Number Joiner
        (0x110BD, 0x110BD),# Kaithi Number Sign
        (0x110CD, 0x110CD),# Kaithi Number Sign Above
        (0x11446, 0x11446),# Newa Sandhi Mark
        (0x0600, 0x0605),  # Arabic Number Signs
        (0x06DD, 0x06DD),  # Arabic End of Ayah
        (0x08E2, 0x08E2),  # Arabic Disputed End of Ayah
        (0x070F, 0x070F),  # Syriac SAM
        (0x1BC9D, 0x1BC9E) # Duployan Controls
    ], INVIS_DEFAULT_IGNORABLE)

    # Manual Patch for New List Items & Historic Controls
    # Ensures detection in Stats/Atlas/Threat Score
    apply_mask([
        (0x180B, 0x180F),  # Mongolian FVS 1-4
        (0x2065, 0x2065),  # Reserved
        (0x1D159, 0x1D159),# Musical Null
        (0x133FC, 0x133FC),# Egyptian Z015B
        (0x16FE4, 0x16FE4),# Khitan Filler
        (0x13439, 0x1343B),# Egyptian Insertions
        (0x11C40, 0x11C40),# Bhaiksuki Gap Filler
        (0x11A47, 0x11A47),# Zanabazar Subjoiner
        (0x11A99, 0x11A99),# Soyombo Subjoiner
        (0x1107F, 0x1107F),# Brahmi Number Joiner
        (0x110BD, 0x110BD),# Kaithi Number Sign
        (0x110CD, 0x110CD),# Kaithi Number Sign Above
        (0x11446, 0x11446) # Newa Sandhi Mark
    ], INVIS_DEFAULT_IGNORABLE)

    # Default Ignorable
    ignorable_ranges = DATA_STORES.get("DefaultIgnorable", {}).get("ranges", [])
    apply_mask(ignorable_ranges, INVIS_DEFAULT_IGNORABLE)

    # Join Controls
    apply_mask([(0x200C, 0x200D)], INVIS_JOIN_CONTROL)
    # --- Explicitly catch CGJ (U+034F) as a Join Control ---
    # It acts as invisible glue, so we treat it as a structural joiner for forensics.
    apply_mask([(0x034F, 0x034F)], INVIS_JOIN_CONTROL)

    # Zero Width Spacing
    apply_mask([(0x200B, 0x200B), (0x2060, 0x2060), (0xFEFF, 0xFEFF)], INVIS_ZERO_WIDTH_SPACING)

    # Bidi Controls
    bidi_ranges = DATA_STORES.get("BidiControl", {}).get("ranges", [])
    apply_mask(bidi_ranges, INVIS_BIDI_CONTROL)

    # Tags
    apply_mask([(0xE0000, 0xE007F)], INVIS_TAG)

    # Add 0x180F and 0x16FE4 to the manual mask list
    apply_mask([
        (0x180B, 0x180F),  # Updated range to include FVS4 (180F)
        (0x2065, 0x2065), 
        (0x1D159, 0x1D159), 
        (0x133FC, 0x133FC),
        (0x16FE4, 0x16FE4) # Khitan Filler
    ], INVIS_DEFAULT_IGNORABLE)

    # Manual Patch for New List Items (Ensure detection in Stats/Atlas)
    # These might not be in UCD "DefaultIgnorable" yet, but we want to flag them.
    # Includes: Mongolian FVS (180B-180D), Reserved (2065), Musical Null (1D159)
    apply_mask([
        (0x180B, 0x180D), # Mongolian FVS 1-3
        (0x2065, 0x2065), # Reserved / Invisible Operator
        (0x1D159, 0x1D159), # Musical Null Notehead
        (0x133FC, 0x133FC)  # Egyptian Z015B (Exploit)
    ], INVIS_DEFAULT_IGNORABLE)

    # Variation Selectors
    apply_mask([(0xFE00, 0xFE0F)], INVIS_VARIATION_STANDARD)
    apply_mask([(0xE0100, 0xE01EF)], INVIS_VARIATION_IDEOG)

    # Do Not Emit
    apply_mask(DATA_STORES.get("DoNotEmit", {}).get("ranges", []), INVIS_DO_NOT_EMIT)

    # Soft Hyphen
    apply_mask([(0x00AD, 0x00AD)], INVIS_SOFT_HYPHEN)

    # Non-Standard Newlines
    apply_mask([(0x2028, 0x2029)], INVIS_NONSTANDARD_NL)

    # Non-ASCII Spaces (Zs != 0x20)
    # Explicitly included MVS (0x180E) and Ogham (0x1680)
    zs_ranges = [
        (0x00A0, 0x00A0), (0x1680, 0x1680), (0x180E, 0x180E), 
        (0x2000, 0x200A), (0x202F, 0x202F), (0x205F, 0x205F), 
        (0x3000, 0x3000)
    ]
    apply_mask(zs_ranges, INVIS_NON_ASCII_SPACE)

    # --- MANUAL FORENSIC OVERRIDES ---
    
    # The "False Vacuums" (Letters/Symbols that act as Spaces)
    # We map these to INVIS_NON_ASCII_SPACE so they trigger "Deceptive Space" flags.
    # U+3164 (Hangul Filler), U+FFA0 (Halfwidth Filler), U+2800 (Braille Blank)
    apply_mask([(0x3164, 0x3164), (0xFFA0, 0xFFA0), (0x2800, 0x2800)], INVIS_NON_ASCII_SPACE)

    # The "Ghost Operators" & "Fillers"
    # These are technically 'Lo' (Letters) or 'Cf' (Format) but behave like invisibles.
    # U+115F (Choseong), U+1160 (Jungseong), U+2064 (Invisible Plus)
    # We map these to INVIS_DEFAULT_IGNORABLE so they trigger "Invisible" flags.
    apply_mask([(0x115F, 0x1160), (0x2061, 0x2064)], INVIS_DEFAULT_IGNORABLE)

    # The "Structural Containers" (Scoping)
    # Egyptian, Musical, Shorthand format controls.
    # Map to INVIS_DEFAULT_IGNORABLE.
    apply_mask([
        (0x13437, 0x13438), # Egyptian
        (0x1D173, 0x1D17A), # Musical
        (0x1BCA0, 0x1BCA3)  # Shorthand
    ], INVIS_DEFAULT_IGNORABLE)

    # The "Zombie Controls" & Invisible Math
    # These are Format (Cf) characters that are deprecated or invisible.
    # Map to INVIS_DEFAULT_IGNORABLE.
    apply_mask([
        (0x206A, 0x206F), # Deprecated Formatting (ISS, ASS, etc.)
        (0x2061, 0x2063), # Invisible Math (FA, IT, IS)
        (0x17B4, 0x17B5)  # Khmer Invisible Vowels
    ], INVIS_DEFAULT_IGNORABLE)
    
    # Object Replacement Character
    # Technically 'So' (Symbol), but acts as a placeholder.
    # Map to INVIS_DEFAULT_IGNORABLE to ensure it's flagged.
    apply_mask([(0xFFFC, 0xFFFC)], INVIS_DEFAULT_IGNORABLE)

    # The "Layout Locks" (Glue)
    # These prevent line breaks. We don't have a specific bitmask for "Glue" yet, 
    # but if you want to detect "Layout Sabotage", you might map them to INVIS_ZERO_WIDTH_SPACING
    # or create a new mask. For now, leaving them as visual characters is safer 
    # unless you want to flag them as "Suspicious". 
    # (Recommendation: Leave unmasked for now, rely on the [TAG] mapping in Part 1 for visibility).

    # Map NUL (0x00), ESC (0x1B), and DEL (0x7F) to the Bitmask
    # This ensures the O(1) engine sees them as "Invisibles" too.
    apply_mask([(0x0000, 0x0000), (0x001B, 0x001B), (0x007F, 0x007F)], INVIS_CRITICAL_CONTROL)
    
    # Map C0 controls (0x00-0x1F) excluding whitespace (TAB/LF/CR)
    # This aligns the Bitmask perfectly with the 'reveal2' Dictionary
    c0_controls = []
    for cp in range(0x00, 0x20):
        if cp not in (0x09, 0x0A, 0x0D): # Skip TAB, LF, CR
            c0_controls.append((cp, cp))
    apply_mask(c0_controls, INVIS_CRITICAL_CONTROL)
    
    # Map C1 Controls (0x80-0x9F) as Critical
    # These are legacy control codes that often indicate encoding errors or obfuscation.
    # Note: 0x85 (NEL) is also handled as a newline elsewhere, but it IS a control.
    apply_mask([(0x80, 0x9F)], INVIS_CRITICAL_CONTROL)
    
    # Map Plane-End Noncharacters (FFFE/FFFF) for ALL Planes (0-16)
    # U+1FFFE, U+1FFFF, U+2FFFE, etc.
    plane_ends = []
    for plane in range(1, 17): # Planes 1 through 16
        base = plane * 0x10000
        plane_ends.append((base + 0xFFFE, base + 0xFFFF))
    apply_mask(plane_ends, INVIS_CRITICAL_CONTROL)

def run_self_tests():
    """
    MODE: Verify that INVIS_TABLE bitmasks strictly match the UCD data.
    This runs once at startup. If it fails, it prints critical warnings to the console.
    """
    print("--- Running Forensic Self-Tests ---")
    
    def check_property(store_key, mask_bit, name):
        """Verifies that every CP in DATA_STORES[store_key] has mask_bit set."""
        store = DATA_STORES.get(store_key, {})
        ranges = store.get("ranges", [])
        
        missing_count = 0
        checked_count = 0
        
        for item in ranges:
            start, end = item[0], item[1]
            start, end = max(0, start), min(1114111, end)
            
            for cp in range(start, end + 1):
                checked_count += 1
                if not (INVIS_TABLE[cp] & mask_bit):
                    missing_count += 1
                    if missing_count <= 5: # Print first 5 failures
                        print(f"TEST FAIL [{name}]: U+{cp:04X} missing bit.")
                        
        if missing_count == 0:
            print(f"PASS: {name} ({checked_count} codepoints verified)")
        else:
            print(f"CRITICAL FAIL: {name} has {missing_count} missing coverage!")

    # 1. Verify Bidi Controls
    check_property("BidiControl", INVIS_BIDI_CONTROL, "Bidi Controls")

    # 2. Verify Join Controls
    # We loaded this into "JoinControl" bucket from PropList
    check_property("JoinControl", INVIS_JOIN_CONTROL, "Join Controls")

    # 3. Verify Tags (if available in PropList, otherwise we rely on range)
    # Note: PropList might call it "Pattern_Syntax" or "Depreciated" depending on version
    # We manually mapped 0xE0000..0xE007F, so we check that range directly
    tag_missing = 0
    for cp in range(0xE0000, 0xE0080):
        if not (INVIS_TABLE[cp] & INVIS_TAG):
            tag_missing += 1
    if tag_missing == 0:
        print(f"PASS: Tags Plane 14 (128 codepoints verified)")
    else:
        print(f"CRITICAL FAIL: Tags has {tag_missing} missing coverage!")

    # 4. Verify Default Ignorables (The Big One)
    check_property("DefaultIgnorable", INVIS_DEFAULT_IGNORABLE, "Default Ignorables")

    # 5. Verify Do Not Emit
    check_property("DoNotEmit", INVIS_DO_NOT_EMIT, "Do Not Emit")

    # 6. Verify WhiteSpace (PropList) -> INVIS_NON_ASCII_SPACE
    # Note: Our mask excludes ASCII space, so we test logic, not direct mapping
    # This is complex to test strictly without replicating logic, so we skip for now 
    # to avoid false failures on 0x20.

    # 7. Verify Variation Selectors
    # Check a few known ones
    if (INVIS_TABLE[0xFE0F] & INVIS_VARIATION_STANDARD) and (INVIS_TABLE[0xE0100] & INVIS_VARIATION_IDEOG):
        print("PASS: Variation Selectors (Sample check)")
    else:
        print("CRITICAL FAIL: Variation Selector bits missing!")

    print("--- Self-Tests Complete ---")

async def load_unicode_data():

    # --- USE THE GLOBAL LOCK ---
    global LOADING_LOCK
    
    # 1. Check if another process is already loading
    if LOADING_LOCK:
        print("LOG: Loading locked. Skipping concurrent execution.")
        return

    # 2. Check if data is already fully loaded (from a previous completed run)
    if "Blocks" in DATA_STORES and isinstance(DATA_STORES["Blocks"], frozenset):
        print("LOG: Data already loaded. Skipping re-initialization.")
        return

    # 3. Lock the door immediately
    LOADING_LOCK = True
    
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
            "emoji-test.txt",
            "inverse_confusables.json",
            "ascii_confusables.json",
            "IdnaMappingTable.txt",
            "Idna2008.txt"
        ]
        results = await asyncio.gather(*[fetch_file(f) for f in files_to_fetch])
    
        # --- MODIFIED (Feature 2 Expanded) ---
        (blocks_txt, age_txt, id_type_txt, id_status_txt, intentional_txt, confusables_txt, variants_txt, 
         script_ext_txt, linebreak_txt, proplist_txt, derivedcore_txt, 
         scripts_txt, emoji_variants_txt, word_break_txt, 
         sentence_break_txt, grapheme_break_txt, donotemit_txt, ccc_txt, 
         decomp_type_txt, derived_binary_txt, num_type_txt, 
         ea_width_txt, vert_orient_txt, bidi_brackets_txt,
         bidi_mirroring_txt, norm_props_txt, comp_ex_txt, emoji_seq_txt, emoji_zwj_seq_txt, emoji_data_txt, emoji_test_txt, 
         inverse_json, ascii_json, idna_map_txt, idna_2008_txt) = results
    
        # Parse each file
        if blocks_txt: _parse_and_store_ranges(blocks_txt, "Blocks")
        if age_txt: _parse_and_store_ranges(age_txt, "Age")
        if id_type_txt: _parse_and_store_ranges(id_type_txt, "IdentifierType")
        if id_status_txt: _parse_and_store_ranges(id_status_txt, "IdentifierStatus")
        if intentional_txt: _parse_intentional(intentional_txt)
        if confusables_txt:
            # Parse Confusables with Type Preservation (Forensic Upgrade)
            # Format: Code ; Target ; Type # Comment
            # We strictly need the 'Type' (MA, ML, SA, SL) for the new Intel Engine.
            temp_map = {}
            lines = confusables_txt.split('\n')
            for line in lines:
                # 1. Strip comments first to ensure clean parsing
                if '#' in line:
                    line = line.split('#')[0]
                
                if line.strip():
                    parts = line.split(';')
                    if len(parts) >= 3:
                        src = int(parts[0].strip(), 16)
                        
                        # Parse target sequence
                        tgt_hex = parts[1].strip().split()
                        tgt = "".join([chr(int(x, 16)) for x in tgt_hex])
                        
                        # Parse Type (MA, ML, SA, SL)
                        tag = parts[2].strip()
                        
                        # Store as tuple: (target_string, tag_type)
                        # This enables the "Smart Skeleton" logic
                        temp_map[src] = (tgt, tag)
                        
            DATA_STORES["Confusables"] = temp_map
            print(f"Loaded {len(temp_map)} Confusable mappings with Forensic Types.")

        # --- Load Forensic JSONs ---
        if inverse_json:
            DATA_STORES["InverseConfusables"] = json.loads(inverse_json)
            print(f"Loaded Inverse Confusables map.")

        if ascii_json:
            # Update the global ASCII_CONFUSABLES set with rigorous data
            # We assume ascii_json is a list of integers
            loaded_ascii = set(json.loads(ascii_json))
            global ASCII_CONFUSABLES
            ASCII_CONFUSABLES = loaded_ascii
            print(f"Loaded {len(ASCII_CONFUSABLES)} high-risk ASCII homoglyphs.")
        
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

        # ---: Create the bucket dynamically ---
        if derivedcore_txt:
            # 1. Initialize the new bucket
            DATA_STORES["DefaultIgnorable"] = {"ranges": [], "starts": [], "ends": []}
            
            # 2. Map the file properties
            _parse_property_file(derivedcore_txt, {
                # Map the specific property name to our new bucket key
                "Default_Ignorable_Code_Point": "DefaultIgnorable",
                "Other_Default_Ignorable_Code_Point": "OtherDefaultIgnorable",
                "Alphabetic": "Alphabetic", 
                "Logical_Order_Exception": "LogicalOrderException"
            })

        # --- IDNA Parsers ---
        if idna_map_txt: _parse_idna_mapping(idna_map_txt)
        if idna_2008_txt: _parse_idna2008(idna_2008_txt)
        
        # --- Add Manual Security Overrides ---
        _add_manual_data_overrides()    
        
        # --- NEW: Build Forensic Bitmask Table ---
        # This must happen AFTER all parsing is done
        build_invis_table()
        
        # --- NEW: Run Self-Tests ---
        run_self_tests()
        
        LOADING_STATE = "READY"
        print("Unicode data loaded successfully.")
        render_status("Ready.")
        update_all() # Re-render with ready state
        
    except Exception as e:
        LOADING_STATE = "FAILED"
        print(f"CRITICAL: Unicode data loading failed. Error: {e}")
        # ---: Remove 'is_error=True' ---
        render_status("Error: Failed to load Unicode data. Please refresh.")
    
    finally:
        # RELEASE THE LOCK so we can retry if needed
        LOADING_LOCK = False

# ===============================================
# BLOCK 5. HELPER UTILITIES & TRANSFORMS
# ===============================================

# Grapheme Segmenter (UAX #29)
# Required by: compute_emoji_analysis, inspect_character
try:
    GRAPHEME_SEGMENTER = window.Intl.Segmenter.new("en", {"granularity": "grapheme"})
except Exception:
    GRAPHEME_SEGMENTER = None # Fallback or error handling

# Runtime State Initialization
HUD_HIT_REGISTRY = {}

# Registry & DOM Helpers

def _register_hit(key: str, start: int, end: int, label: str):
    """Helper to append a hit to the global registry."""
    if key not in HUD_HIT_REGISTRY:
        HUD_HIT_REGISTRY[key] = []
    HUD_HIT_REGISTRY[key].append((start, end, label))

def _dom_to_logical(t: str, dom_idx: int) -> int:
    """
    Converts a DOM UTF-16 index to a Python Logical Code Point index.
    """
    if not t: return 0
    
    logical_idx = 0
    utf16_acc = 0
    
    for char in t:
        if utf16_acc >= dom_idx:
            return logical_idx
        utf16_acc += (2 if ord(char) > 0xFFFF else 1)
        logical_idx += 1
        
    return logical_idx

# Visual Helpers
def get_icon(key, color="currentColor", size=16):
    path = ICONS.get(key, "")
    return f'<svg xmlns="http://www.w3.org/2000/svg" width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" stroke="{color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">{path}</svg>'

# Core Lookup Utilities

def _find_in_ranges(cp: int, store_key: str):
    """Generic range finder using bisect."""
    
    store = DATA_STORES[store_key]
    starts_list = store["starts"]
    
    if not starts_list:
        return None
    
    i = bisect.bisect_right(starts_list, cp) - 1
    if i >= 0 and cp <= store["ends"][i]:
        return store["ranges"][i][2] # Return the value
    return None

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

def _compute_storage_metrics(t: str, supplementary_count: int):
    """
    Helper to calculate the Physical and Runtime dimensions of the text.
    Centralizes the 'encode' logic to ensure consistency.
    """
    return {
        "UTF-16 Units": len(t.encode('utf-16-le')) // 2, # JS/Java .length
        "UTF-8 Bytes": len(t.encode('utf-8')),           # Disk/Network size
        "Astral Count": supplementary_count              # Re-use existing loop count
    }

# Sanitization & Escaping

def _escape_html(s: str):
    """Escapes basic HTML characters including quotes for attribute safety."""
    s = s.replace("&", "&amp;")
    s = s.replace("<", "&lt;")
    s = s.replace(">", "&gt;")
    s = s.replace('"', "&quot;")
    return s

def _escape_for_js(s: str) -> str:
    """
    Sanitizes a string for safe insertion into a JS single-quoted string literal.
    Escapes backslashes, quotes, newlines, and dangerous HTML-like sequences.
    """
    # 1. Backslash must be first to avoid double-escaping
    s = s.replace("\\", "\\\\")
    # 2. Escape quotes
    s = s.replace("'", "\\'")
    s = s.replace('"', '\\"')
    # 3. Escape whitespace control chars
    s = s.replace("\n", "\\n")
    s = s.replace("\r", "\\r")
    # 4. Defensive: Break potentially dangerous tags if they somehow sneaked in
    s = s.replace("</", "<\\/")
    return s

# Normalization Engines (Transformations)

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

def _generate_uts39_skeleton(t: str, return_events=False):
    """
    Generates the UTS #39 'Skeleton' following the full forensic pipeline.
    [HARDENED v1.1] Robust against Schema Drift in DATA_STORES.
    
    Args:
        t (str): Input string.
        return_events (bool): If True, returns (skeleton, events_dict). 
                              If False, returns just skeleton string (Backward Compat).
    """
    # 0. Safety Check
    if LOADING_STATE != "READY" or not t:
        return ("", {}) if return_events else ""
        
    events = {
        "confusables_mapped": 0,
        "ignorables_stripped": 0,
        "mappings": []
    }

    # 1. NFKC (Compatibility Normalization)
    # Collapses fullwidth (Ａ->A) and ligatures (ﬁ->fi)
    try:
        s1 = unicodedata2.normalize("NFKC", t)
    except:
        s1 = unicodedata.normalize("NFKC", t)

    # 2. Casefold (Identity Normalization)
    # Collapses case distinctions (A->a)
    s2 = s1.casefold()

    # 3. Map Confusables (Visual Transformation)
    confusables_map = DATA_STORES.get("Confusables", {})
    mapped_chars = []
    
    for char in s2:
        cp = ord(char)
        if cp in confusables_map:
            # Found a mapping!
            val = confusables_map[cp]
            
            # [CRITICAL FIX] Schema Tolerance Logic
            # We strictly extract what we need (Target, Tag) and ignore the rest.
            tgt = char # Default safe fallback
            tag = "UNK"
            
            if isinstance(val, (tuple, list)):
                # Handle Tuple (New Format): (Target, Tag, [Optional...])
                if len(val) >= 2:
                    tgt = val[0]
                    tag = val[1]
                elif len(val) == 1:
                    tgt = val[0]
            elif isinstance(val, str):
                tgt = val
            
            mapped_chars.append(tgt)
            
            # Log the forensic event
            events["confusables_mapped"] += 1
            events["mappings"].append({
                "char": char,
                "hex": f"{cp:04X}",
                "map_to": tgt,
                "type": tag 
            })
        else:
            mapped_chars.append(char)
        
    s3 = "".join(mapped_chars)

    # 4. Strip Default Ignorables & Bidi (Visual Bone Structure)
    # UTS #39 requires stripping these to see the true visual layout
    filtered_chars = []
    
    # Pre-calculate mask for speed inside the loop
    MASK_STRIP = (INVIS_DEFAULT_IGNORABLE | INVIS_BIDI_CONTROL | INVIS_CRITICAL_CONTROL)

    for char in s3:
        cp = ord(char)
        is_ignorable = False
        
        # O(1) Bitmask Check (Bounds Checked)
        if cp < 1114112:
             if INVIS_TABLE[cp] & MASK_STRIP:
                 is_ignorable = True
        
        if not is_ignorable:
            filtered_chars.append(char)
        else:
            events["ignorables_stripped"] += 1
            
    s4 = "".join(filtered_chars)

    # 5. NFD Normalization (Canonical Final Form)
    # Ensures combining marks are in a consistent order for string equality checks
    try:
        final_skel = unicodedata2.normalize("NFD", s4)
    except:
        final_skel = unicodedata.normalize("NFD", s4)
        
    # 6. Return Contract
    if return_events:
        return final_skel, events
        
    return final_skel

# Tokenization & Profile Helpers

def tokenize_forensic(text: str):
    """
    Forensic Tokenizer (Adversarial Hardened).
    Splits on whitespace but treats Invisible/Format characters as PAYLOADS.
    Returns list of DICTIONARIES.
    """
    tokens = []
    if not text: return tokens
    
    # Python's .split() breaks on whitespace (Zs, Cc whitespace)
    raw_chunks = text.split()
    
    current_start = 0
    for chunk in raw_chunks:
        # Calculate real index (approximation for locating)
        idx = text.find(chunk, current_start)
        if idx == -1: idx = current_start # Fallback
        current_start = idx + len(chunk)
        
        # Strip outer "Open/Close" delimiters to isolate the Identifier
        clean = chunk.strip("()[]{}<>\"',;!|")
        
        if clean:
            tokens.append({
                'token': clean,
                'raw_chunk': chunk,
                'start': idx,
                'end': idx + len(chunk),
                'kind': 'word' # Default kind
            })
            
    return tokens

def _get_script_set(token: str) -> set:
    """Returns the set of unique Scripts used in the token."""
    scripts = set()
    for char in token:
        cp = ord(char)
        # 1. Try ScriptExtensions first (Handles common/inherited chars that morph)
        sc_ext = _find_in_ranges(cp, "ScriptExtensions")
        if sc_ext:
            # ScriptExtensions returns space-separated list e.g. "Latn Grek"
            scripts.update(sc_ext.split())
        else:
            # 2. Fallback to base Script
            sc = _find_in_ranges(cp, "Scripts")
            if sc and sc not in ("Common", "Inherited"):
                scripts.add(sc)
            elif sc == "Common" and 0x30 <= cp <= 0x39:
                # Digits are often Common but functionally behave as the surrounding script
                # We don't add them to avoid polluting the set with "Common"
                pass
    return scripts

def _get_identifier_profile(token: str) -> dict:
    """
    Checks UAX #31 Identifier Status and Type.
    Returns: { 'status': 'Allowed'|'Restricted'|'Disallowed', 'types': {Set of types} }
    """
    # Defaults
    profile = {
        "status": "Allowed", 
        "types": set(),
        "banned_chars": [] 
    }
    
    overall_status_priority = 0 # 0=Allowed, 1=Restricted, 2=Disallowed
    
    for char in token:
        cp = ord(char)
        
        # Check Status
        # Note: Data loader maps IdentifierStatus ranges. 
        # Usually: "Allowed" is implicit if not Restricted? 
        # Actually, UAX31 usually defines 'Allowed' ranges. 
        # We assume if found in "Restricted" list it is restricted.
        status_val = _find_in_ranges(cp, "IdentifierStatus")
        
        if status_val == "Restricted":
            overall_status_priority = max(overall_status_priority, 1)
            profile["banned_chars"].append(char)
        
        # Check Type (Technical, Recommended, Obsolete, etc.)
        type_val = _find_in_ranges(cp, "IdentifierType")
        if type_val:
            profile["types"].add(type_val)
            if type_val in ("Not_Recommended", "Deprecated", "Not_XID", "Obsolete"):
                overall_status_priority = max(overall_status_priority, 1)

    if overall_status_priority == 1: profile["status"] = "Restricted"
    if overall_status_priority == 2: profile["status"] = "Disallowed"
    
    return profile

def _classify_token_kind(token: str) -> str:
    """
    Heuristic classification of token type.
    """
    if "@" in token: return "email"
    if "." in token and not token.startswith(".") and not token.endswith("."):
        # Rudimentary domain check: looks like parts separated by dots
        # Refine: check if TLD part is > 1 char
        parts = token.split(".")
        if all(len(p) > 0 for p in parts) and len(parts[-1]) >= 2:
            return "domain"
    
    # Check if purely alphanumeric (plus _)
    # We use a broad regex for "Identifier-like"
    if re.match(r'^[\w]+$', token): 
        return "identifier"
        
    return "word"

def _get_broad_category(char):
    """Helper: Maps char to broad Forensic Class (Letter, Number, Symbol, Punct)."""
    cat = unicodedata.category(char)
    if cat.startswith('L'): return 'L'
    if cat.startswith('N'): return 'N'
    if cat.startswith('P'): return 'P'
    if cat.startswith('S'): return 'S'
    if cat.startswith('M'): return 'M' # Mark
    return 'O' # Other

# Normalization Metrics & Drift

def _generate_uts39_skeleton_metrics(t: str):
    """
    Generates the skeleton AND granular drift metrics deterministically.
    Returns: (skeleton_string, metrics_dict)
    """
    if LOADING_STATE != "READY":
        return "", {}
        
    confusables_map = DATA_STORES.get("Confusables", {})
    
    mapped_chars = []
    metrics = {
        "total_drift": 0,
        "drift_ascii": 0,        # Safe-ish (1 -> l)
        "drift_cross_script": 0, # Dangerous (Cyrillic a -> Latin a)
        "drift_other": 0         # Neutral (Accents, etc.)
    }
    
    for char in t:
        cp = ord(char)
        val = confusables_map.get(cp)
        
        # Handle Tuples
        skeleton_char_str = None
        if val:
            if isinstance(val, tuple):
                skeleton_char_str = val[0]
            else:
                skeleton_char_str = val
        
        if skeleton_char_str:
            mapped_chars.append(skeleton_char_str)
            metrics["total_drift"] += 1
            
            # 1. ASCII Drift
            if cp < 128 and all(ord(c) < 128 for c in skeleton_char_str):
                metrics["drift_ascii"] += 1
            # 2. Cross-Script Drift
            else:
                input_script = _find_in_ranges(cp, "Scripts")
                target_is_latin = any(_find_in_ranges(ord(c), "Scripts") == "Latin" for c in skeleton_char_str)
                if input_script not in ("Latin", "Common", "Inherited") and target_is_latin:
                    metrics["drift_cross_script"] += 1
                else:
                    metrics["drift_other"] += 1
        else:
            mapped_chars.append(char)
            
    return "".join(mapped_chars), metrics

def compute_normalization_drift(raw, nfkc, nfkc_cf, skeleton, skel_events=None):
    """
    Determines forensic drift using Metadata Proofs.
    Robustly handles missing metadata for backward compatibility.
    """
    # 1. Calculate Standard Equality Deltas
    changed_nfkc = (raw != nfkc)
    changed_casefold = (nfkc != nfkc_cf)
    string_diff_skeleton = (nfkc_cf != skeleton) # Fallback check
    
    # 2. Safe Event Unpacking (Back-Compat)
    if skel_events is None:
        skel_events = {'confusables_mapped': 0, 'ignorables_stripped': 0}
        
    # 3. Use Metadata for Advanced Deltas
    has_visual_mappings = skel_events.get('confusables_mapped', 0) > 0
    has_structure_strip = skel_events.get('ignorables_stripped', 0) > 0
    
    # Fallback: If string changed but no events recorded (Legacy Mode), assume Visual
    if string_diff_skeleton and not has_visual_mappings and not has_structure_strip:
        has_visual_mappings = True

    drift_profile = {
        "format": False,
        "identity": False,
        "visual": False,
        "structure": False,
        "verdict": "Stable (No Drift)",
        "class": "drift-clean",
        "score": 0,
        "events": skel_events # Pass through for UI
    }
    
    if not (changed_nfkc or changed_casefold or has_visual_mappings or has_structure_strip or string_diff_skeleton):
        return drift_profile

    # --- PRIORITY 1: Visual Drift (Homoglyphs) ---
    if has_visual_mappings:
        drift_profile["visual"] = True
        drift_profile["format"] = changed_nfkc
        drift_profile["identity"] = changed_casefold
        
        count = skel_events.get('confusables_mapped', 0)
        count_str = f"{count} " if count > 0 else ""
        drift_profile["verdict"] = f"Visual Drift ({count_str}Homoglyphs Mapped)"
        drift_profile["class"] = "drift-alert"
        drift_profile["score"] = 3
        return drift_profile

    # --- PRIORITY 2: Structure Drift (Invisible Stripping) ---
    if has_structure_strip:
        drift_profile["structure"] = True
        drift_profile["format"] = changed_nfkc
        
        count = skel_events.get('ignorables_stripped', 0)
        drift_profile["verdict"] = f"Structure Drift ({count} Hidden Chars Stripped)"
        drift_profile["class"] = "drift-alert" # High risk because usually malicious
        drift_profile["score"] = 2
        return drift_profile

    # --- PRIORITY 3: Identity Drift ---
    if changed_casefold:
        drift_profile["identity"] = True
        drift_profile["format"] = changed_nfkc
        drift_profile["verdict"] = "Identity Drift (Case Differences)"
        drift_profile["class"] = "drift-warn"
        drift_profile["score"] = 1
        return drift_profile

    # --- PRIORITY 4: Format Drift ---
    if changed_nfkc:
        drift_profile["format"] = True
        drift_profile["verdict"] = "Format Drift (Compatibility / Width)"
        drift_profile["class"] = "drift-warn"
        drift_profile["score"] = 1
        return drift_profile
        
    return drift_profile

# Inspector & Visualization Helpers

def _build_confusable_span(char: str, cp: int, confusables_map: dict) -> str:
    """
    Helper to build the <span class="confusable" title="...">...</span> HTML.
    [HARDENED] Robust against Tuple/String schema drift in confusables_map.
    """
    try:
        # [CRITICAL FIX] Defensive Unpacking
        # The map might return a String ('a') or a Tuple ('a', 'MA', ...)
        val = confusables_map[cp]
        
        if isinstance(val, tuple):
            # Take the first element (Target Char) and ignore metadata
            skeleton_char_str = val[0]
            # Optional: Capture tag if needed for future logic
            # tag = val[1] if len(val) > 1 else "UNK"
        else:
            # Legacy fallback (String)
            skeleton_char_str = val

        # --- EXISTING LOGIC PRESERVED BELOW ---
        
        # Ensure we have a string before performing string ops
        if not isinstance(skeleton_char_str, str):
            skeleton_char_str = str(skeleton_char_str)

        skeleton_cp_hex = f"U+{ord(skeleton_char_str[0]):04X}"
        skeleton_cp = ord(skeleton_char_str[0])
        
        source_script = _find_in_ranges(cp, "Scripts") or "Unknown"
        target_script = _find_in_ranges(skeleton_cp, "Scripts") or "Common"

        # Risk Label Logic (Unchanged)
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
    except Exception as e:
        # [HARDENED] Log error to console for debugging but don't crash UI
        # print(f"Error in _build_confusable_span for {char}: {e}")
        return f'<span class="confusable" title="Confusable processing error">{_escape_html(char)}</span>'

def _get_single_char_skeleton(s: str) -> str:
    """
    Generates the UTS #39 skeleton for a single character context.
    Reuses the global Confusables map to ensure consistency with Threat Engine.
    """
    confusables_map = DATA_STORES.get("Confusables", {})
    res = []
    for char in s:
        cp = ord(char)
        val = confusables_map.get(cp)
        
        if val:
            # DEFENSIVE: Handle New Tuple Format (tgt, tag) vs Legacy String
            if isinstance(val, tuple):
                mapped = val[0] # Extract the skeleton string
            else:
                mapped = val    # Legacy fallback
        else:
            mapped = char       # No mapping exists
            
        res.append(mapped)
    return "".join(res)

def _classify_macro_type(cp, cat, id_status, mask):
    """
    Determines the 'Macro-Type' for the Forensic HUD.
    Refined V3 Logic: strict separation of Rot, Syntax, and Threat.
    """
    is_ascii = (cp <= 0x7F)

    # 0. DATA ROT (Corruption / Integrity Failures)
    # Cn (Unassigned), Cs (Surrogate), Co (Private Use)
    # Add FFFD and NUL to the definition of ROT
    if cat in ('Cn', 'Cs', 'Co') or cp == 0xFFFD or cp == 0x0000: 
        return "ROT"

    # 1. TRUE THREATS (Active Attack Vectors)
    # Must mask specifically to Bidi, High-Risk Invisibles, or Tags
    if mask & (INVIS_BIDI_CONTROL | INVIS_HIGH_RISK_MASK): 
        return "THREAT"

    # 2. FORMAT / CONTROL (Context-Dependent)
    # Cf (Format) that isn't high-risk. E.g. ZWNJ in Persian is fine.
    if cat == 'Cf': 
        return "COMPLEX"

    # 3. COMPLEX (Rich Text)
    # Combining Marks (Mn, Mc, Me)
    if cat.startswith('M'): 
        return "COMPLEX"
    
    # 4. WHITESPACE (Structural)
    if cat.startswith('Z'):
        return "SYNTAX"

    # 5. STANDARD (Safe Atoms)
    # ASCII Letters/Digits.
    if is_ascii and cat in ('Ll', 'Lu', 'Nd'): 
        return "STANDARD"

    # 6. SYNTAX (Technical/Punctuation)
    # ASCII Punctuation/Symbols.
    if is_ascii and cat.startswith(('P', 'S')):
        return "SYNTAX"

    # 7. LEGACY / EXTENDED (Everything Else)
    # Extended Latin, Emoji, Symbols, non-ASCII punctuation.
    return "LEGACY"

def _get_ghost_chain(char: str):
    """
    Returns the Quad-State Ghost Chain if meaningful normalization occurs.
    Filters out simple ASCII case changes to reduce noise.
    """
    raw = char
    nfkc = normalize_extended(raw)
    casefold = nfkc.casefold()
    
    # Use the consistent skeleton logic
    skeleton = _get_single_char_skeleton(casefold)

    # NOISE FILTER: Ignore simple ASCII case changes (A -> a)
    def is_boring_change(a, b):
        return a == b or (len(a) == 1 and len(b) == 1 and ord(a) < 128 and ord(b) < 128 and a.lower() == b.lower())

    # If raw matches skeleton (ignoring case), it's boring
    if is_boring_change(raw, nfkc) and is_boring_change(nfkc, casefold) and is_boring_change(casefold, skeleton):
        return None

    # VISUALIZE ERASURE: If char disappears, show ∅
    return {
        "raw": raw,
        "nfkc": nfkc if nfkc else "∅",
        "casefold": casefold if casefold else "∅",
        "skeleton": skeleton if skeleton else "∅"
    }

def _compute_cluster_identity(cluster_str, base_char_data):
    """
    Forensic Cluster Aggregator (Pro Grade).
    Implements TR-51 Emoji Semantics, UAX #9 Strong Bidi, and UAX #31 Script logic.
    """
    # 1. Atomic Shortcut
    if len(cluster_str) == 1:
        return {
            "type_label": "CATEGORY (Gc)",
            "type_val": f"{base_char_data['category_full']} ({base_char_data['category_short']})",
            "block_val": base_char_data['block'],
            "script_val": base_char_data['script'],
            "bidi_val": base_char_data['bidi'],
            "age_val": base_char_data['age'],
            "is_cluster": False,
            "cluster_mask": INVIS_TABLE[ord(cluster_str)] if ord(cluster_str) < 1114112 else 0,
            "max_risk_cat": base_char_data['category_short']
        }

    # 2. Molecular Aggregation
    blocks = set()
    scripts = set()
    bidi_strong = set() # Strong types only (L, R, AL)
    ages = []
    
    cluster_mask = 0
    risk_cats = set()
    
    mark_count = 0
    
    for char in cluster_str:
        cp = ord(char)
        
        # A. Harvest Data
        blk = _find_in_ranges(cp, "Blocks") or "No_Block"
        scr = _find_in_ranges(cp, "Scripts") or "Common"
        bid = unicodedata.bidirectional(char)
        cat = unicodedata.category(char)
        age_str = _find_in_ranges(cp, "Age") or "0.0"
        
        # B. Accumulate
        blocks.add(blk)
        
        # UAX #31: Ignore Common/Inherited for script mixing
        if scr not in ("Common", "Inherited"):
            scripts.add(scr)
            
        # UAX #9: Track only Strong Bidi Types
        if bid in ("L", "R", "AL"):
            bidi_strong.add(bid)
            
        try: ages.append(float(age_str))
        except: pass
        
        # C. Risk Tracking
        if cp < 1114112:
             cluster_mask |= INVIS_TABLE[cp]
        risk_cats.add(cat)
        
        if cat.startswith("M"): mark_count += 1

    # --- SYNTHESIZE TRUTH ---

    # 1. Emoji Semantics (TR-51)
    # Check against pre-loaded RGI sets (if available)
    rgi_set = DATA_STORES.get("RGISequenceSet", set())
    
    # Default Type
    if mark_count > 0:
        type_label = "COMPOSITION"
        type_val = f"Base + {mark_count} Marks"
    else:
        type_label = "SEQUENCE"
        type_val = f"{len(cluster_str)} Code Points"

    # Specific Overrides
    if cluster_str in rgi_set:
        type_label = "EMOJI SEQUENCE"
        # Distinguish types if possible, or just label RGI
        if "\u20E3" in cluster_str: type_val = "Keycap Sequence" # Keycap
        elif "\u200D" in cluster_str: type_val = "ZWJ Sequence"   # ZWJ
        elif len(cluster_str) == 2 and 0x1F1E6 <= ord(cluster_str[0]) <= 0x1F1FF: type_val = "Flag Sequence" # RI
        else: type_val = "RGI (Valid)"

    # 2. Block Truth
    # Prioritize the Base Block, but flag mixture
    base_block = base_char_data['block']
    other_blocks = blocks - {base_block}
    if not other_blocks:
        block_display = base_block
    else:
        # Explicitly label as 'Block(s)' to distinguish from character count
        count = len(other_blocks)
        suffix = "Block" if count == 1 else "Blocks"
        block_display = f"{base_block} + {count} {suffix}"

    # 3. Script Truth (Clean)
    if not scripts:
        script_display = "Common / Inherited"
    elif len(scripts) == 1:
        script_display = list(scripts)[0]
    else:
        script_display = f"Mixed ({', '.join(sorted(scripts))})"

    # 4. Bidi Truth (Strong)
    if not bidi_strong:
        bidi_display = base_char_data['bidi'] # Fallback to base (likely Neutral/Weak)
    elif len(bidi_strong) == 1:
        bidi_display = list(bidi_strong)[0]
    else:
        bidi_display = "Mixed Strong Direction" # Real risk

    # 5. Age Range
    if ages:
        min_age = min(ages)
        max_age = max(ages)
        age_display = f"{min_age} – {max_age}" if min_age != max_age else str(max_age)
    else:
        age_display = "1.1"

    # 6. Max Risk Category (for Macro-Classification)
    # Precedence: Rot > Control > Mark > Standard
    max_risk_cat = "Ll" # Default safe
    if any(c in ("Cn", "Cs", "Co") for c in risk_cats): max_risk_cat = "Cn"
    elif any(c == "Cf" for c in risk_cats): max_risk_cat = "Cf"
    elif any(c.startswith("M") for c in risk_cats): max_risk_cat = "Mn"
    
    return {
        "type_label": type_label,
        "type_val": type_val,
        "block_val": block_display,
        "script_val": script_display,
        "bidi_val": bidi_display,
        "age_val": age_display,
        "is_cluster": True,
        "cluster_mask": cluster_mask,
        "max_risk_cat": max_risk_cat
    }

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

# ===============================================
# BLOCK 6. FORENSIC LOGIC ENGINES (PURE LOGIC)
# ===============================================

# A. Stage 1.5 Micro-Analyzers (The Sensors)

def scan_vs_topology(text: str):
    """
    [STAGE 1.5] Variation Selector Topology Engine.
    Detects: Excessive runs (>1) and Bare VS (not preceded by valid base).
    Source: Imperceptible Jailbreaking (VS flooding).
    """
    if not text: return {}, []
    
    vs_run_count = 0
    max_run = 0
    bare_count = 0
    total_vs = 0
    
    # Get the valid base set (Tier 1 + Tier 3 from Data Stores)
    valid_bases = DATA_STORES.get("VariantBase", frozenset())
    
    # Bitmask for ANY VS (Standard or Ideographic)
    VS_MASK = INVIS_VARIATION_STANDARD | INVIS_VARIATION_IDEOG
    
    prev_cp = -1
    
    for char in text:
        cp = ord(char)
        mask = INVIS_TABLE[cp] if cp < 1114112 else 0
        
        if mask & VS_MASK:
            total_vs += 1
            vs_run_count += 1
            
            # Check if Bare (Start of run check)
            if vs_run_count == 1:
                # This is the first VS in a sequence. Check antecedent.
                # If prev_cp is -1 (Start of string) or not in Valid Bases -> Bare
                if prev_cp == -1 or prev_cp not in valid_bases:
                    bare_count += 1
        else:
            if vs_run_count > 0:
                max_run = max(max_run, vs_run_count)
                vs_run_count = 0
        
        prev_cp = cp
        
    # Capture trailing run
    if vs_run_count > 0:
        max_run = max(max_run, vs_run_count)
        
    metrics = {
        "vs_total_count": total_vs,
        "vs_max_run_length": max_run,
        "vs_bare_count": bare_count
    }
    
    signals = []
    if bare_count > 0:
        signals.append({
            "type": "VS_BARE",
            "count": bare_count,
            "desc": f"{bare_count} Orphaned Variation Selectors"
        })
        
    if max_run > 1:
        # A run of >1 is structurally redundant (Standard allows 1 per base)
        signals.append({
            "type": "VS_CLUSTER",
            "max_len": max_run,
            "desc": f"Variation Selector Cluster (Length {max_run})"
        })
        
    return metrics, signals

def decode_tag_payload(text: str):
    """
    [STAGE 1.5] Tag Payload Decoder.
    Decodes Plane 14 Tags (U+E00xx) into ASCII to reveal hidden instructions.
    Source: Bypassing Guardrails (Hidden Instructions).
    """
    hidden_chars = []
    
    for char in text:
        cp = ord(char)
        # Plane 14 Tag Block: E0020 - E007E (printable ASCII range mapped to Tags)
        if 0xE0020 <= cp <= 0xE007E:
            ascii_code = cp - 0xE0000
            hidden_chars.append(chr(ascii_code))
            
    if not hidden_chars:
        return None
        
    decoded = "".join(hidden_chars)
    preview = decoded[:50] + "..." if len(decoded) > 50 else decoded
    
    return {
        "type": "TAG_PAYLOAD",
        "payload_len": len(hidden_chars),
        "preview": preview,
        "desc": f"Hidden Tag Payload: '{_escape_html(preview)}'"
    }

def scan_delimiter_masking(text: str):
    """
    [STAGE 1.5] Delimiter Masking Engine (Extension Hiding).
    Detects: [Suspicious Space] + [Dot] + [AlphaExtension].
    Source: Mandiant (Malware extension masking with U+2800).
    """
    if "." not in text: return []
    
    signals = []
    text_len = len(text)
    
    # Define Suspicious Mask: Non-ASCII Space, ZWSP, Default Ignorable, or Joiners
    MASK_DECEPTIVE = INVIS_NON_ASCII_SPACE | INVIS_ZERO_WIDTH_SPACING | INVIS_DEFAULT_IGNORABLE | INVIS_JOIN_CONTROL
    
    for i, char in enumerate(text):
        if char == '.':
            if i == 0: continue
            
            # 1. Check Left Context (Must be suspicious)
            prev_char = text[i-1]
            prev_cp = ord(prev_char)
            prev_mask = INVIS_TABLE[prev_cp] if prev_cp < 1114112 else 0
            
            # [cite_start]Specific check for Braille Pattern Blank (U+2800) as it's the highest risk [cite: 1460]
            is_braille = (prev_cp == 0x2800)
            is_suspicious = (prev_mask & MASK_DECEPTIVE) or is_braille
            
            if not is_suspicious:
                continue
                
            # 2. Check Right Context (Must look like an extension: 2-4 Alphanumerics)
            # e.g., .exe, .bat, .js
            ext_str = ""
            valid_ext = False
            
            for k in range(1, 5):
                if i + k >= text_len: break
                next_char = text[i+k]
                if next_char.isalnum():
                    ext_str += next_char
                else:
                    break
            
            if 2 <= len(ext_str) <= 4:
                valid_ext = True
                
            if valid_ext:
                mask_type = "Braille Blank" if is_braille else "Invisible/Deceptive Space"
                signals.append({
                    "type": "MASKED_EXTENSION",
                    "pos": i - 1, # Point to the masking char
                    "desc": f"Extension Masking ({mask_type} before '.{ext_str}')"
                })
                
    return signals

def scan_token_fracture_safe(token_text):
    """
    [STAGE 1.5] Script-Aware Fracture Scanner (Upgraded v3).
    Detects: [Alpha] + [Fracture Agent(s)] + [Alpha].
    Fracture Agents: Invisibles, Tags, Bidi, AND Emojis.
    
    Improvements:
    1. Handles contiguous runs of agents (e.g. "te<ZWSP><ZWSP>st").
    2. Script-Aware Safety (Persian Defense) applied to ALL agents in the fracture.
    """
    if len(token_text) < 3: return []
    
    signals = []
    
    # Helper to check if a char is a Fracture Agent
    def is_fracture_agent(cp):
        if cp >= 1114112: return False
        mask = INVIS_TABLE[cp]
        # Invisible/Format/Control mask
        if mask & (INVIS_ZERO_WIDTH_SPACING | INVIS_JOIN_CONTROL | INVIS_TAG | 
                   INVIS_BIDI_CONTROL | INVIS_SOFT_HYPHEN | INVIS_VARIATION_STANDARD | 
                   INVIS_VARIATION_IDEOG):
            return True
        # Emoji/Pictographic check
        if _find_in_ranges(cp, "Emoji") or _find_in_ranges(cp, "Extended_Pictographic"):
            return True
        return False

    # Iterate looking for transitions: Alpha -> Agent
    i = 0
    while i < len(token_text):
        char = token_text[i]
        if not char.isalnum():
            i += 1
            continue
            
        # Found Alpha at `i`. Now look ahead for Agents.
        j = i + 1
        agent_run = []
        
        while j < len(token_text):
            next_char = token_text[j]
            next_cp = ord(next_char)
            
            if is_fracture_agent(next_cp):
                agent_run.append((j, next_cp))
                j += 1
            else:
                break
        
        # Now `j` is at the character AFTER the agent run (or end of string)
        # If we found agents AND we have an Alpha on the other side...
        if agent_run and j < len(token_text) and token_text[j].isalnum():
            
            # --- ANALYSIS: Verify the fracture ---
            prev_cp = ord(token_text[i])
            # We use the script of the LEFT char as the context anchor
            context_script = _find_in_ranges(prev_cp, "Scripts") or "Common"
            
            # Check PERSIAN DEFENSE for *every* agent in the run
            # If ANY agent is "unsafe" in this context, the whole fracture is valid.
            # If ALL agents are "safe" (valid joiners), we ignore it.
            is_valid_fracture = False
            
            for pos, ag_cp in agent_run:
                # ZWJ/ZWNJ in Complex Scripts is Valid Orthography
                if context_script in COMPLEX_ORTHOGRAPHY_SCRIPTS and ag_cp in (0x200C, 0x200D):
                    continue # Safe
                
                # If we hit a non-safe agent (e.g. Emoji, Tag, or ZWSP in English), flag it!
                is_valid_fracture = True
                
                # Determine type for reporting
                ag_mask = INVIS_TABLE[ag_cp] if ag_cp < 1114112 else 0
                ag_type = "Emoji" if not (ag_mask & INVIS_ANY_MASK) else "Invisible"
                
                if is_valid_fracture:
                    signals.append({
                        "type": "TOKEN_FRACTURE",
                        "char_hex": f"U+{ag_cp:04X}",
                        "context_script": context_script,
                        "position": pos,
                        "agent_type": ag_type,
                        "run_len": len(agent_run)
                    })
            
        # Advance main loop past the agents
        i = j

    return signals

def scan_injection_vectors(text):
    """
    [STAGE 1.5] Injection Pattern Matcher.
    Detects: ANSI Escapes, Tag Sequences, and Imperative Overrides.
    Returns: Neutral signals (facts), not verdicts.
    """
    signals = []
    
    # 1. ANSI Escape Sequences (Source 1)
    # \x1b followed by [
    if "\x1b[" in text:
        matches = INJECTION_PATTERNS["ANSI_ESCAPE"].findall(text)
        if matches:
            signals.append({
                "type": "ANSI_SEQUENCE",
                "count": len(matches),
                "example": matches[0][:10] # Snippet
            })

    # 2. Plane 14 Tag Characters (Source 1 & 3)
    # Range: U+E0000 - U+E007F
    tag_count = 0
    for char in text:
        if TAG_BLOCK_START <= ord(char) <= TAG_BLOCK_END:
            tag_count += 1
            
    if tag_count > 0:
        signals.append({
            "type": "TAG_SEQUENCE",
            "count": tag_count
        })

    # 3. Imperative Overrides (Source 1)
    if INJECTION_PATTERNS["OVERRIDE"].search(text):
        signals.append({"type": "IMPERATIVE_OVERRIDE"})

    # 4. Tool Chaining (Source 1)
    if INJECTION_PATTERNS["TOOL_CHAIN"].search(text):
        signals.append({"type": "TOOL_CHAIN_PATTERN"})

    return signals

def scan_domain_structure_v2(token_text):
    """
    [STAGE 1.5] Domain Structure Scanner.
    Detects: Script Mixing, Skeleton Collisions, Pseudo-Delimiters.
    Scope: Runs only on tokens that look like domains.
    """
    # Fast filter: Must have a dot or start with xn--
    if "." not in token_text and not token_text.startswith("xn--"):
        return []

    signals = []
    
    # 1. Pseudo-Delimiters (Syntax Spoofing)
    # characters that look like '.', '/', '@' but aren't
    fake_dots = []
    for char in token_text:
        cp = ord(char)
        if cp in PSEUDO_DELIMITERS:
            fake_dots.append(f"{PSEUDO_DELIMITERS[cp]} (U+{cp:04X})")
            
    if fake_dots:
        signals.append({
            "type": "PSEUDO_DELIMITER",
            "artifacts": fake_dots
        })

    # 2. Script Mixing (Per Label)
    # We analyze labels individually (e.g., "google" in "google.com")
    labels = token_text.split('.')
    for label in labels:
        if not label: continue
        
        # Get scripts in this label
        scripts = _get_script_set(label)
        # Filter out safe scripts (Common/Inherited)
        major_scripts = {s for s in scripts if s not in ("Common", "Inherited", "Unknown")}
        
        if len(major_scripts) > 1:
            signals.append({
                "type": "DOMAIN_MIXED_SCRIPTS",
                "scripts": sorted(list(major_scripts)),
                "label": label
            })
            
    # 3. Skeleton Collision (Fact Check)
    # Does the skeleton differ from the raw text in a way that mimics ASCII?
    # (Simplified check: If not ASCII, but Skeleton IS ASCII -> Collision Risk)
    if not token_text.isascii():
        skel = _generate_uts39_skeleton(token_text)
        if skel != token_text and skel.isascii():
            signals.append({
                "type": "DOMAIN_SKELETON_MATCH_ASCII",
                "skeleton": skel
            })

    return signals

def scan_contextual_lures(text):
    """
    [STAGE 1.5] Contextual Lure Scanner.
    Detects Application-Layer attacks: Markdown Exfiltration, Chat Templates, and Memory Poisoning.
    """
    signals = []
    
    # 1. Markdown Image Exfiltration (Trust No AI: Scenario 2)
    # Risk: Automatic rendering triggers GET request to attacker server
    if "![" in text and "](" in text:
        matches = CONTEXT_LURE_PATTERNS["MARKDOWN_IMAGE"].findall(text)
        if matches:
            signals.append({
                "type": "MARKDOWN_EXFIL",
                "count": len(matches),
                "example": matches[0][:20] + "..." # Snippet for context
            })

    # 2. Chat Template Injection (Masquerading)
    # Risk: User fakes "System" turn to override safety guidelines
    if "<|" in text or "[" in text:
        matches = CONTEXT_LURE_PATTERNS["CHAT_HEADER"].findall(text)
        if matches:
            # Deduplicate matches
            unique_headers = list(set(matches))
            signals.append({
                "type": "CHAT_TEMPLATE_INJ",
                "headers": unique_headers
            })

    # 3. Memory Poisoning (Trust No AI: SpAIware)
    # Risk: Persistent prompt injection stored in user profile/memory
    if "remember" in text.lower() or "memory" in text.lower():
        matches = CONTEXT_LURE_PATTERNS["MEMORY_DIRECTIVE"].findall(text)
        if matches:
            # findall returns tuples for groups, flatten if necessary or just take the full match (group 0 equivalent)
            # For this regex, group 0 covers the phrase.
            flat_matches = [m[0] if isinstance(m, tuple) else m for m in matches]
            signals.append({
                "type": "MEMORY_POISON",
                "keywords": list(set(flat_matches))
            })

    return signals

# B. Structural Analyzers (Macro Physics)

def analyze_invisible_clusters(t: str):
    """
    Walks the text once and returns a list of invisible clusters.
    """
    clusters = []
    if LOADING_STATE != "READY": return clusters

    # Use Python's built-in iteration over string (unicode code points)
    # This avoids JS bridge overhead for the loop
    
    in_cluster = False
    start_idx = None
    mask_union = 0
    high_risk = False
    has_alpha = False

    for i, ch in enumerate(t):
        cp = ord(ch)
        mask = INVIS_TABLE[cp] if cp < 1114112 else 0
        invisible = (mask & INVIS_ANY_MASK) != 0

        if invisible:
            if not in_cluster:
                # Start new cluster
                in_cluster = True
                start_idx = i
                mask_union = 0
                high_risk = False
                has_alpha = False

            mask_union |= mask
            if mask & INVIS_HIGH_RISK_MASK:
                high_risk = True
            
            # Check for 'Alpha' property (Semi-invisible sandwich)
            # We can use the _find_in_ranges helper, but for speed we might skip it
            # or use a simpler check. Let's use the helper for accuracy.
            if _find_in_ranges(cp, "Alphabetic"):
                has_alpha = True

        else:
            if in_cluster:
                # Close cluster
                end_idx = i - 1
                length = end_idx - start_idx + 1
                clusters.append({
                    "start": start_idx,
                    "end": end_idx,
                    "length": length,
                    "mask_union": mask_union,
                    "high_risk": high_risk,
                    "has_alpha": has_alpha,
                })
                in_cluster = False

    # Close trailing cluster
    if in_cluster:
        end_idx = len(t) - 1
        length = end_idx - start_idx + 1
        clusters.append({
            "start": start_idx,
            "end": end_idx,
            "length": length,
            "mask_union": mask_union,
            "high_risk": high_risk,
            "has_alpha": has_alpha,
        })

    return clusters

def summarize_invisible_clusters(t: str, rows: list):
    """Adds cluster-level analysis rows. Returns: max_run_length (int)."""
    clusters = analyze_invisible_clusters(t)
    if not clusters:
        return 0 

    total_clusters = len(clusters)
    max_run = max(c["length"] for c in clusters)
    
    def format_cluster(c):
        start, length, m = c["start"], c["length"], c["mask_union"]
        tags = []
        if m & INVIS_BIDI_CONTROL: tags.append("BIDI")
        if m & INVIS_JOIN_CONTROL: tags.append("JOIN")
        if m & INVIS_ZERO_WIDTH_SPACING: tags.append("ZW")
        if m & INVIS_TAG: tags.append("TAG")
        if m & INVIS_VARIATION_STANDARD: tags.append("VS")
        if m & INVIS_NON_ASCII_SPACE: tags.append("SPACE")
        if m & INVIS_NONSTANDARD_NL: tags.append("NL")
        if m & INVIS_SOFT_HYPHEN: tags.append("SHY")
        tag_str = "|".join(tags) if tags else "IGN"
        return f"#{start} (len={length}, {tag_str})"

    # Sort: High risk first, then longest
    sorted_clusters = sorted(clusters, key=lambda c: (not c["high_risk"], -c["length"]))
    top3 = sorted_clusters[:3]

    # 1. Cluster Count
    sev = "crit" if any(c["high_risk"] for c in clusters) else "warn"
    rows.append({
        "label": "Invisible Clusters (All)",
        "count": total_clusters,
        "positions": [format_cluster(c) for c in top3],
        "severity": sev,
        "badge": "DANGER" if sev == "crit" else None
    })

    # 2. Max Run
    rows.append({
        "label": "Max Invisible Run Length",
        "count": max_run,
        "positions": [format_cluster(sorted_clusters[0])] if sorted_clusters else [],
        "severity": "crit" if max_run >= 4 else "warn",
        "badge": None
    })
    
    return max_run

def analyze_combining_structure(t: str, rows: list):
    """
    Scans for 'Zalgo' (excessive combining marks) and repeated marks.
    Adds rows directly to the list.
    """
    if LOADING_STATE != "READY": return

    zalgo_indices = []
    repeated_mark_indices = []
    invisible_mark_indices = [] # Marks on non-base characters

    segments_iterable = GRAPHEME_SEGMENTER.segment(t)
    segments = window.Array.from_(segments_iterable)

    for seg in segments:
        g_str = seg.segment
        index = seg.index
        
        # Count combining marks (Category Mn, Me)
        # We iterate manually to be fast and safe
        mark_count = 0
        last_cp = -1
        
        # Check base char (first char)
        base_char = g_str[0]
        base_cat = unicodedata.category(base_char)
        is_valid_base = base_cat[0] in ('L', 'N', 'S', 'P') # Letter, Number, Symbol, Punct
        
        js_chars = window.Array.from_(g_str)
        for i, char in enumerate(js_chars):
            cp = ord(char)
            cat = unicodedata.category(char)
            
            if cat in ('Mn', 'Me'):
                mark_count += 1
                
                # Check for repeated mark (Spoofing vector)
                if cp == last_cp:
                    # We flag the start of the grapheme for context
                    if f"#{index}" not in repeated_mark_indices:
                        repeated_mark_indices.append(f"#{index}")
            
            last_cp = cp

        # Thresholds
        if mark_count >= 4:
            zalgo_indices.append(f"#{index}")
            
        if mark_count > 0 and not is_valid_base and base_cat != "Co": # Ignore Private Use base
             # Marks on control chars, format chars, etc.
             invisible_mark_indices.append(f"#{index}")

    # Add Rows
    if zalgo_indices:
        rows.append({
            "label": "Flag: Excessive Combining Marks (Zalgo – Local Scan)",
            "count": len(zalgo_indices),
            "positions": zalgo_indices,
            "severity": "warn",
            "badge": "ZALGO"
        })
        
    if repeated_mark_indices:
        rows.append({
            "label": "Flag: Repeated Nonspacing Mark Sequence",
            "count": len(repeated_mark_indices),
            "positions": repeated_mark_indices,
            "severity": "warn",
            "badge": None
        })
        
    if invisible_mark_indices:
         rows.append({
            "label": "Flag: Marks on Non-Visual Base",
            "count": len(invisible_mark_indices),
            "positions": invisible_mark_indices,
            "severity": "crit",
            "badge": "HIDDEN"
        })

def analyze_nsm_overload(graphemes):
    """
    Analyze graphemes for excessive combining marks ("Zalgo"-style overload).
    Returns a dict with stable shape, using codepoint indices for positions.
    """
    total_g = len(graphemes)

    # Solid default: always return all keys so callers never KeyError.
    if total_g == 0:
        return {
            "level": 0,
            "max_marks": 0,
            "mark_density": 0.0,
            "max_repeat_run": 0,
            "total_marks": 0,
            "count": 0,
            "positions": [],
            "max_marks_positions": [],
        }

    total_marks = 0
    g_with_marks = 0
    max_marks = 0
    max_repeat_run = 0

    # Graphemes whose combining load crosses our "Zalgo" threshold.
    zalgo_indices = []

    # Graphemes that realise the global maximum intensity.
    max_intensity_indices = []

    # Global codepoint index (to report positions in the same space as other flags).
    current_cp_index = 0

    for glyph in graphemes:
        marks_in_g = 0
        current_repeat = 1
        max_g_repeat = 0
        last_cp = -1

        grapheme_start_pos = current_cp_index

        for ch in glyph:
            cp = ord(ch)

            # Robust combining detection: category OR non-zero CCC.
            ccc = _find_in_ranges(cp, "CombiningClass")
            is_comb = (
                unicodedata.category(ch) in ("Mn", "Me")
                or (ccc is not None and str(ccc) != "0")
            )

            if is_comb:
                marks_in_g += 1
                if cp == last_cp:
                    current_repeat += 1
                else:
                    max_g_repeat = max(max_g_repeat, current_repeat)
                    current_repeat = 1

            last_cp = cp
            current_cp_index += 1

        max_g_repeat = max(max_g_repeat, current_repeat)
        total_marks += marks_in_g

        if marks_in_g > 0:
            g_with_marks += 1

        # Track global max intensity.
        if marks_in_g > max_marks:
            max_marks = marks_in_g
            max_intensity_indices = [f"#{grapheme_start_pos}"]
        elif marks_in_g == max_marks and marks_in_g > 0:
            max_intensity_indices.append(f"#{grapheme_start_pos}")

        max_repeat_run = max(max_repeat_run, max_g_repeat)

        # Zalgo threshold: 3+ combining marks on a *single* grapheme.
        if marks_in_g >= 3:
            zalgo_indices.append(f"#{grapheme_start_pos}")

    mark_density = g_with_marks / total_g if total_g > 0 else 0.0

    # Heuristic severity:
    #  - level 2 (strong): clearly abusive use of combining marks
    #  - level 1 (mild): something odd but not extreme
    level = 0
    if (
        max_marks >= 7              # one grapheme is overloaded
        or mark_density > 0.7       # most graphemes carry marks
        or total_marks >= 64        # global "wall of marks"
        or max_repeat_run >= 6      # long run of same combining mark
    ):
        level = 2
    elif not (
        max_marks <= 2
        and mark_density <= 0.35
        and max_repeat_run <= 2
    ):
        # Anything outside the "safe" zone but below strong threshold -> mild.
        level = 1

    return {
        "level": level,
        "max_marks": max_marks,
        "mark_density": round(mark_density, 2),
        "max_repeat_run": max_repeat_run,
        "total_marks": total_marks,

        # What the flag row should actually show:
        "count": len(zalgo_indices),
        "positions": zalgo_indices,

        # Where the worst cluster(s) live (for future use / debugging):
        "max_marks_positions": max_intensity_indices,
    }

def analyze_bidi_structure(t: str, rows: list):
    """
    UAX #9 COMPLIANT BIDI STACK MACHINE (Enhanced for Stepper)
    Returns: (penalty_count, fracture_ranges, danger_ranges)
    """
    if LOADING_STATE != "READY": return 0, [], []

    # Data Models
    ISO_INIT = {0x2066, 0x2067, 0x2068} # LRI, RLI, FSI
    EMB_INIT = {0x202A, 0x202B, 0x202D, 0x202E} # LRE, RLE, LRO, RLO
    VAL_PDI = 0x2069
    VAL_PDF = 0x202C
    
    main_stack = [] 
    bracket_stack = [] 
    mirror_map = DATA_STORES.get("BidiMirroring", {})

    # Range Collectors (start, end, label)
    fracture_ranges = [] # Structural breaks (Integrity)
    danger_ranges = []   # Trojan Source patterns (Threat)

    js_array = window.Array.from_(t)
    
    for i, char in enumerate(js_array):
        cp = ord(char)
        
        # --- A. PUSH (Open Scope) ---
        if cp in ISO_INIT:
            main_stack.append({'kind': 'isolate', 'is_isolate': True, 'pos': i, 'cp': cp})
        elif cp in EMB_INIT:
            kind = 'override' if cp in {0x202D, 0x202E} else 'embedding'
            main_stack.append({'kind': kind, 'is_isolate': False, 'pos': i, 'cp': cp})
            
            # THREAT: Track Embeddings/Overrides as potential Trojan Source
            # We record the *opener* as the danger point.
            label = "Bidi Override" if kind == 'override' else "Bidi Embedding"
            danger_ranges.append((i, i+1, label))

        # --- B. POP PDF (Close Embedding) ---
        elif cp == VAL_PDF:
            if main_stack and not main_stack[-1]['is_isolate']:
                main_stack.pop()
            else:
                # Unmatched PDF
                # fracture_ranges.append((i, i+1, "Unmatched PDF")) # Optional: Low severity
                pass

        # --- C. POP PDI (Close Isolate) ---
        elif cp == VAL_PDI:
            isolate_index = -1
            for idx in range(len(main_stack) - 1, -1, -1):
                if main_stack[idx]['is_isolate']:
                    isolate_index = idx
                    break
            
            if isolate_index == -1:
                # Unmatched PDI
                # fracture_ranges.append((i, i+1, "Unmatched PDI"))
                pass
            else:
                if isolate_index != len(main_stack) - 1:
                    # Implicit Closure (Fracture)
                    # Highlight from the implicit closer PDI
                    fracture_ranges.append((i, i+1, "Implicit Closure (PDI)"))
                del main_stack[isolate_index:]

        # --- D. BRACKETS ---
        b_type = _find_in_ranges(cp, "BidiBracketType")
        if b_type == "o":
            expected = mirror_map.get(cp, cp)
            bracket_stack.append((i, expected))
        elif b_type == "c":
            if not bracket_stack:
                fracture_ranges.append((i, i+1, "Stray Bracket"))
            else:
                top_idx, required = bracket_stack[-1]
                if cp == required:
                    bracket_stack.pop()
                else:
                    fracture_ranges.append((i, i+1, "Bracket Mismatch"))

    # --- E. FINAL SWEEP (Spillover) ---
    for frame in main_stack:
        # Highlight the unclosed opener
        # [FORENSIC UPGRADE] Distinguish Scope Bleed from simple unclosed embedding
        lbl = "Unclosed Isolate (Scope Bleed)" if frame['is_isolate'] else "Unclosed Embedding (Stack Leak)"
        fracture_ranges.append((frame['pos'], frame['pos']+1, lbl))
            
    for idx, _ in bracket_stack:
        fracture_ranges.append((idx, idx+1, "Unclosed Bracket"))

    # Generate Rows (Legacy Support)
    # (You can keep the existing row generation logic here or rely on the auditor)
    # For brevity, we assume the rows are generated based on these lists in the caller or here.
    
    # Calculate simple penalty count
    penalty_count = len(fracture_ranges)
                     
    return penalty_count, fracture_ranges, danger_ranges

def compute_whitespace_topology(t):
    """
    Analyzes Whitespace & Line Ending Topology (The 'Frankenstein' Detector).
    Detects Mixed Line Endings (CRLF/LF) and Deceptive Spacing (ASCII/NBSP).
    """
    ws_stats = collections.Counter()
    
    # State tracking for CRLF
    prev_was_cr = False
    
    # Flags for Verdict
    has_lf = False
    has_cr = False
    has_crlf = False
    has_nel = False
    has_ls_ps = False

    for ch in t:
        # --- A. Newline State Machine ---
        if ch == '\n':
            if prev_was_cr:
                ws_stats['CRLF (Windows)'] += 1
                has_crlf = True
                prev_was_cr = False # Consumed
            else:
                ws_stats['LF (Unix)'] += 1
                has_lf = True
        elif ch == '\r':
            if prev_was_cr: # Double CR case (CR + CR)
                ws_stats['CR (Legacy Mac)'] += 1
                has_cr = True
            prev_was_cr = True # Defer count until next char check
        elif ch == '\u0085':
            ws_stats['NEL (Next Line)'] += 1
            has_nel = True
            prev_was_cr = False
        elif ch == '\u2028':
            ws_stats['LS (Line Sep)'] += 1
            has_ls_ps = True
            prev_was_cr = False
        elif ch == '\u2029':
            ws_stats['PS (Para Sep)'] += 1
            has_ls_ps = True
            prev_was_cr = False
        else:
            # Not a newline, but check if we have a dangling CR pending
            if prev_was_cr:
                ws_stats['CR (Legacy Mac)'] += 1
                has_cr = True
                prev_was_cr = False
            
            # --- B. Whitespace Classification ---
            if ch == '\u0020': ws_stats['SPACE (ASCII)'] += 1
            elif ch == '\u00A0': ws_stats['NBSP (Non-Breaking)'] += 1
            elif ch == '\t': ws_stats['TAB'] += 1
            elif ch == '\u3000': ws_stats['IDEOGRAPHIC SPACE'] += 1
            elif ud.category(ch) == 'Zs':
                name = ud.name(ch, 'UNKNOWN SPACE')
                ws_stats[f"{name} (U+{ord(ch):04X})"] += 1

    # Final check for trailing CR
    if prev_was_cr:
        ws_stats['CR (Legacy Mac)'] += 1
        has_cr = True

    # --- C. Heuristic Alerts ---
    alerts = []
    
    # 1. Mixed Line Endings
    newline_types = sum([has_lf, has_cr, has_crlf, has_nel, has_ls_ps])
    if newline_types > 1:
        alerts.append("⚠️ Mixed Line Endings (Consistency Failure)")
    
    # 2. Mixed Spacing (Phishing Vector)
    if ws_stats['SPACE (ASCII)'] > 0 and ws_stats['NBSP (Non-Breaking)'] > 0:
        alerts.append("⚠️ Mixed Spacing (ASCII + NBSP)")
        
    if has_nel or has_ls_ps:
        alerts.append("ℹ️ Unicode Newlines (NEL/LS/PS) Detected")

    # --- D. Render ---
    rows = ""
    for k, v in ws_stats.most_common():
        rows += f"<tr><td>{k}</td><td style='text-align:right; font-family:monospace;'>{v}</td></tr>"
        
    if not rows: rows = "<tr><td colspan='2' style='color:#999'>No whitespace detected.</td></tr>"
    
    alert_html = ""
    if alerts:
        alert_html = f"<div style='color:#b02a37; font-size:0.85em; margin-bottom:8px; font-weight:bold;'>{'<br>'.join(alerts)}</div>"

    html = f"""
    <div class="ws-topology-card" style="margin-top:1rem; border:1px solid #dee2e6; padding:10px; border-radius:4px; background:#f8f9fa;">
        <h4 style="margin:0 0 8px 0; font-size:0.9rem; color:#495057;">Whitespace & Line Ending Topology</h4>
        {alert_html}
        <table style="width:100%; font-size:0.85rem;">
            {rows}
        </table>
    </div>
    """
    return html

# C. Scientific Threat Intelligence (The Papers)

def analyze_symbol_flood(t: str):
    """
    [PAPER 3: SSTA] Detects 'Symbol Cascade' attacks.
    Attackers flood text with 'charged' punctuation (e.g. '......') 
    to bias model sentiment/classification without changing words.
    """
    if not t: return None
    
    # 1. Symbol Density Check
    # Count visible punctuation/symbols (excluding spaces)
    sym_count = sum(1 for c in t if not c.isalnum() and not c.isspace())
    density = sym_count / len(t)
    
    # 2. Cascade Detection (Run-Length Encoding for Symbols)
    max_run = 0
    max_char = ''
    current_run = 0
    prev_char = ''
    
    for char in t:
        if not char.isalnum() and not char.isspace():
            if char == prev_char:
                current_run += 1
            else:
                current_run = 1
            
            if current_run > max_run:
                max_run = current_run
                max_char = char
        else:
            current_run = 0
        prev_char = char
        
    # Thresholds based on SSTA Paper (Cascades often > 8 chars)
    if max_run >= 8:
        risk = 40
        if max_run > 20: risk = 80 # Critical flood
        
        return {
            "type": "CASCADE", 
            "desc": f"Symbol Flood: '{max_char}' x{max_run}", 
            "risk": risk,
            "verdict": "SEMANTIC BIAS"
        }
        
    # High density of non-repeating symbols is also suspicious (Replacement Attack)
    if len(t) > 20 and density > 0.25:
        return {
            "type": "ANOMALY",
            "desc": f"High Symbol Density ({int(density*100)}%)",
            "risk": 30,
            "verdict": "OBFUSCATION"
        }
        
    return None

def analyze_math_spoofing(t: str):
    """
    [PAPER 1: Special-Char] Detects Mathematical Alphanumeric spoofing.
    Attackers replace 'Hello' with '𝐇𝐞𝐥𝐥𝐨' (U+1D400 block) to bypass 
    tokenizers and safety filters.
    """
    # Range: U+1D400 (Math Bold A) to U+1D7FF (Math Monospace digits)
    math_hits = 0
    for char in t:
        cp = ord(char)
        if 0x1D400 <= cp <= 0x1D7FF:
            math_hits += 1
            
    if math_hits > 0:
        # If it looks like a word (multiple math chars), it's a spoof
        if math_hits >= 3:
            return {
                "type": "SPOOFING",
                "desc": f"Math Alphanumeric Spoof ({math_hits} chars)",
                "risk": 75, # High risk as this is a known jailbreak vector
                "verdict": "FILTER BYPASS"
            }
    return None



def analyze_token_fragmentation(tokens: list):
    """
    [PAPER 2: Charmer] Unified Fragmentation Detector.
    Combines three layers of detection:
    1. TARGETED: Re-assembly of high-value threat keywords (Risk 90-100).
    2. LOCAL: Contiguous runs of micro-tokens (Risk 60+).
    3. GLOBAL: Statistical density of micro-tokens (Risk 50).
    """
    if not tokens: return None
    
    # --- LAYER 1: Targeted Re-Assembly (Highest Fidelity) ---
    reassembly_hits = check_reassembly(tokens)
    if reassembly_hits:
        # Calculate Risk based on category severity
        desc_str = ", ".join(reassembly_hits)
        risk = 90
        if "[EXECUTION]" in desc_str or "[INJECTION]" in desc_str:
            risk = 100
            
        return {
            "type": "FRAGMENTATION",
            "desc": f"Fragmented Threat Words: {desc_str}",
            "risk": risk,
            "verdict": "EVASION (TARGETED)"
        }

    # --- LAYER 2: Local Contiguity (Heuristic) ---
    # Detects "s e c u r i t y" even if not in our dictionary
    max_micro_run = 0
    current_micro_run = 0
    
    # --- LAYER 3: Global Statistics (Thermodynamic) ---
    # Detects "l a z y s p a c i n g" across the whole file
    micro_tokens_count = 0
    total_alnum = 0
    
    for tok in tokens:
        t_str = tok['token']
        if t_str.isalnum():
            total_alnum += 1
            
            # Check if it's a micro-token (len 1-2)
            if len(t_str) <= 2:
                current_micro_run += 1
                micro_tokens_count += 1
            else:
                max_micro_run = max(max_micro_run, current_micro_run)
                current_micro_run = 0
                
    # Catch trailing run
    max_micro_run = max(max_micro_run, current_micro_run)
    
    # Evaluate Layer 2 (Local Run)
    # A run of 4+ micro-tokens is statistically unlikely in prose (e.g., "a b c d")
    if max_micro_run >= 4:
         return {
            "type": "OBFUSCATION",
            "desc": f"Token Fragmentation (Run of {max_micro_run} micro-tokens)",
            "risk": 50 + (max_micro_run * 5), # Scales up quickly with length
            "verdict": "TOKENIZER CONFUSION"
        }

    # Evaluate Layer 3 (Global Density)
    # Only apply if we have enough tokens to be statistically significant
    if total_alnum > 10:
        ratio = micro_tokens_count / total_alnum
        if ratio > 0.5:
            return {
                "type": "ANOMALY",
                "desc": f"High Micro-Token Density ({int(ratio*100)}% of text)",
                "risk": 45,
                "verdict": "GLOBAL FRAGMENTATION"
            }
            
    return None

def analyze_token_fragmentation_v2(tokens: list):
    """
    [PAPER 2: Charmer] Deep Fragmentation Engine.
    Checks for re-assembly (Charmer) and contiguous micro-runs.
    Robust against 'string vs dict' token types.
    """
    if not tokens: return None
    
    # 1. Charmer Re-Assembly Check (High Fidelity)
    # Safe check ensures we don't crash if helper is missing
    if 'check_reassembly' in globals():
        reassembly_hits = check_reassembly(tokens)
        if reassembly_hits:
            desc_str = ", ".join(reassembly_hits)
            # Critical risk for Exec/Injection keywords, High for others
            risk = 100 if ("[EXECUTION]" in desc_str or "[INJECTION]" in desc_str) else 90
            
            return {
                "type": "FRAGMENTATION",
                "desc": f"Fragmented Threat Words: {desc_str}",
                "risk": risk,
                "verdict": "TOKENIZER EVASION"
            }

    # 2. Contiguous Micro-Run Check (Heuristic)
    max_micro_run = 0
    current_micro_run = 0
    
    for tok_obj in tokens:
        # DEFENSIVE EXTRACTION: Prevents "string indices must be integers" error
        if isinstance(tok_obj, dict):
            txt = tok_obj.get('token', '')
        else:
            txt = str(tok_obj)
        
        if txt.isalnum() and len(txt) <= 2:
            current_micro_run += 1
        else:
            max_micro_run = max(max_micro_run, current_micro_run)
            current_micro_run = 0
            
    # Capture trailing run
    max_micro_run = max(max_micro_run, current_micro_run)
    
    if max_micro_run >= 4:
         return {
            "type": "OBFUSCATION",
            "desc": f"Token Fragmentation (Run of {max_micro_run} micro-tokens)",
            "risk": 60,
            "verdict": "TOKENIZER CONFUSION"
        }

    return None

def check_reassembly(tokens: list):
    """
    [PAPER 2: Charmer - Deep Logic]
    Attempts to 're-glue' fragmented micro-tokens to see if they form 
    high-value threat words from the Forensic Vocabulary.
    """
    micro_run = []
    findings = []
    
    for tok in tokens:
        t_str = tok['token']
        
        # Collect micro-tokens (len 1-2) - e.g. "s" "h" "e" "ll"
        if t_str.isalnum() and len(t_str) <= 2:
            micro_run.append(t_str)
        else:
            # Process accumulated run
            if len(micro_run) >= 3:
                reassembled = "".join(micro_run).lower()
                
                # 1. Exact Match Check
                if reassembled in ALL_THREAT_TERMS:
                    # Identify Category
                    cat = "UNKNOWN"
                    for c, terms in THREAT_VOCAB.items():
                        if reassembled in terms:
                            cat = c
                            break
                    findings.append(f"[{cat}] {' '.join(micro_run)} -> '{reassembled}'")
                    
                # 2. Substring Heuristic (for longer re-assembled chunks)
                # e.g. "c m d . e x e" -> "cmd.exe" contains "cmd"
                else:
                     for term in ALL_THREAT_TERMS:
                         if len(term) > 3 and term in reassembled:
                              findings.append(f"[SUSPICIOUS] ...{' '.join(micro_run)}... -> contains '{term}'")
                              break

            micro_run = []
            
    # Flush final run
    if len(micro_run) >= 3:
        reassembled = "".join(micro_run).lower()
        if reassembled in ALL_THREAT_TERMS:
            cat = "UNKNOWN"
            for c, terms in THREAT_VOCAB.items():
                if reassembled in terms:
                    cat = c
                    break
            findings.append(f"[{cat}] {' '.join(micro_run)} -> '{reassembled}'")
            
    return findings

def analyze_invisible_fragmentation(t: str):
    """
    [PAPER 1: Special-Char] Detects 'Invisible Sandwich' attacks.
    Unlike generic invisibles, this looks for invisibles embedded BETWEEN
    alphanumeric characters (e.g. 'k<ZWSP>ill'), which specifically 
    shatters LLM tokenization.
    """
    if len(t) < 3: return None
    
    # Scan internal characters only (indices 1 to len-2)
    for i in range(1, len(t) - 1):
        cp = ord(t[i])
        
        # Check using O(1) Lookup
        is_invis = False
        if cp < 1114112:
            mask = INVIS_TABLE[cp]
            # We care about Spacing, Format, and Joiners for fragmentation
            if mask & (INVIS_ZERO_WIDTH_SPACING | INVIS_JOIN_CONTROL | INVIS_SOFT_HYPHEN | INVIS_DEFAULT_IGNORABLE):
                is_invis = True
        
        if is_invis:
            # The "Sandwich" Check
            prev_char = t[i-1]
            next_char = t[i+1]
            
            if prev_char.isalnum() and next_char.isalnum():
                # We found an invisible breaking a word
                return {
                    "type": "FRAGMENTATION",
                    "desc": "Invisible Tokenizer Split (Safety Bypass)",
                    "risk": 95, # Critical: This is almost always malicious
                    "verdict": "JAILBREAK VECTOR"
                }
    return None

def analyze_visual_redaction(t: str):
    """
    [PAPER: Bad Characters] Visual Deletion Engine ('Ghost' Scanner).
    Detects characters that modify cursor position (BS, DEL) to hide content.
    """
    findings = []
    # BS (0x08), DEL (0x7F) are the primary visual erasers.
    # CR (0x0D) overwrites line start.
    REDACTION_SET = {0x0008, 0x007F, 0x000D}
    
    for i, char in enumerate(t):
        cp = ord(char)
        if cp in REDACTION_SET:
            name = "BACKSPACE" if cp == 0x0008 else ("DELETE" if cp == 0x7F else "CARRIAGE RETURN")
            findings.append(f"#{i} ({name})")
            
    if findings:
        return {
            "label": "CRITICAL: Visual Redaction (Ghost Chars)",
            "count": len(findings),
            "positions": findings,
            "severity": "crit",
            "badge": "GHOST"
        }
    return None

def analyze_syntax_fracture_enhanced(t: str):
    """
    [PAPER: Emoji Survey] Enhanced Fracture Scanner (v2).
    Detects 'Sandwich Attacks' where an alphanumeric run is split by
    Emojis, Invisibles, or Tags.
    """
    if len(t) < 3: return None

    fractures = []
    
    # Inline Agent Check
    def is_fracture_agent(cp):
        if cp >= 1114112: return False
        mask = INVIS_TABLE[cp]
        if mask & (INVIS_ZERO_WIDTH_SPACING | INVIS_JOIN_CONTROL | INVIS_TAG | INVIS_BIDI_CONTROL | INVIS_SOFT_HYPHEN):
            return True
        # Check for Emoji ranges
        if _find_in_ranges(cp, "Emoji") or _find_in_ranges(cp, "Extended_Pictographic"):
            return True
        return False

    # Scan for [Alpha] -> [Agent] -> [Alpha]
    for i in range(1, len(t) - 1):
        mid_char = t[i]
        cp_mid = ord(mid_char)
        
        if mid_char.isalnum() or mid_char.isspace():
            continue
            
        if is_fracture_agent(cp_mid):
            prev_char = t[i-1]
            next_char = t[i+1]
            
            if prev_char.isalnum() and next_char.isalnum():
                fractures.append(f"#{i} (U+{cp_mid:04X} splits token)")

    if fractures:
        return {
            "label": "CRITICAL: Syntax Fracture (Token Evasion)",
            "count": len(fractures),
            "positions": fractures,
            "severity": "crit", 
            "badge": "JAILBREAK"
        }
    return None

def analyze_jailbreak_styles(t: str):
    """
    [PAPER: Impact of Non-Standard Unicode] Evasion Alphabet Detector.
    Detects usage of specific Unicode blocks proved to bypass LLM safety filters.
    """
    if not t: return None
    
    hits = {"MATH": 0, "ENCLOSED": 0, "BRAILLE": 0, "TAGS": 0}
    
    for char in t:
        cp = ord(char)
        if 0x1D400 <= cp <= 0x1D7FF: hits["MATH"] += 1
        elif (0x2460 <= cp <= 0x24FF) or (0x1F100 <= cp <= 0x1F1FF): hits["ENCLOSED"] += 1
        elif 0x2800 <= cp <= 0x28FF: hits["BRAILLE"] += 1
        elif 0xE0000 <= cp <= 0xE007F: hits["TAGS"] += 1

    if hits["TAGS"] > 0:
        return {"type": "INJECTION", "desc": f"Unicode Tags (x{hits['TAGS']})", "risk": 95, "verdict": "JAILBREAK (TAGS)"}
    if hits["MATH"] > 3:
        return {"type": "SPOOFING", "desc": f"Math Alphanumerics (x{hits['MATH']})", "risk": 80, "verdict": "JAILBREAK (MATH)"}
    if hits["ENCLOSED"] > 3:
        return {"type": "OBFUSCATION", "desc": f"Enclosed Alphanumerics (x{hits['ENCLOSED']})", "risk": 60, "verdict": "EVASION (STYLE)"}
    if hits["BRAILLE"] > 3:
         return {"type": "OBFUSCATION", "desc": f"Braille Patterns (x{hits['BRAILLE']})", "risk": 70, "verdict": "EVASION (BRAILLE)"}

    return None

def analyze_normalization_inflation(t: str):
    """
    [PAPER: Fun with Unicode] Normalization Bomb Detector.
    Detects single characters that expand significantly (DoS vector).
    """
    flags = {}
    findings = []
    
    # Threshold: If a single char expands to > 10 chars, it's a bomb.
    BOMB_THRESHOLD = 10 
    
    for i, char in enumerate(t):
        # Optimization: Only check complex scripts (skip ASCII)
        if ord(char) < 128: continue
            
        try:
            nfkc = unicodedata.normalize("NFKC", char)
            if len(nfkc) >= BOMB_THRESHOLD:
                # Special Label for the famous U+FDFA
                label = "Arabic Ligature (U+FDFA)" if ord(char) == 0xFDFA else f"U+{ord(char):04X}"
                findings.append(f"#{i} ({label} expands to {len(nfkc)} chars)")
        except: pass
            
    if findings:
        flags["RISK: Normalization Inflation (DoS Vector)"] = {
            "count": len(findings),
            "positions": findings,
            "severity": "warn",
            "badge": "DOS"
        }
    return flags

def analyze_idna_compression(token: str):
    """
    [PAPER: Fun with Unicode] IDNA Compression Detector.
    Detects characters that map to multi-char ASCII strings in IDNA.
    """
    # Scope: Only analyze domain-like tokens
    if not token or '.' not in token: return None
    
    # Heuristic: Check for non-ASCII chars that normalize to ASCII sequences
    # e.g. U+33C5 (㏅) -> "cd"
    suspicious = []
    
    for char in token:
        if ord(char) > 127:
            try:
                norm = unicodedata.normalize("NFKC", char)
                # If it expands to 2+ chars AND becomes pure ASCII
                if len(norm) > 1 and norm.isascii():
                    suspicious.append(f"U+{ord(char):04X}→'{norm}'")
            except: pass
            
    if suspicious:
        return {
            "lvl": "HIGH",
            "type": "SPOOFING", 
            "desc": f"IDNA Compression ({', '.join(suspicious)})"
        }
    return None

def analyze_punctuation_skew(t: str):
    """
    [PAPER 3: SSTA] Replacement Attack Detector.
    Analyzes ratio of 'Grammatical' vs 'Charged' punctuation.
    """
    grammatical = {'.', ',', ';', ':', '"', "'", '?', '!', '-', '(', ')'}
    charged = {'~', '_', '^', '|', '{', '}', '[', ']', '<', '>', '@', '*', '#', '$', '%', '`', '\\', '/'}
    
    gram_count = sum(1 for c in t if c in grammatical)
    charged_count = sum(1 for c in t if c in charged)
    total = gram_count + charged_count
    
    if total > 5 and charged_count > 3:
        ratio = charged_count / total
        if ratio > 0.70:
            return {
                "type": "SKEW",
                "desc": f"Abnormal Punctuation ({int(ratio*100)}% Charged Symbols)",
                "risk": 45,
                "verdict": "REPLACEMENT ATTACK"
            }
    return None

# D. Adversarial & Protocol Engines

def analyze_class_consistency(token: str):
    """
    [SORE THUMB] Scans for singleton anomalies (e.g. 'paypa1' -> LLLLLN).
    """
    if len(token) < 2: return None
    
    runs = []
    current_cat = None
    current_len = 0
    
    for char in token:
        cat = _get_broad_category(char)
        if cat == 'M' and current_cat: continue # Absorb marks
        
        if cat != current_cat:
            if current_cat: runs.append({'cat': current_cat, 'len': current_len})
            current_cat = cat; current_len = 1
        else:
            current_len += 1
    if current_cat: runs.append({'cat': current_cat, 'len': current_len})
    
    counts = {}
    for r in runs: counts[r['cat']] = counts.get(r['cat'], 0) + r['len']
    if not counts: return None
    dominant_cat = max(counts, key=counts.get)
    
    anomalies = []
    for i, r in enumerate(runs):
        # Sore Thumb Rule: Length=1, Not Dominant, Flanked by Dominant
        if r['len'] == 1 and r['cat'] != dominant_cat and r['cat'] in ('L', 'N'):
            if i > 0 and runs[i-1]['cat'] == dominant_cat and runs[i-1]['len'] >= 2:
                anomalies.append(f"Suspicious {r['cat']} in {dominant_cat}-run")
                
    if anomalies:
        return {"desc": ", ".join(anomalies), "risk": 50}
    return None

def analyze_restriction_level(t: str) -> dict:
    """
    [VP-08] UTS #39 Restriction Level Analyzer.
    Determines the 'Script Mixing Class' of the input string.
    [FIXED] Passes explicit code point to helper to avoid TypeError.
    """
    if not t: 
        return {"level": RESTRICTION_LEVELS["ASCII"], "label": "EMPTY", "scripts": [], "score": 0}

    # 1. Fast Path: ASCII
    if t.isascii():
        return {"level": RESTRICTION_LEVELS["ASCII"], "label": "ASCII", "scripts": ["Latin"], "score": 0}

    # 2. Forensic Script Extraction
    major_scripts = set()
    all_scripts = set()
    
    for char in t:
        # [CRITICAL FIX] Must pass both char AND ord(char)
        script = _get_char_script_id(char, ord(char))
        
        all_scripts.add(script)
        # Clean up the ID for logic (strip "Script: " prefix if present or handle raw)
        # The helper returns "Script: Latin" or "Script-Ext: Latn"
        # We normalize specific values for the set logic
        
        # Simple extraction for now:
        if "Script:" in script:
            s_name = script.split(":")[1].strip()
        elif "Script-Ext:" in script:
            s_name = script.split(":")[1].strip().split()[0] # Take first if multiple
        else:
            s_name = script

        if s_name not in ("Common", "Inherited", "Unknown"):
            major_scripts.add(s_name)
            
    sorted_scripts = sorted(list(major_scripts))
    script_count = len(sorted_scripts)

    # 3. Restriction Logic (UTS #39 Section 5.2)

    # Case A: Only Symbols/Numbers (e.g., "123.45")
    if script_count == 0:
        return {
            "level": RESTRICTION_LEVELS["SINGLE_SCRIPT"],
            "label": "SINGLE SCRIPT (Common)",
            "scripts": sorted(list(all_scripts)), 
            "score": 0
        }

    # Case B: Single Script (e.g., "Сбербанк" - Pure Cyrillic)
    if script_count == 1:
        return {
            "level": RESTRICTION_LEVELS["SINGLE_SCRIPT"],
            "label": f"SINGLE SCRIPT ({sorted_scripts[0]})",
            "scripts": sorted_scripts,
            "score": 0
        }

    # Case C: Mixed Scripts (The Danger Zone)
    if "Latin" in major_scripts:
        # Check if ALL other scripts are in the Latin whitelist
        others = major_scripts - {"Latin"}
        if others.issubset(SAFE_SCRIPT_MIXES["Latin"]):
            return {
                "level": RESTRICTION_LEVELS["HIGHLY_RESTRICTIVE"],
                "label": "HIGHLY RESTRICTIVE (Authorized Mix)",
                "scripts": sorted_scripts,
                "score": 10 
            }

    # Case D: Unauthorized Mixes
    return {
        "level": RESTRICTION_LEVELS["MINIMALLY_RESTRICTIVE"],
        "label": "MINIMALLY RESTRICTIVE (Mixed Scripts)",
        "scripts": sorted_scripts,
        "score": 80 
    }

def analyze_identifier_profile(t: str) -> dict:
    """
    [VP-04] UAX #31 Identifier Profile Auditor.
    Checks compliance against standard identifier definitions.
    
    Profiles Checked:
    1. STRICT_ASCII: a-zA-Z0-9_ only.
    2. GENERAL_SECURITY: Unicode Letters, Numbers, Marks, Underscore.
       (Rejects Emoji, Spaces, Symbols, and non-connector Punctuation).
    """
    # 1. Fast Regex Checks (Block 2 Definitions)
    is_strict_ascii = bool(REGEX_ID_ASCII_STRICT.match(t))
    is_general_safe = bool(REGEX_ID_GENERAL_SAFE.match(t))
    
    violation_type = None
    
    # 2. Forensic Diagnostics (Only run if unsafe)
    if not is_general_safe:
        if not t:
            violation_type = "EMPTY"
        else:
            # Slow Path: Iterate to find the first offender
            for char in t:
                # A. Check Invisibles (The "Ghost" Layer)
                cp = ord(char)
                if cp < 1114112:
                    if INVIS_TABLE[cp] & (INVIS_DEFAULT_IGNORABLE | INVIS_BIDI_CONTROL):
                        violation_type = "INVISIBLE/CONTROL"
                        break

                # B. Check Categories (The "Physics" Layer)
                try:
                    cat = unicodedata2.category(char)
                except:
                    cat = unicodedata.category(char)
                
                # Check against Block 2 Definitions
                if cat.startswith(ID_VIOLATION_MAP["WHITESPACE"]):
                    violation_type = "WHITESPACE"
                    break
                if cat.startswith(ID_VIOLATION_MAP["CONTROL"]):
                    violation_type = "CONTROL_CHAR"
                    break
                if cat.startswith(ID_VIOLATION_MAP["SYMBOL"]):
                    violation_type = "SYMBOL/EMOJI"
                    break
                if cat.startswith(ID_VIOLATION_MAP["PUNCTUATION"]):
                    if cat != 'Pc': # Allow Connector Punctuation (e.g. underscore)
                        violation_type = "PUNCTUATION"
                        break

    return {
        "is_strict_ascii": is_strict_ascii,
        "is_general_safe": is_general_safe,
        "violation_type": violation_type
    }

def analyze_normalization_hazards(t: str):
    """
    [SYNTAX PREDATOR]
    Detects characters that are SAFE in Raw state but become DANGEROUS SYNTAX
    after NFKC/NFKD normalization (e.g. U+FF07 'FULLWIDTH APOSTROPHE' -> ').
    """
    hazards = {}
    
    # Optimization: Only scan if text contains non-ASCII (potential transformers)
    if all(ord(c) < 128 for c in t):
        return hazards

    for i, char in enumerate(t):
        # Optimization: Skip if char is already dangerous in raw form (not a hidden attack)
        if char in HAZARD_ALL:
            continue
            
        # 1. Normalize
        try:
            nfkc = unicodedata.normalize("NFKC", char)
            nfkd = unicodedata.normalize("NFKD", char)
        except: continue
        
        # 2. Check for Syntax Injection
        # We check both forms because some filters use NFD (decomposition)
        transformed_chars = set(nfkc) | set(nfkd)
        
        detected_vectors = []
        
        # Check SQL
        if not (HAZARD_SQL & {char}) and (HAZARD_SQL & transformed_chars):
            detected_vectors.append("SQL")
            
        # Check HTML/XSS
        if not (HAZARD_HTML & {char}) and (HAZARD_HTML & transformed_chars):
            detected_vectors.append("HTML")
            
        # Check System/Path
        if not (HAZARD_SYSTEM & {char}) and (HAZARD_SYSTEM & transformed_chars):
            detected_vectors.append("SYSTEM")
            
        if detected_vectors:
            # Build the report key
            vec_str = "/".join(detected_vectors)
            key = f"CRITICAL: Normalization-Activated {vec_str} Injection"
            
            if key not in hazards:
                hazards[key] = {
                    "count": 0,
                    "positions": [],
                    "severity": "crit",
                    "badge": "INJECTION"
                }
            
            hazards[key]["count"] += 1
            # Limit position tracking to avoid UI lag on massive attacks
            if hazards[key]["count"] <= 10:
                target = list(transformed_chars & HAZARD_ALL)[0]
                hazards[key]["positions"].append(f"#{i} (U+{ord(char):04X} &rarr; '{target}')")

    return hazards

def analyze_normalization_hazard_advanced(token: str):
    """
    [SHAPESHIFTING] Checks NFC (Binary) and NFKC_Casefold (Visual).
    Detects tokens that are unstable under normalization (Adversarial Evasion).
    """
    hazards = []
    score = 0
    
    # 1. NFC Hazard (Binary Instability)
    # Detects things like "Ghost Characters" that vanish or merge
    try:
        nfc = unicodedata.normalize("NFC", token)
        if token != nfc:
            if len(token) != len(nfc):
                hazards.append("NFC Length Change (Ghost/Hollow)")
                score += 40
            else:
                hazards.append("NFC Binary Drift")
                score += 20
    except: pass

    # 2. NFKC_Casefold Hazard (Compatibility/Visual Instability)
    # Uses the app's robust 'normalize_extended' to catch Enclosed Alphanumerics
    try:
        # Simulate NFKC_CF: Normalize NFKC then Casefold
        nfkc = normalize_extended(token)
        nfkc_cf = nfkc.casefold()
        
        # Compare against normalized raw
        raw_cf = token.casefold()
        
        if nfkc_cf != raw_cf:
             hazards.append("NFKC-CF Visual Drift")
             score += 30
    except: pass

    if hazards:
        return {"desc": ", ".join(hazards), "risk": score}
    return None

def analyze_structural_perturbation(token: str):
    """
    [BROKEN WORD] Detects non-standard separators inside a token.
    FIXED: Returns accurate labels (Bidi, ZWSP, Joiner, Tag, Invisible).
    """
    perturbations = 0
    types = set()
    
    for char in token:
        cp = ord(char)
        if cp == 0xFE0F or cp == 0xFE0E: continue # Ignore VS
            
        mask = INVIS_TABLE[cp] if cp < 1114112 else 0
        if mask & INVIS_ANY_MASK:
            perturbations += 1
            
            # Precise labeling based on bitmask
            if mask & INVIS_BIDI_CONTROL: types.add("Bidi")
            elif mask & INVIS_ZERO_WIDTH_SPACING: types.add("ZWSP") # Includes BOM
            elif mask & INVIS_JOIN_CONTROL: types.add("Joiner")
            elif mask & INVIS_TAG: types.add("Tag")
            elif mask & INVIS_SOFT_HYPHEN: types.add("SHY") # Explicit SHY
            elif cp == 0x0000: types.add("Null") # Explicit NUL
            else: types.add("Invisible")
            
    if perturbations > 0:
        # Sort for deterministic output
        type_list = sorted(list(types))
        score = 40 + (perturbations * 10)
        return {"desc": f"Perturbation ({perturbations}x {', '.join(type_list)})", "risk": min(100, score)}
    return None

def analyze_context_lure(token: str):
    """
    [CONTEXT] Detects Phishing/Auth Keywords and Syntax Lures.
    Reclassifies 'Login:' and '//' from SPOOFING to CONTEXT.
    """
    # 1. Syntax Lures (//, https://, www)
    if token in ("//", "https://", "http://", "www", "ftp://"):
        return {"desc": "High-Risk URL Syntax", "risk": 20, "type": "CONTEXT"}
        
    # 2. Auth Keywords (Case insensitive)
    t_lower = token.lower().strip(":")
    keywords = {"login", "signin", "password", "admin", "verify", "secure", "account", "update", "confirm"}
    if t_lower in keywords:
        return {"desc": "Authentication Keyword (Phishing Lure)", "risk": 30, "type": "CONTEXT"}
        
    return None

def is_plausible_domain_candidate(token: str) -> bool:
    """
    Forensic Gate v2: Strict Structural Filter.
    Rejects binary blobs, file paths, and random prose.
    """
    if len(token) > 253 or len(token) < 3: return False
    
    # 1. Critical Exclusion (Data Corruption)
    for char in token:
        cp = ord(char)
        if cp == 0 or cp == 0xFFFD: return False
        if 0xFDD0 <= cp <= 0xFDEF: return False
        if (cp & 0xFFFF) >= 0xFFFE: return False
        
    # 2. Structural Shape (Must look like a domain)
    has_dot = '.' in token
    looks_puny = token.lower().startswith("xn--")
    
    # If no dot and not punycode, it's just a word, not a domain.
    if not has_dot and not looks_puny:
        return False
        
    # 3. ASCII Sanity (If purely ASCII, must use domain alphabet)
    if token.isascii():
        # Allow only: Alphanumeric, Dot, Hyphen
        # Reject: Slash, Backslash, Brackets, etc.
        for c in token:
            if not (c.isalnum() or c in ".-"):
                return False
                
    return True

def analyze_idna_label(label: str):
    """
    Label-Centric Analyzer (Top-Tier).
    Handles Punycode decoding, IDNA2008 Categories, and UTS #46 Statuses.
    Refined V3: Explicitly whitelists ASCII A-Z to prevent noise.
    Added V4: Forward Punycode Prediction (Wire Format).
    """
    findings = []

    # Prevent binary blobs from entering the IDNA engine, regardless of caller.
    for char in label:
        cp = ord(char)
        if cp == 0 or cp == 0xFFFD or (0xFDD0 <= cp <= 0xFDEF) or (cp & 0xFFFF) >= 0xFFFE:
            return []
    
    # 1. PUNYCODE INTELLIGENCE
    analysis_target = label
    is_punycode = label.lower().startswith("xn--")
    
    if is_punycode:
        # DECODING (Punycode -> Unicode)
        try:
            payload = label[4:] # Strip 'xn--'
            decoded = payload.encode('ascii').decode('punycode')
            analysis_target = decoded
            findings.append({
                "type": "INFO", "lvl": "LOW",
                "desc": f"Punycode Decodes to: '{decoded}'"
            })
        except Exception:
            return [{
                "type": "CRITICAL", "lvl": "CRIT",
                "desc": "Invalid Punycode Label (Decoding Failed)"
            }]
    else:
        # [NEW] ENCODING (Unicode -> Punycode / Wire Format)
        # If the label contains non-ASCII, show how it looks on the wire.
        if not label.isascii():
            try:
                # We use the 'idna' codec to simulate browser behavior
                encoded_wire = label.encode('idna').decode('ascii')
                if encoded_wire.startswith("xn--"):
                    findings.append({
                        "type": "WIRE", "lvl": "MED",
                        "desc": f"Wire Format: '{encoded_wire}'"
                    })
            except: pass

    # 2. DUAL-LENS ANALYSIS (On the Decoded/Raw Unicode Label)
    idna46 = DATA_STORES.get("IdnaMap", {})
    idna2008 = DATA_STORES.get("Idna2008", {})
    
    for char in analysis_target:
        cp = ord(char)
        
        # Whitelist ASCII Alphanumeric
        # IDNA2008 technically disallows uppercase A-Z (must be mapped to lower),
        # but flagging them as "Strict Violation" is forensic noise.
        # We ignore A-Z, a-z, 0-9, and Hyphen.
        if (0x41 <= cp <= 0x5A) or (0x61 <= cp <= 0x7A) or (0x30 <= cp <= 0x39) or cp == 0x2D:
            continue

        # --- A. IDNA2008 (Strict Lens) ---
        cat08 = idna2008.get(cp, "UNASSIGNED")
        
        if cat08 in ("DISALLOWED", "UNASSIGNED"):
            findings.append({
                "type": "INVALID", "lvl": "HIGH", 
                "desc": f"IDNA2008 Strict Violation: U+{cp:04X} ({cat08})"
            })
        elif cat08 == "CONTEXTJ":
            findings.append({
                "type": "CONTEXT", "lvl": "MED", 
                "desc": f"Context-Dependent Joiner (CONTEXTJ): U+{cp:04X} (Unverified)"
            })
        elif cat08 == "CONTEXTO":
            findings.append({
                "type": "CONTEXT", "lvl": "MED", 
                "desc": f"Context-Dependent Char (CONTEXTO): U+{cp:04X} (Unverified)"
            })

        # --- B. UTS #46 (Compatibility Lens) ---
        if cp in idna46["deviation"]:
             findings.append({
                 "type": "AMBIGUITY", "lvl": "HIGH", 
                 "desc": f"UTS #46 Deviation: U+{cp:04X} (Legacy/Modern Mismatch)"
             })
        elif cp in idna46["ignored"]:
             findings.append({
                 "type": "GHOST", "lvl": "HIGH", 
                 "desc": f"UTS #46 Ignored: U+{cp:04X} (Vanishes in DNS)"
             })
        elif cp in idna46["nv8"]:
             findings.append({
                 "type": "COMPAT", "lvl": "MED", 
                 "desc": f"IDNA2008 Excluded (NV8): U+{cp:04X} (Protocol Gap)"
             })
        elif cp in idna46["xv8"]:
             findings.append({
                 "type": "COMPAT", "lvl": "MED", 
                 "desc": f"IDNA2008 Version Mismatch (XV8): U+{cp:04X}"
             })
            
    return findings

# E. Deobfuscation & Simulation

def recursive_deobfuscate(text: str, depth=0, max_depth=5):
    """
    Recursively strips encoding layers (URL -> HTML -> Base64 -> Escapes -> SQL CHAR).
    Returns: (final_decoded_text, list_of_layers_found)
    """
    if depth >= max_depth or not text:
        return text, []

    layers = []
    current = text
    
    # 1. URL Decoding (Look for %XX)
    if "%" in current:
        try:
            decoded = urllib.parse.unquote(current)
            if decoded != current:
                current = decoded
                layers.append("URL-Encoded")
        except: pass

    # 2. HTML Entity Decoding (Look for &...;)
    if "&" in current and ";" in current:
        try:
            decoded = html.unescape(current)
            if decoded != current:
                current = decoded
                layers.append("HTML-Entity")
        except: pass

    # 3. Unicode/Hex/Octal Escapes (\uXXXX, \xXX, \NNN)
    if "\\" in current:
        try:
            # A. Try Standard Python Decode
            # This handles \u0041, \x41, and some octal
            decoded = current.encode('utf-8').decode('unicode_escape')
            if decoded != current:
                current = decoded
                layers.append("Escape-Sequence")
            
            # B. Explicit Octal Pattern (e.g. \141\142) if Python missed it
            # Matches \1 to \7 followed by two digits
            octal_pattern = re.compile(r'\\([0-7]{1,3})')
            if octal_pattern.search(current):
                def oct_sub(match):
                    try: return chr(int(match.group(1), 8))
                    except: return match.group(0)
                
                decoded_oct = octal_pattern.sub(oct_sub, current)
                if decoded_oct != current:
                    current = decoded_oct
                    if "Escape-Sequence" not in layers: layers.append("Octal-Escapes")
        except: pass

    # 4. SQL CHAR() De-obfuscation (The "Concat" Pattern)
    # Matches: CHAR(83) or CHAR(0x53), optionally joined by + or || or spaces
    # Regex: CHAR\s*\(\s*(0x[0-9a-fA-F]+|[0-9]+)\s*\)
    sql_pattern = re.compile(r'CHAR\s*\(\s*(0x[0-9a-fA-F]+|[0-9]+)\s*\)', re.IGNORECASE)
    if "CHAR" in current.upper():
        def sql_sub(match):
            val = match.group(1)
            try:
                # Handle Hex (0x...) or Decimal
                code = int(val, 16) if val.lower().startswith("0x") else int(val)
                return chr(code)
            except: return match.group(0)
            
        # We also need to strip the '+' concatenation if present between CHARs
        # Simplified approach: Replace CHAR(...) -> X, then cleanup artifacts? 
        # Better: decode in place.
        decoded_sql = sql_pattern.sub(sql_sub, current)
        
        if decoded_sql != current:
            # Cleanup SQL concatenation noise (e.g., 'S'+'E'+'L' -> 'SEL')
            # This is a heuristic cleanup for '+' and '||' between decoded chars
            # Ideally, the user sees "S+E+L+E+C+T", which is readable enough to flag.
            current = decoded_sql
            layers.append("SQL-CHAR")

    # 5. Base64 Heuristic (The False Positive Hazard)
    # Logic: Must be > 16 chars, valid B64 charsets, and decode to meaningful text
    if len(current) > 16 and re.match(r'^[A-Za-z0-9+/=]+$', current.strip()):
        try:
            # Add padding if missing
            pad = len(current) % 4
            if pad: current += "=" * (4 - pad)
            
            b_data = base64.b64decode(current, validate=True)
            decoded_utf8 = b_data.decode('utf-8')
            
            # Entropy check: > 70% printable
            printable = sum(1 for c in decoded_utf8 if c.isprintable())
            if printable / len(decoded_utf8) > 0.7:
                current = decoded_utf8
                layers.append("Base64")
        except: pass

    # Recursion Step
    if layers:
        next_text, next_layers = recursive_deobfuscate(current, depth + 1, max_depth)
        return next_text, layers + next_layers
    
    return current, []

def analyze_waf_policy(text: str):
    """
    Simulates a hardened WAF (SiteMinder/Broadcom style).
    Checks the 'Naked' (De-obfuscated) string for forbidden artifacts.
    """
    alerts = []
    score = 0
    
    # 1. Critical Injection Vectors (SiteMinder BadCssChars)
    # < > ' " ( ) ; +
    xss_vectors = []
    if "<" in text or ">" in text: xss_vectors.append("HTML Tag (< >)")
    if "javascript:" in text.lower(): xss_vectors.append("JS Scheme")
    if "onerror" in text.lower() or "onload" in text.lower(): xss_vectors.append("Event Handler")
    
    if xss_vectors:
        alerts.append(f"XSS Injection ({', '.join(xss_vectors)})")
        score += 40

    # 2. Path Traversal (SiteMinder BadUrlChars)
    # .. // \ %00
    traversal = []
    if "../" in text or "..\\" in text: traversal.append("Dir Traversal (..)")
    if "//" in text and "http" not in text: traversal.append("Double Slash (//)")
    if "\x00" in text: traversal.append("Null Byte Injection")
    
    if traversal:
        alerts.append(f"Path Traversal ({', '.join(traversal)})")
        score += 50

    # 3. SQL Injection Heuristics (Broadcom BadQueryChars)
    sqli_keywords = ["union select", "information_schema", "drop table", "1=1", "--"]
    lower_t = text.lower()
    for kw in sqli_keywords:
        if kw in lower_t:
            alerts.append(f"SQL Injection ({kw})")
            score += 45
            break # One is enough

    return alerts, score

def analyze_code_masquerade(text: str, script_stats: dict):
    """
    Detects 'Solders' style malware: Valid Code structure using Alien Scripts.
    Heuristic: High-Density Non-Latin Identifiers + Code Syntax.
    """
    # 1. Check for Code Syntax ( { } ; function var const => )
    code_syntax_chars = { '{', '}', ';', '(', ')', '[', ']', '=', '+', '>' }
    syntax_hits = sum(1 for c in text if c in code_syntax_chars)
    
    # Needs a minimum syntax density to be considered "Code"
    if len(text) < 50 or (syntax_hits / len(text)) < 0.05:
        return None

    # 2. Check Script Usage (from Module 2.D stats)
    # If we have significant non-Latin/non-Common script usage
    # but the text is structured like code, it's suspicious.
    
    suspicious_scripts = []
    for key in script_stats:
        if "Latin" not in key and "Common" not in key and "Inherited" not in key:
            # Check if this script makes up a significant portion of the text
            # (We approximate using the 'count' from stats)
            count = script_stats[key].get('count', 0)
            if count > 10: # Threshold for relevance
                suspicious_scripts.append(key.replace("Script: ", ""))

    # 3. Dynamic Execution Sinks (The 'eval' equivalent)
    # Check for "constructor" access patterns or "eval"
    has_sinks = False
    if 'constructor' in text or 'eval(' in text or 'Function(' in text:
        has_sinks = True

    if suspicious_scripts and (has_sinks or syntax_hits > 20):
        scripts_str = ", ".join(suspicious_scripts)
        return {
            "verdict": "Obfuscated Code",
            "detail": f"Code Syntax + Alien Identifiers ({scripts_str})",
            "risk": "High (Solders-style malware)",
            "score": 85
        }
    
    return None

def analyze_anti_sanitization(t: str):
    """
    Detects specific characters known to bypass standard filters
    before normalizing into dangerous payloads.
    Source: AppCheck / OWASP / 7ASecurity Research.
    """
    flags = {}
    
    # 1. SQL Injection Vectors (Normalization Exploits)
    # U+FF07 (Fullwidth Apostrophe) -> ' (0x27)
    if "\uff07" in t:
        flags["CRITICAL: SQL Injection Vector (U+FF07)"] = {
            "count": t.count("\uff07"),
            "positions": ["Becomes ' (Apostrophe) under NFKC/NFKD"],
            "severity": "crit",
            "badge": "SQLi"
        }

    # 2. XSS Vectors (Normalization Exploits)
    # U+FE64 (Small Less-Than) -> < (0x3C)
    # U+FF1C (Fullwidth Less-Than) -> < (0x3C)
    # U+FF1E (Fullwidth Greater-Than) -> > (0x3E)
    xss_norm_chars = {
        "\ufe64": "Small <", "\uff1c": "Fullwidth <", "\uff1e": "Fullwidth >"
    }
    found_xss = [name for char, name in xss_norm_chars.items() if char in t]
    if found_xss:
        flags[f"CRITICAL: XSS Bypass Vector ({', '.join(found_xss)})"] = {
            "count": sum(t.count(c) for c in xss_norm_chars if c in t),
            "positions": ["Normalizes to HTML syntax (< >)"],
            "severity": "crit",
            "badge": "XSS"
        }

    # 3. Source Code Obfuscation
    # U+00A0 (NBSP) often breaks parsers expecting 0x20
    if "\u00a0" in t:
        flags["RISK: Source Code Obfuscation (NBSP)"] = {
            "count": t.count("\u00a0"),
            "positions": ["Non-Breaking Space (Breaks Parsers)"],
            "severity": "warn",
            "badge": "SYNTAX"
        }
        
    # 4. Polyglot Canaries (Probing Tools)
    # U+0212A (Kelvin Sign) -> 'K'
    if "\u212a" in t:
        flags["SUSPICIOUS: Polyglot Canary (Kelvin Sign)"] = {
            "count": t.count("\u212a"),
            "positions": ["Used to probe normalization (Becomes 'K')"],
            "severity": "warn",
            "badge": "PROBE"
        }

    # 5. [NEW] Structural Mutation (Overlay Attacks)
    # U+0338 (Combining Long Solidus Overlay) on Syntax Chars
    # Research Vector: '>' + U+0338 = '≯' (Masks the tag closer)
    if "\u0338" in t:
        syntax_targets = {'<', '>', '/', "'", '"', ';', '=', '-'}
        mutation_hits = 0
        
        # Iterate to find U+0338 applied to syntax
        for i, char in enumerate(t):
            if char == "\u0338" and i > 0:
                prev = t[i-1]
                if prev in syntax_targets:
                    mutation_hits += 1
                    
        if mutation_hits > 0:
            flags["CRITICAL: Structural Mutation (Overlay Masking)"] = {
                "count": mutation_hits,
                "positions": ["Syntax characters masked by U+0338 (e.g. ≯)"],
                "severity": "crit",
                "badge": "MASKING"
            }

    return flags

def analyze_case_collisions(t: str):
    """
    Simulates Upper/Lower case transformations to detect
    buffer overflows and logic bypasses (e.g. GitHub Dotless i).
    """
    flags = {}
    
    # 1. Length Expansion (Buffer Overflow Risk)
    # Classic Example: 'ß' (len 1) -> 'SS' (len 2)
    t_upper = t.upper()
    if len(t) != len(t_upper):
        diff = len(t_upper) - len(t)
        flags["DANGER: Case Mapping Expansion"] = {
            "count": 1,
            "positions": [f"String grows by {diff} chars on Uppercase (Buffer Overflow Risk)"],
            "severity": "crit",
            "badge": "OVERFLOW"
        }

    # 2. WAF/Logic Bypass Vectors
    # Long S (ſ) -> S
    if "\u017f" in t:
        flags["CRITICAL: WAF Bypass Vector (Long S)"] = {
            "count": t.count("\u017f"),
            "positions": ["Becomes 'S' on Uppercase (Shadows Keywords)"],
            "severity": "crit",
            "badge": "BYPASS"
        }
    
    # Dotless i (ı) -> I (or I -> i depending on locale, but dotless i is the main vector)
    if "\u0131" in t:
        flags["CRITICAL: Logic Bypass Vector (Dotless i)"] = {
            "count": t.count("\u0131"),
            "positions": ["Becomes 'I' on Uppercase (GitHub-style exploit)"],
            "severity": "crit",
            "badge": "BYPASS"
        }

    return flags

def analyze_domain_heuristics(token: str):
    """
    [TYPOSQUATTING] Detects structural lures in Domain/Filename tokens.
    Checks for: Pseudo-delimiters, Double Extensions, and RTLO injection.
    """
    # 1. Scope: Only analyze tokens that look like paths/domains
    # (Must contain a dot, slash, or look like a file)
    if "." not in token and "/" not in token and "\\" not in token:
        return None

    risks = []
    score = 0
    
    # --- A. PSEUDO-DELIMITERS (The "Fake Dot" Attack) ---
    # Characters that look like '.' but aren't U+002E
    FAKE_DOTS = {
        0x2024: "One Dot Leader",
        0x2025: "Two Dot Leader", 
        0x2026: "Ellipsis",
        0x3002: "Ideographic Full Stop",
        0xFF0E: "Fullwidth Full Stop",
        0x0589: "Armenian Full Stop",
        0x06D4: "Arabic Full Stop"
    }
    
    fake_dot_found = []
    for char in token:
        cp = ord(char)
        if cp in FAKE_DOTS:
            fake_dot_found.append(FAKE_DOTS[cp])
            
    if fake_dot_found:
        risks.append(f"Pseudo-Delimiters ({', '.join(set(fake_dot_found))})")
        score += 80 # Critical: This is almost always malicious in a domain context

    # --- B. DOUBLE EXTENSIONS (The "PDF.EXE" Attack) ---
    # Logic: Look for [suspicious_ext] + . + [executable_ext]
    # Simple regex-free heuristic
    lower_tok = token.lower()
    
    # Common safe-looking decoys
    decoys = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".png", ".jpg", ".txt", ".mp4"}
    # Dangerous payloads
    payloads = {".exe", ".vbs", ".bat", ".cmd", ".sh", ".js", ".jar", ".scr", ".com"}
    
    # Iterate to find patterns like 'document.pdf.exe'
    for payload in payloads:
        if lower_tok.endswith(payload):
            # Check what comes BEFORE the payload
            prefix = lower_tok[: -len(payload)]
            for decoy in decoys:
                if prefix.endswith(decoy):
                    risks.append(f"Double Extension Lure ({decoy}{payload})")
                    score += 90 # Critical
                    break
    
    # --- C. RTLO INJECTION (Filename Spoofing) ---
    # Check for Bidi overrides specifically near extension dots
    # (e.g. "cod\u202Efdp.exe" -> "codexe.pdf")
    if "\u202E" in token or "\u202D" in token: # RLO or LRO
        # If Bidi exists and we have a dot, it's highly suspect
        if "." in token:
            risks.append("Bidi Arrears (Extension Spoofing Risk)")
            score += 100 # Critical

    if risks:
        return {"desc": ", ".join(risks), "risk": score}
    
    return None

# F. Verification & Statistics

def _classify_topology(s: str) -> str:
    """
    [Phase 3.5] Topology Classifier (Forensic Grade).
    Determines the semantic shape using character-class density.
    """
    if not s: return "EMPTY"
    
    # 1. Structure Detection (Syntax)
    has_slash = "/" in s or "\\" in s
    has_at = "@" in s
    has_dot = "." in s
    has_code_syntax = any(c in "{};()[]=" for c in s)
    
    # 2. Entropy / Class Analysis
    # We count broad categories
    alnum = 0
    alpha = 0
    digit = 0
    space = 0
    
    for c in s:
        if c.isalnum(): alnum += 1
        if c.isalpha(): alpha += 1
        if c.isdigit(): digit += 1
        if c.isspace(): space += 1
        
    length = len(s)
    
    # --- Classification Logic ---
    
    # A. Code / Data Structures
    if has_code_syntax and space > 0:
        return "CODE/DATA"
    
    # B. Email
    if has_at and has_dot and not has_slash and " " not in s:
        return "EMAIL"
    
    # C. Domain / Host
    # Criteria: No spaces, has dots, mostly alphanumeric
    if is_plausible_domain_candidate(s):
        return "DOMAIN"
        
    # D. File Path
    if has_slash:
        return "PATH"
        
    # E. Numeric / Key
    if digit == length:
        return "NUMERIC"
    if alnum == length and digit > 0 and alpha > 0:
        return "ALPHANUMERIC_KEY"
        
    # F. Text / Sentence
    if space > 0:
        return "TEXT_PHRASE"
        
    return "TOKEN"

def _audit_reference_safety(trusted_str: str) -> list:
    """
    [Phase 0] The Mirror Test (Expanded).
    Ensures the user isn't trusting a malicious, weak, or deceptive reference.
    """
    warnings = []
    
    # 1. Entropy Guard (Length & Diversity)
    if len(trusted_str) < 3:
        warnings.append("Weak Reference (Too Short)")
    elif len(set(trusted_str)) == 1:
        warnings.append("Weak Reference (Zero Entropy)")

    # 2. Hidden Character Check
    MASK_REF = INVIS_DEFAULT_IGNORABLE | INVIS_BIDI_CONTROL | INVIS_TAG | INVIS_ZERO_WIDTH_SPACING
    
    invis_count = 0
    has_bidi = False
    has_control_pics = False
    
    for char in trusted_str:
        cp = ord(char)
        if cp < 1114112:
            mask = INVIS_TABLE[cp]
            if mask & MASK_REF: invis_count += 1
            if mask & INVIS_BIDI_CONTROL: has_bidi = True
        
        # 3. Control Picture Check (Visual Spoofing)
        if 0x2400 <= cp <= 0x243F:
            has_control_pics = True
                
    if invis_count > 0: warnings.append(f"Reference contains {invis_count} hidden chars")
    if has_bidi: warnings.append("Reference contains Bidi Controls")
    if has_control_pics: warnings.append("Reference contains Control Pictures (Visual Spoof)")
    
    return warnings

def _audit_deep_physics(suspect_str, trusted_str, suspect_nfkc, suspect_prof, trusted_prof) -> list:
    """
    [Phase 3.5] Paranoid Physics Engine.
    Checks Inflation, Topology, Whitespace, Profile Locking, Numeric Value, and Casing.
    """
    threats = []

    # 1. Inflation Check (DoS Vector)
    if len(suspect_nfkc) > len(suspect_str) * 2 and len(suspect_str) > 1:
        ratio = len(suspect_nfkc) / len(suspect_str)
        threats.append(f"INFLATION_RISK (x{ratio:.1f})")

    # 2. Profile Locking (Downgrade Attack)
    if trusted_prof["score"] <= 20 and suspect_prof["score"] >= 80:
        threats.append(f"PROFILE_DOWNGRADE ({trusted_prof['label']} -> {suspect_prof['label']})")

    # 3. Topology Mismatch (Type Drift)
    t_topo = _classify_topology(trusted_str)
    s_topo = _classify_topology(suspect_str)
    
    # We only flag if the types are DISTINCT and incompatible
    # e.g. TEXT -> TEXT is fine. DOMAIN -> PATH is suspicious.
    # Exception: TOKEN -> ALPHANUMERIC_KEY is often fine.
    if t_topo != s_topo:
        # Filter noise: don't flag "TOKEN" vs "TEXT_PHRASE" if they are just words
        safe_transitions = {("TOKEN", "ALPHANUMERIC_KEY"), ("ALPHANUMERIC_KEY", "TOKEN")}
        if (t_topo, s_topo) not in safe_transitions:
             threats.append(f"TOPOLOGY_MISMATCH ({t_topo} -> {s_topo})")

    # 4. Whitespace Topology (The "Invisible Grid")
    def get_ws_set(s): return {ord(c) for c in s if c.isspace()}
    ws_t = get_ws_set(trusted_str)
    ws_s = get_ws_set(suspect_str)
    
    if ws_t != ws_s and ws_t:
        # If trusted uses standard spaces (32) but suspect uses exotic ones
        if 32 in ws_t and not ws_s.issubset(ws_t):
            threats.append("WHITESPACE_SPOOFING")

    # 5. Numeric Value Audit (Financial Defense)
    # Calculates the mathematical sum of digits. Catches 1 vs l, 0 vs O.
    def get_numeric_sum(s):
        total = 0.0
        has_nums = False
        for c in s:
            try: 
                val = unicodedata.numeric(c)
                total += val
                has_nums = True
            except: pass
        return total, has_nums

    val_t, has_t = get_numeric_sum(trusted_str)
    val_s, has_s = get_numeric_sum(suspect_str)
    
    # Only flag if BOTH strings contain numbers, but the sums differ
    if has_t and has_s and val_t != val_s:
        threats.append(f"NUMERIC_MISMATCH ({val_t} vs {val_s})")

    # 6. Casing Lockdown (The "CamelCase" Defense)
    # If skeletons match but case differs, check if complexity changed.
    # e.g. "adminUser" vs "adminuser" (Loss of CamelCase is a structure change)
    if suspect_str.lower() == trusted_str.lower() and suspect_str != trusted_str:
        # Calculate Casing Entropy (Transitions)
        def case_transitions(s):
            trans = 0
            for i in range(len(s)-1):
                if s[i].islower() and s[i+1].isupper(): trans += 1
                if s[i].isupper() and s[i+1].islower(): trans += 1
            return trans
            
        ct_t = case_transitions(trusted_str)
        ct_s = case_transitions(suspect_str)
        
        if ct_t > 0 and ct_s == 0:
            threats.append("CASING_FLATTENED (CamelCase Lost)")
        elif ct_t != ct_s:
            threats.append("CASING_STRUCTURE_MISMATCH")

    return threats

def compute_verification_verdict(suspect_str: str, trusted_str: str) -> dict:
    """
    [VP-09, VP-16] Forensic Comparator V1.4 (Relentless).
    
    Upgrades:
    1. Reference Poisoning Check: Audits the 'Trusted' string for threats.
    2. Profile Locking: Suspect cannot be 'riskier' than Trusted.
    3. Topology Mismatch: Detects Type Drift (Domain vs Path).
    4. Quad-State Alignment: existing logic.
    """
    if not suspect_str or not trusted_str: return None

    # --- PHASE 0: REFERENCE HYGIENE (The Mirror Test) ---
    # Call the new Reference Auditor
    reference_warnings = _audit_reference_safety(trusted_str)

    # --- PHASE 1: QUAD-STATE PIPELINE ---
    suspect_nfkc = normalize_extended(suspect_str)
    trusted_nfkc = normalize_extended(trusted_str)
    
    # Generate Skeletons & Track Events
    suspect_skel, sus_events = _generate_uts39_skeleton(suspect_nfkc.casefold(), return_events=True)
    trusted_skel = _generate_uts39_skeleton(trusted_nfkc.casefold())

    # --- PHASE 2: ALIGNMENT ---
    sm = difflib.SequenceMatcher(None, suspect_skel, trusted_skel)
    match = sm.find_longest_match(0, len(suspect_skel), 0, len(trusted_skel))
    
    matched_skel_len = match.size
    target_len = len(trusted_skel)
    
    MIN_MATCH_LEN = 3 if target_len >= 3 else target_len
    
    if matched_skel_len < MIN_MATCH_LEN:
        overlap_pct = 0.0
        match_start_idx = -1
        match_end_idx = -1
        matched_skel_text = "NO CORRELATION"
    else:
        overlap_pct = (matched_skel_len / target_len) * 100.0
        matched_skel_text = suspect_skel[match.a : match.a + match.size]
        match_start_idx = match.a
        match_end_idx = match.a + match.size

    # --- PHASE 3: RESIDUAL RISK SCANNER ---
    residual_threats = []
    curr_skel_idx = 0
    MASK_RR = MASK_RESIDUAL_RISK | INVIS_VARIATION_SELECTOR

    for char in suspect_str:
        c_skel = _generate_uts39_skeleton(normalize_extended(char).casefold())
        c_len = len(c_skel)
        
        is_outside = False
        if overlap_pct > 0:
            if c_len == 0:
                if not (match_start_idx <= curr_skel_idx < match_end_idx): is_outside = True
            else:
                if (curr_skel_idx + c_len) <= match_start_idx or curr_skel_idx >= match_end_idx:
                    is_outside = True
        
        if is_outside:
            cp = ord(char)
            if cp < 1114112:
                mask_val = INVIS_TABLE[cp]
                if mask_val & MASK_RR:
                    if mask_val & INVIS_BIDI_CONTROL: residual_threats.append("BIDI_INJECTION")
                    elif mask_val & INVIS_TAG: residual_threats.append("TAG_INJECTION")
                    elif mask_val & INVIS_ZERO_WIDTH_SPACING: residual_threats.append("HIDDEN_SPACING")
                    elif mask_val & INVIS_DEFAULT_IGNORABLE: residual_threats.append("DEFAULT_IGNORABLE")
                    elif mask_val & INVIS_VARIATION_SELECTOR: residual_threats.append("HIDDEN_VS")

        curr_skel_idx += c_len

    residual_threats = list(set(residual_threats))

    # --- PHASE 4: PROFILING & PARANOID PHYSICS ---
    suspect_profile = analyze_restriction_level(suspect_str)
    trusted_profile = analyze_restriction_level(trusted_str)
    
    # Call the new Deep Physics Auditor
    # This handles Inflation, Profile Locking, Topology, Whitespace, Numeric, and Casing
    physics_threats = _audit_deep_physics(suspect_str, trusted_str, suspect_nfkc, suspect_profile, trusted_profile)
    
    # Merge physics threats into residual threats for reporting
    residual_threats.extend(physics_threats)

    # --- PHASE 5: VERDICT SYNTHESIS ---
    verdict = "DISTINCT"
    desc = "No significant structural correlation."
    css = "verdict-neutral"
    icon = "≠"
    
    match_raw = (suspect_str == trusted_str)
    match_nfkc = (suspect_nfkc == trusted_nfkc)
    internal_injection = (overlap_pct >= 100.0) and (sus_events.get("ignorables_stripped", 0) > 0)

    # 1. POISONED REFERENCE OVERRIDE
    if reference_warnings:
        verdict = "POISONED REFERENCE"
        desc = f"WARNING: Trusted Reference is unsafe ({', '.join(reference_warnings)})."
        css = "verdict-crit" # Critical because the premise is flawed
        icon = "☣️"
        
    elif match_raw:
        verdict = "IDENTITY MATCH"
        desc = "Bitwise Identical (Raw Bytes)."
        css = "verdict-safe"
        icon = "🛡️"
        
    elif match_nfkc:
        verdict = "NORMALIZATION_EQ"
        desc = "Canonically Identical. Bytes differ (Format/Compatibility)."
        css = "verdict-warn"
        icon = "⚠️"

    elif overlap_pct >= 100.0:
        if len(suspect_skel) > len(trusted_skel):
            verdict = "TARGET_CONTAINED"
            desc = "CRITICAL: Trusted string hidden inside Suspect (Superset)."
            icon = "🎯"
        else:
            verdict = "VISUAL_CLONE"
            icon = "🚨"
            if internal_injection:
                 desc = "CRITICAL: Visual Match contains INVISIBLE INJECTION (Internal Artifacts)."
            else:
                 desc = "CRITICAL: Homograph Attack (Visual Match / Raw Mismatch)."
        
        css = "verdict-crit"
        if residual_threats:
            desc += f" [THREATS: {', '.join(residual_threats)}]"

    elif overlap_pct > 0:
        if residual_threats:
            verdict = "PARTIAL_THREAT"
            desc = f"Partial Match ({overlap_pct:.1f}%) with WEAPONIZED TAIL."
            css = "verdict-crit"
            icon = "☣️"
        else:
            verdict = "VISUAL_OVERLAP"
            desc = f"Partial Visual Match ({overlap_pct:.1f}%)."
            css = "verdict-warn"
            icon = "🧩"

    # --- PHASE 6: CLASSIFICATION ---
    confusable_class = CONFUSABLE_CLASS["NONE"]
    if verdict in ("VISUAL_CLONE", "TARGET_CONTAINED"):
        sus_scripts = set(suspect_profile["scripts"]) - {"Common", "Inherited"}
        tru_scripts = set(trusted_profile["scripts"]) - {"Common", "Inherited"}
        if sus_scripts == tru_scripts:
            confusable_class = CONFUSABLE_CLASS["SINGLE_SCRIPT"]
        else:
            confusable_class = CONFUSABLE_CLASS["CROSS_SCRIPT"]
            
    # Ensure Physics threats are visible in description if not already critical
    if physics_threats and verdict != "POISONED REFERENCE":
        if css != "verdict-crit":
            css = "verdict-warn"
            # Deduplicate description if needed, but append for visibility
            if "THREATS" not in desc:
                 desc += f" [ANOMALIES: {', '.join(physics_threats)}]"

    return {
        "verdict": verdict,
        "desc": desc,
        "css_class": css,
        "icon": icon,
        "states": {
            "raw": "MATCH" if match_raw else "DIFF",
            "nfkc": "MATCH" if match_nfkc else "DIFF",
            "skel": "MATCH" if overlap_pct >= 100 else "PARTIAL" if overlap_pct > 0 else "DIFF"
        },
        "profiles": { "suspect": suspect_profile, "trusted": trusted_profile },
        "confusable_class": confusable_class,
        "residual_threats": residual_threats,
        "internal_injection": internal_injection,
        "overlap_pct": overlap_pct,
        "lens_data": { "match_range": (match_start_idx, match_end_idx), "overlap_pct": overlap_pct } 
    }

def compute_statistical_profile(t: str):
    """
    Stage 1.5 'Chemistry': local statistical properties.
    ULTIMATE VERSION: Combines Sparklines, Detailed Layout Cards, Expanded Tokens,
    Honest Fingerprint, and ASCII/Payload metrics.
    """
    stats = {
        "entropy": 0.0, "entropy_n": 0, "entropy_norm": 0.0, "entropy_conf": "unknown",
        "ttr": 0.0, "ttr_segmented": None,
        "total_tokens": 0, "unique_tokens": 0, "top_tokens": [], "top_shares": {"top1": 0.0, "top3": 0.0},
        "top_chars": [],
        "char_dist": {"letters": 0.0, "digits": 0.0, "ws": 0.0, "sym": 0.0},
        "line_stats": {"count": 0, "min": 0, "max": 0, "avg": 0, "p90": 0, "median": 0, "empty": 0, "sparkline": ""},
        "phonotactics": {"vowel_ratio": 0.0, "status": "N/A", "count": 0, "is_valid": False, "v_count": 0, "c_count": 0},
        "ascii_density": 0.0,
        "payloads": []
    }
    
    if not t: return stats

    # 1. Entropy & ASCII Density
    try:
        utf8_bytes = t.encode("utf-8", errors="replace")
        total_bytes = len(utf8_bytes)
        stats["entropy_n"] = total_bytes
        if total_bytes > 0:
            byte_counts = Counter(utf8_bytes)
            entropy = 0.0
            for count in byte_counts.values():
                p = count / total_bytes
                entropy -= p * math.log2(p)
            stats["entropy"] = round(max(0.0, min(8.0, entropy)), 2)
            
            k = max(1, len(byte_counts))
            h_max = min(8.0, math.log2(k)) if k > 1 else 0.0
            stats["entropy_norm"] = round(entropy / h_max, 3) if h_max > 0 else 0.0
            
            if total_bytes < 128: stats["entropy_conf"] = "low"
            elif total_bytes < 1024: stats["entropy_conf"] = "medium"
            else: stats["entropy_conf"] = "high"

            ascii_bytes = sum(1 for b in utf8_bytes if b <= 0x7F)
            stats["ascii_density"] = round((ascii_bytes / total_bytes) * 100, 1)
    except: pass

    try:
        raw_tokens = t.split()
        
        # Payload Heuristics (Base64 / Hex)
        payload_candidates = []
        # Base64: A-Z, a-z, 0-9, +, / (and URL-safe - _)
        b64_pattern = re.compile(r'^[A-Za-z0-9+/_-]{16,}={0,2}$')
        hex_pattern = re.compile(r'^[0-9A-Fa-f]{16,}$')
        # [NEW] Charcode: 5+ CSV integers (e.g. 65,66,67...)
        char_pattern = re.compile(r'^(\d{2,3},){5,}\d{2,3}$')
        # [NEW] Percent: 5+ encoded bytes (e.g. %20%41...)
        perc_pattern = re.compile(r'^(%[0-9A-Fa-f]{2}){5,}$')
        
        for tok in raw_tokens:
            # Lowered threshold to 14 to catch short %XX runs (5*3=15 chars)
            if len(tok) > 14:
                p_type = None
                if b64_pattern.match(tok): p_type = "Base64"
                elif hex_pattern.match(tok) and len(tok) % 2 == 0: p_type = "Hex"
                elif char_pattern.match(tok): p_type = "Charcode"
                elif perc_pattern.match(tok): p_type = "URL-Enc"
                
                if p_type:
                    # Calculate Local Entropy for this specific token
                    # This distinguishes "padding" from "encrypted data"
                    b_counts = Counter(tok)
                    p_ent = 0.0
                    for count in b_counts.values():
                        p = count / len(tok)
                        p_ent -= p * math.log2(p)
                    
                    payload_candidates.append({
                        "type": p_type, 
                        "token": tok[:32] + "..." if len(tok)>32 else tok, 
                        "len": len(tok),
                        "entropy": round(p_ent, 2)
                    })

        if payload_candidates: stats["payloads"] = payload_candidates[:5]

        # Normalized Tokens
        tokens = [tok.lower() for tok in re.split(r'[\s\.,;!?()\[\]{}"«»„“”]+', t) if tok]
        stats["total_tokens"] = len(tokens)
        if stats["total_tokens"] > 0:
            unique_tokens = set(tokens)
            stats["unique_tokens"] = len(unique_tokens)
            stats["ttr"] = round(len(unique_tokens) / stats["total_tokens"], 3)

            token_counts = Counter(tokens)
            # FETCH 12 TOKENS FOR UI
            top_n_tokens = token_counts.most_common(12) 

            if top_n_tokens:
                stats["top_shares"]["top1"] = round((top_n_tokens[0][1] / stats["total_tokens"]) * 100, 1)
                top3_sum = sum(c for _, c in top_n_tokens[:3])
                stats["top_shares"]["top3"] = round((top3_sum / stats["total_tokens"]) * 100, 1)

                structured_tokens = []
                for tok, count in top_n_tokens:
                    share = (count / stats["total_tokens"]) * 100
                    structured_tokens.append({"token": tok, "count": count, "share": round(share, 1)})
                stats["top_tokens"] = structured_tokens

            seg_size = 50
            if stats["total_tokens"] >= seg_size * 2:
                seg_ttrs = []
                for i in range(0, len(tokens), seg_size):
                    seg = tokens[i : i + seg_size]
                    if len(seg) < seg_size // 2: continue
                    seg_ttrs.append(len(set(seg)) / len(seg))
                if seg_ttrs:
                    stats["ttr_segmented"] = round(sum(seg_ttrs) / len(seg_ttrs), 3)
    except: pass

    # 3. Honest Fingerprint
    try:
        total_chars = len(t)
        if total_chars > 0:
            char_counts = Counter(t)
            valid_chars = {}
            for ch, cnt in char_counts.items():
                cp = ord(ch)
                if cp > 0x20 or cp in (0x20, 0x09, 0x0A):
                    valid_chars[ch] = cnt
            
            if valid_chars:
                top_chars = sorted(valid_chars.items(), key=lambda x: x[1], reverse=True)[:5]
                structured_chars = []
                for ch, count in top_chars:
                    share = (count / total_chars) * 100
                    cat = "Other"
                    if ch.isalpha(): cat = "Let"
                    elif ch.isdigit(): cat = "Num"
                    elif unicodedata.category(ch).startswith("P"): cat = "Punct"
                    elif ch.isspace(): cat = "WS"
                    structured_chars.append({"char": ch, "count": count, "share": round(share, 1), "cat": cat})
                stats["top_chars"] = structured_chars

            l_count = sum(1 for c in t if c.isalpha())
            n_count = sum(1 for c in t if c.isdigit())
            ws_count = sum(1 for c in t if c.isspace())
            sym_count = max(0, total_chars - l_count - n_count - ws_count)
            stats["char_dist"] = {
                "letters": round((l_count / total_chars) * 100, 1),
                "digits": round((n_count / total_chars) * 100, 1),
                "ws": round((ws_count / total_chars) * 100, 1),
                "sym": round((sym_count / total_chars) * 100, 1)
            }
    except: pass

    # 4. Layout Physics (STRICT VISUAL SPLIT + SPARKLINE)
    try:
        normalized_t = t.replace('\r\n', '\n').replace('\r', '\n')
        lines = normalized_t.split('\n')
        if len(lines) > 1 and lines[-1] == '': lines.pop()
        
        n = len(lines)
        stats["line_stats"]["count"] = n
        
        if n > 0:
            line_lens = [len(line) for line in lines]
            sorted_lens = sorted(line_lens)
            
            stats["line_stats"]["min"] = sorted_lens[0]
            stats["line_stats"]["max"] = sorted_lens[-1]
            stats["line_stats"]["avg"] = round(sum(line_lens) / n, 1)
            stats["line_stats"]["empty"] = sum(1 for l in line_lens if l == 0)
            
            # Helper for percentiles (Pure Python, no deps)
            def get_perc(p, d):
                pos = p * (len(d) - 1)
                lower = int(pos)
                upper = lower + 1
                if upper >= len(d): return d[-1]
                weight = pos - lower
                return int(round(d[lower] * (1 - weight) + d[upper] * weight))

            stats["line_stats"]["p25"] = get_perc(0.25, sorted_lens)
            stats["line_stats"]["median"] = get_perc(0.50, sorted_lens)
            stats["line_stats"]["p50"] = stats["line_stats"]["median"] # Alias
            stats["line_stats"]["p75"] = get_perc(0.75, sorted_lens)
            stats["line_stats"]["p90"] = get_perc(0.90, sorted_lens)
            
            # --- MASS DISTRIBUTION MAP (Stacked Bar Data) ---
            total_mass = sum(line_lens)
            if total_mass == 0: total_mass = 1
            
            layout_map = []
            target_segments = 60 
            
            if n <= target_segments:
                for i, length in enumerate(line_lens):
                    pct = (length / total_mass) * 100
                    col = "#3b82f6" if i % 2 == 0 else "#93c5fd" 
                    if length == 0: col = "#e2e8f0" 
                    layout_map.append({"w": pct, "c": col})
            else:
                chunk_size = n / target_segments
                for i in range(target_segments):
                    s = int(i * chunk_size)
                    e = int((i + 1) * chunk_size)
                    chunk = line_lens[s:e]
                    mass = sum(chunk)
                    pct = (mass / total_mass) * 100
                    col = "#3b82f6" if i % 2 == 0 else "#93c5fd"
                    if mass == 0: col = "#e2e8f0"
                    layout_map.append({"w": pct, "c": col})
            
            stats["line_stats"]["layout_map"] = layout_map
    except Exception as e:
        print(f"Layout Calc Error: {e}")

    # 5. Phonotactics (8-Point Analysis)
    try:
        # Filter for just the letters to analyze phonemes
        ascii_letters = [c.lower() for c in t if 'a' <= c.lower() <= 'z']
        letter_count = len(ascii_letters)
        
        # Gate: Need enough data to be meaningful
        if letter_count > 10 and (letter_count / max(1, len(t))) > 0.3:
            vowels = set("aeiou")
            v_count = sum(1 for c in ascii_letters if c in vowels)
            c_count = letter_count - v_count
            
            # 1. Bits Per Phoneme (Letter Entropy)
            # H = -Sum(p * log2(p)) for the letter stream
            l_counts = Counter(ascii_letters)
            l_ent = 0.0
            for cnt in l_counts.values():
                p = cnt / letter_count
                l_ent -= p * math.log2(p)
            
            # 2. Heuristic Frequency Scoring (Simulated N-Grams)
            # Top English frequencies (Approximate)
            top_uni = set("etaoinshrdlu") # ~80% of English
            top_bi = {"th", "he", "in", "er", "an", "re", "nd", "at", "on", "nt", "ha", "es", "st", "en", "ed", "to", "it", "ou", "ea", "hi"}
            top_tri = {"the", "and", "ing", "ent", "ion", "her", "for", "tha", "nth", "int", "ere", "tio", "ter", "est", "ers", "ati", "hat", "ate", "all", "eth"}
            
            # Unigram Score: Density of High-Freq Letters
            uni_hits = sum(1 for c in ascii_letters if c in top_uni)
            uni_score = (uni_hits / letter_count) * 100
            
            # Bigram/Trigram Generation
            letter_str = "".join(ascii_letters)
            
            # Bigram Score
            bi_hits = 0
            if letter_count >= 2:
                total_bi = letter_count - 1
                for i in range(total_bi):
                    if letter_str[i:i+2] in top_bi: bi_hits += 1
                bi_score = (bi_hits / total_bi) * 100
            else:
                bi_score = 0.0

            # Trigram Score
            tri_hits = 0
            if letter_count >= 3:
                total_tri = letter_count - 2
                for i in range(total_tri):
                    if letter_str[i:i+3] in top_tri: tri_hits += 1
                tri_score = (tri_hits / total_tri) * 100
            else:
                tri_score = 0.0

            stats["phonotactics"].update({
                "vowel_ratio": round(v_count / letter_count, 2),
                "count": letter_count,
                "is_valid": True,
                "v_count": v_count,
                "c_count": c_count,
                "bits_per_phoneme": round(l_ent, 2),
                "uni_score": round(uni_score, 1),
                "bi_score": round(bi_score, 1),
                "tri_score": round(tri_score, 1)
            })
            
            r = stats["phonotactics"]["vowel_ratio"]
            if 0.30 <= r <= 0.50: stats["phonotactics"]["status"] = "Balanced"
            elif r < 0.20: stats["phonotactics"]["status"] = "Vowel-Poor"
            elif r > 0.60: stats["phonotactics"]["status"] = "Vowel-Heavy"
            else: stats["phonotactics"]["status"] = "Typical"
    except Exception as e: 
        print(f"Phono Error: {e}")
        pass

    return stats

def analyze_trojan_context(token: str):
    """
    [TROJAN SOURCE] Checks for Bidi controls near code syntax.
    """
    has_bidi = False
    for char in token:
        cp = ord(char)
        if cp < 1114112 and (INVIS_TABLE[cp] & INVIS_BIDI_CONTROL):
            has_bidi = True
            break
            
    if not has_bidi: return None
    
    # Check for code-like syntax chars
    code_syntax = {'"', "'", ';', '{', '}', '/', '*', '#'}
    is_code_adjacent = any(c in code_syntax for c in token)
    
    if is_code_adjacent:
        return {"desc": "Bidi Control near Syntax (Trojan Risk)", "risk": 100}
    return {"desc": "Bidi Control present", "risk": 60}

def analyze_confusion_density(token, confusables=None):
    """
    Calculates the 'Confusion Density' of a token using UTS #39 data.
    [HARDENED v2.0] 
    - GOLDEN FIX: Removes unpacking assignments. Uses strict index access.
    - Handles Strings, 2-Tuples, and N-Tuples safely.
    """
    if not token: return None
    
    # 1. Handle optional argument
    if confusables is None:
        confusables = DATA_STORES.get("Confusables", {})
        
    total_chars = len(token)
    confusable_count = 0
    
    for char in token:
        cp = ord(char)
        if cp in confusables:
            val = confusables[cp]
            tag = "UNK" # Default tag
            
            # --- GOLDEN FIX: SCHEMA TOLERANCE ---
            # Old Code (CRASHES): tgt, tag = val
            # New Code (SAFE): Check type, then index.
            
            if isinstance(val, (tuple, list)):
                # If tuple is ('target', 'MA', ...), val[1] is 'MA'
                if len(val) >= 2: 
                    tag = val[1]
                # If tuple is just ('target',), tag remains "UNK"
                
            elif isinstance(val, str):
                # Legacy string format: "target". Tag remains "UNK".
                pass
            
            # 3. Weighted Scoring
            if tag in ("MA", "ML"): # Mixed Script / Mixed Latin (High Risk)
                confusable_count += 1.0
            elif tag in ("SA", "SL"): # Single Script (Lower Risk)
                confusable_count += 0.5
            else:
                confusable_count += 0.8 # Default/UNK fallback
                
    if total_chars == 0: return None
    
    # Calculate Density
    density = min(confusable_count / total_chars, 1.0)
    
    if density > 0:
        return {
            "density": density,
            "risk": int(density * 50), # Scale to 0-50 risk points
            "desc": f"Confusable Density ({int(density*100)}%)"
        }
        
    return None

def analyze_zalgo_load(token: str):
    """
    [ZALGO] Checks for Diacritic Overload.
    FIX: Ignores Variation Selectors (VS15/VS16) to avoid flagging Emoji as Zalgo.
    """
    mark_count = 0
    base_count = 0
    max_stack = 0
    current_stack = 0
    
    for char in token:
        cp = ord(char)
        # Exclude Variation Selectors from "Mark" count for Zalgo purposes
        if 0xFE00 <= cp <= 0xFE0F or 0xE0100 <= cp <= 0xE01EF:
            continue
            
        if unicodedata.category(char).startswith('M'):
            mark_count += 1
            current_stack += 1
        else:
            base_count += 1
            max_stack = max(max_stack, current_stack)
            current_stack = 0
    max_stack = max(max_stack, current_stack)
    
    ratio = mark_count / max(1, base_count)
    
    if max_stack >= 4 or ratio > 2.0:
        return {"desc": f"Diacritic Overload (Max Stack: {max_stack})", "risk": 80}
    elif max_stack >= 2 or ratio > 0.5:
        return {"desc": "Heavy Diacritics", "risk": 40}
        
    return None

def analyze_case_anomalies(token: str):
    """
    [CASE ANOMALY] Detects suspicious casing (PayPaI).
    """
    if len(token) < 3: return None
    
    # 1. Mixed Case at End (PayPaI)
    if token[:-1].islower() and token[-1].isupper():
        return {"desc": "Suspicious End-Capitalization", "risk": 40}
        
    # 2. Random Upper in Lower (payPa1)
    # Heuristic: Mostly lower with 1 isolated upper in middle
    uppers = sum(1 for c in token if c.isupper())
    lowers = sum(1 for c in token if c.islower())
    
    if lowers > 2 and uppers == 1 and not token[0].isupper():
        return {"desc": "Suspicious Mid-Capitalization", "risk": 40}
        
    return None

def detect_invisible_patterns(t: str):
    """
    [STEGANOGRAPHY] Global scanner for repeating invisible sequences.
    """
    if not t: return None
    invis_seq = []
    for char in t:
        cp = ord(char)
        mask = INVIS_TABLE[cp] if cp < 1114112 else 0
        if mask & INVIS_ANY_MASK:
            if mask & INVIS_ZERO_WIDTH_SPACING: tag = "ZW"
            elif mask & INVIS_JOIN_CONTROL: tag = "JN"
            elif mask & INVIS_TAG: tag = "TG"
            elif mask & INVIS_BIDI_CONTROL: tag = "BD"
            elif mask & (INVIS_VARIATION_STANDARD | INVIS_VARIATION_IDEOG): tag = "VS"
            else: tag = "?? "
            invis_seq.append(tag)
            
    if len(invis_seq) < 4: return None
    
    patterns = collections.Counter()
    n = len(invis_seq)
    for k in [2, 3]:
        for i in range(n - k + 1):
            gram = tuple(invis_seq[i : i + k])
            patterns[gram] += 1
            
    suspects = []
    for gram, count in patterns.items():
        if count > 2 and (count * len(gram) > n * 0.4):
            pat_str = "-".join(gram)
            suspects.append(f"{pat_str} (x{count})")
            
    if suspects:
        return {
            "verdict": "Structured Invisible Pattern",
            "detail": ", ".join(suspects),
            "risk": "Steganography / Watermark",
            "score": 75
        }
    return None

def analyze_adversarial_tokens(t: str):
    """
    The Core Engine for Stage 1.1 "Adversarial Intelligence".
    Tokenizes text and performs per-token forensic extraction.
    
    ULTIMATE VERSION (Syntax-Safe):
    1. Uses Manual Tokenization (char.isspace) to avoid Regex escape issues.
    2. Performs deep forensic enrichment (Skeletons, Scripts, ID Profile).
    """
    if not t: return {"tokens": [], "collisions": [], "stats": {}}

    # --- 1. Forensic Tokenization (Greedy / Whitespace-Based) ---
    # Replaced Regex with Manual Loop to eliminate "invalid escape sequence" errors.
    # This splits purely on Unicode Whitespace while preserving all internal characters
    # (including invisible joiners/format controls) as a single token.
    
    raw_tokens = []
    current_start = -1
    
    for i, char in enumerate(t):
        is_ws = char.isspace()
        
        if not is_ws:
            # If we are not in a token, start one
            if current_start == -1:
                current_start = i
        else:
            # If we were in a token, close it
            if current_start != -1:
                clean_text = t[current_start:i].strip("()[]{}<>\"',;!|")
                
                if clean_text:
                    # Calculate real offsets after strip
                    raw_chunk = t[current_start:i]
                    offset = raw_chunk.find(clean_text)
                    real_start = current_start + offset
                    
                    raw_tokens.append({
                        "text": clean_text,
                        "start": real_start,
                        "end": real_start + len(clean_text)
                    })
                
                current_start = -1

    # Flush final token if string didn't end with whitespace
    if current_start != -1:
        clean_text = t[current_start:].strip("()[]{}<>\"',;!|")
        
        if clean_text:
            raw_chunk = t[current_start:]
            offset = raw_chunk.find(clean_text)
            real_start = current_start + offset
            
            raw_tokens.append({
                "text": clean_text,
                "start": real_start,
                "end": real_start + len(clean_text)
            })

    enriched_tokens = []
    skeleton_map = collections.defaultdict(list) # skeleton -> [token_indices]

    # --- 2. Enrichment Loop ---
    for idx, raw in enumerate(raw_tokens):
        txt = raw["text"]
        
        # A. Classification (Email, Domain, Identifier, Word)
        kind = _classify_token_kind(txt)
        
        # B. Scripts (Set of scripts used in token)
        scripts = _get_script_set(txt)
        
        # C. Identifier Profile (UAX #31 Status/Type)
        id_profile = _get_identifier_profile(txt)
        
        # D. Skeleton Generation & Metadata
        # We need return_events=True to calculate Confusable Density
        skel, skel_events = _generate_uts39_skeleton(txt, return_events=True)
        
        # E. Confusable Analysis (Local Density)
        confusable_count = skel_events.get('confusables_mapped', 0)
        confusable_density = 0
        if len(txt) > 0:
            confusable_density = round(confusable_count / len(txt), 2)
            
        # F. Invisible/Hidden Check (Local Count)
        invis_count = 0
        for char in txt:
            # Use O(1) Lookup Table
            if INVIS_TABLE[ord(char)] & INVIS_ANY_MASK:
                invis_count += 1
                
        # G. Mixed Script Check
        # Filter out "safe" scripts (Common/Inherited) to find true mixing
        major_scripts = {s for s in scripts if s not in ("Common", "Inherited", "Unknown")}
        is_mixed_script = len(major_scripts) > 1

        # Build Feature Vector (Consumed by _evaluate_adversarial_risk)
        token_data = {
            "id": idx,
            "text": txt,
            "span": (raw["start"], raw["end"]),
            "kind": kind,
            "scripts": sorted(list(major_scripts)),
            "is_mixed": is_mixed_script,
            "skeleton": skel,
            "id_status": id_profile["status"],
            "id_types": sorted(list(id_profile["types"])),
            "confusables": {
                "count": confusable_count,
                "density": confusable_density,
                "mappings": skel_events.get('mappings', []) 
            },
            "invisibles": invis_count,
            "risk": "LOW", # Will be updated by Block 2 (Risk Engine)
            "triggers": [] # Will be populated by Block 2
        }
        
        enriched_tokens.append(token_data)
        
        # Map for collision detection (Homograph Radar)
        # Only map tokens > 1 char to avoid noise
        if len(txt) > 1:
            skeleton_map[skel].append(idx)

    # Return intermediate data structure
    return {
        "tokens": enriched_tokens,
        "skeleton_map": skeleton_map
    }

def analyze_signal_processor_state(data):
    """
    Forensic State Machine v5.2 (Fixed Data Structures & Cross-Script Logic).
    Standardizes all facets to dictionaries to prevent NameError.
    """
    
    # --- 1. THREAT DEFINITIONS ---
    RISK_WEIGHTS = {
        "INVISIBLE": 2.0,
        "NON_ASCII": 0.5,
        "BIDI": 4.0,             
        "ZALGO_HEAVY": 3.0,      
        "ZALGO_LIGHT": 0.5,      
        "LAYOUT_CONTROL": 1.5,   
        "CONFUSABLE_CROSS": 3.0, 
        "CONFUSABLE_SAME": 0.0,  
    }

    # --- 2. RAW SENSORS & CONTEXT ---
    
    cp_hex = data.get('cp_hex_base', '').replace('U+', '')
    try:
        cp = int(cp_hex, 16)
    except:
        cp = 0
    
    script = data.get('script', 'Common')
    raw_confusable = bool(data.get('confusable'))
    is_ascii = data.get('ascii', 'N/A') != 'N/A'

    # Check the global set we loaded from JSON
    is_ascii_confusable = (cp in ASCII_CONFUSABLES)
    
    # Cross-Script requires the source to NOT be Common/Inherited.
    # Em Dash (Common) -> Hyphen (Common) is NOT a cross-script threat.
    is_common_script = script in ("Common", "Inherited")
    is_cross_script_confusable = raw_confusable and not is_ascii and not is_common_script
    
    stack_msg = data.get('stack_msg') or ""
    mark_count = 0
    if 'components' in data:
        for c in data['components']:
            if not c['is_base']: mark_count += 1
            
    zalgo_threshold = 2 if script in ('Latin', 'Common') else 4
    is_heavy_zalgo = "Heavy" in stack_msg or mark_count > zalgo_threshold
    is_light_mark = mark_count > 0 and not is_heavy_zalgo
    
    is_invisible = data.get('is_invisible', False)
    bidi_val = data.get('bidi')
    is_bidi_control = bidi_val in ('LRE', 'RLE', 'LRO', 'RLO', 'PDF', 'LRI', 'RLI', 'FSI', 'PDI')
    
    cat = data.get('category', 'N/A')
    is_layout_control = cat in ('Format', 'Space Separator') and not is_bidi_control and not is_invisible and not is_ascii

    # --- 3. FACET STATE CALCULATOR ---

    # Check for Hard Corruption
    is_corruption = (cp == 0xFFFD or cp == 0x0000 or cat == 'Cs')
    
    current_score = 0.0
    reasons = []

    # A. VISIBILITY (Constructs 'vis' dict)
    if is_invisible:
        if is_bidi_control:
             vis = {"state": "HIDDEN", "class": "risk-fail", "icon": "eye_off", "detail": "Control Char"}
        else:
             current_score += RISK_WEIGHTS["INVISIBLE"]
             vis = {"state": "HIDDEN", "class": "risk-fail", "icon": "eye_off", "detail": "Non-Rendered"}
             reasons.append("Invisible Character")
    elif is_corruption:
        # Explicit Corruption Handling
        current_score += 4.0 # Instant Critical
        vis = {"state": "CORRUPT", "class": "risk-fail", "icon": "eye_off", "detail": "Data Loss"}
        reasons.append("Data Corruption")
    elif not is_ascii:
        current_score += RISK_WEIGHTS["NON_ASCII"]
        vis = {"state": "EXTENDED", "class": "risk-info", "icon": "eye", "detail": "Unicode Range"}
    else:
        vis = {"state": "PASS", "class": "risk-pass", "icon": "eye", "detail": "Standard ASCII"}

    # B. STRUCTURE (Constructs 'struct' dict)
    if is_bidi_control:
        current_score += RISK_WEIGHTS["BIDI"]
        struct = {"state": "FRACTURED", "class": "risk-fail", "icon": "layers", "detail": "Bidi Control"}
        reasons.append("Directional Control")
    elif is_heavy_zalgo:
        current_score += RISK_WEIGHTS["ZALGO_HEAVY"]
        struct = {"state": "UNSTABLE", "class": "risk-warn", "icon": "layers", "detail": f"Heavy Stack ({mark_count})"}
        reasons.append("Excessive Marks")
    elif is_light_mark:
        current_score += RISK_WEIGHTS["ZALGO_LIGHT"]
        struct = {"state": "MODIFIED", "class": "risk-info", "icon": "cube", "detail": "Combining Marks"}
    elif is_layout_control:
        current_score += RISK_WEIGHTS["LAYOUT_CONTROL"]
        struct = {"state": "LAYOUT", "class": "risk-warn", "icon": "cube", "detail": "Format Control"}
    else:
        struct = {"state": "STABLE", "class": "risk-pass", "icon": "cube", "detail": "Atomic Base"}

    # C. IDENTITY (Calculates vars, then constructs 'ident' dict)
    ident_state = "UNIQUE"
    ident_class = "risk-pass"
    ident_icon = "fingerprint"
    ident_detail = "No Lookalikes"

    lookalikes = DATA_STORES.get("InverseConfusables", {}).get(str(cp), [])
    lookalike_count = len(lookalikes)

    if is_cross_script_confusable:
        current_score += RISK_WEIGHTS["CONFUSABLE_CROSS"]
        ident_state = "AMBIGUOUS"
        ident_class = "risk-warn"
        ident_icon = "clone"
        detail_text = f"{lookalike_count} Lookalikes" if lookalike_count > 0 else "Cross-Script Risk"
        ident_detail = detail_text
        reasons.append("Confusable Identity")
        
    elif is_ascii_confusable or (raw_confusable and is_common_script): 
        # Common/Inherited confusions (like Em Dash) fall here (Note/Blue), not Warn/Orange
        current_score += RISK_WEIGHTS["CONFUSABLE_SAME"]
        ident_state = "NOTE"
        ident_class = "risk-info"
        ident_icon = "fingerprint"
        ident_detail = f"{lookalike_count} Lookalikes"
        
    elif lookalike_count > 0:
        ident_state = "NOTE"
        ident_class = "risk-info"
        ident_detail = f"{lookalike_count} Lookalikes"

    # Wrap Identity into a dict to match the others
    ident = {
        "state": ident_state,
        "class": ident_class,
        "icon": ident_icon,
        "detail": ident_detail
    }

    # --- 4. VERDICT LEVEL MAPPING ---
    
    level = 0
    label = "BASELINE"
    header_class = "header-baseline"
    icon = "shield_ok"
    footer_label = "ANALYSIS"
    footer_text = "Standard Composition"
    footer_class = "footer-neutral"

    if 0.5 <= current_score < 1.5:
        level = 1
        label = "NON-STD"
        header_class = "header-complex"
        icon = "shield_ok"
        footer_label = "NOTE"
        footer_text = "Extended Unicode / Marks"
        footer_class = "footer-info"
        
    elif 1.5 <= current_score < 3.0:
        level = 2
        label = "ANOMALOUS"
        header_class = "header-anomalous"
        icon = "shield_warn"
        footer_label = "DETECTED"
        footer_class = "footer-warn"
        
    elif 3.0 <= current_score < 4.0:
        level = 3
        label = "SUSPICIOUS"
        header_class = "header-suspicious"
        icon = "shield_warn"
        footer_label = "DETECTED"
        footer_class = "footer-warn"
        
    elif current_score >= 4.0:
        level = 4
        label = "CRITICAL"
        header_class = "header-critical"
        icon = "octagon_crit"
        footer_label = "DETECTED"
        footer_class = "footer-crit"

    # --- 5. HARD OVERRIDES ---
    if is_bidi_control and level < 3:
        level = 3
        label = "SUSPICIOUS"
        header_class = "header-suspicious"
        icon = "shield_warn"
        footer_class = "footer-warn"

    # HARD OVERRIDE FOR CORRUPTION
    if is_corruption:
        level = 4
        label = "CRITICAL"
        header_class = "header-critical"
        icon = "octagon_crit"
        footer_label = "FATAL"
        footer_text = "Data Integrity Failure"
        footer_class = "footer-crit"

    if reasons:
        footer_text = ", ".join(reasons)
    elif level == 0 and is_ascii_confusable:
        footer_label = "NOTE"
        footer_text = "Common Lookalike (Safe)"

    return {
        "level": level,
        "level_text": f"LEVEL {level}",
        "verdict_text": label,
        "header_class": header_class,
        "icon_key": icon,
        "facets": [vis, struct, ident], # Pass the dicts directly
        "footer_label": footer_label,
        "footer_text": footer_text,
        "footer_class": footer_class
    }

def compute_whitespace_topology(t):
    """
    Analyzes Whitespace & Line Ending Topology (The 'Frankenstein' Detector).
    Detects Mixed Line Endings (CRLF/LF) and Deceptive Spacing (ASCII/NBSP).
    """
    
    ws_stats = collections.Counter()
    
    # State tracking for CRLF
    prev_was_cr = False
    
    # Flags for Verdict
    has_lf = False
    has_cr = False
    has_crlf = False
    has_nel = False
    has_ls_ps = False

    for ch in t:
        # --- A. Newline State Machine ---
        if ch == '\n':
            if prev_was_cr:
                ws_stats['CRLF (Windows)'] += 1
                has_crlf = True
                prev_was_cr = False # Consumed
            else:
                ws_stats['LF (Unix)'] += 1
                has_lf = True
        elif ch == '\r':
            if prev_was_cr: # Double CR case (CR + CR)
                ws_stats['CR (Legacy Mac)'] += 1
                has_cr = True
            prev_was_cr = True # Defer count until next char check
        elif ch == '\u0085':
            ws_stats['NEL (Next Line)'] += 1
            has_nel = True
            prev_was_cr = False
        elif ch == '\u2028':
            ws_stats['LS (Line Sep)'] += 1
            has_ls_ps = True
            prev_was_cr = False
        elif ch == '\u2029':
            ws_stats['PS (Para Sep)'] += 1
            has_ls_ps = True
            prev_was_cr = False
        else:
            # Not a newline, but check if we have a dangling CR pending
            if prev_was_cr:
                ws_stats['CR (Legacy Mac)'] += 1
                has_cr = True
                prev_was_cr = False
            
            # --- B. Whitespace Classification ---
            if ch == '\u0020': ws_stats['SPACE (ASCII)'] += 1
            elif ch == '\u00A0': ws_stats['NBSP (Non-Breaking)'] += 1
            elif ch == '\t': ws_stats['TAB'] += 1
            elif ch == '\u3000': ws_stats['IDEOGRAPHIC SPACE'] += 1
            elif ud.category(ch) == 'Zs':
                name = ud.name(ch, 'UNKNOWN SPACE')
                ws_stats[f"{name} (U+{ord(ch):04X})"] += 1

    # Final check for trailing CR
    if prev_was_cr:
        ws_stats['CR (Legacy Mac)'] += 1
        has_cr = True

    # --- C. Heuristic Alerts ---
    alerts = []
    
    # 1. Mixed Line Endings
    newline_types = sum([has_lf, has_cr, has_crlf, has_nel, has_ls_ps])
    if newline_types > 1:
        alerts.append("⚠️ Mixed Line Endings (Consistency Failure)")
    
    # 2. Mixed Spacing (Phishing Vector)
    if ws_stats['SPACE (ASCII)'] > 0 and ws_stats['NBSP (Non-Breaking)'] > 0:
        alerts.append("⚠️ Mixed Spacing (ASCII + NBSP)")
        
    if has_nel or has_ls_ps:
        alerts.append("ℹ️ Unicode Newlines (NEL/LS/PS) Detected")

    # --- D. Render ---
    rows = ""
    for k, v in ws_stats.most_common():
        rows += f"<tr><td>{k}</td><td style='text-align:right; font-family:monospace;'>{v}</td></tr>"
        
    if not rows: rows = "<tr><td colspan='2' style='color:#999'>No whitespace detected.</td></tr>"
    
    alert_html = ""
    if alerts:
        alert_html = f"<div style='color:#b02a37; font-size:0.85em; margin-bottom:8px; font-weight:bold;'>{'<br>'.join(alerts)}</div>"

    html = f"""
    <div class="ws-topology-card" style="margin-top:1rem; border:1px solid #dee2e6; padding:10px; border-radius:4px; background:#f8f9fa;">
        <h4 style="margin:0 0 8px 0; font-size:0.9rem; color:#495057;">Whitespace & Line Ending Topology</h4>
        {alert_html}
        <table style="width:100%; font-size:0.85rem;">
            {rows}
        </table>
    </div>
    """
    return html

def _parse_inline_css(style_str: str) -> Dict[str, str]:
    """
    Parses inline style strings into a dictionary using the robust regex from Block 2.
    Handles 'display: none;' and 'display:none' equally.
    """
    if not style_str:
        return {}
    
    styles = {}
    # Use the pre-compiled regex from METADATA_PATTERNS to allow for complex values
    for match in METADATA_PATTERNS.CSS_DECLARATION_SPLIT.finditer(style_str):
        prop = match.group('prop').lower().strip()
        val = match.group('val').lower().strip()
        styles[prop] = val
    return styles

class ForensicContext:
    """
    Represents the Computed Forensic State of a single DOM node.
    [UPDATED] Adds robust Color Normalization to fix the 'Round Trip' bug.
    """
    def __init__(self, tag: str, attrs: List[Tuple[str, str]], parent: Optional['ForensicContext'] = None):
        self.tag = tag
        self.attrs = dict(attrs)
        self.classes = set(self.attrs.get('class', '').split())
        self.id_ref = self.attrs.get('id', '')
        
        # 1. Parse Local Styles
        self.local_style = _parse_inline_css(self.attrs.get('style', ''))
        
        # 2. Compute Physics (Inheritance Simulation)
        
        # A. Visibility Lineage
        parent_visible = parent.is_visible if parent else True
        self.is_visible = parent_visible and self._check_local_visibility()
        
        # B. Opacity Physics
        parent_opacity = parent.effective_opacity if parent else 1.0
        self.effective_opacity = parent_opacity * self._get_local_opacity()
        
        # C. Color Physics (Contrast) with NORMALIZATION
        # Get raw color strings
        raw_color = self.local_style.get('color') or (parent.raw_color if parent else 'black')
        raw_bg = self.local_style.get('background-color') or (self.local_style.get('background'))
        
        # Save raw for inheritance
        self.raw_color = raw_color 
        
        # Normalize for Physics Check (Strip spaces, lowercase)
        # Fixes the "rgb(255, 255, 255)" vs "rgb(255,255,255)" mismatch
        self.norm_color = self._normalize_color(raw_color)
        
        # Resolve effective background
        # If local bg is missing/transparent, inherit from parent
        local_bg_norm = self._normalize_color(raw_bg)
        if not local_bg_norm or local_bg_norm in METADATA_PHYSICS.TRANSPARENT_ALIASES:
            self.norm_bg = parent.norm_bg if parent else 'white' # Assume page default white
        else:
            self.norm_bg = local_bg_norm

    def _normalize_color(self, color_str: Optional[str]) -> str:
        """
        [CRITICAL FIX] Strips whitespace to ensure 'rgb(255, 255, 255)' matches aliases.
        """
        if not color_str: return ""
        # Remove all spaces and lower case
        return color_str.lower().replace(" ", "")

    def _check_local_visibility(self) -> bool:
        """Checks SOTA Hard-Hiding Flags."""
        # 1. HTML Attributes
        if self.attrs.get('hidden') is not None: return False
        if self.attrs.get('aria-hidden') == 'true': return False
        
        # 2. CSS Display/Visibility
        display = self.local_style.get('display', '')
        visibility = self.local_style.get('visibility', '')
        if display in METADATA_PHYSICS.HARD_DISPLAY_VALUES: return False
        if visibility in METADATA_PHYSICS.HARD_VISIBILITY_VALUES: return False
        
        # 3. Geometric Hiding
        width = self.local_style.get('width', '')
        height = self.local_style.get('height', '')
        font_size = self.local_style.get('font-size', '')
        
        if width in {'0', '0px'} or height in {'0', '0px'}: return False
        if font_size == '0' or font_size == '0px': return False
        
        # 4. Off-Screen Positioning
        left = self.local_style.get('left', '0').replace('px', '')
        text_indent = self.local_style.get('text-indent', '0').replace('px', '')
        try:
            if float(left) < -METADATA_PHYSICS.MAX_OFFSCREEN_OFFSET: return False
            if float(text_indent) < METADATA_PHYSICS.MIN_TEXT_INDENT: return False
        except ValueError:
            pass 
            
        return True

    def _get_local_opacity(self) -> float:
        try:
            val = self.local_style.get('opacity', '1.0')
            return float(val)
        except ValueError:
            return 1.0

    def diagnose_root_cause(self) -> str:
        """Returns the specific forensic reason for invisibility."""
        if self.effective_opacity < METADATA_PHYSICS.MIN_VISIBLE_OPACITY:
            return f"Opacity Chain ({self.effective_opacity:.2f})"
        
        # Check White-on-White (Contrast Hiding) using NORMALIZED values
        if (self.norm_color in METADATA_PHYSICS.WHITE_ALIASES and 
            self.norm_bg in METADATA_PHYSICS.WHITE_ALIASES):
            return "Zero Contrast (White-on-White)"
            
        if self.local_style.get('display') in METADATA_PHYSICS.HARD_DISPLAY_VALUES:
            return f"Display: {self.local_style['display']}"
            
        if self.local_style.get('visibility') in METADATA_PHYSICS.HARD_VISIBILITY_VALUES:
            return f"Visibility: {self.local_style['visibility']}"
            
        if self.attrs.get('hidden') is not None:
            return "Attribute: [hidden]"
            
        if self.attrs.get('aria-hidden') == 'true':
            return "Attribute: [aria-hidden]"
            
        return "Inherited/Geometric Obfuscation"


class ForensicHTMLParser(HTMLParser):
    """
    [STAGE 1.5] The Static Forensic Simulator.
    Iterates raw HTML, maintains the Context Stack, and generates the Forensic X-Ray.
    """
    def __init__(self):
        super().__init__()
        self.stack: List[ForensicContext] = []
        self.findings: List[Dict[str, Any]] = []
        self.ghost_view_fragments: List[str] = []
        self._current_lineage: List[str] = []

    def handle_starttag(self, tag, attrs):
        # 1. Push Context
        parent = self.stack[-1] if self.stack else None
        ctx = ForensicContext(tag, attrs, parent)
        self.stack.append(ctx)
        
        # 2. Maintain Lineage Trace (e.g., "DIV.main > SPAN.hidden")
        ident = tag
        if 'class' in ctx.attrs:
            ident += f".{'.'.join(ctx.classes)[:15]}" # Truncate for UI
        elif ctx.id_ref:
            ident += f"#{ctx.id_ref}"
        self._current_lineage.append(ident)

    def handle_endtag(self, tag):
        if self.stack:
            self.stack.pop()
        if self._current_lineage:
            self._current_lineage.pop()

    def handle_data(self, data):
        if not data.strip(): 
            return # Ignore whitespace nodes

        current = self.stack[-1] if self.stack else None
        
        # 3. Detect Obfuscation (The Trigger)
        is_obfuscated = False
        cause = "Unknown"
        
        if current:
            # Check Physics
            is_hidden = not current.is_visible
            is_transparent = current.effective_opacity < METADATA_PHYSICS.MIN_VISIBLE_OPACITY
            is_contrast_hidden = "Zero Contrast" in current.diagnose_root_cause()
            
            if is_hidden or is_transparent or is_contrast_hidden:
                is_obfuscated = True
                cause = current.diagnose_root_cause()
                
                # Record Finding
                self.findings.append({
                    "type": "CSS_OBFUSCATION",
                    "content": data[:50].strip(), # Preview
                    "lineage": list(self._current_lineage), # Clone list
                    "cause": cause,
                    "context_classes": list(current.classes),
                    "context_tag": current.tag
                })

        # 4. Generate "Ghost View" (Forensic X-Ray)
        # Wraps hidden content in a visualizer span for the Editor Overlay
        safe_data = html.escape(data)
        
        if is_obfuscated:
            # Inject Forensic Markers for Blueprint 3
            # Defines the "Red Dashed" visual style in CSS
            marker_class = "forensic-ghost"
            if "White-on-White" in cause:
                marker_class += " forensic-contrast-fail"
            
            self.ghost_view_fragments.append(
                f'<span class="{marker_class}" title="HIDDEN via {cause}">{safe_data}</span>'
            )
        else:
            self.ghost_view_fragments.append(safe_data)

    def get_ghost_html(self) -> str:
        """Returns the fully reconstructed HTML with forensic markers."""
        return "".join(self.ghost_view_fragments)

# ===============================================
# BLOCK 7. THE AUDITORS (JUDGMENT LAYER)
# ===============================================

def audit_stage1_5_signals(signals):
    """
    [STAGE 1.5] Structural Profiler Engine.
    Converts raw forensic signals into high-fidelity structural flags.
    Focus: Observable Phenomena (Physics), not just Intent (Policy).
    """
    flags = {}
    
    # 1. Aggregate Signals by Type
    sig_map = {}
    for s in signals:
        t = s['type']
        if t not in sig_map: sig_map[t] = []
        sig_map[t].append(s)

    # --- 1. FRACTURE TOPOLOGY (Tokenization Physics) ---
    # Phenomenon: Non-standard characters embedded within alphanumeric tokens.
    if "TOKEN_FRACTURE" in sig_map:
        count = len(sig_map["TOKEN_FRACTURE"])
        
        # Analyze the 'Agent' distribution
        agents = collections.Counter()
        contexts = set()
        
        for s in sig_map["TOKEN_FRACTURE"]:
            agents[s.get('agent_type', 'Unknown')] += 1
            contexts.add(s.get('context_script', 'Unknown'))
            
        # Detailed Breakdown string
        breakdown = ", ".join([f"{k}: {v}" for k, v in agents.items()])
        
        key = f"CRITICAL: Token Fracture Topology ({breakdown})"
        flags[key] = {
            "count": count,
            "positions": [f"(Scripts: {', '.join(contexts)})"],
            "severity": "crit",
            "badge": "STRUCT"
        }

    # --- 2. VARIATION SELECTOR TOPOLOGY (Sequence Physics) ---
    # Phenomenon: VS characters appearing in non-standard clusters or isolation.
    
    # A. Orphaned VS (No Base)
    if "VS_BARE" in sig_map:
        bare_count = sum(s['count'] for s in sig_map["VS_BARE"])
        key = f"SUSPICIOUS: Orphaned Variation Selectors ({bare_count})"
        flags[key] = {
            "count": bare_count,
            "positions": ["(VS codepoint without valid base - Rendering Artifact)"],
            "severity": "warn",
            "badge": "SYNTAX"
        }

    # B. Redundant Clustering (The "Run" Metric)
    if "VS_CLUSTER" in sig_map:
        # Get the worst offender
        max_len = max(s['max_len'] for s in sig_map["VS_CLUSTER"])
        count = len(sig_map["VS_CLUSTER"])
        
        # Grading: >1 is technically redundant. >3 is structurally anomalous.
        if max_len >= 4:
            sev = "crit"
            badge = "DENSITY"
            label = f"CRITICAL: High-Density VS Sequence (Len: {max_len})"
        else:
            sev = "warn"
            badge = "REDUNDANT"
            label = f"HIGH: Redundant VS Sequence (Len: {max_len})"
        
        flags[label] = {
            "count": count,
            "positions": ["(Multiple VS per base char - Information Density Risk)"],
            "severity": sev,
            "badge": badge
        }

    # --- 3. PLANE 14 ANALYSIS (Hidden Channel Physics) ---
    # Phenomenon: Presence of Deprecated Tag Characters (U+E00xx).
    
    # A. Decoded Payload (High Fidelity)
    if "TAG_PAYLOAD" in sig_map:
        for s in sig_map["TAG_PAYLOAD"]:
            p_len = s['payload_len']
            preview = s['preview']
            
            key = f"CRITICAL: Plane 14 Tag Payload ({p_len} chars)"
            flags[key] = {
                "count": 1,
                "positions": [f"Reconstructed: '{_escape_html(preview)}'"],
                "severity": "crit",
                "badge": "CHANNEL"
            }
            
    # B. Raw Count (Fallback)
    elif "TAG_SEQUENCE" in sig_map:
        total_tags = sum(s['count'] for s in sig_map["TAG_SEQUENCE"])
        key = f"CRITICAL: Plane 14 Tag Characters ({total_tags})"
        flags[key] = {
            "count": total_tags,
            "positions": ["(Deprecated Format Characters Detected)"],
            "severity": "crit",
            "badge": "DEPRECATED"
        }

    # --- 4. DELIMITER MASKING (Visual/Logical Gap) ---
    # Phenomenon: Non-Standard Spacing adjacent to File Extension Syntax.
    if "MASKED_EXTENSION" in sig_map:
        count = len(sig_map["MASKED_EXTENSION"])
        key = "CRITICAL: Deceptive Delimiter Spacing"
        flags[key] = {
            "count": count,
            "positions": ["(Non-Standard Space preceding '.' operator)"],
            "severity": "crit",
            "badge": "MASKING"
        }

    # --- 5. INJECTION SIGNATURES (Syntax Physics) ---
    
    # A. ANSI Sequences
    if "ANSI_SEQUENCE" in sig_map:
        total_ansi = sum(s['count'] for s in sig_map["ANSI_SEQUENCE"])
        key = f"HIGH: ANSI Control Sequences ({total_ansi})"
        flags[key] = {
            "count": total_ansi,
            "positions": ["(Terminal Emulation Controls Detected)"],
            "severity": "crit",
            "badge": "CONTROL"
        }

    # B. Imperative Syntax (Override)
    has_override = "IMPERATIVE_OVERRIDE" in sig_map
    has_tool = "TOOL_CHAIN_PATTERN" in sig_map
    
    if has_override and has_tool:
        key = "CRITICAL: Imperative Tool-Use Sequence"
        flags[key] = {
            "count": 1,
            "positions": ["(Syntax: 'Ignore' + 'Use Tool' pattern)"],
            "severity": "crit",
            "badge": "SYNTAX"
        }
    elif has_override:
        key = "HIGH: Imperative Override Syntax"
        flags[key] = {
            "count": 1,
            "positions": ["(Syntax: Directive to ignore instructions)"],
            "severity": "warn",
            "badge": "SEMANTIC"
        }

    # --- 6. DOMAIN STRUCTURE (IDN Physics) ---
    
    # A. Pseudo-Delimiters
    if "PSEUDO_DELIMITER" in sig_map:
        artifacts = []
        for s in sig_map["PSEUDO_DELIMITER"]:
            artifacts.extend(s['artifacts'])
        
        key = "CRITICAL: Homoglyph Delimiters"
        flags[key] = {
            "count": len(artifacts),
            "positions": list(set(artifacts)),
            "severity": "crit",
            "badge": "SYNTAX"
        }

    # B. Script Mixing
    if "DOMAIN_MIXED_SCRIPTS" in sig_map:
        for s in sig_map["DOMAIN_MIXED_SCRIPTS"]:
            scripts = s['scripts']
            label = s['label']
            
            # Profiling Logic: Is this a high-entropy mix?
            is_complex = "Latin" in scripts and ("Cyrillic" in scripts or "Greek" in scripts)
            sev = "crit" if is_complex else "warn"
            badge = "COMPLEX" if is_complex else "MIXED"
            
            key = f"CRITICAL: Multi-Script Label ({', '.join(scripts)})" if is_complex else f"SUSPICIOUS: Mixed-Script Label"
            
            flags[key] = {
                "count": 1,
                "positions": [f"Label: '{label}'"],
                "severity": sev,
                "badge": badge
            }
            
    # C. Skeleton Collision
    if "DOMAIN_SKELETON_MATCH_ASCII" in sig_map:
        key = "HIGH: Skeleton Collision (ASCII)"
        flags[key] = {
            "count": len(sig_map["DOMAIN_SKELETON_MATCH_ASCII"]),
            "positions": ["(Non-ASCII text normalizes to valid ASCII string)"],
            "severity": "warn",
            "badge": "COLLISION"
        }

    # --- 7. APPLICATION CONTEXT (Lure Physics) ---
    
    # A. Markdown Exfiltration
    if "MARKDOWN_EXFIL" in sig_map:
        count = sum(s['count'] for s in sig_map["MARKDOWN_EXFIL"])
        key = "HIGH: Remote Image Inclusion (Markdown)"
        flags[key] = {
            "count": count,
            "positions": ["(External resource loading pattern)"],
            "severity": "warn",
            "badge": "REMOTE"
        }

    # B. Chat Template Injection
    if "CHAT_TEMPLATE_INJ" in sig_map:
        headers = []
        for s in sig_map["CHAT_TEMPLATE_INJ"]:
            headers.extend(s['headers'])
        unique = list(set(headers))
        
        key = f"CRITICAL: Chat Template Tokens ({len(unique)})"
        flags[key] = {
            "count": len(unique),
            "positions": [f"Tokens: {', '.join(unique)}"],
            "severity": "crit",
            "badge": "STRUCT"
        }

    # C. Memory Directives
    if "MEMORY_POISON" in sig_map:
        keywords = []
        for s in sig_map["MEMORY_POISON"]:
            keywords.extend(s['keywords'])
            
        key = "HIGH: Persistence Directives"
        flags[key] = {
            "count": len(keywords),
            "positions": [f"(Keywords: {', '.join(list(set(keywords))[:3])}...)"],
            "severity": "crit",
            "badge": "SEMANTIC"
        }

    return {"flags": flags}

def _evaluate_adversarial_risk(intermediate_data):
    """
    Block 2: The Risk Engine (Robust Version).
    Restores R11 Safety Net and implements Precision Fracture Scanning.
    """
    tokens = intermediate_data["tokens"]
    skeleton_map = intermediate_data["skeleton_map"]
    
    # --- A. Detect Skeleton Collisions ---
    collisions = []
    collision_skeletons = set()
    for skel, indices in skeleton_map.items():
        unique_texts = set(tokens[i]["text"] for i in indices)
        if len(unique_texts) > 1:
            collision_skeletons.add(skel)
            collisions.append({
                "skeleton": skel,
                "variants": list(unique_texts),
                "indices": indices,
                "risk": "CRITICAL"
            })

    # --- B. Per-Token Risk Assessment ---
    risk_stats = {"CRITICAL": 0, "HIGH": 0, "MED": 0, "LOW": 0}
    topology = {"SPOOFING": 0, "INJECTION": 0, "OBFUSCATION": 0, "PROTOCOL": 0, "HIDDEN": 0, "HOMOGLYPH": 0}
    targets = [] 

    for token in tokens:
        risk_level = 0 
        triggers = []
        token_topology_hits = set()
        detailed_stack = [] # Explicit visual stack
        
        t_str = token["text"]
        
        # --- Rule 0: Fracture Scanner (Precision Mode) ---
        if len(t_str) > 2:
            f_state = 0 # 0=Start, 1=Alpha, 2=Agent
            for fc in t_str:
                f_cp = ord(fc)
                f_is_alnum = fc.isalnum()
                f_is_agent = False
                
                # Check for Forensic Fracture Agent
                if f_cp < 1114112:
                    mask = INVIS_TABLE[f_cp]
                    if mask & (INVIS_ZERO_WIDTH_SPACING | INVIS_JOIN_CONTROL | INVIS_TAG | INVIS_BIDI_CONTROL):
                        f_is_agent = True
                    # Emoji check: Must be Emoji AND Not Alphanumeric
                    elif not f_is_alnum and (_find_in_ranges(f_cp, "Emoji") or _find_in_ranges(f_cp, "Extended_Pictographic")):
                        f_is_agent = True

                if f_state == 0:
                    if f_is_alnum: f_state = 1
                elif f_state == 1:
                    if f_is_agent: f_state = 2 # Found Agent
                    elif not f_is_alnum: f_state = 0 # Reset
                elif f_state == 2:
                    if f_is_alnum:
                        # TRIGGER: Alpha -> Agent -> Alpha
                        risk_level = max(risk_level, 3)
                        desc = "R99: Token Fracture (Mid-Token Injection)"
                        triggers.append(desc)
                        token_topology_hits.add("OBFUSCATION")
                        detailed_stack.append({"lvl": "CRITICAL", "type": "OBFUSCATION", "desc": desc})
                        break
                    elif not f_is_agent:
                        f_state = 0 # Reset

        # --- Rule 1: Skeleton Collisions ---
        if token["skeleton"] in collision_skeletons:
            risk_level = max(risk_level, 3)
            desc = "R30: Skeleton Collision (Homograph)"
            triggers.append(desc)
            token_topology_hits.add("HOMOGLYPH")
            detailed_stack.append({"lvl": "CRITICAL", "type": "HOMOGLYPH", "desc": desc})

        # --- Rule 2: Script Mixing ---
        if token["is_mixed"]:
            if token["kind"] in ("domain", "identifier", "email"):
                risk_level = max(risk_level, 2)
                desc = "R10: Mixed Scripts in ID/Domain"
                lvl_tag = "HIGH"
            else:
                risk_level = max(risk_level, 1)
                desc = "R01: Mixed Scripts"
                lvl_tag = "MED"
            triggers.append(desc)
            token_topology_hits.add("SPOOFING")
            detailed_stack.append({"lvl": lvl_tag, "type": "SPOOFING", "desc": desc})

        # --- Rule 3: Confusables ---
        if token["confusables"]["density"] > 0.5:
            risk_level = max(risk_level, 1)
            desc = "R02: High Confusable Density"
            triggers.append(desc)
            token_topology_hits.add("SPOOFING")
            detailed_stack.append({"lvl": "MED", "type": "SPOOFING", "desc": desc})
            
        # --- Rule 4: Identifier Status (Restored Safety Net) ---
        if token["id_status"] in ("Restricted", "Disallowed"):
            # SAFETY NET: Restricted is always at least HIGH risk
            risk_level = max(risk_level, 2)
            desc = f"R11: Identifier Status ({token['id_status']})"
            triggers.append(desc)
            token_topology_hits.add("PROTOCOL")
            detailed_stack.append({"lvl": "HIGH", "type": "PROTOCOL", "desc": desc})

        # --- Rule 5: Hidden Channels & Bidi ---
        if token["invisibles"] > 0:
            has_bidi = False
            for char in t_str:
                if INVIS_TABLE[ord(char)] & INVIS_BIDI_CONTROL:
                    has_bidi = True
                    break
            
            if has_bidi:
                risk_level = max(risk_level, 3)
                desc = "R12: Bidi Control in Token"
                lvl_tag = "CRITICAL"
                top_tag = "INJECTION"
            else:
                risk_level = max(risk_level, 2)
                desc = "R03: Hidden Characters"
                lvl_tag = "HIGH"
                top_tag = "OBFUSCATION"
                
            triggers.append(desc)
            token_topology_hits.add(top_tag)
            detailed_stack.append({"lvl": lvl_tag, "type": top_tag, "desc": desc})

        # Map numeric level to string
        final_risk = "LOW"
        if risk_level == 3: final_risk = "CRITICAL"
        elif risk_level == 2: final_risk = "HIGH"
        elif risk_level == 1: final_risk = "MED"
        
        token["risk"] = final_risk
        token["triggers"] = triggers
        risk_stats[final_risk] += 1

        for hit in token_topology_hits:
            topology[hit] += 1
            
        if risk_level >= 2:
            targets.append({
                "token": t_str,
                "verdict": triggers[0] if triggers else "High Risk",
                "stack": detailed_stack, # Use the explicitly built stack
                "score": risk_level * 25,
                "b64": "N/A", "hex": "N/A" 
            })

    return {
        "tokens": tokens,
        "collisions": collisions,
        "topology": topology,
        "targets": targets,
        "stats": {
            "total": len(tokens),
            "identifiers": sum(1 for t in tokens if t["kind"] == "identifier"),
            "domains": sum(1 for t in tokens if t["kind"] == "domain"),
            "high_risk": risk_stats["HIGH"] + risk_stats["CRITICAL"],
            "collisions": len(collisions)
        }
    }

def compute_integrity_score(inputs):
    """
    The Integrity Auditor.
    Calculates Data Health & Structural Entropy.
    Formula: Score = Base + (Count * Multiplier)
    """
    ledger = []
    
    def add_entry(vector, count, severity, base, mult):
        if count <= 0: return
        # Density Formula
        points = base + (count * mult)
        # Round to 1 decimal for neatness, or int if preferred
        points = int(round(points))
        ledger.append({
            "vector": vector,
            "count": count,
            "severity": severity,
            "points": points
        })

    # --- 1. FATAL (Data Death) ---
    add_entry("Data Corruption (U+FFFD)", inputs.get("fffd", 0), "FATAL", INT_BASE_FATAL, INT_MULT_FATAL)
    add_entry("Broken Encoding (Surrogates)", inputs.get("surrogate", 0), "FATAL", INT_BASE_FATAL, INT_MULT_FATAL)
    add_entry("Binary Injection (Null Bytes)", inputs.get("nul", 0), "FATAL", INT_BASE_FATAL, INT_MULT_FATAL)
    
    # --- 2. FRACTURE (Structural Breaks) ---
    # Logic Gate: If Bidi structure is broken, we flag it here.
    bidi_broken = inputs.get("bidi_broken_count", 0)
    has_bidi_fracture = False
    if bidi_broken > 0:
        has_bidi_fracture = True
        add_entry("Structural Fracture (Bidi)", bidi_broken, "FRACTURE", INT_BASE_FRACTURE, INT_MULT_FRACTURE)

    add_entry("Broken Keycap Sequence", inputs.get("broken_keycap", 0), "FRACTURE", INT_BASE_FRACTURE, INT_MULT_FRACTURE)
    add_entry("Marks on Non-Visual Base", inputs.get("hidden_marks", 0), "FRACTURE", INT_BASE_FRACTURE, INT_MULT_FRACTURE)

    # --- 3. RISK (Protocol Violations) ---
    add_entry("Plane 14 Tags", inputs.get("tags", 0), "RISK", INT_BASE_RISK, INT_MULT_RISK)
    add_entry("Noncharacters", inputs.get("nonchar", 0), "RISK", INT_BASE_RISK, INT_MULT_RISK)
    add_entry("Invalid Variation Selectors", inputs.get("invalid_vs", 0), "RISK", INT_BASE_RISK, INT_MULT_RISK)
    add_entry("Do-Not-Emit Characters", inputs.get("donotemit", 0), "RISK", INT_BASE_RISK, INT_MULT_RISK)
    
    # Logic Gate: Cluster Containment
    # We charge for the cluster, not the atoms inside, to avoid double-counting generic invisibles
    cluster_len = inputs.get("max_cluster_len", 0)
    if cluster_len > 4:
        # Treat massive clusters as a RISK/FRACTURE hybrid
        add_entry(f"Massive Invisible Cluster (Max={cluster_len})", 1, "RISK", INT_BASE_RISK, INT_MULT_RISK)

    # --- 4. DECAY (Hygiene) ---
    add_entry("Internal BOM", inputs.get("bom", 0), "DECAY", INT_BASE_DECAY, INT_MULT_DECAY)
    add_entry("Private Use Area (PUA)", inputs.get("pua", 0), "DECAY", INT_BASE_DECAY, INT_MULT_DECAY)
    add_entry("Legacy Control Chars", inputs.get("legacy_ctrl", 0), "DECAY", INT_BASE_DECAY, INT_MULT_DECAY)
    add_entry("Deceptive Spaces", inputs.get("dec_space", 0), "DECAY", INT_BASE_DECAY, INT_MULT_DECAY)
    
    if inputs.get("not_nfc"):
        add_entry("Normalization Drift (Not NFC)", 1, "DECAY", 1, 0) # Fixed low cost

    # Logic Gate: Exclusive Diagnosis for Bidi
    # If we have a Fracture, we don't charge for "Bidi Controls Present" in the Hygiene tier.
    if not has_bidi_fracture:
        add_entry("Bidi Controls Present", inputs.get("bidi_present", 0), "DECAY", INT_BASE_DECAY, INT_MULT_DECAY)

    # --- SCORE & VERDICT ---
    total_score = sum(item["points"] for item in ledger)
    
    verdict = "HEALTHY"
    severity_class = "ok"
    
    if total_score >= 70:
        verdict = "CORRUPT"
        severity_class = "crit"
    elif total_score >= 40:
        verdict = "FRACTURED"
        severity_class = "crit"
    elif total_score >= 20:
        verdict = "RISKY"
        severity_class = "warn"
    elif total_score >= 1:
        verdict = "DECAYING"
        severity_class = "warn"

    return {
        "score": total_score,
        "verdict": verdict,
        "severity_class": severity_class,
        "ledger": ledger
    }

def compute_threat_score(inputs):
    """
    The Threat Auditor (Maximal Forensic Logic).
    Calculates Weaponization & Malice with Context-Aware Weighting.
    
    Principles:
    1. Clean Room: Strictly excludes 'Rot' (Integrity issues).
    2. Zero-Redundancy: Prevents double-counting of related vectors.
    3. Multi-Vector Boost: Increases score if attacks span multiple pillars.
    """
    ledger = []
    
    def add_entry(vector, points, category):
        ledger.append({"vector": vector, "points": int(points), "category": category})

    # --- PILLAR 1: EXECUTION (Target: Machine / Compiler) ---
    # Severity: FATAL. One hit here is usually enough to Weaponize.
    
    has_execution_threat = False
    
    # [NEW] WAF / Payload Heuristics (Module 4)
    # The WAF Simulator returns a raw risk score (0-100). We trust it.
    waf_score = inputs.get("waf_score", 0)
    if waf_score > 0:
        add_entry(f"Payload Detected (WAF Pattern)", waf_score, "EXECUTION")
        has_execution_threat = True

    # [NEW] Normalization Injection (Syntax Predator)
    # This is a confirmed CVE vector (U+FF07 -> '). 
    norm_inj_count = inputs.get("norm_injection_count", 0)
    if norm_inj_count > 0:
        # High base penalty + density charge
        pts = THR_BASE_EXECUTION + (norm_inj_count * 5)
        add_entry(f"Normalization-Activated Injection (x{norm_inj_count})", pts, "EXECUTION")
        has_execution_threat = True

    # [NEW] Logic Bypass / Case Collision (Shapeshifter)
    # Detects Dotless-i / Long-S attacks on logic
    logic_bypass_count = inputs.get("logic_bypass_count", 0)
    if logic_bypass_count > 0:
        add_entry("Logic Bypass Vector (Case Collision)", THR_BASE_EXECUTION, "EXECUTION")
        has_execution_threat = True

    # Trojan Source (Bidi Syntax Attack)
    # Critical distinction: Must be Override/Embedding, not just Isolates.
    if inputs.get("malicious_bidi"):
        add_entry("Trojan Source (Malicious Bidi)", THR_BASE_EXECUTION, "EXECUTION")
        has_execution_threat = True
        
    # Syntax Spoofing (Unicode 17.0)
    # Variation Selector attached to operators/syntax (e.g. `+` + VS1)
    if inputs.get("suspicious_syntax_vs"):
        add_entry("Syntax Spoofing (VS on Operator)", THR_BASE_EXECUTION, "EXECUTION")
        has_execution_threat = True

    # --- PILLAR 2: SPOOFING (Target: Human / ID) ---
    # Severity: HIGH. Can lead to Phishing or Identity Theft.
    
    # Cross-Script Homoglyphs (The Classic)
    drift_cross = inputs.get("drift_cross_script", 0)
    if drift_cross > 0:
        # Saturation Logic: 
        # Base (25) + 1pt per char, capped at +25 extra. 
        # Prevents 1000 homoglyphs from scoring 1000 points.
        density_bonus = min(drift_cross, 25) * THR_MULT_SPOOFING
        total_pts = THR_BASE_SPOOFING + density_bonus
        add_entry(f"Cross-Script Homoglyphs ({drift_cross})", total_pts, "SPOOFING")

    # Mixed Scripts (Ontology Check)
    mix_class = inputs.get("script_mix_class", "")
    if "Highly Mixed" in mix_class:
        # If we already have Homoglyphs, this is redundant context, but valid.
        # We charge a lower 'Obfuscation' fee if purely structural.
        add_entry(mix_class, THR_BASE_OBFUSCATION, "SPOOFING")
    elif "Mixed Scripts (Base)" in mix_class:
        add_entry(mix_class, THR_BASE_SUSPICIOUS, "SUSPICIOUS")

    # --- PILLAR 3: OBFUSCATION (Target: Filter / Scanner) ---
    # Severity: MEDIUM/HIGH. Used to hide payloads or bypass AI safety.
    
    # Massive Clusters (Invisible Walls)
    cluster_len = inputs.get("max_invis_run", 0)
    cluster_count = inputs.get("invis_cluster_count", 0)
    rgi_count = inputs.get("rgi_count", 0)
    
    # Smart Filter: Is this just broken Emoji glue?
    is_likely_emoji_glue = (rgi_count > 0 and cluster_len <= 2 and cluster_count <= (rgi_count * 3))
    
    if cluster_len > 4:
        # Logic: Massive contiguous run is almost certainly malicious/stego
        add_entry(f"Massive Invisible Cluster (len={cluster_len})", THR_BASE_OBFUSCATION, "OBFUSCATION")
    elif cluster_count > 0 and not is_likely_emoji_glue:
         # If not Emoji glue and not Trojan Source (already charged), charge for Obfuscation
         if not inputs.get("malicious_bidi"):
             pts = THR_BASE_OBFUSCATION + min(cluster_count, 10) * THR_MULT_OBFUSCATION
             add_entry(f"Invisible Clusters ({cluster_count})", pts, "OBFUSCATION")

    # Plane 14 Tags (Steganography / AI Jailbreak)
    tags = inputs.get("tags_count", 0)
    if tags > 0:
        # Tags are illegal in almost all protocols. High penalty.
        add_entry(f"Plane 14 Tags ({tags})", THR_BASE_OBFUSCATION + 10, "OBFUSCATION")

    # Forced Presentation (VS15/VS16 Abuse)
    forced_pres = inputs.get("forced_pres_count", 0)
    if forced_pres > 0:
        add_entry(f"Forced Presentation (VS15/VS16)", 5, "SUSPICIOUS") # Low, often just artifacts
        
    # --- 4. SUSPICIOUS CONTEXT (Tier 4) ---
    # Unclosed Bidi (Sloppy) - Only charge if we didn't charge for Malicious Bidi
    if inputs.get("has_unclosed_bidi") and not inputs.get("malicious_bidi"):
        add_entry("Unclosed Bidi Sequence", THR_BASE_SUSPICIOUS, "SUSPICIOUS")

    # --- 5. SCORE SYNTHESIS ---
    total_score = sum(item["points"] for item in ledger)
    
    # Multi-Vector Boost (The "Smart" Logic)
    # If we have Execution AND Spoofing/Obfuscation, it's a coordinated attack.
    categories = {item["category"] for item in ledger}
    if "EXECUTION" in categories and len(categories) > 1:
        boost = 10
        total_score += boost
        add_entry("Multi-Vector Correlation (Execution + Other)", boost, "CORRELATION")

    # --- VERDICT DETERMINATION ---
    verdict = "CLEAN"
    severity_class = "ok"
    
    if total_score >= 40:
        verdict = "WEAPONIZED"
        severity_class = "crit"
    elif total_score >= 15:
        verdict = "HIGH RISK"
        severity_class = "crit" # High Risk is functionally critical
    elif total_score >= 1:
        verdict = "SUSPICIOUS"
        severity_class = "warn"

    return {
        "score": total_score,
        "verdict": verdict,
        "severity_class": severity_class,
        "ledger": ledger,
        "noise": inputs.get("noise_list", []) 
    }

# BLOCK 7 EXTENSION: THE MASTER AUDITORS

def compute_authenticity_score(inputs, threat_ledger, stage1_5_data):
    """
    The Authenticity Auditor (Identity / Spoofing).
    Derives its score from Threat Ledger (Spoofing category),
    Stage 1.5 Topology (Homoglyphs), and IDNA inputs.
    """
    score = 0
    vectors = []
    
    # 1. Extract Spoofing vectors from the main Threat calculation
    # This ensures consistency with the detailed list
    for entry in threat_ledger:
        if entry["category"] == "SPOOFING":
            score += entry["points"]
            vectors.append(entry["vector"])
            
    # 2. Add IDNA violations (if not already covered)
    idna_violations = inputs.get("idna_violations", 0)
    if idna_violations > 0:
        score += 20
        vectors.append(f"IDNA Violations ({idna_violations})")
        
    # 3. Add Stage 1.5 Topology (Homoglyphs)
    # The 'topology' dict counts hits for 'HOMOGLYPH'
    topology = stage1_5_data.get("topology", {})
    homoglyphs = topology.get("HOMOGLYPH", 0)
    if homoglyphs > 0:
        # We don't double count if it's already in threat_ledger, 
        # but Stage 1.5 adds precision for Skeleton Collisions
        score += (homoglyphs * 10)
        vectors.append(f"Skeleton Collisions ({homoglyphs})")

    verdict = "SAFE"
    severity = "ok"
    # Thresholds aligned with Authenticity concerns
    if score >= 30: verdict, severity = "SPOOFED", "crit"
    elif score >= 1: verdict, severity = "SUSPECT", "warn"
    
    return {
        "score": score,
        "verdict": verdict,
        "severity_class": severity,
        "vector_count": len(vectors),
        "vectors": vectors
    }

def compute_anomaly_score(stats):
    """
    Calculates the Anomaly (Physics) Score.
    Patched to enforce ADR-008: Zalgo is always a Hazard.
    """
    score = 0
    vectors = []

    # 1. Physics: Entropy (The "Dust")
    entropy = stats.get('entropy', 0.0)
    if entropy > 6.5:
        score += 15
        vectors.append(f"High Entropy ({entropy})")

    # 2. Physics: Zalgo (The "Hazard")
    # FIX: Zalgo always carries a penalty (Rendering Risk)
    zalgo_data = stats.get('zalgo', {})
    z_count = zalgo_data.get('count', 0)

    if z_count > 0:
        # Base penalty (20) + density penalty (5 per cluster)
        # Example: 7 clusters = 20 + 35 = 55 points (UNSTABLE / Warn)
        z_pen = 20 + (z_count * 5)
        score += z_pen
        vectors.append(f"Zalgo Clusters (x{z_count})")

    # Verdict Calibration
    verdict = "NORMAL"
    severity_class = "ok"

    if score > 0:
        if score < 40:
            verdict = "DEVIANT"
            severity_class = "warn" # Amber
        elif score < 70:
            verdict = "UNSTABLE"
            severity_class = "warn" # Amber (Orange in HUD)
        else:
            verdict = "ANOMALOUS"
            severity_class = "crit" # Red

    return {
        "score": min(100, score),
        "verdict": verdict,
        "severity_class": severity_class,
        "val": entropy,
        "vectors": vectors
    }

def audit_master_ledgers(inputs, stats_inputs, stage1_5_data, threat_output):
    """
    The Master Auditor (V2.1 - Hardened).
    Aggregates Integrity, Threat, Authenticity, and Anomaly ledgers.
    """
    # 1. INTEGRITY (The Rot)
    integrity = compute_integrity_score(inputs)
    
    decode_status = "OK"
    if inputs.get("fffd", 0) > 0 or inputs.get("nul", 0) > 0:
        decode_status = "CRITICAL"
    elif inputs.get("surrogate", 0) > 0:
        decode_status = "WARNING"
    
    # 2. THREAT (The Malice)
    targets = stage1_5_data.get("targets", [])
    peak_score = 0
    if targets:
        peak_score = max(t["score"] for t in targets)

    # 3. AUTHENTICITY (The Identity)
    # Fallback logic to find the ledger in nested structures
    t_ledger = threat_output.get("ledger", []) 
    if not t_ledger:
        t_ledger = threat_output.get("flags", {}).get("Threat Level (Heuristic)", {}).get("ledger", [])

    auth = compute_authenticity_score(inputs, t_ledger, stage1_5_data)
    
    # 4. ANOMALY (The Physics)
    # [DEPENDENCY]: Requires patched compute_anomaly_score that penalizes Zalgo
    anomaly = compute_anomaly_score(stats_inputs)
    
    # [SAFETY] Ensure severity class exists
    anom_sev = anomaly.get("severity_class")
    if not anom_sev:
        anom_sev = "warn" if anomaly["score"] > 0 else "ok"

    return {
        "integrity": {
            "verdict": integrity["verdict"],
            "score": integrity["score"],
            "severity": integrity["severity_class"],
            "decode_status": decode_status,
            "issues": len(integrity["ledger"]),
            "ledger": integrity["ledger"]
        },
        "authenticity": {
            "verdict": auth["verdict"],
            "score": auth["score"],
            "severity": auth["severity_class"],
            "vector_count": auth["vector_count"],
            "vectors": auth["vectors"] 
        },
        "threat": {
            "verdict": threat_output["verdict"],
            "score": threat_output["score"],
            "severity": threat_output["severity_class"],
            "peak_score": peak_score,
            "signals": len(threat_output["ledger"]),
            "ledger": threat_output["ledger"] 
        },
        "anomaly": {
            "verdict": anomaly["verdict"],
            "score": anomaly["score"],
            "severity": anom_sev,
            # Source truth from stats_inputs to avoid KeyError
            "entropy": stats_inputs.get("entropy", 0.0),
            "vectors": anomaly.get("vectors", [])
        }
    }

def _map_cause_to_vector_category(cause: str) -> str:
    """
    [HELPER] Normalizes specific CSS rules into Abstract Hiding Vectors.
    Used to calculate the 'Polymorphism' score.
    
    Example: 'display:none' and 'visibility:hidden' -> 'LAYOUT_SUPPRESSION'
    """
    c = cause.lower()
    
    # Vector 1: Layout Suppression (Hard Hiding)
    if "display" in c or "visibility" in c or "hidden" in c:
        return "LAYOUT_SUPPRESSION"
        
    # Vector 2: Geometric Collapse (Zero Size)
    if "width" in c or "height" in c or "font-size" in c or "scale" in c:
        return "GEOMETRIC_COLLAPSE"
        
    # Vector 3: Coordinate Displacement (Off-Screen)
    if "left" in c or "text-indent" in c or "position" in c or "absolute" in c:
        return "COORDINATE_DISPLACEMENT"
        
    # Vector 4: Photometric Hiding (Invisible Ink)
    if "opacity" in c or "color" in c or "contrast" in c or "transparent" in c:
        return "PHOTOMETRIC_HIDING"
        
    # Vector 5: Viewport Clipping (Masking)
    if "clip" in c or "mask" in c:
        return "VIEWPORT_CLIPPING"
        
    return "UNKNOWN_VECTOR"


def _audit_metadata_findings(raw_findings: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    [STAGE 1.5] The Master Auditor for Metadata.
    
    Implements the FIS (Forensic Impact & Sophistication) Model:
    Score = (BaseSeverity * VectorPolymorphism * NestingDepth) + PayloadOverrides
    
    Returns:
        1. Audited Findings (Enriched with Verdicts and Badges)
        2. The Forensic Ledger (Structured score data for the HUD)
    """
    audited_results = []
    
    # 1. Topology Counters
    topology = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "INFO": 0}
    
    # 2. Sophistication Trackers
    active_vectors = set()  # Track unique abstract vectors (e.g., GEOMETRY vs LAYOUT)
    max_lineage_depth = 0   # Track deepest obfuscation nesting
    
    # 3. Kill Switches
    has_fatal_payload = False
    fatal_reason = None
    
    for f in raw_findings:
        # --- A. INITIAL CLASSIFICATION (Policy Application) ---
        risk = "HIGH" 
        verdict = "Obfuscated Content"
        badge = "OBFUSCATION"
        
        content_lower = f['content'].lower()
        classes = set(f['context_classes'])
        cause = f['cause']
        lineage_depth = len(f.get('lineage', []))
        max_lineage_depth = max(max_lineage_depth, lineage_depth)
        
        # POLICY 1: ACCESSIBILITY WHITELIST CHECK
        is_a11y_class = not classes.isdisjoint(METADATA_POLICY.A11Y_CLASS_WHITELIST)
        
        if is_a11y_class:
            # Sub-Policy: Payload Injection (The Poisoned Apple)
            payload_trigger = next((t for t in METADATA_POLICY.PAYLOAD_KEYWORDS if t in content_lower), None)
            
            if payload_trigger:
                risk = "CRITICAL"
                verdict = f"Injection in A11Y Wrapper ('{payload_trigger}')"
                badge = "INJECTION"
                has_fatal_payload = True
                fatal_reason = "PAYLOAD_IN_A11Y"
            
            # Sub-Policy: Safe Vocabulary (The Good Citizen)
            elif any(safe in content_lower for safe in METADATA_POLICY.A11Y_SAFE_VOCAB):
                risk = "INFO"
                verdict = "Screen Reader Text"
                badge = "ACCESSIBILITY"
            
            # Sub-Policy: Ambiguity (The Unknown)
            else:
                risk = "MEDIUM"
                verdict = "Hidden Text (A11Y Class)"
                badge = "REVIEW"

        # POLICY 2: BLACK HAT PATTERNS
        elif "Zero Contrast" in cause or "White-on-White" in cause:
            risk = "HIGH"
            verdict = "White-on-White (SEO/Spam)"
            badge = "SPAM"
            
        elif "font-size" in cause and "0" in cause:
            risk = "HIGH"
            verdict = "Micro-Typography (SEO)"
            badge = "SPAM"

        # POLICY 3: PAYLOAD SCANNING (Global)
        else:
            payload_trigger = next((t for t in METADATA_POLICY.PAYLOAD_KEYWORDS if t in content_lower), None)
            if payload_trigger:
                risk = "CRITICAL"
                verdict = f"Hidden Payload ('{payload_trigger}')"
                badge = "THREAT"
                has_fatal_payload = True
                fatal_reason = "HIDDEN_PAYLOAD"

        # --- B. SOPHISTICATION TRACKING ---
        # Only track vectors for actual threats (High/Critical), not A11Y info
        if risk in {"CRITICAL", "HIGH"}:
            vector_category = _map_cause_to_vector_category(cause)
            active_vectors.add(vector_category)

        # --- C. ENRICHMENT ---
        f['severity'] = risk
        f['verdict'] = verdict
        f['badge'] = badge
        f['vector_category'] = _map_cause_to_vector_category(cause) # For UI tooltip
        
        topology[risk] += 1
        audited_results.append(f)

    # --- D. FIS SCORING ENGINE (Forensic Impact & Sophistication) ---
    
    # 1. Base Impact Score (CVSS-style weighted sum)
    base_score = (
        (topology["CRITICAL"] * METADATA_SCORING_CONFIG.W_CRITICAL) +
        (topology["HIGH"]     * METADATA_SCORING_CONFIG.W_HIGH) +
        (topology["MEDIUM"]   * METADATA_SCORING_CONFIG.W_MEDIUM)
    )
    
    # 2. Sophistication Multiplier (Polymorphism)
    # Rationale: Mixing 'Opacity' and 'Clipping' is harder to detect than just 'Opacity'.
    # 2+ Categories = 1.5x | 4+ Categories = 2.2x
    poly_factor = 1.0
    if len(active_vectors) >= 4:
        poly_factor = METADATA_SCORING_CONFIG.POLYMORPHIC_FACTOR
    elif len(active_vectors) >= 2:
        poly_factor = METADATA_SCORING_CONFIG.MULTI_VECTOR_FACTOR
        
    # 3. Nesting Multiplier (Defense in Depth)
    # Rationale: Hiding content 10 levels deep is an evasion technique against shallow parsers.
    nest_factor = 1.0
    if max_lineage_depth >= METADATA_SCORING_CONFIG.NESTING_PENALTY_THRESHOLD:
        nest_factor = METADATA_SCORING_CONFIG.NESTING_FACTOR
        
    # 4. Final Calculation
    final_score = base_score * poly_factor * nest_factor
    
    # 5. Overrides & Clamping
    if has_fatal_payload:
        final_score = METADATA_SCORING_CONFIG.MAX_SCORE
        
    final_score = int(min(final_score, METADATA_SCORING_CONFIG.MAX_SCORE))
    
    # --- E. GENERATE LEDGER ---
    ledger = {
        "score": final_score,
        "grade": _get_risk_grade(final_score),
        "topology": topology,
        "vectors": list(active_vectors), # List of strings e.g., ["PHOTOMETRIC_HIDING", "GEOMETRIC_COLLAPSE"]
        "stats": {
            "is_polymorphic": len(active_vectors) >= 2,
            "max_depth": max_lineage_depth,
            "has_payload": has_fatal_payload,
            "fatal_reason": fatal_reason
        }
    }
    
    return audited_results, ledger

def _get_risk_grade(score: int) -> str:
    """Maps FIS Score to Forensic Verdict."""
    if score >= 90: return "CRITICAL"
    if score >= 50: return "SUSPICIOUS"
    if score >= 20: return "ANOMALOUS"
    if score > 0:   return "NON-STANDARD"
    return "CLEAN"

# ===============================================
# BLOCK 8. ORCHESTRATION (CONTROLLER)
# ===============================================

# Basic & Shape Orchestrators

def compute_emoji_analysis(text: str) -> dict:
    """
    Forensic Cluster Classifier (V3.5 - Interactive Registry Fix).
    1. UNIFIED ATOMIC LOGIC: Captures all hybrids (e.g. Skull).
    2. REGISTRY POPULATION: Explicitly logs hits for 'emoji_irregular' to enable the HUD Stepper.
    3. SYNCS indices using manual Python counter.
    """
    # --- 1. Data Access ---
    rgi_set = DATA_STORES.get("RGISequenceSet", set())
    qual_map = DATA_STORES.get("EmojiQualificationMap", {})
    
    # --- 2. Init Counters (The "Ledger") ---
    counts = {
        "total_emoji_units": 0,
        "rgi_total": 0,
        "non_rgi_total": 0,
        "text_symbols_extended": 0,
        "text_symbols_exotic": 0,
        "hybrid_pictographs": 0, 
        "hybrid_ambiguous": 0,   
        "rgi_atomic": 0,
        "rgi_sequence": 0,
        "emoji_irregular": 0,    
        "components_leaked": 0
    }
    
    emoji_details_list = []
    flags = {} 
    
    def add_flag(key, idx):
        if key not in flags: flags[key] = {'count': 0, 'positions': []}
        flags[key]['count'] += 1
        flags[key]['positions'].append(f"#{idx}")

    if not text:
        return {"counts": counts, "flags": flags, "emoji_list": []}

    # --- 3. Cluster Segmentation Loop ---
    segments_iter = GRAPHEME_SEGMENTER.segment(text)
    
    # [SYNC FIX] Manual Python Index Counter
    current_python_idx = 0
    
    for seg in segments_iter:
        cluster = seg.segment
        idx = current_python_idx # Use manual counter
        
        # Calculate lengths
        cp_len = len(cluster) 
        base_char = cluster[0]
        base_cp = ord(base_char)
        
        # --- A. Property Lookup ---
        is_rgi = cluster in rgi_set
        
        # Base Properties
        is_emoji = _find_in_ranges(base_cp, "Emoji")
        is_ext_pict = _find_in_ranges(base_cp, "Extended_Pictographic")
        is_emoji_pres = _find_in_ranges(base_cp, "Emoji_Presentation")
        is_component = _find_in_ranges(base_cp, "Emoji_Component")
        base_cat = unicodedata.category(base_char)
        
        # --- B. Primary Classification ---
        kind = "other"
        status = "none"
        rgi_status = False
        
        # 1. RGI Emoji (Highest Priority)
        if is_rgi:
            rgi_status = True
            status = qual_map.get(cluster, "fully-qualified")
            kind = "emoji-sequence" if cp_len > 1 else "emoji-atomic"
            
        # 2. Non-RGI Emoji-Like
        elif is_emoji or is_ext_pict:
            rgi_status = False
            if base_cp <= 0x7F: pass 
            elif is_component: 
                kind = "emoji-component"
                status = "component"
            elif cp_len > 1:
                kind = "emoji-sequence"
                status = "unqualified" 
            else:
                kind = "emoji-atomic"
                status = "unqualified"
                
        # 3. Text Symbols (Non-Emoji S*)
        elif base_cat.startswith("S"):
            kind = "text-symbol"
            
        # --- C. Updates & Aggregation ---
        
        # [HUD C5] Text Symbols
        if kind == "text-symbol":
            if base_cp <= 0xFF or (0x2000 <= base_cp <= 0x29FF):
                counts["text_symbols_extended"] += 1
            else:
                if base_cp != 0xFFFD:
                    counts["text_symbols_exotic"] += 1
                    _register_hit("sym_exotic", idx, idx + cp_len, f"Exotic Symbol (U+{base_cp:04X})")

        # [HUD C6 & C7] Atomic Emoji
        elif kind == "emoji-atomic":
            counts["total_emoji_units"] += 1
            
            if rgi_status:
                counts["rgi_total"] += 1
                counts["rgi_atomic"] += 1
                if status != "fully-qualified": 
                    counts["emoji_irregular"] += 1
                    # [INTERACTION FIX] Register Hit
                    _register_hit("emoji_irregular", idx, idx + cp_len, f"Unqualified RGI")
            else:
                counts["non_rgi_total"] += 1
                counts["emoji_irregular"] += 1
                # [INTERACTION FIX] Register Hit
                _register_hit("emoji_irregular", idx, idx + cp_len, f"Non-RGI Atom")
            
            # Sub-logic: Hybrids
            if base_cat.startswith("S") and not rgi_status:
                counts["hybrid_pictographs"] += 1
                has_vs16 = "\uFE0F" in cluster
                if not is_emoji_pres and not has_vs16:
                    counts["hybrid_ambiguous"] += 1
                    _register_hit("emoji_hybrid", idx, idx + cp_len, "Ambiguous Hybrid")

        # [HUD C7] Sequences
        elif kind == "emoji-sequence":
            counts["total_emoji_units"] += 1
            if rgi_status:
                counts["rgi_total"] += 1
                counts["rgi_sequence"] += 1
                if status != "fully-qualified": 
                    counts["emoji_irregular"] += 1
                    # [INTERACTION FIX] Register Hit
                    _register_hit("emoji_irregular", idx, idx + cp_len, "Unqualified Sequence")
            else:
                counts["non_rgi_total"] += 1
                counts["emoji_irregular"] += 1
                # [INTERACTION FIX] Register Hit
                _register_hit("emoji_irregular", idx, idx + cp_len, "Non-RGI Sequence")

        # [HUD C7 Irregular] Components
        elif kind == "emoji-component":
            counts["total_emoji_units"] += 1
            counts["non_rgi_total"] += 1
            counts["components_leaked"] += 1
            counts["emoji_irregular"] += 1
            # [INTERACTION FIX] Register Hit
            _register_hit("emoji_irregular", idx, idx + cp_len, "Leaked Component")
            
            add_flag("Flag: Standalone Emoji Component", idx)

        # --- D. Flag Generation ---
        
        if "\u20E3" in cluster:
            if base_cp not in VALID_KEYCAP_BASES:
                add_flag("Flag: Broken Keycap Sequence", idx)

        if 0x1F1E6 <= base_cp <= 0x1F1FF:
             if cp_len == 1: 
                 add_flag("Flag: Invalid Regional Indicator", idx)
             elif cp_len == 2 and 0x1F1E6 <= ord(cluster[1]) <= 0x1F1FF:
                 if not rgi_status:
                     add_flag("Flag: Invalid Regional Indicator", idx)

        if status == "unqualified":
            if is_emoji_pres or cp_len > 1:
                add_flag("Flag: Unqualified Emoji", idx)
        
        if status == "minimally-qualified": 
            add_flag("Flag: Minimally-Qualified Emoji", idx)
        
        if cp_len == 2:
            if cluster[1] == "\uFE0E": add_flag("Flag: Forced Text Presentation", idx)
            elif cluster[1] == "\uFE0F" and not is_emoji_pres: add_flag("Flag: Forced Emoji Presentation", idx)

        if kind.startswith("emoji"):
            emoji_details_list.append({
                "sequence": cluster,
                "kind": kind,
                "rgi": rgi_status,
                "status": status,
                "base_cat": base_cat, 
                "index": idx
            })

        # [SYNC FIX] Advance Python Index
        current_python_idx += cp_len

    return {
        "counts": counts,
        "flags": flags,
        "emoji_list": emoji_details_list
    }

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
            "pct": round((ascii_count / (total_code_points + epsilon)) * 100, 1),
            "is_full": ascii_count == total_code_points and total_code_points > 0
        },
        "Latin-1-Compatible": {
            "count": latin1_count,
            "pct": round((latin1_count / (total_code_points + epsilon)) * 100, 1),
            "is_full": latin1_count == total_code_points and total_code_points > 0
        },
        "BMP Coverage": {
            "count": bmp_count,
            "pct": round((bmp_count / (total_code_points + epsilon)) * 100, 1),
            "is_full": supplementary_count == 0 and total_code_points > 0
        },
        "Supplementary Planes": {
            "count": supplementary_count,
            "pct": round((supplementary_count / (total_code_points + epsilon)) * 100, 1),
            "is_full": False # This badge doesn't make sense here
        }
    }

    # [Forensic Metric Pack]
    # Calculate Storage & Runtime realities using the helper
    storage_metrics = _compute_storage_metrics(t, supplementary_count)
    
   # We get the count directly from the emoji engine's report
    emoji_total_count = emoji_counts.get("RGI Emoji Sequences", 0)
    
    _, whitespace_count = _find_matches_with_indices("Whitespace", t)

    # [NEW] Populate HUD Registry for Non-Std Whitespace
    # We need to scan specifically for Non-ASCII whitespace
    ns_indices, _ = _find_matches_with_indices("Whitespace", t)
    for idx in ns_indices:
        # Check if it's 0x20 or control chars
        # Since regex \p{White_Space} includes 0x20, we filter.
        # Note: We need the char at idx to check value.
        # matchAll gives indices.
        # This is slightly expensive to re-check, but robust.
        # Easier: Just scan string once for specific HUD buckets.
        pass
    
    derived_stats = {
        "Total Code Points": total_code_points,
        "RGI Emoji Sequences": emoji_total_count,
        "Whitespace (Total)": whitespace_count,
        **storage_metrics # Merge in UTF-16, UTF-8, Astral
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
    
    # [NEW] NFC Stability Tracker
    # We track graphemes that are physically different from their NFC form.
    # This detects "Decomposed" characters (e.g. e + ´ instead of é).
    non_nfc_indices = []

    # [SYNC FIX] Manual Python Index for Reporting
    current_python_idx = 0

    for segment in segments:
        grapheme_str = segment.segment
        if not grapheme_str:
            continue
            
        # --- [NEW] NFC Check ---
        # If the grapheme changes when normalized to NFC, it is "Unstable"
        if grapheme_str != unicodedata.normalize("NFC", grapheme_str):
            non_nfc_indices.append(f"#{current_python_idx}")
        
        # --- Module 1.5 Logic (Forensics) ---
        cp_array = window.Array.from_(grapheme_str)
        cp_count = len(cp_array)
        
        # Advance index for next loop (Must happen after using current_python_idx but before next iteration)
        # Note: We calculate cp_count first, then use it to increment AFTER the NFC check.
        
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

        # Advance index for the next grapheme
        current_python_idx += cp_count

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

    # [NEW] Segmentation Complexity Verdict (Zalgo / Grapheme Complexity)
    # Ref: UTR #36 "Grapheme Cluster Security"
    seg_verdict = "LOW"
    seg_reason = "Simple clusters."
    seg_class = "badge-ok"

    if total_graphemes >= 3: # Ignore microscopic samples
        # Thresholds (Conservative / Latin-Centric Default)
        # Note: Non-Latin scripts (Thai, Tibetan) naturally use more marks. 
        # A truly script-aware engine would relax this if 'Latin' is not dominant.
        high_max, high_avg = 5, 0.8
        med_max, med_avg = 2, 0.2

        if max_marks >= high_max or avg_marks >= high_avg:
            seg_verdict = "HIGH (Zalgo)"
            seg_reason = "Stacking Abuse Detected (Rendering Instability Risk)"
            seg_class = "badge-crit"
        elif max_marks >= med_max or avg_marks >= med_avg:
            seg_verdict = "MED (Complex)"
            seg_reason = "Complex Clusters (Emoji Sequences or Heavy Diacritics)"
            seg_class = "badge-warn"
    
    grapheme_forensic_stats = {
        "Single-Code-Point": single_cp_count,
        "Multi-Code-Point": multi_cp_count,
        "Total Combining Marks": total_mark_count,
        "Max Marks in one Grapheme": max_marks,
        "Avg. Marks per Grapheme": round(avg_marks, 2),
        "seg_verdict": seg_verdict,
        "seg_reason": seg_reason,
        "seg_class": seg_class
    }
    
    # [NEW] Pass the NFC data out via the stats dictionary 
    grapheme_forensic_stats["_non_nfc_indices"] = non_nfc_indices

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

# Advanced Orchestrators

def compute_adversarial_metrics(t: str):
    """
    Adversarial Engine v10 (Consolidated & Paper-Aligned).
    Integrates: Ghost, Fracture, Stutter, and Jailbreak Styles.
    """
    if not t: 
        return {
            "findings": [], "top_tokens": [], "targets": [],
            "topology": {"OBFUSCATION": 0, "INJECTION": 0, "SPOOFING": 0, "HIDDEN": 0, "SEMANTIC": 0}
        }

    # --- 1. Setup ---
    tokens = tokenize_forensic(t) 
    confusables_map = DATA_STORES.get("Confusables", {})
    
    findings = []
    top_tokens = []
    
    topology = { "AMBIGUITY": 0, "SPOOFING": 0, "SYNTAX": 0, "HIDDEN": 0, "INJECTION": 0, "SEMANTIC": 0, "OBFUSCATION": 0 }
    SEVERITY_MAP = { "CRIT": 3, "HIGH": 2, "MED": 1, "LOW": 0 }

    # --- 2. Global Analyzers (State 1.5) ---
    
    # A. Visual Redaction (Ghost)
    ghost = analyze_visual_redaction(t)
    if ghost:
        findings.append({
            'family': '[GHOST]', 'desc': f"{ghost['count']} Deletion Characters",
            'token': 'GLOBAL', 'severity': 'crit'
        })
        topology["HIDDEN"] += 1

    # B. Syntax Fracture (Sandwich)
    frac = analyze_syntax_fracture_enhanced(t)
    if frac:
        findings.append({
            'family': '[FRACTURE]', 'desc': f"{frac['count']} Token Fractures",
            'token': 'GLOBAL', 'severity': 'crit'
        })
        topology["OBFUSCATION"] += 1

    # C. Jailbreak Styles (Evasion Alphabets)
    style = analyze_jailbreak_styles(t)
    if style:
        sev = 'crit' if style['risk'] >= 80 else 'warn'
        findings.append({
            'family': f"[{style['verdict']}]", 'desc': style['desc'],
            'token': 'GLOBAL', 'severity': sev
        })
        t_type = style.get('type', 'OBFUSCATION')
        topology[t_type] = topology.get(t_type, 0) + 1

    # D. Symbol Flood (SSTA)
    flood = analyze_symbol_flood(t)
    if flood:
        findings.append({
            'family': f"[{flood['verdict']}]", 'desc': flood['desc'],
            'token': 'GLOBAL', 'severity': 'crit' if flood['risk'] > 50 else 'warn'
        })
        # Safe update (Fixes KeyError risk)
        topology["SEMANTIC"] = topology.get("SEMANTIC", 0) + 1

    # E. Punctuation Skew (SSTA - Replacement)
    skew = analyze_punctuation_skew(t)
    if skew:
        findings.append({
            'family': f"[{skew['verdict']}]", 'desc': skew['desc'],
            'token': 'GLOBAL', 'severity': 'warn'
        })
        topology["SEMANTIC"] = topology.get("SEMANTIC", 0) + 1

    # F. Token Fragmentation (Charmer)
    frag = analyze_token_fragmentation_v2(tokens)
    if frag:
        sev = 'crit' if frag['risk'] > 80 else 'warn'
        findings.append({
            'family': f"[{frag['verdict']}]", 'desc': frag['desc'],
            'token': 'GLOBAL', 'severity': sev
        })
        topology["HIDDEN"] = topology.get("HIDDEN", 0) + 1

    # --- 3. Token Loop ---
    
    # Legacy Script logic for Restriction Badge
    scripts_found = set()
    has_math_spoof = False
    for char in t:
        cp = ord(char)
        sc = _find_in_ranges(cp, "Scripts")
        blk = _find_in_ranges(cp, "Blocks")
        if blk == "Mathematical Alphanumeric Symbols": has_math_spoof = True
        if sc and sc not in ("Common", "Inherited", "Unknown"): scripts_found.add(sc)
    
    restriction = "UNRESTRICTED"
    badge_class = "intel-badge-danger"
    count = len(scripts_found)
    if has_math_spoof: restriction = "SPOOFING (MATH)"
    elif count == 0:
        if all(ord(c) < 128 for c in t): restriction, badge_class = "ASCII-ONLY", "intel-badge-safe"
        else: restriction, badge_class = "SINGLE SCRIPT", "intel-badge-safe"
    elif count == 1: restriction, badge_class = f"SINGLE ({list(scripts_found)[0]})", "intel-badge-safe"
    else: restriction, badge_class = "MIXED SCRIPTS", "intel-badge-warn"

    # Main Loop
    for tok_obj in tokens:
        # Defensive Extraction
        if isinstance(tok_obj, dict):
            token_text = tok_obj.get('token', '')
        else:
            token_text = str(tok_obj)

        if not token_text.strip(): continue
        
        token_score = 0
        token_reasons = []
        token_families = set()
        threat_stack = [] 

        is_domain_candidate = is_plausible_domain_candidate(token_text)

        # [NEW] FRACTURE SCANNER (Paper 1: Invisible Sandwich)
        # Detects: Alpha -> Agent -> Alpha (e.g. "sens😎itive")
        fracture_risk = 0
        fracture_desc = ""
        
        if len(token_text) > 2:
            f_state = 0 # 0=Start, 1=Alpha, 2=Agent
            SAFE_PUNCT = {'.', '-', '_', '@', ':', '/'}
            
            for char in token_text:
                cp = ord(char)
                is_alnum = char.isalnum()
                is_safe = char in SAFE_PUNCT
                f_is_agent = False
                
                if cp < 1114112:
                    mask = INVIS_TABLE[cp]
                    if mask & (INVIS_ZERO_WIDTH_SPACING | INVIS_JOIN_CONTROL | INVIS_TAG | INVIS_BIDI_CONTROL):
                        f_is_agent = True
                    # Hardened Emoji Check
                    elif not is_alnum and (_find_in_ranges(cp, "Emoji") or _find_in_ranges(cp, "Extended_Pictographic")):
                        f_is_agent = True

                if f_state == 0:
                    if is_alnum: f_state = 1
                elif f_state == 1:
                    if not is_alnum and not is_safe:
                        if f_is_agent: f_state = 2
                    elif not is_alnum and is_safe:
                        f_state = 0
                elif f_state == 2:
                    if is_alnum:
                        fracture_risk = 90
                        fracture_desc = "Token Fracture (Mid-Token Injection)"
                        break
                    elif is_safe:
                        f_state = 0

        if fracture_risk > 0:
            threat_stack.insert(0, { "lvl": "CRIT", "type": "OBFUSCATION", "desc": fracture_desc })
            token_score += 90
            token_families.add("OBFUSCATION")

        # [NEW] Lexical Stutter (Unicode Evil)
        # Logic: Check for exact doubling (e.g. "adminadmin")
        if len(token_text) >= 6:
            mid = len(token_text) // 2
            if token_text[:mid] == token_text[mid:]:
                desc = "Lexical Stutter (Doubling)"
                threat_stack.append({"lvl": "MED", "type": "OBFUSCATION", "desc": desc})
                token_score += 30
                token_families.add("OBFUSCATION")

        # [CONTEXT]
        lure = analyze_context_lure(token_text)
        if lure:
            token_score += lure['risk']
            token_reasons.append(lure['desc'])
            token_families.add("CONTEXT")
            threat_stack.append({ "lvl": "MED", "type": "CONTEXT", "desc": lure['desc'] })

        # [TYPOSQUATTING & IDNA]
        if is_domain_candidate:
            domain_risk = analyze_domain_heuristics(token_text)
            if domain_risk:
                token_score += domain_risk['risk']
                token_reasons.append(domain_risk['desc'])
                token_families.add("SPOOFING") 
                threat_stack.append({ "lvl": "HIGH", "type": "SPOOFING", "desc": domain_risk['desc'] })

            if '.' in token_text or 'xn--' in token_text:
                labels = token_text.split('.')
                for label in labels:
                    if not label: continue
                    idna_findings = analyze_idna_label(label)
                    if idna_findings:
                        for f in idna_findings:
                            cat = "INJECTION"
                            if f['type'] == "GHOST": cat = "HIDDEN"
                            elif f['type'] == "AMBIGUITY": cat = "AMBIGUITY"
                            elif f['type'] == "COMPAT": cat = "SYNTAX"
                            elif f['type'] == "INVALID": cat = "SPOOFING"
                            
                            risk_adder = 0
                            if f['lvl'] == "CRIT": risk_adder = 50
                            elif f['lvl'] == "HIGH": risk_adder = 30
                            elif f['lvl'] == "MED": risk_adder = 10
                            token_score += risk_adder
                            
                            threat_stack.append({ "lvl": f['lvl'], "type": cat, "desc": f['desc'] })
                            if cat == "HIDDEN": token_families.add("OBFUSCATION")
                            elif cat == "SPOOFING": token_families.add("SPOOFING")
                            elif cat == "AMBIGUITY": token_families.add("HOMOGLYPH")
                            elif cat == "SYNTAX": token_families.add("INJECTION")
                            else: token_families.add("INJECTION")

        # [SCRIPT]
        # Was: r_lbl, r_score = analyze_restriction_level(token_text)
        # Fixed: Handle dict return
        r_data = analyze_restriction_level(token_text)
        r_lbl = r_data["label"]
        r_score = r_data["score"]
        
        if r_score > 0:
            if "CONTEXT" in token_families and r_score < 50: pass 
            else:
                token_score += r_score
                token_reasons.append(r_lbl)
                token_families.add("SCRIPT")
                lvl = "CRIT" if r_score > 80 else "HIGH"
                threat_stack.append({ "lvl": lvl, "type": "SPOOFING", "desc": r_lbl })
            
        # [HOMOGLYPH]
        # Call the hardened v1.2 helper. 
        # We pass 'confusables_map' explicitly to avoid global lookup overhead.
        conf_data = analyze_confusion_density(token_text, confusables_map)
        
        if conf_data:
            # Boost risk if the FIRST character is a confusable (visual anchor)
            # This detects spoofing where the "First Letter" is fake (e.g., Cyrillic 'P' in Paypal)
            if len(token_text) > 0 and ord(token_text[0]) in confusables_map:
                conf_data['risk'] = min(100, conf_data['risk'] + 20)
                conf_data['desc'] += " (Start-Char)"
            
            token_score += conf_data['risk']
            token_reasons.append(conf_data['desc'])
            token_families.add("HOMOGLYPH")
            
            lvl = "HIGH" if conf_data['risk'] > 80 else "MED"
            threat_stack.append({ "lvl": lvl, "type": "AMBIGUITY", "desc": conf_data['desc'] })

        # [SPOOFING]
        sore = analyze_class_consistency(token_text)
        if sore:
            token_score += sore['risk']
            token_reasons.append(sore['desc'])
            token_families.add("SPOOFING")
            threat_stack.append({ "lvl": "CRIT", "type": "AMBIGUITY", "desc": sore['desc'] })
            
        # [OBFUSCATION]
        norm = analyze_normalization_hazard_advanced(token_text)
        if norm:
            token_score += norm['risk']
            token_reasons.append(norm['desc'])
            token_families.add("OBFUSCATION")
            threat_stack.append({ "lvl": "HIGH", "type": "HIDDEN", "desc": norm['desc'] })
        
        # [PERTURBATION]
        pert = analyze_structural_perturbation(token_text)
        if pert:
            token_score += pert['risk']
            token_reasons.append(pert['desc'])
            token_families.add("PERTURBATION")
            is_bidi = "Bidi" in pert['desc']
            p_type = "INJECTION" if is_bidi else "HIDDEN"
            threat_stack.append({ "lvl": "CRIT", "type": p_type, "desc": pert['desc'] })

        # [TROJAN]
        trojan = analyze_trojan_context(token_text)
        if trojan:
            token_score += trojan['risk']
            token_reasons.append(trojan['desc'])
            token_families.add("TROJAN")
            lvl = "CRIT" if trojan['risk'] >= 100 else "HIGH"
            threat_stack.append({ "lvl": lvl, "type": "SYNTAX", "desc": trojan['desc'] })

        # [IDNA Compression]
        idna_comp = analyze_idna_compression(token_text)
        if idna_comp:
            threat_stack.append(idna_comp)
            token_families.add("SPOOFING")
            token_score += 50

        # --- Aggregation ---
        if token_score > 0 or threat_stack:
            pillars_seen = set()
            for item in threat_stack:
                t_type = item['type']
                if t_type not in pillars_seen:
                    topology[t_type] = topology.get(t_type, 0) + 1
                    pillars_seen.add(t_type)

            fam_str = " ".join([f"[{f}]" for f in sorted(token_families)])
            sev = 'ok'
            if token_score >= 80: sev = 'crit'
            elif token_score >= 40: sev = 'warn'
            
            if not token_score and threat_stack: token_score = 10 
            
            findings.append({
                'family': fam_str, 'desc': ", ".join(token_reasons),
                'token': token_text, 'severity': sev
            })
            
            threat_stack.sort(key=lambda x: SEVERITY_MAP.get(x['lvl'], 0), reverse=True)
            
            try: b64 = base64.b64encode(token_text.encode("utf-8")).decode("ascii")
            except: b64 = "Error"
            hex_v = "".join(f"\\x{b:02X}" for b in token_text.encode("utf-8"))
            
            primary_verdict = "Unknown Risk"
            if threat_stack:
                primary_verdict = f"{threat_stack[0]['type']} ({threat_stack[0]['lvl']})"

            top_tokens.append({
                'token': token_text, 'score': min(100, token_score),
                'reasons': token_reasons, 'families': list(token_families),
                'stack': threat_stack, 'verdict': primary_verdict,
                'b64': b64, 'hex': hex_v
            })

    # Global Stego Check (Final)
    stego_report = detect_invisible_patterns(t)
    if stego_report:
        findings.append({
            'family': '[STEGO]', 'desc': stego_report['detail'],
            'token': 'GLOBAL', 'severity': 'warn'
        })
        topology["HIDDEN"] = topology.get("HIDDEN", 0) + 1

    top_tokens.sort(key=lambda x: x['score'], reverse=True)
    max_token_score = max(t['score'] for t in top_tokens) if top_tokens else 0
        
    unique_findings = []
    seen_hashes = set()
    for f in findings:
        h = f"{f['token']}:{f['family']}"
        if h not in seen_hashes:
            unique_findings.append(f)
            seen_hashes.add(h)

    return {
        "findings": unique_findings, "top_tokens": top_tokens[:3],
        "topology": topology, "restriction": restriction,
        "badge_class": badge_class, "targets": top_tokens, 
        "stego": stego_report, "max_risk": max_token_score 
    }

def compute_stage1_5_forensics(text):
    """
    [STAGE 1.5] Orchestrator.
    Runs the Sidecar Engines and feeds the Auditor.
    Updated to include VS Topology, Tag Decoding, and Extension Masking.
    """
    all_signals = []
    
    # 1. Scan Global Injection Patterns (Existing)
    all_signals.extend(scan_injection_vectors(text))
    # Scan Contextual Lures (Markdown/Chat/Memory) (Existing)
    all_signals.extend(scan_contextual_lures(text))
    
    # 2. [NEW] Global Structural Scans
    # A. Variation Selector Topology
    vs_metrics, vs_signals = scan_vs_topology(text)
    all_signals.extend(vs_signals)
    
    # B. Tag Payload Decoding
    tag_payload = decode_tag_payload(text)
    if tag_payload:
        all_signals.append(tag_payload)
        
    # C. Delimiter Masking (Extension Hiding)
    all_signals.extend(scan_delimiter_masking(text))

    # 3. Token-Level Scans
    # We use the existing forensic tokenizer helper
    tokens = tokenize_forensic(text)
    
    for tok_obj in tokens:
        # Defensive extraction (handle dict vs str legacy)
        if isinstance(tok_obj, dict):
            t_str = tok_obj.get('token', '')
        else:
            t_str = str(tok_obj)
            
        if not t_str: continue
        
        # A. Fracture Scan (Uses the Upgraded Function from Block 2)
        all_signals.extend(scan_token_fracture_safe(t_str))
        
        # B. Domain Scan (Existing)
        all_signals.extend(scan_domain_structure_v2(t_str))

    # 4. Audit Signals
    return audit_stage1_5_signals(all_signals)

def compute_forensic_stats_with_positions(t: str, cp_minor_stats: dict, emoji_flags: dict, grapheme_stats: dict):
    """Hybrid Forensic Analysis with Uncapped Scoring & Structural Feedback."""
    
    # --- 1. Init Trackers ---
    legacy_indices = {
        "deceptive_ls": [], "deceptive_ps": [], "deceptive_nel": [],
        "bidi_bracket_open": [], "bidi_bracket_close": [],
        "extender": [], "deprecated": [], "dash": [], "quote": [], 
        "term_punct": [], "sent_term": [], "alpha": [], 
        "norm_excl": [], "norm_fold": [],
        "ext_picto": [], "emoji_mod": [], "emoji_mod_base": [],
        "vs_all": [], "invalid_vs": [], "discouraged": [], 
        "other_ctrl": [], "esc": [], "interlinear": [], 
        "bidi_mirrored": [], "loe": [], "unassigned": [], "suspicious_syntax_vs": [],
        "zombie_ctrl": []
    }
    
    decomp_type_stats = {}
    bidi_mirroring_map = {}
    id_type_stats = {} 
    
    flags = {
        "default_ign": [], "join": [], "zw_space": [], "bidi": [],
        "tags": [], "vs_std": [], "vs_ideo": [], "shy": [],
        "non_ascii_space": [], "bad_nl": [], "any_invis": [], "high_risk": []
    }
    
    health_issues = {
        "fffd": [], "surrogate": [], "nonchar": [], "fdd0": [],
        "pua": [], "nul": [], "bom_mid": [], "donotemit": []
    }

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
                cp = ord(char)
                category = unicodedata.category(char)
                mask = INVIS_TABLE[cp] if cp < 1114112 else 0

                # --- Decode Health ---
                if cp == 0xFFFD: health_issues["fffd"].append(i)
                if 0xD800 <= cp <= 0xDFFF: health_issues["surrogate"].append(i)
                if cp == 0x0000: health_issues["nul"].append(i)
                if cp == 0xFEFF and i > 0: health_issues["bom_mid"].append(i)
                if (0xE000 <= cp <= 0xF8FF) or (0xF0000 <= cp <= 0xFFFFD) or (0x100000 <= cp <= 0x10FFFD):
                    health_issues["pua"].append(i)
                # Specific FDD0 Tracking
                if 0xFDD0 <= cp <= 0xFDEF: 
                    health_issues["fdd0"].append(i)
                    health_issues["nonchar"].append(i) # Also count as general nonchar
                elif (cp & 0xFFFF) >= 0xFFFE:
                    health_issues["nonchar"].append(i)
                if mask & INVIS_DO_NOT_EMIT: health_issues["donotemit"].append(i)

                # --- Specific Dangerous Controls ---
                if cp == 0x001B: legacy_indices["esc"].append(i)
                if 0xFFF9 <= cp <= 0xFFFB: legacy_indices["interlinear"].append(i)
                
                # [NEW] Zombie Controls (Deprecated Format)
                # ISS (206A) -> NODS (206F)
                if 0x206A <= cp <= 0x206F:
                    legacy_indices["zombie_ctrl"].append(i)

                if ((0x0001 <= cp <= 0x0008) or (0x000B <= cp <= 0x000C) or (0x000E <= cp <= 0x001F) or (0x0080 <= cp <= 0x009F)) and cp != 0x0085 and cp != 0x001B:
                    legacy_indices["other_ctrl"].append(i)

                # --- Line Breaks ---
                if cp == 0x2028: legacy_indices["deceptive_ls"].append(i)
                elif cp == 0x2029: legacy_indices["deceptive_ps"].append(i)
                elif cp == 0x0085: legacy_indices["deceptive_nel"].append(i)
                
                # --- VS Logic ---
                if _find_in_ranges(cp, "VariationSelector"):
                    legacy_indices["vs_all"].append(i)
                    is_valid_vs = False
                    if i > 0:
                        prev_cp = ord(js_array[i-1])
                        if prev_cp in DATA_STORES["VariantBase"]: is_valid_vs = True
                    if not is_valid_vs: legacy_indices["invalid_vs"].append(i)

                # --- Properties ---
                if _find_in_ranges(cp, "Discouraged"): legacy_indices["discouraged"].append(i)
                if _find_in_ranges(cp, "Extender"): legacy_indices["extender"].append(i)
                if _find_in_ranges(cp, "Dash"): legacy_indices["dash"].append(i)
                if _find_in_ranges(cp, "QuotationMark"): legacy_indices["quote"].append(i)
                if _find_in_ranges(cp, "TerminalPunctuation"): legacy_indices["term_punct"].append(i)
                if _find_in_ranges(cp, "SentenceTerminal"): legacy_indices["sent_term"].append(i)
                if _find_in_ranges(cp, "Alphabetic"): legacy_indices["alpha"].append(i)
                if _find_in_ranges(cp, "CompositionExclusions"): legacy_indices["norm_excl"].append(i)
                if _find_in_ranges(cp, "ChangesWhenNFKCCasefolded"): legacy_indices["norm_fold"].append(i)
                
                bracket_type = _find_in_ranges(cp, "BidiBracketType")
                if bracket_type == "o": legacy_indices["bidi_bracket_open"].append(i)
                elif bracket_type == "c": legacy_indices["bidi_bracket_close"].append(i)
                if _find_in_ranges(cp, "BidiMirrored"): legacy_indices["bidi_mirrored"].append(i)
                if _find_in_ranges(cp, "LogicalOrderException"): legacy_indices["loe"].append(i)
                if cp in DATA_STORES["BidiMirroring"]:
                    mirrored_cp = DATA_STORES["BidiMirroring"][cp]
                    bidi_mirroring_map[i] = f"'{char}' → '{chr(mirrored_cp)}'"

                if _find_in_ranges(cp, "Extended_Pictographic"): legacy_indices["ext_picto"].append(i)
                if _find_in_ranges(cp, "Emoji_Modifier_Base"): legacy_indices["emoji_mod_base"].append(i)
                if _find_in_ranges(cp, "Emoji_Modifier"): legacy_indices["emoji_mod"].append(i)

                decomp_type = _find_in_ranges(cp, "DecompositionType")
                if decomp_type and decomp_type != "Canonical":
                    key = f"Decomposition (Derived): {decomp_type.title()}"
                    if key not in decomp_type_stats: decomp_type_stats[key] = {'count': 0, 'positions': []}
                    decomp_type_stats[key]['count'] += 1
                    decomp_type_stats[key]['positions'].append(f"#{i}")

                if category == "Cn": legacy_indices["unassigned"].append(i)

                # --- Bitmasks ---
                if mask & INVIS_DEFAULT_IGNORABLE: flags["default_ign"].append(i)
                if mask & INVIS_JOIN_CONTROL: flags["join"].append(i)
                if mask & INVIS_ZERO_WIDTH_SPACING: flags["zw_space"].append(i)
                if mask & INVIS_BIDI_CONTROL: flags["bidi"].append(i)
                if mask & INVIS_TAG: flags["tags"].append(i)
                if mask & INVIS_SOFT_HYPHEN: flags["shy"].append(i)
                if mask & INVIS_NON_ASCII_SPACE: flags["non_ascii_space"].append(i)
                if mask & INVIS_HIGH_RISK_MASK: flags["high_risk"].append(i)
                if mask & INVIS_ANY_MASK: flags["any_invis"].append(i)

                # --- 17.0 Syntax Spoofing ---
                if mask & (INVIS_VARIATION_STANDARD | INVIS_VARIATION_IDEOG):
                    if i > 0:
                        prev_char = js_array[i-1]
                        prev_cp = ord(prev_char)
                        prev_cat = unicodedata.category(prev_char)
                        if prev_cat[0] in ('P', 'S', 'Z'):
                            is_emoji_base = _find_in_ranges(prev_cp, "Emoji") or \
                                            _find_in_ranges(prev_cp, "Extended_Pictographic")
                            is_pres_selector = (cp == 0xFE0E or cp == 0xFE0F)
                            if not (is_emoji_base and is_pres_selector):
                                legacy_indices["suspicious_syntax_vs"].append(i)

                # --- Identifiers ---
                id_status_val = _find_in_ranges(cp, "IdentifierStatus")
                status_key = ""
                if id_status_val:
                    if id_status_val not in UAX31_ALLOWED_STATUSES: status_key = f"Flag: Identifier Status: {id_status_val}"
                else:
                    if category not in ("Cn", "Co", "Cs"): status_key = "Flag: Identifier Status: Default Restricted"
                if status_key:
                    if status_key not in id_type_stats: id_type_stats[status_key] = {'count': 0, 'positions': []}
                    id_type_stats[status_key]['count'] += 1
                    id_type_stats[status_key]['positions'].append(f"#{i}")

                specific_id_type = _find_in_ranges(cp, "IdentifierType")
                if specific_id_type and specific_id_type not in ("Recommended", "Inclusion"):
                    clean_label = ID_TYPE_ALIASES.get(specific_id_type, specific_id_type)
                    key = f"Flag: Type: {clean_label}"
                    if key not in id_type_stats: id_type_stats[key] = {'count': 0, 'positions': []}
                    id_type_stats[key]['count'] += 1
                    id_type_stats[key]['positions'].append(f"#{i}")

            except Exception as e:
                print(f"Error in forensic loop index {i}: {e}")
    
    rows = []
    def add_row(label, count, positions, severity="warn", badge=None, pct=None):
        if count > 0:
            row = {"label": label, "count": count, "positions": positions, "severity": severity, "badge": badge}
            if pct is not None: row["pct"] = pct
            rows.append(row)

    # --- 1. STRUCTURAL FEEDBACK LOOP ---
    struct_rows = []
    
    # [FIXED] Call analyze_bidi_structure ONLY ONCE and unpack correctly
    bidi_pen, bidi_fracs, bidi_dangers = analyze_bidi_structure(t, struct_rows)
    cluster_max_len = summarize_invisible_clusters(t, struct_rows)
    analyze_combining_structure(t, struct_rows)

    # --- [NEW] Populate Integrity Aggregator Buckets (Ranges) ---
    for idx in health_issues["fffd"]: _register_hit("int_fatal", idx, idx+1, "U+FFFD")
    for idx in health_issues["nul"]: _register_hit("int_fatal", idx, idx+1, "NUL Byte")
    for idx in health_issues["surrogate"]: _register_hit("int_fatal", idx, idx+1, "Surrogate")
    
    for s, e, lbl in bidi_fracs: _register_hit("int_fracture", s, e, lbl)
    
    # Keycaps
    for pos_str in emoji_flags.get("Flag: Broken Keycap Sequence", {}).get("positions", []):
        try:
            idx = int(pos_str.replace("#", ""))
            _register_hit("int_fracture", idx, idx+1, "Broken Keycap")
        except: pass

    for idx in flags["tags"]: _register_hit("int_risk", idx, idx+1, "Tag")
    for idx in health_issues["nonchar"]: _register_hit("int_risk", idx, idx+1, "Noncharacter")
    for idx in health_issues["donotemit"]: _register_hit("int_risk", idx, idx+1, "Do-Not-Emit")
    
    for idx in health_issues["pua"]: _register_hit("int_decay", idx, idx+1, "PUA")
    for idx in health_issues["bom_mid"]: _register_hit("int_decay", idx, idx+1, "Internal BOM")
    for idx in legacy_indices["other_ctrl"]: _register_hit("int_decay", idx, idx+1, "Legacy Control")
    
    # --- [NEW] Populate Threat Aggregator (Execution Tier) ---
    for s, e, lbl in bidi_dangers: _register_hit("thr_execution", s, e, lbl)
    for idx in legacy_indices["esc"]: _register_hit("thr_execution", idx, idx+1, "Terminal Injection")
    for idx in legacy_indices["suspicious_syntax_vs"]: _register_hit("thr_execution", idx, idx+1, "Syntax Spoofing")

    # --- 2. INTEGRITY AUDITOR ---
    auditor_inputs = {
        "fffd": len(health_issues["fffd"]),
        "surrogate": len(health_issues["surrogate"]),
        "nul": len(health_issues["nul"]),
        "bidi_broken_count": bidi_pen, # CORRECT: Integer Count
        "broken_keycap": len(emoji_flags.get("Flag: Broken Keycap Sequence", {}).get("positions", [])), 
        "hidden_marks": len(legacy_indices["suspicious_syntax_vs"]), 
        "tags": len(flags["tags"]),
        "nonchar": len(health_issues["nonchar"]),
        "invalid_vs": len(legacy_indices["invalid_vs"]),
        "donotemit": len(health_issues["donotemit"]),
        "max_cluster_len": cluster_max_len,
        "bom": len(health_issues["bom_mid"]),
        "pua": len(health_issues["pua"]),
        "legacy_ctrl": len(legacy_indices["other_ctrl"]),
        "dec_space": len(flags["non_ascii_space"]),
        "not_nfc": not (t == unicodedata.normalize("NFC", t)),
        "bidi_present": len(flags["bidi"])
    }

    audit_result = compute_integrity_score(auditor_inputs)

    # --- DECODE HEALTH GRADE (Forensic Lens A) ---
    # Synthesizes a high-level "Traffic Light" for Encoding Health.
    dh_grade = "OK"
    dh_sev = "ok"
    dh_reasons = []
    
    # 1. Critical Failures (Data Corruption)
    if auditor_inputs["fffd"] > 0: dh_reasons.append("Replacement Chars (Data Loss)")
    if auditor_inputs["surrogate"] > 0: dh_reasons.append("Lone Surrogates (Broken Encoding)")
    if auditor_inputs["nonchar"] > 0: dh_reasons.append("Noncharacters (Internal Leak)")
    if auditor_inputs["nul"] > 0: dh_reasons.append("Null Bytes (Binary Injection)")
    
    if dh_reasons:
        dh_grade = "CRITICAL"
        dh_sev = "crit"
    else:
        # 2. Warnings (Suspicious Artifacts)
        if auditor_inputs["bom"] > 0: dh_reasons.append("Internal BOM")
        if auditor_inputs["legacy_ctrl"] > 0: dh_reasons.append("Legacy Control Chars")
        if auditor_inputs["pua"] > 0: dh_reasons.append("Private Use Area")
        if auditor_inputs["not_nfc"]: dh_reasons.append("Text is not NFC")
        
        if dh_reasons:
            dh_grade = "WARNING"
            dh_sev = "warn"
            
    dh_badge = f"{dh_grade}"
    if dh_reasons: dh_badge += f" — {'; '.join(dh_reasons)}"

    # Add the Dashboard Row as the VERY FIRST row
    rows.insert(0, {
        "label": "Decode Health Grade",
        "count": 0, # Symbolic
        "severity": dh_sev,
        "badge": dh_badge,
        "positions": [] 
    })

    # --- Render Rows ---
    rows.append({
        "label": "Integrity Level (Heuristic)",
        "count": audit_result["score"],
        "severity": audit_result["severity_class"],
        "badge": f"{audit_result['verdict']} (Score: {audit_result['score']})",
        "ledger": audit_result["ledger"],
        "positions": [] 
    })

    # FATAL
    add_row("DANGER: Terminal Injection (ESC)", len(legacy_indices["esc"]), legacy_indices["esc"], "crit")
    add_row("Flag: Replacement Char (U+FFFD)", len(health_issues["fffd"]), health_issues["fffd"], "crit")
    add_row("Flag: NUL (U+0000)", len(health_issues["nul"]), health_issues["nul"], "crit")
    # Distinct FDD0 Row
    add_row("CRITICAL: Process-Internal Nonchar (FDD0)", len(health_issues["fdd0"]), health_issues["fdd0"], "crit")
    
    # Filter generic nonchars to exclude FDD0 (avoid double reporting)
    generic_nonchars = [x for x in health_issues["nonchar"] if x not in health_issues["fdd0"]]
    add_row("Noncharacter", len(generic_nonchars), generic_nonchars, "warn")
    add_row("Surrogates (Broken)", len(health_issues["surrogate"]), health_issues["surrogate"], "crit")
    
    # PROTOCOL
    add_row("Flag: Bidi Controls (UAX #9)", len(flags["bidi"]), flags["bidi"], "warn")
    add_row("Flag: Unicode Tags (Plane 14)", len(flags["tags"]), flags["tags"], "warn")
    add_row("Flag: High-Risk Invisible Controls", len(flags["high_risk"]), flags["high_risk"], "crit")
    add_row("Flag: Invalid Variation Selector", len(legacy_indices["invalid_vs"]), legacy_indices["invalid_vs"], "warn")
    add_row("Flag: Do-Not-Emit Characters", len(health_issues["donotemit"]), health_issues["donotemit"], "warn")

    # INVISIBLES
    add_row("Flag: Default Ignorable Code Points (All)", len(flags["default_ign"]), flags["default_ign"], "warn")
    add_row("Flag: Zero-Width Join Controls (ZWJ/ZWNJ)", len(flags["join"]), flags["join"], "warn")
    add_row("Flag: Zero-Width Spacing (ZWSP / WJ / BOM)", len(flags["zw_space"]), flags["zw_space"], "warn")
    add_row("Deceptive Spaces (Non-ASCII)", len(flags["non_ascii_space"]), flags["non_ascii_space"], "warn")
    add_row("Flag: Soft Hyphen (SHY)", len(flags["shy"]), flags["shy"], "warn")
    add_row("Flag: Any Invisible or Default-Ignorable (Union)", len(flags["any_invis"]), flags["any_invis"], "warn")
    
    pua_pct = round((len(health_issues["pua"]) / (len(t) + 1e-9)) * 100, 2)
    add_row("Flag: Private Use Area (PUA)", len(health_issues["pua"]), health_issues["pua"], "warn", pct=pua_pct)
    
    add_row("Flag: Internal BOM (U+FEFF)", len(health_issues["bom_mid"]), health_issues["bom_mid"], "warn")
    add_row("Flag: Other Control Chars (C0/C1)", len(legacy_indices["other_ctrl"]), legacy_indices["other_ctrl"], "warn")
    add_row("Flag: Interlinear Annotation Controls", len(legacy_indices["interlinear"]), legacy_indices["interlinear"], "warn")
    
    if not (t == unicodedata.normalize("NFC", t)):
        add_row("Flag: Normalization (Not NFC)", 1, ["Status: Text is NOT NFC"], "warn")

    add_row("Flag: Deceptive Newline (LS)", len(legacy_indices["deceptive_ls"]), legacy_indices["deceptive_ls"], "warn")
    add_row("Flag: Deceptive Newline (PS)", len(legacy_indices["deceptive_ps"]), legacy_indices["deceptive_ps"], "warn")
    add_row("Flag: Deceptive Newline (NEL)", len(legacy_indices["deceptive_nel"]), legacy_indices["deceptive_nel"], "warn")
    add_row("Flag: Security Discouraged (Compatibility)", len(legacy_indices["discouraged"]), legacy_indices["discouraged"], "warn")

    # INFORMATIONAL
    add_row("Flag: Bidi Paired Bracket (Open)", len(legacy_indices["bidi_bracket_open"]), legacy_indices["bidi_bracket_open"], "ok")
    add_row("Flag: Bidi Paired Bracket (Close)", len(legacy_indices["bidi_bracket_close"]), legacy_indices["bidi_bracket_close"], "ok")
    add_row("Prop: Extender", len(legacy_indices["extender"]), legacy_indices["extender"], "ok")
    add_row("Prop: Deprecated", len(legacy_indices["deprecated"]), legacy_indices["deprecated"], "warn")
    add_row("Prop: Dash", len(legacy_indices["dash"]), legacy_indices["dash"], "ok")
    add_row("Prop: Quotation Mark", len(legacy_indices["quote"]), legacy_indices["quote"], "ok")
    add_row("Prop: Terminal Punctuation", len(legacy_indices["term_punct"]), legacy_indices["term_punct"], "ok")
    add_row("Prop: Alphabetic", len(legacy_indices["alpha"]), legacy_indices["alpha"], "ok")
    add_row("Prop: Bidi Mirrored", len(legacy_indices["bidi_mirrored"]), legacy_indices["bidi_mirrored"], "ok")
    add_row("Prop: Logical Order Exception", len(legacy_indices["loe"]), legacy_indices["loe"], "warn")
    add_row("Prop: Extended Pictographic", len(legacy_indices["ext_picto"]), legacy_indices["ext_picto"], "ok")
    add_row("Prop: Variation Selector", len(legacy_indices["vs_all"]), legacy_indices["vs_all"], "ok")
    add_row("Unassigned (Void)", len(legacy_indices["unassigned"]), legacy_indices["unassigned"], "crit")

    # [NEW] Zombie Controls
    add_row("CRITICAL: Deprecated Format Controls (Zombie)", len(legacy_indices["zombie_ctrl"]), legacy_indices["zombie_ctrl"], "crit")

    # [NEW] NFC Stability Report (Granular)
    non_nfc_list = grapheme_stats.get("_non_nfc_indices", [])
    if non_nfc_list:
        add_row("Flag: Normalization Instability (Not NFC)", len(non_nfc_list), non_nfc_list, "warn")

    if bidi_mirroring_map:
        m_pos = [f"#{idx} ({m})" for idx, m in bidi_mirroring_map.items()]
        add_row("Flag: Bidi Mirrored Mapping", len(m_pos), m_pos, "ok")
        
    add_row("Flag: Full Composition Exclusion", len(legacy_indices["norm_excl"]), legacy_indices["norm_excl"], "warn")
    add_row("Flag: Changes on NFKC Casefold", len(legacy_indices["norm_fold"]), legacy_indices["norm_fold"], "warn")
    add_row("SUSPICIOUS: Variation Selector on Syntax", len(legacy_indices["suspicious_syntax_vs"]), legacy_indices["suspicious_syntax_vs"], "crit")

    for k, v in decomp_type_stats.items(): add_row(k, v['count'], v['positions'], "ok")
    for k, v in id_type_stats.items(): add_row(k, v['count'], v['positions'], "warn")

    rows.extend(struct_rows)

    return rows, audit_result

def compute_threat_analysis(t: str, script_stats: dict = None):
    """Module 3: Runs Threat-Hunting Analysis (UTS #39, etc.)."""
    
    # --- 0. Initialize defaults ---
    threat_flags = {}
    threat_hashes = {}
    confusable_indices = []
    found_confusable = False
    
    # --- Trackers ---
    bidi_danger_indices = []
    base_scripts_in_use = set() 
    ext_scripts_in_use = set()
    is_non_ascii_LNS = False 

    # [Phase 2] Heuristic Counters
    count_visible_mass = 0
    count_artifact_particles = 0 # Tracks ZWSP (200B), LRM (200E), RLM (200F)

    # Initialize output variables
    nf_string = ""
    nf_casefold_string = ""
    skeleton_string = ""
    skel_metrics = {} 
    final_html_report = ""
    
    # Initialize counters for the Overlay Engine
    threat_score = 0
    forensic_flags = []
    
    # ----------------------------------------------------
    # [NEW] Overlay Confusable Engine (Stage 1.1 - U+0334..U+0338)
    # ----------------------------------------------------
    # Maps (Base_Char, Overlay_Char_Ord) -> Atomic_Visual_Twin
    # This detects when a combining overlay is used to mimic a precomposed letter.
    OVERLAY_TWINS = {
        ("O", 0x0338): "Ø", ("o", 0x0338): "ø",
        ("L", 0x0335): "Ł", ("l", 0x0335): "ł",
        ("C", 0x0338): "Ȼ", ("c", 0x0338): "ȼ",
        ("=", 0x0338): "≠", ("-", 0x0338): "+",
        ("I", 0x0335): "Ɨ", ("i", 0x0335): "ɨ",
        ("Y", 0x0336): "Ɏ", ("y", 0x0336): "ɏ",
        ("U", 0x0336): "Ʉ", ("u", 0x0336): "ʉ",
        ("D", 0x0335): "Đ", ("d", 0x0335): "đ",
    }
    
    overlay_stats = {"A": 0, "B": 0, "C": 0}
    overlay_findings = []
    
    # We scan the raw text 't' for overlay combiners
    for i, char in enumerate(t):
        code = ord(char)
        if 0x0334 <= code <= 0x0338:
            # Identify Base (Context)
            base_char = t[i-1] if i > 0 else " "
            base_ord = ord(base_char)
            
            # Check for Atomic Twin (Spoofing)
            atomic_twin = OVERLAY_TWINS.get((base_char, code))
            
            # Classify Risk Tier
            if atomic_twin:
                # Direct Atomic Spoof (Highest Risk)
                overlay_stats["A"] += 1
                overlay_findings.append(f"#{i} ('{base_char}' + U+{code:04X} → {atomic_twin})")
                threat_score += 15 # High penalty for direct atomic mimicry
                
            elif (65 <= base_ord <= 90) or (97 <= base_ord <= 122) or (48 <= base_ord <= 57):
                # Class A: ASCII Base + Overlay (Identifier/URL Attack)
                overlay_stats["A"] += 1
                threat_score += 10
                
            elif ud.category(base_char).startswith("L"):
                # Class B: Non-ASCII Letter + Overlay (Complex Script Spoof)
                overlay_stats["B"] += 1
                threat_score += 5
                
            else:
                # Class C: Symbol/Punct + Overlay (Math/Notation)
                overlay_stats["C"] += 1
                threat_score += 2

    if sum(overlay_stats.values()) > 0:
        desc = f"Total {sum(overlay_stats.values())} (A:{overlay_stats['A']}, B:{overlay_stats['B']}, C:{overlay_stats['C']})"
        if overlay_findings:
             desc += f" [Twins: {', '.join(overlay_findings[:3])}...]"
             
        forensic_flags.append({
            "vector": "SPOOFING",
            "metric": "Overlay Confusables",
            "severity": "WEAPONIZED" if overlay_stats['A'] > 0 else "SUSPICIOUS",
            "penalty": f"+{threat_score}", # Note: This adds to the global score accumulation
            "description": desc
        })

    # Merge Overlay flags into main threat_flags dict if any exist
    for flag in forensic_flags:
        # Convert list format to dict format expected by renderer
        key = f"{flag['severity']}: {flag['metric']}"
        threat_flags[key] = {
            'count': 1, # Grouping handled by description
            'positions': [flag['description']],
            'severity': 'crit' if flag['severity'] == 'WEAPONIZED' else 'warn'
        }
    
    # --- 1. Early Exit ---
    if not t:
        return {
            'flags': {}, 'hashes': {}, 'html_report': "", 'bidi_danger': False,
            'raw': "", 'nfkc': "", 'nfkc_cf': "", 'skeleton': "", 'skel_metrics': {}
        }

    def _get_hash(s: str):
        if not s: return ""
        return hashlib.sha256(s.encode('utf-8')).hexdigest()
   
    try:
        # Use the new name compute_adversarial_metrics (v11)
        adversarial_data = compute_adversarial_metrics(t)
    except Exception as e:
        print(f"CRITICAL ERROR in Adversarial Engine: {e}")
        # Return empty structure so UI doesn't break
        adversarial_data = {
            "findings": [], 
            "top_tokens": [], 
            "topology": {"OBFUSCATION": 0, "INJECTION": 0, "SPOOFING": 0, "HIDDEN": 0, "SEMANTIC": 0}
        }

    try:
        # --- 2. Generate Normalized States ---
        nf_string = normalize_extended(t)
        nf_casefold_string = nf_string.casefold()

        # --- 5. Skeleton & Drift (Restored & Upgraded) ---
        # We generate the skeleton HERE so the metrics are available for the legacy flags below.
        # This uses the NEW function, so it won't crash.
        state_4_skeleton, skel_events = _generate_uts39_skeleton(t, return_events=True)

        # Bridge: Translate new 'skel_events' into old 'skel_metrics' format
        # This satisfies the "Flag: Skeleton Drift" logic further down.
        skel_metrics = {
            "total_drift": skel_events.get('confusables_mapped', 0),
            "drift_ascii": 0,
            "drift_cross_script": 0,
            "drift_other": 0
        }

        # Populate buckets using the new Forensic Metadata
        for m in skel_events.get('mappings', []):
            tgt = m['map_to']
            src_char = m['char']
            
            # [SAFETY FIX] Ignore Identity Mappings (Noise reduction)
            # This prevents flagging 'm' just because it exists in the database.
            if src_char == tgt:
                # Correct the total count since we are discarding this event
                skel_metrics["total_drift"] = max(0, skel_metrics["total_drift"] - 1)
                continue

            # m['type'] comes from the data loader (MA, ML, SA, SL)
            tag = m.get('type', 'UNK') 
            
            # Retrieve Scripts for Source and Target
            # (We use the cached ranges helper for speed)
            src_script = _find_in_ranges(ord(src_char), "Scripts") or "Common"
            
            # Check target script (use first char of skeleton as proxy)
            tgt_script = "Common"
            if tgt:
                tgt_script = _find_in_ranges(ord(tgt[0]), "Scripts") or "Common"

            # 1. ASCII Drift (Safe-ish)
            if ord(src_char) < 128 and all(ord(c) < 128 for c in tgt):
                skel_metrics["drift_ascii"] += 1
                
            # 2. Cross-Script Drift (DANGEROUS)
            # Logic: Source and Target must be DIFFERENT scripts, and neither can be Common/Inherited.
            elif src_script != tgt_script and \
                 src_script not in ("Common", "Inherited") and \
                 tgt_script not in ("Common", "Inherited"):
                skel_metrics["drift_cross_script"] += 1
                
            # 3. Same-Script / Other Drift (Neutral)
            else:
                skel_metrics["drift_other"] += 1
        
        # Update the variables expected by the return statement later
        skeleton_string = state_4_skeleton
        
        # --- 3. Run checks on RAW string ---
        confusables_map = DATA_STORES.get("Confusables", {})

        if LOADING_STATE == "READY":
            js_array_raw = window.Array.from_(t)

            for i, char in enumerate(js_array_raw):
                cp = ord(char)
                mask = INVIS_TABLE[cp] if cp < 1114112 else 0
                cat = unicodedata.category(char)
                
                # --- [Phase 2] Visual Mass Tracking ---
                # A character is "Visible" if it's NOT invisible/format/control/separator.
                # This determines if the string looks "Blank" to a human.
                if not (mask & INVIS_ANY_MASK) and not cat.startswith(('Z', 'C')):
                    count_visible_mass += 1
                    
                # --- [Phase 2] Artifact Tracking (AI/Watermark patterns) ---
                # We specifically count non-structural invisibles often used by LLMs/Watermarkers.
                # We EXCLUDE ZWJ (Emoji glue) and SHY (Hyphenation) to avoid false positives.
                if cp in (0x200B, 0x200E, 0x200F):
                    count_artifact_particles += 1
                
                # --- A. Bidi Check (Trojan Source) ---
                if (0x202A <= cp <= 0x202E) or (0x2066 <= cp <= 0x2069):
                    bidi_danger_indices.append(f"#{i}")

                # --- B. Mixed-Script Detection (Spec-Compliant) ---
                try:
                    # Use category from above
                    if cat[0] in ("L", "N", "S"):
                        if cp > 0x7F: is_non_ascii_LNS = True
                        
                        script_val = _find_in_ranges(cp, "Scripts")
                        if script_val:
                            base_scripts_in_use.add(script_val)
                        
                        script_ext_val = _find_in_ranges(cp, "ScriptExtensions")
                        if script_ext_val:
                            ext_scripts_in_use.update(script_ext_val.split())
                        elif script_val:
                            ext_scripts_in_use.add(script_val)
                except Exception:
                    pass 
                
                # --- C. Confusable Indexing (Threat Registry) ---
                # LOGIC FIX: Only flag NON-ASCII characters as threats.
                if cp > 0x7F and cp in confusables_map:
                    if window.RegExp.new(r"\p{L}|\p{N}|\p{P}|\p{S}", "u").test(char):
                        found_confusable = True
                        confusable_indices.append(i)

            # --- 4. Populate Threat Flags ---
            
            # [Phase 2] Heuristic: Blank ID / Visual Spoofing
            # Logic: Short string (< 50 chars) with ZERO visible mass.
            if len(t) > 0 and len(t) < 50 and count_visible_mass == 0:
                 threat_flags["CRITICAL: Visual Spoofing (Blank String)"] = {
                    'count': 1,
                    'positions': ["(Entire string is invisible)"],
                    'severity': 'crit',
                    'badge': 'SPOOF'
                 }

            # [Phase 2] Heuristic: Non-Structural Invisibles (AI Artifacts)
            # Logic: Latin Text + Artifact Particles (ZWSP/LRM) + No Dangerous Bidi.
            # This filters out legitimate uses in Complex Scripts (Arabic/Hebrew) or Emoji.
            is_latin_only = (len(base_scripts_in_use) == 1 and "Latin" in base_scripts_in_use)
            
            if count_artifact_particles > 0 and is_latin_only and not bidi_danger_indices:
                 threat_flags["ANOMALY: Non-Structural Invisibles (Latin Context)"] = {
                    'count': count_artifact_particles,
                    'positions': ["(Hidden formatting in plain text)"],
                    'severity': 'warn',
                    'badge': 'ARTIFACT'
                 }
            

            # --- 4. Populate Threat Flags ---
            
            # Bidi
            if bidi_danger_indices:
                threat_flags["DANGER: Malicious Bidi Control"] = {
                    'count': len(bidi_danger_indices),
                    'positions': bidi_danger_indices
                }

            # --- Script Mix Logic (Ontology Applied) ---
            ignored = {"Common", "Inherited", "Zzzz", "Unknown"}
            clean_base = {s for s in base_scripts_in_use if s not in ignored}
            clean_ext = {s for s in ext_scripts_in_use if s not in ignored}
            script_mix_class = "" 

            # 1. Base Script Mix
            if len(clean_base) > 1:
                sorted_base = sorted(list(clean_base))
                key = f"CRITICAL: Mixed Scripts (Base: {', '.join(sorted_base)})"
                threat_flags[key] = {
                    'count': len(clean_base),
                    'positions': ["(See Provenance Profile for details)"]
                }
                script_mix_class = "Mixed Scripts (Base)"
                # Do not flag Index 0. Let the specific foreign chars speak for themselves.
                # _register_hit("thr_suspicious", 0, 1, "Mixed Scripts")
                
            # 2. Extension Mix
            if len(clean_ext) > 2:
                 sorted_ext = sorted(list(clean_ext))
                 key = f"CRITICAL: Highly Mixed Scripts (Extensions: {', '.join(sorted_ext)})"
                 threat_flags[key] = {
                    'count': len(clean_ext),
                    'positions': ["(See Provenance Profile for details)"]
                 }
                 # Upgrade severity
                 script_mix_class = "Highly Mixed Scripts (Extensions)"
            
            # 3. Single Script / ASCII status
            if len(clean_base) == 0:
                if is_non_ascii_LNS:
                     threat_flags["Script Profile: Safe (Common/Inherited)"] = {'count': 0, 'positions': []}
                else:
                     threat_flags["Script Profile: ASCII-Only"] = {'count': 0, 'positions': []}
            elif len(clean_base) == 1:
                s_name = list(clean_base)[0]
                if s_name == "Latin" and is_non_ascii_LNS:
                     threat_flags["Script Profile: Single Script (Latin Extended)"] = {'count': 0, 'positions': []}
                elif not threat_flags: 
                     threat_flags[f"Script Profile: Single Script ({s_name})"] = {'count': 0, 'positions': []}


        # --- 5. Skeleton Drift (METRICS ENGINE) ---
        if skel_metrics["total_drift"] > 0:
            drift_desc = f"{skel_metrics['total_drift']} total"
            details = []
            
            # 1. Dangerous
            if skel_metrics['drift_cross_script'] > 0:
                details.append(f"{skel_metrics['drift_cross_script']} cross-script")
            
            # 2. Noise (ASCII)
            if skel_metrics['drift_ascii'] > 0:
                details.append(f"{skel_metrics['drift_ascii']} ASCII")
                
            # 3. Neutral/Other (The missing bucket!)
            if skel_metrics['drift_other'] > 0:
                details.append(f"{skel_metrics['drift_other']} other")
            
            if details:
                drift_desc += f" ({', '.join(details)})"
            
            threat_flags["Flag: Skeleton Drift"] = {
                'count': skel_metrics["total_drift"],
                'positions': [drift_desc]
            }

        # --- 6. QUAD-STATE FORENSIC PIPELINE (New Architecture) ---
        
        # State 1: Forensic (Raw)
        state_1_raw = t
        
        # State 2: NFKC (Compatibility) - Already computed as nf_string
        state_2_nfkc = nf_string
        
        # State 3: Identity (Casefold) - Already computed as nf_casefold_string
        state_3_casefold = nf_casefold_string
        
        # State 4: Visual Truth (Ultimate Skeleton)
        # CRITICAL: We call the NEW function with return_events=True to get forensic metadata
        state_4_skeleton, skel_events = _generate_uts39_skeleton(t, return_events=True)
        
        # Cryptographic Proof (Hashes)
        hashes = {
            "State 1: Forensic (Raw)": _get_hash(state_1_raw),
            "State 2: NFKC": _get_hash(state_2_nfkc),
            "State 3: NFKC-Casefold": _get_hash(state_3_casefold),
            "State 4: UTS #39 Skeleton": _get_hash(state_4_skeleton)
        }
        
        # Forensic Drift Analysis (Using Event Metadata)
        drift_info = compute_normalization_drift(
            state_1_raw, 
            state_2_nfkc, 
            state_3_casefold, 
            state_4_skeleton, 
            skel_events
        )

        # --- [NEW] Recursive De-obfuscation & WAF Check ---
        naked_text, layers_found = recursive_deobfuscate(t)
        waf_alerts, waf_score = analyze_waf_policy(naked_text)
        
        # Add WAF alerts to threat flags if significant
        if waf_score > 0:
            key = f"CRITICAL: Payload Detected ({', '.join(layers_found) or 'Raw'})"
            threat_flags[key] = {
                'count': 1,
                'positions': [f"triggers: {', '.join(waf_alerts)}"],
                'severity': 'crit',
                'badge': 'PAYLOAD'
            }
            # Inject into Adversarial Dashboard
            adversarial_data['topology']['INJECTION'] = adversarial_data['topology'].get('INJECTION', 0) + 1
            adversarial_data['targets'].insert(0, {
                "token": naked_text[:50] + "..." if len(naked_text) > 50 else naked_text,
                "verdict": f"DECODED PAYLOAD ({waf_score})",
                "stack": [{"lvl": "CRIT", "type": "INJECTION", "desc": a} for a in waf_alerts],
                "b64": "N/A", "hex": "N/A", "score": waf_score
            })

        # --- [NEW] Code Masquerade Check ---
        masq = analyze_code_masquerade(t, script_stats or {})
        if masq:
            key = f"CRITICAL: {masq['verdict']}"
            threat_flags[key] = {
                'count': 1,
                'positions': [masq['detail']],
                'severity': 'crit',
                'badge': 'MALWARE'
            }
            # Inject into Adversarial Dashboard
            adversarial_data['topology']['OBFUSCATION'] = adversarial_data['topology'].get('OBFUSCATION', 0) + 1
            adversarial_data['targets'].insert(0, {
                "token": "Global Input",
                "verdict": "MALWARE PATTERN",
                "stack": [{"lvl": "CRIT", "type": "OBFUSCATION", "desc": masq['detail']}],
                "b64": "N/A", "hex": "N/A", "score": masq['score']
            })

        # Ensure WAF/Global injections don't displace higher-risk token fractures.
        # We sort by score (descending) to ensure Paranoia Peak is mathematically accurate.
        if adversarial_data and 'targets' in adversarial_data:
            adversarial_data['targets'].sort(key=lambda x: x['score'], reverse=True)

        # --- [NEW] Module 5: Predictive Attack Simulation ---
        # 1. Anti-Sanitization Flags (Legacy Heuristics)
        sanit_flags = analyze_anti_sanitization(t)
        threat_flags.update(sanit_flags)
        
        # 1.5 [NEW] Syntax Predator (Deterministic Normalization Hazards)
        # This catches dynamic threats missed by the static list above
        norm_hazard_flags = analyze_normalization_hazards(t)
        threat_flags.update(norm_hazard_flags)
        
        # 2. Case Collision Flags
        case_flags = analyze_case_collisions(t)
        threat_flags.update(case_flags)
        
        # 3. Generate Predictive HTML Table
        predictive_html = render_predictive_normalizer(t)

        # --- [NEW] Recursive De-obfuscation & WAF Check ---
        naked_text, layers_found = recursive_deobfuscate(t)
        waf_alerts, waf_score = analyze_waf_policy(naked_text)
        
        # Add WAF alerts to threat flags if significant
        if waf_score > 0:
            key = f"CRITICAL: Payload Detected ({', '.join(layers_found) or 'Raw'})"
            threat_flags[key] = {
                'count': 1,
                'positions': [f"triggers: {', '.join(waf_alerts)}"],
                'severity': 'crit',
                'badge': 'PAYLOAD'
            }
            # Inject into Adversarial Dashboard
            adversarial_data['topology']['INJECTION'] = adversarial_data['topology'].get('INJECTION', 0) + 1
            adversarial_data['targets'].insert(0, {
                "token": naked_text[:50] + "..." if len(naked_text) > 50 else naked_text,
                "verdict": f"DECODED PAYLOAD ({waf_score})",
                "stack": [{"lvl": "CRIT", "type": "INJECTION", "desc": a} for a in waf_alerts],
                "b64": "N/A", "hex": "N/A", "score": waf_score
            })

        # --- 7. HTML Report: The Dual-View Forensic Engine ---
        # Strategy: Stack the "Classic Stream" (Context/Buttons) above the "Adversarial X-Ray" (Alignment)
        
        # A. Collect Sets for Legacy Renderer (Classic Stream)
        vis_confusables = set()
        if confusable_indices:
            js_array_raw = window.Array.from_(t)
            for idx in confusable_indices:
                try:
                    # Filter for non-common script risks (Legacy logic)
                    char = js_array_raw[idx]
                    cp = ord(char)
                    sc = _find_in_ranges(cp, "Scripts") or "Common"
                    if sc not in ("Common", "Inherited"):
                        vis_confusables.add(idx)
                except: pass
        
        vis_invisibles = set()
        clusters = analyze_invisible_clusters(t)
        for c in clusters:
            for k in range(c["start"], c["end"] + 1):
                vis_invisibles.add(k)
                
        vis_bidi = set()
        if bidi_danger_indices:
            for s in bidi_danger_indices:
                try: vis_bidi.add(int(s.replace("#","")))
                except: pass

        # B. Collect Sets for Modern Renderer (Adversarial X-Ray)
        threat_indices = set()
        if confusable_indices: threat_indices.update(confusable_indices)
        for c in clusters:
            for k in range(c["start"], c["end"] + 1):
                threat_indices.add(k)
        if bidi_danger_indices:
            for s in bidi_danger_indices:
                try: threat_indices.add(int(s.replace("#","")))
                except: pass

        # C. Generate Both Views
        html_legacy = ""
        html_xray = ""
        
        if threat_indices:
            # 1. Render Classic Stream (Context & Actions)
            legacy_map = {}
            for k, v in confusables_map.items():
                legacy_map[k] = v[0] if isinstance(v, tuple) else v
            
            # This generates the "Card" view with badges and buttons
            html_legacy = _render_forensic_diff_stream(
                t, 
                vis_confusables, 
                vis_invisibles, 
                vis_bidi, 
                legacy_map 
            )
            
            # 2. Render Adversarial X-Ray (Vertical Alignment)
            # This generates the "DNA Strip" view
            html_xray = render_adversarial_xray(
                t, 
                threat_indices, 
                confusables_map
            )

        # D. Stack Them
        if html_legacy or html_xray:
            final_html_report = f"""
            <div class="forensic-stack">
                <div class="stack-layer legacy-layer">{html_legacy}</div>
                <div class="stack-separator" title="Deep Alignment Analysis">⬇ X-RAY ALIGNMENT ⬇</div>
                <div class="stack-layer xray-layer">{html_xray}</div>
            </div>
            """
        else:
            final_html_report = ""
        
        # [NEW] Inject De-obfuscation Report if layers found
        if layers_found:
            layer_badges = "".join([f"<span class='layer-badge'>{l}</span>" for l in layers_found])
            final_html_report = f"""
            <div class="payload-alert">
                <div class="pa-header">🚨 DEEP OBFUSCATION DETECTED</div>
                <div class="pa-body">
                    <div class="pa-layers">Layers Stripped: {layer_badges}</div>
                    <div class="pa-content">
                        <strong>Naked Payload:</strong>
                        <code>{_escape_html(naked_text)}</code>
                    </div>
                    <div class="pa-waf">
                        <strong>WAF Simulator:</strong> {', '.join(waf_alerts) if waf_alerts else 'No Standard Signatures Detected'}
                    </div>
                </div>
            </div>
            {final_html_report}
            """
            
        # [NEW] Inject Predictive Normalizer Table at the bottom
        if predictive_html:
            final_html_report += predictive_html
        
        # SPOOFING (HUD Registry Logic)
        if confusable_indices and LOADING_STATE == "READY":
            for idx in confusable_indices:
                try:
                    _register_hit("thr_spoofing", idx, idx+1, "Homoglyph")
                except: pass
            
        # OBFUSCATION (HUD Registry Logic)
        for c in clusters:
            label = "Invisible Cluster"
            if c.get("high_risk"): label += " [High Risk]"
            _register_hit("thr_obfuscation", c["start"], c["end"]+1, label)


    except Exception as e:
        print(f"Error in compute_threat_analysis: {e}")
        # Fallback states
        if not nf_string: nf_string = t 
        if not nf_casefold_string: nf_casefold_string = t.casefold()
        # Fallback hashes/drift
        hashes = {}
        drift_info = {}
        final_html_report = "<p class='placeholder-text'>Error generating forensic report.</p>"
        
        # Ensure variables exist for return
        state_1_raw = t
        state_2_nfkc = t
        state_3_casefold = t.casefold()
        state_4_skeleton = t

    # --- CRITICAL: Define locals if they don't exist (Safety Fallback) ---
    if 'script_mix_class' not in locals(): script_mix_class = ""
    if 'skel_metrics' not in locals(): skel_metrics = {}

    # --- BRIDGE: Promote Adversarial Findings to Threat Flags ---
    # This ensures the "Group 3" table sees the "Group 4" discoveries.
    if adversarial_data and 'targets' in adversarial_data:
        for target in adversarial_data['targets']:
            for item in target.get('stack', []):
                # We only promote CRITICAL/HIGH findings to the main flag list to avoid noise
                if item['lvl'] in ('CRIT', 'HIGH'):
                    # Create a readable key like "CRITICAL: Token Fracture (Mid-Token Injection)"
                    key = f"{item['lvl']}: {item['desc']}"
                    
                    if key not in threat_flags:
                        threat_flags[key] = {
                            'count': 0,
                            'positions': [],
                            'severity': 'crit' if item['lvl'] == 'CRIT' else 'warn'
                        }
                    
                    threat_flags[key]['count'] += 1
                    # Add the token itself as the position context
                    threat_flags[key]['positions'].append(f"in '{target['token']}'")
    # -------------------------------------------------------
    # [STAGE 1.5] SOFT MERGE INTEGRATION
    # -------------------------------------------------------
    try:
        # 1. Run the Parallel Engine
        s1_5_results = compute_stage1_5_forensics(t)
        
        # 2. Merge Flags (Additive Only)
        # This injects the new high-fidelity signals into the existing report.
        if s1_5_results and 'flags' in s1_5_results:
            threat_flags.update(s1_5_results['flags'])
            
    except Exception as e:
        print(f"[Stage 1.5] Integration Warning: {e}")
    # -------------------------------------------------------
    return {
        'flags': threat_flags,
        'hashes': hashes,
        'html_report': final_html_report,
        'bidi_danger': bool(bidi_danger_indices),
        'script_mix_class': script_mix_class,
        'skel_metrics': skel_metrics,
        'drift_info': drift_info,
        'states': {
            's1': state_1_raw,
            's2': state_2_nfkc,
            's3': state_3_casefold,
            's4': state_4_skeleton
        },
        'adversarial': adversarial_data,
        'waf_score': waf_score
    }

# ===============================================
# BLOCK 9. RENDERERS (THE VIEW)
# ===============================================

# Core UI Helpers

def _create_position_link(val, text_context=None):
    """
    Helper: Transforms an index (int or '#123' string) into a clickable HTML link.
    Calls window.TEXTTICS_HIGHLIGHT_CODEPOINT(dom_idx).
    
    Indexing Patch: Uses text_context (if provided) to translate Python's 
    Code Point Index to the Browser's UTF-16 DOM Index.
    """
    txt = str(val)
    cp_idx = None

    # Case A: It is an integer (e.g., 52)
    if isinstance(val, int):
        cp_idx = val
        txt = f"#{val}"
    
    # Case B: It is a string (e.g., "#52" or "52")
    elif isinstance(val, str):
        clean = val.strip()
        if clean.startswith("#") and clean[1:].isdigit():
            cp_idx = int(clean[1:])
        elif clean.isdigit():
            cp_idx = int(clean)
            txt = f"#{cp_idx}"
    
    # If we successfully extracted a Code Point index...
    if cp_idx is not None:
        dom_idx = cp_idx # Default fallback
        
        # --- INDEXING PATCH START ---
        # Calculate the exact UTF-16 offset if text context is available.
        if text_context is not None:
            # Encode the substring up to the character as UTF-16-LE.
            # The length of the bytes divided by 2 gives the number of UTF-16 code units.
            try:
                dom_idx = len(text_context[:cp_idx].encode("utf-16-le")) // 2
            except Exception:
                dom_idx = cp_idx # Failsafe
        # --- INDEXING PATCH END ---

        return f'<a href="#" class="pos-link" onclick="window.TEXTTICS_HIGHLIGHT_CODEPOINT({dom_idx}); return false;">{txt}</a>'

    # Otherwise, return the text as-is
    return txt

def _update_css_workbench_ui(ledger: Dict[str, Any], findings: List[Dict[str, Any]], ghost_html: str):
    """
    Handles UI injection for the Metadata Workbench.
    [UPDATED] Uses Custom Forensic SVG Icons instead of Emojis.
    """
    
    # --- INTERNAL ICON SET (Forensic Pack) ---
    # Thermometer / Critical Gauge
    SVG_CRIT = '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 14.76V3.5a2.5 2.5 0 0 0-5 0v11.26a4.5 4.5 0 1 0 5 0z"></path></svg>'
    
    # Triangle Alert
    SVG_WARN = '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>'
    
    # Ghost / Anomaly
    SVG_GHOST = '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 10h.01"></path><path d="M15 10h.01"></path><path d="M12 2a8 8 0 0 0-8 8v12l3-3 2.5 2.5L12 19l2.5 2.5L17 19l3 3V10a8 8 0 0 0-8-8z"></path></svg>'
    
    # Shield Check / Safe
    SVG_SAFE = '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>'
    
    # Eye / Observation
    SVG_EYE = '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>'

    # 1. UI Configuration Map (Colors & Icons)
    UI_MAP = {
        "CRITICAL":   {"title": "CRITICAL THREAT",     "color": "#dc2626", "icon": SVG_CRIT},
        "SUSPICIOUS": {"title": "SUSPICIOUS ACTIVITY", "color": "#f59e0b", "icon": SVG_WARN},
        "ANOMALOUS":  {"title": "ANOMALOUS STRUCTURE", "color": "#8b5cf6", "icon": SVG_GHOST},
        "NON-STANDARD": {"title": "NON-STANDARD CSS",  "color": "#3b82f6", "icon": SVG_WARN},
        "CLEAN":      {"title": "CLEAN: No Obfuscation", "color": "#16a34a", "icon": SVG_SAFE},
        "NEUTRAL":    {"title": "Awaiting Input",      "color": "#9ca3af", "icon": SVG_EYE},
        "ERROR":      {"title": "Analysis Failed",     "color": "#ef4444", "icon": SVG_WARN}
    }
    
    grade = ledger.get("grade", "NEUTRAL")
    data = UI_MAP.get(grade, UI_MAP["NEUTRAL"])
    
    # 2. Update Header & Scoreboard
    document.getElementById("css-verdict-title").textContent = data["title"]
    document.getElementById("css-finding-count").textContent = str(len(findings))
    
    # Update the visual badge
    verdict_box = document.getElementById("metadata-findings-report")
    icon_box = document.getElementById("css-verdict-icon")
    
    if verdict_box: 
        verdict_box.style.borderLeftColor = data["color"]
    
    if icon_box: 
        # Inject SVG directly; color inherits via currentColor
        icon_box.innerHTML = data["icon"]
        icon_box.style.color = data["color"]

    # 3. Update Summary Text (Rich Context)
    summary_el = document.getElementById("css-summary-text")
    if summary_el:
        if grade == "CLEAN":
            summary_el.textContent = "No hidden content or obfuscation vectors detected."
        elif grade == "NEUTRAL":
            summary_el.textContent = "Paste raw HTML to begin analysis."
        else:
            # Show Score and Vectors
            vectors = ", ".join(ledger.get("vectors", [])) or "None"
            summary_el.textContent = f"Risk Score: {ledger['score']}/100 | Vectors: {vectors}"

    # 4. Update Findings List (The Forensic Trace)
    list_el = document.getElementById("css-findings-list")
    if list_el:
        list_el.innerHTML = ""
        
        if findings:
            details = document.getElementById("css-findings-details")
            if details: details.open = True
            
            for f in findings:
                li = document.createElement("li")
                li.style.fontFamily = "monospace"
                li.style.fontSize = "0.85rem"
                li.style.marginBottom = "8px"
                li.style.borderLeft = f"3px solid {data['color']}"
                li.style.paddingLeft = "8px"
                
                safe_preview = html.escape(f.get("content", ""))
                lineage_str = " > ".join(f.get("lineage", [])[-3:]) 
                
                li.innerHTML = (
                    f'<div style="font-size: 0.75rem; color: #6b7280; margin-bottom: 2px;">'
                    f'{lineage_str}</div>'
                    f'<div><span style="color:{data["color"]}; font-weight:700;">[{f["badge"]}] {f["cause"]}</span>'
                    f': <span style="background: #f3f4f6; padding: 0 4px;">"{safe_preview}"</span></div>'
                )
                list_el.appendChild(li)
        else:
            details = document.getElementById("css-findings-details")
            if details: details.open = False

    # 5. Inject Ghost View
    ghost_container = document.getElementById("css-ghost-view-container")
    if ghost_container and ghost_html:
        ghost_container.innerHTML = ghost_html

def render_status(message):
    """Updates the status line with text and CSS class."""
    status_line = document.getElementById("status-line")
    if status_line:
        
        # Determine state and render method based on message
        if message.startswith("Error:"):
            new_class = "status-error"
            status_line.innerText = message
        elif message.startswith("Ready"):
            new_class = "status-ready"
            # Restore the SVG and full text for the "Ready" state
            status_line.innerHTML = 'Input: Ready <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" style="display:inline-block; vertical-align:middle;"><polyline points="20 6 9 17 4 12"></polyline></svg>'
        else:
            new_class = "status-loading"
            status_line.innerText = message
        
        # Update the class list
        status_line.classList.remove("status-loading", "status-ready", "status-error")
        status_line.classList.add(new_class)
        
        # Clear any old inline styles
        status_line.style.color = ""

# General Profile Renderers

def render_cards(stats_dict, element_id=None, key_order=None, return_html=False):
    """Generates and injects HTML for standard stat cards."""
    html = []
    
    REPERTOIRE_KEYS = {
        "ASCII-Compatible", "Latin-1-Compatible", 
        "BMP Coverage", "Supplementary Planes"
    }
    
    keys_to_render = key_order if key_order else sorted(stats_dict.keys())
    
    for k in keys_to_render:
        if k not in stats_dict or stats_dict[k] is None:
            continue
        
        v = stats_dict[k]
        
        # --- RENDER PATH 1: New Repertoire Cards ---
        if k in REPERTOIRE_KEYS:
            count = v.get("count", 0)
            if count > 0:
                pct = v.get("pct", 0)
                is_full = v.get("is_full", False)
                
                if k == "Supplementary Planes":
                    badge_html = f'<div class="card-percentage">{pct}%</div>'
                else:
                    badge_html = (
                        f'<div class="card-badge-full">Fully</div>'
                        if is_full
                        else f'<div class="card-percentage">{pct}%</div>'
                    )
                
                html.append(
                    f'<div class="card card-repertoire">'
                    f'<strong>{k}</strong>'
                    f'<div class="card-main-value">{count}</div>'
                    f'{badge_html}'
                    f'</div>'
                )
        
        # --- RENDER PATH 2: Dict Cards ---
        elif isinstance(v, dict):
            count = v.get('count', 0)
            if count > 0:
                html.append(f'<div class="card"><strong>{k}</strong><div>{count}</div></div>')

        # --- RENDER PATH 2.5: High-Density Forensic Quad Cards ---
        
        # 1. VISUAL REALITY (Graphemes)
        # 1. VISUAL REALITY (Graphemes)
        elif k == "Total Graphemes":
            icon = METRIC_ICONS["eye"]
            
            # Micro-Facts
            avg_marks = stats_dict.get("Avg. Marks per Grapheme", 0)
            rgi_count = stats_dict.get("RGI Emoji Sequences", 0)
            
            # [NEW] Retrieve Verdict
            verdict = stats_dict.get("seg_verdict", "LOW")
            badge_cls = stats_dict.get("seg_class", "badge-ok")
            
            # Scientifically Rigorous Tooltip
            tooltip = (
                "[ DEFINITION ]\n"
                "User-perceived characters based on UAX #29 Extended Grapheme Clusters.\n"
                "Represents the visual 'atomic' unit displayed to the user.\n\n"
                "[ FORENSIC BENCHMARKS ]\n"
                "• ~0.0 marks/graph: Standard Text (Latin/ASCII)\n"
                "• >1.0 marks/graph: Heavy Diacritics or Zalgo\n"
                "• >2.0 marks/graph: Rendering Stack Overflow Risk\n\n"
                "[ THIS SAMPLE ]\n"
                f"• Mark Density: {avg_marks} marks per grapheme\n"
                f"• RGI Emoji Sequences: {rgi_count}\n"
                f"• Complexity: {verdict}"
            )

            html.append(
                f'<div class="card metric-card" title="{tooltip}">'
                f'<div class="card-header"><span class="card-icon">{icon}</span> {k}</div>'
                f'<div class="metric-body">'
                    f'<div class="metric-main">'
                        f'<div class="metric-value">{v:,}</div>'
                        f'<div class="metric-sub">Visual Units</div>'
                    f'</div>'
                    f'<div class="metric-facts">'
                        f'<div class="fact-row">Marks/Graph: <strong>{avg_marks}</strong></div>'
                        # [NEW] Injected Row
                        f'<div class="fact-row">Complexity: <span class="badge {badge_cls}" style="font-size:0.7em;">{verdict}</span></div>'
                    f'</div>'
                f'</div>'
                f'</div>'
            )

        # 2. LOGICAL REALITY (Code Points)
        elif k == "Total Code Points":
            icon = METRIC_ICONS["hash"]
            
            # Forensic Composition Data
            total_marks = stats_dict.get("Total Combining Marks", 0)
            mark_pct = 0
            if v > 0:
                mark_pct = (total_marks / v) * 100
            
            # Scientifically Rigorous Tooltip
            tooltip = (
                "[ DEFINITION ]\n"
                "Total count of Unicode Scalar Values (0x0000-0x10FFFF).\n"
                "The fundamental logical unit before encoding or rendering.\n\n"
                "[ FORENSIC BENCHMARKS ]\n"
                "• < 5% Marks: Standard Prose\n"
                "• > 15% Marks: Heavy Modification / Complex Scripts\n"
                "• High % with Low Graphemes: Invisible/Zalgo Attack\n\n"
                "[ THIS SAMPLE ]\n"
                f"• Combining Marks: {total_marks} ({mark_pct:.1f}% of total cp)\n"
                f"• Base Density: 1 Logical Atom = 1 Code Point"
            )

            html.append(
                f'<div class="card metric-card" title="{tooltip}">'
                f'<div class="card-header"><span class="card-icon">{icon}</span> {k}</div>'
                f'<div class="metric-body">'
                    f'<div class="metric-main">'
                        f'<div class="metric-value">{v:,}</div>'
                        f'<div class="metric-sub">Unicode Scalars</div>'
                    f'</div>'
                    f'<div class="metric-facts">'
                        f'<div class="fact-row">Combining Marks: <strong>{total_marks}</strong></div>'
                        f'<div class="fact-row">Density: <strong>{mark_pct:.1f}%</strong></div>'
                    f'</div>'
                f'</div>'
                f'</div>'
            )

        # 3. RUNTIME REALITY (UTF-16)
        elif k == "UTF-16 Units":
            icon = METRIC_ICONS["code"]
            astral = stats_dict.get("Astral Count", 0)
            cp_count = stats_dict.get("Total Code Points", 1)
            
            # Micro-Facts
            overhead = v - cp_count
            
            # Styles
            val_class = "metric-value-warn" if astral > 0 else "metric-value"
            
            # Scientifically Rigorous Tooltip
            tooltip = (
                "[ DEFINITION ]\n"
                "16-bit Code Unit count (used by Java/JS/C# string.length).\n"
                "Characters > U+FFFF require 2 units (Surrogate Pair).\n\n"
                "[ FORENSIC BENCHMARKS ]\n"
                "• +0 Overhead: BMP Only (Basic Multilingual Plane)\n"
                "• >0 Overhead: Contains Astral Characters (Emoji/Historic)\n"
                "• Risk: Buffer overflows if length calculated by CP vs Unit.\n\n"
                "[ THIS SAMPLE ]\n"
                f"• Astral Code Points: {astral}\n"
                f"• Surrogate Overhead: +{overhead} units vs cp count"
            )
            
            html.append(
                f'<div class="card metric-card" title="{tooltip}">'
                f'<div class="card-header"><span class="card-icon">{icon}</span> {k}</div>'
                f'<div class="metric-body">'
                    f'<div class="metric-main">'
                        f'<div class="{val_class}">{v:,}</div>'
                        f'<div class="metric-sub">JS/Java Length</div>'
                    f'</div>'
                    f'<div class="metric-facts">'
                        f'<div class="fact-row">Astral: <strong>{astral}</strong></div>'
                        f'<div class="fact-row">Overhead: <strong>+{overhead}</strong></div>'
                    f'</div>'
                f'</div>'
                f'</div>'
            )

        # 4. PHYSICAL REALITY (UTF-8)
        elif k == "UTF-8 Bytes":
            icon = METRIC_ICONS["save"]
            cp_count = stats_dict.get("Total Code Points", 1)
            
            # Micro-Facts
            bpc = v / cp_count if cp_count > 0 else 0
            
            # [NEW] Get ASCII Stats for Context
            ascii_data = stats_dict.get("ASCII-Compatible", {})
            ascii_pct = ascii_data.get("pct", 0) if ascii_data else 0
            
            # Scientifically Rigorous Tooltip
            tooltip = (
                "[ DEFINITION ]\n"
                "Physical storage size in bytes (Network/Disk/DB).\n"
                "Variable width encoding: 1 to 4 bytes per Code Point.\n\n"
                "[ FORENSIC BENCHMARKS (Density) ]\n"
                "• 1.0 b/cp: Pure ASCII (Legacy Safe)\n"
                "• ~2.0 b/cp: Latin-1 / Greek / Cyrillic / Arabic\n"
                "• >3.0 b/cp: CJK / Emoji / Mathematical Symbols\n\n"
                "[ THIS SAMPLE ]\n"
                f"• Storage Density: {bpc:.2f} bytes per cp\n"
                f"• ASCII Payload: {ascii_pct}% of code points"
            )

            html.append(
                f'<div class="card metric-card" title="{tooltip}">'
                f'<div class="card-header"><span class="card-icon">{icon}</span> {k}</div>'
                f'<div class="metric-body">'
                    f'<div class="metric-main">'
                        f'<div class="metric-value">{v:,}</div>'
                        f'<div class="metric-sub">Storage Size</div>'
                    f'</div>'
                    f'<div class="metric-facts">'
                        f'<div class="fact-row">Density: <strong>{bpc:.1f}</strong> b/cp</div>'
                        f'<div class="fact-row">ASCII: <strong>{ascii_pct}%</strong></div>'
                    f'</div>'
                f'</div>'
                f'</div>'
            )

        # Skip Astral Count (it's consumed by UTF-16 card)
        elif k == "Astral Count":
            continue
        # [NEW] Specific Renderer for Zalgo Verdict in Detail Cards
        elif k == "Avg. Marks per Grapheme":
            verdict = stats_dict.get("seg_verdict", "")
            badge_cls = stats_dict.get("seg_class", "")
            
            badge_html = ""
            if verdict:
                # Add the badge below the number
                badge_html = f'<div style="margin-top:6px;"><span class="badge {badge_cls}">{verdict}</span></div>'
            
            html.append(f'<div class="card"><strong>{k}</strong><div>{v}</div>{badge_html}</div>')
        # --- RENDER PATH 3: Simple Cards ---
        elif isinstance(v, (int, float)):
            count = v
            # Only force "Total" metrics to show if 0. Emoji/Whitespace will now hide if 0.
            if count > 0 or (k in ["Total Graphemes", "Total Code Points"]):
                html.append(f'<div class="card"><strong>{k}</strong><div>{count}</div></div>')
        
    final_html = "".join(html) if html else "<p class='placeholder-text'>No data.</p>"

    if return_html:
        return final_html

    if element_id:
        element = document.getElementById(element_id)
        if element:
            element.innerHTML = final_html

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

def render_matrix_table(stats_dict, element_id, has_positions=False, aliases=None, text_context=None):
    """Renders a generic 'Matrix of Facts' table."""
    html = []
    sorted_keys = sorted(stats_dict.keys())
    
    for key in sorted_keys:
        data = stats_dict[key]
        if not data: continue
            
        label = aliases.get(key, key) if aliases else key
        
        # --- RENDER PATH 1: Standard `has_positions` flags ---
        if has_positions:
            count = data.get('count', 0)
            if count == 0: continue
            
            row_class = ""
            if key in ("Flag: NUL (U+0000)", "Flag: Replacement Char (U+FFFD)", "Surrogates (Broken)"):
                row_class = "flag-row-critical"
            
            count_html = str(count)
            if 'pct' in data: count_html = f"{count} ({data['pct']}%)"
            
            # [ACTIVE UPDATE] Linkify Positions with Context
            raw_positions = data.get('positions', [])
            # PASS text_context HERE
            position_list = [_create_position_link(p, text_context) for p in raw_positions]

            if len(position_list) > 5:
                visible = ", ".join(position_list[:5])
                hidden = ", ".join(position_list[5:])
                pos_html = (
                    f'<details style="cursor: pointer;">'
                    f'<summary>{visible} ... ({len(position_list)} total)</summary>'
                    f'<div style="padding-top: 8px; user-select: all;">{hidden}</div>'
                    f'</details>'
                )
            else:
                pos_html = ", ".join(position_list)
            
            html.append(f'<tr class="{row_class}"><th scope="row">{label}</th><td>{count_html}</td><td>{pos_html}</td></tr>')
        
        # --- RENDER PATH 2: Simple 2-column ---
        else:
            count = data
            if count == 0: continue
            html.append(f'<tr><th scope="row">{label}</th><td>{count}</td></tr>')
            
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
        
        class_num = key.split('=')[-1]
        description = CCC_ALIASES.get(class_num, "N/A")
        
        html.append(
            f'<tr>'
            f'<th scope="row">{key}</th>'
            f'<td>{count}</td>'
            f'<td style="color: var(--color-text-muted); font-weight: normal; font-family: var(--font-sans);">{description}</td>'
            f'</tr>'
        )
    
    element.innerHTML = "".join(html)

def render_toc_counts(counts):
    """
    Updates the counts in the sticky Table of Contents.
    Hardened to prevent crashes if an HTML element is missing.
    """
    def update_id(el_id, val):
        el = document.getElementById(el_id)
        if el: 
            el.innerText = f"({val})"

    update_id("toc-dual-count", counts.get('dual', 0))
    update_id("toc-shape-count", counts.get('shape', 0))
    update_id("toc-integrity-count", counts.get('integrity', 0))
    update_id("toc-prov-count", counts.get('prov', 0))
    update_id("toc-emoji-count", counts.get('emoji', 0))
    update_id("toc-threat-count", counts.get('threat', 0))
    update_id("toc-atlas-count", counts.get('atlas', 0))
    update_id("toc-stat-count", counts.get('stat', 0))

# Deep Forensic Renderers

def render_integrity_matrix(rows, text_context=None):
    """Renders the forensic integrity matrix with Nested Ledger and Pinned Headers."""
    tbody = document.getElementById("integrity-matrix-body")
    tbody.innerHTML = ""
    
    INTEGRITY_KEY = "Integrity Level (Heuristic)"
    DECODE_KEY = "Decode Health Grade"
    
    # Sorting Logic: Pin Decode Health (000) and Integrity Level (001) to top
    def sort_key(r):
        lbl = r["label"]
        if lbl == DECODE_KEY: return "000"
        if lbl == INTEGRITY_KEY: return "001"
        return lbl
        
    sorted_rows = sorted(rows, key=sort_key)
    
    for row in sorted_rows:
        tr = document.createElement("tr")
        
        # --- HEADER ROWS (Score & Health) ---
        if row["label"] in (INTEGRITY_KEY, DECODE_KEY):
            tr.className = f"flag-row-{row['severity']}"
            tr.style.borderBottom = "2px solid var(--color-border)"
            
            th = document.createElement("th")
            th.textContent = row["label"]
            th.scope = "row"
            th.style.fontWeight = "700"
            th.style.fontSize = "1.05em"
            
            td_badge = document.createElement("td")
            span = document.createElement("span")
            span.className = f"integrity-badge integrity-badge-{row['severity']}"
            span.style.fontSize = "0.9em"
            span.textContent = row["badge"]
            td_badge.appendChild(span)
            
            td_ledger = document.createElement("td")
            
            # Handle Ledger (Integrity Level only)
            ledger_data = row.get("ledger", [])
            if ledger_data:
                details = document.createElement("details")
                details.className = "threat-ledger-details"
                summary = document.createElement("summary")
                summary.textContent = "View Penalty Breakdown"
                details.appendChild(summary)
                
                table = document.createElement("table")
                table.className = "integrity-ledger-table"
                
                thead = document.createElement("thead")
                thead.innerHTML = "<tr><th>Vector</th><th>Severity</th><th>Penalty</th></tr>"
                table.appendChild(thead)
                
                tbody_inner = document.createElement("tbody")
                for item in ledger_data:
                    tr_inner = document.createElement("tr")
                    td_vec = document.createElement("td")
                    td_vec.textContent = item["vector"]
                    if item["count"] > 1: td_vec.textContent += f" (x{item['count']})"
                    
                    td_sev = document.createElement("td")
                    span_sev = document.createElement("span")
                    sev_map = {"FATAL": "crit", "FRACTURE": "crit", "RISK": "warn", "DECAY": "ok"}
                    css_class = sev_map.get(item["severity"], "ok")
                    span_sev.className = f"integrity-badge integrity-badge-{css_class}"
                    span_sev.style.fontSize = "0.7em"
                    span_sev.textContent = item["severity"]
                    td_sev.appendChild(span_sev)
                    
                    td_pts = document.createElement("td")
                    td_pts.className = "score-val"
                    td_pts.textContent = f"+{item['points']}"
                    
                    tr_inner.appendChild(td_vec)
                    tr_inner.appendChild(td_sev)
                    tr_inner.appendChild(td_pts)
                    tbody_inner.appendChild(tr_inner)
                
                table.appendChild(tbody_inner)
                details.appendChild(table)
                td_ledger.appendChild(details)
            elif row["label"] == DECODE_KEY:
                # [NEW] Description for Decode Health
                if row['severity'] == 'ok':
                    td_ledger.textContent = "No encoding artifacts detected."
                else:
                    td_ledger.innerHTML = "<strong>Artifacts Found:</strong> See flags below for details."
            else:
                td_ledger.textContent = "Structure is Pristine."
            
            tr.appendChild(th)
            tr.appendChild(td_badge)
            tr.appendChild(td_ledger)
            
        else:
            # --- STANDARD ROW ---
            if row["severity"] == "crit": tr.classList.add("flag-row-critical")
            
            th = document.createElement("th")
            th.textContent = row["label"]
            th.scope = "row"
            
            td_count = document.createElement("td")
            if row["badge"] and row["badge"] != "OK": 
                if row["count"] > 0:
                     td_count.appendChild(document.createTextNode(f"{row['count']} "))
                span = document.createElement("span")
                span.className = f"integrity-badge integrity-badge-{row['severity']}"
                span.textContent = row["badge"]
                td_count.appendChild(span)
            else:
                td_count.textContent = str(row["count"])
                if "pct" in row: td_count.textContent += f" ({row['pct']}%)"

            td_pos = document.createElement("td")
            raw_positions = row.get("positions", [])
            
            if raw_positions:
                # --- INDEXING PATCH: Manual HTML injection for Positions ---
                pos_links = [_create_position_link(p, text_context) for p in raw_positions]
                
                if len(pos_links) > 5:
                     visible = ", ".join(pos_links[:5])
                     hidden = ", ".join(pos_links[5:])
                     details_html = (
                        f'<details style="cursor: pointer;">'
                        f'<summary>{visible} ... ({len(pos_links)} total)</summary>'
                        f'<div style="padding-top: 8px; user-select: all;">{hidden}</div>'
                        f'</details>'
                     )
                     td_pos.innerHTML = details_html
                else:
                     td_pos.innerHTML = ", ".join(pos_links)
            else:
                td_pos.textContent = "—"
            
            tr.appendChild(th)
            tr.appendChild(td_count)
            tr.appendChild(td_pos)

        tbody.appendChild(tr)

def render_emoji_qualification_table(emoji_list, text_context=None):
    """
    Renders the Emoji Qualification Profile table with Forensic Legend and Base Category.
    Columns: Sequence | Kind | Base | RGI? | Status | Count | Positions
    """
    element = document.getElementById("emoji-qualification-body")
    if not element: return
    if not emoji_list:
        element.innerHTML = "<tr><td colspan='7' class='placeholder-text'>No emoji sequences found.</td></tr>"
        return

    # Group by sequence string
    grouped = {}
    for item in emoji_list:
        seq = item.get("sequence", "?")
        if seq not in grouped:
            grouped[seq] = {
                'status': item.get("status", "unknown"),
                'kind': item.get("kind", "unknown"),
                'rgi': item.get("rgi", False),
                'base_cat': item.get("base_cat", "So"),
                'count': 0, 
                'indices': []
            }
        grouped[seq]['count'] += 1
        grouped[seq]['indices'].append(item.get("index", 0))

    # Sort by count desc, then sequence
    sorted_keys = sorted(grouped.keys(), key=lambda k: (-grouped[k]['count'], k))

    html = []
    for seq in sorted_keys:
        data = grouped[seq]
        
        # 1. Sequence
        td_seq = f'<td style="font-size: 1.5rem; font-family: var(--font-mono);">{seq}</td>'
        
        # 2. Kind Badge
        k_cls = "legend-badge"
        kind_raw = data['kind'].replace("emoji-", "").upper()
        k_style = "background-color: #f3f4f6; color: #374151; border-color: #d1d5db;"
        if kind_raw == 'SEQUENCE':
            k_style = "background-color: #eff6ff; color: #1e40af; border-color: #bfdbfe;"
        elif kind_raw == 'COMPONENT':
            k_style = "background-color: #fef2f2; color: #991b1b; border-color: #fecaca;"
            
        td_kind = f'<td><span class="{k_cls}" style="{k_style}">{kind_raw}</span></td>'
        
        # [NEW] 3. Base Category Badge
        cat = data.get('base_cat', 'So')
        cat_label = "SYM" if cat.startswith("S") else ("LET" if cat.startswith("L") else "OTH")
        cat_style = "background-color: #f3f4f6; color: #6b7280; border: 1px solid #e5e7eb; font-size: 0.7rem; padding: 2px 6px; border-radius: 4px; font-family: var(--font-mono);"
        td_base = f'<td><span style="{cat_style}" title="General Category: {cat}">{cat_label}</span></td>'
        
        # 4. RGI Badge
        r_cls = "legend-badge"
        if data['rgi']:
            r_style = "background-color: #f0fdf4; color: #15803d; border-color: #bbf7d0;"
            r_text = "YES"
        else:
            r_style = "background-color: #fffbeb; color: #b45309; border-color: #fcd34d;"
            r_text = "NO"
        td_rgi = f'<td><span class="{r_cls}" style="{r_style}">{r_text}</span></td>'

        # 5. Status Pill
        s_text = data['status'].replace('-', ' ').title()
        s_cls = "legend-pill legend-pill-neutral"
        if data['status'] == "fully-qualified": s_cls = "legend-pill legend-pill-ok"
        elif data['status'] == "unqualified": s_cls = "legend-pill legend-pill-warn"
        elif data['status'] == "component": s_cls = "legend-pill legend-pill-warn"
        td_status = f'<td><span class="{s_cls}">{s_text}</span></td>'

        # 6. Count
        td_count = f'<td>{data["count"]}</td>'

        # 7. Positions
        indices = data['indices']
        links_list = [_create_position_link(idx, text_context) for idx in indices]
        
        if len(links_list) > 5:
            visible = ", ".join(links_list[:5])
            hidden = ", ".join(links_list[5:])
            pos_html = (
                f'<details style="cursor: pointer;">'
                f'<summary>{visible} ... ({len(links_list)})</summary>'
                f'<div style="padding-top: 4px;">{hidden}</div>'
                f'</details>'
            )
        else:
            pos_html = ", ".join(links_list)

        td_pos = f'<td>{pos_html}</td>'

        html.append(f'<tr>{td_seq}{td_kind}{td_base}{td_rgi}{td_status}{td_count}{td_pos}</tr>')

    # Forensic Legend
    legend_html = """
    <tr>
        <td colspan="7" style="padding: 1rem; background: #f9fafb; border-top: 2px solid #e5e7eb; font-size: 0.85rem; color: #6b7280;">
            <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 1rem;">
                <div>
                    <strong>KIND (Structure):</strong><br>
                    • <b>ATOMIC:</b> Single code point.<br>
                    • <b>SEQUENCE:</b> Multi-char unit.<br>
                    • <b>COMPONENT:</b> Leaked part.
                </div>
                <div>
                    <strong>BASE (Category):</strong><br>
                    • <b>SYM:</b> Symbol (S*).<br>
                    • <b>LET:</b> Letter (L*).<br>
                    • <b>OTH:</b> Other/Mark.
                </div>
                <div>
                    <strong>STATUS (Integrity):</strong><br>
                    • <b>RGI YES:</b> Standard.<br>
                    • <b>Unqualified:</b> Non-std/Missing VS.<br>
                    • <b>Component:</b> Fragment.
                </div>
            </div>
        </td>
    </tr>
    """
    
    element.innerHTML = "".join(html) + legend_html

def render_emoji_summary(emoji_counts, emoji_list):
    """
    Render a detailed summary line using the new granular counters from the Cluster Ledger.
    Format: Emoji Units: 5 (RGI: 4 – atomic 4, sequences 0; Non-RGI: 1)
    """
    summary_el = document.getElementById("emoji-summary")
    if not summary_el: return

    total_rgi = emoji_counts.get("rgi_total", 0)
    rgi_atom = emoji_counts.get("rgi_atomic", 0)
    rgi_complex = emoji_counts.get("rgi_sequence", 0)
    non_rgi = emoji_counts.get("non_rgi_total", 0)
    comp_leaked = emoji_counts.get("components_leaked", 0)
    
    total_units = emoji_counts.get("total_emoji_units", 0)
    
    text = (
        f"Emoji Units: {total_units} ("
        f"RGI: {total_rgi} — atomic {rgi_atom}, sequences {rgi_complex}; "
        f"Non-RGI: {non_rgi}"
    )
    
    if comp_leaked > 0:
        text += f"; Components Leaked: {comp_leaked}"
        
    text += ")"
    
    summary_el.innerText = text

def render_invisible_atlas(invisible_counts, invisible_positions=None):
    """
    Renders the 'Invisible Atlas' (v3.0) - A forensic-grade instrument for hidden characters.
    Architecture: 8-Column Layout + Policy Recommendation + Deep Bidi/NFKC Intelligence.
    """

    if not invisible_counts:
        return '<div class="empty-state">No invisible characters detected.</div>', 0

    # ---------------------------------------------------------
    # 1. FORENSIC CLASSIFICATION LOGIC & CONSTANTS
    # ---------------------------------------------------------
    processed_rows = []
    
    # Explicit C0/C1 Control Names
    C0_CONTROL_NAMES = {
        0x00: "NULL", 0x09: "CHARACTER TABULATION", 0x0A: "LINE FEED (LF)", 
        0x0B: "LINE TABULATION", 0x0C: "FORM FEED (FF)", 0x0D: "CARRIAGE RETURN (CR)", 
        0x1B: "ESCAPE", 0x1F: "UNIT SEPARATOR", 0x85: "NEXT LINE (NEL)"
    }

    # Specific Bidi Mnemonics
    BIDI_TAG_MAP = {
        0x202E: "[RLO]", 0x202D: "[LRO]", 0x202B: "[RLE]", 0x202A: "[LRE]",
        0x202C: "[PDF]", 0x2066: "[LRI]", 0x2067: "[RLI]", 0x2068: "[FSI]",
        0x2069: "[PDI]", 0x061C: "[ALM]", 0x200E: "[LRM]", 0x200F: "[RLM]"
    }

    # Expanded Default Ignorable Set
    DEFAULT_IGNORABLE_SET = {
        0x00AD, 0x034F, 0x180E, 0x200B, 0x200C, 0x200D, 0x2060, 0x2061, 0x2062, 0x2063,
        0x2064, 0x2065, 0x3164, 0xFEFF, 0xFFA0, 0xFFF9, 0xFFFA, 0xFFFB
    }

    # --- Forensic Taxonomy v4.0 ---
    TIER_GLUE = {0x00A0, 0x00AD, 0x2011} 
    TIER_ASCII_WS = {0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x85}
    TIER_UNI_SPACE = {
        0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007, 0x2008, 0x2009, 0x200A, 0x202F, 0x205F, 0x3000, 0x1680
    }
    TIER_JOINERS = {0x200C, 0x200D}
    TIER_IGNORABLE = DEFAULT_IGNORABLE_SET | {0xFEFF}
    TIER_BIDI = set(BIDI_TAG_MAP.keys())

    # SIMPLE SUMMARY: Count distinct TYPES (rows), not total instances.
    summary_counts = collections.Counter()

    for char_code, count in invisible_counts.items():
        char = chr(char_code)
        
        # --- Name Resolution ---
        name = "Unknown"
        if char_code in C0_CONTROL_NAMES:
            name = C0_CONTROL_NAMES[char_code]
        else:
            try: name = ud.name(char)
            except: 
                if 0x80 <= char_code <= 0x9F: name = f"C1 CONTROL 0x{char_code:02X}"
                else: name = "UNASSIGNED / CONTROL"

        # --- Visual Decoding (Symbol) & CATEGORY SLUG ---
        symbol = "."
        category_slug = "UNKNOWN"
        
        if 0xE0000 <= char_code <= 0xE007F:
            tag_char = chr(char_code - 0xE0000)
            if 0xE0020 <= char_code <= 0xE007E: symbol = f"[TAG:{tag_char}]"
            elif char_code == 0xE007F: symbol = "[TAG:X]"
            else: symbol = "[TAG:?]"
            category_slug = "TAG"
        elif 0xFE00 <= char_code <= 0xFE0F:
            symbol = f"[VS{char_code - 0xFE00 + 1}]"; category_slug = "SELECTOR"
        elif 0xE0100 <= char_code <= 0xE01EF:
            symbol = f"[VS{char_code - 0xE0100 + 17}]"; category_slug = "SELECTOR"
        elif char_code == 0x200B: symbol = "[ZWSP]"; category_slug = "ZW-SPACE"
        elif char_code == 0x200D: symbol = "[ZWJ]"; category_slug = "JOINER"
        elif char_code == 0x200C: symbol = "[ZWNJ]"; category_slug = "JOINER"
        elif char_code == 0x00AD: symbol = "[SHY]"; category_slug = "HYPHEN"
        elif char_code in BIDI_TAG_MAP: symbol = BIDI_TAG_MAP[char_code]; category_slug = "BIDI"
        elif char_code in TIER_UNI_SPACE: symbol = "[SP:?]"; category_slug = "SPACE"
        elif 0x00 <= char_code <= 0x1F:
            symbol = f"[CTL:{char_code:02X}]"
            if char_code == 0x00: category_slug = "NULL"
            elif char_code == 0x09: category_slug = "TAB"
            elif char_code in [0x0A, 0x0D]: category_slug = "NEWLINE"
            else: category_slug = "CONTROL"
        else:
            symbol = "[INV]"; category_slug = "FORMAT"
        
        # --- FORENSIC CLASSIFICATION (Single Source of Truth) ---
        tier_badge = "OTHER"
        badge_style = "neutral" 
        tier_rank = 9
        policy_action = "REVIEW"
        policy_class = "prop-warn"

        if char_code == 0x0000:
            tier_badge = "FATAL (NULL)"; badge_style = "crit"; tier_rank = 0
            policy_action = "BLOCK"; policy_class = "prop-crit"
            
        elif 0xE0000 <= char_code <= 0xE007F:
            tier_badge = "DISALLOWED"; badge_style = "crit"; tier_rank = 1
            policy_action = "BLOCK"; policy_class = "prop-crit"
            
        elif char_code in TIER_BIDI:
            tier_badge = "BIDI CONTROL"; badge_style = "warn"; tier_rank = 2
            policy_action = "REVIEW"; policy_class = "prop-warn"
            
        elif category_slug == "CONTROL" or (0xFDD0 <= char_code <= 0xFDEF):
            tier_badge = "RESTRICTED CTRL"; badge_style = "warn"; tier_rank = 3
            policy_action = "REVIEW"; policy_class = "prop-warn"
            
        elif char_code in TIER_GLUE:
            tier_badge = "GLUE"; badge_style = "safe"; tier_rank = 8
            policy_action = "ALLOW"; policy_class = "prop-stable"
            
        elif char_code in TIER_ASCII_WS:
            tier_badge = "ASCII WS"; badge_style = "safe"; tier_rank = 7
            policy_action = "ALLOW"; policy_class = "prop-stable"
            
        elif char_code in TIER_UNI_SPACE:
            tier_badge = "UNICODE SPACE"; badge_style = "neutral"; tier_rank = 6
            policy_action = "NORM"; policy_class = "prop-info"
            
        elif char_code in TIER_JOINERS or category_slug == "SELECTOR":
            tier_badge = "JOINER/SELECTOR"; badge_style = "neutral"; tier_rank = 5
            policy_action = "CONTEXT"; policy_class = "prop-info"
            
        elif char_code in TIER_IGNORABLE:
            tier_badge = "IGNORABLE"; badge_style = "ghost"; tier_rank = 4
            policy_action = "REVIEW"; policy_class = "prop-ghost"

        # --- AGGREGATION (Count 1 per row type) ---
        summary_counts[tier_badge] += 1
        
        # --- ROW PROPERTIES ---
        tier_class = f"atlas-badge-{badge_style}"

        # --- 2. PHYSICAL PROPERTIES ---
        cat = ud.category(char)
        width_badge = ""
        if cat in ['Cf', 'Mn', 'Me', 'Cc'] or char_code == 0x200B:
            width_badge = '<span class="prop-badge prop-warn" title="Physics: Zero Width (Stealth)">W: 0</span>'
        elif cat == 'Zs':
            width_badge = '<span class="prop-badge prop-wide" title="Physics: Positive Width (Spacing)">W: &gt;0</span>'

        gc_badge = f'<span class="prop-badge prop-gc" title="General Category: {cat}">{cat}</span>'

        bc_badge = ""
        try:
            bc = ud.bidirectional(char)
            if bc: bc_badge = f'<span class="prop-badge prop-gc" title="Bidi Class: {bc}">BC:{bc}</span>'
        except: pass

        physics_html = f'<div class="props-flex">{width_badge}{gc_badge}{bc_badge}</div>'

        # --- 3. STABILITY PROPERTIES ---
        nfkc_form = ud.normalize('NFKC', char)
        nfkc_badge = ""
        if nfkc_form == "":
            nfkc_badge = '<span class="prop-badge prop-crit" title="NFKC: Removes Character">NFKC:VOID</span>'
        elif nfkc_form == " ":
            nfkc_badge = '<span class="prop-badge prop-warn" title="NFKC: Maps to Space">NFKC:SP</span>'
        elif nfkc_form != char:
             target_hex = " ".join([f"{ord(c):04X}" for c in nfkc_form])
             nfkc_badge = f'<span class="prop-badge prop-info" title="NFKC Maps to: {target_hex}">NFKC:MOD</span>'
        else:
             nfkc_badge = '<span class="prop-badge prop-stable" title="NFKC: Stable">NFKC:OK</span>'

        di_badge = ""
        is_di = (char_code in DEFAULT_IGNORABLE_SET or 0xE0000 <= char_code <= 0xE007F or 0xFE00 <= char_code <= 0xFE0F or 0x206A <= char_code <= 0x206F)
        if is_di:
             di_badge = '<span class="prop-badge prop-ghost" title="Default Ignorable Code Point: YES">DI:YES</span>'
        
        stability_html = f'<div class="props-flex">{di_badge}{nfkc_badge}</div>'
        
        policy_html = f'<span class="prop-badge {policy_class}" style="font-size:0.65rem;">{policy_action}</span>'

        processed_rows.append({
            "rank": tier_rank, "count": count,
            "html": f"""
            <tr>
                <td style="text-align:center;"><span class="atlas-glyph">{symbol}</span></td>
                <td class="code-col">U+{char_code:04X}</td>
                <td class="name-col" title="{name}">{name}</td>
                <td class="tier-col"><span class="atlas-badge {tier_class}">{tier_badge}</span></td>
                <td class="phys-col">{physics_html}</td>
                <td class="stab-col">{stability_html}</td>
                <td style="text-align:center;">{policy_html}</td>
                <td class="count-col" style="font-family:var(--font-mono); font-weight:700;">{count}</td>
                <td style="text-align:right;">
                    <button class="atlas-btn" onclick="window.TEXTTICS_HIGHLIGHT_CODEPOINT({char_code})" title="Locate in text">LOCATE</button>
                </td>
            </tr>"""
        })

    # Sort: Risk (Low Rank) -> Count (High to Low)
    processed_rows.sort(key=lambda x: (x["rank"], -x["count"]))
    
    # --- Build Summary Ribbon ---
    summary_parts = []
    summary_order = [
        "FATAL (NULL)", "DISALLOWED", "BIDI CONTROL", "RESTRICTED CTRL", 
        "IGNORABLE", "JOINER/SELECTOR", 
        "UNICODE SPACE", "ASCII WS", "GLUE", "OTHER"
    ]
    
    # Style Map
    LEGALITY_STYLE = {
        "FATAL (NULL)": "crit", "DISALLOWED": "crit", 
        "BIDI CONTROL": "warn", "RESTRICTED CTRL": "warn",
        "IGNORABLE": "ghost", "JOINER/SELECTOR": "neutral", 
        "UNICODE SPACE": "neutral", "ASCII WS": "safe", "GLUE": "safe", "OTHER": "neutral"
    }
    
    for label in summary_order:
        if summary_counts[label] > 0:
            val_class = LEGALITY_STYLE.get(label, "neutral")
            
            summary_parts.append(
                f'<div class="atlas-sum-metric">'
                f'<span class="sum-label">{label}</span>'
                f'<span class="sum-val {val_class}">{summary_counts[label]}</span>'
                f'</div>'
            )

    # Total should sum the TYPES (Rows), not the instances.
    # Since every row gets exactly one category, this is just the length of the dictionary.
    total_inv = len(invisible_counts)
    
    summary_html = f"""
        <div class="atlas-summary-bar">
            <div class="atlas-sum-metric main">
                <span class="sum-label">TOTAL</span>
                <span class="sum-val">{total_inv}</span>
            </div>
            {''.join(summary_parts)}
        </div>
    """
    
    # --- Updated Legend (Forensic Dimensions) ---
    desc_html = """
        <div class="atlas-legend-bar">
            <span class="legend-header">FORENSIC DIMENSIONS:</span>
            
            <div class="legend-item">
                <span class="legend-key">LEGALITY</span>
                <span class="legend-val">Security Tier</span>
            </div>
            
            <div class="legend-item">
                <span class="legend-key">PHYSICS</span>
                <span class="legend-val">Display Width &amp; Category</span>
            </div>
            
            <div class="legend-item">
                <span class="legend-key">STABILITY</span>
                <span class="legend-val">Normalization &amp; Stealth Risk</span>
            </div>
            
            <div class="legend-item">
                <span class="legend-key">POLICY</span>
                <span class="legend-val">Recommended Action</span>
            </div>
        </div>
    """

    # 9-Column Forensic Layout
    table_block = f"""
        <table class="atlas-table">
            <thead>
                <tr>
                    <th>Symbol</th>
                    <th>Code</th>
                    <th>Name</th>
                    <th>Legality</th>
                    <th>Physics</th>
                    <th>Stability</th>
                    <th>Policy</th>
                    <th>Count</th>
                    <th>Action</th>
                </tr>
            </thead>
            <tbody>
                {''.join(row["html"] for row in processed_rows)}
            </tbody>
        </table>
    """
    
    table_html = f"""
        <div class="atlas-content">
            {desc_html}
            {summary_html}
            {table_block}
        </div>
    """
    
    atlas_body = document.getElementById("invisible-atlas-body")
    if atlas_body:
        atlas_body.innerHTML = table_html
        
    return table_html, total_inv

def render_encoding_footprint(t: str):
    """
    Forensic Signal Engine v12.1 (Detail Upgrade):
    Now reports specific unique characters (Glyph, U+, Legacy Hex) with clickable positions.
    """
    integrity_container = document.getElementById("encoding-integrity")
    provenance_container = document.getElementById("encoding-provenance")
    synthesis_container = document.getElementById("encoding-synthesis")
    
    if not integrity_container or not provenance_container: return
    if not t:
        integrity_container.innerHTML = ""
        provenance_container.innerHTML = ""
        if synthesis_container: synthesis_container.innerHTML = ""
        return

    total_chars = len(t)
    # We need indices for the detail report, so we'll iterate properly below.
    # Quick check for signal existence:
    has_signal = any(ord(c) >= 128 for c in t)
    
    # --- 1. EXCLUSIVITY & DETAIL TRACKING ---
    legacy_codecs = [item for item in FORENSIC_ENCODINGS if "utf" not in item[1]]
    # Store full details: label -> list of {char, cp, idx, bytes_hex}
    exclusive_details = {item[0]: [] for item in legacy_codecs}
    
    total_non_ascii = 0
    non_ascii_chars = [] # Keep for signal strength calc

    if has_signal:
        for i, char in enumerate(t):
            if ord(char) < 128: continue
            
            total_non_ascii += 1
            non_ascii_chars.append(char)
            
            supported_by = []
            valid_encodings = [] # Stores (label, bytes)
            
            for label, codec, _ in legacy_codecs:
                try:
                    enc_bytes = char.encode(codec)
                    supported_by.append(label)
                    valid_encodings.append((label, enc_bytes))
                except UnicodeEncodeError:
                    pass
            
            # If exactly one legacy codec supports this character, it's a Unique Signal
            if len(supported_by) == 1:
                target_label = supported_by[0]
                target_bytes = valid_encodings[0][1]
                hex_str = " ".join(f"{b:02X}" for b in target_bytes)
                
                exclusive_details[target_label].append({
                    'char': char,
                    'cp': ord(char),
                    'idx': i,
                    'bytes': hex_str
                })

    # --- 2. RENDER LOOP ---
    integrity_html = []
    provenance_data = []
    utf_broken = False
    
    for label, codec, tooltip in FORENSIC_ENCODINGS:
        try:
            # Calc Total Compatibility (T)
            try:
                t.encode(codec)
                valid_count = total_chars
            except UnicodeEncodeError:
                valid_bytes = t.encode(codec, 'ignore')
                valid_s = valid_bytes.decode(codec)
                valid_count = len(valid_s)
            pct_total = (valid_count / total_chars) * 100
            
            # Calc Signal Strength (S)
            signal_strength = 0.0
            if "utf" in codec:
                signal_strength = pct_total
                if pct_total < 100: utf_broken = True
            elif has_signal:
                # Reconstruct non-ascii string for bulk check
                non_ascii_str = "".join(non_ascii_chars)
                try:
                    non_ascii_str.encode(codec)
                    valid_signal = total_non_ascii
                except:
                    valid_b = non_ascii_str.encode(codec, 'ignore')
                    valid_s = valid_b.decode(codec)
                    valid_signal = len(valid_s)
                signal_strength = (valid_signal / total_non_ascii) * 100
            
            # Retrieve details count
            uniq_hits = len(exclusive_details.get(label, []))
            
            # --- VISUAL STATUS LOGIC ---
            status_cls = ""
            val_primary = ""
            val_secondary = ""
            
            if "utf" in codec:
                # Modern Anchors
                status_cls = "status-safe" if valid_count == total_chars else "status-dead"
                val_primary = "100%" if valid_count == total_chars else f"{pct_total:.1f}%"
                
                it_lines = [f"[{label}] {tooltip}"]
                if valid_count == total_chars:
                    it_lines.append("• Status: VALID (100% Integrity)")
                else:
                    it_lines.append("• Status: CORRUPT / MALFORMED")
                
                integrity_html.append(f"""
                    <div class="enc-cell" title="{chr(10).join(it_lines)}">
                        <div class="enc-label">{label}</div>
                        <div class="enc-val-primary {status_cls}">{val_primary}</div>
                    </div>
                """)
            else:
                # Legacy Filters
                report_lines = [f"[{label}] {tooltip}"]
                
                if not has_signal:
                    # ASCII MODE: All legacy encodings are Compatible (Green)
                    status_cls = "status-safe"
                    val_primary = "100%"
                    val_secondary = "ASCII"
                    
                    report_lines.append(f"• Compatibility: 100.0% of this ASCII-only text.")
                    report_lines.append("• Status: Safe. Can be saved without data loss.")
                    report_lines.append("• Forensic Value: Null (ASCII is universal).")
                    
                else:
                    # MIXED MODE: Show Signal (S)
                    if signal_strength == 100.0:
                        status_cls = "status-uniq" if uniq_hits > 0 else "status-safe"
                    elif valid_count == 0:
                        status_cls = "status-dead" # Gray
                    else:
                        status_cls = "status-risk" # Orange
                    
                    val_primary = f"S:{signal_strength:.0f}%"
                    val_secondary = f"C:{pct_total:.0f}%"
                    
                    report_lines.append(f"• Signal Strength: {signal_strength:.1f}% of non-ASCII characters.")
                    report_lines.append(f"• Compatibility: {pct_total:.1f}% of this text fits this encoding.")
                    
                    if uniq_hits > 0:
                        report_lines.append(f"\n◈ UNIQUE MATCH: Sole supporter of {uniq_hits} specific character(s).")
                    elif signal_strength == 100.0:
                        report_lines.append("• Assessment: Strong candidate (fully explains foreign characters).")
                    elif signal_strength == 0.0:
                        report_lines.append("• Assessment: Irrelevant (Explains 0% of foreign chars).")
                    else:
                        report_lines.append("• Assessment: Partial / Data Loss Risk (Mojibake).")

                # ASCII Cell Override (Blue Baseline)
                if label == "ASCII" and has_signal:
                    val_primary = "BASELINE"
                    status_cls = "status-baseline" # BLUE
                    val_secondary = ""
                    
                    report_lines = [f"[{label}] {tooltip}"]
                    report_lines.append(f"• Signal Strength: 0.0% (Non-ASCII)")
                    report_lines.append(f"• Compatibility: {pct_total:.1f}% (ASCII subset only)")
                    report_lines.append("• Forensic Role: Baseline only. Always safe, but not an encoding candidate.")

                lbl_display = label + (' ◈' if uniq_hits > 0 else '')
                full_tooltip = "\n".join(report_lines)
                
                provenance_data.append({
                    'html': f"""
                        <div class="enc-cell" title="{full_tooltip}">
                            <div class="enc-label">{lbl_display}</div>
                            <div class="enc-metrics">
                                <span class="enc-val-primary {status_cls}">{val_primary}</span>
                                <span class="enc-val-secondary">{val_secondary}</span>
                            </div>
                        </div>
                    """,
                    'signal': signal_strength, 'total': pct_total, 'unique': uniq_hits, 'label': label
                })

        except Exception: pass

    # --- 3. VISIBILITY & SORTING ---
    provenance_data.sort(key=lambda x: (-x['unique'], -x['signal'], -x['total'], x['label']))
    
    # Uni-Only Column
    legacy_codecs_list = [item[1] for item in legacy_codecs]
    unsupported_chars = []
    for char in t:
        if ord(char) < 128: continue
        supported = False
        for l_codec in legacy_codecs_list:
            try:
                char.encode(l_codec); supported=True; break
            except: continue
        if not supported: unsupported_chars.append(char)
    
    unsupported_count = len(unsupported_chars)
    other_pct = (unsupported_count / total_chars) * 100
    
    other_style = "status-dead"
    other_tooltip = "All characters fit within tracked legacy encodings."
    if unsupported_count > 0:
        other_style = "status-modern"
        breakdown = {"Emoji": 0, "Math": 0, "Private": 0, "Other": 0}
        for ch in unsupported_chars:
            cat = unicodedata.category(ch)
            cp = ord(ch)
            if _find_in_ranges(cp, "Emoji") or _find_in_ranges(cp, "Extended_Pictographic"): breakdown["Emoji"] += 1
            elif cat == "Sm": breakdown["Math"] += 1
            elif cat in ("Co", "Cn"): breakdown["Private"] += 1
            else: breakdown["Other"] += 1
        bd_str = "\n".join([f"• {k}: {v}" for k,v in breakdown.items() if v > 0])
        other_tooltip = f"[UNI-ONLY] Beyond Legacy\n• Requires Unicode: {unsupported_count} char(s) cannot be saved as ANSI.\n Breakdown:\n{bd_str}"

    integrity_html.append(f"""
        <div class="enc-cell enc-cell-other" title="{other_tooltip}">
            <div class="enc-label">UNI-ONLY</div>
            <div class="enc-metrics" style="flex-direction: column; gap: 0;">
                <span class="enc-val-primary {other_style}">{other_pct:.1f}%</span>
                <span class="enc-val-secondary" style="font-size: 0.6rem;">{unsupported_count} chars</span>
            </div>
        </div>
    """)

    # Render Provenance
    prov_html = []
    hidden_count = 0
    for item in provenance_data:
        label = item['label']; sig = item['signal']; uniq = item['unique']
        is_visible = True
        
        if has_signal:
            if sig == 0 and uniq == 0: is_visible = False
        else:
            if len(prov_html) >= 6: is_visible = False
        if label == "ASCII": is_visible = True
        
        html_str = item['html']
        if not is_visible:
            html_str = html_str.replace('class="enc-cell"', 'class="enc-cell enc-hidden"')
            hidden_count += 1
        prov_html.append(html_str)

    if hidden_count > 0:
        prov_html.append(f"""
            <div class="enc-expand-btn" onclick="document.querySelectorAll('.enc-hidden').forEach(e => e.classList.remove('enc-hidden')); this.style.display='none';">
                <span>+{hidden_count}</span><span>More</span>
            </div>
        """)

    integrity_container.innerHTML = "".join(integrity_html)
    provenance_container.innerHTML = "".join(prov_html)

    # --- 4. SYNTHESIS ---
    if synthesis_container:
        badge_class = "syn-universal"; badge_text = "ANALYSIS"; summary_text = ""
        perfect_candidates = [d['label'] for d in provenance_data if d['signal'] == 100.0]
        
        if utf_broken:
            badge_class = "syn-critical"; badge_text = "CORRUPT DATA"
            summary_text = "Text contains <strong>invalid Unicode sequences</strong> (lone surrogates)."
        elif other_pct > 0:
            badge_class = "syn-modern"; badge_text = "REQUIRES UNICODE"
            summary_text = f"Text contains <strong>{unsupported_count} character(s)</strong> (e.g. Emoji, Math) that <strong>cannot be saved as ANSI</strong>."
        elif not has_signal:
            badge_class = "syn-universal"; badge_text = "UNIVERSAL ASCII"
            summary_text = "Text is <strong>100% 7-bit ASCII</strong>. Compatible with all systems."
        elif any(len(v) > 0 for v in exclusive_details.values()):
            # Find best match (label with highest unique count)
            best_label = max(exclusive_details, key=lambda k: len(exclusive_details[k]))
            hits = exclusive_details[best_label]
            count = len(hits)
            
            badge_class = "syn-match"; badge_text = f"UNIQUE SIGNAL: {best_label}"
            
            # Build Detailed Breakdown
            details = []
            for h in hits[:5]: # Top 5 to avoid bloat
                # Create clickable link using the bridge function
                pos_link = _create_position_link(h['idx'], t)
                char_disp = _escape_html(h['char'])
                details.append(f"<strong>{char_disp}</strong> (U+{h['cp']:04X} &rarr; {h['bytes']}) at {pos_link}")
            
            details_str = ", ".join(details)
            if count > 5:
                details_str += f", and {count - 5} more"
            
            summary_text = f"Contains <strong>{count} unique character(s)</strong> specific to <strong>{best_label}</strong>: {details_str}."
            
        elif perfect_candidates:
            candidates = ", ".join(perfect_candidates[:3])
            badge_class = "syn-universal"; badge_text = "AMBIGUOUS LEGACY"
            summary_text = f"Non-ASCII characters are fully compatible with multiple encodings (<strong>{candidates}</strong>)."
        else:
            badge_class = "syn-critical"; badge_text = "MIXED / MOJIBAKE"
            summary_text = "Does not fit any single legacy encoding. Likely a mix of sources."

        synthesis_container.innerHTML = f"""
            <div class="syn-badge {badge_class}">{badge_text}</div>
            <div class="syn-text">{summary_text}</div>
        """
def render_statistical_profile(stats):
    """
    Renders the Statistical & Lexical Profile (Group 2.F).
    ULTIMATE UI: High-density Micro-Cards, Sparklines with Legends, and Stacked Composition Bars.
    """
    container = document.getElementById("statistical-profile-body")
    if not container: return

    # Fail-soft
    if not stats or (stats.get("total_tokens", 0) == 0 and stats.get("line_stats", {}).get("count", 0) == 0):
        container.innerHTML = '<tr><td colspan="3" class="placeholder-text">Insufficient data for statistical profiling.</td></tr>'
        return

    # --- HELPER: Row Builder ---
    def make_row(label, visual, meta, data_def):
        d_lbl, d_desc, d_logic, d_norm = data_def
        attr_str = (
            f'data-label="{_escape_html(d_lbl)}" '
            f'data-desc="{_escape_html(d_desc)}" '
            f'data-logic="{_escape_html(d_logic)}" '
            f'data-norm="{_escape_html(d_norm)}"'
        )
        return f'<tr {attr_str} onmouseenter="window.updateStatConsole(this)" onmouseleave="window.updateStatConsole(null)"><th scope="row">{label}</th><td colspan="2" style="padding-top:12px; padding-bottom:12px;">{visual}{meta}</td></tr>'


    # --- HELPER: Micro-Card Builder ---
    def micro_card(label, val, sub_text="&nbsp;", alert=False):
        border_col = "#e2e8f0"
        bg_col = "#f8fafc"
        val_col = "#0f172a"
        if alert:
            border_col = "#fed7aa"
            bg_col = "#fff7ed"
            val_col = "#9a3412"
            
        return f"""
        <div style="flex:1; background:{bg_col}; border:1px solid {border_col}; border-radius:4px; padding:6px 4px; min-width:0; display:flex; flex-direction:column; align-items:center; justify-content:center; text-align:center;">
            <div style="font-size:0.55rem; color:#64748b; font-weight:700; text-transform:uppercase; margin-bottom:2px;">{label}</div>
            <div style="font-family:var(--font-mono); font-size:0.9rem; font-weight:700; color:{val_col}; margin-bottom:2px;">{val}</div>
            <div style="font-size:0.6rem; color:#94a3b8; line-height:1.1;">{sub_text}</div>
        </div>
        """

    rows = []

    # 1. Thermodynamics
    ent = float(stats.get("entropy", 0.0))
    ent_norm = float(stats.get("entropy_norm", 0.0))
    n_bytes = int(stats.get("entropy_n", 0))
    ascii_dens = float(stats.get("ascii_density", 0.0))
    ent_pct = min(100, max(0, (ent / 8.0) * 100))
    bar_color = "linear-gradient(90deg, #3b82f6 0%, #10b981 50%, #8b5cf6 100%)"
    
    # Dynamic Forensic Status (Context-Aware Update)
    status_txt = "Unknown structure"
    if n_bytes < 64:
        status_txt = "Insufficient Data (Unstable)"
    elif ent > 6.3:
        status_txt = "High Density (Compressed / Encrypted)"
    elif ent > 4.8:  # Lowered from 5.5 to catch obfuscated strings
        status_txt = "Complex Structure (Code / Binary / Obfuscated)"
    elif ent > 3.5:
        status_txt = "Natural Language (Standard Text)"
    else:
        status_txt = "Low Entropy (Repetitive / Sparse)"

    # Normalized Entropy (Density)
    # Explanation: How "full" is the information content for the characters used?
    norm_val = int(ent_norm * 100)
    norm_desc = f"{norm_val}% Saturation"
    
    vis_ent = f"""
    <div style="display:flex; align-items:center; gap:12px;">
        <div style="flex:1; height:6px; background:#f1f5f9; border-radius:3px; overflow:hidden; border:1px solid #e2e8f0;">
            <div style="width:{ent_pct:.1f}%; height:100%; background:{bar_color};"></div>
        </div>
        <div style="text-align:right; min-width:85px; font-family:var(--font-mono); font-weight:700; font-size:0.85rem; color:#1e293b;">
            {ent:.2f} <span style="font-size:0.65rem; color:#94a3b8; font-weight:400;">bits/byte</span>
        </div>
    </div>"""
    
    meta_ent = f"""
    <div style="margin-top:6px; font-size:0.7rem; color:#64748b; line-height:1.4;">
        <div style="display:flex; justify-content:space-between; margin-bottom:2px;">
            <span>Length: <b>{n_bytes}</b> bytes &bull; ASCII (Bytes): <b>{ascii_dens}%</b></span>
            <span title="Information Density (Normalized Entropy)">Density: <b>{norm_desc}</b></span>
        </div>
        <div style="color:#475569; font-style:italic;">{_escape_html(status_txt)}</div>
    </div>
    """
    
    console_desc = (
        "Shannon Entropy (0-8 bits). Low (<3.0): Repetitive/Sparse. Mid (3.0-4.5): Natural Text. High (>6.5): Compressed/Encrypted.\n"
        "DENSITY: Saturation of the character set. >90% implies uniform distribution (Obfuscation/Randomness)."
    )
    
    rows.append(make_row(
        "Thermodynamics", vis_ent, meta_ent,
        ("ENTROPY (SHANNON)", 
         console_desc, 
         "H = -Σ p(x) log₂ p(x)", 
         "Range: 0.0 (Null) to 8.0 (Random)")
    ))

    # 2. Encoded Payloads (Rich Heuristic Alert)
    payloads = stats.get("payloads", [])
    if payloads:
        p_chips = []
        for p in payloads:
            js_tok = _escape_for_js(p['token'])
            ent = p.get('entropy', 0.0)
            
            # Styling: Red border if high entropy (likely encrypted), Orange if mid
            style_border = "#fed7aa" # Orange (Default)
            style_bg = "#fff7ed"
            style_text = "#9a3412"
            icon = "⚠️"
            
            if ent > 5.8: # Base64 max entropy is 6.0, Hex is 4.0. High relative entropy = data.
                style_border = "#fecaca" # Red
                style_bg = "#fef2f2"
                style_text = "#dc2626"
                icon = "🚨"
            
            safe_lbl = f"<b>{p['type']}</b> <span style='opacity:0.8; font-weight:400; font-size:0.65rem;'>L:{p['len']} H:{ent}</span>"
            
            chip = (
                f'<button onclick="window.TEXTTICS_FIND_SEQ(\'{js_tok}\')" '
                f'style="background:{style_bg}; border:1px solid {style_border}; padding:2px 8px; '
                f'border-radius:4px; cursor:pointer; font-size:0.7rem; color:{style_text}; '
                f'margin-right:6px; display:inline-flex; align-items:center; font-family:var(--font-mono);">'
                f'{icon} {safe_lbl}</button>'
            )
            p_chips.append(chip)
        
        rows.append(make_row(
            "Encoded Payloads", "".join(p_chips), "",
            ("HEURISTIC PAYLOADS", 
             "Pattern matching for encoded strings (Base64/Hex) > 16 chars. H=Local Entropy (bits). High entropy (>5.5 for B64) implies non-text payload.", 
             "Regex(CharSet) + Shannon Entropy", 
             "Target: Hidden shellcode, keys, or exfiltrated data.")
        ))

    # 3. Lexical Density
    ttr = float(stats.get("ttr", 0.0))
    ttr_seg = stats.get("ttr_segmented", None)
    tok_total = int(stats.get("total_tokens", 0))
    uniq = int(stats.get("unique_tokens", 0))
    ttr_pct = min(100, max(0, ttr * 100))
    ttr_grad = "linear-gradient(90deg, #f87171 0%, #fbbf24 30%, #2dd4bf 100%)"
    
    vis_ttr = f"""
    <div style="display:flex; align-items:center; gap:12px;">
        <div style="flex:1; height:6px; background:#f1f5f9; border-radius:3px; overflow:hidden; border:1px solid #e2e8f0;">
            <div style="width:{ttr_pct:.1f}%; height:100%; background:{ttr_grad};"></div>
        </div>
        <div style="text-align:right; min-width:50px; font-family:var(--font-mono); font-weight:700; font-size:0.85rem; color:#1e293b;">{ttr:.2f}</div>
    </div>"""
    
    # Forensic TTR Scales (Calibrated for N > 50)
    if tok_total < 50:
        ttr_hint = "Unstable (Short Text - Ignore Metric)"
    elif ttr < 0.20:
        ttr_hint = "Critical Repetition (Machine / Flood)"
    elif ttr < 0.40:
        ttr_hint = "Low Variety (Simple / Bot-like)"
    elif ttr < 0.60:
        ttr_hint = "Standard Prose (Natural Language)"
    elif ttr < 0.80:
        ttr_hint = "Rich Vocabulary (Complex / Literary)"
    elif ttr < 0.95:
        ttr_hint = "High Density (Lists / Identifiers)"
    else:
        ttr_hint = "Unique Stream (Rainbow / UUIDs)"
    
    seg_html = f" <span title='Segmented TTR (Length-Adjusted)'>Seg: <b>{ttr_seg:.2f}</b></span>" if ttr_seg else ""
    
    # Detailed Metadata Line
    meta_ttr = f"""
    <div style="display:flex; justify-content:space-between; margin-top:4px; font-size:0.65rem; color:#6b7280;">
        <div>{uniq} unique / {tok_total} total tokens{seg_html}</div>
        <div>{_escape_html(ttr_hint)}</div>
    </div>
    """

    rows.append(make_row("Lexical Density", vis_ttr, "", 
        ("TYPE-TOKEN RATIO (TTR)", 
         "Measures vocabulary uniqueness. Low (<0.4): Repetitive logs/bots. Mid (0.4-0.7): Natural prose. High (>0.8): Dense lists, UUIDs, or short text.", 
         "Unique / Total", 
         "Length Sensitive: Decreases naturally as text gets longer.")))

    # 4. Top Tokens
    top_tokens = stats.get("top_tokens", [])
    chips = []
    if top_tokens:
        for item in top_tokens:
            js_tok = _escape_for_js(item['token'])
            safe_tok = _escape_html(item['token'])
            chips.append(f'<button onclick="window.TEXTTICS_FIND_SEQ(\'{js_tok}\')" style="background:#f1f5f9; border:1px solid #e2e8f0; padding:1px 6px; border-radius:4px; cursor:pointer; font-size:0.7rem; color:#334155; margin:0 4px 4px 0;">{safe_tok} <span style="opacity:0.6">{item["share"]}%</span></button>')
    
    rows.append(make_row("Top Tokens", f'<div style="display:flex; flex-wrap:wrap; width:100%;">{"".join(chips)}</div>', "", 
        ("REPETITION ANALYSIS", 
         "Analyzes token frequency (Zipf's Law). Top-1 > 30%: Indication of keyword stuffing, log padding, or DoS attempts. Natural text has smooth decay.", 
         "Count / Total", 
         "Top-1 > 30% suggests flooding.")))

    # 5. Fingerprint
    cd = stats.get("char_dist", {})
    l, n, s, w = cd.get('letters',0), cd.get('digits',0), cd.get('sym',0), cd.get('ws',0)
    
    stacked = f"""
    <div style="display:flex; height:6px; border-radius:3px; overflow:hidden; border:1px solid #e2e8f0; width:100%;">
        <div style="width:{l}%; background:#60a5fa;"></div><div style="width:{n}%; background:#f59e0b;"></div><div style="width:{s}%; background:#a855f7;"></div><div style="width:{w}%; background:#cbd5e1;"></div>
    </div>"""
    legend_items = [f'<span style="color:#60a5fa;">●</span> L:{l}%', f'<span style="color:#f59e0b;">●</span> N:{n}%', f'<span style="color:#a855f7;">●</span> S:{s}%', f'<span style="color:#94a3b8;">●</span> WS:{w}%']
    meta_fing = f"<div style='display:flex; gap:12px; font-size:0.65rem; color:#64748b; margin-top:4px;'>{' '.join(legend_items)}</div>"
    
    rows.append(make_row("Freq. Fingerprint", stacked, meta_fing, 
        ("CHARACTER DISTRIBUTION", 
         "Distribution of character categories. Peaked (High L): Natural Language. Mixed: Code/Logs. Flat (Uniform): Encrypted, Compressed, or Random data.", 
         "Category Freq", 
         "Includes all characters (Honest Mode).")))

    # 6. Layout Physics (7 Cards + Mass Map)
    l_stats = stats.get("line_stats", {})
    cnt = l_stats.get('count',0)
    
    if cnt > 0:
        mn = int(l_stats.get('min',0))
        p25 = int(l_stats.get('p25',0))
        p50 = int(l_stats.get('median',0))
        avg = int(l_stats.get('avg',0))
        p75 = int(l_stats.get('p75',0))
        mx = int(l_stats.get('max',0))
        emp = l_stats.get('empty',0)
        layout_map = l_stats.get('layout_map', [])
        
        is_outlier = (mx > p75 * 3) and (mx > 200)
        
        cards_html = f"""
        <div style="display:grid; grid-template-columns: repeat(7, 1fr); gap:4px; width:100%; margin-bottom:8px;">
            {micro_card("Total", cnt, f"{emp} Empty Lines")}
            {micro_card("Min", int(mn), "Minimum Width")}
            {micro_card("P25", int(p25), "Lower Quartile")}
            {micro_card("Median", int(p50), "Median Width")}
            {micro_card("Mean", int(avg), "Average Width")}
            {micro_card("P75", int(p75), "Upper Quartile")}
            {micro_card("Max", int(mx), "Maximum Width", is_outlier)}
        </div>
        """
        
        # Stacked Mass Map
        map_segments = []
        for seg in layout_map:
            width_style = f"width:{seg['w']}%;"
            # Fix invisible segments by ensuring min-width if percent is tiny but not zero
            if seg['w'] > 0 and seg['w'] < 1: width_style = "width:1%; flex-grow:1;"
            map_segments.append(f'<div style="{width_style} background:{seg["c"]}; height:100%;" title="Line Mass Segment"></div>')
            
        map_html = f"""
        <div style="display:flex; height:8px; border-radius:3px; overflow:hidden; border:1px solid #e2e8f0; width:100%; background:#f8fafc;">
            {''.join(map_segments)}
        </div>
        <div style="font-size:0.6rem; color:#9ca3af; margin-top:2px; display:flex; justify-content:space-between;">
            <span>File Start</span> <span>Visual Mass Distribution (Line Lengths)</span> <span>File End</span>
        </div>
        """
            
        rows.append(make_row("Layout Physics", cards_html + map_html, "", 
            ("LAYOUT TOPOLOGY", 
             "Statistical shape of line lengths. Varied: Standard Prose/Code. Uniform: Fixed-width data. Extreme Outliers (>3x P90): Minified JS, Base64 blobs, or Attacks.", 
             "Strict Newline Split", 
             "Map shows length density from start to end.")))

    # 7. Phonotactics (8 Cards + Stacked Bar)
    ph = stats.get("phonotactics", {})
    if ph.get("is_valid", False):
        ratio = ph.get('vowel_ratio', 0.0)
        v_cnt = ph.get('v_count', 0)
        c_cnt = ph.get('c_count', 0)
        
        # N-Gram & Entropy Metrics
        bits = ph.get('bits_per_phoneme', 0)
        uni = ph.get('uni_score', 0)
        bi = ph.get('bi_score', 0)
        tri = ph.get('tri_score', 0)
        
        total_lets = v_cnt + c_cnt
        v_pct = (v_cnt / total_lets * 100) if total_lets else 0
        c_pct = 100 - v_pct
        
        # Letter Density
        total_chars = max(1, stats.get("entropy_n", 1))
        density_val = round((total_lets / total_chars) * 100, 1)

        # 8-Card Grid (4x2 layout)
        cards_html = f"""
        <div style="display:grid; grid-template-columns: repeat(4, 1fr); gap:6px; width:100%; margin-bottom:8px;">
            {micro_card("V/C Ratio", ratio, "Target: ~0.40")}
            {micro_card("Vowels", v_cnt, "Count (A,E,I,O,U)")}
            {micro_card("Consonants", c_cnt, "Count (B,C,D...)")}
            {micro_card("Letter Dens.", f"{density_val}%", "of total file")}
            
            {micro_card("Bits/Phoneme", bits, "Letter Entropy")}
            {micro_card("Unigram Score", f"{uni}%", "Common Letters")}
            {micro_card("Bigram Score", f"{bi}%", "Common Pairs")}
            {micro_card("Trigram Score", f"{tri}%", "Common Triples")}
        </div>
        """
        
        bar_html = f"""
        <div style="display:flex; height:6px; border-radius:3px; overflow:hidden; border:1px solid #e2e8f0; width:100%;">
            <div style="width:{v_pct}%; background:#86efac;"></div>
            <div style="width:{c_pct}%; background:#475569;"></div>
        </div>
        <div style="display:flex; gap:12px; font-size:0.65rem; color:#64748b; margin-top:4px;">
            <span style="display:flex; align-items:center; gap:4px;"><span style="width:6px; height:6px; border-radius:50%; background:#86efac;"></span> Vowels ({int(v_pct)}%)</span>
            <span style="display:flex; align-items:center; gap:4px;"><span style="width:6px; height:6px; border-radius:50%; background:#475569;"></span> Consonants ({int(c_pct)}%)</span>
        </div>
        """
        
        rows.append(make_row("ASCII Phonotactics", cards_html + bar_html, "", 
            ("PHONOTACTIC BALANCE", 
             "Measures the Vowel/Consonant rhythm of Latin letters. Natural English stabilizes ~40% vowels. Low ratio (<20%) indicates consonant-heavy machine code, Base64, or random keys. High ratio (>60%) indicates vowel-heavy padding or non-English structure.", 
             "Vowels / Total Letters", 
             "Natural: 0.35-0.50 | Machine: <0.20 | High: >0.60 | NOTE: ASCII Only. Not a language classifier.")))
    # 8. Structural Anomalies (The "Participants" List)
    z_parts = stats.get("zalgo_participants", [])
    
    if z_parts:
        z_chips = []
        
        # SVG Definitions
        svg_crit = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M8.5 14.5A2.5 2.5 0 0 0 11 12c0-1.38-.5-2-1-3-1.072-2.143-.224-4.054 2-6 .5 2.5 2 4.9 4 6.5 2 1.6 3 3.5 3 5.5a7 7 0 1 1-14 0c0-1.1.2-2.2.6-3a1 1 0 0 1 .9 2.5z"></path></svg>'
        svg_warn = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>'
        svg_ghost = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 10h.01"></path><path d="M15 10h.01"></path><path d="M12 2a8 8 0 0 0-8 8v12l3-3 2.5 2.5L12 19l2.5 2.5L17 19l3 3V10a8 8 0 0 0-8-8z"></path></svg>'

        for p in z_parts:
            # Color coding by severity
            border = "#e2e8f0"; bg = "#f8fafc"; txt = "#64748b"; icon_svg = svg_warn
            
            if p['severity'] == 'crit':
                border = "#fecaca"; bg = "#fef2f2"; txt = "#dc2626"; icon_svg = svg_crit
            elif p['severity'] == 'warn':
                border = "#fed7aa"; bg = "#fff7ed"; txt = "#9a3412"; icon_svg = svg_warn
            elif p['severity'] == 'ghost':
                border = "#e9d5ff"; bg = "#faf5ff"; txt = "#7e22ce"; icon_svg = svg_ghost
            
            # Label with TYPE and MARKS
            # e.g. "Invisible Stack (3)" or "Heavy Stack (16)"
            lbl = f"Index {p['idx']} <b>{p['type']} ({p['marks']})</b>"
            
            # Action: Highlight using TRUE LOGICAL INDEX
            chip_html = (
                f'<button onclick="window.TEXTTICS_HIGHLIGHT_CODEPOINT({p["idx"]})"'
                f' style="background:{bg}; border:1px solid {border}; color:{txt}; padding:2px 8px; '
                f' border-radius:4px; margin:0 4px 4px 0; font-size:0.7rem; cursor:pointer; font-family:var(--font-mono); display:inline-flex; align-items:center; gap:6px;">'
                f'{icon_svg} {lbl}</button>'
            )
            z_chips.append(chip_html)
            
        chips_container = f'<div style="display:flex; flex-wrap:wrap; width:100%;">{"".join(z_chips)}</div>'
        
        # Update Row Description
        desc_logic = "Count(Mn) > 2 OR (Count(Mn) > 0 AND Base=Invisible)"
        
        rows.append(make_row("Structural Anomalies", chips_container, "",
            ("CLUSTER PHYSICS", 
             f"List of grapheme clusters exceeding structural limits. Includes both visible rendering noise ('Zalgo') and invisible data stacking (Steganography risk).",
             desc_logic,
             "Participants sorted by stack height.")))
             
    container.innerHTML = "".join(rows)
    # --- APPEND CONSOLE & LEGEND (Outside Table) ---
    # We find the parent details element to append this to the bottom
    parent_details = container.closest("details")
    if parent_details:
        # Check if console already exists to prevent duplicate append on re-render
        existing_console = parent_details.querySelector(".stat-console-strip")
        if existing_console: existing_console.remove()
        existing_legend = parent_details.querySelector(".stat-legend-details")
        if existing_legend: existing_legend.remove()

        console_html = """
        <div id="stat-console-strip" class="stat-console-strip">
            <div class="stat-console-left"><span id="stat-console-label" class="sc-main-label">READY</span><span id="stat-console-desc">Hover metrics for forensic context.</span></div>
            <div class="stat-console-right"><div><span class="sc-key">LOGIC:</span> <span id="stat-console-logic">--</span></div><div><span class="sc-key">NORM:</span> <span id="stat-console-norm">--</span></div></div>
        </div>
        <details class="stat-legend-details">
            <summary class="stat-legend-summary">Forensic Metric Guide</summary>
            <div class="stat-legend-content" style="display:grid; grid-template-columns: repeat(3, 1fr); gap:20px;">
                
                <div class="sl-col">
                    <strong>Thermodynamics (Entropy)</strong>
                    <div class="sl-item"><b>Logic:</b> Measures unpredictability per byte.</div>
                    <div class="sl-item"><b>High (>6.5):</b> Compressed, Encrypted, or Binary.</div>
                    <div class="sl-item"><b>Mid (4.5-6.0):</b> Code, Base64, or Complex Scripts.</div>
                </div>

                <div class="sl-col">
                    <strong>Lexical Density (TTR)</strong>
                    <div class="sl-item"><b>Logic:</b> Unique Tokens / Total Tokens.</div>
                    <div class="sl-item"><b>Note:</b> Naturally drops as text gets longer.</div>
                    <div class="sl-item"><b>&lt; 0.20:</b> Machine repetition or keyword flooding.</div>
                </div>

                <div class="sl-col">
                    <strong>Top Tokens (Flooding)</strong>
                    <div class="sl-item"><b>Logic:</b> Zipf's Law Analysis.</div>
                    <div class="sl-item"><b>Flooding:</b> A single token consuming >30% of the text is a strong anomaly (Log padding or SEO attacks).</div>
                </div>

                <div class="sl-col">
                    <strong>Freq. Fingerprint</strong>
                    <div class="sl-item"><b>Peaked:</b> Uneven distribution (e.g. 'e' is 12%) suggests Natural Language.</div>
                    <div class="sl-item"><b>Flat:</b> Uniform distribution suggests Ciphertext or Random Generation.</div>
                </div>

                <div class="sl-col">
                    <strong>Layout Physics</strong>
                    <div class="sl-item"><b>P90 Width:</b> 90% of lines are shorter than this.</div>
                    <div class="sl-item"><b>Outlier:</b> Max Width > 3x P90 indicates minified code, data URI injection, or abnormal formatting.</div>
                </div>

                <div class="sl-col">
                    <strong>ASCII Phonotactics</strong>
                    <div class="sl-item"><b>Scope:</b> Latin A-Z only. Ignored for other scripts.</div>
                    <div class="sl-item"><b>Natural:</b> Ratio 0.35 - 0.50 (approx 40% vowels).</div>
                    <div class="sl-item"><b>Machine:</b> Ratio < 0.20 (Base64, Hex, Keys).</div>
                </div>

            </div>
        </details>
        """
        
        # Append HTML
        div = document.createElement("div")
        div.innerHTML = console_html
        parent_details.appendChild(div)

# Adversarial & Threat Renderers

def render_predictive_normalizer(t: str):
    """
    Generates a Comparative Table showing the future state of the text
    under all 4 Unicode Normalization Forms.
    """
    if not t: return ""
    
    # Limit processing for performance (first 100 chars sufficient for diagnostic)
    sample = t[:100]
    
    forms = {
        "NFC": unicodedata.normalize("NFC", sample),
        "NFD": unicodedata.normalize("NFD", sample),
        "NFKC": unicodedata.normalize("NFKC", sample),
        "NFKD": unicodedata.normalize("NFKD", sample)
    }
    
    # Check for changes
    changes = {k: (v != sample) for k, v in forms.items()}
    
    if not any(changes.values()):
        return "" # No visual report needed if stable

    rows = []
    for form, val in forms.items():
        is_changed = changes[form]
        
        # Highlight dangerous changes
        # (Simple heuristic: length change or ascii shift)
        row_class = "pred-row"
        if is_changed:
            row_class += " pred-changed"
            # Check for high-risk injections in the result
            if any(c in val for c in ["'", "<", ">", "\\"]) and not any(c in sample for c in ["'", "<", ">", "\\"]):
                row_class += " pred-danger"
        
        val_display = _escape_html(val)
        # Visualizing changes (simple diff style)
        if is_changed:
            val_display = f"<strong>{val_display}</strong>"
            
        rows.append(f"""
        <tr class="{row_class}">
            <td class="pred-form">{form}</td>
            <td class="pred-val">{val_display}</td>
            <td class="pred-len">{len(val)}</td>
        </tr>
        """)

    return f"""
    <div class="predictive-wrapper">
        <div class="pred-header">🔮 Predictive Normalization (Future State)</div>
        <table class="pred-table">
            <thead>
                <tr>
                    <th>Form</th>
                    <th>Result (Preview)</th>
                    <th>Len</th>
                </tr>
            </thead>
            <tbody>
                {''.join(rows)}
            </tbody>
        </table>
        <div class="pred-footer">
            <strong>Analysis:</strong> Text mutates under normalization. 
            <span class="pred-danger-text">Red rows</span> indicate potential injection artifacts appearing after processing.
        </div>
    </div>
    """

def render_adversarial_xray(t: str, threat_indices: set, confusables_map: dict) -> str:
    """
    The Skeleton Overlay (X-Ray).
    Renders a vertical alignment of 'Raw' vs 'Skeleton' for suspicious clusters.
    Replaces the linear stream with a comparative 'DNA alignment' view.
    """
    if not t or not threat_indices: return ""

    js_array = window.Array.from_(t)
    text_len = len(js_array)
    
    # --- 1. CLUSTERING (Sparse View Logic) ---
    sorted_threats = sorted(list(threat_indices))
    clusters = []
    MERGE_DIST = 40 # Context window
    
    if sorted_threats:
        current_cluster = [sorted_threats[0]]
        for i in range(1, len(sorted_threats)):
            if sorted_threats[i] - sorted_threats[i-1] <= MERGE_DIST:
                current_cluster.append(sorted_threats[i])
            else:
                clusters.append(current_cluster)
                current_cluster = [sorted_threats[i]]
        clusters.append(current_cluster)

    # --- 2. RENDER CLUSTERS ---
    html_parts = []
    
    for idx, clust in enumerate(clusters):
        start_idx = clust[0]
        end_idx = clust[-1]
        
        # Context padding
        ctx_start = max(0, start_idx - 8)
        ctx_end = min(text_len, end_idx + 9)
        
        # Build the Alignment Strip
        strip_html = []
        
        for i in range(ctx_start, ctx_end):
            char = js_array[i]
            cp = ord(char)
            
            # --- ADVERSARIAL ALIGNMENT LOGIC ---
            # 1. Get Skeleton Target
            # Handle the tuple format from data loader: (target, type)
            val = confusables_map.get(cp)
            if val:
                skel_target = val[0] if isinstance(val, tuple) else val
            else:
                skel_target = char
                
            # 2. Check for "Drift" (Attack Signal)
            # If Raw != Skeleton, it's a visual spoof point.
            # EXCEPTION: Ignore Case Drift (A -> a) to reduce noise.
            is_drift = (char != skel_target) and (char.lower() != skel_target)
            
            # 3. Check for Invisibles (Obfuscation Signal)
            mask = INVIS_TABLE[cp] if cp < 1114112 else 0
            is_invis = bool(mask & INVIS_ANY_MASK)
            
            # 4. Construct CSS Classes
            col_class = "xray-col"
            if is_invis:
                col_class += " xray-void" # Collapsed or dimmed
                skel_target = "∅"       # Explicitly show nullification
            elif is_drift:
                col_class += " xray-drift" # Red highlight
            
            # 5. Visual Safe-Guards
            # Escape HTML to prevent injection from the text itself
            vis_top = _escape_html(char)
            vis_bot = _escape_html(skel_target)
            
            # Handle Control Pictures for unprintables
            if cp in INVISIBLE_MAPPING:
                vis_top = f"<span class='x-tag'>{INVISIBLE_MAPPING[cp]}</span>"
            elif is_invis:
                vis_top = "<span class='x-tag'>[HID]</span>"
            
            # 6. Render Column
            strip_html.append(f"""
            <div class="{col_class}" title="U+{cp:04X} &rarr; {vis_bot}">
                <div class="x-raw">{vis_top}</div>
                <div class="x-skel">{vis_bot}</div>
            </div>
            """)
            
        # Cluster Card Wrapper
        html_parts.append(f"""
        <div class="xray-cluster">
            <div class="xray-meta">Context #{idx+1}</div>
            <div class="xray-strip">
                {"".join(strip_html)}
            </div>
        </div>
        """)

    if not html_parts: return ""
    
    return f"""
    <div class="xray-container">
        <div class="xray-legend-bar">
            <span class="xl-item"><span class="xl-dot dot-red"></span> Visual Drift</span>
            <span class="xl-item"><span class="xl-dot dot-gray"></span> Hidden/Stripped</span>
        </div>
        {"".join(html_parts)}
    </div>
    """

def _render_forensic_diff_stream(t: str, confusable_indices: set, invisible_indices: set, bidi_indices: set, confusables_map: dict) -> str:
    """
    Forensic X-Ray Engine v9.0 (The Ultimate Restoration).
    - Features: Bidi Grouping (x8), Rich Script Tags (Cyr->Lat), Detailed Tooltips.
    - Style: Classic Stream (Cards/Stacks).
    """
    if not t: return ""
    
    all_threats = sorted(list(confusable_indices | invisible_indices | bidi_indices))
    if not all_threats: return ""

    js_array = window.Array.from_(t)
    text_len = len(js_array)
    
    # 1. Clustering
    clusters = []
    MERGE_DIST = 40 
    if all_threats:
        current_cluster = [all_threats[0]]
        for i in range(1, len(all_threats)):
            if all_threats[i] - all_threats[i-1] <= MERGE_DIST:
                current_cluster.append(all_threats[i])
            else:
                clusters.append(current_cluster)
                current_cluster = [all_threats[i]]
        clusters.append(current_cluster)

    cluster_html_list = []
    total_exec = 0; total_spoof = 0; total_obfus = 0
    prev_end = 0
    
    for idx, clust in enumerate(clusters):
        cluster_id = f"cluster-{idx}"
        
        # Stats
        c_exec = 0; c_spoof = 0; c_obfus = 0
        for p in clust:
            if p in bidi_indices: c_exec += 1; total_exec += 1
            if p in confusable_indices: c_spoof += 1; total_spoof += 1
            if p in invisible_indices: c_obfus += 1; total_obfus += 1

        cluster_badges = []
        if c_exec > 0: cluster_badges.append(f'<span class="cluster-badge badge-bidi">{c_exec} EXECUTION</span>')
        if c_spoof > 0: cluster_badges.append(f'<span class="cluster-badge badge-spoof">{c_spoof} SPOOF</span>')
        if c_obfus > 0: cluster_badges.append(f'<span class="cluster-badge badge-invis">{c_obfus} OBFUSCATE</span>')

        start_idx = clust[0]; end_idx = clust[-1]
        ctx_start = max(0, start_idx - 10)
        ctx_end = min(text_len, end_idx + 11)
        
        if ctx_start > prev_end:
            gap = ctx_start - prev_end
            if gap > 0:
                cluster_html_list.append(f'<div class="xray-spacer">[ ... {gap} safe characters omitted from this slice ... ]</div>')
        
        cluster_html_parts = []
        safe_string_parts = []
        
        i = ctx_start
        while i < ctx_end:
            char = js_array[i]
            cp = ord(char)
            
            # Safe String
            if i in invisible_indices or i in bidi_indices: pass 
            elif i in confusable_indices:
                skel = confusables_map.get(cp, char)
                safe_string_parts.append(skel)
            else:
                safe_string_parts.append(char)

            char_vis = _escape_html(char)
            if char == '\n': char_vis = '<span class="xray-control">↵</span>'
            elif char == '\r': char_vis = '<span class="xray-control">↵</span>'
            elif char == '\t': char_vis = '<span class="xray-control">⇥</span>'
            
            safe_wrapper = f'<span class="xray-safe">{char_vis}</span>'

            # 1. BIDI Grouping
            if i in bidi_indices:
                run_len = 1
                lookahead = i + 1
                while lookahead < ctx_end and lookahead in bidi_indices:
                    run_len += 1
                    lookahead += 1
                
                label = f"&times;{run_len}" if run_len > 1 else "&harr;"
                title = f"{run_len} Bidi Controls (Execution Risk)"
                
                marker = (
                    f'<span class="xray-stack stack-bidi" tabindex="0" title="{title}">'
                    f'<span class="xray-top" style="color:#d97706;">{label}</span>'
                    f'<span class="xray-bot">BIDI</span></span>'
                )
                cluster_html_parts.append(marker)
                i += run_len
                continue

            # 2. INVISIBLE Grouping
            elif i in invisible_indices:
                run_len = 1
                lookahead = i + 1
                while lookahead < ctx_end and lookahead in invisible_indices and lookahead not in bidi_indices:
                    run_len += 1
                    lookahead += 1
                
                label = f"×{run_len}" if run_len > 1 else "&bull;"
                title = f"{run_len} Hidden Characters" if run_len > 1 else "Hidden Character"
                
                marker = (
                    f'<span class="xray-stack stack-invis" tabindex="0" title="{title}">'
                    f'<span class="xray-top">{label}</span>'
                    f'<span class="xray-bot">HID</span></span>'
                )
                cluster_html_parts.append(marker)
                i += run_len
                continue

            # 3. SPOOFING (Rich Restoration)
            elif i in confusable_indices:
                skel = confusables_map.get(cp, "?")
                disp_skel = skel[0] if skel else "?"
                
                # Script Tag Logic
                script_tag = ""
                src_sc = "Unknown"; dst_sc = "Unknown"
                try:
                    src_sc = _find_in_ranges(cp, "Scripts") or "Com"
                    dst_sc = _find_in_ranges(ord(skel[0]), "Scripts") or "Com" if skel else "Com"
                    if src_sc != dst_sc and src_sc not in ("Common", "Inherited") and dst_sc not in ("Common", "Inherited"):
                        s_abbr = src_sc[:3]; d_abbr = dst_sc[:3]
                        script_tag = f'<span class="xray-script-tag">{s_abbr}&rarr;{d_abbr}</span>'
                except: pass

                # Rich Tooltip
                safe_cp_display = f"U+{ord(skel[0]):04X}" if skel else "?"
                title_safe = (
                    f"Spoofing Risk&#10;"
                    f"Raw: {_escape_html(char)} (U+{cp:04X}, {src_sc})&#10;"
                    f"Safe: {_escape_html(skel)} ({safe_cp_display}, {dst_sc})"
                )
                
                stack = (
                    f'<span class="xray-stack stack-spoof" tabindex="0" title="{title_safe}">'
                    f'<span class="xray-top">{_escape_html(char)}</span>'
                    f'<span class="xray-bot">{_escape_html(disp_skel)}</span>'
                    f'{script_tag}'
                    f'</span>'
                )
                cluster_html_parts.append(stack)
                i += 1
            
            else:
                cluster_html_parts.append(safe_wrapper)
                i += 1

        safe_str_js = _escape_for_js("".join(safe_string_parts))
        safe_str_attr = _escape_html(safe_str_js)
        
        card = f"""
        <div class="cluster-card" id="{cluster_id}">
            <div class="cluster-header">
                <div class="cluster-meta">
                    <span class="cluster-id">#{idx + 1}</span>
                    {"".join(cluster_badges)}
                </div>
                <button class="safe-copy-btn" onclick="window.TEXTTICS_COPY_SAFE('{safe_str_attr}', this)">Copy Safe Slice</button>
            </div>
            <div class="cluster-body">{"".join(cluster_html_parts)}</div>
        </div>
        """
        cluster_html_list.append(card)
        prev_end = ctx_end

    # Summary
    summary_parts = []
    def make_badge(count, label, color_class):
        return f'<span class="{color_class}"><strong>{count}</strong> {label}</span>' if count else ""

    if total_exec: summary_parts.append(make_badge(total_exec, "Execution", "stat-exec"))
    if total_spoof: summary_parts.append(make_badge(total_spoof, "Spoofing", "stat-spoof"))
    if total_obfus: summary_parts.append(make_badge(total_obfus, "Obfuscation", "stat-obfus"))
    
    summary_text = ", ".join(summary_parts)
    
    legend_html = (
        '<div class="xray-legend">'
        '<span class="xray-legend-item"><span class="xray-dot dot-bidi"></span><strong>EXECUTION:</strong> Bidi/Control (BIDI)</span>'
        '<span class="xray-legend-item"><span class="xray-dot dot-spoof"></span><strong>SPOOFING:</strong> Homoglyphs (SPOOF)</span>'
        '<span class="xray-legend-item"><span class="xray-dot dot-invis"></span><strong>OBFUSCATION:</strong> Hidden/Zero-Width (HID)</span>'
        '</div>'
    )

    return "".join([
        f'<div class="xray-summary-bar">',
        f'<span class="xray-summary-title">Forensic Scan:</span>',
        f'{summary_text} across <strong>{len(clusters)}</strong> active clusters.',
        f'</div>',
        '<div class="xray-stream-wrapper">',
        "".join(cluster_html_list),
        '</div>',
        legend_html
    ])

def render_adversarial_dashboard(report):
    """
    Renders the 'Adversarial Intelligence' Profile.
    Displays Skeleton Collisions and Per-Token Risk Analysis.
    """
    container = document.getElementById("adversarial-dashboard-body")
    if not container: return

    if not report or not report.get("tokens"):
        container.innerHTML = '<div class="empty-state">No identifier-like tokens detected.</div>'
        return

    tokens = report["tokens"]
    collisions = report["collisions"]
    stats = report["stats"]

    # --- Part A: The Metrics Bar ---
    # We define a mini-dashboard for this specific profile
    
    # CSS helper for badges
    def _get_risk_class(level):
        if level == "CRITICAL": return "badge-crit"
        if level == "HIGH": return "badge-high"
        if level == "MED": return "badge-warn"
        return "badge-ok"

    html_parts = []

    # 1. Summary Header
    summary_html = f"""
    <div class="adversarial-stats">
        <div class="stat-box">
            <span class="stat-label">Total Tokens</span>
            <span class="stat-val">{stats['total']}</span>
        </div>
        <div class="stat-box">
            <span class="stat-label">Identifiers</span>
            <span class="stat-val">{stats['identifiers']}</span>
        </div>
        <div class="stat-box">
            <span class="stat-label">Domains/IDs</span>
            <span class="stat-val">{stats['domains']}</span>
        </div>
        <div class="stat-box {'stat-alarm' if stats['collisions'] > 0 else ''}">
            <span class="stat-label">Collisions</span>
            <span class="stat-val">{stats['collisions']}</span>
        </div>
        <div class="stat-box {'stat-alarm' if stats['high_risk'] > 0 else ''}">
            <span class="stat-label">High Risk</span>
            <span class="stat-val">{stats['high_risk']}</span>
        </div>
    </div>
    """
    html_parts.append(summary_html)

    # --- 2. Skeleton Collisions (The Homograph Radar) ---
    if collisions:
        rows = []
        for c in collisions:
            # Format variants: "paypal" vs "pаypal"
            variants_html = []
            for idx in c["indices"]:
                # Safety check for index out of bounds
                if idx < len(tokens):
                    tok = tokens[idx]
                    # Bridge link to highlight the specific token
                    click_js = f"window.opener.TEXTTICS_HIGHLIGHT_SEGMENT({tok['span'][0]}, {tok['span'][1]});"
                    variants_html.append(f'<a href="#" onclick="{click_js} return false;" class="variant-link">{_escape_html(tok["text"])}</a>')
            
            rows.append(f"""
            <tr class="collision-row">
                <td class="mono-cell">{_escape_html(c['skeleton'])}</td>
                <td class="variant-cell">{' vs '.join(variants_html)}</td>
                <td><span class="badge badge-crit">SPOOF DETECTED</span></td>
            </tr>
            """)
        
        html_parts.append(f"""
        <div class="collision-section">
            <h4 class="sub-header-crit">🚨 Skeleton Collisions (Active Homograph Vectors)</h4>
            <table class="matrix collision-table">
                <thead><tr><th>UTS #39 Skeleton</th><th>Conflicting Tokens (Variants)</th><th>Verdict</th></tr></thead>
                <tbody>{''.join(rows)}</tbody>
            </table>
        </div>
        """)

    # --- 3. Token Risk Ledger (The Detail View) ---
    # Filter: Show all High/Med, but limit Lows if there are too many
    display_tokens = [t for t in tokens if t["risk"] in ("CRITICAL", "HIGH", "MED")]
    low_tokens = [t for t in tokens if t["risk"] == "LOW"]
    
    # Simple pagination logic for "Low" risk noise
    hidden_count = 0
    if len(low_tokens) > 10:
        display_tokens.extend(low_tokens[:10])
        hidden_count = len(low_tokens) - 10
    else:
        display_tokens.extend(low_tokens)
        
    # Sort: Critical -> High -> Med -> Low
    risk_order = {"CRITICAL": 0, "HIGH": 1, "MED": 2, "LOW": 3}
    display_tokens.sort(key=lambda x: risk_order.get(x["risk"], 3))

    if display_tokens:
        token_rows = []
        for t in display_tokens:
            risk_cls = _get_risk_class(t["risk"])
            
            # Scripts pill
            scripts_str = ", ".join(t["scripts"]) if t["scripts"] else "Common"
            script_cls = "script-mixed" if t["is_mixed"] else "script-single"
            
            # Issues/Triggers
            triggers_html = ""
            if t["triggers"]:
                triggers_html = "<br>".join([f"<span class='trigger-tag'>{rule}</span>" for rule in t["triggers"]])
            elif t["kind"] == "identifier":
                triggers_html = "<span class='trigger-tag-ok'>Standard Syntax</span>"
            else:
                triggers_html = "<span class='trigger-tag-neutral'>No Anomalies</span>"
                
            # Bridge Link
            click_js = f"window.opener.TEXTTICS_HIGHLIGHT_SEGMENT({t['span'][0]}, {t['span'][1]});"
            
            token_rows.append(f"""
            <tr>
                <td class="token-cell">
                    <a href="#" onclick="{click_js} return false;" class="token-link">{_escape_html(t['text'])}</a>
                    <div class="token-kind">{t['kind']}</div>
                </td>
                <td class="risk-cell"><span class="badge {risk_cls}">{t['risk']}</span></td>
                <td class="script-cell"><span class="{script_cls}">{scripts_str}</span></td>
                <td class="skel-cell">{_escape_html(t['skeleton'])}</td>
                <td class="issue-cell">{triggers_html}</td>
            </tr>
            """)

        html_parts.append(f"""
        <div class="token-ledger">
            <h4 class="sub-header">Token Risk Ledger</h4>
            <table class="matrix token-table">
                <thead>
                    <tr>
                        <th style="width:20%">Token</th>
                        <th style="width:10%">Risk</th>
                        <th style="width:15%">Scripts</th>
                        <th style="width:20%">Skeleton</th>
                        <th style="width:35%">Forensic Notes</th>
                    </tr>
                </thead>
                <tbody>{''.join(token_rows)}</tbody>
            </table>
            {f'<div class="table-footer">... {hidden_count} low-risk tokens hidden ...</div>' if hidden_count > 0 else ''}
        </div>
        """)
    else:
        # Fallback if no tokens worth showing (rare, but good safety)
        html_parts.append('<div class="empty-state">No significant identifiers found.</div>')

    container.innerHTML = "".join(html_parts)

def render_threat_analysis(threat_results, text_context=None):
    """Renders the Group 3 Threat-Hunting results."""
    
    flags = threat_results.get('flags', {})
    html_rows = []
    threat_level_key = "Threat Level (Heuristic)"
    
    if threat_level_key in flags:
        data = flags[threat_level_key]
        badge = data.get("badge", "")
        severity = data.get("severity", "ok")
        
        # Data from the Threat Auditor
        ledger = data.get("ledger", [])
        noise = data.get("noise", [])
        
        badge_class = f"integrity-badge integrity-badge-{severity}"
        
        # --- LEDGER GENERATION (3-Column) ---
        ledger_html = ""
        if ledger:
            ledger_rows = ""
            for item in ledger:
                # Map Category to Severity Class
                cat = item['category'].upper()
                sev_class = "ok"
                if cat in ("EXECUTION", "SPOOFING"):
                    sev_class = "crit"
                elif cat in ("OBFUSCATION"):
                    sev_class = "warn"
                elif cat in ("SUSPICIOUS", "SYNTAX"):
                    sev_class = "warn"
                
                p_val = f"+{item['points']}"
                
                ledger_rows += (
                    f"<tr>"
                    f"<td>{item['vector']}</td>"
                    f"<td><span class='integrity-badge integrity-badge-{sev_class}' style='font-size:0.7em'>{cat}</span></td>"
                    f"<td class='score-val'>{p_val}</td>"
                    f"</tr>"
                )
            
            # Add Noise (Zero-score items)
            if noise:
                 for n in noise:
                     ledger_rows += (
                         f"<tr class='ledger-noise'>"
                         f"<td>{n}</td>"
                         f"<td><span class='integrity-badge integrity-badge-ok' style='font-size:0.7em'>NOISE</span></td>"
                         f"<td class='score-val'>0</td>"
                         f"</tr>"
                     )

            ledger_html = f"""
            <details class="threat-ledger-details">
                <summary>View Penalty Breakdown</summary>
                <table class="threat-ledger-table">
                    <thead><tr><th>Vector</th><th>Severity</th><th>Penalty</th></tr></thead>
                    <tbody>{ledger_rows}</tbody>
                </table>
            </details>
            """
        else:
            ledger_html = "No active threats detected."

        row_html = (
            f'<tr class="flag-row-{severity}" style="border-bottom: 2px solid var(--color-border);">'
            f'<th scope="row" style="font-weight:700; font-size:1.05em;">{threat_level_key}</th>'
            f'<td><span class="{badge_class}" style="font-size:0.9em;">{badge}</span></td>'
            f'<td>{ledger_html}</td>'
            f'</tr>'
        )
        html_rows.append(row_html)
        
        flags_copy = flags.copy()
        del flags_copy[threat_level_key]
        flags = flags_copy
    
    # Pass text_context to the matrix renderer
    render_matrix_table(flags, "threat-report-body", has_positions=True, text_context=text_context)
    
    if html_rows:
        existing_html = document.getElementById("threat-report-body").innerHTML
        document.getElementById("threat-report-body").innerHTML = "".join(html_rows) + existing_html

    # Hashes
    hashes = threat_results.get('hashes', {})
    hash_html = []
    if hashes:
        for k, v in hashes.items():
            hash_html.append(f'<tr><th scope="row">{k}</th><td>{v}</td></tr>')
        document.getElementById("threat-hash-report-body").innerHTML = "".join(hash_html)
    else:
        document.getElementById("threat-hash-report-body").innerHTML = '<tr><td colspan="2" class="placeholder-text">No data.</td></tr>'

    # HTML Report (PVR)
    html_report = threat_results.get('html_report', "")
    report_el = document.getElementById("confusable-diff-report")
    
    if html_report:
        report_el.innerHTML = html_report
    else:
        drift_flag = flags.get("Flag: Skeleton Drift")
        drift_count = drift_flag.get("count", 0) if drift_flag else 0
        msg = "No lookalike confusables; differences come from invisibles, format controls, or normalization." if drift_count > 0 else "No confusable runs detected; raw, NFKC, and skeleton are effectively aligned."
        report_el.innerHTML = f'<p class="placeholder-text">{msg}</p>'
    
    # --- DRIFT REPORT LOGIC (Populates the "Analyzing..." section) ---
    drift_details = document.getElementById("drift-report-details")
    summary_header = document.getElementById("drift-summary-header")
    
    if drift_details and summary_header:
        # Use 'threat_results', NOT 'results'
        drift = threat_results.get('drift_info', {})
        
        # Safety: If analysis skipped/crashed, prevent UI freeze
        if not drift:
            drift = {'class': 'drift-alert', 'verdict': 'Data Missing'}
            
        states = threat_results.get('states', {})
        s1_val = states.get('s1', 'N/A')
        s4_val = states.get('s4', 'N/A')

        # 1. Update the Side-by-Side Text
        s1_el = document.getElementById("disp-state-1")
        s4_el = document.getElementById("disp-state-4")
        if s1_el: s1_el.textContent = s1_val
        if s4_el: s4_el.textContent = s4_val
        
        # 2. Update Header Icon & Color
        icon = "✅"
        d_class = drift.get('class', 'drift-clean')
        if d_class == "drift-alert": icon = "🚨"
        elif d_class == "drift-warn": icon = "⚠️"
        
        verdict = drift.get("verdict", "Unknown")
        summary_header.innerHTML = f'<span class="drift-status-icon">{icon}</span> <span class="drift-status-text">{verdict}</span>'
        summary_header.className = f"drift-summary {d_class}"
        
        # 3. Auto-Expand if Threat
        if d_class == "drift-clean":
            drift_details.removeAttribute("open")
        else:
            drift_details.setAttribute("open", "true")
    
    banner_el = document.getElementById("threat-banner")
    if banner_el: banner_el.setAttribute("hidden", "true")

# The Inspector

def render_inspector_panel(data):
    """
    Forensic Layout v10.0: Synchronized Visuals & Fluid Matrix.
    Fixes 'vis_state' error by correctly using unpacked data dictionaries.
    """
    panel = document.getElementById("inspector-panel-content")
    if not panel: return

    if data is None:
        panel.innerHTML = "<div class='inspector-placeholder'>Click within the text input. Properties will be shown for the character immediately to the right of the cursor.</div>"
        return
        
    if "error" in data:
        panel.innerHTML = f"<p class='status-error'>{data['error']}</p>"
        return

    # --- CALL THE LOGIC ENGINE ---
    state = analyze_signal_processor_state(data)
    
    # --- UNPACK FACETS (The Data Dictionaries) ---
    vis_data = state['facets'][0]
    struct_data = state['facets'][1]
    ident_data = state['facets'][2]

    # --- ICON COLOR SYNCHRONIZATION ---
    # Determine master color based on Header Class
    header_cls = state['header_class']
    
    if header_cls == "header-baseline":
        global_icon_color = "#15803D" # Green-700
    elif header_cls == "header-complex":
        global_icon_color = "#0369A1" # Sky-700
    elif header_cls == "header-anomalous":
        global_icon_color = "#A16207" # Yellow-700
    elif header_cls == "header-suspicious":
        global_icon_color = "#C2410C" # Orange-700
    elif header_cls == "header-critical":
        global_icon_color = "#DC2626" # Red-600
    else:
        global_icon_color = "#6B7280" # Slate-500

    # --- HTML GENERATION ---

    # Zone A: The Verdict Header
    icon_svg = get_icon(state['icon_key'], color="currentColor", size=14)
    risk_header_html = f"""
        <div class="risk-header {state['header_class']}">
            <div class="risk-header-top">
                <span class="risk-header-icon">{icon_svg}</span>
                <span class="risk-level-text">{state['level_text']}</span>
            </div>
            <div class="risk-verdict-text">{state['verdict_text']}</div>
        </div>
    """

    # Zone B: The Diagnostic Matrix
    # Uses 'f_data' dicts (vis_data, etc) instead of raw variables
    def build_row(label, f_data, master_color):
        svg = get_icon(f_data['icon'], color=master_color, size=14)
        
        return f"""
        <div class="risk-row">
            <div class="risk-facet">
                <span class="facet-icon">{svg}</span>
                <span class="facet-label">{label}</span>
            </div>
            <div class="risk-cell-right">
                <div class="risk-status {f_data['class']}">{f_data['state']}</div>
                <div class="risk-detail">{f_data['detail']}</div>
            </div>
        </div>
        """

    matrix_html = f"""
        <div class="risk-matrix">
            {build_row("VISIBILITY", vis_data, global_icon_color)}
            {build_row("STRUCTURE", struct_data, global_icon_color)}
            {build_row("IDENTITY", ident_data, global_icon_color)}
        </div>
    """

    # Zone C: The Footer
    footer_html = ""
    if state['level'] >= 1 and state['footer_text']:
        footer_html = f"""
        <div class="risk-footer">
            <div class="risk-footer-label {state['footer_class']}">{state['footer_label']}</div>
            <div class="risk-footer-content">{state['footer_text']}</div>
        </div>
        """
    elif state['level'] == 0:
        footer_html = f"""
        <div class="risk-footer">
            <div class="risk-footer-label footer-neutral">ANALYSIS</div>
            <div class="risk-footer-content">Standard Composition</div>
        </div>
        """
    
    # Assemble Column 4
    signal_processor_content = risk_header_html + footer_html + matrix_html

    # --- COL 5: IDENTITY (Clean Header V6) ---
    
    # 1. Header Title (Full Name)
    # Prioritize the specific name unless it's a multi-part cluster
    if data.get('is_cluster') and len(data.get('components', [])) > 1:
        header_title = "GRAPHEME CLUSTER"
        header_style = "letter-spacing: 0.05em; color: #4b5563;" 
    else:
        header_title = data['name_base']
        header_style = ""

    # 2. Get Global Forensic Context (The Truth Source)
    active_threats = []
    try:
        if hasattr(window, 'TEXTTICS_CORE_DATA') and window.TEXTTICS_CORE_DATA:
            global_flags = window.TEXTTICS_CORE_DATA.to_py().get('forensic_flags', {})
            current_idx = data.get('python_idx')
            if current_idx is not None:
                idx_marker = f"#{current_idx}"
                for flag_name, flag_data in global_flags.items():
                    raw_positions = flag_data.get('positions', [])
                    if any(p == idx_marker or p.startswith(idx_marker + " ") or p.startswith(idx_marker + ",") for p in raw_positions):
                        name_lower = flag_name.lower()
                        if "zalgo" in name_lower or "mark" in name_lower: active_threats.append("STACK")
                        elif "bidi" in name_lower: active_threats.append("BIDI")
                        elif "invisible" in name_lower: active_threats.append("HIDDEN")
                        elif "confusable" in name_lower or "drift" in name_lower: active_threats.append("SPOOF")
                        elif "rot" in name_lower or "corrupt" in name_lower or "replacement" in name_lower: active_threats.append("ROT")
                        elif "tag" in name_lower: active_threats.append("TAG")
                        elif "restricted" in name_lower: active_threats.append("RESTRICTED")
                        else: active_threats.append("RISK")
    except Exception: pass

    # 3. Extract Macro Type (CRITICAL FIX: Define 'mt' here)
    mt = data['macro_type']

    # 4. Top Grid (Identity Specs)
    type_label = data.get('type_label', 'CATEGORY')
    type_val = data.get('type_val', data['category_full'])
    
    identity_grid = f"""
        <div class="spec-matrix" style="margin-top: 0.5rem; margin-bottom: 0.5rem;">
            <div class="matrix-item">
                <span class="spec-label">BLOCK</span>
                <span class="matrix-val" style="font-size: 0.75rem; font-weight: 600; color: #374151;">{data['block']}</span>
            </div>
            <div class="matrix-item">
                <span class="spec-label">SCRIPT</span>
                <span class="matrix-val" style="font-size: 0.75rem; font-weight: 600; color: #374151;">
                    {data['script']}
                    <span class="matrix-sub" style="display:inline;">{f"({data['script_ext']})" if data.get('script_ext') and not data.get('is_cluster') else ""}</span>
                </span>
            </div>
            <div class="matrix-item">
                <span class="spec-label">{type_label}</span>
                <span class="matrix-val" style="font-size: 0.75rem; font-weight: 600; color: #374151;">{type_val}</span>
            </div>
            <div class="matrix-item">
                <span class="spec-label">AGE</span>
                <span class="matrix-val" style="font-size: 0.75rem; font-weight: 600; color: #374151;">{data['age']}</span>
            </div>
        </div>
    """

    # 5. Bottom Grid (Technical Specs)
    matrix_extra_cell = ""
    if mt in ("THREAT", "ROT", "SYNTAX", "LEGACY"):
        status_cls = "id-status-restricted"
        if data['id_status'] == "Allowed": status_cls = "id-status-allowed"
        if mt == "SYNTAX": status_cls = "id-status-technical"
        matrix_extra_cell = f"""
            <div class="matrix-item">
                <span class="spec-label">SECURITY</span>
                <span class="matrix-val {status_cls}">{data['id_status']}</span>
            </div>
        """
    else:
        matrix_extra_cell = f"""
            <div class="matrix-item">
                <span class="spec-label">SECURITY</span>
                <span class="matrix-val id-status-allowed">{data['id_status']}</span>
            </div>
        """

    technical_grid = f"""
        <div class="spec-matrix">
            <div class="matrix-item">
                <span class="spec-label">DIRECTION</span>
                <span class="matrix-val">{data['bidi']}</span>
            </div>
            <div class="matrix-item">
                <span class="spec-label">SEGMENT</span>
                <span class="matrix-val">{data['word_break']}</span>
                <span class="matrix-sub">{data['grapheme_break']}</span>
            </div>
            <div class="matrix-item">
                <span class="spec-label">WRAP</span>
                <span class="matrix-val">{data['line_break']}</span>
            </div>
            {matrix_extra_cell}
        </div>
    """

    # 6A. Lookalikes Section (Risk-Synchronized)
    lookalike_html = ""
    if data.get('lookalikes_data'):
        count = len(data['lookalikes_data'])
        
        # Build the grid of chips
        chips_buffer = []
        for item in data['lookalikes_data']:
            tooltip = f"{item['name']} &#10;Block: {item['block']}"
            chip = f"""
            <div class="lookalike-chip" title="{tooltip}">
                <span class="lk-glyph">{item['glyph']}</span>
                <span class="lk-meta">
                    <span class="lk-cp">{item['cp']}</span>
                    <span class="lk-script">{item['script']}</span>
                </span>
            </div>
            """
            chips_buffer.append(chip)
            
        grid_html = "".join(chips_buffer)
        
        # Inherit the color class from the Identity Risk Facet
        # ident_data['class'] will be 'risk-info' (Blue), 'risk-warn' (Orange), etc.
        risk_css = ident_data['class'] 
        
        lookalike_html = f"""
        <div class="ghost-section lookalikes {risk_css}" style="margin-top: 10px; margin-bottom: -4px; flex-direction: column; gap: 4px;">
            <span class="ghost-key">LOOKALIKES ({count})</span>
            <div class="lookalike-grid">
                {grid_html}
            </div>
        </div>
        """
    else:
        # Optional: Show "Unique" if you want it strictly constant
        # For now, keeping it cleaner by hiding if none exist, 
        # but if you want it strictly constant, uncomment below:
        # lookalike_html = f"""
        # <div class="ghost-section lookalikes" style="margin-top: 10px; margin-bottom: -4px; border-color: #e5e7eb;">
        #     <span class="ghost-key" style="color:#9ca3af">LOOKALIKES:</span>
        #     <span class="lookalike-list" style="color:#9ca3af">None (Unique)</span>
        # </div>
        # """
        pass

    
    # 6B. Normalization Ghosts (Always Show if Data Exists)
    ghost_html = ""
    if data['ghosts']:
        g = data['ghosts']
        ghost_html = f"""
        <div class="ghost-section">
            <div class="spec-label" style="margin-bottom:4px;">NORMALIZATION GHOSTS</div>
            <div class="ghost-strip">
                <div class="ghost-step">RAW<br><span>{_escape_html(g['raw'])}</span></div>
                <div class="ghost-arrow">→</div>
                <div class="ghost-step">NFKC<br><span>{_escape_html(g['nfkc'])}</span></div>
                <div class="ghost-arrow">→</div>
                <div class="ghost-step">SKEL<br><span>{_escape_html(g['skeleton'])}</span></div>
            </div>
        </div>
        """
    else:
        # CLEAN HTML: No inline styles. Classes control the colors.
        ghost_html = f"""
        <div class="ghost-section stable">
            <span class="ghost-key">NORMALIZATION:</span>
            <span class="ghost-val-ok">STABLE</span>
        </div>
        """

    # 7. Final Assembly (NO CHIPS)
    identity_html = f"""
        <div class="inspector-header" title="{header_title}" style="{header_style}">{header_title}</div>
        
        {identity_grid}
        {technical_grid}
        {lookalike_html}
        {ghost_html}
    """

    # --- COL 6: COMPONENTS TABLE ---
    comp_rows = ""
    for c in data['components']:
        ccc_val = c.get('ccc', 0)
        ccc_display = f'<span style="color:#9ca3af;">0</span>' if ccc_val == 0 else f'<b>{ccc_val}</b>'
        is_mark_style = 'style="color: var(--color-text-muted);"' if not c['is_base'] else 'style="font-weight:600;"'
        
        comp_rows += f"""
        <tr {is_mark_style}>
            <td><code class="mini-code">{c['hex']}</code></td>
            <td style="text-align:center;">{c['cat']}</td>
            <td style="text-align:center;">{ccc_display}</td>
            <td class="truncate-text" title="{c['name']}">{c['name']}</td>
        </tr>
        """

    # --- FINAL HTML ASSEMBLY ---
    prev_vis = _escape_html(data['prev_glyph']) if data['prev_glyph'] else "&nbsp;"
    curr_vis = _escape_html(data['cluster_glyph'])
    next_vis = _escape_html(data['next_glyph']) if data['next_glyph'] else "&nbsp;"

    # [VISUAL SYNC] Inject the calculated risk level (0-4) as a CSS class
    tier_class = f"risk-tier-{state['level']}"

    html = f"""
    <div class="inspector-layout-v3">
        <div class="col-context col-prev">
            <div class="ctx-label">PREV</div>
            <div class="ctx-glyph">{prev_vis}</div>
        </div>
        <div class="col-target">
            <div class="glyph-viewport">
                <div class="inspector-glyph">{curr_vis}</div>
            </div>
            <div class="inspector-codepoint {tier_class}">{data['cp_hex_base']}</div>
        </div>
        <div class="col-context col-next">
            <div class="ctx-label">NEXT</div>
            <div class="ctx-glyph">{next_vis}</div>
        </div>
        
        <div class="col-signal-processor">
            {signal_processor_content}
        </div>
        
        <div class="col-identity">
            {identity_html}
        </div>

        <div class="col-structure">
            <div class="section-label">
                CLUSTER COMPONENTS
                <span style="display:block; font-weight:600; opacity:0.99; font-size:0.7rem; margin-top:2px;">
                    ({len(data['components'])} PARTICLE{'S' if len(data['components']) != 1 else ''})
                </span>
            </div>
            <div class="structure-table-wrapper">
                <table class="structure-table">
                    <thead>
                        <tr>
                            <th>CP</th>
                            <th style="text-align:center;">Cat</th>
                            <th style="text-align:center;" title="Canonical Combining Class">CCC</th>
                            <th>Name</th>
                        </tr>
                    </thead>
                    <tbody>{comp_rows}</tbody>
                </table>
            </div>
        </div>
        
        <div class="col-bytes">
            <div class="section-label">FORENSIC ENCODINGS</div>
            <div class="byte-grid">
                <div class="byte-row"><span class="label">UTF-8:</span>{data['utf8']}</div>
                <div class="byte-row"><span class="label">UTF-16:</span>{data['utf16']}</div>
                <div class="byte-row"><span class="label">UTF-32:</span>{data['utf32']}</div>
                <div class="byte-row">
                    <span class="label">ASCII:</span>
                    <span style="color:{'#dc2626' if data['ascii'] == 'N/A' else '#16a34a'}; font-weight:700;">{data['ascii']}</span>
                </div>
                <div class="byte-row">
                    <span class="label">Latin-1:</span>
                    <span style="color:{'#dc2626' if data['latin1'] == 'N/A' else '#16a34a'}; font-weight:700;">{data['latin1']}</span>
                </div>
                <div class="byte-row">
                    <span class="label">Win-1252:</span>
                    <span style="color:{'#dc2626' if data['cp1252'] == 'N/A' else '#16a34a'}; font-weight:700;">{data['cp1252']}</span>
                </div>
                
                <div class="section-label" style="margin-bottom:4px; color:#374151; margin-top: 8px;">EXPLOIT VECTORS</div>
                
                <div class="byte-row"><span class="label">Base64:</span>{data['base64']}</div>
                <div class="byte-row"><span class="label">Shell:</span>{_escape_html(data['shell'])}</div>
                <div class="byte-row"><span class="label">Octal:</span>{_escape_html(data['octal'])}</div>
                <div class="byte-row"><span class="label">HTML Dec:</span>{_escape_html(data['html_dec'])}</div>
                <div class="byte-row"><span class="label">HTML Hex:</span>{_escape_html(data['html_hex'])}</div>
                <div class="byte-row"><span class="label">ES6/CSS:</span>{_escape_html(data['es6'])}</div>
                <div class="byte-row"><span class="label">Py/JSON:</span>{_escape_html(data['code'])}</div>
            </div>
        </div>
    </div>
    """
    panel.innerHTML = html
    
    try:
        window.TEXTTICS_CENTER_GLYPH()
    except Exception:
        pass

def render_adversarial_dashboard(adv_data: dict):
    """
    Renders the 'Suspicion Dashboard' (Adversarial Forensics).
    V6 COMPLIANT: Consumes 'targets' and 'topology' from the Engine.
    Targets 'adv-*' IDs.
    """
    # 1. Safety Check
    container = document.getElementById("adv-console")
    if not container: return

    if not adv_data:
        container.style.display = "none"
        return

    # 2. Reveal Console
    container.style.display = "block"
    
    # 3. Unpack Data (V6 Structure)
    # The Engine produces 'targets' (list) and 'topology' (dict)
    targets = adv_data.get("targets", [])
    topology = adv_data.get("topology", {})
    stego = adv_data.get("stego")
    restriction = adv_data.get("restriction", "UNKNOWN")
    badge_class = adv_data.get("badge_class", "intel-badge-safe")

    # 4. Render Seal
    badge = document.getElementById("adv-badge")
    if badge:
        badge.className = f"intel-badge {badge_class}"
        badge.innerText = restriction

    # 5. Render Scoreboard
    # Safe setter helper
    def set_text(id_str, val):
        el = document.getElementById(id_str)
        if el: el.innerText = str(val)

    set_text("adv-stat-homoglyph", topology.get("AMBIGUITY", 0))
    set_text("adv-stat-spoofing", topology.get("SPOOFING", 0))
    set_text("adv-stat-obfus", topology.get("HIDDEN", 0))
    total_injection = topology.get("SYNTAX", 0) + topology.get("INJECTION", 0)
    set_text("adv-stat-injection", total_injection)
    
    # 6. Render Peak Row (Top Offender)
    peak_row = document.getElementById("adv-peak-row")
    if peak_row:
        if targets:
            peak = targets[0]
            peak_row.style.display = "flex"
            
            set_text("adv-peak-token", peak['token'])
            set_text("adv-peak-score", f"Risk: {peak['score']}/100")
            
            # Extract reasons from the stack
            # Stack items are dicts: {'desc': '...', 'lvl': '...', 'type': '...'}
            reasons = []
            if 'stack' in peak:
                reasons = [item['desc'] for item in peak['stack'][:3]]
            
            reasons_html = "".join([f"<span class='peak-tag'>{r}</span>" for r in reasons])
            
            el_reasons = document.getElementById("adv-peak-reasons")
            if el_reasons: el_reasons.innerHTML = reasons_html
        else:
            peak_row.style.display = "none"

    # 7. Render Findings List (Enhanced with Domain Intel)
    target_body = document.getElementById("adv-target-body")
    if target_body:
        html_rows = []
        
        # A. Global Stego Banner (Existing)
        if stego:
            html_rows.append(f"""
            <div class="target-row" style="background-color:#fffbeb;">
                <div class="t-head">
                    <span class="th-badge th-med">STEGO</span>
                    <span class="t-token">GLOBAL PATTERN</span>
                    <span class="t-verdict">{stego.get('verdict', 'Pattern Detected')}</span>
                </div>
                <div style="font-size:0.75rem; color:#b45309; padding-top:4px; font-family:var(--font-mono);">{stego['detail']}</div>
            </div>
            """)

        # B. Token Findings
        for tgt in targets:
            # Build Stack HTML
            stack_html = ""
            is_typosquatting = False
            
            for item in tgt.get('stack', []):
                lvl_class = "th-low"
                lvl = item.get('lvl', 'LOW')
                if lvl == "CRIT": lvl_class = "th-crit"
                elif lvl == "HIGH": lvl_class = "th-high"
                elif lvl == "MED": lvl_class = "th-med"
                
                # Check for Domain Heuristics
                if "Double Extension" in item['desc'] or "Pseudo-Delimiters" in item['desc'] or "Bidi Arrears" in item['desc']:
                    is_typosquatting = True
                
                stack_html += f"""
                <div class="th-row">
                    <span class="th-badge {lvl_class}">{item['type']}</span>
                    <span class="th-desc">{item['desc']}</span>
                </div>
                """

            # Special styling for Typosquatting
            row_style = ""
            if is_typosquatting:
                row_style = "border-left: 4px solid #d97706; background-color: #fffaf0;"

            row = f"""
            <div class="target-row" style="{row_style}">
                <div class="t-head">
                    <span class="th-badge th-crit" style="margin-right:8px; font-size:0.7em;">{tgt['score']}</span>
                    <span class="t-token">{_escape_html(tgt['token'])}</span>
                    <span class="t-verdict" style="margin-left:auto; color:#6b7280; font-size:0.85em;">{tgt['verdict']}</span>
                </div>
                
                <details class="intel-details">
                    <summary class="intel-summary">View Threat Hierarchy ({len(tgt.get('stack', []))})</summary>
                    <div class="intel-stack-body">
                        {stack_html}
                        <div class="t-vectors">
                            <div class="vec-item"><span class="v-lbl">B64:</span> <code class="v-val">{tgt.get('b64', 'N/A')}</code></div>
                            <div class="vec-item"><span class="v-lbl">HEX:</span> <code class="v-val">{tgt.get('hex', 'N/A')}</code></div>
                        </div>
                    </div>
                </details>
            </div>
            """
            html_rows.append(row)
            
        if not html_rows:
            target_body.innerHTML = '<div class="placeholder-text" style="padding:12px;">No adversarial anomalies detected.</div>'
        else:
            target_body.innerHTML = "".join(html_rows)

@create_proxy
def render_forensic_hud(t, stats):
    """
    Unified Forensic HUD (V3 Final - Fixed Titles).
    Restores correct Scientific Category Titles (e.g., 'ALPHANUMERIC' instead of 'LITERALS').
    """
    container = document.getElementById("forensic-hud")
    if not container: return 
    if t is None: t = ""
    
    # 1. Init Data
    emoji_counts = stats.get("emoji_counts", {})
    master_ledgers = stats.get("master_ledgers", {})
    is_initial = (len(t) == 0)

    # --- ICONS (V5: Clear & Non-Confusable) ---
    VERDICT_ICONS = {
        # Integrity (Shield + Checkmark - Unchanged)
        "integrity": (
            '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>'
            '<path d="M9 12l2 2 4-4"></path>'
        ),

        # Authenticity (ID Card + Checkmark)
        # Metaphor: Verified Identity / Profile
        "authenticity": (
            '<rect x="3" y="5" width="18" height="14" rx="2" ry="2"></rect>'
            '<circle cx="9" cy="11" r="2"></circle>'
            '<path d="M6.5 16a3.5 3.5 0 0 1 5 0"></path>'
            '<path d="M14 15l2 2 3-4"></path>'
        ),

        # Threat (Tactical Double Target - V6)
        # Metaphor: Weapon System Lock-on (Precision)
        "threat": (
            '<circle cx="12" cy="12" r="8"></circle>'       # Outer Ring
            '<circle cx="12" cy="12" r="3.5"></circle>'     # Inner Ring (Lock)
            '<line x1="12" y1="2" x2="12" y2="5"></line>'   # Top Tick
            '<line x1="12" y1="19" x2="12" y2="22"></line>' # Bottom Tick
            '<line x1="2" y1="12" x2="5" y2="12"></line>'   # Left Tick
            '<line x1="19" y1="12" x2="22" y2="12"></line>' # Right Tick
        ),

        # Anomaly (Histogram + Outlier)
        # Metaphor: Statistical Deviation (Distinct from Health)
        "anomaly": (
            '<path d="M3 19h18"></path>'              # Baseline
            '<path d="M7 19v-3"></path>'              # Normal bar
            '<path d="M12 19v-8"></path>'             # Spike bar
            '<path d="M17 19v-5"></path>'             # Normal bar
            '<circle cx="12" cy="6" r="1.5"></circle>' # Outlier dot
            '<path d="M12 11v-3"></path>'             # Connector line
        )
    }
    def get_svg(key):
        return f'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">{VERDICT_ICONS.get(key, "")}</svg>'
    def esc(s): return s.replace('"', '&quot;')

    # --- INTERACTION HELPER ---
    def get_interaction(val, key, severity="warn"):
        try:
            if float(val) <= 0: return "", ""
        except: return "", ""
        
        if key in HUD_HIT_REGISTRY and HUD_HIT_REGISTRY[key]:
            cls = " hud-interactive"
            if severity == "crit": cls += " hud-interactive-crit"
            elif severity == "warn": cls += " hud-interactive-risk"
            attr = f'onclick="window.hud_jump(\'{key}\')"'
            return cls, attr
        return "", ""

    # --- CELL BUILDER ---
    def r_cell(sci_title, label_1, val_1, class_1, label_2, val_2, class_2,
               d1="", k1="", v1="", rk1="", rv1="", # Primary Meta
               d2="", k2="", v2="", rk2="", rv2="", # Secondary Meta
               reg_key_2=None, risk_2="warn"):
        
        int_cls, int_attr = get_interaction(val_2, reg_key_2, risk_2) if reg_key_2 else ("", "")

        data_attrs = f'data-l1="{esc(label_1)}" data-d1="{esc(d1)}" data-k1="{esc(k1)}" data-v1="{esc(v1)}" data-rk1="{esc(rk1)}" data-rv1="{esc(rv1)}"' \
                     f' data-l2="{esc(label_2)}" data-d2="{esc(d2)}" data-k2="{esc(k2)}" data-v2="{esc(v2)}" data-rk2="{esc(rk2)}" data-rv2="{esc(rv2)}"'

        return f"""
        <div class="hud-col" {data_attrs}>
            <div class="hud-row-sci">{sci_title}</div>
            <div class="hud-metric-group">
                <div class="hud-label">{label_1}</div>
                <div class="hud-val {class_1}">{val_1}</div>
            </div>
            <div class="hud-metric-divider"></div>
            <div class="hud-metric-group">
                <div class="hud-label">{label_2}</div>
                <div class="hud-val {class_2}{int_cls}" {int_attr}>{val_2}</div>
            </div>
        </div>
        """

    # --- HERO ROW RENDERER (Physics vs. Policy Update) ---
    def r_ledger_row(title, type_key, data, hit_count, agg_key):
        if is_initial:
            sev, score, verdict, items = "neutral", 0, "WAITING", []
            click_attr = ""
        else:
            sev = data.get("severity", "ok")
            score = data.get("score", 0)
            verdict = data.get("verdict", "INTACT")
            items = data.get("ledger", []) if "ledger" in data else data.get("vectors", [])
            
            target_ids = {
                "integrity": "integrity-matrix-body", 
                "threat": "threat-report-body", 
                "authenticity": "adversarial-dashboard-body", 
                "anomaly": "statistical-profile-body"
            }
            t_id = target_ids.get(type_key)
            click_attr = f'onclick="window.hud_jump_to_details(\'{t_id}\')"' if t_id else ""

        # [UX] Dynamic Labeling for "Policy Score"
        # "Risk" implies danger. "Defects" implies brokenness.
        # This clarifies why a score can be 0 even if count > 0.
        score_label = "Risk Score"
        if type_key == "integrity": score_label = "Defect Score"
        elif type_key == "anomaly": score_label = "Deviation"
        
        # --- Interactive Counter Logic (Physics) ---
        counter_html = '<span class="interactive-count">-</span>'
        if hit_count > 0:
            risk_cls = " crit" if sev in ("crit", "high", "danger") else ""
            counter_html = f'<span class="interactive-count active{risk_cls}" onclick="event.stopPropagation(); window.hud_jump(\'{agg_key}\')">{hit_count}</span>'
        elif not is_initial:
             counter_html = '<span class="interactive-count">0</span>'

        meta = {
            "integrity":    {"d": "Measures physical health.", "k": "LOGIC", "v": "Base + Density", "rk": "STD", "rv": "Unicode Core Spec"},
            "authenticity": {"d": "Verifies identity.",        "k": "LOGIC", "v": "Skeleton Drift", "rk": "STD", "rv": "UTS #39"},
            "threat":       {"d": "Detects weaponization.",    "k": "LOGIC", "v": "Attack Patterns", "rk": "REF", "rv": "TRAPDOC"},
            "anomaly":      {"d": "Analyzes physics.",         "k": "LOGIC", "v": "Entropy / Zalgo", "rk": "REF", "rv": "Heuristic"}
        }
        m = meta.get(type_key, {})
        
        data_attrs = f'data-l1="{esc(title)} STATUS" data-d1="{esc(m.get("d",""))}" data-k1="{esc(m.get("k",""))}" data-v1="{esc(m.get("v",""))}" data-rk1="{esc(m.get("rk",""))}" data-rv1="{esc(m.get("rv",""))}"' \
                     f' data-l2="IMPACT ANALYSIS" data-d2="Detailed penalty breakdown." data-k2="AUDITOR" data-v2="{title} Engine" data-rk2="SCOPE" data-rv2="{title}"'

        icon = get_svg(type_key)
        
        # --- CHIPS LOGIC (Clarified) ---
        chips = ""
        if is_initial: 
            chips = '<span class="hud-chip chip-dim">System Ready</span>'
        elif items:
            # Case A: Active Threats (Policy > 0)
            c_list = [f'<span class="hud-chip chip-{sev}">{i["vector"] if isinstance(i, dict) else i}</span>' for i in items[:5]]
            chips = "".join(c_list)
        elif hit_count > 0:
            # Case B: Physics Detected, Policy Ignored
            # [UX] Explicitly label these as "Benign" or "Noise" to explain the 0 Score
            ghost_labels = []
            if agg_key == "anomaly_agg":
                if HUD_HIT_REGISTRY.get("phys_zalgo"): ghost_labels.append("Zalgo Clusters")
                if HUD_HIT_REGISTRY.get("phys_entropy"): ghost_labels.append("High Entropy")
                if HUD_HIT_REGISTRY.get("phys_weird"): ghost_labels.append("Structural Noise")
            elif agg_key == "authenticity_agg":
                if HUD_HIT_REGISTRY.get("auth_spoof"): ghost_labels.append("Homoglyphs")
                if HUD_HIT_REGISTRY.get("auth_mixed"): ghost_labels.append("Mixed Script")
            elif agg_key == "integrity_agg":
                if HUD_HIT_REGISTRY.get("int_fracture"): ghost_labels.append("Fracture")
                if HUD_HIT_REGISTRY.get("int_fatal"): ghost_labels.append("Corrupt Data")
            
            if not ghost_labels: ghost_labels.append("Signals")

            # Render Neutral Chips with "Benign" context
            c_list = [f'<span class="hud-chip chip-neutral" style="opacity:0.75; border:1px solid #cbd5e1; color:#475569;">{label} (Benign)</span>' for label in ghost_labels]
            chips = "".join(c_list)
        else:
            chips = '<span class="hud-chip chip-dim">No active signals.</span>'

        # [UX] The "Dual-Score" Visual Layout
        # Left: Policy (Risk Score)
        # Center: Physics (Signal Count)
        return f"""
        <div class="hud-detail-row border-{sev}" {click_attr} {data_attrs}>
            <div class="hud-detail-left bg-{sev}">
                <div class="h-icon-box text-{sev}">{icon}</div>
                <div class="h-meta">
                    <div class="h-title text-{sev}">{title}</div>
                    <div class="h-verdict text-{sev}">{verdict}</div>
                    <div class="h-score text-{sev}" style="font-weight:650; font-size:0.7rem; margin-top:2px;" title="Policy Verdict (Calculated Impact)">{score_label}: {score}</div>
                </div>
            </div>
            <div class="hud-detail-center" title="Physics Measurement (Raw Count)">
                <div style="font-size:0.6rem; color:#94a3b8; margin-bottom:-2px; font-weight:600; letter-spacing:0.5px;">SIGNALS</div>
                {counter_html}
            </div>
            <div class="hud-detail-right">{chips}</div>
        </div>
        """

    # --- COLOR LOGIC ---
    def color_neutral(val): return "txt-muted" if float(val) == 0 else "txt-normal"
    def color_clean(val): return "txt-clean" if float(val) == 0 else "txt-warn"
    
    # --- MATH & ASSEMBLY ---
    alpha_chars = sum(1 for c in t if c.isalnum())
    alpha_runs = 0; in_run = False
    for c in t:
        if c.isalnum():
            if not in_run: alpha_runs += 1; in_run = True
        else: in_run = False
        
    # [FIXED] Scientific Titles Restored
    c0 = r_cell("ALPHANUMERIC", "LITERALS", str(alpha_chars), color_neutral(alpha_chars),
                "RUNS", str(alpha_runs), color_neutral(alpha_runs),
                d1="Count of Unicode alphanumeric characters.", k1="LOGIC", v1="Count(Alnum)", rk1="REF", rv1="Unicode L+N",
                d2="Contiguous runs of alphanumeric characters.", k2="LOGIC", v2="Count(Runs)", rk2="REF", rv2="Pattern Alnum+")

    L = stats.get('major_stats', {}).get("L (Letter)", 0)
    N = stats.get('major_stats', {}).get("N (Number)", 0)
    vu = (L + N) / 5.0
    uax_word = 0; uax_sent = 0
    try:
        c = window.TEXTTICS_CALC_UAX_COUNTS(t)
        if c[0] != -1: uax_word, uax_sent = c[0], c[1]
    except: pass
    
    c1 = r_cell("LEXICAL MASS", "UNITS", f"{vu:.1f}", color_neutral(vu),
                "WORDS", str(uax_word), color_neutral(uax_word),
                d1="Normalized text mass.", k1="CALC", v1="(L+N)/5.0", rk1="REF", rv1="Heuristic",
                d2="Linguistic word count.", k2="CALC", v2="Intl.Segmenter", rk2="STD", rv2="UAX #29")

    seg_est = vu / 20.0
    c2 = r_cell("SEGMENTATION", "BLOCKS", f"{seg_est:.2f}", color_neutral(seg_est),
                "SENTENCES", str(uax_sent), color_neutral(uax_sent),
                d1="Structural units estimate.", k1="CALC", v1="VU / 20.0", rk1="REF", rv1="1 Block=20VU",
                d2="Linguistic sentence count.", k2="CALC", v2="Intl.Segmenter", rk2="STD", rv2="UAX #29")

    std_inv = sum(1 for c in t if ord(c) in {0x20, 0x09, 0x0A, 0x0D})
    non_std_inv = stats.get('forensic_flags', {}).get("Flag: Any Invisible or Default-Ignorable (Union)", {}).get("count", 0)
    c3 = r_cell("WHITESPACE", "ASCII WS", str(std_inv), color_neutral(std_inv),
                "NON-STD", str(non_std_inv), color_clean(non_std_inv),
                d1="Basic layout characters.", k1="CLASS", v1="Layout", rk1="REF", rv1="ASCII",
                d2="Invisible characters.", k2="LOGIC", v2="ZWSP + Tags", rk2="RISK", rv2="Obfuscation",
                reg_key_2="ws_nonstd")

    cnt_p_ascii = 0; cnt_p_exotic = 0; cnt_p_comfort = 0
    for c in t:
        if unicodedata.category(c).startswith('P'):
            cp = ord(c)
            if cp <= 0x7F: cnt_p_ascii += 1
            elif (0xA0 <= cp <= 0xFF) or (0x2000 <= cp <= 0x206F): cnt_p_comfort += 1
            else: cnt_p_exotic += 1
    
    c4_label = "TYPOGRAPHIC" if cnt_p_comfort > 0 else "ASCII PUNC"
    c4_val = cnt_p_ascii + cnt_p_comfort
    c4 = r_cell("DELIMITERS", c4_label, str(c4_val), color_neutral(c4_val),
                "EXOTIC", str(cnt_p_exotic), color_clean(cnt_p_exotic),
                d1="Standard Punctuation.", k1="SCOPE", v1="ASCII+Common", rk1="CLASS", rv1="Punctuation",
                d2="Rare/Script Punctuation.", k2="SCOPE", v2="Exotic", rk2="RISK", rv2="Spoofing",
                reg_key_2="punc_exotic")

    s_ext = emoji_counts.get("text_symbols_extended", 0)
    s_exo = emoji_counts.get("text_symbols_exotic", 0)
    c5_label = "KEYBOARD" if s_ext == 0 and s_exo == 0 else "EXTENDED"
    c5 = r_cell("SYMBOLS", c5_label, str(s_ext), color_neutral(s_ext),
                "EXOTIC", str(s_exo), color_clean(s_exo),
                d1="Technical symbols.", k1="CLASS", v1="Symbol", rk1="REF", rv1="Non-Emoji",
                d2="Rare symbols.", k2="SCOPE", v2="Exotic", rk2="RISK", rv2="Unknown",
                reg_key_2="sym_exotic")

    h_pict = emoji_counts.get("hybrid_pictographs", 0)
    h_amb = emoji_counts.get("hybrid_ambiguous", 0)
    c6 = r_cell("HYBRIDS", "PICTOGRAPH", str(h_pict), color_neutral(h_pict),
                "AMBIGUOUS", str(h_amb), color_clean(h_amb),
                d1="Atomic Emoji.", k1="KIND", v1="Atomic", rk1="CLASS", rv1="Emoji",
                d2="Text-Default Emoji.", k2="CHECK", v2="Emoji_Pres=No", rk2="RISK", rv2="Rendering",
                reg_key_2="emoji_hybrid")

    rgi = emoji_counts.get("rgi_total", 0)
    irr = emoji_counts.get("emoji_irregular", 0)
    c7 = r_cell("EMOJI", "RGI SEQS", str(rgi), color_neutral(rgi),
                "IRREGULAR", str(irr), color_clean(irr),
                d1="Valid Sequences.", k1="STD", v1="UTS #51", rk1="REF", rv1="RGI",
                d2="Broken Sequences.", k2="LOGIC", v2="Flags", rk2="RISK", rv2="Render Failure",
                reg_key_2="emoji_irregular")

    # --- ASSEMBLY (With Deduplication Logic) ---
    row1 = f'<div class="hud-grid-row-1">{c0}{c1}{c2}{c3}{c4}{c5}{c6}{c7}</div>'
    
    # Helper: Calculates UNIQUE hits (Deduplication)
    def calc_agg(prefixes):
        if is_initial: return 0
        raw_hits = []
        for p in prefixes:
            raw_hits.extend(HUD_HIT_REGISTRY.get(p, []))
        
        # Deduplicate by start index (Matches Stepper Logic)
        seen_starts = set()
        unique_count = 0
        for hit in raw_hits:
            if hit[0] not in seen_starts:
                seen_starts.add(hit[0])
                unique_count += 1
        return unique_count

    # 1. Integrity: Fatal, Fracture, Risk, Decay
    cnt_int = calc_agg(["int_fatal", "int_fracture", "int_risk", "int_decay"])
    
    # 2. Authenticity: Spoofing, IDNA, Mixed Scripts
    # Note: 'thr_spoofing' and 'thr_suspicious' are moved here from Threat to fix the split.
    cnt_auth = calc_agg(["auth_spoof", "auth_mixed", "auth_idna", "thr_spoofing", "thr_suspicious"])
    
    # 3. Threat: Execution, Injection, Obfuscation
    # Note: Removed spoofing/suspicious to prevent double-counting 90 vs 47+43
    cnt_thr = calc_agg(["thr_execution", "thr_obfuscation"])
    
    # 4. Anomaly: Entropy, Zalgo
    cnt_ano = calc_agg(["phys_entropy", "phys_zalgo", "phys_weird"])

    rows = ""
    rows += r_ledger_row("INTEGRITY", "integrity", master_ledgers.get("integrity",{}), cnt_int, "integrity_agg")
    rows += r_ledger_row("AUTHENTICITY", "authenticity", master_ledgers.get("authenticity",{}), cnt_auth, "authenticity_agg")
    rows += r_ledger_row("THREAT", "threat", master_ledgers.get("threat",{}), cnt_thr, "threat_agg")
    rows += r_ledger_row("ANOMALY", "anomaly", master_ledgers.get("anomaly",{}), cnt_ano, "anomaly_agg")

    container.innerHTML = row1 + rows

@create_proxy
def render_verification_lens(suspect_str: str, trusted_str: str, analysis: dict) -> str:
    """
    [VP-16] Forensic Lens Renderer V1.1 (Threat-Aware X-Ray).
    
    Hardening Upgrades:
    1. Internal Threat Detection: Flags invisibles *inside* the match as threats, not just spoofs.
    2. Context-Aware Styling: Uses distinct styling for Normalization drift.
    
    Classes:
    - .f-anchor:         Visual Match (Safe).
    - .f-format:         Normalization drift (Amber).
    - .f-payload:        Homoglyph/Spoof (Red).
    - .f-threat-resid:   Cold Zone Threat (Tail Injection).
    - .f-threat-internal: Hot Zone Threat (Token Fracture/Injection).
    - .f-noise:          Unmatched Text.
    """
    if not analysis or not suspect_str: return ""

    match_start, match_end = analysis["lens_data"]["match_range"]
    overlap_pct = analysis["overlap_pct"]
    verdict_type = analysis["verdict"]
    
    html_parts = []
    
    # Pre-calc bitmask for threat highlighting
    MASK_THREAT = MASK_RESIDUAL_RISK | INVIS_VARIATION_SELECTOR
    
    curr_skel_idx = 0
    
    for char in suspect_str:
        # Generate atomic skeleton for position mapping
        c_skel = _generate_uts39_skeleton(normalize_extended(char).casefold())
        c_len = len(c_skel)
        
        # 1. Determine Position Logic
        is_in_hot_zone = False
        if overlap_pct > 0:
            if c_len == 0:
                # Invisible: Check strict containment in timeline
                if match_start <= curr_skel_idx < match_end:
                    is_in_hot_zone = True
            else:
                char_end = curr_skel_idx + c_len
                if curr_skel_idx >= match_start and char_end <= match_end:
                    is_in_hot_zone = True

        # 2. Forensic Classification
        vis_char = _escape_html(char)
        cp = ord(char)
        
        # Check for Threat Physics (O(1))
        is_physically_dangerous = False
        if cp < 1114112 and (INVIS_TABLE[cp] & MASK_THREAT):
            is_physically_dangerous = True

        if is_in_hot_zone:
            # --- HOT ZONE (Visual Match) ---
            if is_physically_dangerous:
                # CRITICAL: Invisible Weapon INSIDE the matched visual structure (Token Fracture)
                html_parts.append(f'<span class="f-threat-internal" title="Internal Injection / Fracture">{vis_char}</span>')
            elif char in trusted_str:
                # Exact byte match (Heuristic anchor)
                html_parts.append(f'<span class="f-anchor">{vis_char}</span>')
            else:
                # Visual match but Byte mismatch
                if verdict_type == "NORMALIZATION_EQ":
                    # It's just a format difference (e.g. NFC vs NFD)
                    html_parts.append(f'<span class="f-format" title="Normalization Drift">{vis_char}</span>')
                else:
                    # It's a Homoglyph
                    html_parts.append(f'<span class="f-payload" title="Homoglyph / Deviation">{vis_char}</span>')
        else:
            # --- COLD ZONE (Noise) ---
            if is_physically_dangerous:
                # Residual Threat in Tail/Head
                html_parts.append(f'<span class="f-threat-resid" title="Residual Threat">{vis_char}</span>')
            else:
                html_parts.append(f'<span class="f-noise">{vis_char}</span>')
        
        curr_skel_idx += c_len

    return "".join(html_parts)

# ===============================================
# BLOCK 10. INTERACTION & EVENTS (THE BRIDGE)
# ===============================================

# State Updaters

@create_proxy
def populate_hud_registry(t: str):
    """Populates simple metric buckets for the HUD Stepper."""
    js_array = window.Array.from_(t)
    
    for i, char in enumerate(js_array):
        cp = ord(char)
        mask = INVIS_TABLE[cp] if cp < 1114112 else 0
        
        # 1. Whitespace / Non-Std (C3)
        if mask & INVIS_ANY_MASK:
             label = "Non-Std"
             if mask & INVIS_NON_ASCII_SPACE: label = "Deceptive Space"
             elif mask & INVIS_DEFAULT_IGNORABLE: label = "Ignorable"
             elif mask & INVIS_BIDI_CONTROL: label = "Bidi Control"
             elif mask & INVIS_TAG: label = "Tag"
             
             _register_hit("ws_nonstd", i, i+1, f"{label} (U+{cp:04X})")

        # 2. Delimiters (C4)
        cat = unicodedata.category(char)
        if cat.startswith('P'):
            if not (cp <= 0xFF or (0x2000 <= cp <= 0x206F)):
                _register_hit("punc_exotic", i, i+1, f"Exotic Punct (U+{cp:04X})")

@create_proxy
def update_all(event=None):
    """The main function called on every input change."""

    # --- RESET REGISTRY (SAFE METHOD) ---
    HUD_HIT_REGISTRY.clear()

    # [IMMUTABLE REVEAL]
    t_input = document.getElementById("text-input")
    if t_input and t_input.classList.contains("reveal-active"):
        t_input.classList.remove("reveal-active")
    
    # RESET HUD STATUS BAR (Left Side)
    hud_status = document.getElementById("hud-stepper-status")
    if hud_status:
        hud_status.style.display = "none"
        hud_status.className = "status-details" 
        hud_status.innerHTML = ""

    t_input = document.getElementById("text-input")
    if not t_input: return
    t = t_input.value
    
    # --- [NEW] Populate Simple HUD Metrics ---
    populate_hud_registry(t)

    # --- 1.5 PASSIVE INVISIBLE SCAN (Right Side) ---
    details_line = document.getElementById("reveal-details")
    reveal_btn = document.getElementById("btn-reveal")
    reveal2_btn = document.getElementById("btn-reveal2")
    
    if details_line:
        counts = { "Format": 0, "Bidi": 0, "Tag": 0, "VS": 0 }
        total_invis = 0
        if t:
            for char in t:
                cp = ord(char)
                cat = None
                if cp in INVISIBLE_MAPPING:
                    rep = INVISIBLE_MAPPING[cp]
                    if "TAG" in rep: cat = "Tag"
                    elif any(x in rep for x in ["RLO","LRO","LRE","RLE","PDF","LRI","RLI","FSI","PDI","ALM","LRM","RLM"]): cat = "Bidi"
                    elif "VS" in rep: cat = "VS"
                    else: cat = "Format"
                elif 0xFE00 <= cp <= 0xFE0F or 0xE0100 <= cp <= 0xE01EF: cat = "VS"
                elif 0xE0000 <= cp <= 0xE007F: cat = "Tag"
                
                if cat:
                    counts[cat] += 1
                    total_invis += 1
                    
        if total_invis > 0:
            details_line.className = "status-details warn"
            icon_alert = """<svg style="display:inline-block; vertical-align:middle; margin-right:6px;" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#d97706" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>"""
            details_line.innerHTML = ( f"Non-Standard Invisibles:&nbsp;{total_invis}&nbsp;Found&nbsp;{icon_alert}" )
            if reveal_btn: reveal_btn.style.display = "flex"
            if reveal2_btn: reveal2_btn.style.display = "flex"
        else:
            details_line.className = "status-details clean"
            icon_check = """<svg style="display:inline-block; vertical-align:middle;" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>"""
            details_line.innerHTML = f"Non-Standard Invisibles: Not Found {icon_check}"
            is_revealed = t_input.classList.contains("reveal-active")
            if not is_revealed:
                if reveal_btn: reveal_btn.style.display = "none"
                if reveal2_btn: reveal2_btn.style.display = "none"
            
    # --- 1. Handle Empty Input (Reset UI) ---
    if not t:
        # Define empty stats for the reset state
        meta_cards = {
            "Total Graphemes": 0, "Total Code Points": 0, "UTF-16 Units": 0, "UTF-8 Bytes": 0,
            "Astral Count": 0, "RGI Emoji Sequences": 0, "Whitespace (Total)": 0,
            "Avg. Marks per Grapheme": 0, "Total Combining Marks": 0,  # <-- Hardcoded 0
            "ASCII-Compatible": None, "Latin-1-Compatible": None,
            "BMP Coverage": None, "Supplementary Planes": None
        }

        # [FORENSIC LAYOUT ENGINE: 2x2 + FLUID] ------------------------------------
        
        # 1. Define the Groups
        # Group A: The Quad (Top 4 Metrics)
        quad_keys = ["Total Graphemes", "Total Code Points", "UTF-16 Units", "UTF-8 Bytes"]
        
        # Group B: Context (Everything else)
        context_keys = [
            "RGI Emoji Sequences", "Whitespace (Total)",
            "ASCII-Compatible", "Latin-1-Compatible", "BMP Coverage", "Supplementary Planes"
        ]

        # 2. Render HTML Strings (Detached Mode)
        # We generate the card HTML but DO NOT inject it yet.
        html_quad = render_cards(meta_cards, element_id=None, key_order=quad_keys, return_html=True)
        html_context = render_cards(meta_cards, element_id=None, key_order=context_keys, return_html=True)

        # 3. Inject Structure (The Wrapper Divs)
        # We wrap the top group in 'cards-2x2' and the bottom in standard 'cards'
        full_html = f"""
        <div class="cards-2x2">{html_quad}</div>
        <div class="cards">{html_context}</div>
        """

        # 4. Final Injection
        document.getElementById("meta-totals-cards").innerHTML = full_html
        # --------------------------------------------------------------------------

        # Clear all other sections
        render_cards({}, "grapheme-integrity-cards")
        render_matrix_table({}, "ccc-matrix-body")
        render_parallel_table({}, {}, "major-parallel-body")
        render_parallel_table({}, {}, "minor-parallel-body", ALIASES)
        render_matrix_table({}, "shape-matrix-body")
        render_integrity_matrix([]) 
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
        render_forensic_hud("", {})
        render_invisible_atlas("")
        render_encoding_footprint("")
        render_adversarial_dashboard({})
        return

    # --- 2. Run All Computations ---

    # Emoji Engine
    emoji_report = compute_emoji_analysis(t)
    emoji_counts = emoji_report.get("counts", {})
    emoji_flags = emoji_report.get("flags", {})
    emoji_list = emoji_report.get("emoji_list", [])
    emoji_counts["RGI Emoji Sequences"] = emoji_counts.get("rgi_total", 0)
    
    cp_summary, cp_major, cp_minor = compute_code_point_stats(t, emoji_counts)
    gr_summary, gr_major, gr_minor, grapheme_forensics = compute_grapheme_stats(t)
    ccc_stats = compute_combining_class_stats(t)
    
    # Shape
    major_seq_stats = compute_sequence_stats(t)
    minor_seq_stats = compute_minor_sequence_stats(t)
    lb_run_stats = compute_linebreak_analysis(t)
    bidi_run_stats = compute_bidi_class_analysis(t)
    wb_run_stats = compute_wordbreak_analysis(t)
    sb_run_stats = compute_sentencebreak_analysis(t)
    gb_run_stats = compute_graphemebreak_analysis(t)
    eaw_run_stats = compute_eastasianwidth_analysis(t)
    vo_run_stats = compute_verticalorientation_analysis(t)

    # Integrity Analysis (Populates Registry)
    # Passing grapheme_forensics for NFC data
    forensic_rows, audit_result = compute_forensic_stats_with_positions(t, cp_minor, emoji_flags, grapheme_forensics)
    forensic_map = {row['label']: row for row in forensic_rows}

    # Reconstruct the inputs dict needed by the Auditor from the UI map
    def _get_f_count(lbl): return forensic_map.get(lbl, {}).get("count", 0)
    
    integrity_inputs = {
        "fffd": _get_f_count("Flag: Replacement Char (U+FFFD)"),
        "surrogate": _get_f_count("Surrogates (Broken)"),
        "nul": _get_f_count("Flag: NUL (U+0000)"),
        "bidi_broken_count": _get_f_count("Flag: Unclosed Bidi Sequence") + _get_f_count("Flag: Unmatched PDF/PDI"),
        "broken_keycap": _get_f_count("Flag: Broken Keycap Sequence"),
        "hidden_marks": _get_f_count("Flag: Marks on Non-Visual Base"),
        "tags": _get_f_count("Flag: Unicode Tags (Plane 14)"),
        "nonchar": _get_f_count("Noncharacter"),
        "invalid_vs": _get_f_count("Flag: Invalid Variation Selector"),
        "donotemit": _get_f_count("Prop: Discouraged (DoNotEmit)"),
        "max_cluster_len": _get_f_count("Max Invisible Run Length"),
        "bom": _get_f_count("Flag: Internal BOM (U+FEFF)"),
        "pua": _get_f_count("Flag: Private Use Area (PUA)"),
        "legacy_ctrl": _get_f_count("Flag: Other Control Chars (C0/C1)"),
        "dec_space": _get_f_count("Deceptive Spaces"),
        "not_nfc": _get_f_count("Flag: Normalization (Not NFC)") > 0,
        "bidi_present": _get_f_count("Flag: Bidi Controls (UAX #9)")
    }

    
    # Provenance & Scripts (Required for Threat Analysis)
    provenance_stats = compute_provenance_stats(t)
    script_run_stats = compute_script_run_analysis(t)

    # Statistical Profile (Required for Anomaly Ledger)
    stat_profile = compute_statistical_profile(t)

    # Threat Analysis (Populates Registry; Required for Threat Ledger)
    threat_results = compute_threat_analysis(t, script_run_stats)
    window.latest_threat_data = threat_results

    # Extract Stage 1.5 Data
    stage1_5_data = threat_results.get('adversarial', {})

    # Helper for extracting flags
    def get_flag_count(label): return forensic_map.get(label, {}).get("count", 0)
    current_flags = threat_results.get('flags', {})

    # Derived Metric
    norm_inj_count = sum(1 for k in current_flags if "Normalization-Activated" in k)
    logic_bypass_count = sum(1 for k in current_flags if "Case Mapping" in k or "Bypass Vector" in k)
    
    # Zalgo & Anomaly Wiring
    # 1. Generate Graphemes ONCE (Optimized for reuse in Stage 2 Bridge)
    try:
        segments_iterable = GRAPHEME_SEGMENTER.segment(t)
        grapheme_list = [seg.segment for seg in window.Array.from_(segments_iterable)]
    except:
        # Fallback if Intl.Segmenter fails/missing
        grapheme_list = list(t)

    # ----------------------------------------------------------------------
    # [UNIFIED PHYSICS LOOP] Zalgo, Invisibles, and Registry Sync
    # ----------------------------------------------------------------------
    # We iterate graphemes ONCE to guarantee that the Hero Counter (Registry)
    # perfectly matches the Statistical Profile list (Participants).
    
    zalgo_participants = []
    current_logical_idx = 0  # Tracks true Code Point index to fix Selection Drift
    
    # We still need nsm_stats for global max/avg metrics, but we won't use its positions.
    nsm_stats = analyze_nsm_overload(grapheme_list) 

    for g in grapheme_list:
        g_len = len(g)
        marks = sum(1 for c in g if unicodedata.category(c) == 'Mn')
        
        # Detection Logic (Physics Rules)
        is_anomaly = False
        p_type = "Visible"
        severity = "low"
        
        # Rule A: Visible Stacking (Zalgo / Complexity)
        if marks > 2: 
            is_anomaly = True
            
            # --- NEW: Gradient Taxonomy ---
            if marks <= 5:
                p_type = "Dense Cluster"    # Tier 1: Linguistic Complexity / Glitch
                severity = "warn"           # Amber
            elif marks <= 15:
                p_type = "Heavy Stack"      # Tier 2: Intentional Modification
                severity = "crit" if marks >= 10 else "warn" # Red starts at 10
            else:
                p_type = "Zalgo Overload"   # Tier 3: Rendering DoS
                severity = "crit"           # Red
            
        # Rule B: Invisible Stacking (Steganography / Watermarking)
        # Condition: Base is Space/Control/Format AND has marks attached
        elif marks > 0:
            if g[0].isspace() or unicodedata.category(g[0]) in ('Cf', 'Cc'):
                is_anomaly = True
                p_type = "Invisible Stack"
                severity = "ghost"
        
        if is_anomaly:
            # 1. Add to Roster (For Statistical Profile UI)
            zalgo_participants.append({
                "idx": current_logical_idx,  # <--- CRITICAL FIX: True Start Index
                "len": g_len,
                "marks": marks, 
                "type": p_type,
                "severity": severity,
                "char": g[0]
            })
            
            # 2. Register for HUD Counter (For Navigation Stepper)
            # This ensures the Yellow Badge count matches the List exactly.
            reg_label = f"{p_type} ({marks} mk)"
            _register_hit("phys_zalgo", current_logical_idx, current_logical_idx + g_len, reg_label)
            
        current_logical_idx += g_len # Advance accumulator by actual cluster length

    # Sort participants by severity (heaviest stacks first)
    zalgo_participants.sort(key=lambda x: x['marks'], reverse=True)

    # ==============================================================================
    # [PATCH] SYNCHRONIZE ZALGO COUNTS (Fixes "x6" vs "7" Discrepancy)
    # The analyze_nsm_overload function strictly counts marks >= 3.
    # The loop above correctly captured an Invisible Stack with only 2 marks.
    # We must force nsm_stats to accept the total forensic count.
    # ==============================================================================
    nsm_stats["count"] = len(zalgo_participants)
    
    # Inject into profile
    stat_profile['zalgo'] = nsm_stats
    stat_profile['zalgo_participants'] = zalgo_participants

    # 5. Build Noise List for Threat Score
    noise_list = []
    if nsm_stats["level"] >= 1: noise_list.append("Excessive Combining Marks (Zalgo)")
    if threat_results.get("skel_metrics", {}).get("drift_ascii", 0) > 0: 
        noise_list.append("ASCII Normalization Drift")
        
    # Build Inputs for Threat Auditor
    score_inputs = {
        "waf_score": threat_results.get("waf_score", 0),
        "norm_injection_count": norm_inj_count,
        "logic_bypass_count": logic_bypass_count,
        "malicious_bidi": threat_results.get('bidi_danger', False),
        "has_unclosed_bidi": get_flag_count("Flag: Unclosed Bidi Sequence") > 0,
        "drift_cross_script": threat_results.get("skel_metrics", {}).get("drift_cross_script", 0),
        "script_mix_class": threat_results.get('script_mix_class', ""),
        "max_invis_run": get_flag_count("Max Invisible Run Length"),
        "invis_cluster_count": get_flag_count("Invisible Clusters (All)"),
        "rgi_count": emoji_counts.get("rgi_total", 0),
        "tags_count": get_flag_count("Flag: Unicode Tags (Plane 14)"),
        "suspicious_syntax_vs": get_flag_count("SUSPICIOUS: Variation Selector on Syntax") > 0,
        "forced_pres_count": (
            emoji_flags.get("Flag: Forced Emoji Presentation", {}).get("count", 0) +
            emoji_flags.get("Flag: Forced Text Presentation", {}).get("count", 0)
        ),
        "noise_list": noise_list
    }
    
    # Calculate! (This generates the 'ledger' key)
    final_score = compute_threat_score(score_inputs)

    # THE MASTER AUDITOR (New Logic from Block 7)
    master_ledgers = audit_master_ledgers(
        inputs=integrity_inputs, 
        stats_inputs=stat_profile, 
        stage1_5_data=stage1_5_data, 
        threat_output=final_score
    )
    
    # --- Prepare Data for Renderers ---
    
    # 2.A Cards
    meta_cards = {
        # --- The Forensic Quad-Metric Reality ---
        "Total Graphemes": gr_summary.get("Total Graphemes", 0),   # Visual
        "Total Code Points": cp_summary.get("Total Code Points", 0), # Logical
        "UTF-16 Units": cp_summary.get("UTF-16 Units", 0),       # Runtime (JS/Java)
        "UTF-8 Bytes": cp_summary.get("UTF-8 Bytes", 0),         # Physical (Storage)
        "Astral Count": cp_summary.get("Astral Count", 0),       # Context (Subtitle for UTF-16)
        "Avg. Marks per Grapheme": grapheme_forensics.get("Avg. Marks per Grapheme", 0),
        "Total Combining Marks": grapheme_forensics.get("Total Combining Marks", 0),
        
        # --- Contextual Metrics ---
        "RGI Emoji Sequences": emoji_counts.get("rgi_total", 0), 
        "Whitespace (Total)": cp_summary.get("Whitespace (Total)", 0),
        "ASCII-Compatible": cp_summary.get("ASCII-Compatible"),
        "Latin-1-Compatible": cp_summary.get("Latin-1-Compatible"),
        "BMP Coverage": cp_summary.get("BMP Coverage"),
        "Supplementary Planes": cp_summary.get("Supplementary Planes"),
    }
    
    # STRICT FORENSIC ORDER: Visual -> Logical -> Runtime -> Physical -> [Context]
    meta_cards_order = [
        "Total Graphemes", 
        "Total Code Points", 
        "UTF-16 Units", 
        "UTF-8 Bytes",
        "RGI Emoji Sequences", 
        "Whitespace (Total)",
        "ASCII-Compatible", "Latin-1-Compatible", "BMP Coverage", "Supplementary Planes"
    ]
    grapheme_cards = grapheme_forensics
    
    shape_matrix = major_seq_stats
    prov_matrix = provenance_stats

    # --- THREAT FLAGS & SCORE LOGIC ---
    grapheme_strings = [seg.segment for seg in window.Array.from_(GRAPHEME_SEGMENTER.segment(t))]
    nsm_stats = analyze_nsm_overload(grapheme_strings)

    def get_count(label):
        return forensic_map.get(label, {}).get("count", 0)

    malicious_bidi = threat_results.get('bidi_danger', False)
    script_mix_class = threat_results.get('script_mix_class', "")
    skel_metrics = threat_results.get("skel_metrics", {})
    
    noise_list = []
    if nsm_stats["level"] >= 1: noise_list.append("Excessive Combining Marks (Zalgo)")
    drift_ascii = skel_metrics.get("drift_ascii", 0)
    if drift_ascii > 0: noise_list.append(f"ASCII Normalization Drift ({drift_ascii} chars)")

    # Calculate counts for new engines
    # Retrieve flags from the results object (threat_flags is not local to this function)
    current_flags = threat_results.get('flags', {})

    score_inputs = {
        # [NEW] WIRING
        "waf_score": threat_results.get("waf_score", 0),
        "norm_injection_count": norm_inj_count,
        "logic_bypass_count": logic_bypass_count,
        
        # [EXISTING]
        "malicious_bidi": malicious_bidi,
        "has_unclosed_bidi": get_count("Flag: Unclosed Bidi Sequence") > 0,
        "drift_cross_script": skel_metrics.get("drift_cross_script", 0),
        "script_mix_class": script_mix_class,
        "max_invis_run": forensic_map.get("Max Invisible Run Length", {}).get("count", 0),
        "invis_cluster_count": forensic_map.get("Invisible Clusters (All)", {}).get("count", 0),
        "rgi_count": emoji_counts.get("rgi_total", 0),
        "tags_count": get_count("Flag: Unicode Tags (Plane 14)"),
        "suspicious_syntax_vs": get_count("SUSPICIOUS: Variation Selector on Syntax") > 0,
        "forced_pres_count": (
            emoji_flags.get("Flag: Forced Emoji Presentation", {}).get("count", 0) +
            emoji_flags.get("Flag: Forced Text Presentation", {}).get("count", 0)
        ),
        "noise_list": noise_list
    }
    
    final_score = compute_threat_score(score_inputs)
    
    final_threat_flags = {}
    score_badge = f"{final_score['verdict']} (Score: {final_score['score']})"
    final_threat_flags["Threat Level (Heuristic)"] = {
        'count': 0, 'positions': [],
        'severity': final_score['severity_class'],
        'badge': score_badge,
        'ledger': final_score.get('ledger', []),
        'noise': final_score.get('noise', [])
    }
    
    if nsm_stats["count"] > 0:
        sev = "crit" if nsm_stats["level"] == 2 else "warn"
        label = "Flag: Excessive Combining Marks (Zalgo)"
        final_threat_flags[label] = {
            'count': nsm_stats["count"],
            'positions': nsm_stats["positions"],
            'severity': sev,
            'badge': "ZALGO"
        }

    final_threat_flags.update(threat_results['flags'])
    
    inv_vs = forensic_map.get("Flag: Invalid Variation Selector")
    if inv_vs and inv_vs.get("count", 0) > 0:
        final_threat_flags["Suspicious: Invalid Variation Selectors"] = inv_vs
    
    unq_emo = emoji_flags.get("Flag: Unqualified Emoji", {})
    if unq_emo.get("count", 0) > 0:
        final_threat_flags["Suspicious: Unqualified Emoji"] = unq_emo
    
    zwj_flag = forensic_map.get("Flag: Zero-Width Join Controls (ZWJ/ZWNJ)")
    if zwj_flag and zwj_flag.get("count", 0) > 0:
        final_threat_flags["Suspicious: Join Control Present (ZWJ)"] = zwj_flag

    new_emoji_flags = {
        "Flag: Broken Keycap Sequence": "Suspicious: Broken Keycap",
        "Flag: Invalid Regional Indicator": "Suspicious: Invalid Regional Indicator",
        "Flag: Forced Emoji Presentation": "Suspicious: Forced Emoji",
        "Flag: Intent-Modifying ZWJ": "Suspicious: Intent-Modifying ZWJ"
    }
    for flag_key, threat_label in new_emoji_flags.items():
        flag_data = emoji_flags.get(flag_key, {})
        if flag_data.get("count", 0) > 0:
            final_threat_flags[threat_label] = flag_data

    # Unqualified
    unq_pos = emoji_flags.get("Flag: Unqualified Emoji", {}).get("positions", [])
    for pos_str in unq_pos:
        try:
            idx = int(pos_str.replace("#", ""))
            _register_hit("thr_suspicious", idx, idx+1, "Unqualified Emoji")
        except: pass

    # Forced Presentation
    forced_pos = emoji_flags.get("Flag: Forced Emoji Presentation", {}).get("positions", []) + \
                 emoji_flags.get("Flag: Forced Text Presentation", {}).get("positions", [])
    for pos_str in forced_pos:
        try:
            idx = int(pos_str.replace("#", ""))
            _register_hit("thr_suspicious", idx, idx+1, "Forced Presentation")
        except: pass

    # Calculate Unique Invisible Count for Atlas TOC
    unique_invis_set = set()
    for char in t:
        if INVIS_TABLE[ord(char)] & INVIS_ANY_MASK:
            unique_invis_set.add(ord(char))
    unique_invis_count = len(unique_invis_set)

    toc_counts = {
        'dual': (
            sum(1 for v in meta_cards.values() if (isinstance(v, (int, float)) and v > 0) or (isinstance(v, dict) and v.get('count', 0) > 0)) + 
            sum(1 for v in grapheme_cards.values() if isinstance(v, (int, float)) and v > 0) + 
            sum(1 for k in set(cp_major.keys()) | set(gr_major.keys()) if cp_major.get(k, 0) > 0 or gr_major.get(k, 0) > 0)
        ),
        'shape': (
            sum(1 for v in shape_matrix.values() if v > 0) + 
            sum(1 for v in minor_seq_stats.values() if v > 0) + 
            sum(1 for v in lb_run_stats.values() if v > 0) + 
            sum(1 for v in bidi_run_stats.values() if v > 0) + 
            sum(1 for v in wb_run_stats.values() if v > 0) + 
            sum(1 for v in sb_run_stats.values() if v > 0) + 
            sum(1 for v in gb_run_stats.values() if v > 0) + 
            sum(1 for v in eaw_run_stats.values() if v > 0) + 
            sum(1 for v in vo_run_stats.values() if v > 0)
        ),
        'integrity': sum(1 for row in forensic_rows if row.get('count', 0) > 0),
        'prov': (
            sum(1 for v in prov_matrix.values() if v.get('count', 0) > 0) + 
            sum(1 for v in script_run_stats.values() if v.get('count', 0) > 0)
        ),
        'emoji': emoji_counts.get("total_emoji_units", 0),
        'threat': sum(1 for v in final_threat_flags.values() if (isinstance(v, dict) and v.get('count', 0) > 0) or (isinstance(v, int) and v > 0)),
        'atlas': unique_invis_count,
        'stat': stat_profile.get("total_tokens", 0)
    }

    # [FORENSIC LAYOUT ENGINE - ACTIVE STATE] ----------------------------------
    # 1. Define Groups
    quad_keys = ["Total Graphemes", "Total Code Points", "UTF-16 Units", "UTF-8 Bytes"]
    
    context_keys = [
        "RGI Emoji Sequences", "Whitespace (Total)",
        "ASCII-Compatible", "Latin-1-Compatible", "BMP Coverage", "Supplementary Planes"
    ]

    # 2. Render HTML Strings (Detached)
    html_quad = render_cards(meta_cards, element_id=None, key_order=quad_keys, return_html=True)
    html_context = render_cards(meta_cards, element_id=None, key_order=context_keys, return_html=True)

    # 3. Inject Structure
    full_html = f"""
    <div class="cards-2x2">{html_quad}</div>
    <div class="cards">{html_context}</div>
    """
    document.getElementById("meta-totals-cards").innerHTML = full_html
    # --------------------------------------------------------------------------

    render_cards(grapheme_cards, "grapheme-integrity-cards")
    render_ccc_table(ccc_stats, "ccc-matrix-body")
    render_parallel_table(cp_major, gr_major, "major-parallel-body")
    render_parallel_table(cp_minor, gr_minor, "minor-parallel-body", ALIASES)
    
    render_matrix_table(shape_matrix, "shape-matrix-body")
    render_matrix_table(minor_seq_stats, "minor-shape-matrix-body", aliases=ALIASES)
    # [NEW] Whitespace & Newline Topology (The Frankenstein Detector)
    ws_topology_html = compute_whitespace_topology(t)
    ws_container = document.getElementById("ws-topology-container")
    if ws_container:
        ws_container.innerHTML = ws_topology_html
    render_matrix_table(lb_run_stats, "linebreak-run-matrix-body")
    render_matrix_table(bidi_run_stats, "bidi-run-matrix-body")
    render_matrix_table(wb_run_stats, "wordbreak-run-matrix-body")
    render_matrix_table(sb_run_stats, "sentencebreak-run-matrix-body")
    render_matrix_table(gb_run_stats, "graphemebreak-run-matrix-body")
    render_matrix_table(eaw_run_stats, "eawidth-run-matrix-body")
    render_matrix_table(vo_run_stats, "vo-run-matrix-body")
    
    render_integrity_matrix(forensic_rows, text_context=t)
    render_matrix_table(prov_matrix, "provenance-matrix-body", has_positions=True, text_context=t)
    render_matrix_table(script_run_stats, "script-run-matrix-body", has_positions=True, text_context=t)

    # [NEW] Statistical Profile (Group 2.F)
    # Note: stat_profile was computed earlier and enriched with Zalgo data.
    render_statistical_profile(stat_profile)
    
    render_emoji_qualification_table(emoji_list, text_context=t)
    render_emoji_summary(emoji_counts, emoji_list)
    
    threat_results['flags'] = final_threat_flags
    render_threat_analysis(threat_results, text_context=t)

    # We map the LOCAL VARIABLES (that definitely exist) to the KEYS expected by the Renderer.
    stats_package = {
        "emoji_counts": emoji_counts,    # Uses local 'emoji_counts'
        "major_stats": cp_major,         # Uses local 'cp_major' (This was the missing link)
        "forensic_flags": forensic_map,  # Uses local 'forensic_map'
        "master_ledgers": master_ledgers,
        
        # Convenience Shortcuts
        "integrity": master_ledgers.get("integrity", {}),
        "threat": master_ledgers.get("threat", {}),
        "authenticity": master_ledgers.get("authenticity", {}),
        "anomaly": master_ledgers.get("anomaly", {})
    }

    # 4. Render
    render_forensic_hud(t, stats_package)
    
    # Render Adversarial Dashboard 
    render_adversarial_dashboard(threat_results.get('adversarial', {}))
    
    render_toc_counts(toc_counts)

    # [Phase 3] Render Invisible Atlas
    # We must calculate counts first because the renderer expects a dict
    atlas_counts = collections.Counter()
    for char in t:
        cp = ord(char)
        # Collect Invisibles, Tags, and Control Characters (C0/C1/DEL)
        if (INVIS_TABLE[cp] & INVIS_ANY_MASK) or (0x00 <= cp <= 0x1F) or (0x7F <= cp <= 0x9F):
            atlas_counts[cp] += 1
            
    render_invisible_atlas(atlas_counts)

    is_ascii_safe = True
    if "ASCII-Compatible" in cp_summary:
        is_ascii_safe = cp_summary["ASCII-Compatible"].get("is_full", False)

    hud_stats = {
        "major_stats": cp_major,
        "forensic_flags": forensic_map,
        "emoji_counts": emoji_counts,
        "integrity": audit_result,
        "threat": final_score,
        "script_mix": script_mix_class,
        "is_ascii": is_ascii_safe,
        "nsm_level": nsm_stats["level"],
        "drift": skel_metrics.get("total_drift", 0),
        "master_ledgers": master_ledgers
    }

    # --- Render Encoding Strip ---
    render_encoding_footprint(t)
    
    # Stage 2 Bridge
    try:
        segments_iterable = GRAPHEME_SEGMENTER.segment(t)
        grapheme_list = [seg.segment for seg in window.Array.from_(segments_iterable)]
        all_flags = forensic_map.copy()
        all_flags.update(emoji_flags)
        nfkc_cf_text = threat_results.get('nfkc_cf', "")
        
        core_data = {
            "raw_text": t,
            "grapheme_list": grapheme_list,
            "grapheme_lengths_codepoints": [len(g) for g in grapheme_list],
            "forensic_flags": all_flags,
            "statistical_profile": stat_profile,
            "nfkc_casefold_text": nfkc_cf_text,
            "timestamp": window.Date.new().toISOString()
        }
        core_data_js = to_js(core_data, dict_converter=window.Object.fromEntries)
        window.TEXTTICS_CORE_DATA = core_data_js
    except Exception as e:
        print(f"Error packaging data for Stage 2: {e}")

@create_proxy
def update_verification(event=None):
    """
    [VP-19] Verification Workbench Event Loop V1.1.
    
    Hardening Upgrades:
    1. Passive Profiling: Renders full Suspect Profile even in Idle state.
    2. Internal Injection Alarm: Updates UI if 'internal_injection' is detected.
    3. Defensive DOM: Handles missing elements gracefully.
    """
    # 1. DOM Acquisition
    trusted_input = document.getElementById("trusted-input")
    text_input = document.getElementById("text-input")
    verdict_display = document.getElementById("verdict-display")
    suspect_display = document.getElementById("suspect-display")
    scope_badge = document.getElementById("scope-badge")
    
    if not trusted_input or not text_input: return

    # 2. Scope Awareness Logic
    full_text = text_input.value
    selection_start = text_input.selectionStart
    selection_end = text_input.selectionEnd
    
    has_selection = (selection_start != selection_end)
    
    if has_selection:
        suspect_text = full_text[selection_start:selection_end]
        scope_label = "SELECTION SCOPE"
        badge_class = "scope-select"
    else:
        suspect_text = full_text
        scope_label = "FULL INPUT SCOPE"
        badge_class = "scope-full"

    if scope_badge:
        scope_badge.textContent = scope_label
        scope_badge.className = f"badge {badge_class}"

    # 3. Trusted Input Check
    trusted_text = trusted_input.value
    
    # [HARDENING] Passive Profile Renderer (Idle State)
    if not trusted_text:
        suspect_profile = analyze_restriction_level(suspect_text)
        
        if verdict_display: verdict_display.classList.add("hidden")
        if suspect_display:
            # Render a mini-profile so the tool is useful even without a reference
            risk_color = "#10b981" if suspect_profile["score"] < 10 else "#ef4444"
            scripts_str = ", ".join(suspect_profile["scripts"])
            
            suspect_display.innerHTML = (
                f'<div style="opacity:0.6; padding:10px;">'
                f'Waiting for trusted reference...<br><hr style="border-color:#eee; margin:5px 0;">'
                f'Active Scope Profile:<br>'
                f'Restriction: <strong style="color:{risk_color}">{suspect_profile["label"]}</strong><br>'
                f'Scripts: <code>{scripts_str}</code>'
                f'</div>'
            )
        return

    # 4. EXECUTE FORENSIC COMPARATOR
    res = compute_verification_verdict(suspect_text, trusted_text)
    if not res: return

    # 5. RENDER VERDICT
    if verdict_display:
        verdict_display.classList.remove("hidden")
        verdict_display.className = f"verdict-box {res['css_class']}"
        
        document.getElementById("verdict-title").textContent = res["verdict"]
        document.getElementById("verdict-desc").textContent = res["desc"]
        document.getElementById("verdict-icon").textContent = res["icon"]

    # 6. RENDER LENS
    lens_html = render_verification_lens(suspect_text, trusted_text, res)
    if suspect_display: suspect_display.innerHTML = lens_html

    # 7. POPULATE EVIDENCE MATRIX (Defensive Update)
    def update_cell(id_str, val, color_override=None):
        el = document.getElementById(id_str)
        if not el: return
        
        # Default Logic
        color = "#6b7280"
        if color_override:
            color = color_override
        elif val == "MATCH":
            color = "#10b981"
        elif val in ("DIFF", "CROSS-SCRIPT SPOOF"):
            color = "#ef4444"
        elif val in ("PARTIAL", "SINGLE-SCRIPT SPOOF", "CASE-DIFF"):
            color = "#f59e0b"
            
        el.innerHTML = f'<span style="color:{color}; font-weight:700;">{val}</span>'

    update_cell("vm-raw", res["states"]["raw"])
    update_cell("vm-nfkc", res["states"]["nfkc"], 
                color_override="#f59e0b" if res["states"]["nfkc"] == "CASE-DIFF" else None)
    update_cell("vm-skel", res["states"]["skel"])
    
    # 8. Render Profile Data
    s_prof = res["profiles"]["suspect"]
    risk_color = "#10b981" if s_prof["score"] < 10 else "#ef4444"
    update_cell("vm-suspect-profile", s_prof["label"], color_override=risk_color)
    
    t_prof = res["profiles"]["trusted"]
    update_cell("vm-trusted-profile", t_prof["label"], color_override="#6b7280") # Trusted is neutral reference

    # 9. Render Confusable Class
    conf_cls = res["confusable_class"]
    conf_color = "#ef4444" if "CROSS" in conf_cls else "#f59e0b" if "SINGLE" in conf_cls else "#9ca3af"
    update_cell("vm-confusable-class", conf_cls, color_override=conf_color)
    
    # [HARDENING] Internal Injection Alarm
    # If we detect internal artifacts, we can force the Confusable Class to indicate it
    if res.get("internal_injection", False):
         update_cell("vm-confusable-class", "INTERNAL INJECTION", color_override="#ef4444")

# Interaction Handlers

@create_proxy
def inspect_character(event):
    """
    Forensic Inspector v3.1: Selection-Aware.
    Now allows inspection even when text is highlighted/selected (e.g., by the Invisible Finder).
    """
    try:
        text_input = document.getElementById("text-input")
        if text_input.classList.contains("reveal-active"):
            render_inspector_panel({"error": "Inspection Paused (Reveal Active)"})
            return

        dom_pos = text_input.selectionStart
        
        # [REMOVED BLOCKER] 
        # Previously, we returned here if selectionStart != selectionEnd.
        # We removed that check so the Inspector works when the Highlighter selects a char.

        # Handle Newline normalization mismatch (Windows \r\n vs \n)
        text = str(text_input.value)
        if not text:
            render_inspector_panel(None)
            return
        
        # 1. Map DOM Index to Python Index
        python_idx = 0
        utf16_accum = 0
        found_sync = False
        
        for i, ch in enumerate(text):
            if utf16_accum == dom_pos:
                python_idx = i
                found_sync = True
                break
            
            # Logic: Is this a surrogate pair? (2 units) or BMP (1 unit)
            step = 2 if ord(ch) > 0xFFFF else 1
            utf16_accum += step
            
            if utf16_accum > dom_pos:
                # We landed inside a character (rare, but possible with surrogates)
                python_idx = i
                found_sync = True
                break
        
        if not found_sync and utf16_accum == dom_pos:
             render_inspector_panel(None) # End of string
             return

        # 2. Localized Segmentation
        start_search = max(0, python_idx - 50)
        end_search = min(len(text), python_idx + 50)
        local_text = text[start_search:end_search]
        
        local_target_idx = python_idx - start_search
        
        segments_iter = GRAPHEME_SEGMENTER.segment(local_text)
        
        target_cluster = None
        prev_cluster = None
        next_cluster = None
        
        current_local_idx = 0
        
        for seg in segments_iter:
            seg_str = str(seg.segment)
            seg_len = len(seg_str)
            seg_end = current_local_idx + seg_len
            
            # Check containment relative to local window
            if current_local_idx <= local_target_idx < seg_end:
                target_cluster = seg_str
                # Continue to get next_cluster
                current_local_idx = seg_end
                continue
            
            if target_cluster is not None:
                next_cluster = seg_str
                break
            
            prev_cluster = seg_str
            current_local_idx = seg_end

        # Fallback
        if not target_cluster:
            target_cluster = text[python_idx]
            
        # 3. Analyze the Cluster
        base_char = target_cluster[0]
        cp_base = ord(base_char)
        
        cat_short = unicodedata.category(base_char)
        base_char_data = {
            "block": _find_in_ranges(cp_base, "Blocks") or "N/A",
            "script": _find_in_ranges(cp_base, "Scripts") or "Common",
            "category_full": ALIASES.get(cat_short, "N/A"),
            "category_short": cat_short,
            "bidi": unicodedata.bidirectional(base_char),
            "age": _find_in_ranges(cp_base, "Age") or "N/A"
        }

        cluster_identity = _compute_cluster_identity(target_cluster, base_char_data)

        comp_cat = cluster_identity["max_risk_cat"]
        comp_mask = cluster_identity["cluster_mask"]
        
        if comp_cat in ("Cn", "Co", "Cs", "Cf"):
            id_status = "Restricted"
        else:
            id_status = _find_in_ranges(cp_base, "IdentifierStatus") or "Restricted"
            
        id_type = _find_in_ranges(cp_base, "IdentifierType")
            
        macro_type = _classify_macro_type(cp_base, comp_cat, id_status, comp_mask)
        ghosts = _get_ghost_chain(base_char)
        
        bidi_short = unicodedata.bidirectional(base_char)
        wb_prop = _find_in_ranges(cp_base, "WordBreak") or "Other"
        lb_prop = _find_in_ranges(cp_base, "LineBreak") or "Unknown"
        gb_val = _find_in_ranges(cp_base, "GraphemeBreak")
        gb_prop = gb_val if gb_val else "Base (Other)"
        
        inv_map = DATA_STORES.get("InverseConfusables", {})
        raw_lookalikes = inv_map.get(str(cp_base), [])
        
        lookalikes_data = []
        for item in raw_lookalikes:
            try:
                if isinstance(item, int):
                    cp = item
                else:
                    clean = str(item).replace("U+", "").strip()
                    cp = int(clean, 16)
                
                char = chr(cp)
                script = _find_in_ranges(cp, "Scripts") or "Common"
                block = _find_in_ranges(cp, "Blocks") or "Unknown Block"
                
                lookalikes_data.append({
                    "cp": f"U+{cp:04X}",
                    "glyph": char,
                    "script": script,
                    "block": block,
                    "name": unicodedata.name(char, "UNKNOWN CHARACTER")
                })
            except Exception:
                continue
        
        components = []
        zalgo_score = 0
        for ch in target_cluster:
            cat = unicodedata.category(ch)
            name = unicodedata.name(ch, "Unknown")
            ccc = unicodedata.combining(ch)
            is_mark = cat.startswith('M')
            if is_mark: zalgo_score += 1
            
            components.append({
                'hex': f"U+{ord(ch):04X}", 
                'name': name, 
                'cat': cat, 
                'ccc': ccc,
                'is_base': not is_mark
            })

        utf8_hex = " ".join(f"{b:02X}" for b in target_cluster.encode("utf-8"))
        utf16_hex = " ".join(f"{b:02X}" for b in target_cluster.encode("utf-16-be"))
        utf32_hex = f"{cp_base:08X}"
        
        def try_enc(enc_name):
            try:
                return " ".join(f"{b:02X}" for b in target_cluster.encode(enc_name))
            except UnicodeEncodeError:
                return "N/A"

        ascii_val = try_enc("ascii")
        latin1_val = try_enc("latin-1")
        cp1252_val = try_enc("cp1252")
        url_enc = "".join(f"%{b:02X}" for b in target_cluster.encode("utf-8"))
        
        # --- NEW: EXPLOIT & OBFUSCATION ENCODINGS ---
        # 1. Base64 (Standard Payload Wrapper)
        try:
            b64_val = base64.b64encode(target_cluster.encode("utf-8")).decode("ascii")
        except:
            b64_val = "Error"

        # 2. Shellcode / Hex Escapes (\xHH)
        shell_val = "".join(f"\\x{b:02X}" for b in target_cluster.encode("utf-8"))

        # 3. Octal Escapes (\NNN)
        octal_val = "".join(f"\\{b:03o}" for b in target_cluster.encode("utf-8"))

        # 4. HTML Entity Variants (Decimal vs Hex)
        if target_cluster.isalnum():
            html_dec_val = target_cluster
            html_hex_val = target_cluster
        else:
            html_dec_val = "".join(f"&#{ord(c)};" for c in target_cluster)
            html_hex_val = "".join(f"&#x{ord(c):X};" for c in target_cluster)

        # 5. ES6 / CSS Unicode (\u{...})
        es6_val = "".join(f"\\u{{{ord(c):X}}}" for c in target_cluster)
        
        # 6. Python/Old JS
        code_enc = target_cluster.encode("unicode_escape").decode("utf-8")

        confusable_msg = None
        
        if ghosts:
             skel_val = ghosts['skeleton']
             if skel_val != base_char and skel_val != base_char.casefold():
                 confusable_msg = f"Base maps to: '{skel_val}'"

        stack_msg = None
        if zalgo_score >= 3: stack_msg = f"Heavy Stacking ({zalgo_score} marks)"

        data = {
            "python_idx": python_idx,
            "cluster_glyph": target_cluster,
            "prev_glyph": prev_cluster,
            "next_glyph": next_cluster,
            "cp_hex_base": f"U+{cp_base:04X}",
            "name_base": unicodedata.name(base_char, "No Name Found"),
            "is_cluster": cluster_identity["is_cluster"],
            "type_label": cluster_identity["type_label"],
            "type_val":   cluster_identity["type_val"],
            "block":      cluster_identity["block_val"],
            "script":     cluster_identity["script_val"],
            "bidi":       cluster_identity["bidi_val"],
            "age":        cluster_identity["age_val"],
            "category_full": base_char_data['category_full'],
            "category_short": base_char_data['category_short'],
            "id_status": id_status,
            "id_type": id_type,
            "macro_type": macro_type,
            "ghosts": ghosts,
            "is_ascii": (cp_base <= 0x7F),
            "lookalikes_data": lookalikes_data,
            "line_break": lb_prop,
            "word_break": wb_prop,
            "grapheme_break": gb_prop,
            
            # --- Forensic Encodings ---
            "utf8": utf8_hex, 
            "utf16": utf16_hex, 
            "utf32": utf32_hex,
            "ascii": ascii_val, 
            "latin1": latin1_val, 
            "cp1252": cp1252_val,
            # --- Exploit Vectors ---
            "url": url_enc, 
            "code": code_enc,
            "base64": b64_val,
            "shell": shell_val,
            "octal": octal_val,
            "html_dec": html_dec_val,
            "html_hex": html_hex_val,
            "es6": es6_val,
            
            "confusable": confusable_msg,
            "is_invisible": bool(comp_mask & INVIS_ANY_MASK),
            "stack_msg": stack_msg,
            "components": components
        }
        
        render_inspector_panel(data)

    except Exception as e:
        print(f"Inspector Error: {e}")
        render_inspector_panel({"error": str(e)})

@create_proxy
def cycle_hud_metric(metric_key, current_dom_pos):
    """
    Stateless stepper. Finds the next range after current_dom_pos.
    Updates the LEFT-SIDE HUD Status bar.
    """
    el = document.getElementById("text-input")
    if not el: return
    
    # Force conversion to Python string to ensure 'enumerate' yields chars, not ints.
    t = str(el.value)
    
    # 1. Map DOM Position to Logical Index (Pure Python)
    current_logical = 0
    if t:
        utf16_acc = 0
        for i, char in enumerate(t):
            if utf16_acc >= current_dom_pos:
                current_logical = i
                break
            utf16_acc += (2 if ord(char) > 0xFFFF else 1)
        else:
            current_logical = len(t)

    # 2. Define Human-Readable Labels
    labels = {
        "integrity_agg": "Integrity Issues",
        "threat_agg": "Threat Signals",
        "authenticity_agg": "Authenticity Signals",
        "anomaly_agg": "Anomaly Signals",
        "ws_nonstd": "Non-Std Whitespace",
        "punc_exotic": "Exotic Delimiters",
        "sym_exotic": "Exotic Symbols",
        "emoji_hybrid": "Hybrid Emoji",
        "emoji_irregular": "Irregular Emoji"
    }
    category_label = labels.get(metric_key, "Forensic Metric")

    # 3. Resolve targets (UPDATED TO MATCH HERO ROWS)
    raw_targets = []
    
    if metric_key == "integrity_agg":
        for k in ["int_fatal", "int_fracture", "int_risk", "int_decay"]:
            raw_targets.extend(HUD_HIT_REGISTRY.get(k, []))
            
    elif metric_key == "threat_agg":
        # STRICT SCOPE: Only Execution/Obfuscation. Matches Hero Count (47).
        for k in ["thr_execution", "thr_obfuscation"]:
            raw_targets.extend(HUD_HIT_REGISTRY.get(k, []))
            
    elif metric_key == "authenticity_agg":
        # NEW AGGREGATOR: Spoofing/Mixed Scripts. Matches Hero Count (43).
        for k in ["auth_spoof", "auth_mixed", "auth_idna", "thr_spoofing", "thr_suspicious"]:
            raw_targets.extend(HUD_HIT_REGISTRY.get(k, []))
            
    elif metric_key == "anomaly_agg":
        # NEW AGGREGATOR: Physics/Entropy.
        for k in ["phys_entropy", "phys_zalgo", "phys_weird"]:
            raw_targets.extend(HUD_HIT_REGISTRY.get(k, []))
            
    else:
        # Standard single-metric lookup
        raw_targets = HUD_HIT_REGISTRY.get(metric_key, [])

    if not raw_targets: return

    # [DEDUPLICATION LOGIC]
    targets = []
    seen_starts = set()
    
    # Sort first to ensure consistent order
    raw_targets.sort(key=lambda x: x[0])
    
    for hit in raw_targets:
        start_idx = hit[0]
        if start_idx not in seen_starts:
            targets.append(hit)
            seen_starts.add(start_idx)

    # 4. Find Next
    next_hit = targets[0]
    hit_index = 1
    
    for i, hit in enumerate(targets):
        if hit[0] >= current_logical:
            next_hit = hit
            hit_index = i + 1
            break

    # 5. Execute Highlight
    # [DEBUG HOOK]
    # if TEXTTICS_DEBUG_THREAT_BRIDGE: _debug_threat_bridge(t, next_hit)

    # PURE PYTHON DOM CALCULATION
    log_start = next_hit[0]
    log_end = next_hit[1]
    
    dom_start = -1
    dom_end = -1
    
    acc = 0
    # Iterate the Python string (t is guaranteed str now)
    for i, char in enumerate(t):
        if i == log_start: dom_start = acc
        if i == log_end: dom_end = acc; break 
        
        acc += (2 if ord(char) > 0xFFFF else 1)
    
    if dom_end == -1 and log_end >= len(t): 
        dom_end = acc
    
    if dom_start != -1:
        el.focus()
        el.setSelectionRange(dom_start, dom_end)

    # 6. Feedback UI
    icon_loc = """<svg style="display:inline-block; vertical-align:middle; margin-left:8px; opacity:0.8;" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#1e40af" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z"></path><circle cx="12" cy="10" r="3"></circle></svg>"""

    status_msg = f"<strong>{category_label} Highlighter:</strong>&nbsp;#{hit_index} of {len(targets)}"
    
    hud_status = document.getElementById("hud-stepper-status")
    if hud_status:
        hud_status.className = "status-details status-hud-active"
        hud_status.style.display = "inline-flex"
        hud_status.innerHTML = f"{status_msg}{icon_loc}"
    
    # 7. Update Inspector
    inspect_character(None)

@create_proxy
def highlight_specific_char(target_cp_val):
    """
    Atlas Action: Finds and selects the next occurrence of a specific code point.
    Args:
        target_cp_val: Integer code point (passed from JS)
    """
    el = document.getElementById("text-input")
    if not el or not el.value: return
    
    # Ensure input is int (JS passes numbers, but safety first)
    try:
        target_cp = int(target_cp_val)
    except:
        return

    text = str(el.value)
    
    # 1. Map all occurrences of this specific char
    ranges = []
    current_utf16_idx = 0
    
    for char in text:
        cp = ord(char)
        char_len = 2 if cp > 0xFFFF else 1 # UTF-16 Length
        
        if cp == target_cp:
            ranges.append((current_utf16_idx, current_utf16_idx + char_len))
            
        current_utf16_idx += char_len

    count = len(ranges)
    if count == 0: return

    # 2. Find NEXT relative to cursor
    current_end_pos = el.selectionEnd
    target_range = None
    target_idx = 1
    
    for i, r in enumerate(ranges):
        if r[0] >= current_end_pos:
            target_range = r
            target_idx = i + 1
            break
            
    # Wrap-around
    if target_range is None:
        target_range = ranges[0]
        target_idx = 1
            
    # 3. Select
    el.blur()
    el.focus()
    el.setSelectionRange(target_range[0], target_range[1])
    
    # 4. Feedback (Reusing the NSI status line for consistency)
    details_line = document.getElementById("reveal-details")
    if details_line:
        details_line.className = "status-details warn"
        icon_loc = """<svg style="display:inline-block; vertical-align:middle; margin-right:6px;" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#d97706" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z"></path><circle cx="12" cy="10" r="3"></circle></svg>"""
        hex_disp = f"U+{target_cp:04X}"
        details_line.innerHTML = f"<strong>Atlas Finder ({hex_disp}):</strong>&nbsp;#{target_idx}&nbsp;of&nbsp;{count}&nbsp;{icon_loc}"
        
    # 5. Trigger Inspector to show details for this char
    inspect_character(None)

@create_proxy
def find_next_sequence(target_str):
    """
    Statistical Navigator.
    Finds and selects the next occurrence of a text sequence (case-insensitive).
    """
    el = document.getElementById("text-input")
    if not el or not el.value or not target_str: return
    
    t = str(el.value)
    t_lower = t.lower()
    target_lower = str(target_str).lower()
    
    # Start searching from AFTER the current selection
    start_pos = el.selectionEnd
    
    # 1. Find next occurrence
    idx = t_lower.find(target_lower, start_pos)
    
    # 2. Wrap around if not found
    if idx == -1:
        idx = t_lower.find(target_lower)
        
    if idx != -1:
        # 3. Calculate UTF-16 DOM indices for selection
        dom_start = 0
        utf16_acc = 0
        
        # Fast-forward to the match index
        # We need to sum the UTF-16 lengths of all chars BEFORE the match
        for i in range(idx):
            char = t[i]
            utf16_acc += (2 if ord(char) > 0xFFFF else 1)
        dom_start = utf16_acc
        
        # Calculate length of the matched string in UTF-16
        match_str = t[idx : idx + len(target_str)]
        dom_len = sum(2 if ord(c) > 0xFFFF else 1 for c in match_str)
        
        # 4. Select
        el.focus()
        el.setSelectionRange(dom_start, dom_start + dom_len)
        
        # 5. Feedback
        status = document.getElementById("reveal-details")
        if status:
            status.className = "status-details status-hud-active"
            status.innerHTML = f"<strong>Finding:</strong> '{_escape_html(target_str)}'"

# Transformation & Tools

@create_proxy
def reveal_invisibles(event=None):
    """
    TRANSFORM MODE (btn-reveal): 
    Replaces invisible characters with visible tags (e.g. [ZWSP]).
    Toggle: Click again to Revert.
    """
    el = document.getElementById("text-input")
    details_line = document.getElementById("reveal-details")
    reveal_btn = document.getElementById("btn-reveal")
    reveal2_btn = document.getElementById("btn-reveal2")
    
    if not el or not el.value: return

    # --- 1. REVERT LOGIC (Obfuscate Back) ---
    if el.getAttribute("data-revealed") == "true":
        original = el.getAttribute("data-original")
        if original: el.value = original
        
        el.removeAttribute("data-revealed")
        el.removeAttribute("data-original")
        el.classList.remove("reveal-active")
        
        if reveal_btn: 
            reveal_btn.innerHTML = "Transform Non-Standard Invisibles &#x21C4;"
        
        # Reset UI
        update_all(None)
        return

    # --- 2. TRANSFORM LOGIC ---
    raw_text = el.value
    new_chars = []
    total_replaced = 0
    
    for char in raw_text:
        cp = ord(char)
        replacement = None
        
        # [Phase 1] Explicit Space Visualization
        # We map standard ASCII Space (0x20) to a Middle Dot (·) 
        # This reveals double-spaces and trailing whitespace deterministically.
        if cp == 0x0020:
            replacement = "\u00B7" # · (Middle Dot)
            
        elif cp in INVISIBLE_MAPPING:
            replacement = INVISIBLE_MAPPING[cp]
        elif 0xFE00 <= cp <= 0xFE0F or 0xE0100 <= cp <= 0xE01EF:
            vs_offset = 1 if cp <= 0xFE0F else 17
            base = 0xFE00 if cp <= 0xFE0F else 0xE0100
            replacement = f"[VS{cp - base + vs_offset}]"
        elif 0xE0000 <= cp <= 0xE007F:
             replacement = f"[TAG:U+{cp:04X}]"
             
        if replacement:
            new_chars.append(replacement)
            total_replaced += 1
        else:
            new_chars.append(char)
            
    if total_replaced > 0:
        # Save state
        el.setAttribute("data-original", raw_text)
        el.setAttribute("data-revealed", "true")
        el.value = "".join(new_chars)
        el.classList.add("reveal-active")
        
        # Toggle Button Text
        if reveal_btn: 
            reveal_btn.style.display = "flex"
            reveal_btn.innerHTML = "Revert to Original &#x21A9;"
            
        if reveal2_btn: reveal2_btn.style.display = "flex"
        
        # Update RIGHT Status (Left remains "Input: Ready")
        details_line.className = "status-details success"
        icon_eye = """<svg style="display:inline-block; vertical-align:middle; margin-left:4px;" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#047857" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>"""
        details_line.innerHTML = f"Non-Standard Invisibles:&nbsp;{total_replaced}&nbsp;Deobfuscated&nbsp;{icon_eye}"

@create_proxy
def reveal2_invisibles(event=None):
    """
    HIGHLIGHT MODE (btn-reveal2): 
    Step-through finder. Selects the NEXT invisible character relative to cursor.
    UPDATED: Now correctly syncs with the Inspector Panel.
    """
    el = document.getElementById("text-input")
    details_line = document.getElementById("reveal-details")
    
    if not el or not el.value: return
    
    text = str(el.value)
    ranges = []
    current_utf16_idx = 0
    
    # 1. Map all invisible positions
    for char in text:
        cp = ord(char)
        char_len = 2 if cp > 0xFFFF else 1 # UTF-16 Length
        
        is_target = False
        if cp in INVISIBLE_MAPPING: is_target = True
        elif 0xFE00 <= cp <= 0xFE0F or 0xE0100 <= cp <= 0xE01EF: is_target = True
        elif 0xE0000 <= cp <= 0xE007F: is_target = True
            
        if is_target:
            ranges.append((current_utf16_idx, current_utf16_idx + char_len))
            
        current_utf16_idx += char_len

    count = len(ranges)
    if count == 0: return

    # 2. Find the NEXT target relative to the END of the current selection.
    current_end_pos = el.selectionEnd
    
    target_range = None
    target_idx = 1
    
    # Scan for the first range that starts AFTER (or at) the current cursor end
    for i, r in enumerate(ranges):
        if r[0] >= current_end_pos:
            target_range = r
            target_idx = i + 1
            break
            
    # 3. Wrap-around Logic (Infinite Cycle)
    if target_range is None:
        target_range = ranges[0]
        target_idx = 1
            
    # 4. Execute Selection
    el.blur()
    el.focus()
    el.setSelectionRange(target_range[0], target_range[1])
    
    # --- SYNC FIX: WAKE UP THE INSPECTOR --- (we can use {char_code} in NSI status bar if we need explicit Unicode)
    # We manually call the inspector logic to update the bottom panel immediately.
    # We pass None because the function doesn't actually use the event argument.
    inspect_character(None)
    
    # 5. Feedback
    if details_line:
        details_line.className = "status-details warn"
        icon_loc = """<svg style="display:inline-block; vertical-align:middle; margin-right:6px;" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#d97706" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z"></path><circle cx="12" cy="10" r="3"></circle></svg>"""
        
        # Get hex code for display
        try:
            raw_idx = 0
            acc = 0
            for j, char in enumerate(text):
                slen = 2 if ord(char) > 0xFFFF else 1
                if acc == target_range[0]:
                    raw_idx = j
                    break
                acc += slen
            
            char_code = f"U+{ord(text[raw_idx]):04X}"
        except:
            char_code = "INVISIBLE"

        details_line.innerHTML = f"<strong>NSI Highlighter:</strong>&nbsp;#{target_idx}&nbsp;of&nbsp;{count}&nbsp;{icon_loc}"

@create_proxy
def sanitize_text(profile_type):
    """
    Forensic Remediation Engine.
    Profiles:
      - 'strict': Nukes ALL characters matching INVIS_ANY_MASK.
      - 'smart': Removes 'Artifacts' (ZWSP, LRM) but PRESERVES structural ZWJ/VS for Emojis.
    """
    el = document.getElementById("text-input")
    if not el or not el.value: return
    
    raw_text = el.value
    new_chars = []
    removed_count = 0
    
    # [Smart Profile Logic]
    # We need to know which ZWJs are "load-bearing" (part of valid emojis).
    # We re-run a quick analysis to find RGI sequences if in smart mode.
    valid_emoji_indices = set()
    if profile_type == 'smart':
        # Reuse the centralized Emoji Engine logic
        # We scan for RGI sequences and whitelist their internal indices
        report = compute_emoji_analysis(raw_text)
        emoji_list = report.get("emoji_list", [])
        for item in emoji_list:
            # If it's a sequence, mark its internal positions as protected
            if item['kind'] == 'emoji-sequence' and item['rgi']:
                start = item['index']
                length = len(item['sequence'])
                for k in range(start, start + length):
                    valid_emoji_indices.add(k)

    for i, char in enumerate(raw_text):
        cp = ord(char)
        mask = INVIS_TABLE[cp] if cp < 1114112 else 0
        should_remove = False
        
        if mask & INVIS_ANY_MASK:
            # 1. STRICT MODE: Destroy everything invisible
            if profile_type == 'strict':
                should_remove = True
                
            # 2. SMART MODE: Targeted remediation
            elif profile_type == 'smart':
                # ALWAYS remove High-Risk Artifacts (ZWSP, Bidi, Tags)
                if cp in (0x200B, 0x200E, 0x200F, 0x202A, 0x202B, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069):
                    should_remove = True
                # Remove deprecated/zombie controls
                elif 0x206A <= cp <= 0x206F:
                    should_remove = True
                # Remove Plane 14 Tags
                elif mask & INVIS_TAG:
                    should_remove = True
                
                # PROTECT Structural Glue (ZWJ/VS) only if inside a valid Emoji
                # [FIXED] Now includes VS15 (0xFE0E) in protection list
                elif cp in (0x200D, 0xFE0F, 0xFE0E):
                    if i not in valid_emoji_indices:
                        should_remove = True
                        
        if not should_remove:
            new_chars.append(char)
        else:
            removed_count += 1
            
    if removed_count > 0:
        el.value = "".join(new_chars)
        # Trigger full re-analysis
        update_all(None)
        
        # Feedback
        status_line = document.getElementById("status-line")
        if status_line:
            status_line.innerText = f"Sanitized {removed_count} particle(s) using '{profile_type.upper()}' profile."
            status_line.className = "status-ready"

@create_proxy
def analyze_html_metadata(raw_html_string: str):
    """
    [STAGE 1.5] METADATA WORKBENCH ORCHESTRATOR (v3.0 SOTA).
    
    Replaces Regex scanning with a Forensic Stack Simulation.
    1. Simulates Browser Physics (Inheritance/Cascade).
    2. Applies FIS Scoring (Impact * Sophistication).
    3. Renders a Dual-View (Report + Ghost Text).
    """
    # 1. Input Hygiene
    if not raw_html_string or len(raw_html_string.strip()) < 10:
        _update_css_workbench_ui(
            {"grade": "NEUTRAL", "score": 0, "vectors": []}, 
            [], 
            ""
        )
        return []

    try:
        # 2. THE PHYSICS PHASE (Simulation)
        # Instantiate the Stack Machine from Block 6
        parser = ForensicHTMLParser()
        parser.feed(raw_html_string)
        
        # 3. THE JUDGMENT PHASE (Auditing)
        # Pass raw physical findings to the Policy Auditor from Block 7
        audited_findings, ledger = _audit_metadata_findings(parser.findings)
        
        # 4. THE RENDER PHASE (View)
        # Generate the "Ghost View" (Forensic X-Ray HTML)
        ghost_html = parser.get_ghost_html()
        
        # Push to UI
        _update_css_workbench_ui(ledger, audited_findings, ghost_html)
        
        return audited_findings

    except Exception as e:
        # Fail gracefully in the UI if parsing crashes
        print(f"Metadata Analysis Error: {e}")
        _update_css_workbench_ui(
            {"grade": "ERROR", "score": 0, "vectors": []}, 
            [], 
            ""
        )
        return []

# This plugs the function into the browser's global scope
window.analyze_html_metadata = analyze_html_metadata

# Export & Utility Bridges

@create_proxy
def py_get_code_snippet(lang):
    """
    Generates a safe, escaped string literal of the current input 
    for use in Python or JavaScript source code.
    """
    el = document.getElementById("text-input")
    if not el or not el.value: return ""
    
    t = el.value
    output = ""
    
    # Forensic escaping: We want ASCII-safe output.
    # Logic: Escape anything non-printable, non-ASCII, or quote-breaking.
    
    if lang == 'python':
        escaped = ""
        for char in t:
            cp = ord(char)
            # Escape non-ascii, controls, quotes, and backslashes
            if cp < 32 or cp > 126 or cp == 0x5C or cp == 0x22 or cp == 0x27:
                if cp <= 0xFFFF:
                    escaped += f"\\u{cp:04x}"
                else:
                    escaped += f"\\U{cp:08x}"
            else:
                escaped += char
        output = f's = "{escaped}"'
        
    elif lang == 'javascript':
        escaped = ""
        for char in t:
            cp = ord(char)
            if cp < 32 or cp > 126 or cp == 0x5C or cp == 0x22 or cp == 0x27:
                if cp <= 0xFFFF:
                    escaped += f"\\u{cp:04x}"
                else:
                    escaped += f"\\u{{{cp:x}}}" # ES6 format for astral planes
            else:
                escaped += char
        output = f'const s = "{escaped}";'
        
    return output

@create_proxy
def py_generate_evidence():
    """
    Generates a full JSON forensic artifact and triggers a browser download.
    Re-runs analysis to ensure the snapshot is authoritative.
    """
    el = document.getElementById("text-input")
    if not el or not el.value: return
    
    t = el.value
    timestamp = window.Date.new().toISOString()
    
    # Re-run key analysis to get fresh data
    emoji_report = compute_emoji_analysis(t)
    threat_results = compute_threat_analysis(t, script_run_stats)
    
    # Calculate SHA-256 for Chain of Custody
    sha256 = hashlib.sha256(t.encode('utf-8')).hexdigest()
    
    evidence = {
        "meta": {
            "tool": "Text...tics Stage 1",
            "timestamp": timestamp,
            "version": "Forensic-v1.0"
        },
        "artifact": {
            "length_codepoints": len(t),
            "sha256": sha256,
            "raw_text": t
        },
        "analysis_snapshot": {
            "flags": list(threat_results.get('flags', {}).keys()),
            "emoji_counts": emoji_report.get('counts', {}),
            "hashes": threat_results.get('hashes', {}),
            "normalization_states": {
                "nfkc": threat_results.get('states', {}).get('s2', ''),
                "skeleton": threat_results.get('states', {}).get('s4', '')
            }
        }
    }
    
    # Convert to JSON
    json_str = json.dumps(evidence, indent=2, ensure_ascii=False)
    
    # Trigger Download via JS Blob
    blob = window.Blob.new([json_str], {type: "application/json"})
    url = window.URL.createObjectURL(blob)
    
    a = document.createElement("a")
    a.href = url
    a.download = f"forensic_artifact_{sha256[:8]}.json"
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    window.URL.revokeObjectURL(url)

@create_proxy
def py_get_stat_report_text():
    """
    Generates a rich, structured plaintext report of the Statistical Profile.
    (Hardened Version: Catches errors to prevent UI freeze)
    """
    try:
        el = document.getElementById("text-input")
        if not el or not el.value: return ""
        
        t = el.value
        # Safety: Handle if compute_statistical_profile fails
        try:
            stats = compute_statistical_profile(t)
        except Exception as e:
            return f"Error in computation: {e}"

        if not stats: return ""
        
        lines = []
        lines.append("[ Statistical & Lexical Profile ]")
        
        # 1. Thermodynamics & Density
        ent = stats.get("entropy", 0.0)
        ent_norm = stats.get("entropy_norm", 0.0)
        n = stats.get("entropy_n", 0)
        ascii_dens = stats.get("ascii_density", 0.0)
        
        # Updated Logic to match UI
        status_txt = "Unknown"
        if n < 64: status_txt = "Insufficient Data"
        elif ent > 6.3: status_txt = "High Density (Compressed / Encrypted)"
        elif ent > 4.8: status_txt = "Complex Structure (Code / Binary / Obfuscated)"
        elif ent > 3.5: status_txt = "Natural Language (Standard Text)"
        else: status_txt = "Low Entropy (Repetitive / Sparse)"
        
        lines.append("")
        lines.append("[ THERMODYNAMICS ]")
        lines.append(f"  Entropy: {ent:.2f} bits/byte (Saturation: {int(ent_norm*100)}%)")
        lines.append(f"  Context: {status_txt}")
        lines.append(f"  Storage: {n} bytes (ASCII: {ascii_dens}%)")
        
        # 2. Payloads
        payloads = stats.get("payloads", [])
        if payloads:
            lines.append("")
            lines.append(f"[ ! HEURISTIC PAYLOADS DETECTED ({len(payloads)}) ]")
            for p in payloads:
                 lines.append(f"  - {p.get('type','UNK')}: '{p.get('token','?')}' (H={p.get('entropy',0)})")
        
        # 3. Lexical Density
        ttr = stats.get("ttr", 0.0)
        uniq = stats.get("unique_tokens", 0)
        tot = stats.get("total_tokens", 0)
        ttr_seg = stats.get("ttr_segmented")
        seg_str = f" | Seg-TTR: {ttr_seg:.2f}" if ttr_seg else ""
        
        lines.append("")
        lines.append("[ LEXICAL DENSITY ]")
        lines.append(f"  TTR:     {ttr:.2f} ({uniq}/{tot} tokens){seg_str}")

        # 4. Top Tokens (Restored)
        top_toks = stats.get("top_tokens", [])
        if top_toks:
            lines.append("")
            lines.append("[ TOP TOKENS ]")
            token_strs = []
            for t in top_toks[:5]: # Limit to top 5
                token_strs.append(f"{t['token']} ({t['share']}%)")
            lines.append("  " + " | ".join(token_strs))
        
        # 5. Fingerprint (Category Dist)
        cd = stats.get("char_dist", {})
        l = cd.get('letters', 0)
        n_dig = cd.get('digits', 0)
        s = cd.get('sym', 0)
        w = cd.get('ws', 0)
        
        lines.append("")
        lines.append("[ FREQ. FINGERPRINT ]")
        lines.append(f"  Dist:    L:{l}% | N:{n_dig}% | S:{s}% | WS:{w}%")
        
        # 6. Layout Physics
        ls = stats.get("line_stats", {})
        count = ls.get("count", 0)
        if count > 0:
            lines.append("")
            lines.append("[ LAYOUT PHYSICS ]")
            lines.append(f"  Lines:   {count} (Empty: {ls.get('empty', 0)})")
            # Safe access with defaults
            p25 = ls.get('p25', '-')
            p75 = ls.get('p75', '-')
            lines.append(f"  Widths:  Min:{ls.get('min',0)}  P25:{p25}  Med:{ls.get('median',0)}  P75:{p75}  Max:{ls.get('max',0)}")
            lines.append(f"  Average: {ls.get('avg',0)}")

        # 7. Phonotactics
        ph = stats.get("phonotactics", {})
        if ph.get("is_valid", False):
            lines.append("")
            lines.append("[ ASCII PHONOTACTICS ]")
            lines.append(f"  V/C Ratio:   {ph.get('vowel_ratio', 0)}")
            lines.append(f"  Balance:     Vowels: {ph.get('v_count', 0)} | Consonants: {ph.get('c_count', 0)}")
            lines.append(f"  Letter Dens: {ph.get('count', 0)} chars")
            lines.append(f"  Entropy:     {ph.get('bits_per_phoneme', 0)} bits/phoneme")
            lines.append(f"  Scoring:     Uni:{ph.get('uni_score',0)}% | Bi:{ph.get('bi_score',0)}% | Tri:{ph.get('tri_score',0)}%")

        return "\n".join(lines)
    
    except Exception as e:
        return f"Error generating stats report: {str(e)}"

# --- AUTOMATIC INJECTION: FDD0 Noncharacters ---
# Range U+FDD0 to U+FDEF are process-internal noncharacters.
# They indicate internal memory leaks or fuzzing attacks.
# We map them programmatically to [NON:D0]..[NON:EF] for visibility.
for i in range(0xFDD0, 0xFDF0):
    INVISIBLE_MAPPING[i] = f"[NON:{i-0xFDD0:02X}]"

# --- JS EXPORTS ---
window.TEXTTICS_SANITIZE = sanitize_text
window.TEXTTICS_HIGHLIGHT_CHAR = highlight_specific_char
window.cycle_hud_metric = cycle_hud_metric
window.TEXTTICS_FIND_SEQ = find_next_sequence
window.py_get_code_snippet = py_get_code_snippet
window.py_generate_evidence = py_generate_evidence
window.py_get_stat_report_text = py_get_stat_report_text
window.py_analyze_html_metadata = create_proxy(analyze_html_metadata)

# Programmatically inject the full range of ASCII-Mapped Tags (Plane 14)
# Range: U+E0020 (Tag Space) to U+E007E (Tag Tilde)
# This converts U+E0041 to "[TAG:A]", U+E0030 to "[TAG:0]", etc.
for ascii_val in range(0x20, 0x7F):
    tag_cp = 0xE0000 + ascii_val
    if ascii_val == 0x20:
         INVISIBLE_MAPPING[tag_cp] = "[TAG:SP]" # Explicit Space
    else:
         INVISIBLE_MAPPING[tag_cp] = f"[TAG:{chr(ascii_val)}]"

# ===============================================
# BLOCK 11. INITIALIZATION (BOOTLOADER)
# ===============================================

async def main():
    """Main entry point: Loads data, then hooks the input."""
    
    # --- Get element first ---
    text_input_element = document.getElementById("text-input")
    
    # Start loading the external data and wait for it to finish.
    await load_unicode_data()
    
    # --- Bind listener *after* await ---
    if text_input_element:
        text_input_element.addEventListener("input", update_all)
    
    # --- Hook the Inspector Panel ---
    document.addEventListener("selectionchange", create_proxy(inspect_character))

    # Update verification bench when selection changes (for Scope Selection)
    document.addEventListener("selectionchange", update_verification)

    # --- Hook the Reveal Buttons ---
    reveal_btn = document.getElementById("btn-reveal")
    if reveal_btn:
        reveal_btn.addEventListener("click", reveal_invisibles)
        
    reveal2_btn = document.getElementById("btn-reveal2")
    if reveal2_btn:
        reveal2_btn.addEventListener("click", reveal2_invisibles)

    # --- Hook the Verification Bench ---
    trusted_input = document.getElementById("trusted-input")
    if trusted_input:
        trusted_input.addEventListener("input", update_verification)
        # Also re-run verification if main input changes (to keep verdict in sync)
        if text_input_element:
            text_input_element.addEventListener("input", update_verification)
    
    # --- Un-gate the UI ---
    if text_input_element:
        text_input_element.disabled = False
        text_input_element.placeholder = "Paste or type here..."
        
    print("Text...tics is ready.")

# Start the main asynchronous task
asyncio.ensure_future(main())
