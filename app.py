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

def get_icon(key, color="currentColor", size=16):
    path = ICONS.get(key, "")
    return f'<svg xmlns="http://www.w3.org/2000/svg" width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" stroke="{color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">{path}</svg>'
    
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

# Aggregates
INVIS_ANY_MASK = (
    INVIS_DEFAULT_IGNORABLE | INVIS_JOIN_CONTROL | INVIS_ZERO_WIDTH_SPACING |
    INVIS_BIDI_CONTROL | INVIS_TAG | INVIS_VARIATION_STANDARD |
    INVIS_VARIATION_IDEOG | INVIS_DO_NOT_EMIT | INVIS_SOFT_HYPHEN |
    INVIS_NON_ASCII_SPACE | INVIS_NONSTANDARD_NL
)
INVIS_HIGH_RISK_MASK = INVIS_BIDI_CONTROL | INVIS_TAG | INVIS_DO_NOT_EMIT

# The O(1) Lookup Table (Populated in load_unicode_data)
INVIS_TABLE = [0] * 1114112  # Covers all of Unicode (0x110000)


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

    # 1. Default Ignorable
    ignorable_ranges = DATA_STORES.get("DefaultIgnorable", {}).get("ranges", [])
    apply_mask(ignorable_ranges, INVIS_DEFAULT_IGNORABLE)

    # 2. Join Controls
    apply_mask([(0x200C, 0x200D)], INVIS_JOIN_CONTROL)
    # --- Explicitly catch CGJ (U+034F) as a Join Control ---
    # It acts as invisible glue, so we treat it as a structural joiner for forensics.
    apply_mask([(0x034F, 0x034F)], INVIS_JOIN_CONTROL)

    # 3. Zero Width Spacing
    apply_mask([(0x200B, 0x200B), (0x2060, 0x2060), (0xFEFF, 0xFEFF)], INVIS_ZERO_WIDTH_SPACING)

    # 4. Bidi Controls
    bidi_ranges = DATA_STORES.get("BidiControl", {}).get("ranges", [])
    apply_mask(bidi_ranges, INVIS_BIDI_CONTROL)

    # 5. Tags
    apply_mask([(0xE0000, 0xE007F)], INVIS_TAG)

    # 6. Variation Selectors
    apply_mask([(0xFE00, 0xFE0F)], INVIS_VARIATION_STANDARD)
    apply_mask([(0xE0100, 0xE01EF)], INVIS_VARIATION_IDEOG)

    # 7. Do Not Emit
    apply_mask(DATA_STORES.get("DoNotEmit", {}).get("ranges", []), INVIS_DO_NOT_EMIT)

    # 8. Soft Hyphen
    apply_mask([(0x00AD, 0x00AD)], INVIS_SOFT_HYPHEN)

    # 9. Non-Standard Newlines
    apply_mask([(0x2028, 0x2029)], INVIS_NONSTANDARD_NL)

    # 10. Non-ASCII Spaces (Zs != 0x20)
    # [UPDATE] Explicitly included MVS (0x180E) and Ogham (0x1680)
    zs_ranges = [
        (0x00A0, 0x00A0), (0x1680, 0x1680), (0x180E, 0x180E), 
        (0x2000, 0x200A), (0x202F, 0x202F), (0x205F, 0x205F), 
        (0x3000, 0x3000)
    ]
    apply_mask(zs_ranges, INVIS_NON_ASCII_SPACE)

    # --- MANUAL FORENSIC OVERRIDES (From Tables 1-8) ---
    
    # 1. The "False Vacuums" (Letters/Symbols that act as Spaces)
    # We map these to INVIS_NON_ASCII_SPACE so they trigger "Deceptive Space" flags.
    # U+3164 (Hangul Filler), U+FFA0 (Halfwidth Filler), U+2800 (Braille Blank)
    apply_mask([(0x3164, 0x3164), (0xFFA0, 0xFFA0), (0x2800, 0x2800)], INVIS_NON_ASCII_SPACE)

    # 2. The "Ghost Operators" & "Fillers"
    # These are technically 'Lo' (Letters) or 'Cf' (Format) but behave like invisibles.
    # U+115F (Choseong), U+1160 (Jungseong), U+2064 (Invisible Plus)
    # We map these to INVIS_DEFAULT_IGNORABLE so they trigger "Invisible" flags.
    apply_mask([(0x115F, 0x1160), (0x2061, 0x2064)], INVIS_DEFAULT_IGNORABLE)

    # 3. The "Structural Containers" (Scoping)
    # Egyptian, Musical, Shorthand format controls.
    # Map to INVIS_DEFAULT_IGNORABLE.
    apply_mask([
        (0x13437, 0x13438), # Egyptian
        (0x1D173, 0x1D17A), # Musical
        (0x1BCA0, 0x1BCA3)  # Shorthand
    ], INVIS_DEFAULT_IGNORABLE)

    # 4. The "Zombie Controls" & Invisible Math
    # These are Format (Cf) characters that are deprecated or invisible.
    # Map to INVIS_DEFAULT_IGNORABLE.
    apply_mask([
        (0x206A, 0x206F), # Deprecated Formatting (ISS, ASS, etc.)
        (0x2061, 0x2063), # Invisible Math (FA, IT, IS)
        (0x17B4, 0x17B5)  # Khmer Invisible Vowels
    ], INVIS_DEFAULT_IGNORABLE)
    
    # 5. Object Replacement Character
    # Technically 'So' (Symbol), but acts as a placeholder.
    # Map to INVIS_DEFAULT_IGNORABLE to ensure it's flagged.
    apply_mask([(0xFFFC, 0xFFFC)], INVIS_DEFAULT_IGNORABLE)

    # 4. The "Layout Locks" (Glue)
    # These prevent line breaks. We don't have a specific bitmask for "Glue" yet, 
    # but if you want to detect "Layout Sabotage", you might map them to INVIS_ZERO_WIDTH_SPACING
    # or create a new mask. For now, leaving them as visual characters is safer 
    # unless you want to flag them as "Suspicious". 
    # (Recommendation: Leave unmasked for now, rely on the [TAG] mapping in Part 1 for visibility).

def run_self_tests():
    """
    PARANOID MODE: Verify that INVIS_TABLE bitmasks strictly match the UCD data.
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

def compute_threat_score(t):
    """
    Aggregates all forensic signals into a single Threat Level (Low/Medium/High).
    't' is a dictionary of core stats extracted from the analysis modules.
    """
    score = 0
    reasons = []
    
    total_cps = max(1, t.get("total_code_points", 1))
    invis_share = t.get("invis_or_ignorable", 0) / total_cps

    # 1. Bidi Controls (Trojan Source)
    bidi = t.get("bidi_controls", 0)
    if bidi >= 1: reasons.append(f"Bidi controls present ({bidi})")
    if bidi >= 3: score += 2
    if bidi >= 6: score += 1

    # 2. Invisible Runs
    max_run = t.get("max_invis_run", 0)
    if max_run >= 4: reasons.append(f"invisible run ≥ 4 (len={max_run})")
    if max_run >= 8: score += 3
    elif max_run >= 4: score += 1

    # 3. Invisible Share
    if invis_share >= 0.30:
        # Standardize to 1 decimal place
        reasons.append(f"invisibles ≥ 30% (≈{invis_share*100:.1f}%)")
        score += 3
    elif invis_share >= 0.10:
        score += 1

    # 4. Deceptive Spaces
    dec_spaces = t.get("deceptive_spaces", 0)
    if dec_spaces >= 5:
        reasons.append(f"deceptive spaces ≥ 5 (found {dec_spaces})")
        score += 2
    elif dec_spaces >= 1:
        score += 1

    # 5. Skeleton Drift
    drift = t.get("skeleton_drift", 0)
    if drift >= 1: reasons.append(f"skeleton drift ≥ 1 ({drift} positions)")
    if drift >= 5: score += 2
    if drift >= 15: score += 1

    # 6. Hard Indicators
    if t.get("has_internal_bom"):
        reasons.append("Internal BOM")
        score += 2
    if t.get("has_invalid_vs"):
        reasons.append("Invalid Variation Selector")
        score += 2
    if t.get("has_unclosed_bidi"):
        reasons.append("Unclosed Bidi Sequence")
        score += 3
    if t.get("is_not_nfc"):
        reasons.append("Not NFC")
        score += 1
    if t.get("has_hidden_marks"):
        reasons.append("Marks on non-visual base")
        score += 1
        
    # 7. Zalgo
    nsm_level = t.get("nsm_level", 0)
    if nsm_level == 2:
        reasons.append("Extreme Combining Marks (Zalgo)")
        score += 2
    elif nsm_level == 1:
        score += 1

    # Map to Level
    if score >= 10: level = "HIGH"
    elif score >= 5: level = "MEDIUM"
    else: level = "LOW"

    return {
        "level": level,
        "score": score,
        "reasons": reasons
    }

def analyze_bidi_structure(t: str, rows: list):
    """
    UAX #9 COMPLIANT BIDI STACK MACHINE
    Implements a single Unified Stack to correctly model Isolates vs Embeddings.
    Detects: Spillover, Unmatched Formatters, and Implicit Closures.
    """
    if LOADING_STATE != "READY": return 0

    # --- 1. DATA MODELS & CONSTANTS ---
    
    # Sets for fast lookup
    ISO_INIT = {0x2066, 0x2067, 0x2068} # LRI, RLI, FSI
    EMB_INIT = {0x202A, 0x202B, 0x202D, 0x202E} # LRE, RLE, LRO, RLO
    VAL_PDI = 0x2069
    VAL_PDF = 0x202C
    
    # The Unified Stack
    # Each frame is a dict: {'kind': str, 'is_isolate': bool, 'pos': int, 'cp': int}
    # kind = 'isolate' | 'embedding' | 'override'
    main_stack = [] 
    
    # Bracket Stack (Still needed separately for paired-bracket checks)
    bracket_stack = [] 
    mirror_map = DATA_STORES.get("BidiMirroring", {})

    # Anomaly accumulators
    anomalies = {
        "unmatched_pdf": [],      # PDF with no matching embedding
        "unmatched_pdi": [],      # PDI with no matching isolate
        "implicit_closure": [],   # Embeddings closed by PDI (Sloppy but valid)
        "unclosed_isolate": [],   # Spillover at EOF
        "unclosed_embedding": [], # Spillover at EOF
        "bracket_mismatch": [],   # ( [ )
        "bracket_unclosed": []    # ( ... EOF
    }
    
    js_array = window.Array.from_(t)
    
    for i, char in enumerate(js_array):
        cp = ord(char)
        
        # --- A. PUSH (Open Scope) ---
        if cp in ISO_INIT:
            # LRI/RLI/FSI -> Isolate
            main_stack.append({
                'kind': 'isolate', 
                'is_isolate': True, 
                'pos': i, 
                'cp': cp
            })
            
        elif cp in EMB_INIT:
            # LRE/RLE/LRO/RLO -> Embedding/Override
            kind = 'override' if cp in {0x202D, 0x202E} else 'embedding'
            main_stack.append({
                'kind': kind, 
                'is_isolate': False, 
                'pos': i, 
                'cp': cp
            })

        # --- B. POP PDF (Close Embedding) - Rule X7 ---
        elif cp == VAL_PDF:
            # Rule X7: Pop ONLY if stack is not empty AND top is NOT an isolate.
            if main_stack and not main_stack[-1]['is_isolate']:
                main_stack.pop()
            else:
                # If top is isolate, or stack empty -> PDF is ignored.
                anomalies["unmatched_pdf"].append(f"#{i}")

        # --- C. POP PDI (Close Isolate) - Rule X6a ---
        elif cp == VAL_PDI:
            # Rule X6a: Find nearest open isolate.
            # Scan stack backwards
            isolate_index = -1
            for idx in range(len(main_stack) - 1, -1, -1):
                if main_stack[idx]['is_isolate']:
                    isolate_index = idx
                    break
            
            if isolate_index == -1:
                # No isolate found -> PDI is ignored.
                anomalies["unmatched_pdi"].append(f"#{i}")
            else:
                # Isolate found. 
                # 1. Check for implicit closure (Embeddings sitting above the isolate)
                # If the isolate is NOT at the top, everything above it gets implicitly closed.
                if isolate_index != len(main_stack) - 1:
                    # Report the implicitly closed embeddings
                    for frame in main_stack[isolate_index+1:]:
                        # We flag the LOCATION of the closing PDI as the cause
                        anomalies["implicit_closure"].append(f"#{i} (Closes #{frame['pos']})")
                
                # 2. Pop the isolate and everything above it (Truncate stack)
                # This implements "Terminate the scope of the isolate and any embeddings within it"
                del main_stack[isolate_index:]

        # --- D. BRACKETS (Keep existing strict logic) ---
        b_type = _find_in_ranges(cp, "BidiBracketType")
        if b_type == "o":
            expected = mirror_map.get(cp, cp)
            bracket_stack.append((i, expected))
        elif b_type == "c":
            if not bracket_stack:
                anomalies["bracket_mismatch"].append(f"#{i} (Stray)")
            else:
                top_idx, required = bracket_stack[-1]
                if cp == required:
                    bracket_stack.pop()
                else:
                    # Mismatch!
                    anomalies["bracket_mismatch"].append(f"#{i} (Expected {chr(required)})")

    # --- E. FINAL SWEEP (Spillover) ---
    # Anything left on stack is unclosed at EOF
    for frame in main_stack:
        label = f"#{frame['pos']}"
        if frame['is_isolate']:
            anomalies["unclosed_isolate"].append(label)
        else:
            anomalies["unclosed_embedding"].append(label)
            
    for idx, _ in bracket_stack:
        anomalies["bracket_unclosed"].append(f"#{idx}")

    # --- F. REPORT GENERATION ---
    
    # 1. Spillover (High Severity)
    if anomalies["unclosed_isolate"]:
        rows.append({
            "label": "Flag: Unclosed Bidi Isolate (Spillover)",
            "count": len(anomalies["unclosed_isolate"]),
            "positions": anomalies["unclosed_isolate"],
            "severity": "crit", "badge": "SPILLOVER"
        })
    if anomalies["unclosed_embedding"]:
        rows.append({
            "label": "Flag: Unclosed Bidi Embedding (Spillover)",
            "count": len(anomalies["unclosed_embedding"]),
            "positions": anomalies["unclosed_embedding"],
            "severity": "warn", "badge": "SPILLOVER" # Lower severity for legacy embeddings
        })
    if anomalies["bracket_unclosed"]:
        rows.append({
            "label": "Flag: Unclosed Bidi Brackets",
            "count": len(anomalies["bracket_unclosed"]),
            "positions": anomalies["bracket_unclosed"],
            "severity": "crit", "badge": "SPILLOVER"
        })

    # 2. Hygiene / Structure (Medium Severity)
    if anomalies["implicit_closure"]:
        rows.append({
            "label": "Flag: Implicit Embedding Closure (PDI)",
            "count": len(anomalies["implicit_closure"]),
            "positions": anomalies["implicit_closure"],
            "severity": "warn", "badge": "HYGIENE"
        })
    if anomalies["bracket_mismatch"]:
        rows.append({
            "label": "Flag: Bidi Bracket Mismatch",
            "count": len(anomalies["bracket_mismatch"]),
            "positions": anomalies["bracket_mismatch"],
            "severity": "crit", "badge": "BROKEN"
        })

    # 3. Ignored/Stray (Low Severity)
    if anomalies["unmatched_pdf"]:
        rows.append({
            "label": "Flag: Unmatched PDF (Ignored)",
            "count": len(anomalies["unmatched_pdf"]),
            "positions": anomalies["unmatched_pdf"],
            "severity": "ok", "badge": None # OK/Info because renderer ignores it
        })
    if anomalies["unmatched_pdi"]:
        rows.append({
            "label": "Flag: Unmatched PDI (Ignored)",
            "count": len(anomalies["unmatched_pdi"]),
            "positions": anomalies["unmatched_pdi"],
            "severity": "ok", "badge": None
        })

    # Total Structural Penalties (For Integrity Score)
    # We weigh them: Spillover = 1, Mismatch = 1, Implicit/Stray = 0 (Hygiene only)
    penalty_count = (len(anomalies["unclosed_isolate"]) + 
                     len(anomalies["unclosed_embedding"]) + 
                     len(anomalies["bracket_unclosed"]) + 
                     len(anomalies["bracket_mismatch"]))
                     
    return penalty_count

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
    
    # --- Invisible Math & Format ---
    0x2061: "[FA]",            # Function Application
    0x2062: "[IT]",            # Invisible Times
    0x2063: "[IS]",            # Invisible Separator
    
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

    # 1. Invisible Khmer Vowels (Fillers)
    0x17B4: "[KHM:AQ]",        # Khmer Vowel Inherent AQ
    0x17B5: "[KHM:AA]",        # Khmer Vowel Inherent AA
    
    # 2. Invisible Math Operators
    0x2061: "[FA]",            # Function Application
    0x2062: "[IT]",            # Invisible Times
    0x2063: "[IS]",            # Invisible Separator
    # (U+2064 Invisible Plus was added in Wave 1)

    # 3. The "Rich Text Ghost"
    0xFFFC: "[OBJ]",           # Object Replacement Character

    # 4. The "Zombie Controls" (Deprecated Format Characters)
    0x206A: "[ISS]",           # Inhibit Symmetric Swapping
    0x206B: "[ASS]",           # Activate Symmetric Swapping
    0x206C: "[IAFS]",          # Inhibit Arabic Form Shaping
    0x206D: "[AAFS]",          # Activate Arabic Form Shaping
    0x206E: "[NDS]",           # National Digit Shapes
    0x206F: "[NODS]",          # Nominal Digit Shapes
    
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

    # --- Wave 4: Invisible Khmer Vowels ---
    0x17B4: "[KHM:AQ]",        # Khmer Vowel Inherent AQ
    0x17B5: "[KHM:AA]",        # Khmer Vowel Inherent AA
    
    # --- Wave 4: Invisible Math (Remaining) ---
    # (U+2064 is already present as [INV+])
    0x2061: "[FA]",            # Function Application
    0x2062: "[IT]",            # Invisible Times
    0x2063: "[IS]",            # Invisible Separator
    
    # --- Wave 4: Rich Text Ghost ---
    0xFFFC: "[OBJ]",           # Object Replacement Character

    # --- Wave 4: Zombie Controls (Deprecated Format) ---
    0x206A: "[ISS]",           # Inhibit Symmetric Swapping
    0x206B: "[ASS]",           # Activate Symmetric Swapping
    0x206C: "[IAFS]",          # Inhibit Arabic Form Shaping
    0x206D: "[AAFS]",          # Activate Arabic Form Shaping
    0x206E: "[NDS]",           # National Digit Shapes
    0x206F: "[NODS]",          # Nominal Digit Shapes
}

# Programmatically inject the full range of ASCII-Mapped Tags (Plane 14)
# Range: U+E0020 (Tag Space) to U+E007E (Tag Tilde)
# This converts U+E0041 to "[TAG:A]", U+E0030 to "[TAG:0]", etc.
for ascii_val in range(0x20, 0x7F):
    tag_cp = 0xE0000 + ascii_val
    if ascii_val == 0x20:
         INVISIBLE_MAPPING[tag_cp] = "[TAG:SP]" # Explicit Space
    else:
         INVISIBLE_MAPPING[tag_cp] = f"[TAG:{chr(ascii_val)}]"


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

        # --- CRITICAL FIX: Create the bucket dynamically ---
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

        # --- Add Manual Security Overrides ---
        _add_manual_data_overrides()    
        
        # --- NEW: Build Forensic Bitmask Table ---
        # This must happen AFTER all parsing is done
        build_invis_table()
        
        # --- NEW: Run Paranoid Self-Tests ---
        run_self_tests()
        
        LOADING_STATE = "READY"
        print("Unicode data loaded successfully.")
        render_status("Ready.")
        update_all() # Re-render with ready state
        
    except Exception as e:
        LOADING_STATE = "FAILED"
        print(f"CRITICAL: Unicode data loading failed. Error: {e}")
        # --- CRITICAL FIX: Remove 'is_error=True' ---
        render_status("Error: Failed to load Unicode data. Please refresh.")

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

def compute_forensic_stats_with_positions(t: str, cp_minor_stats: dict, emoji_flags: dict):
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
        "other_ctrl": [], "esc": [], "interlinear": [], # Specific trackers
        "bidi_mirrored": [], "loe": [], "unassigned": [], "suspicious_syntax_vs": []
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
        "fffd": [], "surrogate": [], "nonchar": [], 
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
                if (0xFDD0 <= cp <= 0xFDEF) or ((cp & 0xFFFF) >= 0xFFFE):
                    health_issues["nonchar"].append(i)
                if mask & INVIS_DO_NOT_EMIT: health_issues["donotemit"].append(i)

                # --- Specific Dangerous Controls [NEW] ---
                if cp == 0x001B: # ESC (Terminal Injection)
                    legacy_indices["esc"].append(i)
                
                if 0xFFF9 <= cp <= 0xFFFB: # Interlinear Controls
                    legacy_indices["interlinear"].append(i)

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

                # --- 17.0 Syntax Spoofing & Sibe Quotes ---
                # Detects Variation Selectors attached to Syntax (Punctuation, Symbols, Separators).
                # Covers: Sibe Quotes (Quote+VS3), Math Obfuscation, and Space+VS trim bypass.
                # CRITICAL: Must strictly exempt valid VS15/VS16 Emoji sequences to avoid false positives.
                if mask & (INVIS_VARIATION_STANDARD | INVIS_VARIATION_IDEOG):
                    if i > 0:
                        prev_char = js_array[i-1]
                        prev_cp = ord(prev_char)
                        prev_cat = unicodedata.category(prev_char) # e.g. 'Po', 'Sm', 'Zs'
                        
                        # Target: Punctuation (P), Symbols (S), Separators (Z)
                        if prev_cat[0] in ('P', 'S', 'Z'):
                            
                            # 1. CHECK EXEMPTION: Valid Emoji Presentation Sequence?
                            # Rule: Base must be Emoji/Pictographic AND VS must be VS15/VS16.
                            is_emoji_base = _find_in_ranges(prev_cp, "Emoji") or \
                                            _find_in_ranges(prev_cp, "Extended_Pictographic")
                            
                            is_pres_selector = (cp == 0xFE0E or cp == 0xFE0F)
                            
                            if is_emoji_base and is_pres_selector:
                                pass # SAFE: Standard, RGI-compliant presentation (e.g. ❤️)
                            else:
                                # DANGER DETECTED:
                                # Case A: Syntax + VS (e.g. " + VS3) -> Sibe Quote Attack
                                # Case B: Space + VS (e.g. ' ' + VS1) -> Trim Bypass
                                # Case C: Emoji + Bad VS (e.g. 😈 + VS1) -> Steganography/Obfuscation
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

    # --- 1. STRUCTURAL FEEDBACK LOOP (Gather Data) ---
    struct_rows = []
    
    # Run Sub-Analyzers
    bidi_broken_count = analyze_bidi_structure(t, struct_rows)
    cluster_max_len = summarize_invisible_clusters(t, struct_rows)
    analyze_combining_structure(t, struct_rows)

    # --- 2. INTEGRITY AUDITOR (The Logic Engine) ---
    # We gather all raw signals into a clean input object for the auditor.
    auditor_inputs = {
        # FATAL
        "fffd": len(health_issues["fffd"]),
        "surrogate": len(health_issues["surrogate"]),
        "nul": len(health_issues["nul"]),
        
        # FRACTURE
        "bidi_broken_count": bidi_broken_count,
        "broken_keycap": len(emoji_flags.get("Flag: Broken Keycap Sequence", {}).get("positions", [])), 
        "hidden_marks": len(legacy_indices["suspicious_syntax_vs"]), # Using syntax VS as proxy for hidden marks logic
        
        # RISK
        "tags": len(flags["tags"]),
        "nonchar": len(health_issues["nonchar"]),
        "invalid_vs": len(legacy_indices["invalid_vs"]),
        "donotemit": len(health_issues["donotemit"]),
        "max_cluster_len": cluster_max_len, # For cluster containment logic
        
        # DECAY
        "bom": len(health_issues["bom_mid"]),
        "pua": len(health_issues["pua"]),
        "legacy_ctrl": len(legacy_indices["other_ctrl"]),
        "dec_space": len(flags["non_ascii_space"]),
        "not_nfc": not (t == unicodedata.normalize("NFC", t)),
        "bidi_present": len(flags["bidi"])
    }

    # Calculate Score & Ledger
    audit_result = compute_integrity_score(auditor_inputs)

    # --- 3. RENDER SCORE ROW (With Ledger) ---
    rows.append({
        "label": "Integrity Level (Heuristic)",
        "count": audit_result["score"],
        "severity": audit_result["severity_class"],
        "badge": f"{audit_result['verdict']} (Score: {audit_result['score']})",
        "ledger": audit_result["ledger"], # [NEW] Pass the structured ledger
        "positions": [] # Legacy fallback
    })

    # --- 4. ADD DETAIL ROWS (Standard Flags) ---
    # We keep the full detail list for the "Flat View", 
    # even though the score is calculated via the Ledger.
    
    # FATAL / HIGH RISK
    add_row("DANGER: Terminal Injection (ESC)", len(legacy_indices["esc"]), legacy_indices["esc"], "crit")
    add_row("Flag: Replacement Char (U+FFFD)", len(health_issues["fffd"]), health_issues["fffd"], "crit")
    add_row("Flag: NUL (U+0000)", len(health_issues["nul"]), health_issues["nul"], "crit")
    add_row("Noncharacter", len(health_issues["nonchar"]), health_issues["nonchar"], "warn") # Downgraded to WARN per new logic
    add_row("Surrogates (Broken)", len(health_issues["surrogate"]), health_issues["surrogate"], "crit")
    
    # PROTOCOL / INTERCHANGE
    add_row("Flag: Bidi Controls (UAX #9)", len(flags["bidi"]), flags["bidi"], "warn") # General presence is warn
    add_row("Flag: Unicode Tags (Plane 14)", len(flags["tags"]), flags["tags"], "warn")
    add_row("Flag: High-Risk Invisible Controls", len(flags["high_risk"]), flags["high_risk"], "crit")
    add_row("Flag: Invalid Variation Selector", len(legacy_indices["invalid_vs"]), legacy_indices["invalid_vs"], "warn")
    add_row("Flag: Do-Not-Emit Characters", len(health_issues["donotemit"]), health_issues["donotemit"], "warn")

    # INVISIBLES & HYGIENE
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

    # INFORMATIONAL / OK PROPERTIES
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

    if bidi_mirroring_map:
        m_pos = [f"#{idx} ({m})" for idx, m in bidi_mirroring_map.items()]
        add_row("Flag: Bidi Mirrored Mapping", len(m_pos), m_pos, "ok")
        
    add_row("Flag: Full Composition Exclusion", len(legacy_indices["norm_excl"]), legacy_indices["norm_excl"], "warn")
    add_row("Flag: Changes on NFKC Casefold", len(legacy_indices["norm_fold"]), legacy_indices["norm_fold"], "warn")
    add_row("SUSPICIOUS: Variation Selector on Syntax", len(legacy_indices["suspicious_syntax_vs"]), legacy_indices["suspicious_syntax_vs"], "crit")

    for k, v in decomp_type_stats.items(): add_row(k, v['count'], v['positions'], "ok")
    for k, v in id_type_stats.items(): add_row(k, v['count'], v['positions'], "warn")

    rows.extend(struct_rows)

    return rows


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
    Hybrid Tokenizer for PVR View.
    Splits on: 1. Whitespace, 2. Major Punctuation, 3. Hard Length Cap.
    Prevents DOM Bloat on minified code, URLs, or large blobs.
    """
    tokens = []
    if not text: return tokens
    
    # Use window.Array.from to respect surrogate pairs/graphemes (JS-aligned)
    js_array = window.Array.from_(text)
    total_len = len(js_array)
    
    # Configuration
    MAX_TOKEN_LEN = 50 # Force split after 50 chars (Safety Cap)
    
    # Set of punctuation that should act as token boundaries
    PUNCT_SET = set(".,;:!?()[]{}<>\"'/\\|@#")
    
    current_start = 0
    current_type = None # 'word' or 'gap'
    
    i = 0
    while i < total_len:
        char = js_array[i]
        is_space = char.isspace()
        is_punct = char in PUNCT_SET
        
        # Determine type of current char
        # Punctuation is treated as a 'delimiter' that breaks a word
        if is_space:
            char_type = 'gap'
        elif is_punct:
            char_type = 'punct'
        else:
            char_type = 'word'
            
        # Initial State
        if current_type is None:
            current_type = char_type
            current_start = i
            i += 1
            continue
            
        # Check for Break Conditions
        should_break = False
        
        # 1. Type Change (Word -> Space, etc.)
        if char_type != current_type:
            should_break = True
            
        # 2. Punctuation Logic: Always breaks from Word, and breaks from itself
        # (This isolates dots in URLs: "paypal" "." "com")
        elif char_type == 'punct': 
            should_break = True 
            
        # 3. Hard Cap (DoS Protection for long blobs)
        elif (i - current_start) >= MAX_TOKEN_LEN:
            should_break = True
            
        if should_break:
            # Flush previous token
            segment_text = "".join(js_array[current_start:i])
            if segment_text:
                # Map internal types to output types ('word' or 'gap')
                # We map 'punct' to 'word' so the renderer can highlight it if it's a confusable
                out_type = 'gap' if current_type == 'gap' else 'word'
                tokens.append({'type': out_type, 'text': segment_text})
                
            current_start = i
            current_type = char_type
            
        i += 1
        
    # Flush Final Token
    segment_text = "".join(js_array[current_start:])
    if segment_text:
        out_type = 'gap' if current_type == 'gap' else 'word'
        tokens.append({'type': out_type, 'text': segment_text})

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
        skeleton_char_str = confusables_map.get(cp)
        
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

def compute_threat_analysis(t: str):
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

    # Initialize output variables
    nf_string = ""
    nf_casefold_string = ""
    skeleton_string = ""
    skel_metrics = {} # [NEW]
    final_html_report = ""

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
        # --- 2. Generate Normalized States ---
        nf_string = normalize_extended(t)
        nf_casefold_string = nf_string.casefold()

        # --- 5. Skeleton & Drift (Refined Logic) ---
        
        # A. The Skeleton String (Standard Identity)
        # Derived from the Canonical (Casefolded) form, for standard equivalence hashing.
        # We re-use the metrics function but ignore the metrics here.
        skeleton_string, _ = _generate_uts39_skeleton_metrics(nf_casefold_string)
        
        # B. The Forensic Drift Metrics (Forensic Insight)
        # [DRIFT BLINDNESS FIX]
        # We calculate drift by comparing the RAW input (t) against its Skeleton mapping.
        # This captures normalization changes (e.g. Fullwidth -> ASCII) as "Drift",
        # preserving the evidence of the original "weirdness".
        _, skel_metrics = _generate_uts39_skeleton_metrics(t)

        # --- 3. Run checks on RAW string ---
        confusables_map = DATA_STORES.get("Confusables", {})

        if LOADING_STATE == "READY":
            js_array_raw = window.Array.from_(t)

            for i, char in enumerate(js_array_raw):
                cp = ord(char)
                
                # --- A. Bidi Check (Trojan Source) ---
                if (0x202A <= cp <= 0x202E) or (0x2066 <= cp <= 0x2069):
                    bidi_danger_indices.append(f"#{i}")

                # --- B. Mixed-Script Detection (Spec-Compliant) ---
                try:
                    category = unicodedata.category(char)[0] 
                    if category in ("L", "N", "S"):
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
                
                # --- C. Confusable Indexing ---
                if cp in confusables_map and window.RegExp.new(r"\p{L}|\p{N}|\p{P}|\p{S}", "u").test(char):
                    found_confusable = True
                    confusable_indices.append(i)
                

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
                     threat_flags["Script Profile: Safe (Common/Inherited)"] = {'count': 0, 'positions': ["No specific script letters found."]}
                else:
                     threat_flags["Script Profile: ASCII-Only"] = {'count': 0, 'positions': ["Text is pure 7-bit ASCII."]}
            elif len(clean_base) == 1:
                s_name = list(clean_base)[0]
                if s_name == "Latin" and is_non_ascii_LNS:
                     threat_flags["Script Profile: Single Script (Latin Extended)"] = {'count': 0, 'positions': ["Latin script with non-ASCII characters."]}
                elif not threat_flags: 
                     threat_flags[f"Script Profile: Single Script ({s_name})"] = {'count': 0, 'positions': ["Text is consistent."]}


        # --- 5. Skeleton Drift (METRICS ENGINE) ---
        skeleton_string, skel_metrics = _generate_uts39_skeleton_metrics(nf_casefold_string)
        
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

        # --- 6. Hashes ---
        threat_hashes["State 1: Forensic (Raw)"] = _get_hash(t)
        threat_hashes["State 2: NFKC"] = _get_hash(nf_string)
        threat_hashes["State 3: NFKC-Casefold"] = _get_hash(nf_casefold_string)
        threat_hashes["State 4: UTS #39 Skeleton"] = _get_hash(skeleton_string)

        # --- 7. HTML Report ---
        if found_confusable:
            final_html_report = _render_confusable_summary_view(t, set(confusable_indices), confusables_map)
        else:
            final_html_report = ""

    except Exception as e:
        print(f"Error in compute_threat_analysis: {e}")
        if not nf_string: nf_string = t 
        if not nf_casefold_string: nf_casefold_string = t.casefold()
        if not skeleton_string: skeleton_string = t
        final_html_report = "<p class='placeholder-text'>Error generating confusable report.</p>"

    return {
        'flags': threat_flags,
        'hashes': threat_hashes,
        'html_report': final_html_report,
        'bidi_danger': bool(bidi_danger_indices),
        'script_mix_class': script_mix_class,
        'skel_metrics': skel_metrics, # [KEY] Pass metrics to scorer
        'raw': t, 'nfkc': nf_string, 'nfkc_cf': nf_casefold_string, 'skeleton': skeleton_string
    }
    
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
    
    banner_el = document.getElementById("threat-banner")
    if banner_el: banner_el.setAttribute("hidden", "true")

# ---
# 4. DOM RENDERER FUNCTIONS
# ---
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

def render_emoji_qualification_table(emoji_list: list, text_context=None):
    """Renders the new Emoji Qualification Profile table."""
    element = document.getElementById("emoji-qualification-body")
    if not element: return
    if not emoji_list:
        element.innerHTML = "<tr><td colspan='4' class='placeholder-text'>No RGI emoji sequences detected.</td></tr>"
        return

    grouped = {}
    for item in emoji_list:
        seq = item.get("sequence", "?")
        status = item.get("status", "unknown").replace("-", " ").title()
        index = item.get("index", 0)
        key = (seq, status)
        if key not in grouped: grouped[key] = []
        
        # [ACTIVE UPDATE] Use the link helper
        # PASS text_context HERE
        grouped[key].append(_create_position_link(index, text_context))

    # 2. Build HTML string
    html = []
    
    # Sort by the first index to keep them in order of appearance
    try:
        # We need to strip html tags to sort by the number inside
        def get_sort_idx(k):
            raw_link = grouped[k][0] # e.g. <a...>#10</a>
            # Quick hack to extract number: split by '#' and take the digits
            try:
                return int(raw_link.split('#')[1].split('<')[0])
            except:
                return 0
                
        sorted_keys = sorted(grouped.keys(), key=get_sort_idx)
    except Exception:
        sorted_keys = sorted(grouped.keys())

    for key in sorted_keys:
        seq, status = key
        positions = grouped[key] # These are now HTML links
        
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
            f'<th scope="row" style="font-family: var(--font-mono); font-size: 1.1rem;">{seq}</th>'
            f'<td style="color: var(--color-text); font-weight: normal;">{status}</td>'
            f'<td>{count}</td>'
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

    rgi_total = emoji_counts.get("RGI Emoji Sequences", 0)

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
        
        # --- RENDER PATH 3: Simple Cards ---
        elif isinstance(v, (int, float)):
            count = v
            if count > 0 or (k in ["Total Graphemes", "Total Code Points", "RGI Emoji Sequences", "Whitespace (Total)"]):
                html.append(f'<div class="card"><strong>{k}</strong><div>{count}</div></div>')
        
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
        
def render_integrity_matrix(rows, text_context=None):
    """Renders the forensic integrity matrix with Nested Ledger."""
    tbody = document.getElementById("integrity-matrix-body")
    tbody.innerHTML = ""
    
    INTEGRITY_KEY = "Integrity Level (Heuristic)"
    sorted_rows = sorted(rows, key=lambda r: "000" if r["label"] == INTEGRITY_KEY else r["label"])
    
    for row in sorted_rows:
        tr = document.createElement("tr")
        
        if row["label"] == INTEGRITY_KEY:
            # --- SCORE & LEDGER ROW ---
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
    Forensic Inspector v3.0: Drift-Proof.
    Uses localized segmentation to prevent long-distance index drift.
    """
    try:
        text_input = document.getElementById("text-input")
        if text_input.classList.contains("reveal-active"):
            render_inspector_panel({"error": "Inspection Paused (Reveal Active)"})
            return

        dom_pos = text_input.selectionStart
        if dom_pos != text_input.selectionEnd: return
        
        # [CRITICAL FIX] Handle Newline normalization mismatch (Windows \r\n vs \n)
        # We pull the raw value. Browsers normalize newlines in .value to \n.
        # BUT selectionStart on Windows sometimes counts \r\n (2 chars).
        # To fix drift, we trust the Python string length logic.
        text = str(text_input.value)
        if not text:
            render_inspector_panel(None)
            return
        
        # 1. Map DOM Index to Python Index
        # We restart the counter to ensure absolute precision
        python_idx = 0
        utf16_accum = 0
        found_sync = False
        
        # Optimization: If the text is huge, this loop is slow.
        # But for Stage 1 accuracy, we must scan from 0 to ensure sync.
        for i, ch in enumerate(text):
            if utf16_accum == dom_pos:
                python_idx = i
                found_sync = True
                break
            
            # Logic: Is this a surrogate pair? (2 units) or BMP (1 unit)
            # Python len() is 1 for emoji. UTF-16 is 2.
            step = 2 if ord(ch) > 0xFFFF else 1
            
            # Windows Newline Hack: If DOM counts \n as 2, we drift.
            # We assume standard browser behavior (normalized \n = 1).
            # If drift persists, it's usually due to this calculation.
            
            utf16_accum += step
            
            if utf16_accum > dom_pos:
                # We landed inside a character (rare, but possible with surrogates)
                python_idx = i
                found_sync = True
                break
        
        if not found_sync and utf16_accum == dom_pos:
             render_inspector_panel(None) # End of string
             return

        # 2. Localized Segmentation (The Fix)
        # Instead of segmenting the whole text, we grab a window around the index
        # to ensure we find the cluster *at this specific point*.
        
        # Define a window (e.g., 50 chars before and after)
        start_search = max(0, python_idx - 50)
        end_search = min(len(text), python_idx + 50)
        local_text = text[start_search:end_search]
        
        # Offset the target index relative to the local window
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
            
        # 3. Analyze the Cluster (Standard Logic)
        base_char = target_cluster[0]
        cp_base = ord(base_char)
        
        components = []
        zalgo_score = 0
        for ch in target_cluster:
            cat = unicodedata.category(ch)
            name = unicodedata.name(ch, "Unknown")
            
            # NEW: Get the Stacking Physics
            ccc = unicodedata.combining(ch)
            
            is_mark = cat.startswith('M')
            if is_mark: zalgo_score += 1
            
            components.append({
                'hex': f"U+{ord(ch):04X}", 
                'name': name, 
                'cat': cat, 
                'ccc': ccc,  # <--- Added this field
                'is_base': not is_mark
            })
            
        # 4. Payload & Extended Forensics (The Forensic 9)
        
        # A. System Layer
        utf8_hex = " ".join(f"{b:02X}" for b in target_cluster.encode("utf-8"))
        utf16_hex = " ".join(f"{b:02X}" for b in target_cluster.encode("utf-16-be"))
        utf32_hex = f"{cp_base:08X}"
        
        # B. Legacy Layer (Fail-Safe Encoding)
        def try_enc(enc_name):
            try:
                return " ".join(f"{b:02X}" for b in target_cluster.encode(enc_name))
            except UnicodeEncodeError:
                return "N/A"

        ascii_val = try_enc("ascii")
        latin1_val = try_enc("latin-1")
        cp1252_val = try_enc("cp1252")
        
        # C. Injection Layer
        # URL: Simple byte-level percent encoding for the UTF-8 sequence
        url_enc = "".join(f"%{b:02X}" for b in target_cluster.encode("utf-8"))
        
        # HTML: Entity representation
        # Simple logic: if alphanumeric, show char. If special, show entity.
        if target_cluster.isalnum():
            html_enc = target_cluster
        else:
            # Force hex entity for clarity
            html_enc = "".join(f"&#x{ord(c):X};" for c in target_cluster)
            
        # Code: Python/JSON style escape
        code_enc = target_cluster.encode("unicode_escape").decode("utf-8")

        confusables_map = DATA_STORES.get("Confusables", {})
        skeleton = confusables_map.get(cp_base)
        confusable_msg = f"Base maps to: '{skeleton}'" if skeleton else None
        
        stack_msg = None
        if zalgo_score >= 3: stack_msg = f"Heavy Stacking ({zalgo_score} marks)"

        data = {
            "cluster_glyph": target_cluster,
            "prev_glyph": prev_cluster,
            "next_glyph": next_cluster,
            "cp_hex_base": f"U+{cp_base:04X}",
            "name_base": unicodedata.name(base_char, "No Name Found"),
            "block": _find_in_ranges(cp_base, "Blocks") or "N/A",
            "script": _find_in_ranges(cp_base, "Scripts") or "Common",
            "category": ALIASES.get(unicodedata.category(base_char), "N/A"),
            "bidi": unicodedata.bidirectional(base_char) or "N/A",
            "age": _find_in_ranges(cp_base, "Age") or "N/A",
            "line_break": _find_in_ranges(cp_base, "LineBreak") or "N/A",
            "word_break": _find_in_ranges(cp_base, "WordBreak") or "N/A",
            
            # Forensic 9 Payload
            "utf8": utf8_hex,
            "utf16": utf16_hex,
            "utf32": utf32_hex,
            "ascii": ascii_val,
            "latin1": latin1_val,
            "cp1252": cp1252_val,
            "url": url_enc,
            "html": html_enc,
            "code": code_enc,
            
            "confusable": confusable_msg,
            "is_invisible": bool(INVIS_TABLE[cp_base] & INVIS_ANY_MASK),
            "stack_msg": stack_msg,
            "components": components
        }
        
        render_inspector_panel(data)
        
    except Exception as e:
        print(f"Inspector Error: {e}")
        render_inspector_panel({"error": str(e)})
        

def render_inspector_panel(data):
    """
    Forensic Layout v6.0: Restored Design + Left-Side Risk.
    Cols: [Prev] [Target] [Next] [RISK] [Identity] [Structure] [Bytes]
    """
    panel = document.getElementById("inspector-panel-content")
    if not panel: return

    if data is None:
        panel.innerHTML = "<p class='placeholder-text'>Click a character to inspect.</p>"
        return
        
    if "error" in data:
        panel.innerHTML = f"<p class='status-error'>{data['error']}</p>"
        return

    # --- BUILD ALERTS COLUMN ---
    alerts_html_parts = []
    
    if data['is_invisible']: 
        alerts_html_parts.append(
            '<div class="legend-badge legend-badge-danger">'
            '<span class="alert-icon">👻</span>INVISIBLE'
            '</div>'
        )

    if data['stack_msg']:
        sev = "danger" if "Heavy" in data['stack_msg'] else "suspicious"
        icon = "📶" if sev == "danger" else "⚠️"
        alerts_html_parts.append(
            f'<div class="legend-badge legend-badge-{sev}">'
            f'<span class="alert-icon">{icon}</span>{data["stack_msg"].upper()}'
            f'</div>'
        )
    
    if data['confusable']:
        alerts_html_parts.append(
            '<div class="legend-badge legend-badge-high" title="Potential Homoglyph">'
            '<span class="alert-icon">👁️</span>CONFUSABLE'
            '</div>'
        )

    alerts_html = "".join(alerts_html_parts)
    # Keep column empty if no risks, but maintain layout
    if not alerts_html:
         alerts_html = '<div style="opacity:0.2; font-size:1.5rem;">🛡️</div>'

    # --- BUILD IDENTITY COLUMN ---
    identity_html = f"""
        <div class="inspector-header">{data['name_base']}</div>
        <div class="inspector-grid-compact">
            <div><span class="label">Block:</span> {data['block']}</div>
            <div><span class="label">Script:</span> {data['script']}</div>
            <div><span class="label">Cat:</span> {data['category']}</div>
            <div><span class="label">Bidi:</span> {data['bidi']}</div>
            <div><span class="label">Age:</span> {data['age']}</div>
        </div>
        <div class="inspector-grid-compact" style="margin-top:0.5rem; padding-top:0.5rem; border-top:1px dashed var(--color-border-light);">
            <div><span class="label">Line:</span> {data['line_break']}</div>
            <div><span class="label">Word:</span> {data['word_break']}</div>
        </div>
    """

   # --- TABLE ROWS (Now with CCC Physics) ---
    comp_rows = ""
    for c in data['components']:
        # Calculate Combining Class (The "Stacking Physics")
        # We need to look up the char from the hex string or pass the char directly.
        # Since 'components' in inspect_character only has metadata, we need to adjust 
        # the data gathering phase OR just re-calculate it here if we have the char.
        # Actually, let's do it cleaner: Update the Data Gathering phase first (see below).
        
        # Assuming 'ccc' is now in c:
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

    # --- VISUALS ---
    prev_vis = _escape_html(data['prev_glyph']) if data['prev_glyph'] else "&nbsp;"
    curr_vis = _escape_html(data['cluster_glyph'])
    next_vis = _escape_html(data['next_glyph']) if data['next_glyph'] else "&nbsp;"

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
            <div class="inspector-codepoint">{data['cp_hex_base']}</div>
        </div>

        <div class="col-context col-next">
            <div class="ctx-label">NEXT</div>
            <div class="ctx-glyph">{next_vis}</div>
        </div>
        
        <div class="col-signal-processor">
            {risk_header_html}
            {matrix_html}
            {footer_html}
        </div>
        
        <div class="col-identity">
            {identity_html}
        </div>

        <div class="col-structure">
            <div class="section-label">
                CLUSTER COMPONENTS
                <span style="display:block; font-weight:400; opacity:0.7; font-size:0.6rem; margin-top:2px;">
                    ({len(data['components'])} PARTICLES)
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

                <div class="byte-row"><span class="label">URL:</span>{data['url']}</div>
                <div class="byte-row"><span class="label">HTML:</span>{_escape_html(data['html'])}</div>
                <div class="byte-row"><span class="label">Code:</span>{_escape_html(data['code'])}</div>

            </div>
        </div>

    </div>
    """
    panel.innerHTML = html

    # Trigger the centering scroll
    # --- TRIGGER CENTERING ---
    # Force JS to scroll the viewport to the middle of the massive padding box
    try:
        window.TEXTTICS_CENTER_GLYPH()
    except Exception:
        pass # Fail silent if JS not ready

def compute_threat_score(inputs):
    """
    The Threat Auditor.
    Calculates Weaponization & Malice.
    Strictly excludes 'Rot' (Integrity issues).
    """
    ledger = []
    
    def add_entry(vector, points, category):
        ledger.append({"vector": vector, "points": int(points), "category": category})

    # --- 1. EXECUTION ATTACKS (Tier 1) ---
    # Trojan Source: Requires Bidi Override/Embedding (not just Isolates)
    if inputs.get("malicious_bidi"):
        add_entry("Trojan Source (Malicious Bidi)", THR_BASE_EXECUTION, "EXECUTION")
        
    # Terminal Injection: ESC key patterns
    # (Assuming forensic stats passes 'has_esc' check)
    # For now, we use the Bidi Danger check as the primary signal
    
    # Syntax Spoofing: Variation Selector on Operator/Syntax
    if inputs.get("suspicious_syntax_vs"):
        add_entry("Syntax Spoofing (VS on Operator)", THR_BASE_EXECUTION, "EXECUTION")

    # --- 2. IDENTITY SPOOFING (Tier 2) ---
    drift_cross = inputs.get("drift_cross_script", 0)
    if drift_cross > 0:
        # Capped Density Model: Base + min(count, 25)
        density_bonus = min(drift_cross, 25) * THR_MULT_SPOOFING
        total_pts = THR_BASE_SPOOFING + density_bonus
        add_entry(f"Cross-Script Homoglyphs ({drift_cross})", total_pts, "SPOOFING")

    # --- 3. OBFUSCATION (Tier 3) ---
    # Massive Clusters
    cluster_len = inputs.get("max_invis_run", 0)
    cluster_count = inputs.get("invis_cluster_count", 0)
    
    if cluster_len > 4:
        # Logic: Massive cluster is obfuscation.
        add_entry(f"Massive Invisible Cluster (len={cluster_len})", THR_BASE_OBFUSCATION, "OBFUSCATION")
    elif cluster_count > 0:
         # Smaller clusters - check if we already charged for Trojan Source
         if not inputs.get("malicious_bidi"):
             # If no Trojan Source, treat as Obfuscation/Stego attempt
             # Scale slightly by count
             pts = THR_BASE_OBFUSCATION + min(cluster_count, 10) * THR_MULT_OBFUSCATION
             add_entry(f"Invisible Clusters ({cluster_count})", pts, "OBFUSCATION")

    # Plane 14 Tags
    tags = inputs.get("tags_count", 0)
    if tags > 0:
        add_entry(f"Plane 14 Tags ({tags})", THR_BASE_OBFUSCATION, "OBFUSCATION")

    # Highly Mixed Scripts
    mix_class = inputs.get("script_mix_class", "")
    if "Highly Mixed" in mix_class:
        add_entry(mix_class, THR_BASE_OBFUSCATION, "OBFUSCATION")

    # --- 4. SUSPICIOUS (Tier 4) ---
    # Unclosed Bidi (Sloppy) - Only if NOT Malicious
    if inputs.get("has_unclosed_bidi") and not inputs.get("malicious_bidi"):
        add_entry("Unclosed Bidi Sequence", THR_BASE_SUSPICIOUS, "SUSPICIOUS")
        
    # Mixed Scripts (Base)
    if "Mixed Scripts (Base)" in mix_class:
        add_entry(mix_class, THR_BASE_SUSPICIOUS, "SUSPICIOUS")

    # --- CALCULATION ---
    total_score = sum(item["points"] for item in ledger)
    
    verdict = "CLEAN"
    severity_class = "ok"
    
    if total_score >= 40:
        verdict = "WEAPONIZED"
        severity_class = "crit"
    elif total_score >= 15:
        verdict = "HIGH RISK"
        severity_class = "crit" # High Risk is still critical red
    elif total_score >= 1:
        verdict = "SUSPICIOUS"
        severity_class = "warn"

    return {
        "score": total_score,
        "verdict": verdict,
        "severity_class": severity_class,
        "ledger": ledger,
        "noise": inputs.get("noise_list", []) # Pass noise list for display
    }

# ---
# 6. MAIN ORCHESTRATOR
# ---

@create_proxy
def update_all(event=None):
    """The main function called on every input change."""
    
    # [IMMUTABLE REVEAL FIX]
    # If the user edits the text, the "Visual Overlay" is broken/invalid.
    # We must strip the warning class and treat this as new Raw Evidence.
    t_input = document.getElementById("text-input")
    if t_input and t_input.classList.contains("reveal-active"):
        t_input.classList.remove("reveal-active")
    
    # --- 0. Debug Logging (Optional) ---
    try:
        blocks_len = len(DATA_STORES.get("Blocks", {}).get("ranges", []))
    except Exception:
        pass

    t_input = document.getElementById("text-input")
    if not t_input: return
    t = t_input.value
    
    # --- 1. Handle Empty Input (Reset UI) ---
    if not t:
        render_cards({}, "meta-totals-cards")
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
        return

    # --- 2. Run All Computations ---

    # Emoji Engine
    emoji_report = compute_emoji_analysis(t)
    emoji_counts = emoji_report.get("counts", {})
    emoji_flags = emoji_report.get("flags", {})
    emoji_list = emoji_report.get("emoji_list", [])
    
    # Module 2.A: Dual-Atom
    cp_summary, cp_major, cp_minor = compute_code_point_stats(t, emoji_counts)
    gr_summary, gr_major, gr_minor, grapheme_forensics = compute_grapheme_stats(t)
    ccc_stats = compute_combining_class_stats(t)
    
    # Module 2.B: Shape
    major_seq_stats = compute_sequence_stats(t)
    minor_seq_stats = compute_minor_sequence_stats(t)
    lb_run_stats = compute_linebreak_analysis(t)
    bidi_run_stats = compute_bidi_class_analysis(t)
    wb_run_stats = compute_wordbreak_analysis(t)
    sb_run_stats = compute_sentencebreak_analysis(t)
    gb_run_stats = compute_graphemebreak_analysis(t)
    eaw_run_stats = compute_eastasianwidth_analysis(t)
    vo_run_stats = compute_verticalorientation_analysis(t)

    # Module 2.C: Forensic Integrity (HYBRID ENGINE)
    forensic_rows = compute_forensic_stats_with_positions(t, cp_minor, emoji_flags)
    forensic_map = {row['label']: row for row in forensic_rows}

    # Module 2.D: Provenance
    provenance_stats = compute_provenance_stats(t)
    script_run_stats = compute_script_run_analysis(t)

    # Module 3: Threat-Hunting
    # [CRITICAL] Compute this first so we have the metrics!
    threat_results = compute_threat_analysis(t)
    window.latest_threat_data = threat_results
    
    # --- 3. Prepare Data for Renderers ---
    
    # 2.A Cards
    meta_cards = {
        "Total Code Points": cp_summary.get("Total Code Points", 0),
        "Total Graphemes": gr_summary.get("Total Graphemes", 0),
        "RGI Emoji Sequences": emoji_counts.get("RGI Emoji Sequences", 0),
        "Whitespace (Total)": cp_summary.get("Whitespace (Total)", 0),
        "ASCII-Compatible": cp_summary.get("ASCII-Compatible"),
        "Latin-1-Compatible": cp_summary.get("Latin-1-Compatible"),
        "BMP Coverage": cp_summary.get("BMP Coverage"),
        "Supplementary Planes": cp_summary.get("Supplementary Planes"),
    }
    meta_cards_order = [
        "Total Code Points", "Total Graphemes", "RGI Emoji Sequences", "Whitespace (Total)",
        "ASCII-Compatible", "Latin-1-Compatible", "BMP Coverage", "Supplementary Planes"
    ]
    grapheme_cards = grapheme_forensics
    
    # 2.B Matrices
    shape_matrix = major_seq_stats
    prov_matrix = provenance_stats

    # --- THREAT FLAGS & SCORE LOGIC ---
    
    # 1. Gather inputs for Threat Score
    grapheme_strings = [seg.segment for seg in window.Array.from_(GRAPHEME_SEGMENTER.segment(t))]
    nsm_stats = analyze_nsm_overload(grapheme_strings)

    # Helper to safely get counts from forensic map
    def get_count(label):
        return forensic_map.get(label, {}).get("count", 0)

    decode_grade_row = forensic_map.get("Integrity Level (Heuristic)", {})
    decode_grade = decode_grade_row.get("badge", "OK").split(' ')[0] # Extract just "CRITICAL"/"WARNING" from badge string
    
    malicious_bidi = threat_results.get('bidi_danger', False)
    script_mix_class = threat_results.get('script_mix_class', "")

    # Retrieve metrics safely from the ALREADY COMPUTED threat_results
    skel_metrics = threat_results.get("skel_metrics", {})
    
    # Gather Noise (for display)
    noise_list = []
    if nsm_stats["level"] >= 1: noise_list.append("Excessive Combining Marks (Zalgo)")
    drift_ascii = skel_metrics.get("drift_ascii", 0)
    if drift_ascii > 0: noise_list.append(f"ASCII Normalization Drift ({drift_ascii} chars)")

    # Inputs for Threat Auditor
    score_inputs = {
        "malicious_bidi": malicious_bidi,
        "has_unclosed_bidi": get_count("Flag: Unclosed Bidi Sequence") > 0,
        
        "drift_cross_script": skel_metrics.get("drift_cross_script", 0),
        "script_mix_class": script_mix_class,
        
        "max_invis_run": forensic_map.get("Max Invisible Run Length", {}).get("count", 0),
        "invis_cluster_count": forensic_map.get("Invisible Clusters (All)", {}).get("count", 0),
        "tags_count": get_count("Flag: Unicode Tags (Plane 14)"),
        
        "suspicious_syntax_vs": get_count("SUSPICIOUS: Variation Selector on Syntax") > 0,
        
        "noise_list": noise_list
    }
    
    final_score = compute_threat_score(score_inputs)
    
    
    # --- Construct Display Flags ---
    final_threat_flags = {}
    
    # 1. Score Row (Exploit Likelihood)
    # FIX: Use 'verdict' and pre-calculated 'severity_class' from the Auditor
    score_badge = f"{final_score['verdict']} (Score: {final_score['score']})"
    
    # Pass the full ledger object to the renderer
    final_threat_flags["Threat Level (Heuristic)"] = {
        'count': 0,
        'positions': [], # Legacy field
        'severity': final_score['severity_class'], # Use the class calculated by the Auditor
        'badge': score_badge,
        'ledger': final_score.get('ledger', []),
        'noise': final_score.get('noise', [])
    }
    
    # 2. Zalgo Row
    if nsm_stats["count"] > 0:
        sev = "crit" if nsm_stats["level"] == 2 else "warn"
        label = "Flag: Excessive Combining Marks (Zalgo)"
        final_threat_flags[label] = {
            'count': nsm_stats["count"],
            'positions': nsm_stats["positions"],
            'severity': sev,
            'badge': "ZALGO"
        }

    # 3. Merge existing threat flags
    final_threat_flags.update(threat_results['flags'])
    
    # 4. Merge mapped forensic flags
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

    # --- TOC Counts ---
    toc_counts = {
        'dual': sum(1 for v in meta_cards.values() if (isinstance(v, (int, float)) and v > 0) or (isinstance(v, dict) and v.get('count', 0) > 0)) + sum(1 for v in grapheme_cards.values() if v > 0) + sum(1 for k in set(cp_major.keys()) | set(gr_major.keys()) if cp_major.get(k, 0) > 0 or gr_major.get(k, 0) > 0),
        'shape': sum(1 for v in shape_matrix.values() if v > 0) + sum(1 for v in minor_seq_stats.values() if v > 0) + sum(1 for v in lb_run_stats.values() if v > 0) + sum(1 for v in bidi_run_stats.values() if v > 0) + sum(1 for v in wb_run_stats.values() if v > 0) + sum(1 for v in sb_run_stats.values() if v > 0) + sum(1 for v in gb_run_stats.values() if v > 0) + sum(1 for v in eaw_run_stats.values() if v > 0) + sum(1 for v in vo_run_stats.values() if v > 0),
        'integrity': sum(1 for row in forensic_rows if row.get('count', 0) > 0),
        'prov': sum(1 for v in prov_matrix.values() if v.get('count', 0) > 0) + sum(1 for v in script_run_stats.values() if v.get('count', 0) > 0),
        'emoji': meta_cards.get("RGI Emoji Sequences", 0),
        'threat': sum(1 for v in final_threat_flags.values() if (isinstance(v, dict) and v.get('count', 0) > 0) or (isinstance(v, int) and v > 0))
    }

    # --- 4. Call All Renderers ---
    # Note: We pass 'text_context=t' ONLY to renderers that generate clickable position links.
    
    render_cards(meta_cards, "meta-totals-cards", key_order=meta_cards_order)
    render_cards(grapheme_cards, "grapheme-integrity-cards")
    render_ccc_table(ccc_stats, "ccc-matrix-body")
    render_parallel_table(cp_major, gr_major, "major-parallel-body")
    render_parallel_table(cp_minor, gr_minor, "minor-parallel-body", ALIASES)
    
    # Shape & Run Profiles (Counts/Sequences only, no positions to click)
    render_matrix_table(shape_matrix, "shape-matrix-body")
    render_matrix_table(minor_seq_stats, "minor-shape-matrix-body", aliases=ALIASES)
    render_matrix_table(lb_run_stats, "linebreak-run-matrix-body")
    render_matrix_table(bidi_run_stats, "bidi-run-matrix-body")
    render_matrix_table(wb_run_stats, "wordbreak-run-matrix-body")
    render_matrix_table(sb_run_stats, "sentencebreak-run-matrix-body")
    render_matrix_table(gb_run_stats, "graphemebreak-run-matrix-body")
    render_matrix_table(eaw_run_stats, "eawidth-run-matrix-body")
    render_matrix_table(vo_run_stats, "vo-run-matrix-body")
    
    # Integrity Profile (Has Positions -> Needs Context)
    render_integrity_matrix(forensic_rows, text_context=t)
    
    # Provenance Profile (Has Positions -> Needs Context)
    render_matrix_table(prov_matrix, "provenance-matrix-body", has_positions=True, text_context=t)
    render_matrix_table(script_run_stats, "script-run-matrix-body", has_positions=True, text_context=t)

    # Emoji Profile (Has Positions -> Needs Context)
    render_emoji_qualification_table(emoji_list, text_context=t)
    render_emoji_summary(emoji_counts, emoji_list)

    # Threat Profile (Has Positions -> Needs Context)
    threat_results['flags'] = final_threat_flags
    render_threat_analysis(threat_results, text_context=t)
    
    render_toc_counts(toc_counts)

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
            "nfkc_casefold_text": nfkc_cf_text,
            "timestamp": window.Date.new().toISOString()
        }
        core_data_js = to_js(core_data, dict_converter=window.Object.fromEntries)
        window.TEXTTICS_CORE_DATA = core_data_js
    except Exception as e:
        print(f"Error packaging data for Stage 2: {e}")

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
        
        # [IMMUTABLE REVEAL FIX] 
        # 1. Signal the state change visually
        element.classList.add("reveal-active")
        
        # 2. Inform the user clearly
        render_status(f"Visual Reveal Active ({replaced_count} tags). Report reflects original raw data.")
        
        # 3. CRITICAL: We DO NOT call update_all(None). 
        # The data model must remain pinned to the 'Evidence' (Raw Text), 
        # while the UI shows the 'Visualization' (Revealed Text).
        
        # 4. Force the Inspector to update immediately to show the "Paused" state
        # (We simulate a selection event)
        inspect_character(None)

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
