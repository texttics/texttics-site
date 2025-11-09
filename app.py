import asyncio
import json
import unicodedata
from pyodide.ffi import create_proxy
from pyodide.http import pyfetch
from pyscript import document, window

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
    "RGI Emoji": window.RegExp.new(r"\p{Emoji_Presentation}", "gv"), # Swapped to \p{Emoji_Presentation} for broad support
    "Whitespace": window.RegExp.new(r"\p{White_Space}", "gu"),
    "Marks": window.RegExp.new(r"\p{M}", "gu"),
    
    # Forensic Properties (for Module 2.C)
    "Deprecated": window.RegExp.new(r"\p{Deprecated}", "gu"),
    "Noncharacter": window.RegExp.new(r"\p{Noncharacter_Code_Point}", "gu"),
    "Ignorables (Invisible)": window.RegExp.new(r"\p{Default_Ignorable_Code_Point}", "gu"),
    "Deceptive Spaces": window.RegExp.new(r"[\p{White_Space}&&[^ \n\r\t]]", "gv"),
    
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

# Pre-compiled testers for single characters
TEST_MINOR = {key: window.RegExp.new(f"^{val}$", "u") for key, val in MINOR_CATEGORIES_29.items()}
TEST_MINOR["Cn"] = window.RegExp.new(r"^\p{Cn}$", "u") # Add Cn for the tester

# Pre-compiled testers for single characters
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

# Grapheme Segmenter (UAX #29)
GRAPHEME_SEGMENTER = window.Intl.Segmenter.new("en", {"granularity": "grapheme"})

# ---
# 1.A. PRE-COMPILE ALL MINOR CATEGORY REGEXES
# ---
# This is the fix for the KeyError: 'Lu'. We must populate
# REGEX_MATCHER with the 29 minor categories so compute_code_point_stats
# can find them.
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
    "IdentifierType": {"ranges": [], "starts": [], "ends": []},
    "ScriptExtensions": {"ranges": [], "starts": [], "ends": []},
    "Confusables": {},
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
    base_set = DATA_STORES["VariantBase"]
    selector_set = DATA_STORES["VariantSelectors"]
    base_set.clear()
    selector_set.clear()
    
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

async def load_unicode_data():
    """Fetches, parses, and then triggers a UI update."""
    global LOADING_STATE
    
    async def fetch_file(filename):
        try:
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
        # Fetch all files in parallel
        files_to_fetch = [
            "Blocks.txt", "DerivedAge.txt", "IdentifierType.txt", 
            "confusables.txt", "StandardizedVariants.txt", "ScriptExtensions.txt"
        ]
        results = await asyncio.gather(*[fetch_file(f) for f in files_to_fetch])
        
        blocks_txt, age_txt, id_type_txt, confusables_txt, variants_txt, script_ext_txt = results
        
        # Parse each file
        if blocks_txt: _parse_and_store_ranges(blocks_txt, "Blocks")
        if age_txt: _parse_and_store_ranges(age_txt, "Age")
        if id_type_txt: _parse_and_store_ranges(id_type_txt, "IdentifierType")
        if confusables_txt: _parse_confusables(confusables_txt)
        if variants_txt: _parse_standardized_variants(variants_txt)
        if script_ext_txt: _parse_script_extensions(script_ext_txt) # Use the new custom parser
        
        LOADING_STATE = "READY"
        print("Unicode data loaded successfully.")
        render_status("Ready. Paste or type text to analyze.")
        update_all() # Re-render with ready state
        
    except Exception as e:
        LOADING_STATE = "FAILED"
        print(f"CRITICAL: Unicode data loading failed. Error: {e}")
        render_status("Error: Failed to load Unicode data. Please refresh.", is_error=True)

def _parse_script_extensions(txt: str):
    """Custom parser for ScriptExtensions.txt (which uses ';')."""
    store_key = "ScriptExtensions"
    store = DATA_STORES[store_key]
    store["ranges"].clear()
    store["starts"].clear()
    store["ends"].clear()

    ranges_list = []
    for raw in txt.splitlines():
        line = raw.split('#', 1)[0].strip()
        if not line:
            continue

        # Data is separated by ';', but with variable whitespace
        parts = line.split(';', 1)
        if len(parts) < 2:
            continue

        code_range = parts[0].strip()
        value = parts[1].strip() # This is the fix

        if not value:
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
    
# ---
# 3. COMPUTATION FUNCTIONS
# ---

def _find_matches_with_indices(regex_key: str, text: str):
    """Uses matchAll to find all matches and their indices."""
    regex = REGEX_MATCHER.get(regex_key)
    if not regex:
        print(f"Error: Regex key '{regex_key}' not found in REGEX_MATCHER.")
        return [], 0 # Return unpackable empty values

    try:
        matches_iter = window.String.prototype.matchAll.call(text, regex)
        matches = window.Array.from_(matches_iter)
        indices = [m.index for m in matches]
        return indices, len(indices)
    except Exception as e:
        print(f"Error in _find_matches_with_indices for {regex_key}: {e}")
        return [], 0 # Return unpackable empty values

def compute_code_point_stats(t: str):
    """Module 1 (Code Point): Runs the 3-Tier analysis."""

    # 1. Get derived stats (from full string)
    code_points_array = window.Array.from_(t)
    total_code_points = len(code_points_array)

    # Use the _find_matches_with_indices function
    _, emoji_count = _find_matches_with_indices("RGI Emoji", t)
    _, whitespace_count = _find_matches_with_indices("Whitespace", t)

    derived_stats = {
        "Total Code Points": total_code_points,
        "RGI Emoji Sequences": emoji_count,
        "Whitespace (Total)": whitespace_count
    }

    # 2. Get 29 minor categories (Honest Mode)
    minor_stats = {}
    sum_of_29_cats = 0
    for key in MINOR_CATEGORIES_29.keys():
        _, count = _find_matches_with_indices(key, t)
        minor_stats[key] = count
        sum_of_29_cats += count

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
        "L (Letter)": major_stats["L (Letter)"],
        "N (Number)": major_stats["N (Number)"],
        "P (Punctuation)": major_stats["P (Punctuation)"],
        "S (Symbol)": major_stats["S (Symbol)"]
    }

    return summary_stats, major_stats, minor_stats

def get_char_type(char, is_minor):
    """
    Classifies a single char as a Major or Minor category.
    (This logic is from the original, working index.html)
    """
    testers = TEST_MINOR if is_minor else TEST_MAJOR
    for key, regex in testers.items():
        if regex.test(char):
            return key
    return "NONE"
    
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

    
    # 2. Get 29 minor categories (Honest Mode)
    minor_stats = {}
    sum_of_29_cats = 0
    for key, regex_str in MINOR_CATEGORIES_29.items():
        # Use the 'gu' flag for simple counting
        regex = window.RegExp.new(regex_str, "gu")
        matches = window.String.prototype.match.call(t, regex)
        count = len(matches) if matches else 0
        minor_stats[key] = count
        sum_of_29_cats += count
        
    # 3. Calculate 'Cn' as the remainder
    minor_stats["Cn"] = total_code_points - sum_of_29_cats
    
    # 4. Aggregate Major Categories
    major_stats = {
        "L (Letter)": minor_stats["Lu"] + minor_stats["Ll"] + minor_stats["Lt"] + minor_stats["Lm"] + minor_stats["Lo"],
        "M (Mark)": minor_stats["Mn"] + minor_stats["Mc"] + minor_stats["Me"],
        "N (Number)": minor_stats["Nd"] + minor_stats["Nl"] + minor_stats["No"],
        "P (Punctuation)": minor_stats["Pc"] + minor_stats["Pd"] + minor_stats["Ps"] + minor_stats["Pe"] + minor_stats["Pi"] + minor_stats["Pf"] + minor_stats["Po"],
        "S (Symbol)": minor_stats["Sm"] + minor_stats["Sc"] + minor_stats["Sk"] + minor_stats["So"],
        "Z (Separator)": minor_stats["Zs"] + minor_stats["Zl"] + minor_stats["Zp"],
        "C (Other)": minor_stats["Cc"] + minor_stats["Cf"] + minor_stats["Cs"] + minor_stats["Co"] + minor_stats["Cn"]
    }
    
    # 5. Build Summary (for Meta-Analysis cards)
    summary_stats = {
        **derived_stats,
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
        
        mark_count = _find_matches_with_indices("Marks", grapheme_str)
        
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

def compute_sequence_stats(t: str, is_minor_mode: bool):
    """
    Module 2.B: Runs the Token Shape Analysis (Major or Minor).
    (This logic is from the original, working index.html)
    """
    testers = TEST_MINOR if is_minor_mode else TEST_MAJOR
    counters = {key: 0 for key in testers}

    if not t:
        return {} # Return an empty dict

    current_state = "NONE"
    for char in t:
        new_state = get_char_type(char, is_minor_mode) # Use the helper

        if new_state != current_state:
            if current_state in counters: # This is the safe, working check
                counters[current_state] += 1
            current_state = new_state

    if current_state in counters: # Handle the last run
        counters[current_state] += 1

    # Return only non-zero counts
    final_counts = {}
    for key, count in counters.items():
        if count > 0:
            final_counts[key] = count

    return final_counts

def compute_forensic_stats_with_positions(t: str, cp_minor_stats: dict):
    """Module 2.C: Runs Forensic Analysis and finds positions."""

    forensic_stats = {}

    # 1. Get pre-calculated counts from Module 1
    forensic_stats["Unassigned (Void)"] = {'count': cp_minor_stats.get("Cn", 0), 'positions': []}
    forensic_stats["Surrogates (Broken)"] = {'count': cp_minor_stats.get("Cs", 0), 'positions': []}
    forensic_stats["Private Use"] = {'count': cp_minor_stats.get("Co", 0), 'positions': []}
    # Note: We can't easily get positions for calculated Cn.

    # 2. Run regex-based checks (REMOVING Ignorables)
    for key in ["Deprecated", "Noncharacter", "Deceptive Spaces"]:
        indices, count = _find_matches_with_indices(key, t)
        forensic_stats[key] = {
            'count': count,
            'positions': [f"#{i}" for i in indices]
        }

    # --- THIS IS THE FIX ---
    # 3. Manually find Ignorables using Python, not a buggy regex
    ignorable_indices = []
    js_array = window.Array.from_(t)
    for i, char in enumerate(js_array):
        # Find Default Ignorable Code Points (like ZWSP) and Format (Cf) chars (like Bidi)
        # This is a more robust check.
        category = unicodedata.category(char)
        if category == "Cf":
            # U+200B (ZWSP), U+2060 (WJ), U+FEFF (BOM), Bidi, etc.
            ignorable_indices.append(f"#{i}")

    forensic_stats["Ignorables (Format/Cf)"] = {
        'count': len(ignorable_indices),
        'positions': ignorable_indices
    }
    # --- END OF FIX ---

    # 4. Add Variant Stats (from Module 8)
    variant_stats = compute_variant_stats_with_positions(t)
    forensic_stats.update(variant_stats)
    # 5. Manually find IdentifierType flags (this was a bug)
    if LOADING_STATE == "READY":
        id_type_stats = {}
        js_array = window.Array.from_(t)
        for i, char in enumerate(js_array):
            cp = ord(char)
            id_type = _find_in_ranges(cp, "IdentifierType")

            # We only care about problematic types
            if id_type and id_type not in ("Recommended", "Inclusion"):
                key = f"Type: {id_type}"
                if key not in id_type_stats:
                    id_type_stats[key] = {'count': 0, 'positions': []}

                id_type_stats[key]['count'] += 1
                id_type_stats[key]['positions'].append(f"#{i}")

        forensic_stats.update(id_type_stats)
    
    return forensic_stats

def compute_variant_stats_with_positions(t: str):
    """Part of Module 2.C: Counts variant base chars and selectors."""
    if LOADING_STATE != "READY":
        return {}

    base_set = DATA_STORES["VariantBase"]
    selector_set = DATA_STORES["VariantSelectors"]

    base_indices = []
    selector_indices = []
    ivs_indices = [] # <-- ADDED THIS

    # We must iterate using JS-style string indices
    js_array = window.Array.from_(t)
    for i, char in enumerate(js_array):
        cp = ord(char)
        if cp in base_set:
            base_indices.append(f"#{i}")
        if cp in selector_set:
            selector_indices.append(f"#{i}")

        # --- ADDED THIS BLOCK ---
        # Check for Ideographic Variation Selectors (Steganography vector)
        if 0xE0100 <= cp <= 0xE01EF:
            ivs_indices.append(f"#{i}")
        # --- END OF ADDED BLOCK ---

    return {
        "Variant Base Chars": {'count': len(base_indices), 'positions': base_indices},
        "Variation Selectors": {'count': len(selector_indices), 'positions': selector_indices},
        "Steganography (IVS)": {'count': len(ivs_indices), 'positions': ivs_indices} # <-- ADDED THIS
    }
    
def compute_provenance_stats(t: str):
    """Module 2.D: Runs UAX #44 and Deep Scan analysis."""

    # 1. Fast UAX #44 Stats (non-Script properties)
    provenance_stats = {}
    for key in ["Dash", "Alphabetic"]:
        _, count = _find_matches_with_indices(key, t)
        if count > 0:
            provenance_stats[key] = count

    # --- THIS IS THE FIX ---
    # 2. We will now find Scripts char-by-char to avoid double counting

    # Pre-compile single-char script testers for the "fallback"
    script_testers = {
        "Script: Cyrillic": window.RegExp.new(r"^\p{Script=Cyrillic}$", "u"),
        "Script: Greek": window.RegExp.new(r"^\p{Script=Greek}$", "u"),
        "Script: Han": window.RegExp.new(r"^\p{Script=Han}$", "u"),
        "Script: Arabic": window.RegExp.new(r"^\p{Script=Arabic}$", "u"),
        "Script: Hebrew": window.RegExp.new(r"^\p{Script=Hebrew}$", "u"),
        "Script: Latin": window.RegExp.new(r"^\p{Script=Latin}$", "u"),
        "Script: Common": window.RegExp.new(r"^\p{Script=Common}$", "u"),
        "Script: Inherited": window.RegExp.new(r"^\p{Script=Inherited}$", "u"),
    }

    # These dicts will hold the counts
    script_stats = {} 
    script_ext_stats = {}
    # --- END OF SETUP ---

    # 3. Deep Scan Stats (if data is loaded)
    if LOADING_STATE != "READY":
        # If data isn't ready, just return the fast stats
        return provenance_stats

    numeric_total_value = 0
    number_script_zeros = set()

    deep_stats = {} # for Block, Age, Type, etc.

    # We loop char-by-char for all data-file properties
    for char in t:
        cp = ord(char)

        # --- THIS IS THE NEW LOGIC ---
        script_ext_val = _find_in_ranges(cp, "ScriptExtensions")
        if script_ext_val:
            # Case 1: Char is in ScriptExtensions.txt (e.g., the Middle Dot)
            scripts = script_ext_val.split()
            for script in scripts:
                key = f"Script-Ext: {script}"
                script_ext_stats[key] = script_ext_stats.get(key, 0) + 1
        else:
            # Case 2: Char is NOT in ScriptExtensions.txt (e.g., 't' or '(')
            # We fall back to its primary 'Script' property.
            for key, regex in script_testers.items():
                if regex.test(char):
                    script_stats[key] = script_stats.get(key, 0) + 1
                    break # Found its primary script
        # --- END OF NEW LOGIC ---

        # Block, Age, Type
        block_name = _find_in_ranges(cp, "Blocks")
        if block_name:
            key = f"Block: {block_name}"
            deep_stats[key] = deep_stats.get(key, 0) + 1

        age = _find_in_ranges(cp, "Age")
        if age:
            key = f"Age: {age}"
            deep_stats[key] = deep_stats.get(key, 0) + 1

        # Numeric Properties
        try:
            value = unicodedata.numeric(char)
            numeric_total_value += value
            gc = unicodedata.category(char)
            if gc == "Nd":
                zero_code_point = ord(char) - int(value)
                number_script_zeros.add(zero_code_point)
        except (ValueError, TypeError):
            pass

    if numeric_total_value > 0:
        deep_stats["Total Numeric Value"] = round(numeric_total_value, 4)
    if len(number_script_zeros) > 1:
        deep_stats["Mixed-Number Systems"] = len(number_script_zeros)

    # Combine fast and deep stats
    # --- THIS IS THE FINAL FIX ---
    provenance_stats.update(script_stats)
    provenance_stats.update(script_ext_stats)
    provenance_stats.update(deep_stats)
    return provenance_stats

    numeric_total_value = 0
    number_script_zeros = set()

    deep_stats = {} # for Block, Age, Type, etc.

    for char in t:
        cp = ord(char)

        # --- THIS IS THE FIX (ScriptExtensions + Fallback) ---
        script_ext_val = _find_in_ranges(cp, "ScriptExtensions")
        if script_ext_val:
            # Case 1: Char is in ScriptExtensions.txt (e.g., the Middle Dot)
            scripts = script_ext_val.split()
            for script in scripts:
                key = f"Script-Ext: {script}"
                deep_stats[key] = deep_stats.get(key, 0) + 1
        else:
            # Case 2: Char is NOT in ScriptExtensions.txt (e.g., 't' or '(')
            # We must fall back to its primary 'Script' property.
            try:
                # Use Python's built-in 'script' function
                script = unicodedata.script(char) 
                key = f"Script: {script}" # Note: "Script:", not "Script-Ext:"
                deep_stats[key] = deep_stats.get(key, 0) + 1
            except ValueError:
                pass # Should not happen for valid chars
        # --- END OF FIX ---

        # Block, Age, Type
        block_name = _find_in_ranges(cp, "Blocks")
        if block_name:
            key = f"Block: {block_name}"
            deep_stats[key] = deep_stats.get(key, 0) + 1

        age = _find_in_ranges(cp, "Age")
        if age:
            key = f"Age: {age}"
            deep_stats[key] = deep_stats.get(key, 0) + 1

        id_type = _find_in_ranges(cp, "IdentifierType")
        if id_type and id_type not in ("Recommended", "Inclusion"):
             # This belongs in the Forensic module, not Provenance
             pass

        # Numeric Properties
        try:
            value = unicodedata.numeric(char)
            numeric_total_value += value
            gc = unicodedata.category(char)
            if gc == "Nd":
                zero_code_point = ord(char) - int(value)
                number_script_zeros.add(zero_code_point)
        except (ValueError, TypeError):
            pass

    if numeric_total_value > 0:
        deep_stats["Total Numeric Value"] = round(numeric_total_value, 4)
    if len(number_script_zeros) > 1:
        deep_stats["Mixed-Number Systems"] = len(number_script_zeros)

    # Combine fast and deep stats
    provenance_stats.update(deep_stats)
    return provenance_stats

# ---
# 4. DOM RENDERER FUNCTIONS
# ---

def render_status(message, is_error=False):
    """Updates the status line."""
    status_line = document.getElementById("status-line")
    if status_line:
        status_line.innerText = message
        status_line.style.color = "#dc2626" if is_error else "var(--color-text-muted)"

def render_cards(stats_dict, element_id):
    """Generates and injects HTML for standard stat cards."""
    html = []
    for k, v in stats_dict.items():
        if v > 0 or (isinstance(v, (int, float)) and v == 0 and k in ["Total Graphemes", "Total Code Points"]):
             html.append(f'<div class="card"><strong>{k}</strong><div>{v}</div></div>')
    
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

def render_matrix_table(stats_dict, element_id, has_positions=False):
    """Renders a generic "Matrix of Facts" table."""
    html = []

    # Check if this is the shape matrix *and* it's in minor mode
    is_shape_minor_mode = (element_id == "shape-matrix-body" and 
                         document.getElementById("shape-mode-toggle").checked)

    for key, data in stats_dict.items():
        if not data:
            continue

        # Use alias if this is the minor shape matrix, otherwise use the raw key
        label = ALIASES.get(key, key) if is_shape_minor_mode else key

        if has_positions:
            # Data is a dict: {'count': 1, 'positions': ['#42']}
            count = data.get('count', 0)
            if count == 0:
                continue
            positions = ", ".join(data.get('positions', []))
            html.append(
                f'<tr><th scope="row">{label}</th><td>{count}</td><td>{positions}</td></tr>'
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

def render_toc_counts(counts):
    """Updates the counts in the sticky Table of Contents."""
    document.getElementById("toc-dual-count").innerText = f"({counts.get('dual', 0)})"
    document.getElementById("toc-shape-count").innerText = f"({counts.get('shape', 0)})"
    document.getElementById("toc-forensic-count").innerText = f"({counts.get('forensic', 0)})"
    document.getElementById("toc-prov-count").innerText = f"({counts.get('prov', 0)})"
    document.getElementById("toc-threat-count").innerText = f"({counts.get('threat', 0)})"

# ---
# 5. MAIN ORCHESTRATOR
# ---

@create_proxy
def update_all(event=None):
    """The main function called on every input change."""
    
    t = document.getElementById("text-input").value
    
    if not t:
        # Render empty state
        render_cards({}, "meta-totals-cards")
        render_cards({}, "grapheme-integrity-cards")
        render_parallel_table({}, {}, "major-parallel-body")
        render_parallel_table({}, {}, "minor-parallel-body", ALIASES)
        render_matrix_table({}, "shape-matrix-body")
        render_matrix_table({}, "forensic-matrix-body", has_positions=True)
        render_matrix_table({}, "provenance-matrix-body")
        render_toc_counts({})
        return

    # --- 1. Run All Computations ---
    
    # Module 2.A: Dual-Atom Fingerprint
    cp_summary, cp_major, cp_minor = compute_code_point_stats(t)
    gr_summary, gr_major, gr_minor, grapheme_forensics = compute_grapheme_stats(t)
    
    # Module 2.B: Structural Shape
    is_minor_shape_mode = document.getElementById("shape-mode-toggle").checked
    seq_stats = compute_sequence_stats(t, is_minor_shape_mode)
    
    # Module 2.C: Forensic Integrity
    forensic_stats = compute_forensic_stats_with_positions(t, cp_minor)
    
    # Module 2.D: Provenance & Context
    provenance_stats = compute_provenance_stats(t)
    
    # --- 2. Prepare Data for Renderers ---
    
    # 2.A
    meta_cards = {
        "Total Code Points": cp_summary.get("Total Code Points", 0),
        "Total Graphemes": gr_summary.get("Total Graphemes", 0),
        "RGI Emoji Sequences": cp_summary.get("RGI Emoji Sequences", 0),
        "Whitespace (Total)": cp_summary.get("Whitespace (Total)", 0),
    }
    grapheme_cards = grapheme_forensics
    
    # 2.B
    shape_matrix = seq_stats
    
    # 2.C
    forensic_matrix = forensic_stats
    
    # 2.D
    prov_matrix = provenance_stats
    
    # TOC Counts (count non-zero entries)
    toc_counts = {
        'dual': sum(1 for v in meta_cards.values() if v > 0) + sum(1 for v in grapheme_cards.values() if v > 0) + sum(1 for k in set(cp_major.keys()) | set(gr_major.keys()) if cp_major.get(k, 0) > 0 or gr_major.get(k, 0) > 0),
        'shape': sum(1 for v in shape_matrix.values() if v > 0),
        'forensic': sum(1 for v in forensic_matrix.values() if v.get('count', 0) > 0),
        'prov': sum(1 for v in prov_matrix.values() if v > 0),
        'threat': 0 # Placeholder
    }
    
    # --- 3. Call All Renderers ---
    
    # Render 2.A
    render_cards(meta_cards, "meta-totals-cards")
    render_cards(grapheme_cards, "grapheme-integrity-cards")
    render_parallel_table(cp_major, gr_major, "major-parallel-body")
    render_parallel_table(cp_minor, gr_minor, "minor-parallel-body", ALIASES)
    
    # Render 2.B
    render_matrix_table(shape_matrix, "shape-matrix-body")
    
    # Render 2.C
    render_matrix_table(forensic_matrix, "forensic-matrix-body", has_positions=True)
    
    # Render 2.D
    render_matrix_table(prov_matrix, "provenance-matrix-body")
    
    # Render TOC
    render_toc_counts(toc_counts)

# ---
# 6. INITIALIZATION
# ---

# Hook the main function to the text-input
document.getElementById("text-input").addEventListener("input", update_all)

# Hook the new shape toggle
document.getElementById("shape-mode-toggle").addEventListener("input", update_all)

# Start loading the external data
asyncio.ensure_future(load_unicode_data())
