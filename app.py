import asyncio
import json
import unicodedata
from pyodide.ffi import create_proxy
from pyodide.http import pyfetch
from pyscript import document, window
import hashlib

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
    "IdentifierType": {"ranges": [], "starts": [], "ends": []},
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
            "Blocks.txt", "DerivedAge.txt", "IdentifierType.txt", 
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
            "CompositionExclusions.txt"
        ]
        results = await asyncio.gather(*[fetch_file(f) for f in files_to_fetch])
    
        # --- MODIFIED (Feature 2 Expanded) ---
        (blocks_txt, age_txt, id_type_txt, confusables_txt, variants_txt, 
         script_ext_txt, linebreak_txt, proplist_txt, derivedcore_txt, 
         scripts_txt, emoji_variants_txt, word_break_txt, 
         sentence_break_txt, grapheme_break_txt, donotemit_txt, ccc_txt, 
         decomp_type_txt, derived_binary_txt, num_type_txt, 
         ea_width_txt, vert_orient_txt, bidi_brackets_txt,
         bidi_mirroring_txt, norm_props_txt, comp_ex_txt) = results
    
        # Parse each file
        if blocks_txt: _parse_and_store_ranges(blocks_txt, "Blocks")
        if age_txt: _parse_and_store_ranges(age_txt, "Age")
        if id_type_txt: _parse_and_store_ranges(id_type_txt, "IdentifierType")
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

def compute_code_point_stats(t: str):
    """Module 1 (Code Point): Runs the 3-Tier analysis."""

    # 1. Get derived stats (from full string)
    code_points_array = window.Array.from_(t)
    total_code_points = len(code_points_array)
    _, emoji_count = _find_matches_with_indices("RGI Emoji", t)
    _, whitespace_count = _find_matches_with_indices("Whitespace", t)

    derived_stats = {
        "Total Code Points": total_code_points,
        "RGI Emoji Sequences": emoji_count,
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
    """Module 2.D-Script: Runs Token Shape Analysis (Script Properties)."""
    counters = {}
    if not t or LOADING_STATE != "READY":
        return counters

    current_state = "NONE"
    
    # --- START: CORRECT RLE LOGIC ---
    js_array = window.Array.from_(t)
    for char in js_array:
        try:
            cp = ord(char)
            new_state = _get_char_script_id(char, cp)
        except Exception:
            new_state = "Script: Unknown" # Failsafe
        
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

def compute_wordbreak_analysis(t: str):
    """Module 2.B-WordBreak: Runs Token Shape Analysis (UAX #29)."""
    counters = {}
    if not t or LOADING_STATE != "READY":
        return counters

    current_state = "NONE"
    
    for char in t:
        cp = ord(char)
        wb_class = _find_in_ranges(cp, "WordBreak")
        new_state = wb_class if wb_class else "XX"
        
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
        new_state = sb_class if sb_class else "XX"
        
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
        new_state = gb_class if gb_class else "XX"
        
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
        new_state = eaw_class if eaw_class else "N" # 'N' (Neutral) is the default
        
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

def compute_forensic_stats_with_positions(t: str, cp_minor_stats: dict):
    """Module 2.C: Runs Forensic Analysis and finds positions."""

    forensic_stats = {}

    # 1. Manually find flags in one Python loop
    deceptive_space_indices = []
    nonchar_indices = []
    private_use_indices = []
    surrogate_indices = []
    unassigned_indices = []
    
    # Cf/Ignorable buckets
    bidi_control_indices = []
    join_control_indices = []
    true_ignorable_indices = []
    other_ignorable_indices = []
    
    # PropList buckets
    extender_indices = []
    deprecated_indices = []
    donotemit_indices = []
    dash_indices = []
    quote_indices = []
    terminal_punct_indices = []
    sentence_terminal_indices = []
    alphabetic_indices = []
    
    # Other
    decomp_stats = {}
    decomp_type_stats = {}
    bidi_mirrored_indices = []
    loe_indices = []

    bidi_bracket_open_indices = []
    bidi_bracket_close_indices = []
    bidi_mirroring_map = {}  # This will store the mappings {index: "char -> mirrored_char"}
    norm_exclusion_indices = []
    norm_nfkc_casefold_indices = []
    deceptive_ls_indices = []
    deceptive_ps_indices = []
    deceptive_nel_indices = []
    
    js_array = window.Array.from_(t)
    for i, char in enumerate(js_array):
        try:
            category = unicodedata.category(char)
            cp = ord(char)

            # --- NEW: Deceptive Newline Check (Phase 1.B) ---
            if cp == 0x2028: # Line Separator (LS)
                deceptive_ls_indices.append(f"#{i}")
            elif cp == 0x2029: # Paragraph Separator (PS)
                deceptive_ps_indices.append(f"#{i}")
            elif cp == 0x0085: # Next Line (NEL)
                deceptive_nel_indices.append(f"#{i}")
            # --- END NEW ---
            
            # --- 1. Deconstruct the old 'Cf' logic ---
            if _find_in_ranges(cp, "BidiControl"):
                bidi_control_indices.append(f"#{i}")
            elif _find_in_ranges(cp, "JoinControl"):
                join_control_indices.append(f"#{i}")
            elif category == "Cf":
                true_ignorable_indices.append(f"#{i}")

            # --- 2. Add Other Ignorables ---
            if _find_in_ranges(cp, "OtherDefaultIgnorable"):
                other_ignorable_indices.append(f"#{i}")

            # --- 3. Add Decomposition Type ---
            decomp = unicodedata.decomposition(char)
            if decomp and decomp.startswith('<'):
                try:
                    tag = decomp.split('>', 1)[0].strip('<')
                    key = f"Decomposition: {tag}"
                    if key not in decomp_stats:
                        decomp_stats[key] = {'count': 0, 'positions': []}
                    decomp_stats[key]['count'] += 1
                    decomp_stats[key]['positions'].append(f"#{i}")
                except Exception:
                    pass 

            # --- 4. Add Other Properties (Extender, Deprecated, etc.) ---
            if _find_in_ranges(cp, "Extender"):
                extender_indices.append(f"#{i}")
            if _find_in_ranges(cp, "Deprecated"):
                deprecated_indices.append(f"#{i}")
            if _find_in_ranges(cp, "DoNotEmit"):
                donotemit_indices.append(f"#{i}")
            if _find_in_ranges(cp, "Dash"):
                dash_indices.append(f"#{i}")
            if _find_in_ranges(cp, "QuotationMark"):
                quote_indices.append(f"#{i}")
            if _find_in_ranges(cp, "TerminalPunctuation"):
                terminal_punct_indices.append(f"#{i}")
            if _find_in_ranges(cp, "SentenceTerminal"):
                sentence_terminal_indices.append(f"#{i}")
            if _find_in_ranges(cp, "Alphabetic"):
                alphabetic_indices.append(f"#{i}")
            
            # --- 5. Keep the General Category checks ---
            if category == "Zs" and cp != 0x0020:
                deceptive_space_indices.append(f"#{i}")
            elif category == "Co":
                private_use_indices.append(f"#{i}")
            elif category == "Cs":
                surrogate_indices.append(f"#{i}")
            elif category == "Cn":
                unassigned_indices.append(f"#{i}")

            # Independent Code Point check
            if (cp >= 0xFDD0 and cp <= 0xFDEF) or (cp & 0xFFFF) in (0xFFFE, 0xFFFF):
                nonchar_indices.append(f"#{i}")

            # --- 6. Add new Derived Properties (NON-DESTRUCTIVE TEST) ---

            # Add Decomposition Type (from new file)
            decomp_type = _find_in_ranges(cp, "DecompositionType")
            if decomp_type and decomp_type != "Canonical":
                key = f"Decomposition (Derived): {decomp_type.title()}"
                if key not in decomp_type_stats:
                    decomp_type_stats[key] = {'count': 0, 'positions': []}
                decomp_type_stats[key]['count'] += 1
                decomp_type_stats[key]['positions'].append(f"#{i}")
            
            # Add Binary Properties
            if _find_in_ranges(cp, "BidiMirrored"):
                bidi_mirrored_indices.append(f"#{i}")
            if _find_in_ranges(cp, "LogicalOrderException"):
                loe_indices.append(f"#{i}")
            # --- END OF NEW BLOCK ---

            # --- 7. Add new GEM properties ---

            # Gem 1: Bidi-Brackets
            bracket_type = _find_in_ranges(cp, "BidiBracketType")
            if bracket_type == "o":
                bidi_bracket_open_indices.append(f"#{i}")
            elif bracket_type == "c":
                bidi_bracket_close_indices.append(f"#{i}")
    
            # Gem 1: Bidi-Mirroring (Update)
            # Check if this char is in our new mirroring map
            if cp in DATA_STORES["BidiMirroring"]:
                mirrored_cp = DATA_STORES["BidiMirroring"][cp]
                bidi_mirroring_map[f"#{i}"] = f"'{char}' → '{chr(mirrored_cp)}'"
    
            # Gem 4: Normalization Properties
            if _find_in_ranges(cp, "CompositionExclusions"):
                norm_exclusion_indices.append(f"#{i}")
            if _find_in_ranges(cp, "ChangesWhenNFKCCasefolded"):
                norm_nfkc_casefold_indices.append(f"#{i}")
        
        except Exception as e:
            print(f"Error processing char at index {i}: {e}")

    
    # Add new decomposed Cf/Ignorable stats
    forensic_stats["Bidi Control (UAX #9)"] = {'count': len(bidi_control_indices), 'positions': bidi_control_indices}
    forensic_stats["Join Control (Structural)"] = {'count': len(join_control_indices), 'positions': join_control_indices}
    forensic_stats["True Ignorable (Format/Cf)"] = {'count': len(true_ignorable_indices), 'positions': true_ignorable_indices}
    forensic_stats["Other Default Ignorable"] = {'count': len(other_ignorable_indices), 'positions': other_ignorable_indices}
    
    # Add other PropList stats
    forensic_stats["Prop: Extender"] = {'count': len(extender_indices), 'positions': extender_indices}
    forensic_stats["Prop: Deprecated"] = {'count': len(deprecated_indices), 'positions': deprecated_indices}
    forensic_stats["Prop: Discouraged (DoNotEmit)"] = {'count': len(donotemit_indices), 'positions': donotemit_indices}
    forensic_stats["Prop: Dash"] = {'count': len(dash_indices), 'positions': dash_indices}
    forensic_stats["Prop: Quotation Mark"] = {'count': len(quote_indices), 'positions': quote_indices}
    forensic_stats["Prop: Terminal Punctuation"] = {'count': len(terminal_punct_indices), 'positions': terminal_punct_indices}
    forensic_stats["Prop: Sentence Terminal"] = {'count': len(sentence_terminal_indices), 'positions': sentence_terminal_indices}
    forensic_stats["Prop: Alphabetic"] = {'count': len(alphabetic_indices), 'positions': alphabetic_indices}

    # Add Decomposition stats
    forensic_stats.update(decomp_stats)

    # Add new Decomposition stats (ADD THIS BLOCK)
    forensic_stats.update(decomp_type_stats)
    
    # Add new Binary Property stats (ADD THIS BLOCK)
    forensic_stats["Prop: Bidi Mirrored"] = {'count': len(bidi_mirrored_indices), 'positions': bidi_mirrored_indices}
    forensic_stats["Prop: Logical Order Exception"] = {'count': len(loe_indices), 'positions': loe_indices}

    forensic_stats["Flag: Bidi Paired Bracket (Open)"] = {'count': len(bidi_bracket_open_indices), 'positions': bidi_bracket_open_indices}
    forensic_stats["Flag: Bidi Paired Bracket (Close)"] = {'count': len(bidi_bracket_close_indices), 'positions': bidi_bracket_close_indices}

    # Special formatter for the Bidi Mirroring map
    mirror_count = len(bidi_mirroring_map)
    if mirror_count > 0:
        # We just list the mappings directly
        mirror_positions = [f"#{idx} ({mapping})" for idx, mapping in bidi_mirroring_map.items()]
        forensic_stats["Flag: Bidi Mirrored Mapping"] = {'count': mirror_count, 'positions': mirror_positions}
    
    forensic_stats["Flag: Full Composition Exclusion"] = {'count': len(norm_exclusion_indices), 'positions': norm_exclusion_indices}

    # --- NEW: Add Deceptive Newline flags ---
    forensic_stats["Flag: Deceptive Newline (LS)"] = {'count': len(deceptive_ls_indices), 'positions': deceptive_ls_indices}
    forensic_stats["Flag: Deceptive Newline (PS)"] = {'count': len(deceptive_ps_indices), 'positions': deceptive_ps_indices}
    forensic_stats["Flag: Deceptive Newline (NEL)"] = {'count': len(deceptive_nel_indices), 'positions': deceptive_nel_indices}
    # --- END NEW ---
    
    forensic_stats["Flag: Changes on NFKC Casefold"] = {'count': len(norm_nfkc_casefold_indices), 'positions': norm_nfkc_casefold_indices}
    
    # Add back the other flags we kept
    forensic_stats["Deceptive Spaces"] = {
        'count': len(deceptive_space_indices),
        'positions': deceptive_space_indices
    }
    forensic_stats["Noncharacter"] = {
        'count': len(nonchar_indices),
        'positions': nonchar_indices
    }
    forensic_stats["Private Use"] = {
        'count': len(private_use_indices),
        'positions': private_use_indices
    }
    forensic_stats["Surrogates (Broken)"] = {
        'count': len(surrogate_indices),
        'positions': surrogate_indices
    }
    forensic_stats["Unassigned (Void)"] = {
        'count': len(unassigned_indices),
        'positions': unassigned_indices
    }

    
    # 2. Add Variant Stats (from Module 8)
    variant_stats = compute_variant_stats_with_positions(t)
    forensic_stats.update(variant_stats)

    # 3. Manually find IdentifierType flags
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
    ivs_indices = []
    
    # We must iterate using JS-style string indices
    js_array = window.Array.from_(t)
    for i, char in enumerate(js_array):
        cp = ord(char)
        if cp in base_set:
            base_indices.append(f"#{i}")
        # Check both the old set (for Mongolian) AND the new property (for Emoji)
        is_selector = (cp in selector_set) or (_find_in_ranges(cp, "VariationSelector") is not None)
        if is_selector:
            selector_indices.append(f"#{i}")
        # Check for Ideographic Variation Selectors (Steganography vector)
        if 0xE0100 <= cp <= 0xE01EF:
            ivs_indices.append(f"#{i}")
            
    return {
        "Variant Base Chars": {'count': len(base_indices), 'positions': base_indices},
        "Variation Selectors": {'count': len(selector_indices), 'positions': selector_indices},
        "Steganography (IVS)": {'count': len(ivs_indices), 'positions': ivs_indices}
    }

def compute_provenance_stats(t: str):
    """Module 2.D: Runs UAX #44 and Deep Scan analysis."""

    # 1. UAX #44 Stats are now data-driven and moved to compute_forensic_stats
    # This section is now only for Script, Block, Age, and Numeric analysis.

    # These dicts will hold the counts
    script_stats = {} 
    script_ext_stats = {}
    
    # 2. Deep Scan Stats (if data is loaded)
    if LOADING_STATE != "READY":
        return {} # Return empty if data isn't ready

    numeric_total_value = 0
    number_script_zeros = set()
    deep_stats = {} # for Block, Age, Type, etc.

    # We loop char-by-char for all data-file properties
    for char in t:
        cp = ord(char)

        # --- THIS IS THE NEW DATA-DRIVEN SCRIPT LOGIC ---
        script_ext_val = _find_in_ranges(cp, "ScriptExtensions")
        if script_ext_val:
            # Case 1: Char is in ScriptExtensions.txt (e.g., the Middle Dot)
            scripts = script_ext_val.split()
            for script in scripts:
                key = f"Script-Ext: {script}"
                script_ext_stats[key] = script_ext_stats.get(key, 0) + 1
        else:
            # Case 2: Char is NOT in ScriptExtensions.txt (e.g., 't' or '(')
            # We fall back to its primary 'Script' property from Scripts.txt
            script_val = _find_in_ranges(cp, "Scripts")
            if script_val:
                key = f"Script: {script_val}"
                script_stats[key] = script_stats.get(key, 0) + 1
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

        # --- ADD THIS BLOCK ---
        num_type = _find_in_ranges(cp, "NumericType")
        if num_type:
            key = f"Numeric Type: {num_type}"
            deep_stats[key] = deep_stats.get(key, 0) + 1
        # --- END ADD ---

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

    # Combine all stats
    final_stats = {}
    final_stats.update(script_stats)
    final_stats.update(script_ext_stats)
    final_stats.update(deep_stats)
    return final_stats

def _generate_uts39_skeleton(t: str):
    """Generates the UTS #39 'skeleton' for a string."""
    if LOADING_STATE != "READY":
        return ""
        
    confusables_map = DATA_STORES.get("Confusables", {})
    if not confusables_map:
        return "" # Data not loaded
        
    # Per UTS #39, the skeleton is created from the NFKC-Casefolded form
    # We will use NFD first as a base for mapping, then re-compose.
    # A more robust implementation would use NFKC-Casefold, but let's
    # build the NFD-based mapper first as it's the core of confusables.txt
    
    try:
        # 1. Decompose the string (e.g., 'é' -> 'e' + '´')
        nfd_string = unicodedata.normalize('NFD', t)
        
        mapped_chars = []
        for char in nfd_string:
            cp = ord(char)
            # 2. Map each character to its confusable prototype
            # If not in the map, it maps to itself.
            skeleton_char = confusables_map.get(cp, char)
            mapped_chars.append(skeleton_char)
        
        mapped_string = "".join(mapped_chars)
        
        # 3. Re-normalize to NFD to stabilize the mapped string
        final_skeleton = unicodedata.normalize('NFD', mapped_string)
        
        return final_skeleton
    except Exception as e:
        print(f"Error generating skeleton: {e}")
        return ""

def compute_threat_analysis(t: str):
    """Module 3: Runs Threat-Hunting Analysis (UTS #39, etc.)."""
    threat_flags = {}
    threat_hashes = {}
    html_report = "" # We'll populate this later

    if not t:
        return {'flags': threat_flags, 'hashes': threat_hashes, 'html_report': html_report}
    
    # --- Helper for hashing ---
    def _get_hash(s: str):
        return hashlib.sha256(s.encode('utf-8')).hexdigest()[:16] # 16 chars (64-bit) is enough

    try:
        # --- 1. Generate Normalized States (Phase 2.B) ---
        # Note: We use the raw string 't' for Forensic state
        nf_string = unicodedata.normalize('NFKC', t)
        nf_casefold_string = nf_string.casefold()

        # --- 2. Implement Mixed-Script Detection (Phase 3.B) ---
        scripts_in_use = set()
        if LOADING_STATE == "READY":
            for char in nf_string: # Analyze the normalized string
                cp = ord(char)
                # Use the same logic from Group 2.D
                script_ext_val = _find_in_ranges(cp, "ScriptExtensions")
                if script_ext_val:
                    scripts_in_use.update(script_ext_val.split())
                else:
                    script_val = _find_in_ranges(cp, "Scripts")
                    if script_val:
                        scripts_in_use.add(script_val)
            
            # Remove "benign" scripts to reduce noise
            scripts_in_use.discard("Common")
            scripts_in_use.discard("Inherited")
            
            if len(scripts_in_use) > 1:
                key = f"High-Risk: Mixed Scripts ({', '.join(sorted(scripts_in_use))})"
                # render_cards expects a simple integer value, not a dict
                threat_flags[key] = 1

        # --- 3. Implement UTS #39 Skeleton (Phase 3.C) ---
        # Note: The plan says use nf_string, but UTS #39 recommends
        # NFKC-Casefold. Let's stick to the plan for now.
        skeleton_string = _generate_uts39_skeleton(nf_string)

        # --- 4. Generate Hashes (Phase 3.D) ---
        threat_hashes["State 1: Forensic (Raw)"] = _get_hash(t)
        threat_hashes["State 2: NFKC"] = _get_hash(nf_string)
        threat_hashes["State 3: NFKC-Casefold"] = _get_hash(nf_casefold_string)
        threat_hashes["State 4: UTS #39 Skeleton"] = _get_hash(skeleton_string)

    except Exception as e:
        print(f"Error in compute_threat_analysis: {e}")

    return {'flags': threat_flags, 'hashes': threat_hashes, 'html_report': html_report}

def render_threat_analysis(threat_results):
    """Renders the Group 3 Threat-Hunting results."""
    
    # 1. Render Flags
    flags = threat_results.get('flags', {})
    render_cards(flags, "threat-report-cards") # We can re-use render_cards!
    
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
    
    # 4. Render Banner (TODO)
    # (We'll add logic here later to un-hide and update #threat-banner if flags are present)

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

def render_toc_counts(counts):
    """Updates the counts in the sticky Table of Contents."""
    document.getElementById("toc-dual-count").innerText = f"({counts.get('dual', 0)})"
    document.getElementById("toc-shape-count").innerText = f"({counts.get('shape', 0)})"
    document.getElementById("toc-integrity-count").innerText = f"({counts.get('integrity', 0)})"
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
        render_threat_analysis({}) 
        
        render_toc_counts({})
        return

    # --- 1. Run All Computations ---
    
    # Module 2.A: Dual-Atom Fingerprint
    cp_summary, cp_major, cp_minor = compute_code_point_stats(t)
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
    forensic_stats = compute_forensic_stats_with_positions(t, cp_minor)
    
    # Module 2.D: Provenance & Context
    provenance_stats = compute_provenance_stats(t)
    script_run_stats = compute_script_run_analysis(t)

    # Module 3: Threat-Hunting
    threat_results = compute_threat_analysis(t)
    
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
    shape_matrix = major_seq_stats
    
    # 2.C
    forensic_matrix = forensic_stats
    
    # 2.D
    prov_matrix = provenance_stats
    
    # TOC Counts (count non-zero entries)
    toc_counts = {
        'dual': sum(1 for v in meta_cards.values() if v > 0) + sum(1 for v in grapheme_cards.values() if v > 0) + sum(1 for k in set(cp_major.keys()) | set(gr_major.keys()) if cp_major.get(k, 0) > 0 or gr_major.get(k, 0) > 0),
        'shape': sum(1 for v in shape_matrix.values() if v > 0) + sum(1 for v in minor_seq_stats.values() if v > 0) + sum(1 for v in lb_run_stats.values() if v > 0) + sum(1 for v in bidi_run_stats.values() if v > 0) + sum(1 for v in wb_run_stats.values() if v > 0) + sum(1 for v in sb_run_stats.values() if v > 0) + sum(1 for v in gb_run_stats.values() if v > 0) + sum(1 for v in eaw_run_stats.values() if v > 0) + sum(1 for v in vo_run_stats.values() if v > 0),
        'integrity': sum(1 for v in forensic_matrix.values() if v.get('count', 0) > 0),
        'prov': sum(1 for v in prov_matrix.values() if v > 0) + sum(1 for v in script_run_stats.values() if v > 0),
        'threat': sum(1 for v in threat_results.get('flags', {}).values() if v > 0)
    }
    
    # --- 3. Call All Renderers ---
    
    # Render 2.A
    render_cards(meta_cards, "meta-totals-cards")
    render_cards(grapheme_cards, "grapheme-integrity-cards")
    render_matrix_table(ccc_stats, "ccc-matrix-body")
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
    render_matrix_table(prov_matrix, "provenance-matrix-body")
    render_matrix_table(script_run_stats, "script-run-matrix-body")

    # Render 3
    render_threat_analysis(threat_results)
    
    # Render TOC
    render_toc_counts(toc_counts)

# ---
# 6. INITIALIZATION
# ---

async def main():
    """Main entry point: Loads data, then hooks the input."""
    # Start loading the external data and wait for it to finish.
    # By the time this 'await' finishes, the document has
    # almost certainly finished parsing.
    await load_unicode_data()
    
    # Now that the DOM is stable and data is loaded,
    # hook the main function to the text-input.
    document.getElementById("text-input").addEventListener("input", update_all)
    print("Text...tics is ready.") # A good sign to see in the console

# Start the main asynchronous task
asyncio.ensure_future(main())
