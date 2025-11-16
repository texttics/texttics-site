# stage2.py
import asyncio
from pyscript import document, window
from pyodide.ffi import create_proxy
from pyodide.http import pyfetch
import bisect 

# ---
# 0. STAGE 2 DATA STORES & LOADERS
# ---

# We load the UAX files Stage 2 needs for its own logic
STAGE2_DATA_STORES = {
    "WordBreak": {"ranges": [], "starts": [], "ends": []},
    "SentenceBreak": {"ranges": [], "starts": [], "ends": []},
    "PropList": {"ranges": [], "starts": [], "ends": []},
    "DerivedCore": {"ranges": [], "starts": [], "ends": []},
}
DATA_LOADED = False

# We need to map the property names from the files to our store keys
PROP_MAP = {
    # From PropList.txt
    "White_Space": "PropList",
    "Bidi_Control": "PropList",
    "Join_Control": "PropList",
    # From DerivedCoreProperties.txt
    "Default_Ignorable_Code_Point": "DerivedCore",
}

def _parse_and_store_ranges(txt: str, store_key: str, property_map: dict = None):
    """
    Generic parser for Unicode range data files.
    If property_map is provided, it sorts properties into the correct store.
    """
    # This logic is for multi-property files like PropList.txt
    if property_map:
        temp_ranges = {key: [] for key in STAGE2_DATA_STORES.keys()}
        
        for raw in txt.splitlines():
            line = raw.split('#', 1)[0].strip()
            if not line: continue
            parts = line.split(';', 1)
            if len(parts) < 2: continue
            code_range, prop_name = parts[0].strip(), parts[1].strip()
            
            if prop_name in property_map:
                target_store_key = property_map[prop_name]
                try:
                    if '..' in code_range:
                        a, b = code_range.split('..', 1)
                        temp_ranges[target_store_key].append((int(a, 16), int(b, 16), prop_name))
                    else:
                        cp = int(code_range, 16)
                        temp_ranges[target_store_key].append((cp, cp, prop_name))
                except Exception:
                    pass # Ignore malformed lines
        
        # Now populate the real data stores from the temp lists
        for key, ranges_list in temp_ranges.items():
            if not ranges_list: continue
            store = STAGE2_DATA_STORES[key]
            ranges_list.sort()
            store["ranges"].extend([(s, e, v) for s, e, v in ranges_list])
            
    # This logic is for single-property files like WordBreakProperty.txt
    else:
        store = STAGE2_DATA_STORES[store_key]
        ranges_list = []
        for raw in txt.splitlines():
            line = raw.split('#', 1)[0].strip()
            if not line: continue
            parts = line.split(';', 1)
            if len(parts) < 2: continue
            code_range, value = parts[0].strip(), parts[1].strip()
            try:
                if '..' in code_range:
                    a, b = code_range.split('..', 1)
                    ranges_list.append((int(a, 16), int(b, 16), value))
                else:
                    ranges_list.append((int(code_range, 16), int(code_range, 16), value))
            except Exception:
                pass
        
        ranges_list.sort()
        store["ranges"] = [(s, e, v) for s, e, v in ranges_list]

    # After all parsing, create the fast lookup lists
    for key in STAGE2_DATA_STORES:
        store = STAGE2_DATA_STORES[key]
        if store["ranges"] and not store["starts"]: # Only build if new
            store["ranges"].sort() # Sort all ranges from all files
            store["starts"] = [s for s, e, v in store["ranges"]]
            store["ends"] = [e for s, e, v in store["ranges"]]
            print(f"Stage 2: Finalized {len(store['starts'])} ranges for {key}.")


async def load_stage2_data():
    """Fetches and parses the UAX data needed for Stage 2."""
    global DATA_LOADED
    try:
        wb_res_task = pyfetch("./WordBreakProperty.txt")
        pl_res_task = pyfetch("./PropList.txt")
        dc_res_task = pyfetch("./DerivedCoreProperties.txt")
        
        wb_res, pl_res, dc_res = await asyncio.gather(wb_res_task, pl_res_task, dc_res_task)
        
        if wb_res.ok and pl_res.ok and dc_res.ok:
            _parse_and_store_ranges(await wb_res.string(), "WordBreak")
            _parse_and_store_ranges(await pl_res.string(), None, property_map=PROP_MAP)
            _parse_and_store_ranges(await dc_res.string(), None, property_map=PROP_MAP)
            DATA_LOADED = True
        else:
            print(f"Stage 2: Failed to load data (WB:{wb_res.status}, PL:{pl_res.status}, DC:{dc_res.status})")
    except Exception as e:
        print(f"Stage 2: Error loading data: {e}")

def _find_in_ranges(cp: int, store_key: str):
    """Stage 2's local copy of the range finder."""
    store = STAGE2_DATA_STORES[store_key]
    starts_list = store["starts"]
    if not starts_list: return None
    i = bisect.bisect_right(starts_list, cp) - 1
    if i >= 0 and cp <= store["ends"][i]:
        # Return the *value* (e.g., "ALetter", "White_Space")
        return store["ranges"][i][2]
    return None

def _find_in_ranges_multi(cp: int, store_key: str):
    """Finds ALL matching properties for a code point in a store."""
    store = STAGE2_DATA_STORES[store_key]
    starts_list = store["starts"]
    if not starts_list: return []
    
    props = []
    # Find potential matches
    i = bisect.bisect_right(starts_list, cp) - 1
    # Check all properties that start at or before cp
    for j in range(i, -1, -1):
        if starts_list[j] > cp:
            continue
        if cp <= store["ends"][j]:
            props.append(store["ranges"][j][2]) # Add the value
        # Optimization: if the start is too far back, stop
        if cp - starts_list[j] > 2000: # Heuristic
             break
             
    # This is not perfect for overlapping ranges, but good enough for this
    # A more robust way is to check all `i` where starts_list[i] <= cp
    
    # Let's use a simpler, correct-but-slower method
    props = []
    for s, e, v in store["ranges"]:
        if s <= cp <= e:
            props.append(v)
    return props

# ---
# 1. METRIC HELPER FUNCTIONS (GRAPHEME-BASED)
# ---

def get_grapheme_base_properties(grapheme: str) -> dict:
    """Finds all UAX properties of the *first code point* in a grapheme."""
    props = {
        "wb": "Other", 
        "sb": "Other",
        # We will check these boolean properties directly
        "is_WhiteSpace": False, 
        "is_Bidi_Control": False, 
        "is_Join_Control": False,
        "is_Default_Ignorable": False
    }
    if not grapheme:
        return props
    
    first_char = window.Array.from_(grapheme)[0]
    cp = ord(first_char)
    
    # --- THIS IS THE FIX ---
    # Use the simple, reliable _find_in_ranges for all properties
    props["wb"] = _find_in_ranges(cp, "WordBreak") or "Other"
    props["sb"] = _find_in_ranges(cp, "SentenceBreak") or "Other" # <-- This caused the KeyError
    
    # Check PropList properties
    # We find *all* matching properties in this file
    pl_props = []
    # We must check if the ranges list exists before iterating
    if "ranges" in STAGE2_DATA_STORES["PropList"]:
        for s, e, v in STAGE2_DATA_STORES["PropList"]["ranges"]:
            if s <= cp <= e:
                pl_props.append(v)
            
    if "White_Space" in pl_props: props["is_WhiteSpace"] = True
    if "Bidi_Control" in pl_props: props["is_Bidi_Control"] = True
    if "Join_Control" in pl_props: props["is_Join_Control"] = True
    
    # Check DerivedCore properties
    dc_props = []
    if "ranges" in STAGE2_DATA_STORES["DerivedCore"]:
        for s, e, v in STAGE2_DATA_STORES["DerivedCore"]["ranges"]:
            if s <= cp <= e:
                dc_props.append(v)
            
    if "Default_Ignorable_Code_Point" in dc_props:
        props["is_Default_Ignorable"] = True
    # --- END OF FIX ---
    
    return props

# ---
# 2. CORE LOGIC: THE SEGMENTED ANALYSIS PIPELINE
# ---

def compute_segmented_profile(core_data, N=10):
    """
    The main Stage 2 pipeline.
    Takes core data from Stage 1 and runs all macro-analysis.
    """
    print("Stage 2: Running macro-analysis...")
    
    # 1. Get data from Stage 1
    grapheme_list = core_data.get("grapheme_list", [])
    grapheme_lengths = core_data.get("grapheme_lengths_codepoints", [])
    forensic_flags = core_data.get("forensic_flags", {})
    
    total_graphemes = len(grapheme_list)
    if total_graphemes == 0:
        return {"error": "No graphemes to analyze."}

    # 2. Segmentation (by Grapheme index)
    chunk_size = total_graphemes // N
    if chunk_size == 0: chunk_size = 1
        
    segmented_reports = []
    
    # --- Define our "structural types" based on UAX properties ---
    WORD_PROPS = {"ALetter", "Numeric", "Katakana", "Hebrew_Letter"}
    LINEBREAK_PROPS = {"LF", "CR"}
    
    for i in range(N):
        # 3. Get the slice (chunk) for this segment
        start_grapheme_index = i * chunk_size
        end_grapheme_index = (i + 1) * chunk_size if i < N - 1 else total_graphemes
        
        if start_grapheme_index >= total_graphemes: continue
            
        segment_graphemes = grapheme_list[start_grapheme_index:end_grapheme_index]
        
        # 4. Feature Extraction (Grapheme-based RLE)
        
        # --- Section 2: Content Run Histogram ---
        content_run_lengths = []
        current_content_run = 0
        
        # --- Section 3: Separator Run Profile ---
        space_run_lengths = []
        current_space_run = 0
        line_break_count = 0
        
        # --- Section 4: Invisible Atom Integrity ---
        bidi_atom_count = 0
        join_atom_count = 0
        other_invisible_atom_count = 0
        
        for grapheme in segment_graphemes:
            # --- THIS IS THE UPDATED LOGIC ---
            props = get_grapheme_base_properties(grapheme)
            wb_prop = props["wb"]

            # --- Classify this grapheme ---
            
            # Is it an Invisible Atom?
            if props["is_Bidi_Control"]:
                bidi_atom_count += 1
                if current_content_run > 0: content_run_lengths.append(current_content_run)
                if current_space_run > 0: space_run_lengths.append(current_space_run)
                current_content_run, current_space_run = 0, 0
                continue 
            
            if props["is_Join_Control"]:
                join_atom_count += 1
                if current_content_run > 0: content_run_lengths.append(current_content_run)
                if current_space_run > 0: space_run_lengths.append(current_space_run)
                current_content_run, current_space_run = 0, 0
                continue

            if props["is_Default_Ignorable"]:
                other_invisible_atom_count += 1
                if current_content_run > 0: content_run_lengths.append(current_content_run)
                if current_space_run > 0: space_run_lengths.append(current_space_run)
                current_content_run, current_space_run = 0, 0
                continue
            
            # Is it a Separator?
            if props["is_WhiteSpace"] or wb_prop in LINEBREAK_PROPS:
                if current_content_run > 0:
                    content_run_lengths.append(current_content_run)
                    current_content_run = 0
                
                if wb_prop in LINEBREAK_PROPS:
                    line_break_count += 1
                    if current_space_run > 0:
                        space_run_lengths.append(current_space_run)
                        current_space_run = 0
                elif props["is_WhiteSpace"]: # Must be a \p{Zs}
                    current_space_run += 1
            
            # Is it Content?
            else:
                if current_space_run > 0:
                    space_run_lengths.append(current_space_run)
                    current_space_run = 0
                
                current_content_run += 1
            # --- END OF UPDATED LOGIC ---

        # End of loop, flush any remaining runs
        if current_content_run > 0: content_run_lengths.append(current_content_run)
        if current_space_run > 0: space_run_lengths.append(current_space_run)

        # 5. Bin the Content Runs
        bins = {"1": 0, "2": 0, "3-5": 0, "6-10": 0, "11+": 0}
        for length in content_run_lengths:
            if length == 1: bins["1"] += 1
            elif length == 2: bins["2"] += 1
            elif 3 <= length <= 5: bins["3-5"] += 1
            elif 6 <= length <= 10: bins["6-10"] += 1
            else: bins["11+"] += 1
        
        total_content_runs = len(content_run_lengths)
        avg_content_length = (sum(content_run_lengths) / total_content_runs) if total_content_runs > 0 else 0
        
        # 6. Analyze Separator Runs
        total_space_runs = len(space_run_lengths)
        avg_space_length = (sum(space_run_lengths) / total_space_runs) if total_space_runs > 0 else 0
        
        # 7. Aggregate Stage 1 Threats
        threat_count = 0
        grapheme_lengths_in_this_segment = grapheme_lengths[start_grapheme_index:end_grapheme_index]
        start_cp_index = sum(grapheme_lengths[:start_grapheme_index])
        end_cp_index = start_cp_index + sum(grapheme_lengths_in_this_segment)
        
        # forensic_flags is now a dict of dicts, e.g. {"Bidi Control (UAX #9)": {"count": 1, "positions": ["#89"]}}
        if forensic_flags: # Check if it's not None or empty
            for flag, data in forensic_flags.items():
                if data and data.get('count', 0) > 0:
                    for pos_str in data.get('positions', []):
                        try:
                            # Handle positions like "#12" or "#12 (mapping)"
                            pos = int(pos_str.lstrip('#').split(' ')[0]) 
                            if start_cp_index <= pos < end_cp_index:
                                threat_count += 1
                        except Exception:
                            pass # Ignore malformed position strings

        # 8. Store metrics
        metrics = {
            "grapheme_count": len(segment_graphemes),
            "bin_1": bins["1"],
            "bin_2": bins["2"],
            "bin_3_5": bins["3-5"],
            "bin_6_10": bins["6-10"],
            "bin_11_plus": bins["11+"],
            "total_content_runs": total_content_runs,
            "avg_content_length": round(avg_content_length, 2),
            "space_runs": total_space_runs,
            "line_breaks": line_break_count,
            "avg_space_length": round(avg_space_length, 2),
            "bidi_atoms": bidi_atom_count,
            "join_atoms": join_atom_count,
            "other_invisibles": other_invisible_atom_count,
            "threat_flags": threat_count
        }
        
        report = {
            "segment_id": f"{i+1} / {N}",
            "indices": f"{start_grapheme_index}–{end_grapheme_index-1}",
            "metrics": metrics
        }
        segmented_reports.append(report)

    print(f"Stage 2: Processed {len(segmented_reports)} segments.")
    return segmented_reports

# ---
# 3. RENDERING FUNCTIONS
# ---

def render_macro_table(segmented_reports):
    """
    Renders the main "Heatmap Table" for Stage 2.
    """
    table_el = document.getElementById("macro-table-body") # Target <tbody>
    if not table_el:
        return

    html = []
    
    if not segmented_reports or "error" in segmented_reports:
        error_msg = segmented_reports.get("error", "No data.")
        html.append(f"<tr><td colspan='17'>{error_msg}</td></tr>") # Updated colspan
    else:
        for report in segmented_reports:
            metrics = report['metrics']
            html.append('<tr>')
            # Section 1: Identification
            html.append(f"<td>{report['segment_id']}</td>")
            html.append(f"<td>{report['indices']}</td>")
            html.append(f"<td>{metrics.get('grapheme_count', 0)}</td>")
            
            # Section 2: Content Run Histogram
            html.append(f"<td>{metrics.get('bin_1', 0)}</td>")
            html.append(f"<td>{metrics.get('bin_2', 0)}</td>")
            html.append(f"<td>{metrics.get('bin_3_5', 0)}</td>")
            html.append(f"<td>{metrics.get('bin_6_10', 0)}</td>")
            html.append(f"<td>{metrics.get('bin_11_plus', 0)}</td>")
            html.append(f"<td>{metrics.get('total_content_runs', 0)}</td>")
            html.append(f"<td>{metrics.get('avg_content_length', 0)}</td>")
            
            # Section 3: Separator Run Profile
            html.append(f"<td>{metrics.get('space_runs', 0)}</td>")
            html.append(f"<td>{metrics.get('line_breaks', 0)}</td>")
            html.append(f"<td>{metrics.get('avg_space_length', 0)}</td>")

            # Section 4: Invisible Atom Integrity
            html.append(f"<td>{metrics.get('bidi_atoms', 0)}</td>")
            html.append(f"<td>{metrics.get('join_atoms', 0)}</td>")
            html.append(f"<td>{metrics.get('other_invisibles', 0)}</td>")
            
            # Section 5: Threat Location
            html.append(f"<td>{metrics.get('threat_flags', 0)}</td>")
            
            html.append('</tr>')

    table_el.innerHTML = "".join(html)

def render_sparklines(segmented_reports):
    sparkline_el = document.getElementById("sparkline-output")
    if sparkline_el:
        sparkline_el.innerHTML = "<h3>Macro-Profile (Sparklines)</h3><p>(Charts will be rendered here)</p>"

# ---
# 4. MAIN BOOTSTRAP FUNCTION
# ---

# ---
# 4. MAIN BOOTSTRAP FUNCTION
# ---

async def main():
    global DATA_LOADED
    status_el = document.getElementById("loading-status")
    
    status_el.innerText = "Loading Stage 2 UAX data (WordBreak, PropList, DerivedCore)..."
    # --- FIX: We must also load SentenceBreak ---
    status_el.innerText = "Loading Stage 2 UAX data (WordBreak, SentenceBreak, PropList, DerivedCore)..."
    await load_stage2_data()
    if not DATA_LOADED:
        status_el.innerText = "Error: Could not load UAX data. Cannot proceed."
        status_el.style.color = "red"
        return

    try:
        core_data_proxy = window.opener.TEXTTICS_CORE_DATA
        
        if not core_data_proxy:
            status_el.innerText = "Error: No data from Stage 1. Please run an analysis on the main app page and click 'Analyze Macrostructure' again."
            status_el.style.color = "red"
            return

        core_data = core_data_proxy.to_py()
        
        status_el.innerText = f"Successfully loaded data from Stage 1 (Timestamp: {core_data.get('timestamp')}). Running macro-analysis..."
        
        segmented_report = compute_segmented_profile(core_data, N=10)
        
        render_sparklines(segmented_report)
        render_macro_table(segmented_report)
        
        status_el.innerText = "Macrostructure Profile (v1.0)"

    except Exception as e:
        status_el.innerText = f"A critical error occurred: {e}. Is the main app tab still open?"
        status_el.style.color = "red"
        print(f"Stage 2 Error: {e}")

# Start the Stage 2 app
print("Stage 2 starting...")
asyncio.ensure_future(main())
