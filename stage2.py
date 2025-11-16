# stage2.py
import asyncio
from pyscript import document, window
from pyodide.ffi import create_proxy
from pyodide.http import pyfetch
import bisect # <-- IMPORTED FOR _find_in_ranges

# ---
# 0. STAGE 2 DATA STORES & LOADERS
# ---

# We load the UAX files Stage 2 needs for its own logic
STAGE2_DATA = {
    "WordBreak": {"ranges": [], "starts": [], "ends": []},
    "SentenceBreak": {"ranges": [], "starts": [], "ends": []},
}
DATA_LOADED = False

def _parse_and_store_ranges(txt: str, store_key: str):
    """Generic parser for Unicode range data files."""
    store = STAGE2_DATA[store_key]
    store["ranges"].clear()
    store["starts"].clear()
    store["ends"].clear()
    
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
                cp = int(code_range, 16)
                ranges_list.append((cp, cp, value))
        except Exception:
            pass # Ignore malformed lines
    
    ranges_list.sort()
    
    for s, e, v in ranges_list:
        store["ranges"].append((s, e, v))
        store["starts"].append(s)
        store["ends"].append(e)
    print(f"Stage 2: Loaded {len(ranges_list)} ranges for {store_key}.")

async def load_stage2_data():
    """Fetches and parses the UAX data needed for Stage 2."""
    global DATA_LOADED
    try:
        # Fetch both files in parallel
        wb_res_task = pyfetch("./WordBreakProperty.txt")
        sb_res_task = pyfetch("./SentenceBreakProperty.txt")
        
        wb_res = await wb_res_task
        sb_res = await sb_res_task
        
        if wb_res.ok and sb_res.ok:
            wb_txt = await wb_res.string()
            sb_txt = await sb_res.string()
            
            _parse_and_store_ranges(wb_txt, "WordBreak")
            _parse_and_store_ranges(sb_txt, "SentenceBreak")
            DATA_LOADED = True
        else:
            print(f"Stage 2: Failed to load data (WB: {wb_res.status}, SB: {sb_res.status})")
            DATA_LOADED = False
    except Exception as e:
        print(f"Stage 2: Error loading data: {e}")
        DATA_LOADED = False

def _find_in_ranges(cp: int, store_key: str):
    """Stage 2's local copy of the range finder."""
    store = STAGE2_DATA[store_key]
    starts_list = store["starts"]
    
    if not starts_list: return None
    
    # *** THIS WAS THE MISSING LOGIC ***
    i = bisect.bisect_right(starts_list, cp) - 1
    if i >= 0 and cp <= store["ends"][i]:
        return store["ranges"][i][2] # Return the value
    # *** END MISSING LOGIC ***
    return None

# ---
# 1. METRIC HELPER FUNCTIONS
# ---

def compute_word_count(word_break_properties: list) -> int:
    """
    Counts deterministic "word" runs based on UAX #29 Word Break properties.
    A "word" is a continuous run of ALetter, Numeric, Katakana, or Hebrew_Letter.
    """
    word_count = 0
    in_word = False
    
    # Define what properties constitute a "word"
    WORD_PROPS = {"ALetter", "Numeric", "Katakana", "Hebrew_Letter"}
    
    for prop in word_break_properties:
        is_word_char = prop in WORD_PROPS
        
        if is_word_char and not in_word:
            # This is the start of a new word
            word_count += 1
            in_word = True
        elif not is_word_char:
            # This is a break (like a space or punctuation), so reset
            in_word = False
            
    return word_count

def compute_line_break_count(word_break_properties: list) -> int:
    """Counts the number of explicit Line Feeds (LF)."""
    # UAX #29 (Word Break) defines LF as a property.
    # This is a simple, deterministic "line" counter.
    line_break_count = 0
    for prop in word_break_properties:
        if prop == "LF":
            line_break_count += 1
            
    # N line breaks separate N+1 lines of text
    # If the text isn't empty, it has at least one line.
    if len(word_break_properties) > 0:
        return line_break_count + 1
    else:
        return 0

def compute_inter_dot_count(wb_props: list, sb_props: list) -> int:
    """
    Counts "meaningful" dots (terminators) that follow a word,
    per your specific requirement.
    """
    dot_count = 0
    has_word_since_last_dot = False
    
    WORD_PROPS = {"ALetter", "Numeric", "Katakana", "Hebrew_Letter"}
    TERMINATOR_PROPS = {"STerm", "ATerm"} # (e.g., . ! ?)
    
    # We iterate through both lists in parallel
    for i in range(len(wb_props)):
        wb_prop = wb_props[i]
        sb_prop = sb_props[i]
        
        # 1. Check if we are in a "word"
        if wb_prop in WORD_PROPS:
            has_word_since_last_dot = True
        
        # 2. Check if we hit a "dot"
        if sb_prop in TERMINATOR_PROPS:
            # 3. Check if this "dot" is meaningful (i.e., it followed a word)
            if has_word_since_last_dot:
                dot_count += 1
                has_word_since_last_dot = False # Reset the flag
            else:
                # This is a "dot" like in "..." or ". ."
                # We do NOT count it, and we do NOT reset the flag.
                pass
                
    return dot_count

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
    raw_text = core_data.get("raw_text", "")
    grapheme_list = core_data.get("grapheme_list", [])
    grapheme_lengths = core_data.get("grapheme_lengths_codepoints", [])
    
    total_graphemes = len(grapheme_list)
    if total_graphemes == 0 or total_graphemes != len(grapheme_lengths):
        return {"error": "No graphemes or mismatched data."}

    # 2. Build our own property lists from the raw text
    # This avoids all data passing bugs.
    wb_props = []
    sb_props = []
    for char in raw_text: # Iterate by code point
        cp = ord(char)
        
        wb_prop = _find_in_ranges(cp, "WordBreak")
        wb_props.append(wb_prop if wb_prop else "Other")
        
        sb_prop = _find_in_ranges(cp, "SentenceBreak")
        sb_props.append(sb_prop if sb_prop else "Other")

    # 3. Segmentation (by Grapheme index)
    chunk_size = total_graphemes // N
    if chunk_size == 0:
        chunk_size = 1
        
    segmented_reports = []
    
    for i in range(N):
        # 4. Get the slice (chunk) for this segment
        start_grapheme_index = i * chunk_size
        end_grapheme_index = (i + 1) * chunk_size if i < N - 1 else total_graphemes
        
        if start_grapheme_index >= total_graphemes:
            continue
            
        # 5. Map Grapheme indices to Code Point indices
        start_codepoint_index = sum(grapheme_lengths[:start_grapheme_index])
        
        graphemes_in_this_segment = grapheme_lengths[start_grapheme_index:end_grapheme_index]
        end_codepoint_index = start_codepoint_index + sum(graphemes_in_this_segment)

        # 6. Feature Extraction (Run metrics on the *sliced property lists*)
        metrics = {}
        metrics["grapheme_count"] = len(graphemes_in_this_segment)
        
        # Slice the UAX property lists
        segment_wb_props = wb_props[start_codepoint_index:end_codepoint_index]
        segment_sb_props = sb_props[start_codepoint_index:end_codepoint_index]

        # Call the UAX-based counters
        metrics["word_count"] = compute_word_count(segment_wb_props)
        metrics["line_break_count"] = compute_line_break_count(segment_wb_props)
        metrics["inter_dot_count"] = compute_inter_dot_count(segment_wb_props, segment_sb_props)
        
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
    table_el = document.getElementById("macro-table-output")
    if not table_el:
        return

    # --- NEW: Update table headers ---
    html = ['<table class="matrix"><thead>']
    html.append('<tr><th scope="col">Segment</th>'
                '<th scope="col">Indices (Grapheme)</th>'
                '<th scope="col">Grapheme Count</th>'
                '<th scope="col">Word Count</th>'
                '<th scope="col">Line Count</th>'
                '<th scope="col">Dot-Terminators</th></tr>')
    html.append('</thead><tbody>')
    # --- END NEW ---
    
    if not segmented_reports or "error" in segmented_reports:
        html.append("<tr><td colspan='6'>No data.</td></tr>") # Updated colspan
    else:
        for report in segmented_reports:
            metrics = report['metrics']
            html.append('<tr>')
            html.append(f"<td>{report['segment_id']}</td>")
            # --- NEW: Add new metric cells ---
            html.append(f"<td>{report['indices']}</td>")
            html.append(f"<td>{metrics.get('grapheme_count', 0)}</td>")
            html.append(f"<td>{metrics.get('word_count', 0)}</td>")
            html.append(f"<td>{metrics.get('line_break_count', 0)}</td>")
            html.append(f"<td>{metrics.get('inter_dot_count', 0)}</td>")
            # --- END NEW ---
            html.append('</tr>')

    html.append('</tbody></table>')
    table_el.innerHTML = "".join(html)

def render_sparklines(segmented_reports):
    sparkline_el = document.getElementById("sparkline-output")
    if sparkline_el:
        sparkline_el.innerHTML = "<h3>Macro-Profile (Sparklines)</h3><p>(Charts will be rendered here)</p>"

# ---
# 4. MAIN BOOTSTRAP FUNCTION
# ---

async def main():
    global DATA_LOADED
    status_el = document.getElementById("loading-status")
    
    # --- NEW: We must load data for Stage 2 first ---
    status_el.innerText = "Loading Stage 2 UAX data (WordBreak, SentenceBreak)..."
    await load_stage2_data()
    if not DATA_LOADED:
        status_el.innerText = "Error: Could not load UAX data. Cannot proceed."
        status_el.style.color = "red"
        return
    # --- END NEW ---

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
