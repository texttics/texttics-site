# stage2.py
import asyncio
from pyscript import document, window
from pyodide.ffi import create_proxy



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
    # This matches the properties you'd see in your RLE table
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

def compute_sentence_count(sentence_break_properties: list) -> int:
    """
    Counts deterministic "sentence terminators" based on UAX #29.
    This is a "Terminator Count" metric, not a full linguistic count.
    """
    sentence_terminator_count = 0
    
    # STerm = Sentence Terminal (e.g., '!')
    # ATerm = Ambiguous Terminal (e.g., '.')
    TERMINATOR_PROPS = {"STerm", "ATerm"}
    
    for prop in sentence_break_properties:
        if prop in TERMINATOR_PROPS:
            sentence_terminator_count += 1
            
    # If no terminators are found, but the text is not empty,
    # it still constitutes one "sentence segment".
    if sentence_terminator_count == 0 and len(sentence_break_properties) > 0:
        return 1
        
    return sentence_terminator_count

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
    wb_props = core_data.get("word_break_properties", [])
    sb_props = core_data.get("sentence_break_properties", [])
    
    total_graphemes = len(grapheme_list)
    if total_graphemes == 0 or total_graphemes != len(grapheme_lengths):
        return {"error": "No graphemes or mismatched data."}

    # 2. Segmentation (by Grapheme index)
    chunk_size = total_graphemes // N
    if chunk_size == 0:
        chunk_size = 1 # Avoid division by zero on tiny strings
        
    segmented_reports = []
    
    # This tracks our position in the *code point* property lists
    current_codepoint_index = 0
    
    for i in range(N):
        # 3. Get the slice (chunk) for this segment
        start_grapheme_index = i * chunk_size
        end_grapheme_index = (i + 1) * chunk_size if i < N - 1 else total_graphemes
        
        if start_grapheme_index >= total_graphemes:
            continue
            
        # 4. ***NEW*** Map Grapheme indices to Code Point indices
        
        # Calculate the start CP index
        # This sums the lengths of all graphemes *before* this chunk
        start_codepoint_index = sum(grapheme_lengths[:start_grapheme_index])
        
        # Get the list of graphemes in this chunk
        segment_graphemes = grapheme_list[start_grapheme_index:end_grapheme_index]
        
        # Calculate the end CP index
        # This is just the start_cp_index + the sum of lengths of graphemes *in* this chunk
        graphemes_in_this_segment = grapheme_lengths[start_grapheme_index:end_grapheme_index]
        end_codepoint_index = start_codepoint_index + sum(graphemes_in_this_segment)

        # 5. Feature Extraction (Run metrics on the *sliced property lists*)
        metrics = {}
        metrics["grapheme_count"] = len(segment_graphemes)
        
        # Slice the UAX property lists using our new CP indices
        segment_wb_props = wb_props[start_codepoint_index:end_codepoint_index]
        segment_sb_props = sb_props[start_codepoint_index:end_codepoint_index]

        # --- NEW: Call the UAX-based counters ---
        metrics["word_count"] = compute_word_count(segment_wb_props)
        metrics["sentence_count"] = compute_sentence_count(segment_sb_props)
        # --- END NEW ---
        
        report = {
            "segment_id": f"{i+1} / {N}",
            "start_index": start_grapheme_index,
            "end_index": end_grapheme_index,
            "metrics": metrics
        }
        segmented_reports.append(report)

    # 6. Anomaly Detection (Z-Score)
    # (We will add the z-score calculation here later)
    
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

    html = ['<table class="matrix"><thead>']
    html.append('<tr><th scope="col">Segment</th>'
                '<th scope="col">Grapheme Count</th>'
                '<th scope="col">Word Count</th>'
                '<th scope="col">Sentence Count</th></tr>')
    html.append('</thead><tbody>')
    
    if not segmented_reports or "error" in segmented_reports:
        html.append("<tr><td colspan='4'>No data.</td></tr>")
    else:
        for report in segmented_reports:
            metrics = report['metrics']
            html.append('<tr>')
            html.append(f"<td>{report['segment_id']}</td>")
            html.append(f"<td>{metrics.get('grapheme_count', 0)}</td>")
            html.append(f"<td>{metrics.get('word_count', 0)}</td>")
            html.append(f"<td>{metrics.get('sentence_count', 0)}</td>")
            html.append('</tr>')

    html.append('</tbody></table>')
    table_el.innerHTML = "".join(html)

def render_sparklines(segmented_reports):
    """
    Renders the "Big Picture" sparkline charts.
    (Placeholder for now)
    """
    sparkline_el = document.getElementById("sparkline-output")
    if sparkline_el:
        sparkline_el.innerHTML = "<h3>Macro-Profile (Sparklines)</h3><p>(Charts will be rendered here)</p>"

# ---
# 4. MAIN BOOTSTRAP FUNCTION
# ---

async def main():
    status_el = document.getElementById("loading-status")
    try:
        # 1. Get the JsProxy from the opener window
        core_data_proxy = window.opener.TEXTTICS_CORE_DATA
        
        if not core_data_proxy:
            status_el.innerText = "Error: No data from Stage 1. Please run an analysis on the main app page and click 'Analyze Macrostructure' again."
            status_el.style.color = "red"
            return

        # 2. Convert the pure JavaScript object back into a native Python dict.
        core_data = core_data_proxy.to_py()
        
        status_el.innerText = f"Successfully loaded data from Stage 1 (Timestamp: {core_data.get('timestamp')}). Running macro-analysis..."
        
        # 3. Run the full Stage 2 pipeline
        segmented_report = compute_segmented_profile(core_data, N=10)
        
        # 4. Render the UI
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
