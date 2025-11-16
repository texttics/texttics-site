# stage2.py
import asyncio
from pyscript import document, window
from pyodide.ffi import create_proxy

# ---
# 0. NATIVE JS SEGMENTERS (for Word/Sentence counting)
# ---

# *** THIS IS FIX #1 ***
# We use `None` for the locale to use the browser's default.
# This is more robust than assuming "en" is available.
try:
    WORD_SEGMENTER = window.Intl.Segmenter.new(None, {"granularity": "word"})
    SENTENCE_SEGMENTER = window.Intl.Segmenter.new(None, {"granularity": "sentence"})
    print("Stage 2: Segmenters initialized.")
except Exception as e:
    print(f"Error creating Intl.Segmenter: {e}")
    WORD_SEGMENTER = None
    SENTENCE_SEGMENTER = None

# ---
# 1. METRIC HELPER FUNCTIONS
# ---

def compute_word_count(segment_text: str) -> int:
    """Counts only segments that are 'words' (isWordLike: true)."""
    if not WORD_SEGMENTER:
        return 0
    try:
        segments_iterable = WORD_SEGMENTER.segment(segment_text)
        
        # *** THIS IS FIX #2 ***
        # We must iterate the JsProxy explicitly and use getattr()
        # to safely access the JavaScript property.
        word_count = 0
        for seg in segments_iterable:
            if getattr(seg, "isWordLike", False):
                word_count += 1
        return word_count
        # --- END OF FIX ---

    except Exception as e:
        print(f"Error in word segmentation: {e}")
        return 0

def compute_sentence_count(segment_text: str) -> int:
    """Counts sentence segments."""
    if not SENTENCE_SEGMENTER:
        return 0
    try:
        segments_iterable = SENTENCE_SEGMENTER.segment(segment_text)
        
        # *** THIS IS FIX #3 ***
        # We will also iterate this manually to be robust,
        # just in case len() is also failing on this proxy.
        sentence_count = 0
        for seg in segments_iterable:
            sentence_count += 1
        return sentence_count
        # --- END OF FIX ---

    except Exception as e:
        print(f"Error in sentence segmentation: {e}")
        return 0

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
    forensic_flags = core_data.get("forensic_flags", {})
    
    total_graphemes = len(grapheme_list)
    if total_graphemes == 0:
        return {"error": "No graphemes to analyze."}

    # 2. Segmentation (by Grapheme index)
    chunk_size = total_graphemes // N
    if chunk_size == 0:
        chunk_size = 1 # Avoid division by zero on tiny strings
        
    segmented_reports = []
    
    for i in range(N):
        # 3. Get the slice (chunk) for this segment
        start_index = i * chunk_size
        end_index = (i + 1) * chunk_size if i < N - 1 else total_graphemes
        
        # Skip empty segments (can happen if N > total_graphemes)
        if start_index >= total_graphemes:
            continue
            
        segment_graphemes = grapheme_list[start_index:end_index]
        segment_text = "".join(segment_graphemes)
        
        # 4. Feature Extraction (Run metrics on this chunk)
        metrics = {}
        metrics["grapheme_count"] = len(segment_graphemes)
        metrics["word_count"] = compute_word_count(segment_text)
        metrics["sentence_count"] = compute_sentence_count(segment_text)
        
        report = {
            "segment_id": f"{i+1} / {N}",
            "start_index": start_index,
            "end_index": end_index,
            "metrics": metrics
        }
        segmented_reports.append(report)

    # 5. Anomaly Detection (Z-Score)
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
