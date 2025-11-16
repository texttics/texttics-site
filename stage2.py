# stage2.py
import asyncio
from pyscript import document, window
from pyodide.ffi import create_proxy

# ---
# 1. CORE LOGIC: THE SEGMENTED ANALYSIS PIPELINE
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
    # nfkc_cf_text = core_data.get("nfkc_casefold_text", "") # For TTR
    
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
        # The last chunk gets all the remaining graphemes
        end_index = (i + 1) * chunk_size if i < N - 1 else total_graphemes
        
        segment_graphemes = grapheme_list[start_index:end_index]
        segment_text = "".join(segment_graphemes)
        
        # 4. Feature Extraction (Run metrics on this chunk)
        # We will build these functions next.
        metrics = {}
        # metrics["word_count"] = compute_word_count(segment_text)
        # metrics["sentence_count"] = compute_sentence_count(segment_text)
        # metrics["punct_density"] = compute_punct_density(segment_graphemes)
        # metrics["ttr"] = compute_ttr(segment_text, nfkc_cf_text)
        # metrics["threat_flags"] = count_flags_in_segment(forensic_flags, start_index, end_index)
        # metrics["zalgo_score"] = compute_zalgo_score(segment_graphemes)
        
        # For now, just a placeholder:
        metrics["grapheme_count"] = len(segment_graphemes)
        
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
# 2. RENDERING FUNCTIONS
# ---

def render_macro_table(segmented_reports):
    """
    Renders the main "Heatmap Table" for Stage 2.
    """
    table_el = document.getElementById("macro-table-output")
    if not table_el:
        return

    html = ['<table class="matrix"><thead>']
    html.append('<tr><th scope="col">Segment</th><th scope="col">Grapheme Count</th></tr>')
    html.append('</thead><tbody>')
    
    if not segmented_reports or "error" in segmented_reports:
        html.append("<tr><td colspan='2'>No data.</td></tr>")
    else:
        for report in segmented_reports:
            html.append('<tr>')
            html.append(f"<td>{report['segment_id']}</td>")
            html.append(f"<td>{report['metrics']['grapheme_count']}</td>")
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
# 3. MAIN BOOTSTRAP FUNCTION
# ---

async def main():
    status_el = document.getElementById("loading-status")
    try:
        # `window.opener` is the JS way to access the tab that opened this one
        core_data = window.opener.TEXTTICS_CORE_DATA
        
        if not core_data:
            status_el.innerText = "Error: No data from Stage 1. Please run an analysis on the main app page and click 'Analyze Macrostructure' again."
            status_el.style.color = "red"
            return
        
        status_el.innerText = f"Successfully loaded data from Stage 1 (Timestamp: {core_data.get('timestamp')}). Running macro-analysis..."
        
        # Run the full Stage 2 pipeline
        segmented_report = compute_segmented_profile(core_data, N=10)
        
        # Render the UI
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
