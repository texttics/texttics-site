import asyncio
import json
import math
from pyscript import document, window
from pyodide.ffi import create_proxy
from pyodide.http import pyfetch
import bisect 

# ---
# 0. STAGE 2 DATA STORES & LOADERS
# ---

GLOBAL_SEGMENTED_REPORT = None

STAGE2_DATA_STORES = {
    "WordBreak": {"ranges": [], "starts": [], "ends": []},
    "White_Space": {"ranges": [], "starts": [], "ends": []},
    "Bidi_Control": {"ranges": [], "starts": [], "ends": []},
    "Join_Control": {"ranges": [], "starts": [], "ends": []},
    "Default_Ignorable_Code_Point": {"ranges": [], "starts": [], "ends": []},
}
DATA_LOADED = False

PROP_MAP = {
    "White_Space": "White_Space",
    "Bidi_Control": "Bidi_Control",
    "Join_Control": "Join_Control",
    "Default_Ignorable_Code_Point": "Default_Ignorable_Code_Point",
}

def _parse_and_store_ranges(txt: str, store_key: str, property_map: dict = None):
    """Generic parser for Unicode range data files."""
    if property_map:
        temp_ranges = {key: [] for key in STAGE2_DATA_STORES.keys() if key in property_map.values()}
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
                except Exception: pass 
        for key, ranges_list in temp_ranges.items():
            if not ranges_list: continue
            store = STAGE2_DATA_STORES[key]
            ranges_list.sort()
            store["ranges"].extend([(s, e, v) for s, e, v in ranges_list])
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
            except Exception: pass
        ranges_list.sort()
        store["ranges"] = [(s, e, v) for s, e, v in ranges_list]

    for key in STAGE2_DATA_STORES:
        store = STAGE2_DATA_STORES[key]
        if store["ranges"] and (not store.get("starts") or len(store["starts"]) != len(store["ranges"])):
            store["ranges"].sort()
            store["starts"] = [s for s, e, v in store["ranges"]]
            store["ends"] = [e for s, e, v in store["ranges"]]

async def load_stage2_data():
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
    except Exception as e:
        print(f"Stage 2: Error loading data: {e}")
        DATA_LOADED = False

def _find_in_ranges(cp: int, store_key: str):
    store = STAGE2_DATA_STORES[store_key]
    starts_list = store.get("starts", []) 
    if not starts_list: return None
    i = bisect.bisect_right(starts_list, cp) - 1
    if i >= 0 and cp <= store["ends"][i]:
        return store["ranges"][i][2]
    return None

# ---
# 1. METRIC HELPER FUNCTIONS
# ---

def get_grapheme_base_properties(grapheme: str) -> dict:
    props = {"wb": "Other", "is_WhiteSpace": False, "is_Bidi_Control": False, "is_Join_Control": False, "is_Default_Ignorable": False}
    if not grapheme: return props
    # Native Python string access
    first_char = grapheme[0]
    cp = ord(first_char)
    props["wb"] = _find_in_ranges(cp, "WordBreak") or "Other"
    props["is_WhiteSpace"] = _find_in_ranges(cp, "White_Space") is not None
    props["is_Bidi_Control"] = _find_in_ranges(cp, "Bidi_Control") is not None
    props["is_Join_Control"] = _find_in_ranges(cp, "Join_Control") is not None
    props["is_Default_Ignorable"] = _find_in_ranges(cp, "Default_Ignorable_Code_Point") is not None
    return props

def _calculate_entropy(run_lengths):
    """Calculates Shannon Entropy (H) for the run length distribution."""
    if not run_lengths: return 0.0
    total = len(run_lengths)
    counts = {}
    for x in run_lengths:
        counts[x] = counts.get(x, 0) + 1
    entropy = 0.0
    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy

def _calculate_stats(values: list) -> (float, float):
    """Returns Mean and StdDev."""
    n = len(values)
    if n == 0: return 0.0, 0.0
    mean = sum(values) / n
    if n == 1: return mean, 0.0
    variance = sum((x - mean) ** 2 for x in values) / n
    std_dev = variance ** 0.5
    return mean, std_dev

# ---
# 2. CORE ANALYSIS PIPELINE
# ---

def compute_segmented_profile(core_data, N=10):
    print("Stage 2: Running macro-analysis...")
    grapheme_list = core_data.get("grapheme_list", [])
    grapheme_lengths = core_data.get("grapheme_lengths_codepoints", [])
    forensic_flags = core_data.get("forensic_flags", {})
    
    total_graphemes = len(grapheme_list)
    if total_graphemes == 0: return {"error": "No graphemes to analyze."}

    # --- Interpolated Segmentation Logic ---
    actual_N = min(N, total_graphemes)
    if actual_N < 1: actual_N = 1
    
    segmented_reports = []
    LINEBREAK_PROPS = {"LF", "CR", "Newline"}
    
    # O(N) prefix sum map for mapping
    cp_map = [0] * (total_graphemes + 1)
    current_cp_index = 0
    for i in range(total_graphemes):
        cp_map[i] = current_cp_index
        current_cp_index += grapheme_lengths[i]
    cp_map[total_graphemes] = current_cp_index
    
    for i in range(actual_N):
        # Linear Interpolation for smooth slicing
        start_grapheme_index = (i * total_graphemes) // actual_N
        end_grapheme_index = ((i + 1) * total_graphemes) // actual_N
        segment_graphemes = grapheme_list[start_grapheme_index:end_grapheme_index]
        
        # RLE Analysis
        content_run_lengths = []
        current_content_run = 0
        space_run_lengths = []
        current_space_run = 0
        line_break_count = 0
        bidi_atom_count = 0
        join_atom_count = 0
        other_invisible_atom_count = 0
        
        for grapheme in segment_graphemes:
            props = get_grapheme_base_properties(grapheme)
            wb_prop = props["wb"]

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
            
            if wb_prop in LINEBREAK_PROPS:
                line_break_count += 1
                if current_content_run > 0: content_run_lengths.append(current_content_run)
                if current_space_run > 0: space_run_lengths.append(current_space_run)
                current_content_run, current_space_run = 0, 0
            
            elif props["is_WhiteSpace"]:
                if current_content_run > 0:
                    content_run_lengths.append(current_content_run)
                    current_content_run = 0
                current_space_run += 1
            
            else:
                if current_space_run > 0:
                    space_run_lengths.append(current_space_run)
                    current_space_run = 0
                current_content_run += 1

        if current_content_run > 0: content_run_lengths.append(current_content_run)
        if current_space_run > 0: space_run_lengths.append(current_space_run)

        # --- Advanced Statistics ---
        total_content_runs = len(content_run_lengths)
        mean_len, std_dev = _calculate_stats(content_run_lengths)
        max_run = max(content_run_lengths) if content_run_lengths else 0
        entropy = _calculate_entropy(content_run_lengths)

        # --- Granular Bins (1-16+) ---
        # Bins are now keys 1..16, where 16 represents 16+
        bins = {x: 0 for x in range(1, 17)}
        for length in content_run_lengths:
            if length >= 16: bins[16] += 1
            else: bins[length] += 1

        total_space_runs = len(space_run_lengths)
        avg_space_length = (sum(space_run_lengths) / total_space_runs) if total_space_runs > 0 else 0
        
        # --- Threat Integration ---
        start_cp_index = cp_map[start_grapheme_index]
        end_cp_index = cp_map[end_grapheme_index]
        
        critical_flag_positions = set()
        all_flag_positions = set()
        CRITICAL_FLAGS_SET = {"Bidi Control (UAX #9)", "Join Control (Structural)"}
        
        if forensic_flags:
            for flag_name, data in forensic_flags.items():
                if data and data.get('count', 0) > 0:
                    if flag_name.startswith("Prop:"): continue
                    is_critical = flag_name in CRITICAL_FLAGS_SET
                    for pos_str in data.get('positions', []):
                        try:
                            pos = int(pos_str.lstrip('#').split(' ')[0]) 
                            if start_cp_index <= pos < end_cp_index:
                                all_flag_positions.add(pos) 
                                if is_critical: critical_flag_positions.add(pos)
                        except Exception: pass

        # --- Density & Share Metrics ---
        vol = len(segment_graphemes)
        epsilon = 1e-9
        total_content_graphemes = sum(content_run_lengths)
        total_gap_graphemes = sum(space_run_lengths) + line_break_count
        
        content_density_pct = round((total_content_graphemes / (vol + epsilon)) * 100, 1)
        gap_density_pct = round((total_gap_graphemes / (vol + epsilon)) * 100, 1)
        
        # 8. Store metrics
        metrics = {
            # Metadata
            "volume": vol,
            
            # Texture / Bins
            "bins": bins, # Dict 1..16
            
            # Stats
            "mean_run": round(mean_len, 2),
            "std_dev": round(std_dev, 2),
            "max_run": max_run,
            "entropy": round(entropy, 2),
            
            # Separators / Gaps
            "space_runs": total_space_runs,
            "line_breaks": line_break_count,
            "avg_space_length": round(avg_space_length, 2),
            
            # Integrity (Counts)
            "bidi_atoms": bidi_atom_count,
            "join_atoms": join_atom_count,
            "other_invisibles": other_invisible_atom_count,
            "threats_critical": len(critical_flag_positions),
            "threats_all": len(all_flag_positions),
            
            # Densities (Percentages)
            "content_density_pct": content_density_pct,
            "gap_density_pct": gap_density_pct
        }
        
        report = {
            "segment_id": f"{i+1} / {actual_N}",
            "indices_str": f"{start_grapheme_index}–{end_grapheme_index-1}",
            "start_grapheme_index": start_grapheme_index,
            "end_grapheme_index": end_grapheme_index,
            "metrics": metrics
        }
        segmented_reports.append(report)

    return segmented_reports

# ---
# 3. RENDERING FUNCTIONS
# ---

def _get_heat_style(value, max_val, color_tuple="13, 110, 253"):
    """
    Returns an inline style string for Excel-like heatmaps.
    color_tuple: RGB string e.g. "13, 110, 253" (Bootstrap Primary Blue)
    """
    if max_val == 0 or value == 0: return ""
    # Calculate intensity (0.0 to 1.0)
    ratio = value / max_val
    # Cap opacity at 0.5 so text remains readable
    opacity = 0.05 + (0.45 * ratio) 
    return f'style="background-color: rgba({color_tuple}, {opacity});"'

def render_tables(segmented_reports):
    """Renders BOTH the Macro-Overview and the Texture-MRI tables."""
    
    # Handle Errors
    if isinstance(segmented_reports, dict) and "error" in segmented_reports:
        err = segmented_reports['error']
        document.getElementById("macro-table-output").innerHTML = f"<div class='alert'>{err}</div>"
        return
    elif not segmented_reports:
        document.getElementById("macro-table-output").innerHTML = "<div>No Data</div>"
        return

    # --- PRE-CALCULATION: FIND COLUMN MAXIMA FOR HEATMAPS ---
    # We need the max value for every column to normalize colors
    max_vals = {
        "content_density_pct": 0, "gap_density_pct": 0,
        "space_runs": 0, "line_breaks": 0, "avg_space_length": 0,
        "bins": {i: 0 for i in range(1, 17)}
    }
    
    for r in segmented_reports:
        m = r['metrics']
        max_vals["content_density_pct"] = max(max_vals["content_density_pct"], m["content_density_pct"])
        max_vals["gap_density_pct"] = max(max_vals["gap_density_pct"], m["gap_density_pct"])
        max_vals["space_runs"] = max(max_vals["space_runs"], m["space_runs"])
        max_vals["line_breaks"] = max(max_vals["line_breaks"], m["line_breaks"])
        max_vals["avg_space_length"] = max(max_vals["avg_space_length"], m["avg_space_length"])
        
        for k, v in m["bins"].items():
            max_vals["bins"][k] = max(max_vals["bins"][k], v)

    # --- TABLE 1: MACRO-MRI (Overview) ---
    html_macro = [
        '<table class="matrix">',
        '<thead><tr>',
        '<th rowspan="2">Segment</th><th rowspan="2">Indices</th><th rowspan="2">Vol.</th>',
        '<th colspan="2">Density Metrics</th>',
        '<th colspan="3">Gap Structure</th>',
        '<th colspan="3">Integrity (Atoms)</th>',
        '<th colspan="2">Threats</th>',
        '</tr><tr>',
        # Sub-headers
        '<th>Content %</th><th>Gap %</th>',
        '<th>Space Runs</th><th>Lines</th><th>Avg Gap</th>',
        '<th>Bidi</th><th>Join</th><th>Other</th>',
        '<th>Critical</th><th>All Flags</th>',
        '</tr></thead><tbody>'
    ]

    for rep in segmented_reports:
        m = rep['metrics']
        
        # Bridge Logic
        s_idx, e_idx = rep['start_grapheme_index'], rep['end_grapheme_index']
        click_js = f"window.opener.TEXTTICS_HIGHLIGHT_SEGMENT({s_idx},{e_idx}); return false;"
        link = f'<a href="#" class="bridge-link" onclick="{click_js}">{rep["indices_str"]}</a>'
        
        # Styles
        style_cont = _get_heat_style(m['content_density_pct'], max_vals['content_density_pct'], "25, 135, 84") # Green
        style_gap = _get_heat_style(m['gap_density_pct'], max_vals['gap_density_pct'], "108, 117, 125") # Grey
        style_space = _get_heat_style(m['space_runs'], max_vals['space_runs'], "13, 202, 240") # Cyan
        
        # Threat Coloring (Threshold, not Gradient)
        cls_bidi = "cell-critical" if m['bidi_atoms'] > 0 else ""
        cls_join = "cell-warning" if m['join_atoms'] > 0 else ""
        cls_crit = "cell-critical" if m['threats_critical'] > 0 else ""
        cls_all = "cell-warning" if m['threats_all'] > 0 else ""

        html_macro.append(f'<tr>')
        html_macro.append(f'<td>{rep["segment_id"]}</td>')
        html_macro.append(f'<td>{link}</td>')
        html_macro.append(f'<td>{m["volume"]}</td>')
        
        html_macro.append(f'<td {style_cont}>{m["content_density_pct"]}%</td>')
        html_macro.append(f'<td {style_gap}>{m["gap_density_pct"]}%</td>')
        
        html_macro.append(f'<td {style_space}>{m["space_runs"]}</td>')
        html_macro.append(f'<td>{m["line_breaks"]}</td>')
        html_macro.append(f'<td>{m["avg_space_length"]}</td>')
        
        html_macro.append(f'<td class="{cls_bidi}">{m["bidi_atoms"]}</td>')
        html_macro.append(f'<td class="{cls_join}">{m["join_atoms"]}</td>')
        html_macro.append(f'<td>{m["other_invisibles"]}</td>')
        
        html_macro.append(f'<td class="{cls_crit}">{m["threats_critical"]}</td>')
        html_macro.append(f'<td class="{cls_all}">{m["threats_all"]}</td>')
        html_macro.append('</tr>')
    
    html_macro.append('</tbody></table>')
    document.getElementById("macro-table-output").innerHTML = "".join(html_macro)

    # --- TABLE 2: TEXTURE-MRI (1-16+ Bins) ---
    html_tex = [
        '<table class="matrix">',
        '<thead><tr>',
        '<th rowspan="2">Segment</th>',
        '<th colspan="16">Content Run-Length Distribution (Graphemes)</th>',
        '<th colspan="4">Texture Statistics</th>',
        '</tr><tr>'
    ]
    # Header numbers 1..15, 16+
    for i in range(1, 16): html_tex.append(f'<th>{i}</th>')
    html_tex.append('<th>16+</th>')
    html_tex.append('<th>Mean (&mu;)</th><th>StdDev (&sigma;)</th><th>Max Run</th><th>Entropy (H)</th>')
    html_tex.append('</tr></thead><tbody>')

    for rep in segmented_reports:
        m = rep['metrics']
        html_tex.append(f'<tr><td>{rep["segment_id"]}</td>')
        
        # Bins 1..16
        for i in range(1, 17):
            val = m['bins'][i]
            # Blue Heatmap
            style = _get_heat_style(val, max_vals['bins'][i], "13, 110, 253")
            html_tex.append(f'<td {style} class="texture-cell">{val}</td>')
            
        # Statistics
        html_tex.append(f'<td class="stat-cell">{m["mean_run"]}</td>')
        html_tex.append(f'<td class="stat-cell">{m["std_dev"]}</td>')
        html_tex.append(f'<td class="stat-cell">{m["max_run"]}</td>')
        html_tex.append(f'<td class="stat-cell">{m["entropy"]}</td>')
        html_tex.append('</tr>')

    html_tex.append('</tbody></table>')
    document.getElementById("texture-table-output").innerHTML = "".join(html_tex)


@create_proxy
async def copy_report_to_clipboard(event):
    global GLOBAL_SEGMENTED_REPORT
    btn = document.getElementById("btn-copy-report")
    if not GLOBAL_SEGMENTED_REPORT: return

    try:
        report_json = json.dumps(GLOBAL_SEGMENTED_REPORT, indent=2)
        await window.navigator.clipboard.writeText(report_json)
        btn.innerText = "Copied!"
        await asyncio.sleep(2)
        btn.innerText = "Copy JSON Report"
    except Exception:
        btn.innerText = "Error"

# ---
# 4. MAIN BOOTSTRAP FUNCTION
# ---

async def main():
    global DATA_LOADED
    status_el = document.getElementById("loading-status")
    
    status_el.innerText = "Loading Stage 2 UAX data (WordBreak, PropList, DerivedCore)..."
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
        
        # Store for copy function
        global GLOBAL_SEGMENTED_REPORT
        GLOBAL_SEGMENTED_REPORT = segmented_report
        
        render_sparklines(segmented_report)
        
        # --- FIX IS HERE: Calling the correct new function ---
        render_tables(segmented_report) 
        
        # Enable and attach listener to the copy button
        copy_btn = document.getElementById("btn-copy-report")
        if copy_btn:
            copy_btn.disabled = False
            copy_btn.addEventListener("click", create_proxy(copy_report_to_clipboard))
        
        status_el.innerText = "Macrostructure Profile (v1.0)"

    except Exception as e:
        status_el.innerText = f"A critical error occurred: {e}. Is the main app tab still open?"
        status_el.style.color = "red"
        print(f"Stage 2 Error: {e}")

# Start the Stage 2 app
print("Stage 2 starting...")
asyncio.ensure_future(main())
