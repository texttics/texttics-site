import asyncio
import json
import math
from pyscript import document, window
from pyodide.ffi import create_proxy
from pyodide.http import pyfetch
import bisect
import statistics

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

def _calculate_stats(values: list):
    """Returns Mean, StdDev, Median, and Mode."""
    n = len(values)
    if n == 0: return 0.0, 0.0, 0, 0
    
    # Mean
    mean = sum(values) / n
    
    # StdDev
    if n == 1:
        std_dev = 0.0
    else:
        variance = sum((x - mean) ** 2 for x in values) / n
        std_dev = variance ** 0.5
        
    # Median
    median = statistics.median(values)
    
    # Mode (Robust handling for multi-modal data - takes the smallest mode)
    try:
        mode = statistics.mode(values)
    except statistics.StatisticsError:
        # If multiple modes, statistics.mode might raise error in older Py versions
        # or return the first one. We fallback to a simple counter.
        counts = {}
        for v in values: counts[v] = counts.get(v, 0) + 1
        max_freq = max(counts.values())
        mode = min([k for k, v in counts.items() if v == max_freq])

    return mean, std_dev, median, mode

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

    # --- Accumulator for Global Stats ---
    all_content_run_lengths = []
    
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

        # --- Accumulate for Global Stats ---
        all_content_run_lengths.extend(content_run_lengths)

        # --- Advanced Statistics ---
        total_content_runs = len(content_run_lengths)
        mean_len, std_dev, median, mode = _calculate_stats(content_run_lengths)
        max_run = max(content_run_lengths) if content_run_lengths else 0
        entropy = _calculate_entropy(content_run_lengths)

        # --- Granular Bins (1-16+) & Volume Shares ---
        # Bins: Raw Counts
        bins_counts = {x: 0 for x in range(1, 17)}
        # Bins: Volume (Total Graphemes in this bin)
        bins_volume = {x: 0 for x in range(1, 17)}
        
        for length in content_run_lengths:
            target_bin = 16 if length >= 16 else length
            bins_counts[target_bin] += 1
            bins_volume[target_bin] += length

        # Calculate Percentages
        # p_vol: % of total content graphemes in this slice that belong to this bin
        # p_run: % of total runs in this slice that belong to this bin
        bins_p_vol = {}
        bins_p_run = {}
        
        total_content_graphemes_slice = sum(content_run_lengths)
        total_runs_slice = len(content_run_lengths)
        epsilon = 1e-9

        for k in range(1, 17):
            bins_p_vol[k] = round((bins_volume[k] / (total_content_graphemes_slice + epsilon)) * 100, 1)
            bins_p_run[k] = round((bins_counts[k] / (total_runs_slice + epsilon)) * 100, 1)

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
            "bins_counts": bins_counts,
            "bins_volume": bins_volume,
            "bins_p_vol": bins_p_vol, # This drives the heatmap cell number
            "bins_p_run": bins_p_run, # This is for the tooltip
            
            # Stats
            "mean_run": round(mean_len, 2),
            "std_dev": round(std_dev, 2),
            "median_run": median,
            "mode_run": mode,
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

    # --- Compute Global Stats for the Summary Row ---
    g_mean, g_std, g_med, g_mode = _calculate_stats(all_content_run_lengths)
    g_max = max(all_content_run_lengths) if all_content_run_lengths else 0
    g_entropy = _calculate_entropy(all_content_run_lengths)
    
    # Attach global stats to the first report (or a metadata object) 
    # hacky but effective way to pass it to the renderer without changing return signature
    if segmented_reports:
        segmented_reports[0]['global_stats'] = {
            "mean": round(g_mean, 2),
            "std": round(g_std, 2),
            "median": g_med,
            "mode": g_mode,
            "max": g_max,
            "entropy": round(g_entropy, 2)
        }

    print(f"Stage 2: Processed {len(segmented_reports)} segments.")
    
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
    else:
        # --- v3 Anomaly Layer ---
        
        # 1. Define metrics to analyze
        metrics_to_normalize = [
            "avg_content_length", 
            "v3_content_density", 
            "v3_gap_density", 
            "v3_flag_density", 
            "v3_critical_density"
        ]
        
        # 2. Extract metric vectors
        metric_data = {key: [] for key in metrics_to_normalize}
        for report in segmented_reports:
            metrics = report['metrics']
            for key in metrics_to_normalize:
                metric_data[key].append(metrics.get(key, 0.0))
        
        # 3. Calculate stats (μ, σ) for each metric
        metric_stats = {}
        for key, values in metric_data.items():
            metric_stats[key] = _calculate_stats(values) # (mean, std_dev)
            
        # --- GUARDRAIL: Check Total Volume ---
        # If text is too short (< 100 graphemes), Z-score is noisy. Disable it.
        total_vol = sum(r['metrics']['volume'] for r in segmented_reports)
        suppress_zscore = total_vol < 100

        # 4. Calculate Anomaly Score and assign heatmap class to each report
        for report in segmented_reports:
            metrics = report['metrics']
            
            # Guardrail 1: Critical flags always get the highest alert
            if metrics.get("threats_critical", 0) > 0:
                report["heatmap_class"] = "heatmap-critical"
                continue

            # Guardrail 2: Small Sample Suppression
            if suppress_zscore:
                report["heatmap_class"] = "heatmap-normal"
                continue

            # Guardrail 3: Calculate Z-scores
            z_scores_squared = []
            for key in metrics_to_normalize:
                mean, std_dev = metric_stats[key]
                
                # Guardrail 3a: Skip if σ=0 (no variance)
                if std_dev == 0:
                    continue
                    
                value = metrics.get(key, 0.0)
                z = (value - mean) / std_dev
                z_scores_squared.append(z ** 2)
            
            if not z_scores_squared:
                report["heatmap_class"] = "heatmap-normal"
                continue
                
            # Combine into a single score: sqrt(sum(z^2))
            anomaly_score = sum(z_scores_squared) ** 0.5
            
            # 5. Bin the score into a heatmap class
            if anomaly_score > 3.0: # Arbitrary threshold for high anomaly
                report["heatmap_class"] = "heatmap-high"
            elif anomaly_score > 1.5: # Arbitrary threshold for low anomaly
                report["heatmap_class"] = "heatmap-low"
            else:
                report["heatmap_class"] = "heatmap-normal"
        # --- End of Anomaly Layer ---

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
        
        for k, v in m["bins_p_vol"].items():
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
        # Use heatmap class from Anomaly Layer as base row style
        row_cls = rep.get('heatmap_class', '')
        
        cls_bidi = "cell-critical" if m['bidi_atoms'] > 0 else ""
        cls_join = "cell-warning" if m['join_atoms'] > 0 else ""
        cls_crit = "cell-critical" if m['threats_critical'] > 0 else ""
        cls_all = "cell-warning" if m['threats_all'] > 0 else ""

        html_macro.append(f'<tr class="{row_cls}">')
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
        '<th colspan="16">Content Run-Length Distribution (Volume Share %)</th>',
        '<th colspan="6">Texture Statistics</th>',
        '</tr><tr>'
    ]
    # Header numbers 1..15, 16+
    for i in range(1, 16): html_tex.append(f'<th>{i}</th>')
    html_tex.append('<th>16+</th>')
    html_tex.append('<th>Mean (&mu;)</th><th>Median</th><th>Mode</th><th>StdDev (&sigma;)</th><th>Max Run</th><th>Entropy (H)</th>')
    html_tex.append('</tr></thead><tbody>')

    for rep in segmented_reports:
        m = rep['metrics']
        html_tex.append(f'<tr><td>{rep["segment_id"]}</td>')
        
        # Bins 1..16 (Showing Volume % Share)
        for i in range(1, 17):
            val_vol_pct = m['bins_p_vol'][i]
            
            # Data for Tooltip
            count = m['bins_counts'][i]
            run_pct = m['bins_p_run'][i]
            vol_abs = m['bins_volume'][i]
            
            tooltip = f"Length: {i if i < 16 else '16+'}&#10;Runs: {count} ({run_pct}%)&#10;Volume: {vol_abs} gr. ({val_vol_pct}%)"
            
            # Blue Heatmap based on Volume %
            style = _get_heat_style(val_vol_pct, max_vals['bins'][i], "13, 110, 253")
            
            # Render cell
            display_val = f"{val_vol_pct}%" if val_vol_pct > 0 else '<span style="color:#ccc; font-size:0.8em;">-</span>'
            
            html_tex.append(f'<td {style} class="texture-cell" title="{tooltip}">{display_val}</td>')
            
        # Statistics
        html_tex.append(f'<td class="stat-cell">{m["mean_run"]}</td>')
        html_tex.append(f'<td class="stat-cell">{m["median_run"]}</td>')
        html_tex.append(f'<td class="stat-cell">{m["mode_run"]}</td>')
        html_tex.append(f'<td class="stat-cell">{m["std_dev"]}</td>')
        html_tex.append(f'<td class="stat-cell">{m["max_run"]}</td>')
        html_tex.append(f'<td class="stat-cell">{m["entropy"]}</td>')
        html_tex.append('</tr>')

    # --- Global Summary Row (The Fingerprint) ---
    # 1. Aggregate totals across all slices
    global_bins_vol = {x: 0 for x in range(1, 17)}
    total_global_content = 0
    
    for r in segmented_reports:
        m = r['metrics']
        # Ensure we are summing the VOLUME (content mass), not raw counts
        for k, v in m['bins_volume'].items():
            global_bins_vol[k] += v
            total_global_content += v
            
    # 2. Render the Summary Row
    html_tex.append('<tr style="border-top: 2px solid #333; background-color: #e9ecef; font-weight: bold;">')
    html_tex.append('<td>Global %</td>')
    
    for i in range(1, 17):
        epsilon = 1e-9
        g_pct = round((global_bins_vol[i] / (total_global_content + epsilon)) * 100, 1)
        # Display formatting: Show dash if 0 for cleaner look
        disp = f"{g_pct}%" if g_pct > 0 else '<span style="color:#ccc; font-weight:normal;">-</span>'
        html_tex.append(f'<td>{disp}</td>')
        
    # Spanning the 6 statistics columns with REAL GLOBAL DATA
    gs = segmented_reports[0].get('global_stats', {})
    if gs:
        html_tex.append(f'<td class="stat-cell" style="background-color:#e9ecef;">{gs.get("mean", "-")}</td>')
        html_tex.append(f'<td class="stat-cell" style="background-color:#e9ecef;">{gs.get("median", "-")}</td>')
        html_tex.append(f'<td class="stat-cell" style="background-color:#e9ecef;">{gs.get("mode", "-")}</td>')
        html_tex.append(f'<td class="stat-cell" style="background-color:#e9ecef;">{gs.get("std", "-")}</td>')
        html_tex.append(f'<td class="stat-cell" style="background-color:#e9ecef;">{gs.get("max", "-")}</td>')
        html_tex.append(f'<td class="stat-cell" style="background-color:#e9ecef;">{gs.get("entropy", "-")}</td>')
    else:
        html_tex.append('<td colspan="6"></td>')
        
    html_tex.append('</tr>')

    html_tex.append('</tbody></table>')
    document.getElementById("texture-table-output").innerHTML = "".join(html_tex)

def render_sparklines(segmented_reports):
    """
    Generates three interactive SVG sparklines with Normalized Entropy, Subtitles, and Threat Cross-Marking.
    """
    container = document.getElementById("sparkline-output")
    if not container or not segmented_reports: return

    # 1. Extract Data Vectors
    # Fallback to 0 if key is missing to prevent crash
    entropies = [r['metrics'].get('entropy', 0) for r in segmented_reports]
    densities = [r['metrics'].get('content_density_pct', 0) for r in segmented_reports]
    threats   = [r['metrics'].get('threats_all', 0) for r in segmented_reports]
    
    # Identify Threat Segments for Cross-Marking (List of indices where threats > 0)
    threat_indices = [i for i, t in enumerate(threats) if t > 0]
    
    count = len(segmented_reports)
    if count < 2:
        container.innerHTML = "<p style='color:#999; font-style:italic; font-size:0.9rem;'>Insufficient segments for trend analysis.</p>"
        return

    # 2. CSS for Hover Effects (Injected directly for portability)
    style_block = """
    <style>
        .spark-svg { overflow: visible; }
        .spark-point { transition: r 0.1s ease-out, stroke-width 0.1s; cursor: crosshair; }
        .spark-point:hover { r: 4px; stroke: #fff; stroke-width: 2px; }
        .spark-bar { transition: opacity 0.1s; cursor: crosshair; }
        .spark-bar:hover { opacity: 0.7; }
        .spark-val-label { font-size: 10px; font-family: monospace; font-weight: bold; fill: #6c757d; }
        .spark-grid { stroke: #e9ecef; stroke-width: 1; }
        .spark-axis { stroke: #adb5bd; stroke-width: 1; }
        .spark-threat-mark { stroke: #dc3545; stroke-width: 1; stroke-dasharray: 2,2; opacity: 0.4; }
        .spark-subtitle { font-size: 0.75rem; color: #999; margin-top: -4px; margin-bottom: 8px; font-style: italic; }
    </style>
    """

    # 3. Helper: Interactive SVG Builder
    def build_svg(values, type='line', color='#0d6efd', y_max=None, unit="", cross_marks=None):
        # Dimensions (ViewBox coordinates)
        w, h = 300, 60 
        
        # Normalize Y
        data_max = max(values) if values else 0
        mx = y_max if y_max is not None else data_max
        if mx == 0: mx = 1 # Avoid div zero
        
        step_x = w / (count - 1) if count > 1 else w
        
        # Build Point List & Path Strings
        path_d = []
        area_d = [f"M0,{h}"] 
        
        rects_html = []
        circles_html = []
        
        for i, val in enumerate(values):
            x = round(i * step_x, 1)
            y = round(h - ((val / mx) * h), 1)
            
            # Tooltip Text
            tooltip = f"Segment {i+1}: {val}{unit}"
            
            if type == 'bar':
                bar_w = (w / count) * 0.8
                # Bar logic
                if val > 0:
                    bar_h = (val / mx) * h
                    bx = (i * (w / count)) + ((w/count)*0.1)
                    by = h - bar_h
                    bar_col = "#dc3545" if val > 0 else color
                    rects_html.append(f'<rect x="{bx}" y="{by}" width="{bar_w}" height="{bar_h}" fill="{bar_col}" class="spark-bar"><title>{tooltip}</title></rect>')
                else:
                     # Invisible hit target for zero values
                    bx = (i * (w / count))
                    rects_html.append(f'<rect x="{bx}" y="0" width="{w/count}" height="{h}" fill="transparent"><title>{tooltip}</title></rect>')

            else:
                # Line/Area logic
                path_d.append(f"{x},{y}")
                area_d.append(f"L{x},{y}")
                
                # Interactive circle (visible dot + tooltip)
                # Increased radius slightly for better visibility
                circles_html.append(f'<circle cx="{x}" cy="{y}" r="3" fill="{color}" class="spark-point"><title>{tooltip}</title></circle>')

        # Finish Path Strings
        area_d.append(f"L{w},{h} Z")
        poly_line = " ".join(path_d)
        poly_area = " ".join(area_d).replace("M", "M ").replace("L", " L ").replace("Z", " Z")
        
        # --- Construct SVG ---
        svg = [f'<svg viewBox="0 -15 {w} {h+20}" class="spark-svg" preserveAspectRatio="none" style="width:100%; height:75px; display:block;">']
        
        # Scale Label (Max Y)
        svg.append(f'<text x="0" y="-5" class="spark-val-label">Max: {mx}{unit}</text>')
        
        # Grid Lines
        svg.append(f'<line x1="0" y1="0" x2="{w}" y2="0" class="spark-grid" stroke-dasharray="4,4" />') # Top
        svg.append(f'<line x1="0" y1="{h}" x2="{w}" y2="{h}" class="spark-axis" />') # Bottom axis
        
        # Threat Cross-Marks (Vertical Lines)
        if cross_marks:
            for t_idx in cross_marks:
                tx = round(t_idx * step_x, 1)
                # For bars, shift to center of bar
                if type == 'bar': tx += ((w / count) * 0.5) 
                svg.append(f'<line x1="{tx}" y1="0" x2="{tx}" y2="{h}" class="spark-threat-mark" />')

        # Chart Content
        if type == 'area':
            svg.append(f'<path d="{poly_area}" stroke="none" fill="{color}" opacity="0.15" />')
            svg.append(f'<polyline points="{poly_line}" fill="none" stroke="{color}" stroke-width="1.5" />')
            svg.append("".join(circles_html)) 
            
        elif type == 'line':
            svg.append(f'<polyline points="{poly_line}" fill="none" stroke="{color}" stroke-width="2" />')
            svg.append("".join(circles_html))
            
        elif type == 'bar':
            svg.append("".join(rects_html))

        svg.append('</svg>')
        return "".join(svg)

    # 4. Generate Charts with Normalized Scaling & Cross-Marks
    
    # Entropy: Normalized to 4.0 bits (Log2(16))
    # This makes the scale consistent across ALL texts.
    svg_entropy = build_svg(entropies, 'line', '#6f42c1', y_max=4.0, cross_marks=threat_indices)
    
    # Density: Fixed 100% scale
    svg_density = build_svg(densities, 'area', '#198754', y_max=100, unit="%", cross_marks=threat_indices)
    
    # Threats: Min scale of 5
    max_threat = max(threats) if threats else 0
    scale_threat = max(5, max_threat) 
    # No cross-marks needed on the threat chart itself (redundant)
    svg_threat = build_svg(threats, 'bar', '#dc3545', y_max=scale_threat)

    # 5. Inject HTML (Grid Layout with Subtitles)
    html = f"""
    {style_block}
    <div style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 1rem; margin-bottom: 2rem;">
        <div style="background:#fff; border:1px solid #dee2e6; border-radius:4px; padding:10px; box-shadow:0 1px 2px rgba(0,0,0,0.05);">
            <div style="font-size:0.8rem; text-transform:uppercase; color:#6c757d; font-weight:600; border-bottom:1px solid #eee; margin-bottom:2px;">Run-Length Entropy</div>
            <div class="spark-subtitle">Rhythm Variety (Scale: 0-4 bits)</div>
            {svg_entropy}
        </div>
        <div style="background:#fff; border:1px solid #dee2e6; border-radius:4px; padding:10px; box-shadow:0 1px 2px rgba(0,0,0,0.05);">
            <div style="font-size:0.8rem; text-transform:uppercase; color:#6c757d; font-weight:600; border-bottom:1px solid #eee; margin-bottom:2px;">Content Density</div>
            <div class="spark-subtitle">Visible Mass vs. Gaps</div>
            {svg_density}
        </div>
        <div style="background:#fff; border:1px solid #dee2e6; border-radius:4px; padding:10px; box-shadow:0 1px 2px rgba(0,0,0,0.05);">
            <div style="font-size:0.8rem; text-transform:uppercase; color:#6c757d; font-weight:600; border-bottom:1px solid #eee; margin-bottom:2px;">Threat Events</div>
            <div class="spark-subtitle">Forensic Flags (Count)</div>
            {svg_threat}
        </div>
    </div>
    """
    container.innerHTML = html

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
