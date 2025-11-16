# Stage 2: The Macrostructure Profile ("Structural MRI")

## 1. 🔬 Core Philosophy: From "Microscope" to "Altitude"

The Text...tics project is a unified, two-part analysis system. Each part serves a distinct, complementary purpose, following a "Microscope-to-Altitude" philosophy.

* **Stage 1 (The Microscope):** This is the core `app.py` application. It functions as a "microscope," performing a deep, *atomic-level* integrity analysis. It examines every individual **Code Point** and **Grapheme** to find specific, known *threats*.
    * **It Answers:** "Does this text contain a threat? Is there a single `U+202E` Bidi override? Is there a lone `U+200D` Zero Width Joiner? Is this emoji sequence valid?"
    * **Its Goal:** **Threat Identification**. It provides a definitive, granular report of all atomic-level integrity flags.

* **Stage 2 (The Altitude View):** This is the new `stage2.py` macro-profile, which opens in a separate tab. It functions as an "altitude view" or a "structural MRI," performing a *macro-shape* analysis. It slices the text into segments and analyzes the *distribution* and *concentration* of structural properties.
    * **It Answers:** "**Where** in the text are the anomalies? Is there a segment with unusually high punctuation density? Is there a "normal" looking segment that contains 5 critical invisible threats? Does the *shape* of the text (e.g., average word length) change suddenly?"
    * **Its Goal:** **Anomaly & Distribution Analysis**.

Stage 2 is not just a summary of Stage 1; it is a new analytical dimension. It provides the "where" (the altitude) to Stage 1's "what" (the microscope), allowing an analyst to pinpoint the exact location of structural anomalies and threat concentrations.

---

## 2. 🧬 The Analytical Model: The Dual-Atom "Slice"

The Macrostructure Profile is built on two core concepts: **Grapheme-Based Slicing** (for human-perceived volume) and a **Hybrid RLE Engine** (for dual-atom analysis).

### The Grapheme-Based "Slice" (Segmentation)

To create a "structural MRI," we must first slice the text into segments of equal "volume." In text analysis, there are three ways to slice: by byte, by code point, or by grapheme.

Slicing by byte or code point is a machine-centric view that is meaningless to a human. It could cut an emoji (`👨‍👩‍👧‍👦`) or a complex character (`é`) in half, corrupting the analysis.

The primary unit of "volume" for a human is the **Grapheme Cluster**, as defined by **Unicode Standard Annex #29 (UAX #29)**. This is what a user *perceives* as a single "character."

Therefore, Stage 2's first and most critical step is to use the browser's native `Intl.Segmenter` to segment the entire text into its full list of graphemes. This list is then split into `N` equal-sized segments (e.g., 10 "slices" of 100 graphemes each).

This ensures that each "MRI slice" represents an equal portion of the *user-perceived text*, providing a meaningful and consistent basis for comparison.

### The "Grapheme-RLE" Engine (The 3-Way Classification)

This is the core "brain" of `compute_segmented_profile` in `stage2.py`. It extends Stage 1's "Dual-Atom" philosophy by using a hybrid Grapheme/Code Point model to analyze the *shape* of each slice.

The engine iterates through each grapheme in a slice and performs a **3-way classification** to determine its structural purpose. This robust model can analyze prose, source code, or "garbage" text with equal, deterministic precision.

1.  **Is it an "Invisible Atom"?**
    * **Logic:** The engine first checks if the grapheme's base code point has a property like `Bidi_Control`, `Join_Control`, or `Default_Ignorable_Code_Point`.
    * **Behavior:** These are not "content" or "gaps"; they are a third category of "structural junk." They are counted in their respective "Invisible Atom" bins (`Bidi Atoms`, `Join Atoms`, `Other Cf/Cc`).
    * **Crucially, they *break* any active Content or Separator run.** This correctly identifies them as "run-breaking" atoms that add hidden structural cost.

2.  **Is it a "Separator"?**
    * **Logic:** If not an invisible, the engine checks if the grapheme is a `White_Space` or a Line Break (`LF`, `CR`).
    * **Behavior:** A separator *breaks* an active "Content Run." It is then counted, either by incrementing `line_break_count` or by starting/continuing a "Space Run."

3.  **Is it "Content"?**
    * **Logic:** If the grapheme is neither an invisible nor a separator, it is classified as "Content."
    * **Behavior:** A content grapheme *breaks* an active "Space Run" and starts/continues a "Content Run."
    * **Examples:** This logic correctly identifies `aaa'a` (with an apostrophe) as a *single* Content Run. It also correctly identifies `if(x==1):` as a *single* Content Run, making it a robust "token" finder for analyzing source code.

This 3-way classification engine allows Stage 2 to profile two distinct layers simultaneously:

* **Visible Structure (Grapheme-Based Runs):** It profiles the "shape" of what the user can see by analyzing "Content Runs" (the tokens) and "Separator Runs" (the gaps).
* **Invisible Integrity (Code Point-Based Atoms):** It profiles the "hidden" machine-level structure by counting the raw Code Points of invisible characters.

---

## 3. 📊 The "MRI" Table: Anatomy of a Segment Profile

The primary UI is a table where each row is one "slice" of the text, presenting its complete structural story. This table is the "UI Contract" rendered by `render_macro_table`.

### Section 1: Identification
*What and where this slice is.*

* **Segment:** The slice number (e.g., `1 / 10`).
* **Indices (Grapheme):** The `start–end` grapheme index range for this slice. This is not just text; it is a **clickable link** that forms the "Interactive Bridge" back to Stage 1, allowing a user to instantly highlight this segment in the main text editor.
* **Grapheme Count (Volume):** The total number of graphemes in this slice (the `N` for this segment).

### Section 2: Visible Content Run Histogram
*The "shape" of the "tokens" in this slice.*

* **1 gr. / 2 gr. / 3-5 gr. / 6-10 gr. / 11+ gr.:** These columns form a 5-bin histogram of "Content Run" lengths. A sudden spike in the `1 gr.` or `2 gr.` bins in a prose segment is a strong anomaly signal, often indicating fragmented text or source code.
* **Total Runs:** The total count of Content Runs in the slice.
* **Avg. Length (μ):** The mean length (in graphemes) of a Content Run. This is a key metric for the anomaly detector.

### Section 3: Visible Separator Run Profile
*The "shape" of the "gaps" between the content.*

* **Space Runs:** The number of `Space` sequences.
* **Line Breaks:** A raw count of Line Break characters.
* **Avg. Space (μ):** The mean length of a Space Run. A value of `1.0` indicates single-spacing, while a value of `2.0` would indicate consistent double-spacing.

### Section 4: Invisible Atom Integrity (Code Point Count)
*The hidden structural cost of this slice, as observed by Stage 2.*

These columns represent the *raw physical observation* from the Stage 2 "MRI" (i.e., `stage2.py`'s *own* analysis of its local UAX data files).

* **Bidi Atoms:** Raw count of `Bidi_Control` code points.
* **Join Atoms:** Raw count of `Join_Control` (ZWJ, ZWNJ) code points.
* **Other (Cf/Cc):** Raw count of all other Format, Control, and Ignorable code points (e.g., ZWSP, Soft Hyphen).

### Section 5: Threat Location (Stage 1 Bridge)
*The interpreted threat level, as diagnosed by Stage 1.*

These columns represent the *interpreted diagnosis* from the Stage 1 "Pathologist" (i.e., `app.py`). Stage 2 counts how many of Stage 1's `forensic_flags` fall within this segment's code point boundaries.

* **Threats (Critical):** This is the most important column. It is **not** a simple sum of Section 4. It is a de-duplicated count of all code points in this slice that were flagged by Stage 1 with a *semantically critical* flag. This is defined in the `CRITICAL_FLAGS_SET` in `stage2.py` and includes high-risk attack vectors like:
    * `Bidi Control (UAX #9)`
    * `Join Control (Structural)`
* **Threats (All Flags):** A de-duplicated count of all other code points in this slice that were flagged by Stage 1 (e.g., `Flag: Invalid Variation Selector`, `Flag: Deceptive Spaces`), excluding purely informational `Prop:` flags.

---

## 4. 🔥 The v3 Analytics Layer (The "Heatmap")

A table of 180 numbers is data. A *heatmap* is an answer. The v3 Analytics Layer is a system built into `render_macro_table` that runs a final statistical analysis on the `segmented_reports` list to *automatically find and highlight anomalies*.

This turns the "MRI" from a static table into a dynamic, "heat-seeking" anomaly detector.

### Core Density Metrics
First, the system calculates four "Core Density Metrics" for each segment. These normalize the raw counts by the segment's volume (`grapheme_count`), making them comparable.

1.  **`content_density`:** `total_content_graphemes / grapheme_count`
    * **Meaning:** "How much 'text' is in this slice?" (A value of 1.0 would be pure content).
2.  **`gap_density`:** `(sum(space_run_lengths) + line_breaks) / grapheme_count`
    * **Meaning:** "How much 'visible separation' is in this slice?"
3.  **`flag_density`:** `all_flags / grapheme_count`
    * **Meaning:** "How much 'hidden structural junk' is in this slice?"
4.  **`critical_density`:** `threats_critical / grapheme_count`
    * **Meaning:** "What is the concentration of 'high-risk threats' in this slice?"

### The Structural Opacity Index
These metrics are combined to create the **Structural Opacity Index**, a key heuristic for finding anomalies:

> **`Opacity Index = gap_density + flag_density`**

This index captures the classic anomaly signal: a slice with **low `content_density`** but a **high `opacity_index`** is a segment filled with "structural junk" (gaps, invisibles, flags) but very little visible content.

### The Anomaly Score (Z-Score)
Next, the system identifies *statistical* outliers using a Z-score calculation:
1.  **Collect Vectors:** It builds a list of values for each of the Core Density Metrics and `avg_content_length` across all `N` segments.
2.  **Calculate Stats:** It finds the mean (`μ`) and standard deviation (`σ`) for each metric's vector.
3.  **Calculate Z-Scores:** For each segment, it calculates a Z-score for *each metric* (`z = (value - μ) / σ`).
4.  **Combine:** It combines these into a single, unified `Anomaly Score` for the segment, representing its total statistical deviation from the norm:
    $$
    \text{Anomaly Score}_i = \sqrt{ \sum_{m} (z^m_i)^2 }
    $$

### The Final Readout (Guardrails & Heatmap)
Finally, the system uses two critical "guardrails" to assign a final CSS heatmap class to each `<tr>` row:

1.  **Guardrail 1 (The Override):** The system *first* checks if `metrics.get("threats_critical", 0) > 0`. If `true`, the segment is *always* and *immediately* assigned `heatmap-critical`. A known threat is, by definition, the most important anomaly and overrides any statistical score.
2.  **Guardrail 2 (The Statistics):** If no critical threat is found, the system uses the `Anomaly Score` to assign a statistical class:
    * `heatmap-high` (e.g., `Anomaly Score > 3.0`)
    * `heatmap-low` (e.g., `Anomaly Score > 1.5`)
    * `heatmap-normal` (for all others)

This layered logic ensures the user's eye is drawn *first* to known, high-risk threats, and *second* to statistically "weird" segments.

---

## 5. 🏗️ Architectural Model: The "Provider-Consumer" Pipeline

To ensure 100% data consistency and prevent redundant calculations, the entire Stage 1 / Stage 2 system operates on a clean "Provider-Consumer" model.

### Stage 1 (Provider)
The main `app.py` is the "Provider." When `update_all()` finishes its analysis, it packages a complete "Core Data" payload and exposes it to the browser.
1.  **Event:** `update_all()` runs on every text input.
2.  **Payload:** It gathers `grapheme_list`, `grapheme_lengths_codepoints` (a critical prefix-sum array), the full `forensic_flags` dictionary (including all emoji and integrity flags), and the `nfkc_casefold_text`.
3.  **Export:** It packages this into a Python `dict`, converts it to a pure JavaScript object (using `to_js(..., dict_converter=window.Object.fromEntries)` to prevent proxy errors), and saves it to `window.TEXTTICS_CORE_DATA`.

### User Action
1.  The user clicks the "Analyze Macrostructure" button (`btn-run-stage2`).
2.  A simple JavaScript listener calls `window.open('stage2.html', '_blank')`.

### Stage 2 (Consumer)
The new `stage2.html` tab opens, and `stage2.py` boots as the "Consumer." Its `async def main()` function executes a clear, linear pipeline:

1.  **`await load_stage2_data()`:** The consumer *first* asynchronously fetches its *own* set of required UAX data files (`WordBreakProperty.txt`, `PropList.txt`, `DerivedCoreProperties.txt`). This is a critical design choice that makes Stage 2 self-sufficient and solely responsible for its own RLE logic.
2.  **Read Payload:** It reads the data from the first tab using `window.opener.TEXTTICS_CORE_DATA` and converts it back to a native Python `dict` using `.to_py()`.
3.  **`compute_segmented_profile(core_data)`:** This is the main analysis.
    * It first builds the `grapheme_to_cp_map` from the `grapheme_lengths_codepoints` payload. This O(N) operation enables O(1) lookups for mapping Stage 1 flags.
    * It loops `N` times to create each "slice."
    * In each slice, it inner-loops through `segment_graphemes`, calling `get_grapheme_base_properties()` to query its *local* `DATA_STORES` and perform the 3-way RLE classification ("Invisible," "Separator," "Content").
    * It bins the run lengths (`content_run_lengths`, `space_run_lengths`).
    * It uses the `grapheme_to_cp_map` to find the `start_cp_index` and `end_cp_index` for this slice.
    * It iterates through the `forensic_flags` payload from Stage 1, using the index map to count all flags that fall within its boundaries.
    * It calculates all Core Density Metrics.
    * It returns the complete `segmented_reports` list of dictionaries.
4.  **`render_macro_table(segmented_reports)`:**
    * The renderer receives the raw report data.
    * It performs the **v3 Analytics (Z-Score)** calculations.
    * It applies the **Heatmap Guardrails** (`heatmap-critical`, etc.).
    * It builds and injects the final HTML, including the clickable "Interactive Bridge" links.

---

## 6. 🌉 The "Altitude-to-Microscope" Workflow

Stage 2 is not just a report; it's an *interactive tool*. It provides two key features to bridge the "Altitude" view back to the "Microscope" (Stage 1).

### Feature 1: The Interactive Bridge (Click-to-Highlight)
This feature allows a user to "click-to-inspect" an anomaly.

* **Stage 2 (The Call):** The `Indices (Grapheme)` column in the MRI table is rendered as an `<a>` tag with an `onclick` handler. This handler is defensively coded to check if the opener tab is still available:
    > `if (window.opener && !window.opener.closed) { ... }`
* **The API Call:** The click fires `window.opener.TEXTTICS_HIGHLIGHT_SEGMENT(start_grapheme_index, end_grapheme_index)`.
* **Stage 1 (The API):** A new public function, `window.TEXTTICS_HIGHLIGHT_SEGMENT`, is defined in Stage 1's `ui-glue.js`. When called, it:
    1.  Grabs the *current* text from the Stage 1 `<textarea>`.
    2.  Runs `Intl.Segmenter` *again* on this text to create a fresh array of grapheme segments.
    3.  Finds the *code unit* (`.index`) of the `startGraphemeIndex`-th grapheme.
    4.  Finds the *code unit* (`.index`) of the `endGraphemeIndex`-th grapheme (or the end of the text).
    5.  Calls `textArea.focus()` and `textArea.setSelectionRange()` to instantly select the corresponding text in the main app.

> **The "Aha!" Moment: Visualizing Bidi Attacks**
> This bridge does more than just highlight; it *visually proves* inter-layer mismatch attacks.
>
> When analyzing a string with a `U+202E` (Right-to-Left Override), the *logical* order of the text (in memory) is different from the *perceptual* order (on screen).
>
> When a user clicks the *last* segment in the Stage 2 table (e.g., indices `333-375`), the Interactive Bridge correctly finds the *logical* text at that position. However, the browser renders this selection on the *perceptually corrupted* text. The user sees a "broken" selection highlighting text in the middle of the input, **visually proving** that the Bidi attack has successfully broken the text's logical-to-perceptual mapping.

### Feature 2: Exportable Macro-Profile (Structural Diff)
This feature provides a machine-readable copy of the analysis, enabling the "Structural Diff" use case.

* **The Button:** A "Copy JSON Report" button (`btn-copy-report`) is included in `stage2.html`.
* **The Logic:** This button triggers a `copy_report_to_clipboard` proxy function in `stage2.py`.
* **The Payload:** The function `json.dumps()` the `GLOBAL_SEGMENTED_REPORT` (the final list of segment dictionaries) to the clipboard.
* **The Goal:** This enables the tool's ultimate "Structural Integrity" check. A user can run the report on "version 1" of a text, save the JSON, then run it on "version 2." By diffing the two JSON files, they can deterministically prove *if* and *where* any structural changes (in shape, density, or threat level) have occurred, even if the text looks perceptually identical.
