# Stage 2: The Macrostructure Profile ("Structural MRI")

## 1. Core Philosophy: From "Microscope" to "Altitude"

* **Stage 1 (The Microscope):** The core Text...tics application functions as a "microscope." It performs an *atomic integrity* analysis at the **Code Point** level to find *threats* (e.g., a single `U+202E` Bidi override, a lone `ZWJ`). Its goal is to tell you *if* a structural threat exists.

* **Stage 2 (The Altitude View):** This new Macrostructure Profile functions as an "altitude view" or "structural MRI." It performs a *macro-shape* analysis at the **Grapheme Run** level. Its goal is to find *anomalies* and *distribution* (e.g., a segment with unusually high punctuation, or a segment that contains 5 high-risk threats).

Stage 2 answers the question: **"Where** in the text are the structural anomalies and "shape" changes concentrated?"

## 2. The Analytical Model: A Dual-Atom "Slice"

The Macrostructure Profile extends the core "Dual-Atom" philosophy. The text is first sliced into `N` equal segments, and then each slice is profiled using a hybrid Grapheme/Code Point model.

### The Grapheme-Based "Slice" (Segmentation)

The primary unit of "volume" for a human is the **Grapheme** (what a user *perceives* as a character).

The entire text is first segmented into its full list of graphemes using the browser's native `Intl.Segmenter` (UAX #29). This list is then split into `N` equal-sized segments (e.g., 10 "slices" of 100 graphemes each). This ensures each "MRI slice" represents an equal portion of the user-perceived text.

### The Hybrid Counting Model (Grapheme Runs vs. Code Point Atoms)

This is the core of the Stage 2 analysis, allowing it to analyze prose, code, or "garbage" text with equal, deterministic precision.

1.  **Visible Structure (Grapheme-Based Runs):** We profile the "shape" of what the user can see.
    * **"Content Runs" (Your "inter-whitespace run"):** A sequence of one or more graphemes that are *not* separators. This correctly identifies `aaa'a` and `if(x==1):` as single "Content" tokens.
    * **"Separator Runs" (Your "gaps"):** A sequence of one or more graphemes that *are* separators (e.g., ` ` or `   `).

2.  **Invisible Integrity (Code Point-Based Atoms):** We profile the "hidden" machine-level structure.
    * **"Invisible Atoms":** A raw **Code Point** count of all formatting, control, and Bidi characters (`\p{Cf}`, `\p{Cc}`, etc.) that are *not* visible separators. This provides the "hidden integrity cost" of each slice.

## 3. The "MRI" Table: Anatomy of a Segment Profile

The primary UI is a table where each row is one "slice" of the text, telling its complete structural story.

### Section 1: Identification
*What and where this slice is.*
* **Segment:** The slice number (e.g., `1 / 10`).
* **Indices (Grapheme):** The `start–end` grapheme index range for this slice.
* **Grapheme Count (Volume):** The total number of graphemes in this slice.

### Section 2: Visible Content Run Histogram
*The "shape" of the "tokens" in this slice, based on your binning idea.*
* **1 gr.:** Count of Content Runs 1 grapheme long.
* **2 gr.:** Count of Content Runs 2 graphemes long.
* **3-5 gr.:** Count of Content Runs 3-5 graphemes long.
* **6-10 gr.:** Count of Content Runs 6-10 graphemes long.
* **11+ gr.:** Count of Content Runs 11+ graphemes long.
* **Total Runs:** The total number of Content Runs in the slice.
* **Avg. Length (μ):** The mean length of a Content Run (a key metric for anomaly detection).

### Section 3: Visible Separator Run Profile
*The "shape" of the "gaps" between the content.*
* **Space Runs:** The number of `Space` sequences.
* **Line Breaks:** A raw count of Line Break characters.
* **Avg. Space (μ):** The mean length of a Space Run (e.g., a high number indicates "double-spacing").

### Section 4: Invisible Atom Integrity (Code Point Count)
*The hidden structural cost of this slice.*
* **Bidi Atoms:** Raw count of `Bidi_Control` code points.
* **Join Atoms:** Raw count of `Join_Control` (ZWJ, ZWNJ) code points.
* **Other (Cf/Cc):** Raw count of all other Format, Control, and Ignorable code points.

### Section 5: Threat Location (Stage 1 Bridge)
*This is the "bridge" back to Stage 1, answering "Where are the threats?"*
* **Threats (Critical):** A de-duplicated count of all code points in this slice that were flagged with `DANGER:` by Stage 1.
* **Threats (All Flags):** A de-duplicated count of all code points in this slice flagged with `DANGER:` *or* `Flag:`.

## 4. How It Works: The "Provider-Consumer" Data Flow

To ensure 100% consistency and efficiency, the Macrostructure Profile operates as a "Consumer."

1.  **Stage 1 (Provider):** The main `app.py` runs its full atomic analysis and exports its key findings (e.g., `grapheme_list`, `grapheme_lengths_codepoints`, `forensic_flags`) to a `window.TEXTTICS_CORE_DATA` object.
2.  **Stage 2 (Consumer):** The new `stage2.html` page is opened. Its `stage2.py` script:
    * Reads the pre-computed data from `window.opener.TEXTTICS_CORE_DATA`.
    * Loads its *own* necessary UAX data files (`WordBreakProperty.txt`, `PropList.txt`, etc.) to be self-sufficient in its macro-logic.
    * Performs the "Grapheme-Based RLE" analysis described above.
    * Renders the final "MRI Table."

This model isolates the logic, prevents code duplication, and ensures Stage 2 is always analyzing the *exact same data* that Stage 1 analyzed.
