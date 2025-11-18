# Stage 2: The Macrostructure Profile ("Structural MRI")
## 1. 🔬 Core Philosophy: From "Microscope" to "Altitude"
The **Text...tics** project operates on a unified, two-tier analytical philosophy known as the "Microscope-to-Altitude" model. While Stage 1 provides the atomic ground truth, Stage 2 provides the structural context.
### The Limits of the Microscope (Stage 1)
**Stage 1** acts as a high-powered **"Microscope."** It performs a deep, atomic-level integrity analysis. It examines every individual **Code Point** and **Grapheme** in isolation to identify specific, known threats.
* **It Answers:** "Does this text contain a threat? Is there a `U+202E` Bidi override at index 45? Is this emoji sequence valid?"
* **The Blind Spot:** A microscope cannot see *shape*. A text can be composed entirely of "safe" characters (e.g., Latin letters and numbers) yet be structured in a way that indicates a malicious payload (e.g., a Base64 blob hidden inside a paragraph of prose). Stage 1 sees "safe characters"; it misses the **anomaly of distribution**.
### The Power of Altitude (Stage 2)
**Stage 2** acts as the **"Altitude View"** or **"Structural MRI."** It does not look at atoms in isolation; it looks at the **distribution of properties** across time (the length of the string). It slices the text into segments and analyzes the *rhythm, density, and texture* of the data.
* **It Answers:** "Where in the text does the *texture* change? Is there a segment that is statistically too dense? Is there a 'normal' looking segment that contains a sudden drop in entropy? Does the rhythm of the text shift from 'human prose' to 'machine code' halfway through?"
* **Its Goal:** **Anomaly Detection via Pattern Recognition.** It allows the analyst to spot "outliers of form" even when the "content" appears valid.
Stage 2 is not a summary of Stage 1. It is a distinct analytical dimension. It provides the **"Where"** (the location and shape) to Stage 1's **"What"** (the specific character identity).
---
## 2. 🧬 The Analytical Model: Interpolated Dual-Atom Slicing
The Macrostructure Profile is built on a rigorous mathematical foundation designed to normalize texts of any length into a comparable "standardized view."
### 2.1 The Unit of Volume: The Grapheme Cluster
To create a "Structural MRI," we must first slice the text into segments of equal "volume." In text analysis, strictly slicing by **byte** or **code point** is a machine-centric error that corrupts human-perceived meaning.
* Slicing by code point splits surrogate pairs (destroying the character).
* Slicing by code point splits grapheme clusters (e.g., severing a "Family" emoji `👨‍👩‍👧‍👦` into four separate people and three invisible joiners).
Stage 2 utilizes the browser's native `Intl.Segmenter` (UAX #29 compliant) to determine the **Grapheme Cluster** as the fundamental unit of volume. This ensures that every slice represents an equal portion of *user-perceived text*, regardless of the underlying byte complexity.
### 2.2 The Slicing Algorithm: Linear Interpolation
Previous iterations used "naive chunking" (e.g., `total // 10`), which resulted in "remainder dumping"—where the final segment would be significantly larger or smaller than the others, creating false statistical anomalies.
Stage 2 (v3) implements **Linear Interpolation Slicing**. This algorithm distributes the "remainder" characters evenly across the segments, ensuring maximum uniformity.
$$\text{Start}_i = \lfloor \frac{i \times \text{Total}}{N} \rfloor, \quad \text{End}_i = \lfloor \frac{(i+1) \times \text{Total}}{N} \rfloor$$
This ensures that a 17-character string sliced into 10 segments results in a balanced distribution (e.g., 2, 1, 2, 2, 1...) rather than a lopsided one (1, 1, ... 8). This mathematical smoothing is critical for the accuracy of the heatmap.
### 2.3 The "3-Way" RLE Classification Engine
Once sliced, the engine performs a **Run-Length Encoding (RLE)** analysis on every grapheme to determine the "Texture" of the segment. It classifies every atom into one of three structural bins:
1. **The Invisible Atom (Structural Integrity):**
    * **Definition:** Characters that have no visual width but alter the text state. Includes `Bidi_Control`, `Join_Control` (ZWJ/ZWNJ), and `Default_Ignorable`.
    * **Behavior:** These are treated as **"Run Breakers."** They interrupt the flow of both Content and Separators. They represent "hidden structural cost."
2. **The Separator (The Void):**
    * **Definition:** Characters that create visual space. Includes `White_Space` and the UAX #29 `Newline` set (CR, LF, LS, PS).
    * **Behavior:** These create "Gaps." A sequence of separators forms a **"Space Run."**
3. **The Content (The Mass):**
    * **Definition:** Anything that is visible and not a separator. Letters, Numbers, Punctuation, Symbols, Emoji.
    * **Behavior:** These create "Mass." A sequence of content characters forms a **"Content Run."**
    * **Significance:** This logic correctly identifies `aaa'a` as a *single* run (prose token) and `if(x==1):` as a *single* run (code token), making it robust across different text types.
---
## 3. 📈 The Visual Layer: "The Structural Seismograph"
The first thing the analyst sees is not a table, but a **"Structural Triptych."** This is a set of three synchronized, interactive sparklines that visualize the **Narrative Flow** of the text.
Tables are excellent for values, but poor for trends. The Seismograph provides an immediate visual "ECG" of the text, allowing the user to spot sudden changes in authorship, inserted payloads, or structural corruption before reading a single number.
### Track 1: Run-Length Entropy (The Rhythm)
* **Visual:** A Purple Line Chart.
* **Metric:** **Shannon Entropy ($H$)**, normalized to a scale of **0 to 4.0 bits**.
* **The Question:** *"How complex is the pattern of word lengths?"*
* **Forensic Interpretation:**
    * **High/Volatile ($H \approx 3.5$):** Natural Language. Humans use a mix of short (`a`, `the`) and long (`extraordinary`) words, creating high entropy.
    * **Low/Flat ($H < 1.0$):** Machine Data or Padding. A sequence like `AAAA BBBB CCCC` has very low entropy. A drop in this line indicates a "dead zone" of repetitive data.
    * **Sudden Spike:** An encrypted block or Base64 string (which maximizes randomness).
### Track 2: Content Density (The Mass)
* **Visual:** A Green Filled Area Chart.
* **Metric:** **Content Density %** (Percentage of the segment composed of visible graphemes vs. gaps).
* **The Question:** *"How solid is this text?"*
* **Forensic Interpretation:**
    * **High Plateau (~90-100%):** Dense prose or a "Wall of Text."
    * **Low Valley (~50%):** A list, poetry, or code with heavy indentation.
    * **Dip:** If a dense text suddenly dips in the middle, it suggests a format shift (e.g., an inserted table or list).
### Track 3: Threat Events (The Pulse)
* **Visual:** A Red Bar Chart.
* **Metric:** **Threat Count** (Absolute count of Stage 1 forensic flags in that segment).
* **The Question:** *"Is this segment radioactive?"*
* **Forensic Interpretation:**
    * **Flat Line:** Clean text.
    * **Single Spike:** A specific, localized attack (e.g., a Bidi override inserted in the middle of a sentence).
    * **Rising Bar:** A concentration of anomalies (e.g., a cluster of invisible separators).
### The "Cross-Marking" System
This is the killer feature of the Triptych.
* **Logic:** Whenever `Track 3 (Threats)` registers a value $> 0$, the system draws a **faint red vertical line** through `Track 1 (Entropy)` and `Track 2 (Density)` at that exact X-coordinate.
* **Value:** This creates an instant **Visual Correlation.** The analyst can see, at a glance: *"The Entropy line dropped exactly where the Red Threat line appeared."* This binds the structural symptom to the forensic cause.
---
## 4. 📊 Table 1: The Macro-MRI (Overview)
Following the Seismograph is the **Macro-MRI Table**. This is the "Triage" view. It breaks the text down into segments and analyzes their **Density** and **Integrity**.
### The Logic: "Density vs. Quantity"
In Stage 2, we move away from raw counts (which are misleading if segments vary in size) and focus on **Density Metrics**.
* **Content %:** How much of this slice is text?
* **Gap %:** How much is whitespace?
* **Space Runs:** The number of distinct gaps.
* **Avg Gap:** The average width of those gaps.
### The "Heatmap" Anomaly Detector
This table utilizes a sophisticated **Z-Score Anomaly Detector** to highlight deviations.
1. **The Baseline:** It calculates the Mean ($\mu$) and Standard Deviation ($\sigma$) for the entire text.
2. **The Z-Score:** For each segment, it calculates how many standard deviations it is from the mean.
3. **The Paint:**
    * **Green/White:** Within normal parameters.
    * **Yellow/Orange:** Statistically significant deviation ($Z > 1.5$).
    * **Red (Critical):** **Threshold Override.** If any *Critical Threat* (Bidi/Join control) is found, the row is painted Red regardless of statistics.
### The "Small Sample" Guardrail
Statistical analysis is noisy on very short texts. If the total volume is **< 100 graphemes**, the system automatically **suppresses the Z-Score Heatmap** (painting the rows neutral). This prevents "False Alarms" where a standard sentence looks like a statistical outlier simply because the dataset is too small to establish a baseline.
---
## 5. 🔬 Table 2: The Texture-MRI (Forensic Fingerprint)
This is the deepest layer of the analysis. The **Texture-MRI** moves beyond "how much text is there" to answer "what is the *shape* of that text?"
It profiles the **Content Run-Length Distribution**. (i.e., "How many 3-letter words vs. 10-letter words are in this segment?").
### 5.1 The "1–15 + 16+" Binning Strategy
Based on linguistic stylometry and forensic needs, we use a specific granular binning strategy:
* **Columns 1–15:** Individual bins for run lengths from 1 to 15 graphemes. This captures the "fingerprint" of almost all natural language (average word length ~5) and source code (average token length ~4).
* **Column 16+:** A "Tail Bin" for anything longer than 15 graphemes.
    * **Forensic Value:** Natural text rarely hits this bin. **Encrypted strings, Hashes, and Base64 payloads** almost *always* hit this bin. A spike in "16+" is a primary indicator of a non-human payload.
### 5.2 The Metric: Volume Share % (Not Raw Counts)
This table does not show raw counts (which deceive the eye). It shows **Volume Share Percentage ($p_{vol}$)**.
* **Definition:** *"What percentage of the visible text mass in this segment is composed of runs of this length?"*
* **Why:** This normalizes the data. A "Wall of Text" segment and a "Short Sentence" segment can be compared directly.
* **Visual:** The background of each cell is heat-mapped based on this percentage (Excel-style conditional formatting). This creates a "Visual Ribbon" flowing down the table.
    * **Prose:** The ribbon flows down the middle (Columns 4–7).
    * **Code:** The ribbon clings to the left (Columns 1–3).
    * **Payloads:** The ribbon jumps to the far right (Column 16+).
### 5.3 World-Class Descriptive Statistics
To the right of the distribution matrix, we provide four high-fidelity statistical descriptors for the segment's texture:
1. **Mean ($\mu$):** The average run length. (Baseline).
2. **Median ($\tilde{x}$):** The middle value. Crucial for detecting skew. If Mean is 10 but Median is 3, you have hidden outliers (payloads).
3. **Mode (Mo):** The most common run length. The "Beat" of the text.
4. **StdDev ($\sigma$):** The variety. Low $\sigma$ = machine repetition. High $\sigma$ = human variance.
5. **Max Run:** The absolute length of the longest run. This disambiguates the "16+" bin. (Is it a 17-letter German word, or a 500-letter API key?).
6. **Entropy ($H$):** The complexity of the distribution.
### 5.4 The Global Summary Row (The Fingerprint)
At the very bottom, a **Global Summary Row** aggregates all data to provide a single, master fingerprint for the entire text. This serves as the "Control Sample" against which individual segments can be judged.
---
## 6. 🌉 The Interactive Bridge (Stage 2 $\to$ Stage 1)
Stage 2 is not a passive report; it is a navigation tool for Stage 1. It implements a bidirectional **Interactive Bridge**.
1. **Click-to-Highlight:**
    * Clicking the **Segment Index** (e.g., "Indices 0-50") in the table...
    * OR clicking any **Data Point** in the Sparklines...
    * ...triggers a command sent to the opening window (`window.opener`).
    * The Main App (Stage 1) receives this command, calculates the exact UTF-16 offsets for that grapheme range, focuses the textarea, and **physically selects/highlights** that specific text segment.
2. **Visual Feedback:**
    * Hovering over a Sparkline point instantly highlights the corresponding row in **both** tables (Macro and Texture), linking the visual trend to the numerical data.
    * A vertical "Guide Bar" appears across all three sparklines to align the metrics visually.
### The "Aha!" Moment: Visualizing Inter-Layer Attacks
This bridge visually proves **Inter-Layer Mismatch Attacks** (like Bidi overrides).
* *Scenario:* You have a text with a `U+202E` (Right-to-Left Override) that scrambles the visual order of characters.
* *Action:* You click "Segment 10" (the end of the string) in Stage 2.
* *Result:* Because Stage 2 operates on the *Logical* backing store, it selects the *Logical* end of the string. However, due to the Bidi attack, the browser highlights text that appears in the *Middle* or *Beginning* of the visual line.
* *Conclusion:* The user sees a "broken selection," providing irrefutable visual proof that the text they *see* is not the text the machine *reads*.
---
## 7. 🧠 Forensic Use Cases: How to Read the MRI
### Case A: The Hidden Payload (Steganography/Injection)
* **Sparklines:** Entropy is flat, then suddenly drops (if padding) or spikes (if encrypted). Threat bar spikes red.
* **Macro-MRI:** A segment shows normal density but high "Flag Density."
* **Texture-MRI:** The "Ribbon" flows normally (cols 4-7), then one row has a massive block in **Column 16+**.
* **Diagnosis:** A block of non-natural data has been inserted.
### Case B: The "Trojan Source" (Bidi Attack)
* **Sparklines:** Entropy and Density look normal (it's just code). **Threat Pulse** has a single, thin red line.
* **Macro-MRI:** One segment shows `Bidi: 1`.
* **Texture-MRI:** Normal code profile (left-skewed).
* **Action:** Click the segment. See the selection jump to the wrong visual location in Stage 1.
* **Diagnosis:** Bidi control character reordering logic.
### Case C: The "Invisible Wall" (Homoglyphs/Formatting)
* **Sparklines:** Content Density drops slightly (invisible chars take up logical space but no visual space).
* **Macro-MRI:** A segment shows **Gap %: 0** but **Other Invisibles: 50**.
* **Texture-MRI:** Normal.
* **Diagnosis:** The text is padded with invisible characters (e.g., ZWSP) to break filters or fingerprinting.
---
## 8. Technical Architecture
* **File:** `stage2.py` (Python via PyScript).
* **Dependency:** Zero server-side code. Runs 100% in-browser.
* **Data Source:** `window.opener.TEXTTICS_CORE_DATA`. It consumes a "frozen" snapshot of the analysis from Stage 1.
* **Rendering:**
    * **Tables:** Dynamic HTML generation with Python f-strings.
    * **Sparklines:** Dynamic SVG generation with Python strings (no external charting libraries for maximum speed and security).
    * **Styling:** CSS Grid for layout, `rgba` transparency for heatmaps to ensure text legibility.
This architecture makes Stage 2 a robust, standalone forensic instrument. It minimizes its dependency on Stage 1 by consuming only the core data snapshot and performing its own lightweight UAX-based analysis for RLE classification.
