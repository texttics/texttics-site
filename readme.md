# Text...tics: A Deterministic Structural Profiler & Integrity Analyzer

## What is Text...tics?

This is a single-page web application that functions as a real-time, deterministic text analyzer. It is a highly specialized, browser-based "lab instrument" meticulously engineered to provide a literal, precise, and unfiltered view of any text string's internal structure, composition, and integrity.

Its primary goal is to function as a **"Structural Profiler"**. This tool is not a "best guess" analyzer; it is a deterministic machine. It generates a complete, absolute, and unambiguous statistical signature, or "profile," for any given text. This profile serves as a verifiable, ground-truth baseline, allowing for the computational detection of *any* structural change between two strings, no matter how perceptually subtle.

Its secondary, but equally important, goal is to serve as a **"Structural Integrity Analyzer."** It uses its detailed, multi-layered profile to detect, flag, and locate anomalies, deceptions, and sophisticated "inter-layer mismatch attacks." These are attacks specifically designed to deceive human perception while presenting a different logical reality to a machine. This tool is built to find the invisible, ambiguous, or malicious characters (such as homoglyphs, "Trojan Source" bidirectional overrides, invisible format controls, or steganographic variation selectors) that successfully survive the common copy/paste process and persist as a threat in a "post-clipboard" environment.

---

## The Architectural Model: A Hybrid, Serverless Powerhouse

The entire application runs 100% in the user's browser, requiring no server-side backend or data processing. This guarantees user privacy and enables instantaneous, real-time analysis. It operates on a powerful, serverless, hybrid model that leverages the best of two different environments: the high-speed JavaScript engine and the deep-analysis Python runtime (via PyScript).

### 1. The JavaScript Layer (High-Speed Standards Parsing)

This layer uses the browser's native, Just-In-Time (JIT) compiled JavaScript engines (like Google's V8 or Mozilla's SpiderMonkey). These engines are written in high-performance C++ and are the "world-class" standard for executing high-frequency, standards-compliant operations at native speed. We delegate two critical, high-throughput tasks to this layer:

* **Unicode Property Classification (UAX #18):** All 30 minor category checks (e.g., `\p{Lu}`, `\p{Po}`) and dozens of property checks (e.g., `\p{Emoji_Presentation}`, `\p{White_Space}`) are handled by the browser's native `RegExp` engine. This engine has a pre-compiled, optimized implementation of the Unicode Character Database, making it the fastest possible way to classify millions of code points per second.
* **Grapheme Cluster Segmentation (UAX #29):** The "perceptual" analysis is powered by the native `Intl.Segmenter` API. This is the browser's built-in, trusted implementation of **Unicode Standard Annex #29 (UAX #29)**, the official rulebook for determining "what counts as a single character" to a human user. We treat this as an authoritative black box for perceptual segmentation.

### 2. The Python Layer (Orchestration & Deep Analysis)

This layer runs a full Python 3.12 runtime in the browser via PyScript. Python acts as the application's "brain" or "chief orchestrator." It is used for lower-frequency, "heavy-lifting" tasks that require deep, data-driven logic and complex state management that JavaScript alone cannot easily provide.

* **State Management & Orchestration:** The main `update_all` function in `app.py` manages the entire application state and analysis pipeline, calling all computation functions and passing their results to the correct DOM renderers.
* **Deep Unicode Analysis:** It uses the rich, built-in `unicodedata` library for complex, stateful operations (like `unicodedata.numeric()` for summing values, `unicodedata.bidirectional()` for UAX #9 classes, or `unicodedata.decomposition()` for compatibility analysis) that are not available in JavaScript's `RegExp` engine.
* **Data-Driven Analysis (The Core):** This is the heart of the tool's "world-class" analytical depth. Python asynchronously fetches, parses, and analyzes raw data files directly from the Unicode Character Database (UCD). This data-driven approach allows the tool to perform checks that are impossible with regular expressions or built-in functions alone. The data files currently implemented include:
    * **`Blocks.txt`**: To determine a character's "neighborhood" (e.g., "Basic Latin," "Cyrillic," "Greek and Coptic").
    * **`DerivedAge.txt`**: To determine *when* a character was introduced to the Unicode standard (e.g., "1.1," "15.0").
    * **`Scripts.txt`**: Provides the primary `Script` property for every character (e.g., `Latn`, `Cyrl`), which is the data-driven fallback for our script analysis.
    * **`ScriptExtensions.txt`**: Provides the `Script_Extensions` property for "shared" characters (like punctuation), enabling our advanced, "dual-logic" script analysis.
    * **`LineBreak.txt`**: Provides the `Line_Break` class for every character, enabling the UAX #14 "Line Break Run Analysis" engine.
    * **`IdentifierType.txt`**: Provides security and identifier flags from UAX #31 (e.g., `Not_XID`, `Default_Ignorable`, `Deprecated`).
    * **`StandardizedVariants.txt`**: Provides the mapping for standardized (non-emoji, e.g., math and CJK) variation sequences.
    * **`PropList.txt`**: A "Rosetta Stone" file that provides dozens of critical binary properties. We parse this for:
        * `Bidi_Control`
        * `Join_Control`
        * `Deprecated`
        * `Extender`
        * `Dash`
        * `Quotation_Mark`
        * `Terminal_Punctuation`
        * `Sentence_Terminal`
        * `Variation_Selector` (the key fix for our emoji VS bug)
    * **`DerivedCoreProperties.txt`**: Provides other key derived properties, most notably `Alphabetic` and the steganographic vector `Other_Default_Ignorable_Code_Point`.
    * **`confusables.txt`**: (Fetched, but implementation is pending in Group 3)

The final result is a multi-layered, literal, and data-driven analysis of text composition, sequence (run) shape, structural integrity, and deep provenance, all based on the official Unicode Standard.

---

## 🔬 Core Philosophy: A "Post-Clipboard" Structural Integrity Analyzer

### What is a "Post-Clipboard" Analyzer?

The design of this tool is the result of a specific, critical scoping decision. It is a **"Post-Clipboard Structural Integrity Analyzer."**

This means its primary mission is to analyze the structural integrity of a decoded string *exactly as it exists* after being copied from an external source (like a website, email, or document) and pasted (Ctrl+V) into the browser's `<textarea>`.

This "post-clipboard" scope is a core feature, not a limitation. It defines our analytical boundary and allows us to focus on a class of threats that *survive* normalization and transit.

### The "Great Standardizer": A Core Feature, Not a Limitation

The operating system's clipboard and the browser's "paste" event are a powerful, standards-compliant security boundary. We call this boundary the **"Great Standardizer."**

By the time the text appears in our input box, the browser's strict, hardened rendering and paste engine has *already* performed a massive, free sanitization and pre-analysis for us:

1.  **Byte-Level Interpretation:** The browser has already interpreted the raw bytes from the clipboard, using a (guessed) encoding (e.g., UTF-8, Windows-1252, etc.).
2.  **Decoding:** It has decoded that byte stream into a standardized, internal JavaScript string (typically UTF-16).
3.  **Sanitization & Rejection:** This is the most critical step. The browser's engine has *already* strictly rejected or replaced any invalid, malformed, or corrupt byte-level data. This includes:
    * **Overlong UTF-8 sequences** (a classic security filter bypass).
    * **"Non-shortest form" byte sequences.**
    * **Lone Surrogates** (remnants of broken UTF-16 pairs).
    * **Invalid byte sequences** (e.g., `0xFF`).
    * **Ill-formed sequences** (e.g., a 4-byte UTF-8 sequence representing a code point > U+10FFFF).
    * In all these cases, the browser's modern, security-first engine will have **replaced** the offending data with the Unicode Replacement Character (, `U+FFFD`), providing an immediate, unambiguous flag of data corruption *before* our tool even runs.

### Defining Our Analytical Boundary (What This Tool IS NOT)

This "Great Standardizer" process allows our tool to focus 100% on its primary mission: analyzing the *structural integrity of the resulting, decoded string*. This is a critical distinction that separates our tool from others.

This tool **intentionally excludes** a whole class of "raw file" analysis. It **does not**:

* **Analyze raw bytes.** That is the job of a hex editor (like HxD or 010 Editor). Our tool does not show you `0xFE 0xFF`.
* **Perform encoding guessing.** That is the job of a library like `charset-normalizer`. Our tool trusts the browser's guess.
* **Detect byte-level corruption.** The browser has already detected this and replaced it with .

We analyze the **result** of that sanitization process, not the process itself. This makes our tool a "structural integrity" analyzer, not a "byte-level forensic" analyzer.

### Our Focus: Structural Profiling First, Threat-Hunting Second

This tool's philosophy is built on a clear, two-part order of operations:

1.  **IT IS:** A **"Post-Clipboard" analyzer** that examines the structural integrity of a *decoded, sanitized string*.
2.  **IT IS NOT:** A **"raw file analyzer"** or **"byte-level parser."** It analyzes the string *after* the browser's "Great Standardizer" has already processed it.
3.  **ITS MAIN GOAL (Group 2):** To be a **"Structural Profiler."** It provides the absolute, deterministic data needed to find *any* structural deviation between two text versions.
4.  **ITS SECONDARY GOAL (Group 3):** To be a **"Threat-Hunting Analyzer."** It uses this profile to detect *inter-layer mismatch attacks* (like homoglyphs, invisible characters, and Bidi controls) that *successfully survive* the browser's sanitization process.

---

## 🧭 Guiding Principles & Analytical Models

The entire application is built on two core models that allow it to analyze the structural integrity of text. These models are not just theories; they are directly expressed in the tool's User Interface.

### 1. The "Dual-Atom" Analysis Model (The "What")

This is the tool's foundational concept. It is built on the fact that any text string is composed of two different "atoms" *simultaneously*. The "inter-layer mismatch" between these two atoms is the primary vector for structural attacks and deceptions.

**Why a Parallel View? Why No Toggle?**
Our UI **does not use a toggle** to switch between these two atomic views. That would be a critical design failure, as it would *hide* the mismatch and force the user to rely on memory to compare the two.

Instead, our UI presents the analysis of both layers in **parallel, side-by-side tables.** This is the core feature. It *forces* the user to see the discrepancy at a glance. When the "Code Point" count and the "Grapheme" count for a given category do not match, the tool has successfully exposed an inter-layer mismatch.

* **Atom 1: The Code Point (Logical Atom)**
    * **What it is:** This is the foundational, logical atom. It is the "machine's-eye-view" of the text. This is the "raw" sequence of Unicode numbers (e.g., `U+0041` for 'A') that a database, parser, or compiler "sees."
    * **Forensic Value:** This is the *only* atom that can detect invisible deceptions. A Zero-Width Space (`U+200B`) is a full-fledged, first-class atom at this layer, as are Bidi control characters.
    * **Example 1 (Emoji):** The string `👨‍👩‍👧‍👦` (Family emoji) is correctly identified at this layer as **7 distinct logical atoms**:
        1.  `U+1F468` (Man)
        2.  `U+200D` (Zero Width Joiner)
        3.  `U+1F469` (Woman)
        4.  `U+200D` (Zero Width Joiner)
        5.  `U+1F467` (Girl)
        6.  `U+200D` (Zero Width Joiner)
        7.  `U+1F466` (Boy)
    * **Example 2 (Zalgo):** The string `é` (e with acute) is correctly identified as **2 distinct logical atoms**:
        1.  `U+0065` (Latin Small Letter e)
        2.  `U+0301` (Combining Acute Accent)

* **Atom 2: The Grapheme Cluster (Perceptual Atom)**
    * **What it is:** This is the "user-facing," perceptual atom. It is the "human's-eye-view" of the text. This is the "character" that a human user "sees," clicks on, or selects.
    * **Tooling:** This layer is analyzed using the browser's native `Intl.Segmenter`, which implements **Unicode Standard Annex #29 (UAX #29)**—the official Unicode rulebook for "Grapheme Cluster Boundaries."
    * **Forensic Value:** This layer's entire purpose is to *contrast* with the Code Point layer. It correctly identifies `👨‍👩‍👧‍👦` as **1 single perceptual atom,** just as a user would. It also identifies `é` as **1 single perceptual atom**.
    * **The Mismatch:** The tool's core power comes from this built-in, parallel comparison. The user can instantly see the mismatch (**Total Code Points: 7** vs. **Total Graphemes: 1**) and immediately prove that invisible structural characters (the Zero Width Joiners) are present. Likewise, they can see the mismatch for `é` (**L (Letter): 1, M (Mark): 1** vs. **L (Letter): 1, M (Mark): 0**), proving the presence of a combining mark.

### 2. The "Tri-State" Normalization Pipeline (The "How")

This tool uses a powerful **"Tri-State" Normalization Pipeline** as its analytical framework. This model defines the *state* of the text being analyzed. The entire "Structural Profile" (Group 2) operates *only* on State 1 to preserve 100% of the evidence. The "Threat-Hunting Analysis" (Group 3) will *intentionally* use States 2 and 3 to destroy evidence and unmask deceptions.

* **State 1: Forensic State (Raw String)**
    * **Algorithm:** No normalization. This is the raw, unaltered text as it was pasted (after the browser's "Great Standardizer" has sanitized it).
    * **Purpose:** Preserves 100% of the structural evidence. This is the *only* state that can see the physical difference between a pre-composed `é` (`U+00E9`) and a decomposed `e+´` (`U+0065` `U+0301`). It is the only state that sees compatibility characters (like `ﬁ`) and case differences.
    * **Used By:** **The entire "Structural Profile" (Group 2).** All core integrity profiling is done on this raw, unaltered data.

* **State 2: Compatibility State (NFKC)**
    * **Algorithm:** `unicodedata.normalize('NFKC', string)`
    * **Purpose:** Reveals compatibility spoofing. This state *intentionally destroys* compatibility evidence to unmask attacks. It canonicalizes *and* compat-decomposes.
    * **Example:** The ligature `ﬁ` (`U+FB01`) is "destroyed" and becomes its two-character equivalent `f` + `i`. A single, full-width `１` (`U+FF11`) becomes a standard `1`.
    * **Used By:** **Threat-Hunting Analysis (Group 3).**

* **State 3: Canonical Identity State (NFKC Casefold)**
    * **Algorithm:** `unicodedata.normalize('NFKC', string).casefold()`
    * **Purpose:** Reveals case-based spoofing. This is the ultimate "skeleton" for *compatibility and case* (but not homoglyphs). It destroys all compatibility *and* case evidence to create the ultimate canonical profile for comparison. It is the most aggressive normalization specified by the Unicode standard.
    * **Example:** `PayPal` becomes `paypal`. A Greek `Σ` (Sigma) becomes `σ` (small sigma).
    * **Used By:** **Threat-Hunting Analysis (Group 3).**

---

## 🏛️ Anatomy of the "Lab Instrument" (The Structural Profile)

The UI is not a flat list of modules but a hierarchical "lab bench" that presents the full structural profile in a logical, facts-first order. It consists of a sticky navigation list and a main content feed broken into the following anchored sections.

### Group 1: Analysis Configuration

This is the "Control Plane" for the instrument.
* **Text Input:** The main `<textarea>` that receives the "post-clipboard" string.
* **"Copy Report" Button:** A utility to copy the *entire* structured profile to the clipboard as a human-readable, timestamped text report.

### Group 2.A: Dual-Atom Profile

This is the "Atomic Count" of the string—the **what**. It provides the core parallel analysis of "Logical" (Code Point) vs. "Perceptual" (Grapheme) atoms.

* **Meta-Analysis (Cards):** The highest-level counts.
    * `Total Code Points`: The total number of logical atoms.
    * `Total Graphemes`: The total number of perceptual atoms.
    * `Whitespace (Total)`: Total `\p{White_Space}` characters.
    * `RGI Emoji Sequences`: Total `\p{Emoji_Presentation}` sequences.
* **Grapheme Structural Integrity (Cards):** A "Zalgo-detector" that analyzes the *physical structure* of the graphemes themselves.
    * `Single-Code-Point`: "Simple" graphemes (e.g., `a`).
    * `Multi-Code-Point`: "Complex" graphemes (e.g., `e+´` or `👨‍👩‍👧‍👦`).
    * `Total Combining Marks`: Total `\p{M}` marks found.
    * `Max Marks in one Grapheme`: The "Zalgo" score (e.g., `H̊̇ëļļo̧` would have a high score).
    * `Avg. Marks per Grapheme`: The average "complexity" of each grapheme.
* **Parallel Comparison Tables (Tabs):**
    * **Overview Tab:** A side-by-side table comparing the Code Point vs. Grapheme counts for the **7 Major Categories** (Letter, Number, Punctuation, etc.).
    * **Full Breakdown (30) Tab:** A side-by-side table comparing the Code Point vs. Grapheme counts for all **30 Minor Categories** (Lu, Ll, Nd, Po, Cf, etc.).

### Group 2.B: Structural Shape Profile

This is the "Structural Arrangement" of the string—the **how**. It analyzes the text as a *sequence* of runs, not just a "bag of atoms." This module leverages a powerful Run-Length Encoding (RLE) engine to profile the text's "shape."

* **Why it's a profile:** A simple "bag of atoms" diff won't see a structural change. This module will. The string `"don't"` produces a Major Run profile of **L-P-L** (Letter, Punctuation, Letter) and has `3` runs. The "fixed" string `"dont"` produces a profile of **L** and has `1` run. This change in the run-count is a deterministic flag of a structural edit.
* **Features:** This module contains **four** parallel Run-Length Encoding (RLE) analyses:
    * **`Major Category Run Analysis Table`**: A matrix that counts the uninterrupted runs of characters belonging to the **7 Major Categories** (`L`, `P`, `N`, etc.).
    * **`Minor Category Run Analysis Table`**: A deeper matrix that counts the uninterrupted runs of the **30 Minor Categories**. This is a far more granular profile. For example, the Major Run profile for `a.a` (Ll-Po-Ll) and `a'a` (Ll-Pf-Ll) is identical (`L-P-L`). But the Minor Run profile is different (`Ll: 2, Po: 1` vs. `Ll: 2, Pf: 1`), providing a definitive signature of the structural change.
    * **`Line Break Run Analysis (UAX #14)`**: A matrix that counts the uninterrupted runs of Line Break properties (e.g., `AL` (Alphabetic), `BK` (Break), `LS` (Line Separator)). This provides a fingerprint of the text's paragraph structure and is the core detector for "deceptive newline" attacks.
    * **`Bidi Class Run Analysis (UAX #9)`**: A matrix that counts the runs of Bidirectional properties (e.g., `L` (Left-to-Right), `R` (Right-to-Left), `RLO` (R-L Override)). This provides the foundational structural fingerprint for analyzing "Trojan Source" (Bidi) attacks.

### Group 2.C: Structural Integrity Profile

This is the "Flag" report. It provides a detailed, non-judgmental list of all "problematic," invisible, or modifying atoms found in the string. It is a "matrix of facts" that reports both the **Count** and the **Positions** (indices) of each flag. This list is the result of deep, data-driven analysis and has been "deconstructed" from old, naive flags into a granular, high-fidelity profile.

* **Corruption Flags:**
    * `Unassigned (Void) (Cn)`: Code points with no meaning. A vector for "future-tense" exploits.
    * `Surrogates (Broken) (Cs)`: A clear sign of a corrupt copy/paste from a broken UTF-16 pair.
    * `Prop: Deprecated`: A data-driven flag from `PropList.txt` for characters Unicode explicitly deprecates (e.g., `U+0149 ŉ`).
    * `Noncharacter`: `\p{Noncharacter_Code_Point}` code points (e.g., `U+FFFF`).
* **Invisible & Deceptive Flags:**
    * `Bidi Control (UAX #9)`: A granular flag for Bidi-control characters (e.g., `U+202E RLO`) parsed from `PropList.txt`.
    * `Join Control (Structural)`: A granular flag for `U+200D` (ZWJ) and `U+200C` (ZWNJ) parsed from `PropList.txt`.
    * `True Ignorable (Format/Cf)`: A flag for the *remaining* format characters (e.g., `U+200B` ZWSP, `U+2060` WJ) that are not Bidi or Join controls.
    * `Other Default Ignorable`: A data-driven flag for other ignorable characters (a known steganography vector) parsed from `DerivedCoreProperties.txt`.
    * `Deceptive Spaces`: A check for any whitespace (`Zs`) character that is not a standard ASCII space (`U+0020`).
* **Contextual & Steganography Flags:**
    * `Private Use (Co)`: "Black box" characters with no public meaning, often used by fonts for custom glyphs (e.g., "Nerd Fonts") or for steganography.
    * `Variant Base Chars`: Characters that *can be* modified by a variation selector (from `StandardizedVariants.txt`).
    * `Variation Selectors`: Invisible modifiers, now robustly sourced from both `PropList.txt` (for emoji) and `StandardizedVariants.txt` (for non-emoji) to ensure 100% coverage.
    * `Steganography (IVS)`: A specific check for **Ideographic Variation Selectors** (`U+E0100`–`U+E01EF`), a known vector for steganography.
* **Property Flags (Data-Driven):**
    * `Prop: Extender`: Flags characters from `PropList.txt` that modify the shape of others (e.g., `U+00B7 MIDDLE DOT`).
    * `Prop: Dash`: A data-driven flag for all characters with the `Dash` property.
    * `Prop: Quotation Mark`: A data-driven flag for all quotation characters.
    * `Prop: Terminal Punctuation`: A data-driven flag for all terminal punctuation.
* **Identifier Flags (Data-Driven):**
    * `Type: ...`: Flags from `IdentifierType.txt` like `Type: Not_XID` or `Type: Deprecated`.

### Group 2.D: Provenance & Context Profile

This is the "Origin Story" of the atoms. It provides the deep forensic context of *what* the characters are and *where* they come from.

* **`Script:` & `Script-Ext:` (The Script Profile)**
    * This is a sophisticated, two-level analysis. The tool first checks if a character is in **`ScriptExtensions.txt`**.
    * **If YES** (it's a "shared" char like `·`), it adds to all its `Script-Ext:` counters (e.g., `Script-Ext: Latn`, `Script-Ext: Grek`).
    * **If NO** (it's a "simple" char like `a`), it falls back to its primary `Script:` property, which is read directly from **`Scripts.txt`**.
    * This provides a 100% accurate, non-redundant script profile and is a primary detector for homograph attacks.
* **Block: Counters**
    * Fetches `Blocks.txt` to find the "neighborhood" of a character (e.g., `Block: Basic Latin`, `Block: Cyrillic`). A change in this profile is a 100% reliable flag that a cross-script change (like a homograph attack) has occurred.
* **Age: Counters**
    * Fetches `DerivedAge.txt` to show *when* a character was introduced (e.g., `Age: 1.1`, `Age: 15.0`). A key tool for finding modern emoji or symbols.
* **Total Numeric Value:**
    * A powerful, non-obvious profile. It uses `unicodedata.numeric()` to calculate the **actual mathematical sum** of all numeric characters (e.g., `V` + `¼` = `5.25`). Any change to a number, even a "confusable" one, will change this profile.
* **Script Run-Length Analysis**
    * A separate RLE table that provides a "shape" profile of the text's *scripts*. This is a far superior homograph detector than a simple "bag of atoms" count. For example, `paypal` (all Latin) produces a profile of `Script: Latin: 1`. The confusable string `pаypal` (with a Cyrillic 'а') produces a profile of `Script: Latin: 1, Script: Cyrillic: 1, Script: Latin: 1`, instantly flagging the attack.

---

## 💻 Tech Stack

The application is a pure, serverless, single-page web application. The logic is cleanly separated for maintainability.

* **`index.html`**: A single, semantic HTML5 file that defines the "skeleton" of the lab instrument. It uses ARIA roles for all components to ensure full accessibility.
* **`styles.css`**: A single, responsive CSS3 stylesheet that provides the clean, information-dense "lab instrument" aesthetic.
* **`pyscript.toml`**: The PyScript configuration file. It lists the required Python packages (like `pyodide-http`) and, crucially, the list of all **10** Unicode data files to be pre-fetched:
    * `Blocks.txt`
    * `DerivedAge.txt`
    * `IdentifierType.txt`
    * `ScriptExtensions.txt`
    * `StandardizedVariants.txt`
    * `confusables.txt` *(Note: Fetched, but implementation is pending in Group 3)*
    * **`LineBreak.txt`**
    * **`PropList.txt`**
    * **`DerivedCoreProperties.txt`**
    * **`Scripts.txt`**
* **`app.py`**: The Python "brain." This file contains all the application's logic.
    * It imports `unicodedata`, `asyncio`, and `pyfetch`.
    * It defines all computation functions (e.g., `compute_code_point_stats`, `compute_bidi_class_analysis`).
    * It defines all rendering functions (e.g., `render_matrix_table`).
    * It contains the main `update_all` orchestrator.
* **`ui-glue.js`**: The JavaScript "nerves." A lightweight, dependency-free script that manages high-performance, accessibility-driven UI components, such as the ARIA tab controls and the "Copy Report" button logic.
* **Browser-Native APIs:**
    * `RegExp` engine: Used for all high-performance Unicode property classifications (e.g., `\p{L}`, `\p{Script=Cyrillic}`).
    * `Intl.Segmenter` API: Used to perform UAX #29-compliant grapheme cluster segmentation.
* **Deployment:**
    * The site is built from the `main` branch and deployed as a static site using **GitHub Pages**.
* **Analytics (Google):**
    * Google Analytics (GA4) & Google Tag Manager (GTM): For website traffic analysis.
    * Google Consent Mode v2: Implements a "default-deny" state for privacy.

---

## ⚙️ How It Works (The New Architecture)

1.  **On Page Load:**
    * `index.html` and `styles.css` render the static "lab instrument" skeleton.
    * `pyscript.toml` is read by PyScript.
    * `app.py` begins to load and immediately calls `asyncio.ensure_future(load_unicode_data())`.
    * The `load_unicode_data` function uses `pyfetch` to fetch all 10 data files in parallel.
    * As files return, they are parsed into efficient Python data structures (`DATA_STORES`).
    * `ui-glue.js` runs, attaching its event listeners to the "Copy Report" button and the Tab controls.
2.  **On Data Ready:**
    * `load_unicode_data` finishes and updates the `status-line` to "Ready."
3.  **On User Input:**
    * The user types or pastes text into the `<textarea>`.
    * The `input` event triggers the main `update_all` function in `app.py`.
4.  **`update_all` Orchestration:**
    * The `update_all` function executes its main logic, which is a single, sequential pipeline. It gathers all the data for the "Structural Profile."
    * It calls `compute_code_point_stats(t)` to get the logical atom counts.
    * It calls `compute_grapheme_stats(t)` to get the perceptual atom counts.
    * It calls `compute_sequence_stats(t)` (for Major runs) and `compute_minor_sequence_stats(t)` (for Minor runs) to get the "Shape" profile.
    * It calls `compute_linebreak_analysis(t)` and `compute_bidi_class_analysis(t)` to get the UAX #14/9 RLE profiles.
    * It calls `compute_forensic_stats_with_positions(t)` to get all integrity flags.
    * It calls `compute_provenance_stats(t)` to get all script, block, and age data.
    * It calls `compute_script_run_analysis(t)` to get the script RLE profile.
5.  **Render Data:**
    * The results from all `compute` functions are passed to the `render` functions.
    * `render_cards`, `render_parallel_table`, and `render_matrix_table` build HTML strings.
    * These HTML strings are injected into their respective `<tbody>` or `<div>` elements (e.g., `#major-parallel-body`, `#integrity-matrix-body`).
    * The UI updates in a single, efficient paint.

---

## 🚀 Project Status & Roadmap

This project is divided into two major "Groups" of features. Group 2, the primary goal, is functionally complete. Group 3, the secondary goal, is the next major development phase.

### ✅ Completed: The Structural Profile (Group 2)

The primary goal of the application is **100% complete and verified.** The tool successfully generates a deterministic, multi-layered "structural profile" for any pasted text, based on the raw, unaltered (State 1) string. All "roadmap" features from the initial audit have been successfully implemented, debugged, and validated.

Our "facts-first" parallel-analysis architecture is fully implemented:

* **Dual-Atom Profile:** Fully implemented. This includes the "Meta-Analysis" & "Grapheme Structural Integrity" cards, as well as the parallel (Code Point vs. Grapheme) comparison tables for both **7 Major Categories** and **30 Minor Categories**.
* **Structural Shape Profile:** Fully implemented. This module now correctly generates **four** separate, parallel RLE tables, providing a deep fingerprint of the text's "shape":
    1.  **Major Category Run Analysis**
    2.  **Minor Category Run Analysis**
    3.  **UAX #14 Line Break Run Analysis**
    4.  **UAX #9 Bidi Class Run Analysis**
* **Structural Integrity Profile:** Fully implemented. This "Matrix of Facts" has been successfully upgraded from a single, naive flag to a granular, data-driven profile. It now correctly identifies all problematic flags with positions, including:
    * The deconstructed `Cf` flags: **`Bidi Control (UAX #9)`**, **`Join Control (Structural)`**, and **`True Ignorable (Format/Cf)`**.
    * All **`Decomposition_Type`** flags (e.g., `Decomposition: compat`, `Decomposition: font`) using the `unicodedata` library.
    * A robust set of data-driven properties from `PropList.txt` and `DerivedCoreProperties.txt`, including **`Prop: Deprecated`**, **`Prop: Extender`**, `Prop: Dash`, `Other_Default_Ignorable_Code_Point`, etc.
    * The **`Variation Selectors`** flag is now **100% bug-free**, correctly sourcing data from both `StandardizedVariants.txt` (for non-emoji) and `PropList.txt` (for emoji selectors).
* **Provenance & Context Profile:** Fully implemented. This matrix correctly calculates and displays all **Script**, **Block**, **Age**, and **Numeric** properties from 100% data-driven sources (including `Scripts.txt`). It also now includes the powerful **`Script Run-Length Analysis`** table as a primary homograph detector.

### ▶️ Next Steps (The New "World-Class" Roadmap)

With the "Structural Profile" (Group 2) complete, the next development phase will focus on enhancing this profile with deeper segmentation, fixing the final `Variant Base Chars` gap, and finally beginning the implementation of Group 3.

#### Task 1: Complete the "Variant" Sub-Module
* **Goal:** Fix the `Variant Base Chars` flag for emoji, which is the last remaining gap in the Group 2 profile.
* **Plan:** We will load **`emoji/emoji-variation-sequences.txt`** (a new file). We will write a new, simple parser for it that extracts the *base characters* (like `U+2602 ☂`) and adds them to the existing `DATA_STORES["VariantBase"]` set. This will cause the `Variant Base Chars` flag to light up for emoji, completing the feature.

#### Task 2: Expand the "RLE Engine" (UAX #29)
* **Goal:** Apply our successful Run-Length Encoding (RLE) engine to the Word and Sentence boundary properties defined in UAX #29.
* **Plan:** We will load **`auxiliary/WordBreakProperty.txt`** and **`auxiliary/SentenceBreakProperty.txt`**. We will then create two new RLE computation functions (`compute_wordbreak_analysis`, `compute_sentencebreak_analysis`) and add two new tables ("Word Break Run Analysis" and "Sentence Break Run Analysis") to the "Structural Shape" profile, providing the final layer of structural fingerprinting.

#### Task 3: Add "Linter" Flag (DoNotEmit)
* **Goal:** Add a new, data-driven forensic flag for "discouraged" characters.
* **Plan:** We will load **`DoNotEmit.txt`**. We will write a new parser that applies the 80/20 rule: it will parse all single characters and ranges, but *ignore* complex sequences. We will then add a new flag, **`Prop: Discouraged (DoNotEmit)`**, to the "Structural Integrity" module.

#### Task 4: Implement "Threat-Hunting Analysis" (Group 3)
* **Goal:** Begin the final, major development phase: the "Threat-Hunting" module, which analyzes text using States 2 and 3 of our Normalization Pipeline.
* **Plan:**
    * **Algorithmic Detection:** We will load `confusables.txt` (which we already fetch) and implement the **`UTS #39` skeleton algorithm**. This will be our *dictionary-based* homograph detector. We will also implement the `UTS #39` "mixed-script" algorithm.
    * **New "Tri-State" Hashes:** We will generate *four* hashes to be displayed: `Raw`, `NFKC`, `NFKC-Casefold` (to show its failure), and the new **`UTS #39 Skeleton`** (to show its success).
    * **The "Defensive UI":** We will discard any old "diff" plans and implement a modern, three-layer defensive UI:
        1.  **Layer 1 (Highlight):** Render confusable characters with an in-line highlight and invisible characters as a visible glyph (e.g., `[ZWSP]`).
        2.  **Layer 2 (Tooltip):** On hover, show a tooltip explaining the "Perception vs. Reality" (e.g., "Appears as: 'p', Actual: 'Cyrillic er'").
        3.  **Layer 3 (Banner):** For *critical* threats like a `Bidi Control (Malicious)` flag, display a prominent, Gmail-style warning banner.

---

## 🔒 Privacy-First Design

This tool is **privacy-first**.
* **No Server:** All analysis, including the "deep scan" modules, runs 100% in *your* browser. The text you paste is **never** sent to a server.
* **No Analytics (by Default):** The application implements Google's Consent Mode v2. All analytics and ad tracking are **disabled by default** (set to 'denied') to ensure user privacy. Because there is no consent banner to "accept" tracking, this state is permanent.
