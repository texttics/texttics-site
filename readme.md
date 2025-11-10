# Text...tics: A Deterministic Structural Profiler & Integrity Analyzer

## What is Text...tics?

This is a single-page web application that functions as a real-time, deterministic text analyzer. It is a highly specialized, browser-based "lab instrument" designed to give a literal, precise, and unfiltered view of any text string's internal structure and integrity.

Its primary goal is to function as a **"Structural Profiler"**—a tool that generates a complete, absolute, and unambiguous statistical signature, or "profile," for any text. This profile serves as a ground-truth baseline, allowing for the verifiable detection of any structural change.

Its secondary, but equally important, goal is to serve as a **"Structural Integrity Analyzer."** It uses its detailed profile to detect and flag anomalies, deceptions, and "inter-layer mismatch attacks" that are designed to deceive human perception. It finds the invisible, ambiguous, or malicious characters (e.g., homoglyphs, invisible format controls, bidirectional overrides) that successfully survive the common copy/paste process.

## The Architectural Model: A Hybrid, Serverless Powerhouse

The entire application runs 100% in the user's browser, requiring no server-side backend. It operates on a powerful, serverless, hybrid model that leverages the best of two different environments: the high-speed JavaScript engine and the deep-analysis Python runtime (via PyScript).

### 1. The JavaScript Layer (High-Speed Standards Parsing)

This layer uses the browser's native, JIT-compiled JavaScript engines (like Google's V8 or Mozilla's SpiderMonkey). These engines are written in high-performance C++ and are the "world-class" standard for executing high-frequency, standards-compliant operations at native speed. We delegate two critical tasks to this layer:

* **Unicode Property Classification:** All 30 minor category checks (e.g., `\p{Lu}`, `\p{Po}`) and dozens of property checks (e.g., `\p{Emoji_Presentation}`, `\p{White_Space}`) are handled by the browser's `RegExp` engine. This is the fastest possible way to classify millions of code points per second.
* **Grapheme Cluster Segmentation:** The "perceptual" analysis is powered by the native `Intl.Segmenter` API. This is the browser's built-in implementation of **Unicode Standard Annex #29 (UAX #29)**, the official rulebook for determining "what counts as a single character" to a human user.

### 2. The Python Layer (Orchestration & Deep Analysis)

This layer runs a full Python 3.12 runtime in the browser via PyScript. Python acts as the application's "brain" or "chief orchestrator." It is used for lower-frequency, "heavy-lifting" tasks that require deep, data-driven logic that JavaScript alone cannot provide.

* **State Management & Orchestration:** The main `update_all` function in `app.py` manages the entire application state and analysis pipeline.
* **Deep Unicode Analysis:** It uses the rich `unicodedata` library for complex operations (like `unicodedata.numeric()` or `unicodedata.category()`) that are not available in JavaScript.
* **Data-Driven Analysis (The Core):** Python asynchronously fetches, parses, and analyzes raw data files from the Unicode Character Database (UCD). This data-driven approach is what gives the tool its "world-class" analytical depth, allowing it to perform checks that are impossible with regular expressions alone. The data files currently implemented include:
    * **`Blocks.txt`**: To determine a character's "neighborhood" (e.g., "Basic Latin," "Cyrillic," "Greek and Coptic").
    * **`DerivedAge.txt`**: To determine *when* a character was introduced to the Unicode standard (e.g., "1.1," "15.0").
    * **`ScriptExtensions.txt`**: For the advanced, "dual-logic" script analysis.
    * **`IdentifierType.txt`**: To find flags like `Not_XID` or `Default_Ignorable` based on the UAX #31 "Identifier" standard.
    * **`StandardizedVariants.txt`**: To detect invisible variation selectors (like `U+FE0F`) and their base characters.

The final result is a multi-layered, literal, and data-driven analysis of text composition, sequence (run) shape, structural integrity, and deep provenance, all based on the official Unicode Standard.

---

## 🔬 Core Philosophy: A "Post-Clipboard" Structural Integrity Analyzer

### What is a "Post-Clipboard" Analyzer?

The design of this tool is the result of a specific, critical scoping decision. It is a **"Post-Clipboard Structural Integrity Analyzer."**

This means its primary mission is to analyze the structural integrity of a decoded string *exactly as it exists* after being copied from an external source (like a website, email, or document) and pasted (Ctrl+V) into the browser's `<textarea>`.

This "post-clipboard" scope is a core feature, not a limitation.

### The "Great Standardizer": A Core Feature, Not a Limitation

The operating system's clipboard and the browser's "paste" event are a powerful, standards-compliant security boundary. We call this boundary the **"Great Standardizer."**

By the time the text appears in our input box, the browser's strict, hardened rendering and paste engine has *already* performed a massive, free sanitization and pre-analysis for us:

1.  **Byte-Level Interpretation:** The browser has already interpreted the raw bytes from the clipboard, using a (guessed) encoding (e.g., UTF-8, Windows-1252, etc.).
2.  **Decoding:** It has decoded that byte stream into a standardized, internal JavaScript string (typically UTF-16).
3.  **Sanitization & Rejection:** This is the most critical step. The browser's engine has *already* strictly rejected or replaced any invalid, malformed, or corrupt byte-level data. This includes:
    * **Overlong UTF-8 sequences** (a classic security filter bypass).
    * **Lone Surrogates** (remnants of broken UTF-16 pairs).
    * **Invalid byte sequences** (e.g., `0xFF`).
    * In all these cases, the browser's modern, security-first engine will have **replaced** the offending data with the Unicode Replacement Character (``, `U+FFFD`), providing an immediate, unambiguous flag of data corruption *before* our tool even runs.

### Defining Our Analytical Boundary (What This Tool IS NOT)

This "Great Standardizer" process allows our tool to focus 100% on its primary mission: analyzing the *structural integrity of the resulting, decoded string*. This is a critical distinction that separates our tool from others.

This tool **intentionally excludes** a whole class of "raw file" analysis. It **does not**:

* **Analyze raw bytes.** That is the job of a hex editor (like HxD or 010 Editor). Our tool does not show you `0xFE 0xFF`.
* **Perform encoding guessing.** That is the job of a library like `charset-normalizer`. Our tool trusts the browser's guess.
* **Detect byte-level corruption.** The browser has already detected this and replaced it with ``.

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
    * **Example:** The string `👨‍👩‍👧‍👦` (Family emoji) is correctly identified at this layer as **7 distinct logical atoms**:
        1.  `U+1F468` (Man)
        2.  `U+200D` (Zero Width Joiner)
        3.  `U+1F469` (Woman)
        4.  `U+200D` (Zero Width Joiner)
        5.  `U+1F467` (Girl)
        6.  `U+200D` (Zero Width Joiner)
        7.  `U+1F466` (Boy)

* **Atom 2: The Grapheme Cluster (Perceptual Atom)**
    * **What it is:** This is the "user-facing," perceptual atom. It is the "human's-eye-view" of the text. This is the "character" that a human user "sees," clicks on, or selects.
    * **Tooling:** This layer is analyzed using the browser's native `Intl.Segmenter`, which implements **Unicode Standard Annex #29 (UAX #29)**—the official Unicode rulebook for "Grapheme Cluster Boundaries."
    * **Forensic Value:** This layer's entire purpose is to *contrast* with the Code Point layer. It correctly identifies `👨‍👩‍👧‍👦` as **1 single perceptual atom,** just as a user would.
    * **The Mismatch:** The tool's core power comes from this built-in, parallel comparison. The user can instantly see the mismatch (**Total Code Points: 7** vs. **Total Graphemes: 1**) and immediately prove that invisible structural characters (the Zero Width Joiners) are present.

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

This is the "Structural Arrangement" of the string—the **how**. It analyzes the text as a *sequence* of runs, not just a "bag of atoms."

* **Why it's a profile:** A simple "bag of atoms" diff won't see a structural change. This module will. The string `"don't"` produces a Major Run profile of **L-P-L** (Letter, Punctuation, Letter) and has `3` runs. The "fixed" string `"dont"` produces a profile of **L** and has `1` run. This change in the run-count is a deterministic flag of a structural edit.
* **Features:** This module contains two parallel Run-Length Encoding (RLE) analyses:
    * **Major Category Run Analysis Table:** A matrix that counts the uninterrupted runs of characters belonging to the **7 Major Categories** (`L`, `P`, `N`, etc.).
    * **Minor Category Run Analysis Table:** A deeper matrix that counts the uninterrupted runs of the **30 Minor Categories**. This is a far more granular profile. For example, the Major Run profile for `a.a` (Ll-Po-Ll) and `a'a` (Ll-Pf-Ll) is identical (`L-P-L`). But the Minor Run profile is different (`Ll: 2, Po: 1` vs. `Ll: 2, Pf: 1`), providing a definitive signature of the structural change.

### Group 2.C: Structural Integrity Profile

This is the "Flag" report. It provides a detailed, non-judgmental list of all "problematic," invisible, or modifying atoms found in the string. It is a "matrix of facts" that reports both the **Count** and the **Positions** (indices) of each flag. This list is the result of deep, data-driven analysis.

* **Corruption Flags:**
    * `Unassigned (Void) (Cn)`: Code points with no meaning. A vector for "future-tense" exploits.
    * `Surrogates (Broken) (Cs)`: A clear sign of a corrupt copy/paste from a broken UTF-16 pair.
    * `Deprecated`: `\p{Deprecated}` characters.
    * `Noncharacter`: `\p{Noncharacter_Code_Point}` code points (e.g., `U+FFFF`).
* **Invisible & Deceptive Flags:**
    * `Ignorables (Format/Cf)`: A robust, Python-based `unicodedata.category == 'Cf'` check that finds *all* format characters, including `U+200B` (Zero Width Space), `U+2060` (Word Joiner), and all Bidi control characters (e.g., `U+2067` RLI). *[Note: This will be deconstructed in our new roadmap].*
    * `Deceptive Spaces`: A `RegExp` check (`[\p{White_Space}&&[^ \n\r\t]]`) for any whitespace atom that is *not* a standard space, tab, or newline (e.g., `U+200A` Hair Space).
* **Contextual & Steganography Flags:**
    * `Private Use (Co)`: "Black box" characters with no public meaning, often used by fonts for custom glyphs (e.g., "Nerd Fonts") or for steganography.
    * `Variant Base Chars`: Characters that *can be* modified by a variation selector.
    * `Variation Selectors`: The invisible modifiers themselves (e.g., `U+FE0F` for emoji).
    * `Steganography (IVS)`: A specific check for **Ideographic Variation Selectors** (`U+E0100`–`U+E01EF`), a known vector for steganography.
* **Identifier Flags (Data-Driven):**
    * `Type: ...`: Flags from `IdentifierType.txt`. This replaces old, unreliable `RegExp` checks.
    * `Type: Not_XID`: Flags characters that are disallowed in identifiers.
    * `Type: Default_Ignorable`: A data-driven confirmation of ignorable characters.

### Group 2.D: Provenance & Context Profile

This is the "Origin Story" of the atoms. It provides the deep forensic context of *what* the characters are and *where* they come from.

* **`Script:` & `Script-Ext:` (The Script Profile)**
    * This is a sophisticated, two-level analysis. The tool first checks if a character is in **`ScriptExtensions.txt`**.
    * **If YES** (it's a "shared" char like `·`), it adds to all its `Script-Ext:` counters (e.g., `Script-Ext: Latn`, `Script-Ext: Grek`).
    * **If NO** (it's a "simple" char like `a`), it falls back to its primary `Script:` property (e.g., `Script: Latin`).
    * This provides a 100% accurate, non-redundant script profile and is a primary detector for homograph attacks.
* **Block: Counters**
    * Fetches `Blocks.txt` to find the "neighborhood" of a character (e.g., `Block: Basic Latin`, `Block: Cyrillic`). A change in this profile is a 100% reliable flag that a cross-script change (like a homograph attack) has occurred.
* **Age: Counters**
    * Fetches `DerivedAge.txt` to show *when* a character was introduced (e.g., `Age: 1.1`, `Age: 15.0`). A key tool for finding modern emoji or symbols.
* **Total Numeric Value:**
    * A powerful, non-obvious profile. It uses `unicodedata.numeric()` to calculate the **actual mathematical sum** of all numeric characters (e.g., `V` + `¼` = `5.25`). Any change to a number, even a "confusable" one, will change this profile.
* **UAX #44 Properties:**
    * High-speed `RegExp` properties like `Alphabetic` / `Dash`.

---

## 💻 Tech Stack

The application is a pure, serverless, single-page web application. The logic is cleanly separated for maintainability.

* **`index.html`**: A single, semantic HTML5 file that defines the "skeleton" of the lab instrument. It uses ARIA roles for all components to ensure full accessibility.
* **`styles.css`**: A single, responsive CSS3 stylesheet that provides the clean, information-dense "lab instrument" aesthetic.
* **`pyscript.toml`**: The PyScript configuration file. It lists the required Python packages (like `pyodide-http`) and, crucially, the list of all Unicode data files to be pre-fetched:
    * `Blocks.txt`
    * `DerivedAge.txt`
    * `IdentifierType.txt`
    * `ScriptExtensions.txt`
    * `StandardizedVariants.txt`
    * `confusables.txt` *(Note: Fetched, but implementation is pending in Group 3)*
* **`app.py`**: The Python "brain." This file contains all the application's logic.
    * It imports `unicodedata`, `asyncio`, and `pyfetch`.
    * It defines all computation functions (e.g., `compute_code_point_stats`, `compute_minor_sequence_stats`).
    * It defines all rendering functions (e.g., `render_matrix_table`).
    * It contains the main `update_all` orchestrator.
* **`ui-glue.js`**: The JavaScript "nerves." A lightweight, dependency-free script that manages high-performance, accessibility-driven UI components, such as the ARIA tab controls and the "Copy Report" button logic.
* **Browser-Native APIs:**
    * `RegExp` engine: Used for all high-performance Unicode property classifications (e.g., `\p{L}`, `\p{Script=Cyrillic}`).
    * `Intl.Segmenter` API: Used to perform UAX #29-compliant grapheme cluster segmentation.
* **Analytics (Google):**
    * Google Analytics (GA4) & Google Tag Manager (GTM): For website traffic analysis.
    * Google Consent Mode v2: Implements a "default-deny" state for privacy.

---

## ⚙️ How It Works (The New Architecture)

1.  **On Page Load:**
    * `index.html` and `styles.css` render the static "lab instrument" skeleton.
    * `pyscript.toml` is read by PyScript.
    * `app.py` begins to load and immediately calls `asyncio.ensure_future(load_unicode_data())`.
    * The `load_unicode_data` function uses `pyfetch` to fetch all data files (`Blocks.txt`, `ScriptExtensions.txt`, etc.) in parallel.
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
    * It calls `compute_forensic_stats_with_positions(t)` to get all integrity flags.
    * It calls `compute_provenance_stats(t)` to get all script, block, and age data.
    * *(Note: This pipeline will be expanded with our new planned functions like `compute_linebreak_analysis(t)`).*
5.  **Render Data:**
    * The results from all `compute` functions are passed to the `render` functions.
    * `render_cards`, `render_parallel_table`, and `render_matrix_table` build HTML strings.
    * These HTML strings are injected into their respective `<tbody>` or `<div>` elements (e.g., `#major-parallel-body`, `#integrity-matrix-body`).
    * The UI updates in a single, efficient paint.

---

## 🚀 Project Status & Roadmap

This project is divided into two major "Groups" of features. Group 2, the primary goal, is functionally complete. Group 3, the secondary goal, is the next major development phase.

### ✅ Completed: The Structural Profile (Group 2)

The primary goal of the application is **100% complete and verified.** The tool successfully generates a deterministic, multi-layered "structural profile" for any pasted text, based on the raw, unaltered (State 1) string.

Our "facts-first" parallel-analysis architecture is fully implemented:

* **Dual-Atom Profile:** Fully implemented. This includes the "Meta-Analysis" & "Grapheme Structural Integrity" cards, as well as the parallel (Code Point vs. Grapheme) comparison tables for both **7 Major Categories** and **30 Minor Categories**.
* **Structural Shape Profile:** Fully implemented. This module correctly generates two separate, parallel tables for:
    1.  **Major Category Run Analysis** (e.g., `L-Run: 3`)
    2.  **Minor Category Run Analysis** (e.g., `Lu-Run: 1`, `Ll-Run: 2`).
* **Structural Integrity Profile:** Fully implemented. This "Matrix of Facts" correctly identifies all problematic flags (like Ignorables, Private Use, Deceptive Spaces, Variation Selectors, and **Steganography (IVS)**) and lists their exact **Positions**.
* **Provenance & Context Profile:** Fully implemented. This matrix correctly calculates and displays all **Script**, **Block**, **Age**, and **Numeric** properties. The advanced, "dual-logic" **`ScriptExtensions.txt`** parser is fully integrated and verified.

### ▶️ Next Steps (The New "World-Class" Roadmap)

Our roadmap has been updated based on a deep, critical audit of "world-class" Unicode standards (UAX #9, #14, #39). The next steps involve enhancing our "Structural Profile" with these new algorithmic analyses, followed by implementing the "Threat-Hunting" module using a standards-compliant pipeline.

#### Task 1: Implement "Granularity & Precision" (Group 2 Enhancements)

This task involves upgrading our existing "Structural Integrity Profile" to be more precise and to fix the "naive lumping" of flags, as identified by our audit.

* **Sub-Task 1.A: Deconstruct the `Cf` (Ignorables) Flag:**
    * **Goal:** Fix the "single greatest weakness" in our profile. We will replace the single `Ignorables (Format/Cf)` flag with a granular breakdown.
    * **Plan:** We will load `PropList.txt` and modify `compute_forensic_stats_with_positions` to check for data-driven properties *first*, splitting the `Cf` category into:
        1.  `Bidi Control (UAX #9)` (via `PropList.txt`)
        2.  `Join Control (Structural)` (via `PropList.txt`)
        3.  `True Ignorable (Format/Cf)` (the remaining `Cf` characters)
* **Sub-Task 1.B: Add `Decomposition_Type` Flags:**
    * **Goal:** Show *why* a grapheme is complex and *why* it will be changed by NFKC.
    * **Plan:** We will use the built-in `unicodedata.decomposition(char)` function. If a decomposition starts with `<...>` (e.g., `<compat>`, `<font>`), we will add a new flag (e.g., `Decomposition: compat`) to the "Structural Integrity Profile."
* **Sub-Task 1.C: Add Remaining Data-Driven Properties:**
    * **Goal:** Complete the profile with other key binary properties from the UCD.
    * **Plan:** We will load `PropList.txt` and `DerivedCoreProperties.txt` to add new flags for:
        * `White_Space` (the definitive, data-driven version)
        * `Extender` (flags shape-modifying characters)
        * `Other_Default_Ignorable_Code_Point` (a steganography vector)

#### Task 2: Implement "Missing Algorithms" (Group 2 Enhancements)

This task involves applying our powerful "Run-Length Encoding" (RLE) engine to the two remaining "critical gap" standards, `UAX #9` and `UAX #14`.

* **Sub-Task 2.A: Implement `UAX #14` (Line Breaking Properties):**
    * **Goal:** To fix the "Deceptive Newline" blind spot.
    * **Plan:** We will load `LineBreak.txt` into `DATA_STORES`. We will create a new RLE function, `compute_linebreak_analysis(t)`, that uses the `Line_Break` property (e.g., `AL`, `BK`, `LS`, `CR`) as its "state." This will create a new "Line Break Run Analysis" table, flagging invisible newlines like `U+2028` (LS).
* **Sub-Task 2.B: Implement `UAX #9` (Bidirectional Algorithm) Foundation:**
    * **Goal:** To fix the "Trojan Source" blind spot foundation.
    * **Plan:** We will create a new RLE function, `compute_bidi_class_analysis(t)`. It will use `unicodedata.bidirectional(char)` (e.g., `L`, `R`, `RLO`, `LRI`) as its "state." This will create a new "Bidi Class Run Analysis" table, providing the core structural fingerprint for Bidi analysis.

#### Task 3: Implement "Threat-Hunting Analysis" (Group 3)

This is the final, major development phase. We will **discard our old, flawed "Tri-State Hashing" plan** and replace it with the "best-in-class," 4-stage pipeline identified by our audit.

* **Stage 1 (Invisible Detection):** We will build this logic as part of **Task 1** (Deconstructing the `Cf` flag).
* **Stage 2 (Safe Normalization):** The `compute_threat_analysis` function will safely generate the `NFKC` and `NFKC-Casefold` strings *after* Stage 1 analysis.
* **Stage 3 (Algorithmic Detection):** This is the core of Group 3.
    * **Mixed-Script Detection:** We will implement the `UTS #39` algorithm for detecting high-risk script mixes (e.g., `{"Latin", "Cyrillic"}`). This will be our *algorithmic* homograph detector.
    * **`UTS #39` Skeleton Algorithm:** We will load `confusables.txt` (which we already fetch) and implement the *correct* `UTS #39` skeleton algorithm. This will be our *dictionary-based* homograph detector.
    * **New "Tri-State" Hashes:** We will generate *four* hashes to be displayed: `Raw`, `NFKC`, `NFKC-Casefold` (to show its failure), and the new **`UTS #39 Skeleton`** (to show its success).
* **Stage 4 (The "Defensive UI"):** We will **discard the "skeleton diff" UI**.
    * **Layer 1 (Highlight):** We will implement logic to render confusable characters with an in-line highlight (like a spell-checker) and invisible characters as a visible glyph (e.g., `[ZWSP]`).
    * **Layer 2 (Tooltip):** On hover, this UI will show a tooltip explaining the "Perception vs. Reality" (e.g., "Appears as: 'p', Actual: 'Cyrillic er'").
    * **Layer 3 (Banner):** For *critical* threats like a `Bidi Control (Malicious)` flag, we will display a prominent, Gmail-style warning banner at the top of the section.

---


---

## 🔒 Privacy-First Design

This tool is **privacy-first**.
* **No Server:** All analysis, including the "deep scan" modules, runs 100% in *your* browser. The text you paste is **never** sent to a server.
* **No Analytics (by Default):** The application implements Google's Consent Mode v2. All analytics and ad tracking are **disabled by default** (set to 'denied') to ensure user privacy. Because there is no consent banner to "accept" tracking, this state is permanent.
