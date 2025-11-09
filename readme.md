# Text...tics: A Deterministic Structural Fingerprinter

This is a single-page web application that functions as a real-time, **deterministic** text analyzer. Its primary goal is to be a **"Structural Fingerprinter"**—a tool that generates a complete, absolute, and unambiguous statistical signature for any text.

Its secondary, but equally important, goal is to use this "fingerprint" to detect forensic anomalies and **"inter-layer mismatch attacks"** (e.g., homoglyphs, invisible characters, Bidi controls) that survive the copy/paste process.

It is a **Post-Clipboard Forensic Analyzer** designed to give a literal, precise, and unfiltered view of the *structural integrity* of a decoded string.

It runs 100% in the browser using **PyScript** to execute Python 3.12, leveraging a high-performance, serverless, hybrid model:

* **Python (Orchestration & Deep Analysis):** Manages all application state, event handling, and DOM rendering. It uses the `unicodedata` library for deep analysis and asynchronously fetches raw Unicode data files (`Blocks.txt`, `ScriptExtensions.txt`, etc.) to perform data-driven analysis that is impossible with regular expressions alone.
* **JavaScript (High-Speed Standards Parsing):** Leverages the browser's native JavaScript engines for all high-performance, standards-compliant parsing. This includes the `RegExp` engine (for all `\p{...}` Unicode property checks) and the `Intl.Segmenter` API (for UAX #29 Grapheme Cluster segmentation).

The result is a multi-layered, *literal* analysis of text composition, sequence (run) shape, script properties, and hidden forensic flags, all based on the official **Unicode Standard**.

---

## 🔬 Core Philosophy: A "Post-Clipboard" Structural Fingerprinter

This tool is a **"Post-Clipboard Forensic Analyzer"** and, primarily, a **"Structural Fingerprinter."**

Its **main goal** is to create a **complete, deterministic, and absolute structural fingerprint** of any text. It is designed to analyze the *structural integrity* of a decoded string exactly as it exists after being copied (Ctrl+C) and pasted (Ctrl+V) into the browser.

This "fingerprint"—the full set of statistics across all sections—provides an **unambiguous structural signature** of the text. It is the "ground truth." By generating a fingerprint for a 'v1' (original) and 'v2' (modified) of a document, you can deterministically identify *any* change, no matter how slight.

A single, tiny change—like replacing a Latin 'a' with a Cyrillic 'а', or adding one Zero-Width Space—will cause a **verifiable and quantifiable change** in the fingerprint (e.g., in the `Script-Ext: Cyrl` counter or the `Forensic Integrity` flags). This allows you to find the "slightest changes" that a simple line-by-line 'diff' tool, or even the human eye, could never see.

### The "Great Standardizer": A Core Feature

This "post-clipboard" scope is a **core feature, not a limitation.** The operating system's clipboard and the browser's "paste" event act as the **"Great Standardizer."**

By the time the text appears in the input box, the browser's strict, standards-compliant engine has *already*:
1.  Interpreted the raw bytes using a (guessed) encoding (e.g., UTF-8, Windows-1252).
2.  Decoded the text into a standard, internal JavaScript string (typically UTF-16).
3.  Strictly rejected or replaced any invalid byte-level corruption (like overlong UTF-8 sequences or lone surrogates).

This process allows the tool to focus 100% on its primary mission and **intentionally excludes** a whole class of "raw file" analysis. This tool **does not**:

* Analyze raw bytes.
* Perform encoding guessing (like `charset-normalizer`).
* Detect overlong UTF-8 sequences or other byte-level corruption.

These tasks are considered "pre-analysis" and are brilliantly handled by the browser *before* our tool ever receives the text. We analyze the *result* of that process, not the process itself.

### Our Focus: Fingerprinting First, Threat-Hunting Second

This tool's philosophy is built on a clear order of operations:

* **IT IS:** A **Post-Clipboard** analyzer that forensically examines the *structural integrity* of a decoded string.
* **IT IS NOT:** A **raw file analyzer** or **byte-level parser**. It analyzes the string *after* the browser's "Great Standardizer" has already decoded it.
* **ITS MAIN GOAL IS:** To be a **Structural Fingerprinter.** It provides the absolute, deterministic data needed to find *any* structural deviation between text versions.
* **ITS ADDITIONAL GOAL IS:** To use this fingerprint to detect **inter-layer mismatch attacks** (like homoglyphs, invisible characters, and Bidi controls) that successfully survive the copy/paste process.

---

## 🧭 Guiding Principles & Forensic Models

The entire application is built on two core forensic models that allow it to analyze the *structural integrity* of text.

### 1. The "Dual-Atom" Analysis Model (The "What")

This tool's architecture is built on the "Dual-Atom" model, which states that any text string is composed of two different "atoms" simultaneously. The "inter-layer mismatch" between these two atoms is the primary vector for structural attacks.

Our UI **does not use a toggle** to switch between these atoms. Instead, it presents the analysis of both layers in **parallel**, providing an immediate, at-a-glance view of any mismatches.

* **Atom 1: The Code Point (Logical Atom)**
    * **What it is:** The foundational, logical atom. This is the "raw" sequence of Unicode numbers (e.g., `U+0041`) that a database, parser, or compiler "sees."
    * **Forensic Value:** This is the *only* atom that can detect invisible deceptions. A Zero-Width Space (`U+200B`) is a full-fledged atom at this layer, as are Bidi control characters. The string `👨‍👩‍👧‍👦` is correctly identified as **7 distinct logical atoms** (`👨` + `ZWJ` + `👩` + `ZWJ` + `👧` + `ZWJ` + `👦`).

* **Atom 2: The Grapheme Cluster (Perceptual Atom)**
    * **What it is:** The "user-facing," perceptual atom. This is the "character" that a human user "sees" and interacts with.
    * **Tooling:** This layer is analyzed using the browser's native `Intl.Segmenter` (which implements Unicode Standard Annex #29, or **UAX #29**).
    * **Forensic Value:** This layer's entire purpose is to *contrast* with the Code Point layer. It correctly identifies `👨‍👩‍👧‍👦` as **1 single perceptual atom**, just as a user would.

The tool's core forensic power comes from this built-in, parallel comparison. The user can instantly see the mismatch (`Total Code Points: 7` vs. `Total Graphemes: 1`) and immediately prove that invisible structural characters (`ZWJ`) are present.

### 2. The "Tri-State" Normalization Pipeline (The "How")

This tool uses a powerful **Tri-State Normalization Pipeline** to generate its fingerprint and (in the future) unmask threats. The entire "Structural Fingerprint" (Group 2) operates *only* on State 1 to preserve evidence. The "Threat-Hunting Analysis" (Group 3) will *intentionally* use States 2 and 3 to unmask deceptions.

* **State 1: Forensic State (Raw String)**
    * **Algorithm:** No normalization. This is the raw, unaltered text as it was pasted.
    * **Purpose:** **Preserves 100% of evidence.** This is the *only* state that can see the physical difference between a pre-composed `é` (`U+00E9`) and a decomposed `e`+`´` (`U+0065` `U+0301`). It's the only state that sees compatibility characters (like `ﬁ`) and case differences.
    * **Used By:** **The entire "Structural Fingerprint" (Group 2).** All core forensic fingerprinting is done on the raw, unaltered data.

* **State 2: Compatibility State (NFKC)**
    * **Algorithm:** `unicodedata.normalize('NFKC', string)`
    * **Purpose:** **Reveals compatibility spoofing.** This state *intentionally destroys* compatibility evidence to unmask attacks. It canonicalizes *and* compat-decomposes.
    * **Example:** The ligature `ﬁ` (`U+FB01`) is "destroyed" and becomes its two-character equivalent `f` + `i`. A single, full-width `１` (`U+FF11`) becomes a standard `1`.
    * **Used By:** **Threat-Hunting Analysis (Group 3).**

* **State 3: Canonical Identity State (NFKC Casefold)**
    * **Algorithm:** `unicodedata.normalize('NFKC', string).casefold()`
    * **Purpose:** **Reveals case-based spoofing.** This is the ultimate "skeleton." It destroys all compatibility *and* case evidence to create the ultimate canonical fingerprint for comparison. It is the most aggressive normalization specified by the Unicode standard.
    * **Example:** `PayPal` becomes `paypal`. A Greek `Σ` becomes `σ`.
    * **Used By:** **Threat-Hunting Analysis (Group 3).**

---

## 🏛️ Anatomy of the "Lab Instrument" (The Fingerprint)

The UI is not a flat list of modules but a hierarchical "lab bench" that presents the full fingerprint in a logical, facts-first order. It consists of a sticky navigation list and a main content feed broken into the following anchored sections.

### Group 1: Analysis Configuration
This is the "Control Plane" for the instrument.
* **Text Input:** The main `<textarea>` that receives the "post-clipboard" string.
* **"Copy Report" Button:** A utility to copy the *entire* structured fingerprint to the clipboard as a human-readable, timestamped text report.

### Group 2.A: Dual-Atom Fingerprint
This is the "Atomic Count" of the string—the *what*. It provides the core parallel analysis of "Logical" (Code Point) vs. "Perceptual" (Grapheme) atoms.

* **Meta-Analysis (Cards):** The highest-level counts.
    * `Total Code Points`: The total number of logical atoms.
    * `Total Graphemes`: The total number of perceptual atoms.
    * `Whitespace (Total)`: Total `\p{White_Space}` characters.
    * `RGI Emoji Sequences`: Total `\p{Emoji_Presentation}` sequences.
* **Grapheme Structural Integrity (Cards):** A "Zalgo-detector" that analyzes the *physical structure* of the graphemes themselves.
    * `Single-Code-Point`: "Simple" graphemes (e.g., `a`).
    * `Multi-Code-Point`: "Complex" graphemes (e.g., `e`+`´` or `👨‍👩‍👧‍👦`).
    * `Total Combining Marks`: Total `\p{M}` marks found.
    * `Max Marks in one Grapheme`: The "Zalgo" score (e.g., `H̊̇ëļļo̧` would have a high score).
* **Parallel Comparison Tables (Tabs):**
    * **Overview Tab:** A side-by-side table comparing the Code Point vs. Grapheme counts for the **7 Major Categories** (Letter, Number, Punctuation, etc.).
    * **Full Breakdown (30) Tab:** A side-by-side table comparing the Code Point vs. Grapheme counts for all **30 Minor Categories** (`Lu`, `Ll`, `Nd`, `Po`, `Cf`, etc.).

### Group 2.B: Structural Shape Fingerprint
This is the "Structural Arrangement" of the string—the *how*. It analyzes the text as a *sequence* of runs, not just a "bag of atoms."

* **Why it's a fingerprint:** A simple `diff` tool won't see a structural change. This module will. The string `"don't"` produces a Major Run fingerprint of `L-P-L` (Letter, Punctuation, Letter) and has **3** runs. The "fixed" string `"dont"` produces a fingerprint of `L` and has **1** run. This change in the run-count is a deterministic flag of a structural edit.
* **Features:**
    * **Sequence (Run) Analysis Table:** A matrix that counts the uninterrupted runs of characters belonging to the **7 Major Categories**.
    * *(See Roadmap for Minor Category runs)*.

### Group 2.C: Forensic Integrity Fingerprint
This is the "Flag" report. It provides a detailed, non-judgmental list of all "problematic," invisible, or modifying atoms found in the string. It is a "matrix of facts" that reports both the `Count` and the `Positions` (indices) of each flag.

* **Corruption Flags:**
    * `Unassigned (Void) (Cn)`: Code points that have not been assigned a meaning by Unicode. A key vector for "future-tense" exploits.
    * `Surrogates (Broken) (Cs)`: Remnants of a broken `UTF-16` pair. A clear sign of a corrupt copy/paste.
    * `Deprecated`: `\p{Deprecated}` characters explicitly removed from the standard.
    * `Noncharacter`: `\p{Noncharacter_Code_Point}` code points explicitly defined as illegal (e.g., `U+FFFF`).
* **Invisible & Deceptive Flags:**
    * `Ignorables (Format/Cf)`: A robust, Python-based `unicodedata.category == 'Cf'` check that finds *all* format characters, including `U+200B` (Zero Width Space), `U+2060` (Word Joiner), and all Bidi control characters (e.g., `U+2067` RLI).
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

### Group 2.D: Provenance & Context Fingerprint
This is the "Origin Story" of the atoms. It provides the deep forensic context of *what* the characters are and *where* they come from.

* **`Script:` & `Script-Ext:` (The "Script Fingerprint")**
    * This is a sophisticated, two-level analysis. The tool first checks if a character is in `ScriptExtensions.txt`.
    * If **YES** (it's a "shared" char like `·`), it adds to all its `Script-Ext:` counters (e.g., `Script-Ext: Latn`, `Script-Ext: Grek`).
    * If **NO** (it's a "simple" char like `a`), it falls back to its primary `Script:` property (e.g., `Script: Latin`).
    * This provides a 100% accurate, non-redundant script fingerprint and is a primary detector for homograph attacks.
* **`Block:` Counters:**
    * Fetches `Blocks.txt` to find the "neighborhood" of a character (e.g., `Block: Basic Latin`, `Block: Cyrillic`). A change in this fingerprint is a 100% reliable flag that a cross-script change (like a homograph attack) has occurred.
* **`Age:` Counters:**
    * Fetches `DerivedAge.txt` to show *when* a character was introduced (e.g., `Age: 1.1`, `Age: 15.0`). A key tool for finding modern emoji or symbols.
* **`Total Numeric Value:`**
    * A powerful, non-obvious fingerprint. It uses `unicodedata.numeric()` to calculate the *actual mathematical sum* of all numeric characters (e.g., `V` + `¼` = `5.25`). Any change to a number, even a "confusable" one, will change this fingerprint.
* **`Alphabetic` / `Dash` / etc.:**
    * High-speed `RegExp` properties from UAX #44.

---

## 💻 Tech Stack

The application is a pure, serverless, single-page web application. The logic is cleanly separated for maintainability.

* **`index.html`:** A single, semantic HTML5 file that defines the "skeleton" of the lab instrument. It uses ARIA roles for all components to ensure full accessibility.
* **`styles.css`:** A single, responsive CSS3 stylesheet that provides the clean, information-dense "lab" aesthetic.
* **`pyscript.toml`:** The PyScript configuration file. It lists the required Python packages (like `pyodide-http`) and, crucially, the list of all Unicode data files (`Blocks.txt`, etc.) to be pre-fetched.
* **`app.py`:** The Python "brain." This file contains all the application's logic.
    * It imports `unicodedata`, `asyncio`, and `pyfetch`.
    * It defines all computation functions (e.g., `compute_code_point_stats`).
    * It defines all rendering functions (e.g., `render_matrix_table`).
    * It contains the main `update_all` orchestrator.
* **`ui-glue.js`:** The JavaScript "nerves." A lightweight, dependency-free script that manages high-performance, accessibility-driven UI components, such as the ARIA tab controls and the "Copy Report" button logic.
* **Browser-Native APIs:**
    * **`RegExp` engine:** Used for all high-performance Unicode property classifications (e.g., `\p{L}`, `\p{Script=Cyrillic}`).
    * **`Intl.Segmenter` API:** Used to perform UAX #29-compliant grapheme cluster segmentation.
* **Google Analytics (GA4) & Google Tag Manager (GTM):** For website traffic analysis.
* **Google Consent Mode v2:** Implements a "default-deny" state for privacy.

---

## ⚙️ How It Works (The New Architecture)

1.  **On Page Load:**
    * `index.html` and `styles.css` render the skeleton.
    * `pyscript.toml` is read.
    * `app.py` begins to load and calls `asyncio.ensure_future(load_unicode_data())`.
    * The `load_unicode_data` function uses `pyfetch` to fetch all data files (`Blocks.txt`, `ScriptExtensions.txt`, etc.) in parallel. These are parsed into efficient Python data structures.
    * `ui-glue.js` runs, attaching its event listeners to the "Copy Report" button and the Tab controls.
2.  **On Data Ready:**
    * `load_unicode_data` finishes and updates the status line to "Ready."
3.  **On User Input:**
    * The user types or pastes text into the `<textarea>`.
    * The `input` event triggers the main `update_all` function in `app.py`.
4.  **`update_all` Orchestration:**
    * The `update_all` function executes its main logic, which is a single, sequential pipeline (no complex toggles).
    * It calls `compute_code_point_stats(t)` to get the logical atom counts.
    * It calls `compute_grapheme_stats(t)` to get the perceptual atom counts.
    * It calls `compute_sequence_stats(t)` to get the Major run counts.
    * It calls `compute_forensic_stats_with_positions(t)` to get all integrity flags.
    * It calls `compute_provenance_stats(t)` to get all script, block, and age data.
5.  **Render Data:**
    * The results from all `compute` functions are passed to the `render` functions.
    * `render_cards`, `render_parallel_table`, and `render_matrix_table` build HTML strings.
    * These HTML strings are injected into their respective `<tbody>` or `<div>` elements (e.g., `#major-parallel-body`, `#forensic-matrix-body`).
    * The UI updates in a single, efficient paint.


---

## 🚀 Project Status & Roadmap

### ✅ Completed: The Structural Fingerprint (Group 2)

The primary goal of the application is **complete**. The tool successfully generates a deterministic, multi-layered "structural fingerprint" for any pasted text, based on the raw, unaltered (State 1) string.

Our "facts-first" parallel-analysis architecture is fully implemented:

1.  **Dual-Atom Fingerprint:** Fully implemented. This includes the "Meta-Analysis" & "Grapheme Structural Integrity" cards, as well as the parallel (Code Point vs. Grapheme) comparison tables for both **7 Major Categories** and **30 Minor Categories**.

2.  **Structural Shape Fingerprint:** Fully implemented. This was our most recent task. The module now correctly generates *two separate, parallel tables* for:
    * **Major Category Run Analysis** (e.g., `L-Run: 3`)
    * **Minor Category Run Analysis** (e.g., `Lu-Run: 1`, `Ll-Run: 2`)
    This provides the complete "shape" signature of the text and officially replaces the old, inferior "toggle" plan.

3.  **Forensic Integrity Fingerprint:** Fully implemented. This "Matrix of Facts" correctly identifies all problematic flags (like Ignorables, Private Use, Deceptive Spaces, and Variation Selectors) and lists their exact `Positions` in the text.

4.  **Provenance & Context Fingerprint:** Fully implemented. This matrix correctly calculates and displays all `Script`, `Block`, `Age`, and `Numeric` properties based on the data files we currently load (`Blocks.txt`, `DerivedAge.txt`, etc.).

---



---

## 🔒 Privacy-First Design

This tool is **privacy-first**.
* **No Server:** All analysis, including the "deep scan" modules, runs 100% in *your* browser. The text you paste is **never** sent to a server.
* **No Analytics (by Default):** The application implements Google's Consent Mode v2. All analytics and ad tracking are **disabled by default** (set to 'denied') to ensure user privacy. Because there is no consent banner to "accept" tracking, this state is permanent.
