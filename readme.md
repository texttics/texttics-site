Here is the complete, elaborated `README.md` file for your project.

It integrates all your new modules, the "Post-Clipboard Structural Fingerprinter" philosophy as the new core, and the detailed technical explanations, resulting in a comprehensive document that far exceeds the length requirement.

---

# Text...tics: A Deterministic Structural Fingerprinter

This is a single-page web application that functions as a real-time, **deterministic** text analyzer. Its primary goal is to be a **"Structural Fingerprinter"**—a tool that generates a complete, absolute, and unambiguous statistical signature for any text.

Its secondary goal is to use this "fingerprint" to detect forensic anomalies and **"inter-layer mismatch attacks"** (e.g., homoglyphs, invisible characters, Bidi controls) that survive the copy/paste process.

It is a **Post-Clipboard Forensic Analyzer** designed to give a literal, precise, and unfiltered view of the *structural integrity* of a decoded string.

It uses **PyScript** to run Python 3.12 directly in the browser. It is built on a high-performance, serverless, hybrid model:
* **Python (Orchestration):** Manages all application state, event handling, and DOM manipulation.
* **Data-Driven Analysis (Python):** Uses the `unicodedata` library and asynchronously fetches raw Unicode data files (`confusables.txt`, `IdentifierType.txt`, etc.) to perform deep, data-driven analysis.
* **Standards-Based Analysis (JavaScript):** Leverages the browser's native JavaScript `RegExp` engine (for `\p{...}` properties) and `Intl.Segmenter` API (for UAX #29) for maximum performance.

The result is a multi-layered, *literal* analysis of text composition, sequence (run) shape, script properties, and hidden forensic flags, all based on the official **Unicode Standard**.

---

## 🔬 Core Philosophy: A "Post-Clipboard" Structural Fingerprinter

This tool is a **"Post-Clipboard Forensic Analyzer"** and, primarily, a **"Structural Fingerprinter."**

Its **main goal** is to create a **complete, deterministic, and absolute structural fingerprint** of any text. It is designed to analyze the *structural integrity* of a decoded string exactly as it exists after being copied (Ctrl+C) and pasted (Ctrl+V) into the browser.

This "fingerprint"—the full set of statistics across all modules—provides an **unambiguous structural signature** of the text. It is the "ground truth." By generating a fingerprint for a 'v1' (original) and 'v2' (modified) of a document, you can deterministically identify *any* change, no matter how slight.

A single, tiny change—like replacing a Latin 'a' with a Cyrillic 'а', or adding one Zero-Width Space—will cause a **verifiable change** in the fingerprint (e.g., in the `Script: Cyrillic` counter or the `Ignorables (Invisible)` count). This allows you to find the "slightest changes" that a simple line-by-line 'diff' tool could never see.

### The "Great Standardizer": A Core Feature
This "post-clipboard" scope is a **core feature, not a limitation.** The operating system's clipboard and the browser's "paste" event act as the **"Great Standardizer."**

By the time the text appears in the input box, the browser's strict, standards-compliant engine has *already*:
1.  Interpreted the raw bytes using a (guessed) encoding.
2.  Decoded the text into a standard JavaScript string.
3.  Strictly rejected or replaced any invalid byte-level corruption (like overlong UTF-8 sequences).

This allows the tool to focus 100% on its primary mission and **intentionally excludes** a whole class of "raw file" analysis. This tool **does not**:

* Analyze raw bytes.
* Perform encoding guessing (like `charset-normalizer`).
* Detect overlong UTF-8 sequences or other byte-level corruption.

These tasks are considered "pre-analysis" and are handled by the browser *before* your tool ever receives the text.

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

This tool rejects the idea of a single "character." Instead, it is a **Dual-Atom Analyzer** that allows you to pivot between the two different "atoms" of a string. The "inter-layer mismatch" between these two atoms is the primary vector for structural attacks.

* **Atom 1: The Code Point (Logical Atom)**
    * **What it is:** The foundational atom. This is the "raw" sequence of Unicode numbers (e.g., `U+0041`) that a database, parser, or compiler "sees."
    * **Tooling:** This is the default **`Code Points (Raw)`** mode.
    * **Forensic Value:** This is the *only* atom that can detect invisible deceptions. A Zero-Width Space (`U+200B`) is a full-fledged atom at this layer, as are Bidi control characters. The string `👨‍👩‍👧‍👦` is correctly identified as **7 distinct atoms** (`👨` + `ZWJ` + `👩` + `ZWJ` + `👧` + `ZWJ` + `👦`).

* **Atom 2: The Grapheme Cluster (Perceptual Atom)**
    * **What it is:** The "user-facing" atom. This is the "perceived character" that a human user "sees."
    * **Tooling:** This is the **`Graphemes (Perceived)`** mode, powered by the browser's native `Intl.Segmenter` (UAX #29).
    * **Forensic Value:** This layer's entire purpose is to *contrast* with the Code Point layer. It correctly identifies `👨‍👩‍👧‍👦` as **1 single atom**, just as a user would.

The core of the tool's philosophy is that you can only find structural deceptions by comparing the analysis of **Atom 1** against the analysis of **Atom 2**.

### 2. The "Tri-State" Normalization Pipeline (The "How")

This tool uses a powerful **Tri-State Normalization Pipeline** to generate its fingerprint and unmask threats. Most of the tool operates *only* on State 1 to preserve evidence, while the dedicated spoofing module (Module 7) *intentionally* uses States 2 and 3 to unmask deceptions.

* **State 1: Forensic State (Raw String)**
    * **Algorithm:** No normalization. This is the raw, unaltered text as it was pasted.
    * **Purpose:** **Preserves 100% of evidence.** This is the *only* state that can see the physical difference between a pre-composed `é` and a decomposed `e`+`´`. It's the only state that sees compatibility characters (like `ﬁ`) and case differences.
    * **Used By:** **Modules 1, 2, 3, 4, 5, 6, and 8.** All core forensic fingerprinting is done on the raw, unaltered data.

* **State 2: Compatibility State (NFKC)**
    * **Algorithm:** `unicodedata.normalize('NFKC', string)`
    * **Purpose:** **Reveals compatibility spoofing.** This state *intentionally destroys* compatibility evidence (e.g., `ﬁ` → `fi`) to unmask attacks that rely on them.
    * **Used By:** **Module 7 (Spoofing Analysis)**.

* **State 3: Canonical Identity State (NFKC Casefold)**
    * **Algorithm:** `unicodedata.normalize('NFKC', string).casefold()`
    * **Purpose:** **Reveals case-based spoofing.** This is the ultimate "skeleton." It destroys all compatibility *and* case evidence (e.g., `PayPal` → `paypal`) to create the ultimate canonical fingerprint for comparison.
    * **Used By:** **Module 7 (Spoofing Analysis)**.

---

## 🚀 Features (The Structural Fingerprint)

The tool's "fingerprint" is generated by a series of modules. Modules 1 and 1.5 are for *general analysis*, while Modules 2-8 are *forensic modules* that only appear when analyzing Code Points.

### Module 1: Comprehensive Character Analysis
This is the main "Dual-Atom" analysis engine. A top-level toggle (`Code Points (Raw)` vs. `Graphemes (Perceived)`) switches the entire analysis unit for this module.

* **1. Code Points (Raw) Mode (Default):** Analyzes every individual Unicode code point. This mode provides two further analysis models:
    * **Honest (Full Partition) Mode:** 100% standards-compliant.
        1.  It counts the code points of *all* characters, including complex emoji (`👨‍💻` is tallied as 2 `So` + 1 `Cf`).
        2.  It *calculates* the `Cn` (Unassigned) category as the mathematical remainder.
        3.  This **guarantees** `Total Code Points == Sum(All 30 Minor Categories)`. This deterministic guarantee is a core part of the "fingerprint."
    * **Filtered (Legacy) Mode:** A "cleaner" view.
        1.  It pre-filters and *removes* all `\p{RGI_Emoji}` sequences before analysis.
        2.  It uses a regex to count `\p{Cn}`.
        3.  In this mode, `Total Code Points` will *not* equal the sum of all categories.

* **2. Graphemes (Perceived) Mode:** Analyzes "user-perceived characters."
    1.  Uses the browser's native **`Intl.Segmenter`** (UAX #29) to algorithmically segment the string into **Extended Grapheme Clusters** (e.g., `e` + `◌́` is 1 grapheme; `👨‍👩‍👧‍👦` is 1 grapheme).
    2.  It then classifies each grapheme based on the `General_Category` of its *first* code point.
    3.  **Note:** When this mode is active, Modules 2-8 (which are code-point-specific) are hidden to prevent logical contradictions.

### NEW! Module 1.5: Grapheme Forensic Analysis
This module is **only visible when "Graphemes (Perceived)" mode is active** and provides a "forensically honest" look at the *physical structure* of the grapheme clusters themselves. This is a key "Zalgo detector" and part of the "inter-layer mismatch" analysis.

* **Total Graphemes:** The total count of "user-perceived characters."
* **Single-Code-Point:** A count of "simple" graphemes that consist of only one code point (e.g., `a`).
* **Multi-Code-Point:** A count of "complex" graphemes that are clusters of multiple code points (e.g., `e` + `◌́`).
* **Total Combining Marks:** A `\p{M}` count of all combining marks found *inside* all graphemes.
* **Max Marks in one Grapheme:** A "Zalgo detector" that reports the highest number of marks found in a single cluster.
* **Avg. Marks per Grapheme:** A statistical average of marks per grapheme.

### Module 2: Sequence (Run) Analysis
This module performs a true **run-length analysis** on the string's *code points* (State 1) to analyze its structural shape. This is a critical part of the "fingerprint."
* **Why it's a fingerprint:** A simple `diff` tool won't see a structural change. This module will. For example, the string "don't" produces a fingerprint of `L-P-L` (Letter, Punctuation, Letter). The "fixed" string "dont" produces a fingerprint of `L` (one run of Letters). This change in the run-count is a deterministic flag of a structural edit.
* **Features:**
    * **Major Categories:** Counts runs of the 7 major categories (e.g., `Hello-100%` is `L` run, `P` run, `N` run, `P` run).
    * **Minor Categories:** Counts runs of the 30 minor categories (e.g., `Hello-100%` is `Lu` run, `Ll` run, `Pd` run, `Nd` run, `Po` run).

### Module 3: Script Analysis (Simplified)
This module provides a basic, high-level overview of the script properties of the code points.
* **Script Counters:** Provides counts for `Latin`, `Common` (punctuation, symbols), and `Inherited` (marks).
* **`Other` (Calculated):** A calculated counter (`Total - Latin - Common - Inherited`) that serves as a primary detector for any non-Latin text.
* **🔒 [DEPRECATED] Homograph Detector:** The old `Mixed-Script Runs` feature has been deprecated. It was a "best-guess" regex, which has been replaced by the far superior, data-driven **Module 7**.

### Module 4: Forensic Analysis (RegExp-Based)
This module is dedicated to detecting "invisible," "deceptive," "corrupt," or "problematic" characters based on their deterministic `RegExp` properties. These are the "fast" checks.
* **Corruption & Error Flags:**
    * `Unassigned (Void)`: (`Cn` from Module 1) Code points that have not been assigned a meaning by Unicode. A key vector for "future" exploits.
    * `Surrogates (Broken)`: (`Cs` from Module 1) Remnants of a broken `UTF-16` pair. A clear sign of a corrupt copy/paste.
    * `Noncharacter`: (`\p{Noncharacter_Code_Point}`) Code points explicitly defined by Unicode as illegal (e.g., `U+FFFF`).
    * `Deprecated`: (`\p{Deprecated}`) Characters explicitly removed from the standard that should no longer be used.
* **Invisible Ink Detectors:**
    * `Ignorables (Invisible)`: (`\p{Default_Ignorable_Code_Point}`) The primary "invisible ink" detector. Catches `U+200B` (Zero Width Space), `U+2060` (Word Joiner), etc.
    * `Deceptive Spaces`: (`[\p{White_Space}&&[^ \n\r\t]]`) Detects any whitespace atom that is *not* a standard space, tab, or newline (e.g., `U+200A Hair Space`).
* **Contextual Flags:**
    * `Private Use (Black Box)`: (`Co` from Module 1) Characters with no public meaning, often used by fonts for custom glyphs (e.g., "Nerd Fonts") or for steganography.
* **Note on Deprecated Flags:** The `RegExp`-based `Bidi Controls` and `Control (Cc)` counters have been removed from this module. They are now correctly and more accurately identified by the data-driven **Module 6**.

### Module 5: Full UCD Profile (RegExp-Based)
This is a high-speed, `RegExp`-based module that provides a high-level UAX #44 profile of the text. It's the "fast" way to check script properties without a full Python deep scan.
* **Binary Properties:** `Dash (binary)`, `Alphabetic (binary)`, etc.
* **Script Properties:** `Script: Cyrillic`, `Script: Greek`, `Script: Han`, etc. This provides a precise, standards-based script-by-script breakdown and is a key fingerprinting tool for detecting homograph attacks.

### Module 6: UCD Deep Scan (Python & Data-Driven)
This is the most powerful **fingerprinting** module. It performs a deep scan of every code point using Python's `unicodedata` library and data fetched asynchronously from the Unicode Consortium. It finds properties that are impossible to get with `RegExp` alone.

* **Data-Driven Properties (The "Fetched" Atoms):**
    * **`Block: ...` counters:** Fetches `Blocks.txt`. Provides the "neighborhood" of a character (e.g., `Block: Basic Latin`, `Block: Cyrillic`). A change in this fingerprint is a 100% reliable flag that a cross-script change (like a homograph attack) has occurred.
    * **`Age: ...` counters:** Fetches `DerivedAge.txt`. Provides the Unicode version a character was introduced in (e.g., `Age: 1.1`, `Age: 9.0`). A key tool for finding modern emoji or symbols.
    * **`Type: ...` counters:** Fetches `IdentifierType.txt`. This is the new, **unified forensic flag** that replaces old `RegExp` checks. It provides a granular, data-driven reason *why* a character is problematic (e.g., `Type: Not_XID`, `Type: Default_Ignorable`, `Type: Format` (Bidi), `Type: Technical` (Controls)).
    * **NEW! Steganography Vector (IVS):** Detects **Ideographic Variation Selectors** (`U+E0100`–`U+E01EF`), a known vector for steganography that is invisible to most tools.

* **Numeric & Security Analysis (The "Python" Atoms):**
    * **`Total Numeric Value:`** A powerful, non-obvious fingerprint. It calculates the *actual mathematical sum* of all numeric characters (e.g., `V` + `¼` = `5.25`). Any change to a number, even a "confusable" one, will change this fingerprint.
    * **`Num Type: ...` counters:** Deterministically classifies numbers (e.g., `Decimal (Nd)`, `Letter (Nl)`).
    * **`Mixed-Number Systems:`** A security flag that triggers when digits from different scripts (e.g., Latin `1` and Arabic-Indic `٥`) are mixed.

### Module 7: True Confusable & Spoofing Analysis
This is the "holy grail" **threat-hunting** module, replacing the old Module 3 `Mixed-Script Runs` detector. It fetches and parses the 700K+ `confusables.txt` file to build a true, standards-based spoofing detector based on the "Tri-State Normalization" model.

* **Hybrid Counter:** The `Confusable Chars` card is powered by a robust Python helper function that checks *both* the `confusables.txt` map (for script-based attacks) **and** performs `NFKC` normalization (for compatibility-based attacks).
* **NEW! Tri-State Canonical Fingerprints:** To provide the most complete spoofing detection, this module also generates three distinct "fingerprints" of the string:
    1.  **Forensic State (Raw):** The hash of the raw, pasted string.
    2.  **Compatibility State (NFKC):** The hash of the `NFKC` normalized string.
    3.  **Canonical Identity State (NFKC Casefold):** The hash of the `NFKC_Casefold` string.
    * A mismatch between these hashes deterministically proves the string is using compatibility or case-based obfuscation.
* **Intelligent Report Generator:** The visual "diff" report finds all physical, uninterrupted runs of Letters, Numbers, Punctuation, and Symbols (`\p{L}+|\p{N}+|\p{P}+|\p{S}+`) and generates a forensic diff for any run containing a character found by the hybrid counter.

### Module 8: Standardized Variant Analysis
This is a dedicated data-driven module that detects "invisible" characters that modify the appearance of *other* characters.
* **File Fetched:** `StandardizedVariants.txt`.
* **Fingerprint:**
    * `Variant Base Chars:` Counts characters that can be modified (e.g., `0`, `“`).
    * `Variation Selectors:` Counts the modifying characters themselves (e.g., the invisible `U+FE00` or the emoji selector `U+FE0F`). This is a key tool for detecting subtle changes, like an emoji being "forced" into text-style.

---

## 💻 Tech Stack

The application is a pure, serverless, single-page web application. It uses a hybrid of Python (for orchestration and deep analysis) and JavaScript (for high-performance, standards-compliant parsing).

* **HTML5:** Structures the application.
* **CSS3:** Styles all modules and UI elements.
* **PyScript (2024.9.1):** Runs Python 3.12 in the browser.
* **Python 3.12 (via PyScript):**
    * All logic is contained within a single `<script type="py">` tag.
    * Orchestrates all application state and DOM manipulation.
    * Uses `pyodide.ffi.create_proxy` to create event handlers for UI elements.
    * Manipulates the DOM directly using `from pyscript import document`.
    * Imports `unicodedata` for powerful, data-driven analysis (NFKC normalization, numeric values, categories).
    * Imports `asyncio` and `from pyodide.http import pyfetch` for asynchronously fetching Unicode data files (`.txt`) from the server on page load.
* **JavaScript (via PyScript `window` object):**
    * Python leverages the browser's JavaScript engines to perform all deterministic analysis:
    * **`RegExp` engine:** Used for all high-performance Unicode property classifications (e.g., `\p{L}`, `\p{Script=Cyrillic}`, `\p{L}+|\p{N}+|\p{P}+|\p{S}+`).
    * **`Intl.Segmenter` API:** Used to perform UAX #29-compliant grapheme cluster segmentation.
* **Google Analytics (GA4) & Google Tag Manager (GTM):** For website traffic analysis.
* **Google Consent Mode v2:** Implements a "default-deny" state for privacy.

---

## ⚙️ How It Works

### Unicode-Aware App Logic

1.  **On page load,** the Python `asyncio.ensure_future(load_unicode_data())` function is called. This asynchronously fetches and parses all required Unicode data files (`confusables.txt`, `Blocks.txt`, `IdentifierType.txt`, `StandardizedVariants.txt`, `DerivedAge.txt`, `ScriptExtensions.txt`) in parallel, populating the global Python dictionaries and sets.
2.  A user types or pastes text into the `<textarea>`.
3.  The `py-input="update_all"` attribute triggers the Python `update_all` function on every keypress.
4.  The `update_all` function reads the entire UI state:
    * `is_grapheme_mode`: (Bool) The state of the "Unit of Analysis" toggle.
    * `is_honest_mode`: (Bool) The state of the "Analysis Mode" sub-toggle.
    * `is_minor_seq`: (Bool) The state of the "Sequence (Run)" toggle.
    * `active_tab`: (String) Which tab is currently open.
5.  The `update_all` function then executes its main logic:
    * **IF `is_grapheme_mode == True`:**
        1.  Calls `compute_grapheme_stats(t)` (which uses `Intl.Segmenter`).
        2.  Calls `render_stats` to update Module 1.
        3.  Shows Module 1.5 (Grapheme Forensics).
        4.  Hides Modules 2, 3, 4, 5, 6, 7, and 8.
    * **ELSE (`is_grapheme_mode == False`):**
        1.  Hides Module 1.5 (Grapheme Forensics).
        2.  Shows Modules 2, 3, 4, 5, 6, 7, and 8.
        3.  Calls `compute_comprehensive_stats(t, is_honest_mode)` to run **Module 1**. This generates the crucial `minor_stats` dictionary.
        4.  Calls `compute_sequence_stats(t, is_minor_seq)` to run **Module 2**.
        5.  Calls `compute_script_stats(t, is_honest_mode)` to run **Module 3**.
        6.  Calls `compute_forensic_stats(t, is_honest_mode, minor_stats)` to run **Module 4**, efficiently passing in the `minor_stats` (for `Cn`, `Cs`, `Co`) from Module 1.
        7.  Calls `compute_uax44_stats(t, is_honest_mode)` to run **Module 5**.
        8.  Calls `compute_ucd_deep_scan(t, is_honest_mode)` to run **Module 6**.
        9.  Calls `compute_confusable_stats(t, is_honest_mode)` to run **Module 7**.
        10. Calls `compute_variant_stats(t, is_honest_mode)` to run **Module 8**.
        11. Calls `render_stats` to inject all results into the appropriate UI sections.

### Analytics & Privacy Logic

1.  On page load, Google Tag Manager and the GA4 tag are loaded.
2.  Crucially, **before** the tags fully initialize, Google Consent Mode is set to **'denied'** by default for all tracking categories (`analytics_storage`, `ad_storage`, etc.).
3.  Because the application does not include a cookie/consent banner for users to click "Accept," this **'denied' state is permanent**, and no user-specific analytics data is collected.

---

## 🔒 Privacy-First Design

This tool is **privacy-first**.
* **No Server:** All analysis, including the "deep scan" modules, runs 100% in *your* browser. The text you paste is **never** sent to a server.
* **No Analytics (by Default):** The application implements Google's Consent Mode v2. All analytics and ad tracking are **disabled by default** (set to 'denied') to ensure user privacy. Because there is no consent banner to "accept" tracking, this state is permanent.
