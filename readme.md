# Text...tics
### Stage 1: The Profiler
**Focus:** Metrics, Lists, Integrity Flags

> **The Algorithmically Deterministic Structural Profiler of Textual Particles (Unicode-based)**

---

## 🧪 Method & Scope
**Method:** Deterministic particle-level analysis of the post-clipboard string, leveraging the Unicode Technical Standards (UAX/UTS) to profile composition, logical identity, and perceptual boundaries.

**Text...tics** is a single-page web application that functions as a real-time, deterministic forensic instrument. It is a highly specialized, browser-based "lab instrument" meticulously engineered to provide a literal, precise, and unfiltered view of any text string's internal structure, composition, and integrity.

As **Stage 1 (The Profiler)**, its primary mission is to generate the verifiable, ground-truth baseline statistics and forensic flags required to detect sophisticated "inter-layer mismatch attacks" (such as homoglyphs, "Trojan Source" bidirectional overrides, or invisible format controls).

---

## 🔬 Core Philosophy: A "Post-Clipboard" Analyzer

The design of this tool is the result of a specific, critical scoping decision. It is a **"Post-Clipboard Structural Integrity Analyzer."** This means its primary mission is to analyze the structural integrity of a decoded string *exactly as it exists* after being copied from an external source and pasted (Ctrl+V) into the browser.

### The "Great Standardizer" Boundary
The operating system's clipboard and the browser's "paste" event act as a security boundary we call the **"Great Standardizer."** By the time text appears in our input box, the browser's hardened rendering engine has already performed a massive, free sanitization:

1.  **Byte-Level Interpretation:** The browser has interpreted raw bytes using a guessed encoding.
2.  **Decoding:** It has decoded that stream into a standardized internal JavaScript string (UTF-16).
3.  **Sanitization:** It has strictly rejected or replaced invalid data (e.g., Overlong UTF-8, Lone Surrogates, or invalid byte sequences) with the Unicode Replacement Character (`U+FFFD`).

### Defining the Analytical Boundary
This "Great Standardizer" process allows Text...tics to focus 100% on the **structural integrity of the resulting, decoded string**. This creates a clear distinction:

* **IT IS NOT:** A "raw file analyzer" or "byte-level parser." We do not guess encodings or show raw hex bytes (`0xFE 0xFF`).
* **IT IS:** A "Post-Clipboard" analyzer. We analyze the *result* of the sanitization process.
* **THE GOAL:** To detect threats that *survive* normalization and transit—threats specifically designed to deceive human perception while presenting a different logical reality to a machine.

---

## 🏗️ The Architectural Model: A Hybrid, Serverless Powerhouse

The entire application runs **100% in the user's browser**, requiring no server-side backend. This guarantees user privacy and enables instantaneous analysis. It operates on a powerful, hybrid model that leverages the best of two environments.

### 1. The JavaScript Layer (High-Speed Standards Parsing)
We delegate high-frequency, standard-compliant tasks to the browser's native, JIT-compiled C++ engines (V8/SpiderMonkey) for native speed:
* **Unicode Property Classification (UAX #18):** Using the native `RegExp` engine to classify millions of code points per second (e.g., `\p{Lu}`, `\p{White_Space}`).
* **Grapheme Cluster Segmentation (UAX #29):** Using the `Intl.Segmenter` API as the authoritative "black box" for determining perceptual character boundaries.

### 2. The Python Layer (Orchestration & Deep Analysis)
We run a full **Python 3.12 runtime** in the browser via PyScript. Python acts as the "brain," handling heavy-lifting tasks that require deep, data-driven logic:
* **State Management:** The main `update_all` function in `app.py` orchestrates the entire analysis pipeline.
* **Deep Unicode Analysis:** Unlike the JS layer, Python performs direct lookups against a local, virtualized copy of the Unicode Character Database.
* **Data-Driven Analysis (The Core):** Python asynchronously fetches and parses **31 raw data files** directly from the Unicode Consortium to perform checks impossible with built-in functions alone, including:
    * **Core Profile:** `Blocks.txt`, `Scripts.txt`, `DerivedAge.txt`.
    * **Shape Profile:** `LineBreak.txt`, `BidiBrackets.txt`, `EastAsianWidth.txt`.
    * **Integrity Profile:** `PropList.txt`, `DoNotEmit.txt`, `CompositionExclusions.txt`.
    * **Threat-Hunting:** `confusables.txt`, `IdentifierStatus.txt` (UAX #31).
    * **Emoji Powerhouse (UTS #51):** A dedicated 5-file subsystem (`emoji-test.txt`, `emoji-zwj-sequences.txt`, etc.) for forensic emoji analysis.

---

## 🎯 Primary Objectives

### Goal 1: Structural Profiling
To provide an absolute, deterministic statistical signature for any text. This serves as a verifiable ground-truth baseline, allowing for the computational detection of *any* structural change between two strings, no matter how perceptually subtle.

### Goal 2: Structural Integrity Analysis
To use that profile to flag "Inter-Layer Mismatches." These are attacks where the **Logical Atom** (what the machine sees) differs from the **Perceptual Atom** (what the human sees). This tool is built to expose invisible characters, homoglyphs, Trojan Source overrides, and steganographic variation selectors that hide within plain sight.

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

### 2. The "Quad-State" Normalization Pipeline (The "How")

This tool uses a powerful **"Quad-State" Normalization Pipeline** as its analytical framework. This model defines the *state* of the text being analyzed. The "Structural Profile" (Group 2) operates *only* on State 1 to preserve 100% of the evidence. The "Threat-Hunting Analysis" (Group 3) *intentionally* uses all four states to destroy evidence and unmask deceptions.

* **State 1: Forensic State (Raw String)**
    * **Algorithm:** No normalization. This is the raw, unaltered text as it was pasted (after the browser's "Great Standardizer" has sanitized it).
    * **Purpose:** Preserves 100% of the structural evidence. This is the *only* state that can see the physical difference between a pre-composed `é` (`U+00E9`) and a decomposed `e`+`´` (`U+0065` `U+0301`). It is the only state that sees compatibility characters (like `ﬁ`) and case differences.
    * **Used By:** **The entire "Structural Profile" (Group 2).** All core integrity profiling is done on this raw, unaltered data.

* **State 2: Compatibility State (NFKC)**
    * **Algorithm:** `normalize_extended(string)`
    * **Purpose:** Reveals compatibility spoofing. This state *intentionally destroys* compatibility evidence to unmask attacks. It uses a custom-built normalization pipeline that first applies `NFKC` and then manually normalizes hundreds of other compatibility characters (like `⓼` $\to$ `8` and `Ｆ` $\to$ `F`) that are missed by the browser's built-in library.
    * **Used By:** **Threat-Hunting Analysis (Group 3).**

* **State 3: Canonical Identity State (NFKC Casefold)**
    * **Algorithm:** `normalize_extended(string).casefold()`
    * **Purpose:** Reveals case-based spoofing. This is the ultimate "skeleton" for *compatibility and case*. It destroys all compatibility *and* case evidence to create the ultimate canonical profile for comparison. It is the most aggressive normalization specified by the Unicode standard.
    * **Used By:** **Threat-Hunting Analysis (Group 3).**

* **State 4: Confusable Skeleton State (UTS #39)**
    * **Algorithm:** `_generate_uts39_skeleton(State 3)`
    * **Purpose:** Reveals homoglyph and confusable attacks. This is the final and most secure state. It runs the **UTS #39 Skeleton algorithm** (using `confusables.txt`) on the *already normalized and case-folded* string (State 3). This process destroys all visual ambiguity, mapping characters like Cyrillic `а` to their Latin `a` equivalent.
    * **Used By:** **Threat-Hunting Analysis (Group 3).** This state's hash is the definitive, "purest" signature of the string's intent.

---
---


## 🏛️ Anatomy of the "Lab Instrument" (The Structural Profile)

The UI is not a flat list of modules but a hierarchical "lab bench" that presents the full structural profile in a logical, facts-first order. It consists of a sticky navigation list (the "Table of Contents") and a main content feed broken into the following anchored sections.

### Group 1: Control Panel

This is the "Control Plane" for the instrument.
* **Text Input:** The main `<textarea>` that receives the "post-clipboard" string.
* **"Copy Report" Button:** A utility to copy the *entire* structured profile to the clipboard as a human-readable, timestamped text report.

* **Character Inspector (Click-to-Inspect):** A new panel added to the "Control Plane" that completes the "lab instrument" metaphor. It directly connects the *where* (the text) to the *what* (its deep Unicode properties).
    * **How it Works:** The inspector is a high-speed, read-only query engine. It attaches a listener to the browser's `selectionchange` event. When the user clicks or moves the cursor in the text input, the inspector:
        1.  Gets the cursor's precise `selectionStart` position.
        2.  Reads the code point immediately to the **right** of the cursor.
        3.  Correctly resolves surrogate pairs (e.g., `😀`) into their full 32-bit code points.
        4.  Queries this single code point against the **31 pre-parsed UCD files** already loaded into the `DATA_STORES`.
    * **Displayed Properties:** The panel provides an instantaneous "deep dive" into the selected character, emulating world-class tools like BabelPad. It lists all core properties, including:
        > * **Identity:** The character glyph, its `U+XXXX` Hex code, and its Decimal value.
        > * **Name:** The official Unicode `unicodedata.name()`.
        > * **Provenance:** `Block`, `Age`, and `Script`.
        > * **Classification:** `Category` (Minor), e.g., "Lowercase Letter" (`Ll`).
        > * **Bidi Class (UAX #9):** e.g., `L` (Left-to-Right).
        > * **Line Break (UAX #14):** e.g., `AL` (Alphabetic).
        > * **Word Break (UAX #29):** e.g., `ALetter`.
        > * **Sentence Break (UAX #29):** e.g., `Lower`.
        > * **Grapheme Break (UAX #29):** e.g., `Other`.

### Group 2.A: Dual-Atom Profile

This is the "Atomic Count" of the string—the **what**. It provides the core parallel analysis of "Logical" (Code Point) vs. "Perceptual" (Grapheme) atoms.

* **Core Metrics (Cards):** The highest-level counts.
    * `Total Code Points`: The total number of logical atoms.
    * `Total Graphemes`: The total number of perceptual atoms.
    * `Whitespace (Total)`: Total `\p{White_Space}` characters.
    * `RGI Emoji Sequences`: The total count of valid, Recommended-for-General-Interchange emoji sequences, as defined by **UTS #51**.
* **Grapheme Structural Integrity (Cards):** A "Zalgo-detector" that analyzes the *physical structure* of the graphemes themselves.
    * `Single-Code-Point`: "Simple" graphemes (e.g., `a`).
    * `Multi-Code-Point`: "Complex" graphemes (e.g., `e+´` or `👨‍👩‍👧‍👦`).
    * `Total Combining Marks`: Total `\p{M}` marks found.
    * `Max Marks in one Grapheme`: The "Zalgo" score (e.g., `H̊̇ëļļo̧` would have a high score).
    * `Avg. Marks per Grapheme`: The average "complexity" of each grapheme.
* **Combining Class Profile (Table):** A data-driven "Zalgo-detector" (from `DerivedCombiningClass.txt`) that shows the *type* of combining marks being used (e.g., `ccc=220 (Below)`, `ccc=230 (Above)`), providing a precise fingerprint of how characters are being stacked.
* **Parallel Comparison Tables (Tabs):**
    * **Overview Tab:** A side-by-side table comparing the Code Point vs. Grapheme counts for the **7 Major Categories** (Letter, Number, Punctuation, etc.).
    * **Full Breakdown (30) Tab:** A side-by-side table comparing the Code Point vs. Grapheme counts for all **30 Minor Categories** (Lu, Ll, Nd, Po, Cf, etc.).

### Group 2.B: Structural Shape Profile

This is the "Structural Arrangement" of the string—the **how**. It analyzes the text as a *sequence* of runs, not just a "bag of atoms." This module leverages a powerful Run-Length Encoding (RLE) engine to profile the text's "shape."

* **Why it's a profile:** A simple "bag of atoms" diff won't see a structural change. This module will. The string `"don't"` produces a Major Run profile of **L-P-L** (Letter, Punctuation, Letter) and has `3` runs. The "fixed" string `"dont"` produces a profile of **L** and has `1` run. This change in the run-count is a deterministic flag of a structural edit.
* **Features:** This module correctly generates **ten** separate, parallel RLE tables, providing a deep fingerprint of the text's "shape":
    1.  **Major Category Run Analysis**
    2.  **Minor Category Run Analysis**
    3.  **UAX #14 Line Break Run Analysis**
    4.  **UAX #9 Bidi Class Run Analysis**
    5.  **UAX #29 Word Break Run Analysis**
    6.  **UAX #29 Sentence Break Run Analysis**
    7.  **UAX #29 Grapheme Break Run Analysis**
    8.  **East Asian Width Run Analysis** (from `EastAsianWidth.txt`)
    9.  **Vertical Orientation Run Analysis** (from `VerticalOrientation.txt`)
    10. **Script Run-Length Analysis** (from `Scripts.txt` & `ScriptExtensions.txt`)

### Group 2.C: Structural Integrity Profile

This is the "Flag" report. It provides a detailed, non-judgmental list of all "problematic," invisible, or modifying atoms found in the string. It is a "matrix of facts" that reports both the **Count** and the **Positions** (indices) of each flag.

* **Corruption Flags:**
    * `Unassigned (Void) (Cn)`: Code points with no meaning.
    * `Surrogates (Broken) (Cs)`: A clear sign of a corrupt copy/paste from a broken UTF-16 pair.
    * `Prop: Deprecated`: A data-driven flag from `PropList.txt` for characters Unicode explicitly deprecates.
    * `Noncharacter`: `\p{Noncharacter_Code_Point}` code points.
* **Invisible & Deceptive Flags:**
    * `Bidi Control (UAX #9)`: A granular flag for Bidi-control characters (e.g., `U+202E RLO`).
    * `Join Control (Structural)`: A granular flag for `U+200D` (ZWJ) and `U+200C` (ZWNJ).
    * `True Ignorable (Format/Cf)`: A flag for the *remaining* format characters (e.g., `U+200B` ZWSP).
    * `Other Default Ignorable`: A data-driven flag for other ignorable characters (a known steganography vector).
    * `Deceptive Spaces`: A check for any whitespace (`Zs`) character that is not a standard ASCII space (`U+0020`).
* **Property Flags (Data-Driven):**
    * `Prop: Extender`: Flags characters from `PropList.txt` that modify the shape of others.
    * `Prop: Dash`: A data-driven flag for all characters with the `Dash` property.
    * `Prop: Quotation Mark`: A data-driven flag for all quotation characters.
    * `Prop: Terminal Punctuation`: A data-driven flag for all terminal punctuation.
    * `Flag: Bidi Mirrored Mapping`: A high-fidelity flag (from `BidiMirroring.txt`) that shows the *exact* character a mirrored bracket (like `(`) maps to (like `)`).
    * `Prop: Bidi Mirrored`: A boolean flag (from `PropList.txt`) indicating a character can be mirrored.
    * `Prop: Logical Order Exception`: A flag (from `DerivedCoreProperties.txt`) for scripts (like Thai) that have non-sequential memory layouts.
    * `Flag: Bidi Paired Bracket (Open/Close)`: A high-precision flag for paired punctuation (from `BidiBrackets.txt`).
    * `Prop: Discouraged (DoNotEmit)`: A "linter" flag for discouraged characters (from `DoNotEmit.txt`).
    * `Flag: Security Discouraged (Compatibility)`: A manually-curated flag for entire Unicode blocks (like Fullwidth Forms) known to be used in spoofing attacks.
* **Identifier Flags (Data-Driven):**
    * `Flag: Identifier Status: ...`: A UAX #31-compliant flag (from `IdentifierStatus.txt`) that correctly applies the "Default Restricted" rule to all non-allowed characters.
    * `Flag: Type: ...`: Aliased flags from `IdentifierType.txt` like `Flag: Type: Technical (Not_XID)` or `Flag: Type: Obsolete`.
* **Normalization Flags (Data-Driven):**
    * `Decomposition (Derived): ...`: A complete, data-driven flag for all decomposition types (from `DerivedDecompositionType.txt`), such as `Wide`, `Circle`, `Compat`, etc.
    * `Flag: Full Composition Exclusion`: A flag (from `CompositionExclusions.txt`) for characters that are explicitly excluded from Unicode composition.
    * `Flag: Changes on NFKC Casefold`: A critical normalization flag (from `DerivedNormalizationProps.txt`) that identifies characters guaranteed to change during NFKC-Casefold normalization.
* **Emoji Integrity Flags (Data-Driven):**
    * `Prop: Variation Selector` / `Prop: Extended Pictographic` / `Prop: Emoji Modifier`: Core property flags from `emoji-data.txt`.
    * `Flag: Unqualified Emoji`: Detects text-default characters (like `©`) that will render ambiguously.
    * `Flag: Forced Text Presentation`: Detects emoji-default characters (like `😀︎`) forced to a text style.
    * `Flag: Forced Emoji Presentation`: Detects text-default characters (like `©️`) forced to an emoji style.
    * `Flag: Standalone Emoji Component`: Detects "leftover" components (like a lone ZWJ `‍` or modifier `🏻`).
    * `Flag: Broken Keycap Sequence`: Detects a keycap mark (`U+20E3`) attached to an invalid base (like `A⃣`).
    * `Flag: Invalid Regional Indicator`: Detects a pair of regional indicators that do not form a valid flag (like `🇺🇽`).
    * `Flag: Ill-formed Tag Sequence`: Detects an emoji tag sequence (like `🏴`) missing its CANCEL TAG.
    * `Flag: Intent-Modifying ZWJ`: Detects non-RGI ZWJ sequences that modify emoji intent (like `🏃‍➡️`).
    * `Flag: Invalid Variation Selector`: Detects a VS attached to a non-designated base character.
    * `Steganography (IVS)`: A specific check for **Ideographic Variation Selectors** (`U+E0100`–`U+E01EF`).

### Group 2.D: Provenance & Context Profile

This is the "Origin Story" of the atoms. It provides the deep forensic context of *what* the characters are and *where* they come from. Unlike the simple counters of earlier versions, this module is now a full "matrix of facts" that reports both **Count** and **Positions** for each property, allowing for precise cross-referencing.

* **`Script:`, `Script-Ext:`, `Block:`, `Age:`, `Numeric Type:`**
    * A sophisticated, multi-property analysis (from `Scripts.txt`, `ScriptExtensions.txt`, `Blocks.txt`, `DerivedAge.txt`, and `DerivedNumericType.txt`) that reports the count and all positions for each property found. This provides a 100% accurate, non-redundant profile for detecting homograph attacks.
* **Total Numeric Value:**
    * A powerful, non-obvious profile. It uses `unicodedata.numeric()` to calculate the **actual mathematical sum** of all numeric characters (e.g., `V` + `¼` = `5.25`). Any change to a number, even a "confusable" one, will change this profile.
* **Mixed-Number Systems:**
    * A flag that triggers if characters from two different numbering systems (e.g., Latin `1` and Arabic `١`) are found in the same string.

### Group 2.E: Emoji Qualification Profile

This is a dedicated module powered by the UTS #51 file `emoji-test.txt`. It scans the string and renders a table listing every RGI (Recommended for General Interchange) sequence found, along with its official qualification status.

* This table provides the ground truth for emoji rendering, flagging sequences as:
    * **Fully-Qualified:** Will render as emoji consistently (e.g., `❤️`, `©️`).
    * **Unqualified:** Will render ambiguously (e.g., `©`, `®`).
    * **Component:** A sub-part of an emoji that is not RGI on its own (e.g., `🏻`, `‍`).
    * **Intent-Modifying:** A non-RGI sequence that modifies an emoji's meaning (e.g., `🏃‍➡️`).

### Group 3: Threat-Hunting Profile

This is the final, high-level security assessment. It operates on a "Clean Room" philosophy, strictly separating "Malice" (Intent) from "Rot" (Integrity).

* **Threat Level (Ledger):** A sophisticated scoring engine that calculates a "Weaponization Score." It uses a nested **Audit Ledger** to display the exact math behind the verdict.
    * **Tier 1 (Execution):** Attacks on compilers (Trojan Source, Terminal Injection).
    * **Tier 2 (Spoofing):** Attacks on humans (Homoglyphs, Identity Spoofing).
    * **Tier 3 (Obfuscation):** Attacks on filters (Invisible Clusters, Steganography).
* **Threat Flags:** A filtered list of active exploit vectors. Unlike the Integrity Profile, this view hides "noise" (like Zalgo or broken encoding) to focus exclusively on security threats.
* **Normalization Hashes:** A "fingerprint" of the text in all four normalization states (Raw, NFKC, Casefold, Skeleton).
* **Perception vs. Reality Report:** A diff view showing exactly how the text "shapeshifts" under normalization.

---

---

## 💻 Tech Stack

The application is a pure, serverless, single-page web application. The logic is cleanly separated for maintainability.

* **`index.html`**: A single, semantic HTML5 file that defines the "skeleton" of the lab instrument. It uses ARIA roles for all components to ensure full accessibility.
* **`styles.css`**: A single, responsive CSS3 stylesheet that provides the clean, information-dense "lab instrument" aesthetic.
* **`pyscript.toml`**: The PyScript configuration file. It lists the required Python packages (like `pyodide-http` and `unicodedata2`) and, crucially, the list of all **31** Unicode data files to be pre-fetched, which are grouped by purpose:
    * **Core Profile (`Blocks.txt`, `DerivedAge.txt`, `Scripts.txt`, `ScriptExtensions.txt`)**
    * **Shape Profile (`LineBreak.txt`, `WordBreakProperty.txt`, `SentenceBreakProperty.txt`, `GraphemeBreakProperty.txt`, `EastAsianWidth.txt`, `VerticalOrientation.txt`)**
    * **Integrity Profile (`PropList.txt`, `DerivedCoreProperties.txt`, `DoNotEmit.txt`, `CompositionExclusions.txt`, `DerivedNormalizationProps.txt`, `DerivedBinaryProperties.txt`)**
    * **Specialized Profile (`StandardizedVariants.txt`, `DerivedCombiningClass.txt`, `DerivedDecompositionType.txt`, `DerivedNumericType.txt`, `BidiBrackets.txt`, `BidiMirroring.txt`)**
    * **Threat-Hunting (`confusables.txt`, `IdentifierType.txt`, `IdentifierStatus.txt`, `intentional.txt`)**
    * **UTS #51 Emoji Profile (`emoji-sequences.txt`, `emoji-zwj-sequences.txt`, `emoji-data.txt`, `emoji-test.txt`, `emoji-variation-sequences.txt`)**
* **`app.py`**: The Python "brain." This file contains all the application's logic.
    * It defines all data-loading, computation, and rendering functions.
    * It contains the main `update_all` orchestrator.
    * It implements the custom `normalize_extended` function to provide a robust, multi-tier normalization process.
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

## ⚙️ How It Works (The Data Pipeline)

1.  **On Page Load:**
    * `index.html` and `styles.css` render the static "lab instrument" skeleton.
    * `pyscript.toml` is read, and PyScript begins loading the Python runtime and the **31 data files** in parallel.
    * As files return, `app.py` parses them into efficient Python data structures (`DATA_STORES`).
    * `ui-glue.js` runs, attaching its event listeners to the "Copy Report" button and the Tab controls.
2.  **On Data Ready:**
    * `load_unicode_data` finishes and updates the `status-line` to "Ready."
3.  **On User Input:**
    * The user types or pastes text into the `<textarea>`.
    * The `input` event triggers the main `update_all` function in `app.py`.
4.  **`update_all` Orchestration:**
    * The `update_all` function executes its main logic, a single, sequential pipeline.
    * **Group 2 (Structural Profile) compute:** It calls all compute functions for the structural profile (Grapheme, Code Point, RLEs, Integrity, Provenance, and Emoji Qualification).
    * **Group 3 (Threat-Hunting) compute:** It calls `compute_threat_analysis`, which generates the four normalized states, their hashes, and the high-level threat flags.
5.  **Render Data:**
    * The results from all `compute` functions are passed to the `render` functions.
    * `render_cards`, `render_parallel_table`, and `render_matrix_table` build HTML strings.
    * These HTML strings are injected into their respective `<tbody>` or `<div>` elements (e.g., `#integrity-matrix-body`, `#provenance-matrix-body`, `#emoji-qualification-body`, `#threat-hash-report-body`).
    * The UI updates in a single, efficient paint.

The tool now correctly implements:
* **Full Data-Driven Analysis:** All **31** UCD and UTS files are correctly loaded and used in the analysis.
* **UAX #31 Compliance:** A robust, UAX #31-compliant "Default Restricted" model for `IdentifierStatus`, with aliased flags for readability.
* **Quad-State Normalization:** A powerful, four-state pipeline (Raw, NFKC, NFKC-Casefold, Skeleton) that provides a definitive security fingerprint.
* **Complete Integrity Flagging:** All integrity flags, including those for `DoNotEmit`, `BidiBrackets`, and `CompositionExclusions`, are fully functional.

📈 Core Engine Enhancements
The core analysis engine is complete. All "Known Issues" previously documented have been resolved and superseded by the following comprehensive, forensic-grade subsystems.

### ✅ Completed Enhancement: The "Emoji Powerhouse" (UTS #51)
The tool no longer uses a simple, inaccurate regex. It has been upgraded to a forensic-grade, 5-file parser that is fully compliant with Unicode Technical Standard #51 (UTS #51).

This new subsystem provides 100% accurate sequence counting and powers a new, deeper layer of forensic analysis.

1. **Data-Driven Foundation**
The engine loads and cross-references all five canonical emoji data files:
* `emoji-zwj-sequences.txt`: (Tier 1) For the most complex RGI (Recommended for General Interchange) ZWJ sequences like families (👨‍👩‍👧‍👦).
* `emoji-sequences.txt`: (Tier 2) For all other RGI sequences, including flags (🇺🇦), skin-tone modifiers (👍🏻), and keycaps (7️⃣).
* `emoji-variation-sequences.txt`: (Tier 3) For RGI sequences defined by an explicit style selector (❤️).
* `emoji-data.txt`: (Tier 4) For all single-character emoji properties (e.g., `Emoji_Presentation`, `Emoji_Modifier_Base`).
* `emoji-test.txt`: (Analysis Layer) For the RGI Qualification status of every character and sequence.

2. **New Forensic Capabilities**
This upgrade not only ensures the RGI Emoji Sequences count is 100% accurate but also adds a new suite of high-value flags to the **Threat-Hunting Profile**:
* **Flag: Unqualified Emoji:** Detects text-default characters (like `©`) that will render ambiguously across platforms.
* **Flag: Forced Text Presentation:** Detects an emoji-default character (like `😀︎`) that has been forced to a text-style with an invisible `VS15`.
* **Flag: Forced Emoji Presentation:** Detects a text-default character (like `©️`) that has been forced to an emoji-style with a `VS16`.
* **Flag: Standalone Emoji Component:** Detects "leftover" structural characters (like a lone `‍` ZWJ or `🏻` skin-tone modifier).
* **Flag: Invalid Regional Indicator:** Detects a pair of regional indicators (like `🇺🇽`) that do not form a valid, RGI country flag.
* **Flag: Broken Keycap Sequence:** Detects a combining keycap (`U+20E3`) attached to an invalid base character (like `A⃣`).
* **Flag: Ill-formed Tag Sequence:** Detects a flag tag sequence (like `🏴`) that is malformed and missing its CANCEL TAG.
* **Flag: Intent-Modifying ZWJ:** Detects non-RGI ZWJ sequences (like `🏃‍➡️`) that modify an emoji's semantics.

### Enhancement: Position-Aware Forensic Profiles
The "Provenance" (Group 2.D) and "Script Run" modules are no longer simple counters. They have been upgraded to full forensic matrices that report both **Count** and **Positions** for every property. This enhancement makes the `(See Provenance Profile for details)` instruction in the Threat-Hunting profile fully actionable, allowing an analyst to pinpoint the exact location of cross-script characters.

### Enhancement: Emoji Qualification Profile
The `EmojiQualificationMap` (from `emoji-test.txt`) is now fully loaded and used to render a dedicated **"Emoji Qualification Profile"** table (Group 2.E). This table lists every RGI sequence found in the text and displays its official Unicode qualification status (e.g., "Fully-Qualified", "Unqualified", "Component"), providing a new layer of rendering and ambiguity analysis.


---

## 🔒 Privacy-First Design

This tool is **privacy-first**.
* **No Server:** All analysis, including the "deep scan" modules, runs 100% in *your* browser. The text you paste is **never** sent to a server.
* **No Analytics (by Default):** The application implements Google's Consent Mode v2. All analytics and ad tracking are **disabled by default** (set to 'denied') to ensure user privacy. Because there is no consent banner to "accept" tracking, this state is permanent.
* 

---
---

## ADDENDUM: Repertoire & Decode Health Enhancements

This addendum details the "Repertoire Analysis" and "Decode Health" subsystems, which were added to enhance the tool's forensic capabilities. These features are 100% compliant with the "Post-Clipboard" philosophy, analyzing the *results* of the browser's sanitization process to provide a deeper integrity report.

### 1. New in Group 2.A: The "Repertoire Footprint" (Core Metrics)

To provide an immediate, high-level context of the text's "shape," the **Core Metrics** (Group 2.A) have been enhanced with four **Repertoire Analysis Cards**.

**Philosophy:** This is **not** encoding detection. Encoding (the byte-level format) is lost "pre-clipboard." This is **Repertoire Analysis**—a structural "footprint" of the *decoded characters themselves*. It answers the forensic question: "What Unicode 'era' or 'tech level' does this text belong to?"

The new cards provide a 7-bit, 8-bit, 16-bit, and 21-bit profile:

* **`ASCII-Compatible (U+0000–U+007F)`**
    * **What it is:** The 7-bit baseline. This shows the count and percentage of "pure ASCII" characters.
    * **Forensic Value:** The `Fully` badge provides a definitive "Yes/No" answer. If "Fully," this text could be safely stored and transmitted in any 7-bit ASCII-only system without data loss.

* **`Latin-1-Compatible (U+0000–U+00FF)`**
    * **What it is:** The 8-bit baseline, covering the first 256 code points.
    * **Forensic Value:** This range represents the entire "legacy" world of 8-bit encodings (like ISO-8859-1 and Windows-1252). The `Fully` badge indicates the text *could* have originated from one of these systems. If the text is *not* "Fully" Latin-1, it is definitively a "modern" Unicode string.

* **`BMP Coverage (U+0000–U+FFFF)`**
    * **What it is:** The 16-bit **Basic Multilingual Plane**. This covers all "classic" Unicode characters, including most of the world's living languages (Latin, Cyrillic, Greek, CJK, etc.).
    * **Forensic Value:** The `Fully` badge indicates the text is "BMP-only." This was the limit for many older systems (like UCS-2).

* **`Supplementary Planes (U+10000+)`**
    * **What it is:** The "modern" 21-bit Unicode world. This includes all code points *above* the BMP.
    * **Forensic Value:** This is the "emoji plane." A non-zero count here is a definitive sign of modern text, as it includes all modern emoji (`😀`), rare CJK characters, historic scripts, and special notations (like musical symbols).

### 2. New in Group 2.C: The "Decode Health Dashboard" (Integrity Profile)

The **Structural Integrity Profile** (Group 2.C) has been upgraded with a comprehensive **Decode Health Dashboard**.

**Philosophy:** These flags are the *symptoms* and *forensic artifacts* of the text's journey *before* it reached our textarea. They signal that the browser's "Great Standardizer" had to handle a "dirty" or corrupt input.

This dashboard adds seven new high-value metrics, which work in concert with the existing `Surrogates (Broken)` and `Noncharacter` flags:

* **`Decode Health Grade` (Summary Row)**
    * **What it is:** A high-level, synthetic "grade" (OK, Warning, Critical) that summarizes the *entire* decode health profile.
    * **Rule:**
        * **`Critical`**: Triggered by unambiguous data loss or corruption (`U+FFFD`, `Surrogates`, `Noncharacters`).
        * **`Warning`**: Triggered by interoperability risks or integrity artifacts (`PUA`, `NUL`, `C0/C1`, `Internal BOM`, `Not NFC`).
        * **`OK`**: The absence of all the above.

* **`Flag: Replacement Char (U+FFFD)`**
    * **What it is:** This is the *most critical* decode-health flag.
    * **Forensic Value:** `U+FFFD` (``) is the canonical, unambiguous symbol that a decoder encountered an invalid or unmappable byte sequence and *data was permanently lost*. Its presence is a "Critical" grade event.

* **`Flag: NUL (U+0000)`**
    * **What it is:** A specific flag for the `NUL` character.
    * **Forensic Value:** This is not a "normal" control character. In C-based languages, it is the string terminator. Its presence in text is a massive red flag, indicating either **binary data pasted as text** or a **deliberate truncation attack**.

* **`Flag: Internal BOM (U+FEFF)`**
    * **What it is:** A flag for the Byte Order Mark (`U+FEFF`) *when it appears at any position other than index 0*.
    * **Forensic Value:** A BOM at the start is fine. A BOM in the *middle* of a string is a classic "structural integrity artifact" that proves the text is the result of a **broken file concatenation** or a **corrupt copy-paste operation**.

* **`Flag: Private Use Area (PUA)`**
    * **What it is:** A flag for any character in the PUA ranges (e.g., `U+E000`–`U+F8FF`).
    * **Forensic Value:** PUA characters have no meaning in Unicode. They are "custom fonts" (like icon fonts) or system-specific glyphs. They are **non-interoperable** and will render as junk on any system that doesn't share the exact same custom font.

* **`Flag: Other Control Chars (C0/C1)`**
    * **What it is:** A count of all C0/C1 control characters *excluding* the common ones (`TAB`, `LF`, `CR`) and the high-severity ones (`NUL`).
    * **Forensic Value:** This is a "junk" filter. It catches "binary garbage" like `[ACK]`, `[BEL]`, `[ESC]`, etc., which often results from copy-pasting from a terminal or a corrupted binary file.

* **`Flag: Normalization (Not NFC)`**
    * **What it is:** A boolean check (Yes/No) on the text's canonical integrity.
    * **Forensic Value:** It answers, "Is this text in Unicode Normalization Form C?" If the answer is `No`, it's a structural integrity flag. It proves the text is a "mixed" composition (e.g., it contains both a pre-composed `é` and a decomposed `e`+`´`), likely from multiple copy-paste operations. The flag also provides an **"approximate changes" count** to show the *scale* of the non-NFC data.

---

### 3. New in Group 2.C & 3: Threat-Hunting & Triage Upgrades

This update adds three high-value "triage" flags. One enhances the forensic clarity of the "Structural Integrity Profile," while the other two add a powerful "executive summary" layer to the "Threat-Hunting Profile," allowing an analyst to spot complex threats at a single glance.

#### 1. `Flag: Unicode Tags` (in Group 2.C)

* **What it is:** A new, high-precision flag in the "Structural Integrity Profile" that specifically isolates and counts characters from the Unicode Tag block (`U+E0000`–`U+E007F`).
* **Forensic Value (The Nuance):** This is a critical **"forensic clarity"** enhancement. These Tag characters were previously counted in the generic `True Ignorable (Format/Cf)` bucket. This patch "promotes" them to their own line item. This is crucial because Tags are not just "ignorable junk" (like a Zero-Width Space); they are **active structural components** of complex, modern emoji sequences (like regional flags, e.g., `🏴󠁧󠁢󠁥󠁮󠁧󠁿`). This allows an analyst to instantly distinguish between "ignorable whitespace" and "ignorable structural tags."

#### 2. `Script-Mix Severity Flag` (in Group 3)

* **What it is:** A high-level "triage" flag in the "Threat-Hunting Profile" that automatically analyzes the `Script Run` data from Group 2.D and produces a single, graded "badge" of the threat level.
* **Forensic Value (The Nuance):** This is a powerful **"executive summary"** for the #1 classic homoglyph attack. Instead of forcing an analyst to manually scan the noisy "Script Run" table (in Group 2.D) to find a mix of `Latin` and `Cyrillic` characters, this flag does the work for them. It automatically filters out "safe" scripts (like `Common` and `Inherited`) and hoists a single, clear severity badge (e.g., `ASCII-Only`, `Single-Script`, or `CRITICAL: Mixed Scripts (Cyrillic, Latin)`) directly into the main threat report.

#### 3. `Flag: Skeleton Drift` (in Group 3)

* **What it is:** A "capstone" flag for the entire "Quad-State" normalization pipeline. It calculates and quantifies the "drift" between the `State 1: Forensic (Raw)` string and the final `State 4: UTS #39 Skeleton`.
* **Forensic Value (The Nuance):** This flag is the **"executive summary" of the entire "Perception vs. Reality" report**. It provides a single, hard number (e.g., "5 positions differ") that proves *why* the normalization pipeline is so critical. This "drift count" instantly quantifies the total, combined impact of all case-folding, compatibility normalization, and homoglyph skeleton-mapping, showing an analyst *exactly how much* the string "shapeshifted" from its raw, deceptive form to its final, secure state.

---

## 📈 Addendum: The "Forensic Depth" Upgrade (Stage 1 Enhanced)

**Summary:** This update transitions the tool from a "Passive Detector" (counting characters) to an "Active Analyst" (evaluating structure, clusters, and intent). It introduces an O(1) Bitmask Engine, a Self-Test suite, and three new structural analyzers (Bidi Stack, Invisible Clusters, Zalgo/NSM).

### 1. Core Architecture: The Bitmask Engine & Self-Verification
To handle the complexity of "Invisible" and "Default Ignorable" characters without performance loss or coverage gaps, we replaced the linear lookup model with a **Global Forensic Bitmask**.

* **The `INVIS_TABLE` (O(1) Lookup):**
    * A global array covering the full Unicode space (0x110000).
    * Each code point is mapped to a bitmask combining 11 properties: `INVIS_DEFAULT_IGNORABLE`, `INVIS_BIDI_CONTROL`, `INVIS_TAG`, `INVIS_JOIN_CONTROL`, `INVIS_ZERO_WIDTH_SPACING`, etc.
    * **Forensic Value:** This allows us to define complex threat signatures (e.g., `INVIS_HIGH_RISK_MASK`) that are checked instantly per character.

* **"Test Mode" Self-Tests (`run_self_tests`):**
    * **Philosophy:** "Don't assume the data loader works; prove it."
    * **Mechanism:** Immediately after loading Unicode data, the engine runs a self-test suite. It iterates through the raw UCD ranges (e.g., `BidiControl` in `PropList.txt`) and asserts that the corresponding bits are set in `INVIS_TABLE`.
    * **Coverage:** Verifies Bidi, Join Controls, Tags (Plane 14), Default Ignorables, and Do-Not-Emit characters. If a single bit is missing, the console logs a critical failure.

### 2. New Structural Analyzers (Beyond "Bag of Atoms")
We introduced three new analyzers that look at the *relationship* between characters, not just the characters themselves.

#### A. The Invisible Cluster Analyzer
* **The Problem:** A single Zero-Width Space is noise; a run of 10 mixed invisible characters is a payload.
* **The Solution:** `analyze_invisible_clusters` scans for contiguous runs of any invisible/ignorable characters.
* **Metrics:**
    * **Cluster Count:** Total number of invisible islands.
    * **Max Run Length:** The size of the largest contiguous invisible sequence.
    * **Composition Tags:** e.g., `TAG|VS|SPACE` (identifies exactly *what* kinds of invisibles are mixed in the cluster).

#### B. The Bidi Stack Analyzer
* **The Problem:** Simply counting "Right-to-Left Overrides" doesn't detect broken syntax or "stack underflow" attacks.
* **The Solution:** `analyze_bidi_structure` simulates a Bidi stack machine. It pushes Isolates/Embeddings/Overrides and pops on PDF/PDI.
* **New Flags:**
    * `Flag: Unclosed Bidi Sequence`: Detects overrides that are opened but never closed (bleeding directionality).
    * `Flag: Unmatched PDF/PDI`: Detects stack underflows (formatting characters with no matching opener).

#### C. The Zalgo / NSM Analyzer
* **The Problem:** "Zalgo" text (stacking millions of combining marks) causes rendering DoS and obfuscation.
* **The Solution:** `analyze_nsm_overload` iterates through Grapheme Clusters to measure "Mark Density."
* **Metrics:**
    * **Frequency:** Counts how many graphemes exceed the safety threshold.
    * **Intensity:** Measures the max marks on a single base.
    * **Heuristics:** Flags `Flag: Excessive Combining Marks (Zalgo)` if marks per grapheme ≥ 3, or `Flag: Repeated Nonspacing Mark Sequence` if the same mark is repeated (e.g., `x` + 10 grave accents).

### 3. Threat Scoring & Heuristics (The "Executive Summary")
We introduced a synthesis layer that aggregates the disparate flags into a single, actionable verdict.

* **The Threat Score:**
    * A weighted algorithm (`compute_threat_score`) that assigns points to specific risks:
        * **+4:** Critical Decode Health (e.g., Replacement Char).
        * **+3:** Malicious Bidi, Huge Invisible Runs, Steganography (Tags).
        * **+2:** Internal BOM, Zalgo, Invalid VS.
        * **+1:** Minor anomalies (e.g., Non-NFC).
* **The Threat Level:**
    * **HIGH (Score ≥ 10):** Active obfuscation or structural attacks detected.
    * **MEDIUM (Score ≥ 5):** Suspicious formatting or compatibility issues.
    * **LOW:** Clean or trivial anomalies.
* **Presentation:** The Threat Level is forced to the top of the **Threat-Hunting Profile**, providing an immediate "Red/Yellow/Green" signal with a list of top contributing reasons (e.g., *"Reasons: Invisible run length 24; Bidi controls present"*).

### 4. UI & Reporting Polish (Forensic Clarity)
We refined the presentation layer to ensure the data is interpretable and consistent.

* **Explanatory Decode Health:** The "Decode Health Grade" row now includes the specific reasons for the grade (e.g., *"WARN — Internal BOM; Text is not NFC"*) directly in the details column.
* **Smart "No Confusables" Message:** The "Perception vs. Reality" report now distinguishes between "Clean text" and "Text with Invisibles." If **Skeleton Drift** is high but no homoglyphs are found, it explicitly warns: *"No lookalike confusables; differences come from invisibles, format controls, or normalization."*
* **Hybrid Integrity Profile:** The profile now combines the broad bitmask detections (`Flag: Any Invisible...`) with specific legacy checks (`Flag: Deceptive Newline (LS)`), ensuring no granular detail is lost while maintaining total coverage.
* **Copy Report Fidelity:** Fixed the "Flag: Flag:" duplication bug in the clipboard copy function, ensuring clean, professional reports.

---

**Forensic Polish (v1.1)

**Summary:** This update transitions the tool from "functional detection" to **"formal specification."** We have implemented a rigorous **Threat Model & Data Model** that eliminates ambiguity, standardizes reporting grammar, and enforces a strict ontology for complex threats like Mixed Scripts and Zalgo.

### 1. Formalized Threat Model & Data Schema
The **Threat-Hunting Profile** is no longer just a list of flags; it is now backed by a structured **Data Model Specification**.

* **Separation of Concerns:**
    * **Banners (Exploit Detectors):** Hard-coded, signature-based alerts for specific CVE-class patterns (e.g., "Trojan Source" Bidi overrides). These trigger independently of the score.
    * **Heuristic Score (Health Assessment):** A weighted, additive score based on a "sum of sins" (Invisibles, Drift, Zalgo, etc.).
* **The "Reason" Schema:**
    * The Threat Score is derived from a list of structured reasons, now enforced by a strict grammar: `{Metric} {Relation} {Threshold} (actual={Value})`.
    * *Example:* Instead of generic text, the engine reports: `invisible run ≥ 4 (actual=17); deceptive spaces ≥ 5 (actual=19)`. This ensures the output is machine-parsable and auditable.

### 2. Mixed-Script Ontology (Base vs. Extensions)
We resolved the ambiguity in mixed-script detection by implementing a dual-layer ontology. The tool now explicitly distinguishes between **Physical Mixing** and **Confusable Contexts**:

* **CRITICAL: Mixed Scripts (Base):** Triggered by the **`Script`** property. This indicates a text containing characters that *physically belong* to different writing systems (e.g., a string mixing Latin `p` and Cyrillic `а`).
* **CRITICAL: Highly Mixed Scripts (Extensions):** Triggered by the **`Script_Extensions`** property. This flags characters that are valid in multiple scripts but are being used in a "confusable" or high-density context (e.g., mixing Greek, Latin, and Cyrillic-compatible symbols in a way that obscures intent).
* **Result:** No more duplicate flags. A string can now be diagnosed as having a Base Mix, an Extension Mix, or both, providing precise forensic clarity.

### 3. Zalgo Synchronization (Global vs. Local)
We unified the "Zalgo" (Excessive Combining Marks) detection logic into a single source of truth (`nsm_stats`) while maintaining distinct reporting scopes:

* **Global Scope (Threat Profile):** "Is this text malicious?" The flag `Flag: Excessive Combining Marks (Zalgo)` represents the **Verdict**. It contributes to the Threat Score based on a global heuristic (Density, Max Marks).
* **Local Scope (Integrity Profile):** "Where is the noise?" The flag `Flag: Excessive Combining Marks (Zalgo – Local Scan)` represents the **Map**. It provides the specific positions of clusters that exceed the visual safety threshold.
* **Consistency:** Both scopes now rely on the exact same Grapheme Cluster analysis, ensuring that a High Threat score always corresponds to specific, locatable integrity flags.

### 4. Precision & Robustness Standards
To meet the "Lab Instrument" standard, we enforced strict numeric and logical precision across the engine:

* **Decimal Standardization:** All percentages (e.g., Repertoire coverage, PUA density) are now strictly formatted to **two decimal places** (`.2f`). This eliminates false equivalence (e.g., distinguishing `0.40%` from `0.00%`).
* **Wiring Verification:** The orchestration layer (`update_all`) was refactored to ensure that all calculated metrics—specifically `script_mix_class` and `malicious_bidi`—are correctly passed to the scoring engine, ensuring the visual banner and the calculated score never drift apart.

### 5. Coverage Verification (The "Stress Test")
The engine was validated against an **"Ultimate Invisible Stress Test"** string containing:
* Contiguous runs of 12+ invisible characters (ZWSP, ZWNJ, ZWJ, WJ, BOM, SHY).
* Hidden Plane 14 Tags (Steganography).
* Malicious Bidi Overrides (Trojan Source).
* Invalid Variation Selectors.
* Deceptive non-ASCII spaces.

**Result:** The tool correctly identified, clustered, and flagged every single anomaly, yielding a **HIGH** threat score and a perfect forensic breakdown.

---

## 📈 Addendum #2: The Forensic Precision Upgrade (Stage 1 Finalization)

**Summary:** This update transitions the tool from a "Passive Data Logger" to an **"Active Forensic Investigator."** We have refined the domain model, implemented a high-precision interaction bridge, and radically re-architected the scoring engines to distinguish between "Structural Noise" (Complexity) and "Active Malice" (Exploit Likelihood).

### 1. Domain Model: The "Particle" Taxonomy
We have formally redefined the application's identity to match its deterministic nature.
* **New Title:** *The Algorithmically Deterministic Structural Profiler of Textual Particles.*
* **The Particle Model:**
    * **Elementary Particles:** Code Points (The logical atom).
    * **Composite Particles:** Grapheme Clusters (The perceptual atom).
    * **Molecular Structures:** Runs, Sequences, and Emoji Chains.
* **Method:** We no longer "guess." We apply fixed, UCD-based laws to measure the "spectral composition" of the text.

### 2. The Interactive Bridge ("Active Investigator")
We resolved the "disconnect" between the data tables and the raw text. The tool now closes the loop between **Analysis** and **Action**.
* **The Mechanism:** A dedicated `window.TEXTTICS_HIGHLIGHT_CODEPOINT` bridge in `ui-glue.js`.
* **The Behavior:** Every position index (e.g., `#52`, `#920`) in the Integrity, Provenance, and Threat tables is now a clickable link.
* **The Visuals:** Hovering over a position index changes the cursor to `zoom-in` (Magnifying Glass), reinforcing the "Lab Instrument" metaphor. Clicking instantly scrolls to and selects the exact character in the input field, allowing for immediate inspection or deletion of invisible threats.

### 3. The Dual-Score Threat Engine
We solved the "False Positive" problem (where messy keyboards flagged as threats) by decoupling the scoring logic into two orthogonal axes.

**A. Exploit Likelihood Score (The Security Alarm)**
* **Question:** "Is this text actively trying to deceive the user or the system?"
* **Inputs:** Cross-Script Homoglyphs (Cyrillic 'a' vs Latin 'a'), Malicious Bidi Controls (Trojan Source), Invisible Clusters, and broken syntax.
* **Behavior:** This is the primary "Threat Level." It ignores innocent ASCII noise.
    * *Example:* `pаypal` (Cyrillic 'a') triggers **HIGH/CRITICAL**.

**B. Structural Complexity Score (The Noise Meter)**
* **Question:** "How visually ambiguous or structurally messy is this text?"
* **Inputs:** ASCII Drift (`1` vs `l`), Zalgo (combining mark density), Drift Ratio.
* **Behavior:** This warns the user of "messiness" without crying wolf.
    * *Example:* `123123` triggers **High Complexity** but **Zero Exploit Risk**.

### 4. The Dual-Ledger Scoring Engine (The "Jurisdiction" Model)

Text...tics abandons the traditional single "risk score" in favor of a **Dual-Ledger System** that rigorously separates "Malice" from "Rot." This prevents the common forensic error where a corrupted file is flagged as a "hacker tool," or a highly dangerous homoglyph attack is ignored because the file is "clean."

* **Jurisdiction A: The Integrity Auditor (`compute_integrity_score`)**
    * **Focus:** **Data Health & Entropy.** (Is this text *broken*?)
    * **Metrics:** Tracks `Data Corruption` (NUL, FFFD), `Structural Fractures` (broken Bidi chains), and `Protocol Violations` (Tags, Noncharacters).
    * **Scoring:** Uses a **Base + Density** formula to calculate verdicts ranging from **HEALTHY** to **CORRUPT**.

* **Jurisdiction B: The Threat Auditor (`compute_threat_score`)**
    * **Focus:** **Weaponization & Intent.** (Is this text *attacking*?)
    * **"Clean Room" Design:** Strictly **excludes** all "rot" vectors (like Nulls or broken UTF-8). This ensures a high Threat Score *always* indicates active malice, not just bad data.
    * **Target-Based Tiers:**
        * **Tier 1 (Execution):** Attacks on Compilers (Trojan Source, Terminal Injection).
        * **Tier 2 (Spoofing):** Attacks on Humans (Homoglyphs, Skeleton Drift).
        * **Tier 3 (Obfuscation):** Attacks on Filters (Invisible Clusters, Steganography).

### 5. Deep Research & Edge Case Coverage
Based on a canonical inventory of invisible particles, we closed specific coverage gaps to ensure 100% forensic exhaustion.

* **Terminal Injection Risk (ESC):** The Escape character (`U+001B`) is now elevated to a **Tier 1 Critical Threat**. Its presence forces the Integrity Level to "CRITICAL" due to the risk of terminal command injection.
* **Smart Tag Deobfuscation:** Plane 14 Tag Characters are no longer generic hex codes. They are programmatically mapped to their ASCII equivalents (e.g., `[TAG:A]`, `[TAG:!]`), making steganography instantly readable.
* **Exotic Space Detection:** The Mongolian Vowel Separator (`U+180E`) and other rare spaces are explicitly added to the forensic bitmask to ensure they trigger "Deceptive Space" flags.
* **Interlinear Annotation Controls:** Specific tracking added for `U+FFF9`–`U+FFFB` to detect suppressed formatting structures.

---

## 📈 Addendum #3: The "Forensic Exhaustion" Upgrade (Deobfuscation Engine)

**Summary:** This update pushes the tool beyond "detection" into **"Forensic Deobfuscation."** We have implemented a "Zero-Trust" particle mapper that translates over **200+** specific invisible, control, and deceptive characters into human-readable tags (e.g., `[HF]`, `[RLO]`, `[PIC:NUL]`). This ensures that *no* particle—whether a deprecated format control or a legacy terminal command—remains invisible to the analyst.

### 1. The "Four Waves" of Particle Coverage
We have expanded the `INVISIBLE_MAPPING` engine to cover four distinct classes of structural threats that standard "whitespace" filters miss:

* **Wave 1: The "False Vacuums" (Identity Spoofing)**
    * **Threat:** Characters that render as empty space but are technically Letters (`Lo`) or Symbols (`So`), bypassing `trim()` and whitespace regexes.
    * **Coverage:** Explicit mapping for the **Hangul Filler** (`[HF]`, `[HCF]`), **Braille Pattern Blank** (`[BRAILLE]`), and **Halfwidth Fillers** (`[HHF]`).
    * **Structural Glue:** Detection of "Layout Locks" like **Non-Breaking Hyphens** (`[NBH]`) and **Figure Spaces** (`[FIGSP]`) that sabotage line-breaking algorithms.

* **Wave 2: The "Ghost Containers" (Invisible Scoping)**
    * **Threat:** Invisible control characters used to "group" text in specialized scripts, creating hidden "pockets" for payload storage.
    * **Coverage:** Full mapping of **Egyptian Hieroglyph Controls** (`[EGY:BS]`), **Musical Scoping** (`[MUS:BB]`), and **Shorthand Format Controls** (`[SHORT:LO]`).

* **Wave 3: The "Legacy Drones" (Terminal Injection)**
    * **Threat:** C0 and C1 control codes (relics of the teletype era) that can manipulate terminal logs (e.g., Backspace Overwriting).
    * **Coverage:** A complete hex-map for the C0 block (`[CTL:0x07]`, `[CTL:0x1B]`) and the C1 block (`[NEL]`, `[DEL]`).

* **Wave 4: The "Zombie Controls" (Parsing Desynchronization)**
    * **Threat:** Deprecated Unicode format characters (like "Inhibit Symmetric Swapping") that modern renderers ignore (making them invisible) but legacy parsers might still process.
    * **Coverage:** Explicit tags for **Zombie Controls** (`[ISS]`, `[NODS]`), **Invisible Math Operators** (`[FA]`, `[IT]`), and **Khmer Inherent Vowels** (`[KHM:AQ]`).

### 2. The "Visual Deception" Shield (Control Pictures)
We addressed a specific social-engineering vector where visible glyphs *mimic* invisible control codes to fool analysts.
* **The Attack:** Using `U+2400` (␀, Symbol for Null) to make a string *look* like it contains a Null Byte, while hiding the real payload elsewhere.
* **The Defense:** The Reveal Engine now translates these ambiguous glyphs into explicit **Picture Tags** (e.g., `[PIC:NUL]`, `[PIC:ESC]`), instantly distinguishing them from actual control codes (`[NUL]`, `[ESC]`).

### 3. Forensic Report Deobfuscation (JS/Python Bridge)
We have bridged the "Reveal" logic directly into the reporting engine.
* **Feature:** When "Copy Stage 1 Report" is clicked, the system now runs a pure-JavaScript replica of the Python deobfuscator (`getDeobfuscatedText`).
* **Output:** The copied report automatically appends a **"[ Forensic Deobfuscation (Revealed) ]"** section at the bottom, providing a "Christmas Tree" view of the input string with all 200+ forensic tags applied. This allows for immediate, immutable evidence preservation in bug reports.

### 4. The "Browser Boundary" Defense (Non-Unicode Handling)
We have confirmed the tool's resilience against "Non-Unicode" (invalid byte) attacks.
* **Architecture:** Since the tool operates "Post-Clipboard," it relies on the browser's internal sanitization.
* **Detection:** The tool explicitly tracks the "Scar Tissue" left by this sanitization:
    * **`U+FFFD` (Replacement Character):** Flagged as "Data Loss" (evidence of invalid UTF-8 bytes).
    * **Lone Surrogates (`0xD800`):** Flagged as "Broken Encoding" (evidence of raw, invalid UTF-16 manipulation).
    * **Unassigned (`Cn`):** Flagged as "Void" (evidence of future-proofing or fuzzing attacks).
 

---

***

## 🛡️ Update: The "Forensic Saturation" & UTS #55 Compliance Upgrade

**Session Goal:** To achieve total forensic exhaustion against advanced "Inter-layer Mismatch" attacks, utilizing the threat models defined in **UTS #55 (Source Code Handling)** and the new vector deltas from **Unicode 17.0**.

**Summary:** We moved beyond simple "character counting" to **"State-Machine Validation."** The engine now tracks the *structural logic* of the text (nesting, stacks, and sequence binding) to detect exploits that are technically valid Unicode but forensically malicious.

### 1. The "Stack-Machine" Bidi Scanner (UTS #55 Sec 5.2.1)
We replaced the linear Bidi counter with a **Tri-State Stack Machine**. Previous versions counted control characters but ignored their nesting order, leaving the tool vulnerable to "Stack Cross-Over" and "Spillover" attacks.

* **The Upgrade:** The `analyze_bidi_structure` function now maintains **three independent isolation stacks**:
    1.  **The Isolate Stack:** Strictly tracks `LRI`, `RLI`, `FSI` -> `PDI`.
    2.  **The Embedding Stack:** Strictly tracks `LRE`, `RLE`, `LRO`, `RLO` -> `PDF`.
    3.  **The Bracket Stack:** Strictly enforces **Identity Matching** for paired brackets (e.g., `(` must be closed by `)`).
* **The Threat Neutralized:**
    * **Spillover Attacks:** An attacker injects an unbalanced `(` to force the renderer to leak RTL directionality into subsequent code. The engine now flags `Flag: Unbalanced Bidi Brackets`.
    * **Stack Cross-Over:** An attacker tries to close an Isolate (`LRI`) with an Embedding closer (`PDF`). The engine now flags this as a structural break (`Flag: Unmatched PDF` + `Flag: Unclosed Isolate`).

### 2. The "Syntax Spoofing" Detector (Unicode 17.0 Delta)
We addressed a specific vulnerability introduced in Unicode 17.0 ("Sibe Quotation Marks") where Variation Selectors can be legally attached to punctuation.

* **The Threat:** An attacker appends `VS3` (`U+FE02`) to a quotation mark (`"`). To a compiler, `"` + `VS3` $\neq$ `"`, allowing the attacker to break out of string literals while maintaining the visual appearance of a string. This also applies to Math Operators (obfuscating logic) and Spaces (bypassing `trim()` functions).
* **The Defense:** We implemented a **"Context-Aware" Variation Selector Scanner** in `compute_forensic_stats`.
    * **Heuristic:** It flags any Variation Selector attached to **Punctuation**, **Symbols**, or **Separators**.
    * **The Smart Filter (False Positive Prevention):** It performs a deep check against `Emoji` and `Extended_Pictographic` ranges. If the sequence is a valid Emoji Presentation (e.g., `❤️` or `⚠️`), it is **ignored**. If it is a Syntax character (e.g., `"`, `+`, ` `), it triggers `SUSPICIOUS: Variation Selector on Syntax`.

### 3. The "Ghost Glue" Patch (CGJ Hardening)
We identified a gap in the detection of **`U+034F` (Combining Grapheme Joiner)**.

* **The Threat:** `CGJ` is a "transparent" character used to block canonical reordering. It is frequently used in "Invisible Cluster" attacks to inflate file size or hide payloads without triggering standard whitespace filters.
* **The Fix:** We patched the **O(1) Bitmask Engine** (`build_invis_table`) to explicitly map `0x034F` to the `INVIS_JOIN_CONTROL` bit.
* **Result:** Runs of CGJ now contribute to the "Invisible Cluster" density score and trigger "High Risk" warnings.

### 4. UAX #44 Forensic Labelling (The Zalgo Fix)
We audited the "Combining Class Profile" against **UAX #44** and the **Unicode 17.0 Property Value Aliases**.

* **The Issue:** The tool previously labeled `CCC=233` as generic "Below."
* **The Fix:** We updated `CCC_ALIASES` to strictly match the UAX #44 specification.
    * `233` is now correctly identified as **"Double Below"** (the primary mechanism for high-density Zalgo stacking).
    * Added strict range markers for **Fixed Position Classes (10–199)**.
* **Result:** The tool now identifies the *mechanism* of a Zalgo attack, not just the presence of it.

### 5. Standards Compliance Verification
This session brings `app.py` into verified compliance with the structural requirements of:

* ✅ **UTS #55 (Source Code Handling):** Full structural coverage of Line Break Spoofing, Bidi Overrides, Lookalikes, and Mixed Scripts. (Note: Syntax-aware checks like comment boundaries remain out of scope by design).
* ✅ **UTS #39 (Security Mechanisms):** Full implementation of the "General Security Profile" via `IdentifierStatus` and Skeleton Drift.
* ✅ **Unicode 17.0 (Pre-Release):** Architecture validated to automatically ingest the new `IdentifierStatus` restrictions (78k+ chars) and `LineBreak` properties (`HH`) upon data file update.

***
---

# Text...tics Architecture & Logic Summary (Stage 1)

## 1. Executive Architecture Overview

Text...tics is built on a **Hybrid, Serverless, Client-Side Architecture**. It leverages the browser's main thread to run a full Python 3.12 runtime (via PyScript/WebAssembly) alongside high-performance native JavaScript APIs.

Unlike traditional string analysis tools that rely on simple Regular Expressions or passive character counting, Text...tics operates as an **Active State-Machine Forensic Engine**. It processes text through a rigorous pipeline that includes normalization, O(1) bitmask filtering, stack-machine structural validation (UTS #55), and heuristic threat scoring, all without sending a single byte to a remote server.

The system is composed of five distinct, tightly coupled files that separate concerns between **Data Supply**, **Visual Semantics**, **Interaction Logic**, and **Forensic Computation**.

---

## 2. Component Breakdown (The "Five Pillars")

### File 1: `pyscript.toml` (The Data Manifest & Supply Chain)
This configuration file is the "bootloader" of the forensic engine. It defines the application's environment and ensures the forensic payload is available before the logic executes.

* **Forensic Payload Definition:** The `[[fetch]]` block explicitly lists **31 Unicode Data Files** (e.g., `DerivedCoreProperties.txt`, `emoji-test.txt`, `BidiBrackets.txt`). This acts as a strict manifest. The application does not rely on the browser's internal (often outdated) Unicode tables; it virtualizes these 31 raw UCD files into the browser's file system, ensuring the tool runs on the exact Unicode version specified (currently aligned with v15.1/v16.0 standards).
* **Dependency Injection:** It forces the loading of `unicodedata2`. This is a critical architectural decision. The standard Python `unicodedata` library in Pyodide is often stripped down or outdated. By injecting `unicodedata2`, the tool ensures access to the C-optimized, full-spec Unicode database for Tier 1 normalization.

### File 2: `index.html` (The Lab Bench Skeleton)
This is the semantic skeleton of the application. It is designed not as a web page, but as a "Control Plane."

* **Hidden DOM State:** The HTML contains "ghost" elements (like `#threat-banner` and `#inspector-panel-content`) that are empty or hidden by default. These are not static content areas but **dynamic containers** that the Python runtime manipulates directly.
* **Semantic Collapsibility:** The use of `<details>` and `<summary>` elements for the major profiles (Dual-Atom, Integrity, Threat-Hunting) allows the application to render massive datasets (thousands of data points) without overwhelming the user, preserving the "at-a-glance" utility of the Dashboard while keeping deep forensic data one click away.
* **Sticky Navigation (`.jump-list`):** Implements a persistent sidebar that tracks the user's position in the forensic report, crucial for navigating long reports generated from large text dumps.

### File 3: `styles.css` (The Visual Semantics & Severity Encoding)
The CSS layer is not merely aesthetic; it is a functional component of the forensic reporting engine. It encodes logic into visual cues.

* **Severity Class Mapping:** The stylesheet defines specific utility classes—`.flag-row-crit`, `.flag-row-warn`, and `.flag-row-ok`—that correspond 1:1 with the logic decisions made in Python. When `app.py` determines a threat score is "CRITICAL," it injects the `.flag-row-crit` class, which `styles.css` renders with a specific red background and bold typography. This makes the style sheet the "decoder ring" for the engine's output.
* **The "Microscope" Metaphor:** The `.pos-link:hover { cursor: zoom-in; }` rule is a subtle but vital UX pattern. It signals to the user that the blue position links (e.g., `#52`) are not navigation links, but **inspection triggers** that will focus the "microscope" (the text input) on that specific particle.
* **Zalgo Containment:** Specific CSS rules handle the rendering of the `.inspector-glyph`, ensuring that characters with excessive combining marks (Zalgo text) do not break the UI layout but are contained within the inspection panel.

### File 4: `ui-glue.js` (The Bridge & Split-Brain Deobfuscator)
This JavaScript file acts as the **Translator** and **Bridge** between the Python runtime (Logic) and the Browser DOM (Perception).

* **The Interaction Bridge (`window.TEXTTICS_HIGHLIGHT_CODEPOINT`):** This is the most critical function in this file. Python operates on "Logical Code Points" (0-indexed integers). The browser's DOM `selectionStart` / `selectionEnd` operates on UTF-16 code units. This function translates the Python index into a DOM selection range by iterating through the string and summing `codePoint.length`. This ensures that the highlighter handles surrogate pairs (like Emoji `😀` which are 2 units) correctly, preventing the "cursor drift" bug common in hybrid apps.
* **Split-Brain Deobfuscation:** The logic for mapping invisible characters to tags (e.g., `U+200B` -> `[ZWSP]`) exists here as `JS_INVISIBLE_MAPPING`. This duplicates logic found in Python.
    * *Why?* To allow the "Copy Report" button to function instantaneously. When a user copies the report, `ui-glue.js` generates the "Forensic Deobfuscation" footer locally in the browser. This prevents a costly round-trip to the Python interpreter for a simple string formatting task, keeping the UI snappy.
* **ARIA Management:** It handles the WAI-ARIA state for the tab controls, ensuring the application remains accessible to screen readers.

### File 5: `app.py` (The Forensic State Machine)
This is the monolithic "brain" of the application. It is not a linear script but an event-driven orchestrator that manages the entire analysis pipeline.

#### 3. The Core Logic Architecture (`app.py`)

The `app.py` file has evolved from a simple character counter into a sophisticated state machine. Its architecture rests on four pillars:

1.  **The O(1) Bitmask Engine:**
    Instead of performing binary searches on range tables for every character (which would be $O(N \log M)$), the app pre-calculates a global lookup array, `INVIS_TABLE`, covering the entire Unicode space (0x110000).
    * **Mechanism:** `build_invis_table()` maps properties (Bidi, Join Control, Tag) to specific bits in an integer mask.
    * **Forensic Check:** `analyze_invisible_clusters` can then check `if mask & INVIS_HIGH_RISK_MASK` in strictly $O(1)$ time per character. This optimization allows the tool to analyze large bodies of text in real-time on the main thread.

2.  **The UTS #55 Bidi Stack Machine:**
    The `analyze_bidi_structure` function implements the strict security requirements of **Unicode Technical Standard #55 (Source Code Handling)**. It is not a counter; it is a **Pushdown Automaton**.
    * **State Separation:** It maintains three independent stacks:
        1.  **Isolate Stack:** Tracks `LRI`/`RLI`/`FSI` $\to$ `PDI`.
        2.  **Embedding Stack:** Tracks `LRE`/`RLE`/`LRO`/`RLO` $\to$ `PDF`.
        3.  **Bracket Stack:** Tracks paired punctuation (e.g., `(` $\to$ `)`).
    * **Validation:** It detects structural violations that simple counters miss, such as "Stack Cross-Over" (closing an isolate with a PDF) or "Spillover" (unclosed brackets bleeding directionality).

3.  **The Quad-State Normalization Pipeline:**
    To detect homoglyph attacks and canonical equivalence issues, the app maintains the text in four simultaneous states:
    * **State 1 (Forensic/Raw):** The literal input. Used for all integrity checks.
    * **State 2 (NFKC):** Compatibility decomposition.
    * **State 3 (NFKC-Casefold):** The "Search Canonical" form.
    * **State 4 (UTS #39 Skeleton):** The "Visual Identity" form.
    * **Logic:** The function `compute_threat_analysis` compares these states. If the "Skeleton" differs significantly from the "Raw" input (calculated as "Skeleton Drift"), it flags a potential homoglyph or spoofing attack.


### 4. The Dual-Ledger Scoring Engine (The "Jurisdiction" Model)

Text...tics abandons the traditional single "risk score" in favor of a **Dual-Ledger System** that rigorously separates "Malice" from "Rot." This prevents the common forensic error where a corrupted file is flagged as a "hacker tool," or a highly dangerous homoglyph attack is ignored because the file is "clean."

* **Jurisdiction A: The Integrity Auditor (`compute_integrity_score`)**
    * **Focus:** **Data Health & Entropy.** (Is this text *broken*?)
    * **Metrics:** Tracks `Data Corruption` (NUL, FFFD), `Structural Fractures` (broken Bidi chains), and `Protocol Violations` (Tags, Noncharacters).
    * **Scoring:** Uses a **Base + Density** formula (e.g., 40pts + 2pts/char) to calculate verdicts ranging from **HEALTHY** to **CORRUPT**.

* **Jurisdiction B: The Threat Auditor (`compute_threat_score`)**
    * **Focus:** **Weaponization & Intent.** (Is this text *attacking*?)
    * **"Clean Room" Design:** Strictly **excludes** all "rot" vectors (like Nulls or broken UTF-8). This ensures a high Threat Score *always* indicates active malice, not just bad data.
    * **Target-Based Tiers:**
        * **Tier 1 (Execution):** Attacks on Compilers (Trojan Source, Terminal Injection).
        * **Tier 2 (Spoofing):** Attacks on Humans (Homoglyphs, Skeleton Drift).
        * **Tier 3 (Obfuscation):** Attacks on Filters (Invisible Clusters, Steganography).

---

## 4. Functional Interconnections & Data Flow

The system operates in a tight loop, triggered by user interaction.

**1. Initialization Phase:**
* `main()` (Entry Point) triggers `load_unicode_data()`.
* `load_unicode_data()` fetches the 31 `.txt` files.
* **Test Check:** Immediately runs `run_self_tests()`. This iterates through the raw data ranges and asserts that the `INVIS_TABLE` bitmasks were built correctly. If this fails, the system alerts the console, refusing to "fail silent."

**2. The Analysis Loop (`update_all`):**
This function is bound to the `<textarea>` `input` event.
* **Step A (Ingest):** Captures the raw string `t`.
* **Step B (Compute - The Engines):** Calls the specialized engines:
    * `compute_emoji_analysis(t)`: Scans for RGI sequences.
    * `compute_forensic_stats_with_positions(t)`: Acts as the **Integrity Collector**, running the Bitmask/Stack logic and passing data to the **Integrity Auditor**.
    * `compute_provenance_stats(t)`: Maps blocks and scripts.
    * `compute_threat_analysis(t)`: Runs Quad-State Normalization and feeds data to the **Threat Auditor**.
* **Step C (Render - The Ledgers):** Calls `render_...` functions. Crucially, `render_integrity_matrix` and `render_threat_analysis` now generate **Nested 3-Column Ledgers** (Vector | Severity | Penalty) inside the summary rows, providing a transparent audit log of the score.

**3. The Bridge Phase:**
* After rendering, `update_all` packages the `grapheme_list` and `forensic_flags` into a JSON object.
* It exports this object to `window.TEXTTICS_CORE_DATA` via `to_js`. This makes the deep forensic data available to the "Stage 2" visualizer (which runs in a separate tab/window) without re-calculation.

**4. The Mutation Phase (`reveal_invisibles`):**
* When clicked, this function uses the `INVISIBLE_MAPPING` dictionary to rewrite the input string (e.g., `U+200B` $\to$ `[ZWSP]`).
* **Recursive Trigger:** Crucially, it calls `update_all(None)` at the end. This forces the engine to re-analyze the *new, revealed* string, verifying that the "invisible" threats have been successfully converted into visible, safe ASCII characters.

---

## 5. Key Function Reference (`app.py`)

### Initialization & Setup
* **`async def load_unicode_data()`:** The heavy lifter. Fetches 31 files, parses them using specialized parsers (`_parse_and_store_ranges`, `_parse_property_file`, etc.), and populates the global `DATA_STORES`. Triggers `build_invis_table`.
* **`def build_invis_table()`:** Compiles the O(1) lookup array. Iterates through property ranges (Bidi, Join Control, etc.) and sets the corresponding bits in the `INVIS_TABLE` integer array.
* **`def run_self_tests()`:** The "Trust but Verify" unit test. Checks random samples and boundary cases in `INVIS_TABLE` to ensure data integrity before the UI unlocks.

### Forensic Analysis Engines
* **`def analyze_bidi_structure(t, rows)`:** The implementation of the UTS #55 Bidi Stack Machine. Iterates the string, pushing/popping Isolates and Embeddings. Returns a penalty score based on broken chains and spillovers.
* **`def analyze_invisible_clusters(t)`:** Scans for contiguous runs of invisible characters. Returns a list of clusters with metadata (e.g., "High Risk" if it contains Bidi controls mixed with Tags).
* **`def analyze_nsm_overload(graphemes)`:** The "Zalgo Detector." Calculates mark density per grapheme and checks for repeated mark sequences (a common rendering DoS vector).
* **`def compute_threat_analysis(t)`:** The "Threat Hunter." Orchestrates the Quad-State Normalization. Generates the `UTS #39 Skeleton` and calculates the "Skeleton Drift" metric (how much the text changes when visually normalized).

### Scoring Auditors (The Judges)
* **`def compute_integrity_score(inputs)`:** The **Integrity Auditor**. Calculates the "Health Score" using a rigorous Base+Density formula. Applies tier-based penalties for Corruption, Fractures, Risk, and Decay.
* **`def compute_threat_score(inputs)`:** The **Threat Auditor**. Calculates the "Weaponization Score." It explicitly filters out "Rot" (Integrity issues) to focus purely on Execution Risks, Spoofing, and Obfuscation.

### Orchestration & Rendering
* **`def compute_forensic_stats_with_positions(t, ...)`:** The integration hub. It calls the sub-analyzers, gathers raw counts, and delegates judgment to the **Integrity Auditor** before generating the report rows.
* **`def normalize_extended(text)`:** The resilient normalizer. Attempts `unicodedata2.normalize("NFKC", text)`. If that fails/is missing, falls back to built-in, and applies the manual `ENCLOSED_MAP` patch to ensure `⓼` becomes `8`.
* **`@create_proxy def update_all(event)`:** The main event handler. Sequentially calls all `compute_` functions, aggregates the data, and calls all `render_` functions to update the DOM.
* **`@create_proxy def reveal_invisibles(event)`:** The deobfuscator. Maps invisible code points to their bracketed tag equivalents and updates the textarea value.

This architecture ensures that **Text...tics** is not just a passive observer of text, but a hardened, verified, and deterministic instrument for structural analysis.

---

## 🛡️ Update: Stage 1 Forensic Mastery & Inspector V11

**Session Focus:** Achieving **"State-of-the-Art" (SOTA)** status in forensic risk assessment. We transitioned from naive counting to a rigorous, UTS #39-compliant Risk Matrix Engine, and subsequently evolved the Inspector from a passive data viewer into a **Cluster-Aware, Verdict-Synchronized Forensic HUD**.

### 1. Core Engine: The "Forensic State Machine v5.0"
*(Foundation established in V10 - Unchanged)*

We abandoned the simple "if-else" logic for a sophisticated, **additive scoring engine** that mimics professional static analysis tools (like ICU SpoofChecker).

* **Risk Score Matrix:** Instead of a single "worst-case" flag, the engine now calculates a cumulative `risk_score` based on a weighted table of threats:
    * `BIDI`: **+4.0** (Critical)
    * `ZALGO_HEAVY`: **+3.0** (Suspicious)
    * `CONFUSABLE_CROSS`: **+3.0** (Suspicious)
    * `INVISIBLE`: **+2.0** (Anomalous)
    * `LAYOUT_CONTROL`: **+1.5** (Non-Standard)
* **5-Tier Verdict System:** The engine maps the score to a precise, forensic-grade verdict scale:
    * **Level 0 (BASELINE):** Standard composition (ASCII 1, Latin 'a'). Safe.
    * **Level 1 (NON-STD):** Extended Unicode or light combining marks. Not dangerous, but noted.
    * **Level 2 (ANOMALOUS):** Invisibles, layout controls, or odd formatting. Manual review recommended.
    * **Level 3 (SUSPICIOUS):** High probability of spoofing (Zalgo, Cross-Script Confusables).
    * **Level 4 (CRITICAL):** Active exploit vectors (Trojan Source Bidi, Injection).
* **Security Invariants:** Implemented hard overrides (e.g., `is_bidi_control` → **Minimum Level 4**) to ensure known CVE-class threats never slip through as "low risk."

### 2. Data Engineering: The "Inverse Lookalike" Pipeline
*(Foundation established in V10 - Unchanged)*

We solved the "missing dataset" problem for homoglyphs by building a custom ETL (Extract-Transform-Load) pipeline directly into the repo.

* **The Builder Script (`build_data.py`):** A robust Python tool that parses the official `confusablesSummary.txt` from the Unicode Consortium.
* **Inverse Map Generation:** Instead of relying on one-way mappings, we now generate `inverse_confusables.json`, a massive map linking every code point to **all** its potential lookalikes.
* **Auto-Generated ASCII Risks:** We programmatically derived the `ascii_confusables.json` set. Instead of manually hardcoding `{'1', 'l', 'I'}`, the engine now **knows** exactly which 91 ASCII characters are spoofing targets based on official Unicode data.
* **Result:** `1` and `l` are now treated identically as **"Level 0: NOTE (Common Lookalike)"**, eliminating the previous logic gap where one was flagged and the other ignored.

### 3. The "Forensic Truth" Architecture (Inspector V11)
*(Major Logic Overhaul)*

In V11, we resolved a critical "split-brain" design flaw where the Threat Engine flagged a cluster as **"CRITICAL"** (e.g., Zalgo or Bidi), but the Inspector naively labeled its base character as **"SAFE."**

* **State Synchronization (The Ledger Bridge):** The Inspector no longer "guesses" safety based on local properties. It now queries the **Global Threat Ledger** via a direct bridge.
    * **Logic:** "If the Threat Engine flags this cluster index, the Inspector HUD screams 'THREAT'. It *only* grants a 'SAFE' badge if the global ledger is silent."
* **Cluster-Aware Molecular Engine:** We replaced the atomic inspection logic with a **Molecular Aggregator** (`_compute_cluster_identity`). We eliminated the "Part-for-Whole" fallacy, ensuring the UI reflects the composite risk of the entire grapheme cluster.
    * **TR-51 Emoji Semantics:** Detects and labels Keycap sequences, ZWJ families, and Flag sequences as **"EMOJI SEQUENCE"** instead of "Base + 3 Marks."
    * **Forensic Composition:** Zalgo strings are now correctly identified as **"COMPOSITION: Base + 16 Marks"** rather than masquerading as "Basic Latin."
    * **Block Mixing:** Explicitly flags "Basic Latin + 1 Other Block" to expose the multi-block nature of spoofing attacks.

### 4. The "Forensic HUD" (Global Dashboard)
*(New in V14-V24)*

The application now features a **10-Column Forensic Matrix** serving as the primary "Heads-Up Display" (HUD). This component replaces passive data tables with an active, scientifically calibrated triage instrument.

* **Elastic Tiering ("The Comfort Zone"):** The HUD uses a dynamic labeling system to prevent "analyst fatigue" (false positives). It distinguishes between **Safe Typography** (Smart quotes, Latin-1, Math Operators) and **True Exotics** (Dingbats, Rare Scripts).
    * **Delimiters:** Shifts dynamically from `ASCII` $\to$ `TYPOGRAPHIC` (if safe smart-quotes are present) $\to$ `EXOTIC` (only for true anomalies).
    * **Symbols:** Shifts from `KEYBOARD` $\to$ `EXTENDED` (Currency, Math, Arrows, Boxes) $\to$ `EXOTIC` (Risk).
* **Volumetric Analysis:** Replaces simple "Length" with forensic mass metrics.
    * **Lexical Mass:** Calculates `Units` based on a standardized keystroke model (`(L+N)/5.0`) to compare payload density across languages.
    * **Segmentation:** Provides a rigorous `1 Block = 20 Units` structural estimate alongside standard **UAX #29** sentence counting.
* **Zero-State Logic:** Utilizes a strict color-coding system for cognitive clarity:
    * **Neutral Metrics (Gray/Black):** Used for volume and standard counts.
    * **Safety Metrics (Green/Orange/Red):** Used for Integrity, Threat, and Anomalies. "Clean" (0 anomalies) renders in a calm Light Green, distinct from the authoritative Deep Green of "Safe" statuses.

### 5. The Partitioning Engine (Emoji & Hybrids)
*(New in V19-V24)*

We have implemented a rigorous, **Disjoint Partitioning Strategy** to solve the "Double-Counting" problem inherent in Unicode (e.g., where `✅` is both a Symbol and an Emoji). The engine synchronizes the **Atomic View** (Code Points) with the **Sequence View** (RGI Clusters).

* **Zero Double-Counting:** The engine tracks "consumed indices." If a character is part of a valid **RGI Emoji Sequence** (e.g., the Check Mark in a complex chain), it is consumed by the **Emoji Column (C7)** and strictly excluded from the Symbol/Hybrid counts.
* **The "Hybrid" Class (C6):** A dedicated forensic bucket for **Atomic Pictographs**—characters with the `Emoji` property that appear as loose atoms (not part of a sequence).
    * **Primary:** `PICTOGRAPHS` (Atomic Emoji Symbols).
    * **Secondary:** `AMBIGUOUS` (Text-Default Hybrids). Detects "Shapeshifters"—characters like `™` or `☺` that default to text presentation (`VS15`) but can render as emoji (`VS16`), a primary vector for obfuscation.
* **Granular Qualification Profile:** The detailed Emoji table now explicitly categorizes every unit as **Atomic** or **Sequence**, and flags **Non-RGI** anomalies separately from standard RGI units.

### 6. The Character Inspector (Micro-Analysis)
*(Forensic Spec Sheet)*

While the HUD provides the *Macro* view, the Inspector provides the *Micro* view. It connects the *where* (cursor position) to the *what* (deep Unicode properties).

* **The "Truth Chip" System:**
    * **Verdict-Driven:** Chips like `[STACKED]`, `[BIDI]`, `[SPOOF]`, and `[ROT]` appear *only* when the Threat Engine confirms an active vector.
    * **Context-Aware Color:** `[NOTE]` badges use a calm Blue (matching the Lookalikes box), ensuring strict visual hierarchy alongside Red (Critical) and Orange (Suspicious).
* **Dynamic Identity:** The header dynamically shifts from "LATIN LETTER A" to **"GRAPHEME CLUSTER"** when analyzing complex sequences, forcing the analyst to recognize the multi-part nature of the selection.
* **Visual Evidence Arrays:**
    * **Lookalikes Matrix:** Renders a visual grid of potential homoglyphs (e.g., `a` `U+0430` `CYRILLIC`), inheriting the risk color of the verdict.
    * **Normalization Ghost Strip:** Visualizes the full `RAW` $\to$ `NFKC` $\to$ `SKELETON` transformation chain, exposing "shapeshifting" characters at a glance.

### 7. Architectural Polish

* **Hybrid Bridge Architecture:** To ensure performance without blocking the UI, heavy linguistic segmentation tasks (UAX #29) are offloaded to the browser's native V8 engine via `window.TEXTTICS_CALC_UAX_COUNTS`, while Python handles the deep forensic logic.
* **CSS "Calm" System:** The UI utilizes a "Calm" white background with thin light-gray borders for stable states, reserving high-contrast colors strictly for active signals.
* **Robust Data Loader:** The engine now gracefully handles dynamic range-based lookups for Emoji properties, ensuring stability even if specific Unicode data files are updated or missing.

### 8. Cluster-First Disjoint Partition

To achieve a good forensic model, we transitioned the engine to a **Cluster-First** architecture. This ensures that every particle in the text stream is accounted for exactly once, eliminating "phantom" double-counts.

* **Forensic Invariant:** $Hybrids \cap Emoji = \emptyset$.
* **Mechanism:** The `compute_emoji_analysis` function now classifies clusters into mutually exclusive categories:
    1.  **Text Symbol (C5):** Pure symbols (S*) with no Emoji property.
    2.  **Hybrid (C6):** Non-RGI atomic symbols with Emoji property (e.g., `™` text-style).
    3.  **Emoji (C7):** Any valid RGI unit, whether atomic (`🚀`) or sequence (`🏳️‍🌈`).
* **The "Rocket" Logic:** Previously, RGI atoms like the Rocket (`🚀`) were counted in both Hybrids and Emoji. The new logic correctly identifies them as RGI and moves them exclusively to the Emoji bucket, preserving mathematical integrity.
* **Forensic Facet (Base GC):** To preserve the insight that a Rocket is *also* a symbol, the **Emoji Qualification Profile** now includes a **"BASE"** column (e.g., `BASE: SYM`), exposing the underlying character category without corrupting the top-level count.
* **Ledger Integrity:** The engine now strictly accounts for **Leaked Components** (e.g., standalone Skin Tones) in the total unit count, ensuring that the Header Summary ("13 Units") perfectly matches the visual table rows.

***

## 📈 Update: The "Active Forensic HUD" & Signal Engine

**Session Focus:** Transitioning the tool from a "Passive Readout" to an **"Active Navigation Instrument."** We implemented a deterministic "Forensic Signal Engine" for legacy encoding analysis and a **Registry-Based State Machine** to turn static metrics into interactive navigation controllers.

### 1. New Module: Forensic Encoding Footprint (Signal vs. Compatibility)

We introduced a high-density visualization strip that answers: *"Which legacy ecosystem could this text have originated from, and what data is lost if saved as ANSI?"*

* **Philosophy:** Strictly "Post-Clipboard." We do not guess original bytes. We measure **Compatibility** (physical fit) and **Signal Strength** (discriminatory power of non-ASCII characters).
* **The "Forensic Signal" Logic:**
    * **Integrity Anchors (Left):** Verifies structural validity for `UTF-8`, `UTF-16`, and `UTF-32` (detects lone surrogates).
    * **UNI-ONLY (The Modernity Metric):** A specific, Violet-coded metric tracking characters (Emoji, Math, Historic) that are *physically impossible* in legacy encodings. Includes a rich tooltip breakdown.
    * **Legacy Filters (Right):** A sorted strip of 13 legacy encodings (Win-125x, ISO-8859-1, CJK, etc.).
        * **Metric T (Total Compatibility):** Can the file be saved without data loss?
        * **Metric S (Signal Strength):** How well does this encoding explain the *non-ASCII* characters?
    * **Exclusivity Detection:** Flags encodings as **[UNIQUE]** if they are the *sole* explanation for specific characters (e.g., a Cyrillic letter found only in CP866).
    * **The "Blue Baseline" State:** If text is 100% ASCII, the engine switches modes. Legacy encodings are marked **SAFE (Green)**, but the ASCII indicator turns **BLUE (Baseline)** to signal that while safe, it carries no forensic provenance data.

### 2. New Core Architecture: The Registry-Based State Machine (HUD v3)

We fundamentally re-architected how metrics are counted and interacted with. The HUD no longer displays "Ledger Rows" (summary counts); it now displays and controls **Evidence Instances**.

* **The Evidence Registry (`HUD_HIT_REGISTRY`):**
    * Instead of throwing away coordinates after counting, the engine now maintains a global, O(1) registry mapping forensic buckets (e.g., `int_fatal`, `thr_spoofing`, `ws_nonstd`) to exact text ranges.
* **Metric Synchronization:**
    * We resolved the "Schizophrenic Counting" bug where the HUD displayed **7** (Summary Rows) but the Stepper found **25** (Actual Violations).
    * **The Fix:** The HUD now strictly counts the length of the Registry arrays. If there are 10 malicious Bidi characters and 1 Homoglyph, the HUD displays **11 Signals**, ensuring mathematical consistency with the navigation tool.
* **The Forensic Stepper (Active Navigation):**
    * **Mechanism:** Clicking any metric (e.g., "Integrity Issues", "Threat Signals") triggers the stateless `cycle_hud_metric` engine.
    * **Behavior:** It converts the DOM cursor position to a Logical Index, scans the Registry for the next target, highlights the specific threat range, and auto-focuses the Inspector.
    * **Feedback:** A dedicated Left-Side Status Bar (`#hud-stepper-status`) provides individualized feedback with a Map Pin icon: *"Threat Signals Highlighter: #19 of 25 — Trojan Source"*.

### 3. Threat Logic Refinement: "Victim vs. Attacker"

We patched a critical philosophical flaw in the Threat Engine where innocent ASCII characters were flagged as threats simply because they *could* be spoofed.

* **The "Guilt by Association" Bug:** Previously, the digit `1` was flagged as a threat because it is listed in `confusables.txt` (it looks like `l`).
* **The "Active Malice" Fix:** We implemented a strict **ASCII Whitelist** (`cp > 0x7F`) in the `compute_threat_analysis` loop.
* **The Result:**
    * **Victims:** ASCII characters (like `1`, `m`, `o`) are now **Green/Safe Baseline**, even if they are visually ambiguous.
    * **Attackers:** Only Non-ASCII characters (like Cyrillic `а`) that mimic ASCII are flagged as **Red/Threat**.
    * This reduces noise by ~90% and focuses the tool strictly on foreign spoofing vectors.

### 4. Interaction & UI/UX Refinements

* **DOM Un-Nesting:** Resolved a critical "Cannibalistic DOM" issue where the Status Bar update logic was overwriting the Stepper UI. The Status Bar components are now independent siblings.
* **The "Invisible Hunter":** The "Highlight Non-Std Inv." button uses a `selectionEnd` delta loop to force-march through zero-width characters, auto-triggering the Inspector for immediate analysis.
* **Workbench Aesthetic:** Renamed "Controls" to **"Global Actions"** with a "Rigorous Violet" theme (`#5b21b6`) to visually separate tools from data.
* **Clipboard Fidelity:** The "Copy All Data" report now parses the deep forensic tooltips from the Encoding Footprint and appends a full "Deobfuscated" view of the text.


## 🛡️ Update: The Forensic X-Ray Engine (v8.0)

**Session Goal:** To transform the "Perceived vs. Reality" view from a passive visualization into an active, forensically accurate **"Sparse Forensic Stream."** We moved from heuristic guessing to a deterministic, architecture-driven approach that prioritizes data correctness and cognitive clarity.

### 1. Architecture & Logic: The "Sparse Stream" Renderer
The new "Perceived vs Encoded" block is powered by a **Clustering & Priority State Machine** designed to handle massive inputs without overwhelming the analyst.

* **Context Clustering Algorithm:**
    * Instead of rendering the full text, the engine identifies "Threat Hotspots."
    * It aggregates threats within a tunable heuristic window (`MERGE_DIST = 40`) to form **Context Clusters**.
    * This creates a "Sparse View," rendering only the relevant slices of text while mathematically summarizing the gaps (e.g., `[ ... 103 safe characters omitted ... ]`).
* **The Render Priority Stack:**
    * The engine iterates through the text using a strict **Threat Hierarchy** to resolve overlapping properties (e.g., a character that is both "Invisible" and "Bidi"):
        1.  **`EXECUTION` (Critical):** Bidi Controls (Trojan Source). *Always renders first.*
        2.  **`OBFUSCATION` (High):** Invisible/Format characters. *Compressed into Run-Length Stacks (e.g., `×17 HID`).*
        3.  **`SPOOFING` (Medium):** Confusables. *Renders with Script Tags (e.g., `Cyr→Lat`).*
        4.  **`SAFE` (Baseline):** Standard text. *Rendered with a "Context Halo" (dimmed opacity) to reduce noise.*

### 2. Engineering Achievements: Logic, Security & Ergonomics
We successfully audited and hardened the engine to reach a "Local Maximum" of utility and safety:

* **Logic Repair (The Priority Inversion Fix):** We patched a critical flaw where Bidi controls were being masked by the "Invisible" check. The engine now strictly enforces `Execution > Obfuscation`, ensuring dangerous controls like `RLO` render as high-visibility Amber **BIDI** stacks rather than generic Purple hidden tags.
* **Security Hardening (XSS & Contracts):**
    * **Double-Layer Escaping:** The interactive "Copy Safe Slice" button now uses a rigorous pipeline (`_escape_for_js` + `_escape_html`) to prevent attribute injection attacks via malicious inputs.
    * **Explicit Contracts:** Vague labels were replaced with precise definitions. `DEL` (often confused with "Delete Key") became **`HID`** (Hidden), and tooltips now explicitly define the sanitization rules (Confusables mapped to Skeleton; Invisibles dropped).
* **Visual & Cognitive Polish:**
    * **Fact-Based Dashboard:** We removed noisy "Target Guessing" (e.g., "Target: PayPal") in favor of deterministic **Cluster-Level Counters** (e.g., `[10 EXECUTION] [3 SPOOF]`).
    * **Unified Mental Model:** A global "Scoreboard" at the top and a "Legend" at the bottom now share the exact same terminology and color coding, significantly reducing the cognitive load for non-expert analysts.

🛠️ New Module: The Forensic Workbench (Remediation)

This update introduces a dedicated Remediation & Evidence layer to the Actions panel, transforming the tool from a passive analyzer into an active forensic instrument.

The Problem

Detecting a threat is only step one. Analysts and developers often struggle with the next step: "How do I safely move this malicious string into a ticket, a unit test, or a report without triggering the exploit myself?"

The Solution: Three Active Workflows

The new Forensic Workbench provides three distinct pipelines for handling hazardous text safely:

1. 🛡️ Sanitization Engine (The "Fixer")

Instantly neutralizes invisible and structural threats while preserving the visual text.

Strict Mode: The "Nuke" option. Drops all Bidi controls, Tags, invisible formatters, private use characters, and non-standard whitespace. Forces NFC normalization. Ideal for logs and legacy databases.

Conservative Mode: The "Human" option. Preserves valid RGI Emoji sequences (including ZWJ families) while stripping structural threats from the rest of the string. Ideal for chat apps and tickets.

2. 💻 Encapsulation Engine (The "Developer")

Generates safe, escaped string literals for immediate use in source code.

Copy as Python/JS: Escapes dangerous characters (quotes, backslashes, controls) and converts non-ASCII text into safe Unicode escapes (e.g., \u202E or \u{1F4A9}). This allows developers to write unit tests that reproduce the attack without making the source file itself malicious.

3. 💾 Evidence Engine (The "Chain of Custody")

Download as JSON: Generates a forensic artifact containing the full analysis profile, timestamps, and a SHA-256 cryptographic hash of the input. This provides an immutable record of the analysis for incident response logs.


🔧 Technical Deep Dive: The "Bridge Problem" (Python vs. JS Indexing)

1. The Core Conflict: "Two Truths"

To understand the complexity of building a forensic tool in a hybrid environment (PyScript), one must understand the fundamental disagreement between the backend (Python) and the frontend (JavaScript/DOM) regarding what constitutes a "character."

Python (The Brain): Python 3 treats strings as sequences of Unicode Code Points.

Example: The Zombie Emoji 🧟 (U+1F9DF) is considered Length 1.

Indexing: text[5] returns the 6th code point, regardless of byte size.

JavaScript (The DOM): JavaScript treats strings as sequences of UTF-16 Code Units.

Example: The Zombie Emoji 🧟 is outside the Basic Multilingual Plane (BMP). It requires two code units (a High Surrogate and a Low Surrogate) to represent. JavaScript considers this Length 2.

Indexing: text[5] returns the 6th code unit, which might be the second half of a surrogate pair.

The Problem (The "Drift"):
When the Python-based Threat Engine identifies a threat at Logical Index 5, it tells the browser to highlight index 5.

If the text is ABCDE..., both languages agree. Index 5 is F.

If the text is 🧟ABC...:

Python sees 🧟 at Index 0, A at Index 1.

JavaScript sees 🧟 at Indices 0-1, A at Index 2.

If Python says "Highlight A at Index 1," the browser highlights the second half of the Zombie emoji.

This error accumulates. After 50 emojis, the highlighter is highlighting empty space or wrong characters 50 positions away.

2. The "Battles" (Architecture Iterations)

We went through four distinct architectural attempts to solve this synchronization problem before arriving at the final solution.

Round 1: The "Naive Python" Approach

Strategy: We simply passed Python indices directly to the JavaScript setSelectionRange API.

The Failure: "Highlight Drift."

As soon as the user pasted emojis or astral symbols, the highlighting drifted. The visual selection was offset from the logical threat by exactly the number of surrogate pairs preceding it.

Round 2: The "Proxy Iterator" Approach

Strategy: We attempted to force Python to "think like JS" by creating a Pyodide Proxy object: js_sequence = window.Array.from_(t). We then iterated this proxy in Python to find indices.

The Failure: "Select All" / "Sluggishness."

Iterating over a JS Proxy object from within Python incurs a massive performance penalty (marshalling data across the WASM boundary for every character).

The iterator behavior was brittle. In edge cases, the loop would miss the target index entirely, leaving the dom_start variable at its default -1. The fallback logic then selected the entire text ("Select All"), confusing the user.

Round 3: The "Hybrid Bridge" (The Syntax Error)

Strategy: We attempted to offload the index calculation entirely to JavaScript by injecting a dynamic script using window.eval(). The idea was to ensure perfect UTF-16 fidelity by running the math in the browser's native engine.

The Failure: Syntax Error.

Implementation error: A stray triple-quote (""") and debug block were accidentally left in the production code, commenting out the logic and crashing the application.

Round 4: The "Desync" (Log 101 vs Len 96)

Strategy: We fixed the syntax, but encountered a new crash: Logical 101 not found in text (len 96).

The Failure: "Split Brain."

The Registry (the map of threats) was being populated by the Emoji Engine. At that time, the Emoji Engine was using the browser's Intl.Segmenter (JavaScript) to count characters. It reported indices in UTF-16 Code Units.

The Stepper was trying to walk the Python String (Code Points).

Result: The Registry said: "Threat at Index 101!" (JS counting). Python looked at its string (Length 96) and crashed because logical index 101 did not exist. The system was fighting itself.

3. The Final Victory: "The United Python Front"

The Solution:
We stopped trying to bridge the gap in the middle. We forced the entire application to speak Python (Logical Indices) until the very last millisecond before rendering.

Architecture of the Fix:

Registry Source: We rewrote populate_hud_registry and compute_emoji_analysis to iterate using enumerate(t) (Native Python).

Result: The Registry now records threats using Logical Indices (e.g., "Index 5").

Stepper Logic: We rewrote cycle_hud_metric to iterate using enumerate(t) (Native Python).

Result: The Stepper looks for Index 5. Since it uses the same counting method as the Registry, it finds it perfectly.

The Translation Layer (The Rosetta Stone):
Only at the exact moment of calling the browser API do we translate Logical Index to DOM Index. We use a high-speed, pure Python loop that simulates UTF-16 encoding rules:

The Rosetta Stone Loop
acc = 0 # DOM Index (Accumulator)
for i, char in enumerate(t): # i is Logical Index
    if i == target_logical_index: 
        dom_index = acc # Found the match!
        break
    # Add 2 if it's an emoji/surrogate (Astral), else 1 (BMP)
    acc += (2 if ord(char) > 0xFFFF else 1) 


Why is this better?

Deterministic Sync: The Registry and the Stepper are mathematically guaranteed to match because they use the exact same iteration method (Python enumerate).

Precision: The cursor lands exactly on the target, even if it's buried behind 50 "Zombie Mosquitos," because we manually calculate the UTF-16 offset byte-by-byte in the language that owns the data.

Stability: We removed window.eval (security risk) and JS Proxies (performance bottleneck). The solution runs at native WASM speed.


## 🛡️ Update: The "Deep Truth" Upgrade (Quad-State Forensics)

**Session Goal:** To eliminate heuristic guessing in threat detection by implementing the **UTS #39 Security Mechanisms** as a rigorous, observable pipeline. We transitioned the tool from simply flagging "Suspicious" characters to mathematically proving **"Normalization Drift."**

### 1. The Quad-State Forensic Pipeline
We architected a "Lifecycle of Deception" model that analyzes text across four distinct forensic states simultaneously. This ensures no attack can hide behind compatibility layers or case folding.

* **State 1: Forensic (Raw):** The chain-of-custody truth (Post-Clipboard). Used for invisible/integrity analysis.
* **State 2: Compatibility (NFKC):** The "Format" state. Collapses stylistic obfuscation (e.g., Fullwidth `Ａ` $\to$ `A`, Ligatures `ﬁ` $\to$ `fi`).
* **State 3: Identity (NFKC-Casefold):** The "Machine" state. Represents how a backend database or filesystem "sees" the string (collapsing Case and Compatibility).
* **State 4: UTS #39 Skeleton (The "Deep Truth"):** The "Visual" state. Uses a custom **Forensic Transformation Pipeline** to map visual lookalikes to their prototypes (e.g., Cyrillic `а` $\to$ Latin `a`), stripping all "invisible glue" to reveal the bare visual bones of the text.

### 2. The Metadata-Driven Drift Engine
We replaced simple string equality checks (`if s1 != s2`) with a **Forensic Event System**. The engine now generates an audit log during normalization, allowing us to classify "Drift" with absolute precision:

* **Visual Drift (CRITICAL):** Triggered *only* when the Skeleton Event Log records a **Confusable Mapping** event.
    * *Verdict:* "Visual Drift (6 Homoglyphs Mapped)" — proves active spoofing.
* **Structure Drift (HIGH):** Triggered when invisible characters (Bidi controls, ZWJ) are stripped during skeleton generation.
    * *Verdict:* "Structure Drift (Hidden Chars Stripped)" — exposes Bidi attacks that rely on "Snap-Back" rendering.
* **Identity/Format Drift (WARN):** Distinguishes benign case/width normalization from malicious obfuscation.

### 3. The "Perception vs. Reality" Interface
We upgraded the Group 3 UI from a static Hash List to an **Active Forensic Dashboard**.
* **Side-by-Side Comparison:** Visually renders the `Raw` vs. `Skeleton` states. This creates a "Forensic X-Ray" effect where Bidi attacks "unravel" and Homoglyphs "shapeshift" before the user's eyes.
* **Cryptographic Evidence:** SHA-256 hashes are now preserved in a collapsible evidence locker, keeping the UI focused on actionable intelligence.

### 4. The "Intel Engine" & Greedy Tokenization
We rebuilt the Token Analyzer to be robust against "Symbol-Only" payloads.
* **Greedy Tokenizer:** Replaced the restrictive Regex (`\w+`) with a whitespace-based splitter. This ensures that pure-symbol attacks (e.g., isolated Bidi controls `‮`, Broken Emoji components `🏻`) are captured as High-Value Targets.
* **Multi-Vector Hierarchy:** Implemented a **Strict Severity Sort** (`CRIT > HIGH > MED`). A token containing both a "Mixed Script" (Spoofing) and a "Bidi Override" (Syntax) is now correctly classified as a **SYNTAX (CRITICAL)** threat, prioritizing Execution Risk over Visual Risk.

### 5. Data Engineering: Type-Aware Confusables
We upgraded the `_io.js` loader to parse the **Forensic Type Tags** (`MA`, `ML`, `SA`, `SL`) from `confusables.txt`. This allows the engine to distinguish between "Weak Ambiguity" (Intra-script lookalikes like `1` vs `l`) and "Strong Spoofing" (Cross-script lookalikes), significantly reducing false positives in the Drift Engine.

### ✅ Completed Enhancement: The "Forensic Quad" UI (High-Density Metrics)

The **Core Metrics (Group 2.A)** have been radically re-architected. We moved away from a "dashboard" aesthetic (big numbers with empty space) to a **"Lab Instrument"** philosophy. Every pixel of the card is now used to provide immediate forensic context, allowing an analyst to assess the text's "physical properties" without clicking a single button.

**1. The High-Density "Micro-Facts" System**
Each of the four core cards now displays a primary metric (left) alongside dynamic **Micro-Facts** (right). These derived metrics allow for instantaneous "Triangulation of Anomaly":

* **Total Graphemes (Visual Reality):**
    * Now displays **Mark Density** (Marks/Grapheme). *Forensic Value:* Instantly flags Zalgo text or heavy diacritics (> 1.0) vs standard prose (~0.1).
    * Now displays **RGI Emoji Count**.
* **Total Code Points (Logical Reality):**
    * **Major Logic Upgrade:** Replaced static definitions ("1 Logical Atom") with dynamic **Composition Data**.
    * Now displays **Combining Mark Count & %**. *Forensic Value:* Explains the gap between Graphemes and Code Points. High mark density with low grapheme count signals invisible structural abuse.
* **UTF-16 Units (Runtime Reality):**
    * Now displays **Surrogate Overhead** (+N units). *Forensic Value:* Instantly quantifies "Astral Plane" content. A high overhead warns of potential buffer overflows in legacy JS/Java systems that count units, not points.
* **UTF-8 Bytes (Physical Reality):**
    * Now displays **Byte Density** (Bytes/Code Point). *Forensic Value:* A heuristic for language detection. `1.0` = ASCII, `~2.0` = Latin/Cyrillic, `>3.0` = CJK/Emoji.
    * Now displays **ASCII Coverage %**. Replaced the tautological "Encoding: UTF-8" label with a distribution metric.

**2. The "Forensic Datasheet" Tooltip Engine**
We implemented a rigorous standard for data tooltips. They no longer just define the term; they act as a reference manual.
* **Structure:**
    * `[ DEFINITION ]`: Technical standard (e.g., UAX #29).
    * `[ FORENSIC BENCHMARKS ]`: Expected ranges (e.g., "Normal: < 5% marks").
    * `[ THIS SAMPLE ]`: The specific calculated values for the input.

**3. Visual Semantics**
* **"Steel Gray" Headers:** Standardized header hierarchy for a cleaner, instrument-like look.
* **Data-First Typography:** Removed "pill/button" styling from facts to emphasize that they are immutable measurements, not UI controls.

---

***

## 🛡️ Update: The "Forensic Superiority" & Remediation Upgrade

**Session Goal:** To transition the tool from a "Passive Analyzer" to an **"Active Hunter & Neutralizer."** This update introduces a dedicated Invisible Atlas, targeted sanitization profiles, and a suite of "Red Team" exploit generators, solidifying the tool's position as a security instrument.

### 1. New Module: The Invisible Character Atlas
We moved beyond simple flags to a **"Quantifiable Forensic Ledger."** This new panel provides a definitive, interactive legend of every invisible, control, and format character detected in the input.

* **The "Atlas" Table:**
    * Lists every unique invisible character found.
    * **Dynamic Visualization:** Uses **Unicode Control Pictures** (e.g., `␀`, `␛`) and dynamic tags (e.g., `[VS16]`) to reduce visual noise while maintaining precision.
    * **Interactive Locator:** A "Find" button for every row instantly highlights the specific character in the text input, bridging the gap between aggregate data and specific location.
* **The Summary Bar:**
    * A dashboard-style strip above the table that aggregates counts by category (e.g., `12 IGNORABLE`, `4 BIDI`, `2 ZW-SPACE`), allowing for immediate cross-verification with the HUD.

### 2. New Engine: Forensic Remediation (Sanitization)
We replaced generic "cleaning" with **"Targeted Neutralization Profiles."** The tool now allows the analyst to surgically remove threats based on intent.

* **Profile A: Strict Mode ("Nuke")**
    * **Logic:** Destroys *all* invisible characters, formatting codes, Bidi controls, and tags.
    * **Use Case:** Sanitizing code snippets, logs, or raw data where *any* invisible character is a liability.
* **Profile B: Smart Mode ("Artifact Hunter")**
    * **Logic:** Removes "dangling" artifacts (ZWSP, LRM, isolated ZWJs) but **preserves** structural glue (ZWJ, VS16) *if and only if* they are part of a valid RGI Emoji sequence.
    * **Use Case:** Cleaning user-generated content (chat logs, bios) without breaking valid emojis.

### 3. New Intelligence: Heuristics & "Zombie" Detection
We implemented specific detection engines for modern and legacy threats.

* **"Blank ID" Heuristic:**
    * Mathematically proves if a string has "Zero Visible Mass" despite containing data. Detects usernames composed entirely of invisible characters.
* **"Artifact" Heuristic:**
    * Detects non-structural invisibles (like `ZWSP`) in contexts where they don't belong (e.g., simple Latin text). Flags potential AI-generated hallucinations or copy-paste "rot."
* **"Zombie Control" Hunter:**
    * Elevated the deprecated Unicode Format range (`U+206A`–`U+206F`) to **CRITICAL** severity. These are legacy "ghosts" (Inhibit Symmetric Swapping, etc.) often used for obfuscation.
* **NFC Stability Analyzer:**
    * A new granular check that reports exactly *which* graphemes are "Unstable" (physically different from their NFC form), detecting "Frankenstein" text compositions.

### 4. New Utility: Exploit Vector Generation
To serve the "Red Team" / Penetration Testing persona, the Inspector panel now includes a **Forensic Encodings** tab.

* **Purpose:** Answers the question, *"How does this invisible payload look in a shell or JSON context?"*
* **Vectors Generated:**
    * **Shellcode:** `\xE2\x93\xBC` (for C/Bash injection testing).
    * **Octal:** `\342\223\274` (for legacy system exploits).
    * **Base64:** `4pO8` (for payload encoding checks).
    * **ES6/JSON:** `\u{24FC}` (for web application vectors).

### 5. Architectural Polish
* **Visual Truth:** Standard spaces (`U+0020`) are now explicitly rendered as Middle Dots (`·`) in "Reveal Mode," allowing for the detection of trailing whitespace and double-spacing errors.
* **Crash Prevention:** Hardened the `app.py` counters to handle complex metadata (lists) without type errors.
* **Gap Closure:** Added `U+FFF9`–`U+FFFB` (Interlinear Annotation) and `U+001B` (ESC) to the global forensic bitmasks to ensure no character escapes detection.

This output confirms the system is working as designed. The **Suspicion Dashboard** is robust, detailed, and prioritized correctly.

### What We Achieved (The Delta)
1.  **Semantic Precision:** The dashboard now correctly identifies `SYNTAX (CRIT)` for Trojan Source attacks, where previously it might have been lost in "Spoofing."
2.  **Visual Hierarchy:** The X-Ray is visually aligned (horizontal strip) and informative (script tags, drift highlights).
3.  **Noise Reduction:** The Emoji `🅰️` is no longer flagged as "Heavy Diacritics" (Zalgo), but rather as "Perturbation (1x Invisible)" due to the variation selector, which is forensically accurate.
4.  **Context Awareness:** Tokens like `Login:` and `//` are flagged as "SPOOFING (HIGH)" due to the `analyze_context_lure` logic, correctly identifying them as Phishing/Lure components rather than just "Latin text."


### 🛡️ Addendum: The "Adversarial Intelligence" Upgrade

**Session Goal:** To evolve Text...tics from a passive structural profiler into an active **Counter-Intelligence Instrument**. We implemented a deterministic "Adversarial Engine" capable of deconstructing complex deception vectors (Trojan Source, Homographs, Steganography) without relying on probabilistic AI or external APIs.

#### 1. The "Forensic Tokenizer" (Atomic Intent)
Standard whitespace splitting fails against adversarial text (e.g., `user[ZWSP]name`). We implemented a **Forensic Tokenizer** that isolates "Atomic Units of Intent" (identifiers, domains, filenames) while preserving internal punctuation and invisible perturbation payloads for analysis.

#### 2. The "Suspicion Dashboard" (Deep Forensics)
We introduced a high-level intelligence panel that aggregates risk across four distinct pillars of deception:
* **HOMOGLYPH (Ambiguity):** Measures visual confusion density using UTS #39 skeletons (e.g., Cyrillic `a` vs Latin `a`, `1` vs `l`).
* **SPOOFING (Structure):** Detects "Sore Thumb" anomalies (e.g., `paypa1` - single digit in letter run) and Script Mixing.
* **OBFUSCATION (Hidden):** Detects Zalgo (diacritic overload), invisible characters, and normalization hazards (shapeshifting tokens).
* **INJECTION (Syntax):** Detects Trojan Source (Bidi controls) and unauthorized tag characters.

**Features:**
* **Paranoia Peak:** Instantly isolates the single highest-risk token in the text (e.g., Risk: 98/100) for immediate triage.
* **Multi-Vector Stacking:** Tokens are no longer flagged with a single error; they carry a sorted "Threat Stack" (e.g., `[CRIT] Trojan Source` + `[HIGH] Mixed Script` + `[MED] Homoglyph`).
* **Context Lures:** Specific heuristics to flag authentication keywords (`Login:`, `Password`) and URL syntax (`//`) when they appear in suspicious contexts.

#### 3. The "Adversarial X-Ray" (Visual Evidence)
We replaced the linear "Perceived vs. Reality" list with a horizontal **"DNA Alignment Strip."**
* **Mechanism:** Vertically aligns the **Raw Text** (Reality) against the **UTS #39 Skeleton** (Perception).
* **Visual Drift:** Automatically highlights specific characters in **Red** where the visual appearance diverges from the underlying code point (e.g., `⓼` $\to$ `8`).
* **Cluster Grouping:** Intelligently groups contiguous threats (e.g., `x8 BIDI`) to prevent visual noise while maintaining forensic completeness.

#### 4. Steganography & Pattern Detection
We implemented a **Global Pattern Scanner** that analyzes the sequence of invisible characters.
* **Detection:** It identifies repeating cycles of non-printing characters (e.g., `ZWSP` $\to$ `ZWNJ` $\to$ `ZWSP` $\to$ `ZWNJ`).
* **Verdict:** Flags these patterns as **"Structured Invisible Patterns,"** a strong indicator of watermarking or covert channel data exfiltration.

#### 5. Zero-Inflation Logic (Mathematical Integrity)
We engineered a **"Unique Pillar Counting"** system to prevent stat inflation.
* **The Problem:** A single token with multiple flaws (e.g., `paypa1`) could previously inflate global counters by +3.
* **The Fix:** The engine now ensures that each token contributes exactly **once** to each relevant topology pillar, ensuring the "Scoreboard" reflects the *breadth* of the attack surface, not just the volume of errors.

---

## 🛡️ Update: The "Zero-Trust" & Adversarial Intelligence Upgrade

**Session Goal:** To transition **Text...tics** from a "Passive Microscope" (profiling what is there) to an **"Active Comparator"** (verifying identity against a trusted baseline). We have introduced a **Forensic Tokenization Layer** and a **Verification Bench**, allowing for deterministic detection of targeted spoofing attacks (e.g., Homoglyphs, Typosquatting) with surgical precision.

### 1. New Module: The Verification Bench ("Zero-Trust Comparator")
We implemented a dedicated workspace for **Reference-Based Forensics**. Unlike standard diff tools that check for byte equality, this instrument performs a **Quad-State Containment Analysis** to determine if a suspect string is a visual clone of a trusted reference.

* **Scope-Aware Analysis (The "Surgical" Update):**
    * **The Logic:** The engine now respects the user's DOM selection range (`selectionStart` / `selectionEnd`).
    * **Behavior:** Users can highlight a specific domain within a larger payload (e.g., just `pаypal.com` inside a phishing email body). The bench automatically switches scope from **FULL INPUT** to **SELECTION**, creating a "Suspect Monitor" readout that confirms exactly what data is being analyzed.
    * **Value:** Eliminates false negatives caused by surrounding noise (headers, protocols) and allows for precision targeting of suspicious artifacts.

* **The Forensic Lens (Visualizer):**
    * **Mechanism:** Instead of a simple "Diff," we implemented a **Contiguous Skeleton Matcher**. It identifies the "Hot Zone"—the longest sequence where the Suspect visually matches the Reference.
    * **Anchors vs. Payloads:**
        * **Anchor (Bold Black):** Characters that match the reference structurally and bitwise.
        * **Payload (Bold Red):** Characters that match the reference *visually* (Skeleton) but differ *physically* (Raw Bytes). This highlights the spoof (e.g., Cyrillic 'a') while keeping the context readable.
        * **Noise (Dimmed):** Characters outside the matched sequence are visually suppressed.

* **Fluid Intersection Meter:**
    * **Algorithm:** Replaced binary "Match/No-Match" logic with a floating-point **Containment Metric** (0.0% to 100.0%) based on `difflib.SequenceMatcher`.
    * **Context-Aware Metrics:**
        * **0% (Distinct):** Metrics explicitly state **N/A** (Uncorrelated) to prevent false "Diff" alarms on unrelated text.
        * **1–99% (Partial):** Metrics state **PARTIAL**, guiding the user to expand their selection.
        * **100% (Containment):** Triggers **TARGET LOCK**. Only at this stage does the engine issue a definitive **SPOOF CONFIRMED** or **IDENTITY MATCH** verdict.

### 2. Core Engine: The Forensic Tokenizer (Option A+)
To enable "Typosquatting" and "Sore Thumb" detection, we moved beyond whitespace splitting to a **Forensic Tokenization Strategy**.

* **The "Transparent" Logic:**
    * **Invisibles:** Characters like `ZWSP`, `Bidi Controls`, and `Tags` are treated as **Transparent Payloads**. They do *not* break a token. This ensures that `User[ZWSP]Name` is analyzed as a single unit, preserving the attack context for the "Invisible Density" scanner.
    * **Glue:** Alphanumerics and internal connectors (`_`, `-`) bind together to form semantic "Words."
    * **Fracture:** Structural delimiters (`.`, `/`, `@`, `:`) force atomic splits. This granular slicing allows the engine to analyze specific URL components (e.g., isolating a TLD or a subdomain).

### 3. New Intelligence: The Typosquatting Radar
Built on top of the Forensic Tokenizer, this module scans for structural lures specifically designed to deceive URL parsers and human eyes.

* **Pseudo-Delimiter Detection:**
    * Flags the use of **Confusable Separators** in domain contexts, such as the One Dot Leader (`․`, `U+2024`) masquerading as a Full Stop (`.`).
* **Double Extension Heuristics:**
    * Detects the classic malware masking pattern `[Safe_Ext].[Exec_Ext]` (e.g., `document.pdf.exe`).
* **Bidi Arrears (RTLO):**
    * Flags Right-to-Left Overrides specifically when they appear near file extensions (e.g., reversing `exe` to `fdp`), marking them as **CRITICAL (Syntax)** threats.

### 4. Integration & UI/UX Polish
* **Visual Hierarchy:** The **Verification Bench** was physically relocated below the **Character Inspector**, establishing a logical workflow: *Input → Macro Metrics → Micro Inspection → Target Verification*.
* **Adversarial Dashboard:** The "Suspicion Dashboard" was rewired to consume the new Tokenizer's output, populating the "Findings" list with specific **Typosquatting** and **Spoofing** alerts (e.g., "Mixed Script Label", "Pseudo-Delimiter").
* **Active Feedback:** Added a dynamic **Suspect Monitor** row that mirrors the user's selection in real-time, providing immediate visual confirmation of the analysis scope.


---

## 📈 Addendum #4: The "Forensic Chemistry" Upgrade (Statistical & Lexical Profile)

**Session Goal:** To complete Stage 1 by adding the missing dimension of **"Textual Thermodynamics."** While previous profiles analyzed the *physics* (structure, atoms, layout) of the text, this update implements the *chemistry* (distribution, density, and entropy). It answers the question: *"Is this text natural language, machine code, random noise, or an encrypted payload?"*

### 1. New Profile: Group 2.F (Statistical & Lexical)
We have implemented a comprehensive, serverless statistical engine that runs purely in the browser. It provides a rigorous, non-judgmental "soft signal" analysis of the text's information density and texture.

* **Thermodynamics (Shannon Entropy):**
    * **Method:** Calculates entropy on **UTF-8 Bytes** (0.0–8.0 bits/byte).
    * **Forensic Context:**
        * **< 3.0:** Repetitive padding or sparse data.
        * **3.0 – 4.5:** Natural Language (English/Latin prose).
        * **> 6.5:** High-density artifacts (Compressed archives, Encrypted payloads, or Random binary).
    * **Science:** Includes a **"Density" (Saturation)** metric and a **Sample Confidence** badge (Low/Moderate/Stable) to prevent misinterpretation of short strings.

* **Lexical Density (Forensic TTR):**
    * **Method:** Calculates Type-Token Ratio (Unique / Total).
    * **Upgrade:** Implements **6 Forensic Tiers** to handle TTR's natural length sensitivity. It distinguishes between "Bot-like Repetition" (<0.20), "Natural Prose" (0.40–0.60), and "High-Density Lists/UUIDs" (>0.80). Includes a **Segmented TTR** proxy for long texts.

* **Layout Physics (7-Point Stats + Mass Map):**
    * **The "Shape" of Data:** Replaced simple line counts with a full statistical breakdown: **Min**, **P25** (Lower Quartile), **Median**, **Mean**, **P75** (Upper Quartile), and **Max**.
    * **Mass Distribution Map:** A visual "Spark-Bar" that renders the density of the file from start to end. This instantly reveals if a payload is hidden at the bottom of a file or if the structure is uniform (e.g., a log file) vs. jagged (e.g., code).
    * **Logic:** Uses **Strict Visual Newline** splitting to match human perception.

* **Honest Frequency Fingerprint:**
    * **The "Invisible Majority":** Unlike standard frequency counters, this module operates in **"Honest Mode."** It explicitly visualizes **Whitespace** (Space, Tab, Newline) alongside letters and numbers.
    * **Visualization:** Uses a **Stacked Composition Bar** (Letters vs. Numbers vs. Symbols vs. Whitespace) to provide an immediate spectral signature of the data type (e.g., "Code" is symbol-heavy; "Prose" is letter-heavy).

* **ASCII Phonotactics (Gated):**
    * **Method:** Vowel/Consonant ratio analysis restricted strictly to ASCII Latin letters.
    * **Forensic Value:** Detects **Machine Code** (Base64, Hex keys) which typically have a V/C ratio < 0.20, contrasting with Natural English (~0.40).
    * **Visualization:** A "Sweet Spot" gauge showing deviation from natural language norms.

* **Heuristic Payload Detection (The "Silent Sentinel"):**
    * **Method:** Scans for contiguous strings > 16 chars matching **Base64** or **Hex** patterns.
    * **Entropy-Aware:** Calculates local entropy of the candidate string to distinguish "padding" (low entropy) from "actual payloads" (high entropy).
    * **UX:** This row is **hidden by default** and only renders a high-visibility alert row if a threat is detected.

### 2. UI/UX: The "Interactive Lab Console"
To manage the complexity of statistical data without overwhelming the user, we implemented a **Dynamic Console Pattern**.

* **Hover-to-Explain:** The static legend was replaced with a dynamic **"Lab Console"** at the bottom of the profile. Hovering over any metric row (e.g., Entropy) instantly updates the console with:
    * **Scientific Definition:** What is being measured?
    * **The Logic:** The formula used (e.g., $H = -\Sigma p(x) \log_2 p(x)$).
    * **Forensic Norms:** The expected ranges for natural vs. malicious text.
* **Micro-Card Layouts:** Layout Physics and Phonotactics use high-density **Micro-Card Grids** to present multiple data points (P90, Median, Counts) in a single, scannable row.

### 3. The Interaction Bridge (Data $\to$ Reality)
We closed the loop between abstract statistics and the raw text.

* **Click-to-Find:** Every "Top Token" and "Payload Candidate" is rendered as an interactive chip. Clicking a token (e.g., `'admin'`) triggers the **Forensic Finder**, which instantly scrolls to and highlights instances of that token in the raw input.
* **Clipboard Integration:** The **"Copy Full Report"** feature was upgraded with a Python-to-JS bridge (`py_get_stat_report_text`) to ensure the rich statistical profile is included in the plaintext evidence export.

***

## 🛡️ Addendum #5: The "State-Level" Forensic Upgrade (IDNA & Decode Health)

**Session Goal:** To elevate the tool from a "Passive Detector" to a **"Forensic Arbitrator."** We implemented a **Dual-Lens Architecture** that separates "Data Corruption" (Physical Integrity) from "Protocol Ambiguity" (Logical Safety), resolving the classic forensic noise problem where binary garbage is misidentified as a domain spoof.

### 1. Architectural Shift: The "Dual-Lens" System
We acknowledged that a text string exists in two simultaneous realities: as a **Byte Stream** (Storage) and as a **Network Identifier** (Protocol). We engineered two orthogonal lenses to analyze these realities without cross-contamination.

* **Lens A: The Decode Health Monitor (Integrity)**
    * **Scope:** The entire input stream.
    * **Mission:** Detect "Physical Rot"—characters that should never exist in valid interchange text.
    * **New Signals:**
        * **`U+FDD0..U+FDEF` (Process-Internal):** Now explicitly mapped and flagged as **DANGER**. These indicate internal memory leaks or fuzzer artifacts.
        * **`U+0000` (NUL):** Elevated to **FATAL** severity (Binary Injection).
    * **The "Traffic Light" Dashboard:** A new, high-priority row in the Integrity Profile that synthesizes a grade (e.g., `CRITICAL — Noncharacters; Null Bytes`) separate from the general heuristic score.

* **Lens B: The Protocol Ambiguity Engine (IDNA)**
    * **Scope:** Strictly gated. Only runs on tokens identified as **"Plausible Domain Candidates"** (must contain structure like `.` or `xn--` and pass a binary sanity check).
    * **Mission:** Detect "Logical Schisms"—domain labels that resolve differently depending on the software version (Browser vs. Backend).
    * **Dual-Source Truth:** We now cross-reference **UTS #46** (Compatibility/Transitional) against strict **IDNA2008** (RFC 5892) to identify gaps.

### 2. Deep Forensic Capabilities (The "Top Tier")

#### A. The "Plausibility Gate" (Noise Reduction)
We solved the "False Positive" crisis where binary blobs (`Sys﷐CoreDump...`) were generating thousands of "IDNA Violation" alerts.
* **Mechanism:** `is_plausible_domain_candidate(token)`
* **Logic:** If a token contains `NUL`, `Replacement Char`, or `Noncharacters`, it is immediately disqualified from Protocol Analysis. It is handed exclusively to the **Decode Health** lens.
* **Result:** 100% separation between "Corrupt Files" and "Malicious Domains."

#### B. Punycode Intelligence (Recursive Scanning)
The tool no longer just flags `xn--` as "Punycode." It performs a **Recursive Forensic Scan**:
1.  **Detect:** Identifies the ACE prefix.
2.  **Decode:** strips the prefix and decodes the payload to Unicode.
3.  **Analyze:** Runs the full threat engine on the *decoded* string.
4.  **Verdict:** If the *hidden* payload contains threats (e.g., `xn--broken-code` decoding to `br˓oken˓` with a forbidden Modifier Letter), it flags the Punycode itself as a **SPOOFING (CRIT)** vector.

#### C. The "Protocol Schism" Detector
We implemented a nuanced taxonomy for IDNA threats, moving beyond simple "Allowed/Disallowed" flags:
* **`AMBIGUITY` (Violet):** **Deviations** (e.g., `ß`, `ς`). Characters that change form between IDNA2003 and IDNA2008.
* **`GHOST` (Gray):** **Ignored** (e.g., `SHY`, `ZWJ`). Characters that exist in the clipboard but vanish in DNS resolution.
* **`COMPAT` (Gap):** **NV8/XV8**. Characters allowed by browsers (UTS #46) but forbidden by strict protocols (IDNA2008).
* **`INVALID` (Red):** **Strict Violations**. Characters strictly forbidden in all standards (e.g., Emoji in IDNA2008).

### 3. Visual & Taxonomy Calibration
We aligned the Code Taxonomy with the User Interface to ensure "Forensic Honesty."

* **Taxonomy Normalization:**
    * **`PROTOCOL`:** Now specifically refers to IDNA/Ambiguity issues.
    * **`INJECTION`:** Reserved for Bidi Overrides and Trojan Source attacks.
    * **`OBFUSCATION`:** Covers Invisible clusters, Ghosts, and Zalgo.
* **Visual Language:**
    * Added **Violet** badges (`.th-med`) for Protocol Ambiguity (signaling "Dual Nature").
    * Added **Strikethrough/Gray** badges (`.th-ghost`) for Ignored Characters (signaling "Disappearance").
    * Added **Red** badges (`.atlas-badge-crit`) for Internal Noncharacters in the Atlas.

### 4. Technical Specifications
* **Data Sources:** Added `IdnaMappingTable.txt` and `Idna2008.txt` to the virtual file system.
* **Performance:** All IDNA checks are O(1) lookups against pre-parsed sets.
* **Safety:** The IDNA engine explicitly whitelists ASCII Alphanumerics (A-Z, 0-9) to prevent "Boy Who Cried Wolf" alerts on standard text.


***

## 🛡️ Addendum #6: The "Scientific Threat Intelligence" Upgrade (AI Security & De-Obfuscation)

**Session Goal:** To transition the tool from a "Structural Profiler" to a **"Predictive Adversarial Simulator."** We integrated findings from three seminal academic papers on LLM Jailbreaking, NLP Evasion ("Charmer"), and Semantic Bias ("SSTA"), while strictly adhering to the "Post-Clipboard" (no raw byte) architecture.

### 1. New Core Engine: The "Scientific Threat Intelligence" Module (Group 2.F)

We implemented a dedicated analysis block (`[MODULE 6]`) powered by a **Forensic Threat Dictionary** derived from SecLists, FuzzDB, and LLM Jailbreak research.

* **LLM Jailbreak Detection (Paper 1: Special-Character Attacks):**
    * **Math Alphanumeric Spoofing:** Detects the substitution of Latin letters with Mathematical Bold/Italic symbols (`U+1D400` block) used to bypass tokenizers (e.g., `𝐇𝐞𝐥𝐥𝐨`).
    * **Invisible Fragmentation (The "Sandwich" Detector):** A surgical heuristic that flags invisible characters (`ZWSP`, `SHY`) *only* when they split two alphanumeric characters (e.g., `k<ZWSP>ill`). This distinguishes active tokenizer evasion from accidental formatting.
    * **TAG Injection:** Explicitly raised `U+E007F` (Cancel Tag) to **CRITICAL** severity as a known prompt injection signature used to "reset" LLM context windows.

* **Optimized Evasion Detection (Paper 2: Charmer):**
    * **Targeted Re-Assembly (High Fidelity):** Replaced global counting with a **"Re-Glue Engine."** It scans for fragmented micro-tokens (e.g., `s h e l l`) and attempts to re-assemble them into known dangerous keywords (`shell`, `admin`, `ignore instructions`) from a categorized threat vocabulary.
    * **Localized Fragmentation (Heuristic):** Detects contiguous runs of 4+ micro-tokens (len 1-3) as a fallback for unknown payloads.
    * **First-Character Weighting:** Updated the Homoglyph engine to assign higher risk scores if an anomaly occurs at **Index 0** of a token, violating standard "Robust Word Recognition" defense constraints.

* **Semantic Bias Detection (Paper 3: SSTA):**
    * **Symbol Flooding (Cascades):** Detects runs of >8 identical symbols (e.g., `~~~~~~`) used to manipulate model attention and sentiment classification.
    * **Punctuation Skew (Replacement Attack):** Calculates the ratio of "Grammatical" punctuation (`.`, `,`) vs. "Charged" symbols (`~`, `^`, `_`). High skew (>70% Charged) flags a "Replacement Attack" designed to alter classification without changing words.

### 2. New Core Engine: The "Deep-Dive" Normalizer (Recursive De-Obfuscation)

We acknowledged that attackers use the clipboard to transport *encoded* payloads. We implemented a recursive stripping engine (`recursive_deobfuscate`) that peels back layers until the "Naked Payload" is revealed.

* **Layer Support:**
    * **URL Encoding:** Recursive unquote (`%2522` $\to$ `%22` $\to$ `"`).
    * **HTML Entities:** Named, Decimal, and Hex decoding.
    * **Escape Sequences:** Unicode (`\uXXXX`), Hex (`\xHH`), and **Octal** (`\141`) escapes.
    * **SQL Evasion:** De-obfuscates concatenated `CHAR(83)+CHAR(69)...` patterns used in SQLi.
    * **Base64 Heuristic:** Detects and decodes Base64 blobs >16 chars if they resolve to high-entropy readable text.

* **The "Payload Alert" UI:** If layers are stripped, a high-visibility **"🚨 DEEP OBFUSCATION DETECTED"** alert is injected into the report, displaying the **Naked Payload** alongside the original input and listing the exact layers removed.

### 3. New Core Engine: The "Predictive Attack Simulator"

We moved beyond analyzing what the text *is* to predicting what it *will become* when processed by backend systems.

* **WAF Policy Simulator:**
    * Scans the "Naked Payload" against a hardened blacklist (derived from SiteMinder/Broadcom research) to detect **XSS** (`<script>`, `javascript:`), **SQLi** (`UNION SELECT`, `DROP TABLE`), and **Path Traversal** (`../`, `\`) vectors.
* **Predictive Normalizer Table:**
    * Generates a comparative preview of the text under **NFC**, **NFD**, **NFKC**, and **NFKD** forms.
    * **Visual Drift:** Highlights characters that change identity (e.g., `U+FF1C` Fullwidth `<` $\to$ ASCII `<`) in **Red**, flagging "Normalization Injection" risks.
* **Case Collision Simulator:**
    * Detects "Length Expansion" attacks (e.g., `ß` $\to$ `SS`) that cause buffer overflows.
    * Detects "WAF Bypass" vectors (e.g., `ſ` (Long S) $\to$ `S`, `ı` (Dotless I) $\to$ `I`).

### 4. New Heuristic: "Code Masquerade" (Solders Malware)

* **Logic:** Detects text that has valid code syntax (`{`, `}`, `function`, `=>`) but uses "Alien" (non-Latin) scripts for identifiers.
* **Target:** Specifically identifies the obfuscation technique used in the `solders` npm malware package (Katakana variable names).

### 5. Architectural Refinements

* **Unified Threat Scoring:** The "Score Soup" problem was resolved. The Global Threat Score is now derived from the **Maximum Token Risk**, ensuring that a single Critical (100) token correctly flags the entire document as "WEAPONIZED."
* **Bidi Context:** Updated Bidi control messaging to explicitly warn of **"AI Prompt Injection"** alongside "Trojan Source."
* **Punycode Forward-Prediction:** The "IDNA Lens" now shows the **Wire Format** (`xn--...`) for any Unicode domain, allowing the analyst to see the ASCII reality of a Homoglyph domain.

* **Overlay Confusable Engine:** Implemented a dedicated "Atomic Twin" scanner for combining overlays (`U+0334`–`U+0338`). It mathematically proves when a base character + overlay (e.g., `O` + `̸`) mimics a precomposed letter (`Ø`), exposing a high-value normalization bypass vector often missed by standard NFKC.
* **4-Tier Forensic Legality:** The Invisible Atlas now categorizes hidden characters by **Security Utility** rather than just Unicode properties. It distinguishes **Benign Typographic** glue (Tier 0) from **Fatal Protocol Violations** (Tier 3: Tags, Nulls), providing immediate triage between "bad text" and "malware."
* **Unicode 17.0 Readiness:** Hardened the "Syntax Spoofing" heuristics to align with the new **Sibe Quotation** standard. Variation Selectors attached to delimiters are rigorously flagged as **SUSPICIOUS**, countering the specific "Syntax-Masking" threats identified in the 17.0 spec.

* **Adversarial Token Intelligence:** A dedicated counter-intelligence module that shifts analysis from "Global Stats" to **"Per-Token Forensics."** It features a **"Sticky" Forensic Tokenizer** that captures invisible characters *inside* identifiers (preventing token-splitting evasion) and a **Skeleton Collision Radar** that deterministically proves Homograph Attacks by flagging distinct tokens that share the same UTS #39 visual skeleton (e.g., `paypal` vs `pаypal`).
* **Segmentation Complexity Verdict:** A heuristic engine embedded in the Grapheme Profile that assigns a stability grade (**LOW / MED / HIGH**) to the text's rendering structure. It specifically detects **Stacking Abuse (Zalgo)** by measuring the density of combining marks per cluster, flagging sequences that threaten rendering engines or visual stability.
* **Whitespace & Line Ending Topology:** A "Frankenstein Detector" that analyzes the invisible substrate of the text. It exposes **Mixed Line Endings** (consistency failures like `CRLF` mixed with `LF`) and **Deceptive Spacing** (mixing ASCII Space with Non-Breaking Space), providing immediate evidence of "patchwork" text origin or active phishing obfuscation.


## 🛡️ Addendum #7: The "Stage 1.5" Adversarial Intelligence Upgrade

**Session Goal:** To transition the tool from **Passive Profiling** (what characters *are*) to **Active Threat Hunting** (what characters *do*). We implemented a "Stage 1.5" layer that detects active exploitation attempts against LLMs, SQL parsers, and WAFs without requiring semantic understanding.

### 1. New Engine: The "Syntax Predator" (Global Injection)
We implemented a deterministic detector for **Normalization-Activated Injection** attacks, a class of vulnerability where safe characters "shapeshift" into dangerous syntax after backend normalization.

* **The Threat:** Attackers bypass WAFs by using fullwidth or compatibility characters (e.g., `U+FF07` Fullwidth Apostrophe) that normalize to syntax triggers (e.g., `'`) *after* the security check.
* **The Defense:** The Syntax Predator Engine scans the **Raw** vs. **NFKC** delta against three hardened hazard sets (`HAZARD_SQL`, `HAZARD_HTML`, `HAZARD_SYSTEM`).
* **Verdict:** If a safe character transforms into a hazard, it triggers **"CRITICAL: Normalization-Activated Injection"**.

### 2. New Engine: The "Fracture Scanner" (Token Evasion)
We engineered a **Precision State Machine** to detect "Invisible Sandwich" attacks designed to shatter LLM tokenization.

* **The Threat:** Injecting Emoji or Invisible characters *inside* a word (e.g., `sens😎itive`) to force the tokenizer to split it into harmless sub-tokens (`sens`, `😎`, `itive`), bypassing safety filters.
* **The Defense:**
    * **Greedy Tokenizer:** Replaced regex splitting with a manual whitespace scanner to capture the "sandwich" as a single token.
    * **Fracture Logic:** Implemented a strict `Alpha` $\to$ `[Fracture Agent]` $\to$ `Alpha` state machine.
    * **Agent Definition:** Strictly defined "Fracture Agents" as **Invisibles**, **Tags**, **Joiners**, or **Non-Alphanumeric Emojis**, ensuring standard punctuation (e.g., `file.txt`) does not trigger false positives.
* **Verdict:** Flags `sens😎itive` as **"R99: Token Fracture (Mid-Token Injection)"** with a **CRITICAL** risk score.

### 3. New Engine: The "Shapeshifter" (Visual Drift)
We formalized the detection of **Identity Instability** tokens that change meaning or length when normalized.

* **The Threat:** Attacks relying on "Ghost Characters" that vanish (e.g., Soft Hyphens in usernames) or "Identity Maps" (e.g., `admın` (Dotless i) $\to$ `admin`) to spoof identity or bypass logic.
* **The Defense:** Calculates the **Binary Drift** (`Raw` vs `NFC`) and **Visual Drift** (`Raw` vs `NFKC-Casefold`) for every token.
* **Verdict:** Flags tokens with **"NFC Length Change"** or **"Visual Drift"**, creating a forensic audit trail for spoofing attempts.

### 4. Architectural Hardening (The "Paranoia Peak")
To support these new engines, we upgraded the core **Risk Scoring & UI Architecture**:

* **Scoring Logic:** Updated the `compute_threat_score` Auditor to include "Multi-Vector Correlation," boosting the score if an attack combines Execution (Injection) with Obfuscation (Fracture).
* **Leaderboard Sorting:** Enforced a strict re-sort of the "Paranoia Peak" (Top Offender) to ensure that high-scoring Token Fractures (75+) correctly displace lower-scoring generic payloads (45).
* **Stack integrity:** Implemented explicit "Visual Stacks" for tokens to prevent badge collision (e.g., ensuring a Fracture correctly displays the `OBFUSCATION` badge instead of a generic `PROTOCOL` badge).

### Six Papers - Adversarial Intelligence & Forensic Hardening

**Session Summary:**
In this session, we evolved **Text...tics Stage 1** from a "Structural Profiler" into an **"Active Adversarial Intelligence Engine" (Stage 1.5)**. We integrated cutting-edge forensic logic derived from **six seminal security papers** (Boucher et al. 2022, Dionysiou & Athanasopoulos 2021, Cooper et al. 2025, Sakpal 2025, Daniel & Pal 2024, OWASP 2014), closing critical gaps in the detection of tokenizer evasion, visual spoofing, and DoS vectors.

### 1. New Forensic Engines (The Detectors)

We implemented **nine** new specialized detection engines, each targeting a specific class of attack identified in the literature.

* **The "Ghost" Scanner (Visual Deletion)**
    * *Source:* *Bad Characters* (Boucher et al., 2022).
    * *Logic:* Detects characters that actively modify cursor position to "erase" previous content (Backspace `U+0008`, Delete `U+007F`, Carriage Return `U+000D`).
    * *Verdict:* **CRITICAL (Execution)**. Flags "Active Deception" where the visual string differs from the logical payload without normalization.
    * *Impact:* Closes the "Browser Boundary" gap by treating raw control codes as payloads, not editing operations.

* **The "Fracture" Scanner v2 (Syntax Sandwich)**
    * *Source:* *A Survey on Emoji...* (Sakpal, 2025) & *Bad Characters*.
    * *Logic:* Detects alphanumeric runs split by **Emojis**, **Invisibles**, or **Tags** (e.g., `print🚀data`, `sys<ZWSP>tem`).
    * *Verdict:* **CRITICAL (Obfuscation)**. Identified as the primary vector for "Jailbreaking" tokenizers and bypassing safety filters.
    * *Impact:* Upgraded the previous "Invisible Fragmentation" logic to include visible Emojis as functional separators.

* **The "Jailbreak Alphabet" Detector (Evasion Styles)**
    * *Source:* *Impact of Non-Standard Unicode...* (Daniel & Pal, 2024).
    * *Logic:* Detects usage of specific Unicode blocks proven to bypass LLM safety filters. Tracks **20+ sets** including Mathematical Alphanumerics (Bold/Italic), Enclosed Alphanumerics (Circled/Squared), Braille Patterns, and Plane 14 Tags.
    * *Verdict:* **CRITICAL/HIGH (Spoofing/Injection)**. Assigns risk based on the "Alien" quality of the block.

* **The "Normalization Bomb" Detector (Inflation DoS)**
    * *Source:* *Fun with Unicode* (OWASP, 2014).
    * *Logic:* Detects single characters that expand significantly (>10 chars) upon NFKC normalization (e.g., `U+FDFA` $\to$ 18 chars).
    * *Verdict:* **WARN (DoS)**. Identifies potential buffer overflow or resource exhaustion vectors targeting fixed-width backends.

* **The "IDNA Compression" Detector**
    * *Source:* *Fun with Unicode* (OWASP, 2014).
    * *Logic:* Detects non-ASCII characters that normalize to multi-character ASCII strings in IDNA/NFKC (e.g., `U+33C5` ㏅ $\to$ `cd`).
    * *Verdict:* **HIGH (Spoofing)**. Flags attempts to spoof ASCII keywords using complex symbols that "compress" down.

* **The "Deep Fragmentation" Engine (Re-Assembly)**
    * *Source:* *Unicode Evil* (Dionysiou et al., 2021) & *Charmer* logic.
    * *Logic:* Attempts to "re-glue" fragmented micro-tokens (e.g., "s", "h", "e", "ll") to see if they form high-value threat words from a forensic vocabulary (Execution, Auth, Injection).
    * *Verdict:* **CRITICAL (Evasion)**.

* **The "Punctuation Skew" Analyzer**
    * *Source:* *The Lies Characters Tell* (Cooper et al., 2025).
    * *Logic:* Calculates the ratio of "Charged" symbols (used in exploits like `~`, `_`, `^`) versus "Grammatical" symbols (`.`, `,`).
    * *Verdict:* **WARN (Semantic Bias)**. Detects "Replacement Attacks" where symbols flood text to manipulate model attention.

* **The "Lexical Stutter" Scanner (Doubling)**
    * *Source:* *Unicode Evil* (Dionysiou et al., 2021).
    * *Logic:* Detects exact-repeat substrings within a single token (e.g., `adminadmin` or `badbad`), a proven method for evading sentiment/toxicity classifiers.
    * *Verdict:* **MEDIUM (Obfuscation)**.

* **The "Hardened Tokenizer" (Option A)**
    * *Source:* Architectural Requirement.
    * *Logic:* Updated to return **Dictionaries** instead of Objects/Strings to resolve critical type errors and ensure compatibility with the new Adversarial Engine.

### 2. Unified Reporting Architecture

We solved the "Split Brain" reporting problem by implementing a **Bridge Mechanism**.

* **Adversarial Dashboard (Group 4):** The primary home for detailed forensic analysis. Displays per-token risk stacks, decoding layers, and paranoia peaks.
* **Threat Flags (Group 3):** The "Bridge" now promotes **CRITICAL** and **HIGH** findings from the Adversarial Engine up to the main Threat Profile summary. This ensures that a "Token Fracture" found deep in the token list is visible immediately in the high-level report.
* **Integrity Profile (Group 2.C):** Continues to track "Rot" and "Structure" (e.g., Legacy Control Chars), maintaining the "Dual-Ledger" separation of concerns.

### 3. Validation Status

The system has been verified against the `ULTIMATE_STRESS_TEST` string, confirming correct detection and reporting for:
* [x] **Ghost Chars** (`Safe[BS]...`) -> **CRITICAL**
* [x] **Token Fracture** (`sys[ZW]tem`, `print🚀data`) -> **CRITICAL**
* [x] **IDNA Compression** (`corp.㏅.com`) -> **HIGH**
* [x] **Lexical Stutter** (`adminadmin`) -> **MEDIUM**
* [x] **Math/Tag Evasion** (`𝐀𝐝𝐦𝐢𝐧`) -> **CRITICAL**

🛡️ Addendum #8: The "Stage 1.5" Adversarial Intelligence Upgrade

Session Goal: To transition the tool from a "Passive Structural Profiler" (what characters are) to an "Active Forensic Hunter" (detecting specific patterns of evasion, spoofing, and injection). This upgrade integrates insights from five seminal security papers (2018–2025) on RAG Poisoning, IDN Masquerading, and AI Agent Exfiltration.

1. Architectural Philosophy: "Physics vs. Judgment"

We enforced a strict architectural boundary to maintain the tool's integrity as a "Lab Instrument":

Stage 1 (The Detectors): Pure, neutral "Physics Engines" that report observable facts (e.g., "This string contains ANSI codes"). They never assign risk scores.

Stage 1.5 (The Auditors): A "Policy Layer" that interprets those facts through specific heuristics (e.g., "ANSI codes in a prompt context = High Risk"). This ensures we don't conflate capability with intent.

2. New Forensic Modules

A. The "Token Fracture" Scanner (The Persian Defense)

Source: The Hidden Threat in Plain Text (2025).

The Threat: Attackers insert invisible characters inside keywords (e.g., vio<ZWSP>lent) to break LLM tokenization and bypass safety filters.

The Defense: A script-aware engine detects [Alpha] + [Invisible] + [Alpha] patterns.

The "Persian Defense": Crucially, we implemented a whitelist for complex scripts (Arabic, Syriac, N'Ko, etc.) where ZWJ/ZWNJ are legitimate orthographic tools. This prevents false positives on non-Latin languages, respecting global typography while catching Latin evasion attempts.

B. The "Injection Pattern" Matcher

Source: Exploiting Web Search Tools of AI Agents... (2025).

The Threat: "Indirect Prompt Injection" via web content.

The Defense:

ANSI Escape Detection: Flags terminal control sequences (\x1b[...]) used to manipulate logs or model output (proven 12% success rate).

Imperative Overrides: Detects structural patterns of "Jailbreak" syntax (e.g., "Ignore previous instructions", "System Prompt Override").

Tool Chaining: Identifies syntax designed to hijack agent tools (e.g., "Search for X and send to URL").

C. The Domain Structure Scanner (IDN Masquerading)

Source: Large Scale Detection of IDN Domain Name Masquerading (2018).

The Threat: Homoglyph spoofing in Internationalized Domain Names.

The Defense:

Script Mixing: Detects labels mixing conflicting scripts (e.g., Latin + Cyrillic) which is a primary phishing indicator.

Pseudo-Delimiters: specific detection of characters that mimic structural syntax (e.g., U+2024 One Dot Leader mimicking .).

Skeleton Collision: Flags when a non-ASCII domain's visual skeleton matches a pure ASCII string.

D. The "Legal Clarity" Inspector

Source: Emojis: An Approach to Interpretation (2024).

The Threat: Courts misinterpreting emojis due to cross-platform rendering differences.

The Defense:

Decomposition View: The Inspector now breaks down emoji sequences into their "Bill of Materials" (Base + Glue + Modifier).

Ambiguity Flag: Explicitly warns users if an emoji lacks a specific Variation Selector (VS16) or Emoji Presentation property, signaling that it may render as text on some devices and color graphics on others.

3. "Sidecar" Implementation Strategy

To protect the stability of the existing codebase, these features were implemented as an Additive Sidecar:

Isolated Engines: New logic resides in standalone functions (scan_token_fracture_safe, scan_injection_vectors).

Soft Merge: Results are computed in parallel and merged into the final report only at the last step.

Zero Regression: Existing "Stage 1" logic remains untouched and authoritative.

---

## 🛡️ Addendum #9: The "Adversarial Physics" & Contextual Lure Upgrade (Stage 1.5)

**Session Goal:** To elevate the tool from a **Structural Profiler (Stage 1)** to an **Adversarial Physics Engine (Stage 1.5)**. We integrated actionable intelligence from the "Golden Trio" of security papers (*Trust No AI*, *TRAPDOC*, *Trojan Source*), transitioning the system from passive measurement to active anomaly detection without violating the "Post-Clipboard" boundary.

### 1. Architectural Pivot: Physics vs. Policy
We formalized the separation between **Measurement** (Sensors) and **Judgment** (Auditors) to prevent false positives in complex scripts.

* **The Physics Layer (`AdversarialEngine`):** A set of deterministic sensors that report observable facts (e.g., "This token contains a mid-word ZWSP"). It does *not* assign severity.
* **The Policy Layer (`ThreatAuditor`):** A logic engine that interprets physical facts based on context. It decides whether a mid-word ZWSP is a **"Token Fracture Attack"** (in Latin text) or valid orthography (in Persian/Arabic).

### 2. New Detection Engines (The "Golden Trio" Implementation)
We implemented three targeted scanners to detect "Blind Spot" attacks that bypass standard tokenizers and filters.

#### A. The "Fracture" Scanner (Source: *TRAPDOC*)
* **The Threat:** Attackers inject invisible characters inside words (e.g., `P<ZWSP>rint`) to break LLM tokenization and bypass safety filters.
* **The Logic:** `scan_token_fracture_safe` detects the specific pattern `[Alpha] + [Invisible] + [Alpha]`.
* **The "Persian Defense":** A sophisticated whitelist mechanism that ignores legitimate ZWJ/ZWNJ sequences in complex scripts (Arabic, Syriac, Indic), ensuring the tool flags only actual evasion attempts without punishing non-Latin languages.

#### B. The "Protocol Smuggler" Scanner (Source: *Trust No AI*)
* **The Threat:** Using non-printing characters to execute code or exfiltrate data.
* **The Logic:** `scan_injection_vectors` scans for two specific high-fidelity signatures:
    * **Plane 14 Tags (`U+E0000`+):** Flagged as **CRITICAL**. These have zero valid use in plain text and are a known vector for "ASCII Smuggling."
    * **ANSI Escape Sequences (`\x1b[...]`):** Flagged as **Terminal Injection Risk**. Detects attempts to hijack developer consoles or spoof logs.

#### C. The "Contextual Lure" Scanner (Source: *Trust No AI*, *WASA*)
* **The Threat:** Exploiting the *application layer* (Chat UI, Markdown parsers, Memory) rather than the LLM itself.
* **The Logic:** `scan_contextual_lures` detects three specific application-layer attacks:
    1.  **Markdown Exfiltration:** Detects `![alt](url)` patterns used to auto-trigger GET requests and leak chat context to third-party servers.
    2.  **Chat Masquerade:** Detects fake conversation headers (e.g., `<|im_start|>`, `[INST]`) used to confuse the model's turn-taking logic.
    3.  **Memory Poisoning (SpAIware):** Detects persistence directives (e.g., "store in memory", "always reply with") used to implant permanent instructions in the user's profile.

### 3. The Forensic Visual System (UI/UX Upgrade)
We overhauled the visualization layer to support "High-Density Forensics."

* **The Forensic X-Ray:** A vertical "DNA Alignment" view that renders the **Raw** string vs. the **UTS #39 Skeleton**. It uses clustering logic to hide safe text and zoom in on "Drift Hotspots," visualizing exactly where the visual appearance diverges from the logical reality.
* **The Adversarial Dashboard:** A dedicated "Scoreboard" module that categorizes threats into **Spoofing**, **Obfuscation**, **Injection**, and **Ambiguity**, complete with a "Paranoia Peak" row that highlights the single highest-risk token in the document.
* **The Token Risk Ledger:** A detailed table view of every suspicious identifier, sorting them by risk severity (CRITICAL > HIGH > MED) and exposing their internal script composition.

### 4. Validation & Completeness Audit
We performed a "Red Team" audit against external threat intelligence (AWS Security Blog, Neural Computing NMT papers) and confirmed **Forensic Completeness**.
* **Unicode Tag Smuggling:** Covered by the **Protocol Smuggler** engine.
* **Homoglyph Phishing:** Covered by the **Skeleton Drift** metric.
* **Invisible NMT Attacks:** Covered by the **Fracture Scanner** and **Ghost Scanner** (Visual Redaction).

---

## 🛡️ Addendum #10: The "Adversarial Physics" Upgrade (Stage 1.5)

**Session Goal:** To bridge the gap between **Stage 1** (Structural Profiling) and **Stage 2** (Semantic Analysis) by implementing a **Stage 1.5 "Adversarial Physics" Layer**. This update integrates actionable intelligence from eight seminal security papers (including *Mandiant*, *Emoji Attack*, and *Imperceptible Jailbreaking*) to detect structural weaponization without crossing into semantic interpretation.

### 1. Architecture: The Sensor/Policy Split
We enforced a strict separation of concerns to maintain the tool's determinism while increasing its forensic sensitivity.

* **The Sidecar Sensors (Block 1):** Pure logic engines that measure physical phenomena (e.g., "A run of 5 Variation Selectors exists"). They return raw metrics, not verdicts.
* **The Threat Auditor (Block 4):** A policy engine that interprets these metrics. It decides that "5 Variation Selectors" = **CRITICAL: Steganography Risk**, whereas "1 Variation Selector" = **CLEAN**.
* **Impact:** This adheres strictly to **ADR-006 (Dual-Ledger)**, ensuring that the tool remains a neutral instrument of measurement rather than a biased "content filter."

### 2. New Forensic Capabilities (The "Physics Engines")

We implemented four specific detection engines based on confirmed "In-the-Wild" attack vectors.

#### A. The "Fracture" Scanner (Source: *Emoji Attack*)
* **The Threat:** Attackers insert characters inside words (e.g., `b🔥omb` or `vio<ZWSP>lent`) to shatter tokenizer boundaries (BPE/SentencePiece), allowing harmful tokens to bypass safety filters.
* **The Upgrade:** We upgraded the fracture logic to recognize **Emojis** as "Fracture Agents" alongside invisible characters.
* **The "Persian Defense":** To prevent false positives, we implemented a script-aware whitelist. The engine explicitly ignores `ZWJ`/`ZWNJ` fractures if the surrounding context is a complex script (Arabic, Syriac, N'Ko), preserving valid orthography while catching Latin evasion attempts.

#### B. The Variation Selector (VS) Topology Engine (Source: *Imperceptible Jailbreaking*)
* **The Threat:** Using runs of invisible Variation Selectors (`U+FE0F` repeated 10x) to hide payloads or shift embedding vectors without altering visual rendering.
* **The Logic:** The engine now tracks **VS Clusters**.
    * **Length > 1:** Flagged as **Redundant** (Structurally unnecessary).
    * **Length > 4:** Flagged as **CRITICAL: High-Density Sequence** (Likely Steganography).
    * **Bare VS:** Flagged as **Artifact/Fuzzing** (VS without a valid base).

#### C. The Delimiter Masking Engine (Source: *Mandiant: Text-to-Malware*)
* **The Threat:** Using "Deceptive Spaces" that render as blank but are technically Symbols (not Separators) to mask file extensions (e.g., `malware.mp4[U+2800].exe`).
* **The Logic:** We mapped `U+2800` (Braille Pattern Blank) to a new `MASK_SUSPICIOUS_SPACE` bitmask. The engine scans for the pattern `[Suspicious Space] + [Dot] + [AlphaExtension]`.
* **Verdict:** Triggers **CRITICAL: Malware Extension Masking**.

#### D. The Tag Payload Decoder (Source: *Bypassing Guardrails*)
* **The Threat:** Hiding readable instructions inside Plane 14 Tag Characters (`U+E0000` block).
* **The Logic:** We implemented a decoder that shifts Tag Codepoints back to ASCII (`Tag 'A'` $\to$ `'A'`).
* **Verdict:** If a payload is reconstructed, it triggers **CRITICAL: Hidden Tag Payload**, displaying the decoded text in the forensic report.

### 3. Scope Discipline (What We Rejected)
To preserve the "Post-Clipboard" philosophy, we explicitly **rejected** semantic features suggested by the research papers, such as "Lexical Rarity Scores" or "Dictionary Definition Detection." These belong in Stage 2. Stage 1.5 remains strictly focused on the **physics** of the text string.

### 4. Validation
The system has been verified against the `b🔥omb` (Token Fracture) and `malware.mp4⠀.exe` (Extension Masking) vectors, correctly identifying them as **CRITICAL** threats in the Dashboard while maintaining a **CLEAN** verdict for standard text.
This component addresses the limitation of any "Post-Clipboard" analyzer: the deliberate loss of styling metadata.

### 5. Metadata Workbench & CSS Stealth Detector

This component addresses the primary limitation of any "Post-Clipboard" analyzer: the deliberate loss of styling metadata.

* **The Flaw in Plain Text:** While the main input successfully analyzes the character-level payload for the LLM (the **structural threat**), it deliberately strips CSS formatting. This could allow attackers to camouflage large payloads of malicious text using visual styles (e.g., white text on a white background or `visibility: hidden`).
* **The Architecture (Dual-Input):** We implemented a dedicated, opt-in `contenteditable` **Metadata Workbench** input mode that captures the raw `text/html` string directly from the clipboard. This preserves the original visual context.
* **The Analysis:** A new Python engine (`analyze_html_metadata`) scans this raw HTML string for **CSS Obfuscation** signatures, including `visibility: hidden`, `opacity: 0`, off-screen positioning, and explicit white-on-white low-contrast rules.
* **Forensic Correlation:** This module functions as a **complementary tool**. It confirms *how* the text was visually hidden on the source website, validating the findings already present in the main Structural Integrity Profile.

---

### 🛡️ Update: The "Quad-Ledger" HUD & Master Auditor (Stage 1.5 Finalization)

**Session Goal:** To transition the application's top-level reporting from a binary model (Integrity vs. Threat) to a professional-grade **"3+1" Risk Architecture** aligned with modern SIEM/CVSS standards. We separated "Malice" (Execution) from "Identity" (Spoofing) and "Complexity" (Anomaly).

#### 1. Architecture: The Master Auditor (Block 7)
We implemented a new orchestration layer in **Block 7** (`audit_master_ledgers`) that reorganizes forensic signals into four orthogonal axes without altering the underlying physics engines.
* **Integrity:** Data health, decoding reliability, and structural rot (Absorbed "Decode Health").
* **Authenticity (New):** Dedicated to Identity verification. Aggregates IDNA violations, Skeleton Drifts, and Mixed-Script spoofing.
* **Threat:** Focused strictly on Weaponization (Execution, Injection, malicious Obfuscation).
* **Anomaly (New):** A "Physics" ledger measuring Entropy, Zalgo density, and structural weirdness.

#### 2. UI/UX: The "Verdict Bar" (Block 9 & CSS)
We replaced the linear metric list with a high-density **Verdict Bar**.
* **Renderer:** Implemented `render_forensic_hud_v2` as a parallel function to safely supersede the legacy display.
* **Visuals:** Added a CSS Grid architecture (`.hud-verdict-row`) supporting "Hero Cards" with distinct color themes (Red/Critical, Amber/Warning, Green/Safe) and interactive drill-down values.

#### 3. Logic Hardening: The Data Flow Repair (Block 10)
We resolved a critical dependency cycle in the `update_all` orchestrator.
* **The Bug:** The `audit_master_ledgers` function required a calculated `ledger` object (from `compute_threat_score`) but was receiving the raw `threat_results` report, causing a `KeyError`.
* **The Fix:** We refactored `update_all` to explicitly calculate `final_score` (inputs + logic) locally before passing it to the Master Auditor. This ensures the "Threat" column in the HUD matches the detailed "Threat-Hunting" profile exactly.

**Result:** The tool now presents a holistic, multi-dimensional security posture (Physical Health, Identity Trust, Active Threat, Structural Anomaly) at a single glance.

### Group 1.5: The Forensic HUD (V3)
The Head-Up Display has been re-architected into a **Split-Data System**.

* **The Problem:** Previous versions baked labels like "Logic:" directly into the data string. This caused alignment errors in the fixed-width CSS grid of the console, creating empty visual gaps when labels were missing.
* **The Solution (V3):**
    1.  **Python Layer:** The `render_forensic_hud` function now generates **Atomic Attributes**. It sends `data-k1="LOGIC"` and `data-v1="Entropy"` as separate signals.
    2.  **JavaScript Layer:** The `ui-glue.js` bridge reads these attributes separately and injects them into distinct DOM spans (`.console-key` and `.console-val`).
    3.  **Result:** Zero visual gaps. If a Key is missing, the CSS grid collapses cleanly. If present, it aligns perfectly to the 50px grid line.

🆕 New Section: Group 2.F: Forensic Chemistry (Thermodynamics & Lexical)
This module analyzes the "texture" and information density of the text, answering the question: "Is this natural language, machine code, or encrypted data?"

Thermodynamics (Shannon Entropy):

Calculates the bit-density of the UTF-8 byte stream.

Forensic Ranges: <3.0 (Sparse/Repetitive), 4.5 (Natural Text), >6.5 (Encrypted/Compressed).

Visuals: A gradient density bar indicating the "Saturation" of the information content.

Lexical Density (Forensic TTR):

Measures vocabulary richness using Type-Token Ratio.

Forensic Value: Detects "Bot-like" repetition (<0.20) vs. "UUID/Hash" density (>0.90).

Layout Physics (Topology):

Sparkline Mass Map: A visual heatmap showing the density of line lengths from start to end. instantly reveals hidden payloads (e.g., a massive base64 blob at the end of a log file).

7-Point Distribution: Min, Mean, Median, P75, P90, Max statistics for line lengths.

ASCII Phonotactics:

Analyzes the Vowel/Consonant ratio of Latin text to detect Machine Code (Ratio < 0.20) vs. Natural Language (~0.40).

Structural Anomalies (The Roster):

A dedicated list of every cluster violating physical structure limits.

Visual Classification: Differentiates between Visible Zalgo (🔥) and Invisible/Steganographic Stacks (👻).

🛠️ Update: The Quad-Ledger HUD (Heads-Up Display)
The dashboard has been re-architected to enforce a strict "Physics vs. Policy" separation.

The 4 Axes of Risk:

Integrity: Data health (Rot, Corruption, Encoding Errors).

Authenticity: Identity verification (Spoofing, Homoglyphs).

Threat: Active weaponization (Execution, Injection).

Anomaly: Structural physics (Entropy, Zalgo).

The "Two-Number" System:

Center Counter (Signals): The raw Physics Count. How many anomalies exist? (e.g., "7 Zalgo Clusters").

Left Score (Risk/Deviation): The Policy Verdict. Does this matter? (e.g., "Score: 0 (Benign)" if the clusters are small).

Interactive Navigation: Clicking the Signal Count triggers the Forensic Stepper, instantly scrolling to and highlighting specific anomalies in the text.
C. The "Zalgo Gradient" Taxonomy
We moved beyond binary "Zalgo Detection" to a 3-Tier Forensic Taxonomy. The tool now forensically distinguishes intent based on stack density:

Tier 1: Dense Cluster (3–5 marks): Flagged as Amber. Likely complex linguistics (e.g., Vietnamese, IPA) or mild typos.

Tier 2: Heavy Stack (6–15 marks): Flagged as Amber/Red. Intentional visual modification.

Tier 3: Zalgo Overload (16+ marks): Flagged as Red. Active Rendering Denial-of-Service (DoS) risk.

D. The Quad-Ledger Finalization
You can now formally document the "3+1" Risk Architecture as complete.

Integrity: Rot/Corruption (Shield).

Authenticity: Identity/Spoofing (ID Card).

Threat: Weaponization/Malice (Target).

Anomaly: Physics/Deviation (Scatter Plot). Note: Explicitly distinct from "Health".

***

### 🛡️ Update: The Invisible Atlas V3.1 (Forensic-Grade Instrument)

**Session Goal:** To transition the Invisible Character Atlas from a "Passive Legend" to a **"Scientifically Exhaustive Forensic Instrument."** We moved beyond simple character counting to a robust, **9-column** architecture that exposes the **Security Physics** of every hidden particle.

#### 1. Scientific Hardening & Terminology
We conducted a rigorous audit against **Unicode 16.0** and **UTS #39** standards to eliminate vague or misleading terminology.
* **Precision Naming:** Replaced generic fallback names ("UNASSIGNED") with a dedicated **C0/C1 Control Lookup Engine**, ensuring characters like `U+000A` are correctly identified as `LINE FEED (LF)`.
* **Bidi Specificity:** Abandoned the generic `[BIDI]` tag in favor of precise, forensic mnemonics: `[RLO]` (Right-to-Left Override), `[LRI]` (Isolate), `[PDF]` (Pop Directional Formatting). This allows analysts to distinguish between "Trojan Source" weapons and standard grammar.
* **Risk Taxonomy:** Renamed "ILLEGAL" to **"DISALLOWED"** (matching IDNA standards) and "BENIGN" to **"TYPOGRAPHIC"**.

#### 2. New Dimension: Forensic Physics & Stability
We added three new dimensions of analysis to answer *why* a character is dangerous, not just *that* it exists.
* **Visual Physics (`W:0` vs `W: >0`):** Explicitly badges characters as **Zero-Width (Stealth)** vs. **Positive Width (Spacing)**.
* **Normalization Stability (`NFKC`):** A predictive badge that warns if a character will **Vanish (`VOID`)**, **Mutate (`MOD`)**, or turn into a Space (`SP`) during NFKC normalization—a primary vector for WAF bypass.
* **Ignorability (`DI:YES`):** A heuristic check against the **Default_Ignorable_Code_Point** property, flagging "Ghost" characters that persist in data but vanish in rendering.

#### 3. The "Ghost" Tier & Policy Engine
We refined the risk model to prevent false confidence.
* **The "Ghost" Tier (Purple):** We moved characters like **Zero Width Space (`U+200B`)**, **Mongolian Vowel Separator**, and **Word Joiner** out of the "Typographic" (Safe) tier and into a dedicated **"GHOST/FORMAT"** tier. This creates a distinct visual alert for characters used in evasion attacks.
* **Policy Recommendations:** Added a **POLICY** column that translates abstract risk into actionable advice: `[BLOCK]`, `[REVIEW]`, `[NORM]`, or `[ALLOW]`.

#### 4. UX Architecture: The 9-Column Grid
We completely rebuilt the CSS layout to support high-density forensic data without clutter.
* **No-Wrap Discipline:** Implemented surgical CSS overrides (`white-space: nowrap`, `width: 1%`) to ensure symbol columns auto-fit perfectly while preventing the "Code" column from feeling depressed or squashed.
* **The "Sponge" Logic:** Engineered the **Name** column to act as a layout buffer, absorbing excess whitespace while prioritizing the visibility of forensic badges.
* **Synchronized Color System:** Aligned the **Summary Ribbon** metrics (Totals) with the **Table Rows** using a unified color theory (Red/Critical, Amber/Warning, Purple/Ghost, Green/Safe).

---

### 🛡️ New Module: The Metadata Workbench (Stage 1.5)
**Focus:** Forensic CSS Simulation & Obfuscation Analysis

> **The "Dual-Pipe" Adversarial Physics Engine for Raw Clipboard Forensics**

We have introduced a **Stage 1.5** analysis layer designed to solve the "Blind Spot" of standard text forensics: the loss of styling metadata during paste operations. While the main analyzer secures the *Logical Atom* (plain text), the **Metadata Workbench** secures the *Contextual Reality* (the DOM). It operates on a specialized **"Dual-Pipe" Architecture** that intercepts the raw `text/html` clipboard stream before browser sanitization occurs, enabling the detection of threats that rely on being "technically present but visually missing."

#### 🔬 The Static Forensic Simulator
Unlike traditional regex scanners, this module utilizes a deterministic **Forensic Stack Machine** (built on Python’s `html.parser`). It performs a single-pass simulation of the browser’s rendering engine to calculate the **Effective Forensic State** of every node.
* **Physics Simulation:** It models CSS inheritance (Parent `visibility` $\to$ Child), opacity multiplication, and geometric stacking to detect deep obfuscation.
* **SOTA Detection Engines:** Implements the **CSEMiner Taxonomy** (ESORICS 2025) to detect **Photometric Hiding** (White-on-White, Transparent), **Geometric Collapse** (0px fonts, 1px clipping), **Layout Suppression** (display:none), and **Coordinate Displacement** (Off-screen positioning).
* **Forensic Impact & Sophistication (FIS) Scoring:** A CVSS-style risk model that calculates threat levels based not just on severity, but on **Vector Diversity**. It applies polymorphic multipliers to flag sophisticated attacks (which mix multiple hiding techniques) while using an **A11Y Policy Auditor** to whitelist legitimate accessibility patterns (like `.sr-only` skip links) derived from WebAIM standards.

#### 🏛️ The "Lab Instrument" Interface
The UI has been upgraded to a **Forensic Laboratory** aesthetic, featuring:
* **Active Sensor Array:** A dedicated header visualizing active detection modules (Layout, Geometry, Lineage).
* **Lineage Trace:** A "Debugger-style" stack view that answers *why* text is hidden (e.g., `DIV.wrapper > SPAN.hidden`).
* **Ghost Text X-Ray:** A specialized "Invisibility Goggles" mode that renders hidden payloads inline with a distinct visual signature (Red/Dashed), allowing analysts to see the invisible layer of the web.
