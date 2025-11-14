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

* **Unicode Property Classification (UAX #18):** All 30 minor category checks (e.g., `\p{Lu}`, `\p{Po}`) and dozens of property checks (e.g., `\p{White_Space}`) are handled by the browser's native `RegExp` engine. This engine has a pre-compiled, optimized implementation of the Unicode Character Database, making it the fastest possible way to classify millions of code points per second.
* **Grapheme Cluster Segmentation (UAX #29):** The "perceptual" analysis is powered by the native `Intl.Segmenter` API. This is the browser's built-in, trusted implementation of **Unicode Standard Annex #29 (UAX #29)**, the official rulebook for determining "what counts as a single character" to a human user. We treat this as an authoritative black box for perceptual segmentation.

### 2. The Python Layer (Orchestration & Deep Analysis)

This layer runs a full Python 3.12 runtime in the browser via PyScript. Python acts as the application's "brain" or "chief orchestrator." It is used for lower-frequency, "heavy-lifting" tasks that require deep, data-driven logic and complex state management that JavaScript alone cannot easily provide.

* **State Management & Orchestration:** The main `update_all` function in `app.py` manages the entire application state and analysis pipeline, calling all computation functions and passing their results to the correct DOM renderers.
* **Deep Unicode Analysis:** The tool uses a file-first, data-driven approach for maximum precision. While built-in `unicodedata` functions are used for simple tasks (like `unicodedata.numeric()`), the core forensic engine is powered by direct lookups against a local copy of the Unicode Character Database.
* **Data-Driven Analysis (The Core):** This is the heart of the tool's analytical depth. Python asynchronously fetches, parses, and analyzes **27 raw data files** directly from the Unicode Character Database (UCD). This data-driven approach allows the tool to perform UAX-compliant checks that are impossible with built-in functions alone. The data files implemented include:
    * **Core Profile (`Blocks.txt`, `DerivedAge.txt`, `Scripts.txt`, `ScriptExtensions.txt`):** For Block, Age, and Script properties.
    * **Shape Profile (`LineBreak.txt`, `WordBreakProperty.txt`, `SentenceBreakProperty.txt`, `GraphemeBreakProperty.txt`, `EastAsianWidth.txt`, `VerticalOrientation.txt`):** The raw data for the six file-based Run-Length Encoding (RLE) engines.
    * **Integrity Profile (`PropList.txt`, `DerivedCoreProperties.txt`, `DoNotEmit.txt`, `CompositionExclusions.txt`, `DerivedNormalizationProps.txt`, `DerivedBinaryProperties.txt`):** A deep well of binary flags and properties used for the forensic integrity report.
    * **Specialized Profile (`StandardizedVariants.txt`, `emoji-variation-sequences.txt`, `DerivedCombiningClass.txt`, `DerivedDecompositionType.txt`, `DerivedNumericType.txt`, `BidiBrackets.txt`, `BidiMirroring.txt`):** High-precision files for features like the Zalgo-detector, decomposition analysis, numeric types, and variant/Bidi bracket pairing.
    * **Threat-Hunting (`confusables.txt`, `IdentifierType.txt`, `IdentifierStatus.txt`, `intentional.txt`):** The data files that power the Group 3 (homoglyph) and UAX #31 (Identifier) security analysis.

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

### Group 1: Analysis Configuration

This is the "Control Plane" for the instrument.
* **Text Input:** The main `<textarea>` that receives the "post-clipboard" string.
* **"Copy Report" Button:** A utility to copy the *entire* structured profile to the clipboard as a human-readable, timestamped text report.

### Group 2.A: Dual-Atom Profile

This is the "Atomic Count" of the string—the **what**. It provides the core parallel analysis of "Logical" (Code Point) vs. "Perceptual" (Grapheme) atoms.

* **Core Metrics (Cards):** The highest-level counts.
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
* **Combining Class Profile (Table):** A data-driven "Zalgo-detector" (from `DerivedCombiningClass.txt`) that shows the *type* of combining marks being used (e.g., `ccc=220 (Below)`, `ccc=230 (Above)`), providing a precise fingerprint of how characters are being stacked.
* **Parallel Comparison Tables (Tabs):**
    * **Overview Tab:** A side-by-side table comparing the Code Point vs. Grapheme counts for the **7 Major Categories** (Letter, Number, Punctuation, etc.).
    * **Full Breakdown (30) Tab:** A side-by-side table comparing the Code Point vs. Grapheme counts for all **30 Minor Categories** (Lu, Ll, Nd, Po, Cf, etc.).

### Group 2.B: Structural Shape Profile

This is the "Structural Arrangement" of the string—the **how**. It analyzes the text as a *sequence* of runs, not just a "bag of atoms." This module leverages a powerful Run-Length Encoding (RLE) engine to profile the text's "shape."

* **Why it's a profile:** A simple "bag of atoms" diff won't see a structural change. This module will. The string `"don't"` produces a Major Run profile of **L-P-L** (Letter, Punctuation, Letter) and has `3` runs. The "fixed" string `"dont"` produces a profile of **L** and has `1` run. This change in the run-count is a deterministic flag of a structural edit.
* **Features:** This module now correctly generates **ten** separate, parallel RLE tables, providing a deep fingerprint of the text's "shape":
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
* **Contextual & Steganography Flags:**
    * `Private Use (Co)`: "Black box" characters with no public meaning.
    * `Steganography (IVS)`: A specific check for **Ideographic Variation Selectors** (`U+E0100`–`U+E01EF`).
    * `Variant Base Chars`: Characters that can be modified by a variation selector (from `StandardizedVariants.txt` and `emoji-variation-sequences.txt`).
    * `Variation Selectors`: Invisible modifiers sourced from `PropList.txt` and `StandardizedVariants.txt`.
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
    * `Type: ...`: Flags from `IdentifierType.txt` like `Type: Not_XID` or `Type: Technical`.
* **Normalization Flags (Data-Driven):**
    * `Decomposition (Derived): ...`: A complete, data-driven flag for all decomposition types (from `DerivedDecompositionType.txt`), such as `Wide`, `Circle`, `Compat`, etc.
    * `Flag: Full Composition Exclusion`: A flag (from `CompositionExclusions.txt`) for characters that are explicitly excluded from Unicode composition.
    * `Flag: Changes on NFKC Casefold`: A critical normalization flag (from `DerivedNormalizationProps.txt`) that identifies characters guaranteed to change during NFKC-Casefold normalization.

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
* **Numeric Type: Counters**
    * Fetches `DerivedNumericType.txt` to show the *type* of number (`Decimal`, `Digit`, or `Numeric`), providing a deeper profile than just the total value.
* **Total Numeric Value:**
    * A powerful, non-obvious profile. It uses `unicodedata.numeric()` to calculate the **actual mathematical sum** of all numeric characters (e.g., `V` + `¼` = `5.25`). Any change to a number, even a "confusable" one, will change this profile.

### Group 3: Threat-Hunting Profile

This is the final, high-level security assessment. It uses the "Quad-State" pipeline to unmask deceptions.

* **Threat Flags (Cards):** A high-level summary of the most critical security risks, such as `DANGER: Malicious Bidi Control` (for Trojan Source attacks) and `High-Risk: Mixed Scripts` (for homoglyph attacks).
* **Normalization Hashes (Table):** A "fingerprint" of the text in all four of its normalization states:
    1.  **Forensic (Raw)**
    2.  **NFKC** (Compatibility-normalized)
    3.  **NFKC-Casefold** (Compatibility-normalized and case-folded)
    4.  **UTS #39 Skeleton** (The ultimate security hash: normalized, folded, and confusable-mapped)
* **Perception vs. Reality Report (Diff):** A visual report showing the *exact* transformations the string undergoes at each normalization state, allowing a human to see precisely how `pаypal.⓼` (Raw) becomes `pаypal.8` (NFKC) and finally `paypal.8` (Skeleton).

---

## 💻 Tech Stack

The application is a pure, serverless, single-page web application. The logic is cleanly separated for maintainability.

* **`index.html`**: A single, semantic HTML5 file that defines the "skeleton" of the lab instrument. It uses ARIA roles for all components to ensure full accessibility.
* **`styles.css`**: A single, responsive CSS3 stylesheet that provides the clean, information-dense "lab instrument" aesthetic.
* **`pyscript.toml`**: The PyScript configuration file. It lists the required Python packages (like `pyodide-http`) and, crucially, the list of all **27** Unicode data files to be pre-fetched, which are grouped by purpose:
    * **Core Profile (`Blocks.txt`, `DerivedAge.txt`, `Scripts.txt`, `ScriptExtensions.txt`)**
    * **Shape Profile (`LineBreak.txt`, `WordBreakProperty.txt`, `SentenceBreakProperty.txt`, `GraphemeBreakProperty.txt`, `EastAsianWidth.txt`, `VerticalOrientation.txt`)**
    * **Integrity Profile (`PropList.txt`, `DerivedCoreProperties.txt`, `DoNotEmit.txt`, `CompositionExclusions.txt`, `DerivedNormalizationProps.txt`, `DerivedBinaryProperties.txt`)**
    * **Specialized Profile (`StandardizedVariants.txt`, `emoji-variation-sequences.txt`, `DerivedCombiningClass.txt`, `DerivedDecompositionType.txt`, `DerivedNumericType.txt`, `BidiBrackets.txt`, `BidiMirroring.txt`)**
    * **Threat-Hunting (`confusables.txt`, `IdentifierStatus.txt`, `intentional.txt`)**
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
    * `pyscript.toml` is read, and PyScript begins loading the Python runtime and the **27 data files** in parallel.
    * As files return, `app.py` parses them into efficient Python data structures (`DATA_STORES`).
    * `ui-glue.js` runs, attaching its event listeners to the "Copy Report" button and the Tab controls.
2.  **On Data Ready:**
    * `load_unicode_data` finishes and updates the `status-line` to "Ready."
3.  **On User Input:**
    * The user types or pastes text into the `<textarea>`.
    * The `input` event triggers the main `update_all` function in `app.py`.
4.  **`update_all` Orchestration:**
    * The `update_all` function executes its main logic, a single, sequential pipeline.
    * **Group 2 (Structural Profile) compute:** It calls all compute functions for the structural profile (Grapheme, Code Point, RLEs, Integrity, Provenance).
    * **Group 3 (Threat-Hunting) compute:** It calls `compute_threat_analysis`, which generates the four normalized states, their hashes, and the high-level threat flags.
5.  **Render Data:**
    * The results from all `compute` functions are passed to the `render` functions.
    * `render_cards`, `render_parallel_table`, and `render_matrix_table` build HTML strings.
    * These HTML strings are injected into their respective `<tbody>` or `<div>` elements (e.g., `#integrity-matrix-body`, `#eawidth-run-matrix-body`, `#threat-hash-report-body`).
    * The UI updates in a single, efficient paint.

## ✅ Project Status: Complete & Stable

The **"Structural Profile" (Group 2)** and **"Threat-Hunting" (Group 3)** modules are **100% complete, functional, and stable.** All previously-known bugs related to data access, normalization, and logic have been resolved.

The tool now correctly implements:
* **Full Data-Driven Analysis:** All 27 UCD files are correctly loaded and used in the analysis.
* **UAX #31 Compliance:** A robust, UAX #31-compliant "Default Restricted" model for `IdentifierStatus`.
* **Quad-State Normalization:** A powerful, four-state pipeline (Raw, NFKC, NFKC-Casefold, Skeleton) that provides a definitive security fingerprint.
* **Complete Integrity Flagging:** All integrity flags, including those for `DoNotEmit`, `BidiBrackets`, and `CompositionExclusions`, are fully functional.

📈 Core Engine Enhancements & Future Work
The core analysis engine is complete. The "Known Issue" previously documented in this section has been resolved and superseded by a comprehensive, forensic-grade "Emoji Powerhouse" subsystem.

✅ Completed Enhancement: The "Emoji Powerhouse" (UTS #51)
The tool no longer uses a simple, inaccurate \p{Emoji_Presentation} regex. It has been upgraded to a forensic-grade, 5-file parser that is fully compliant with Unicode Technical Standard #51 (UTS #51).

This new subsystem provides 100% accurate sequence counting and powers a new, deeper layer of forensic analysis.

1. Data-Driven Foundation
The engine loads and cross-references all five canonical emoji data files:

emoji-zwj-sequences.txt: (Tier 1) For the most complex RGI (Recommended for General Interchange) ZWJ sequences like families (👨‍👩‍👧‍👦) or professions (👩‍🔬).

emoji-sequences.txt: (Tier 2) For all other RGI sequences, including flags (🇺🇦), skin-tone modifiers (👍🏻), and keycaps (7️⃣).

emoji-variation-sequences.txt: (Tier 3) For RGI sequences that are defined by an explicit style selector (❤️).

emoji-data.txt: (Tier 4) For all single-character emoji properties, such as Emoji_Presentation, Emoji_Component, and Emoji_Modifier_Base.

emoji-test.txt: (Analysis Layer) For the RGI Qualification status of every character and sequence.

2. New Forensic Capabilities
This upgrade not only ensures the RGI Emoji Sequences count is 100% accurate (as confirmed by our test cases), but it also adds a new suite of high-value flags to the "Structural Integrity Profile":

Flag: Unqualified Emoji: This flag detects text-default characters (like ©) that are missing a required variation selector. This is a critical forensic flag, as these characters will render differently (text vs. emoji) on different platforms, creating a classic "inter-layer mismatch" ambiguity.

Flag: Forced Text Presentation: This flag detects the opposite attack: a default-emoji character (like 😀︎) that has been forced to a text-style presentation using an invisible FE0E selector.

Flag: Standalone Emoji Component: This flag detects malformed sequences or "leftover" structural characters (like a lone ZWJ ‍ or VS16 ️) that are not part of a valid RGI sequence. This is a direct indicator of a broken or intentionally-crafted string.

New Prop: Flags: The integrity profile is now also populated with Prop: Extended Pictographic, Prop: Emoji Modifier, and Prop: Emoji Modifier Base, providing a complete, data-driven picture of all emoji-related characters in the string.

📈 Future Enhancements
With the core engine and all data-loading pipelines now complete, future "v2" work can focus on enhancing the UI-level presentation of the rich data we've already collected.

Display Emoji Qualification: The EmojiQualificationMap (from emoji-test.txt) is now fully loaded and used for flagging. A future enhancement will be to display this qualification status (e.g., "Fully-Qualified", "Minimally-Qualified", "Unqualified") for each emoji sequence found, providing even deeper context in a new, dedicated "Emoji Analysis" table.

Enhance Script Profiling: The Script Run-Length Analysis could be enhanced to detect whole-confusable-runs based on the confusables.txt skeleton, providing a higher-level threat flag than the current per-character highlighting.

---

## 🔒 Privacy-First Design

This tool is **privacy-first**.
* **No Server:** All analysis, including the "deep scan" modules, runs 100% in *your* browser. The text you paste is **never** sent to a server.
* **No Analytics (by Default):** The application implements Google's Consent Mode v2. All analytics and ad tracking are **disabled by default** (set to 'denied') to ensure user privacy. Because there is no consent banner to "accept" tracking, this state is permanent.
