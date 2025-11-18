# Text...tics: A Deterministic Structural Profiler & Integrity Analyzer

## What is Text...tics?

This is a single-page web application that functions as a real-time, deterministic text analyzer. It is a highly specialized, browser-based "lab instrument" meticulously engineered to provide a literal, precise, and unfiltered view of any text string's internal structure, composition, and integrity.

Its primary goal is to function as a **"Structural Profiler"**. This tool is not a "best guess" analyzer; it is a deterministic machine. It generates a complete, absolute, and unambiguous statistical signature, or "profile," for any given text. This profile serves as a verifiable, ground-truth baseline, allowing for the computational detection of *any* structural change between two strings, no matter how perceptually subtle.

Its secondary, but equally important, goal is to serve as a **"Structural Integrity Analyzer."** It uses its detailed, multi-layered profile to detect, flag, and locate anomalies, deceptions, and sophisticated "inter-layer mismatch attacks." These are attacks specifically designed to deceive human perception while presenting a different logical reality to a machine. This tool is built to find the invisible, ambiguous, or malicious characters (such as homoglyphs, "Trojan Source" bidirectional overrides, invisible format controls, or steganographic variation selectors) that successfully survive the common copy/paste process and persist as a threat in a "post-clipboard" environment.

---

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
* **Data-Driven Analysis (The Core):** This is the heart of the tool's analytical depth. Python asynchronously fetches, parses, and analyzes **31 raw data files** directly from the Unicode Consortium. This data-driven approach allows the tool to perform UAX-compliant checks that are impossible with built-in functions alone. The data files implemented include:
    * **Core Profile (`Blocks.txt`, `DerivedAge.txt`, `Scripts.txt`, `ScriptExtensions.txt`):** For Block, Age, and Script properties.
    * **Shape Profile (`LineBreak.txt`, `WordBreakProperty.txt`, `SentenceBreakProperty.txt`, `GraphemeBreakProperty.txt`, `EastAsianWidth.txt`, `VerticalOrientation.txt`):** The raw data for the six file-based Run-Length Encoding (RLE) engines.
    * **Integrity Profile (`PropList.txt`, `DerivedCoreProperties.txt`, `DoNotEmit.txt`, `CompositionExclusions.txt`, `DerivedNormalizationProps.txt`, `DerivedBinaryProperties.txt`):** A deep well of binary flags and properties used for the forensic integrity report.
    * **Specialized Profile (`StandardizedVariants.txt`, `DerivedCombiningClass.txt`, `DerivedDecompositionType.txt`, `DerivedNumericType.txt`, `BidiBrackets.txt`, `BidiMirroring.txt`):** High-precision files for features like the Zalgo-detector, decomposition analysis, numeric types, and variant/Bidi bracket pairing.
    * **Threat-Hunting (`confusables.txt`, `IdentifierType.txt`, `IdentifierStatus.txt`, `intentional.txt`):** The data files that power the Group 3 (homoglyph) and UAX #31 (Identifier) security analysis.
    * **UTS #51 Emoji Profile (`emoji-variation-sequences.txt`, `emoji-sequences.txt`, `emoji-zwj-sequences.txt`, `emoji-data.txt`, `emoji-test.txt`):** The 5 data files that power the UTS #51 "Emoji Powerhouse" subsystem.

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

This is the final, high-level security assessment. It uses the "Quad-State" pipeline to unmask deceptions.

* **Threat Flags (Table):** A high-level summary of the most critical security risks. This table collects high-severity flags from the Integrity Profile (like `DANGER: Malicious Bidi Control`) and adds its own (like `High-Risk: Mixed Scripts`) to provide a single, consolidated threat report.
* **Normalization Hashes (Table):** A "fingerprint" of the text in all four of its normalization states:
    1.  **Forensic (Raw)**
    2.  **NFKC** (Compatibility-normalized)
    3.  **NFKC-Casefold** (Compatibility-normalized and case-folded)
    4.  **UTS #39 Skeleton** (The ultimate security hash: normalized, folded, and confusable-mapped)
* **Perception vs. Reality Report (Diff):** A visual report showing the *exact* transformations the string undergoes at each normalization state, allowing a human to see precisely how `pаypal.⓼` (Raw) becomes `pаypal.8` (NFKC) and finally `paypal.8` (Skeleton).

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

## ✅ Project Status: Complete & Stable

The **"Structural Profile" (Group 2)** and **"Threat-Hunting" (Group 3)** modules are **100% complete, functional, and stable.** All previously-known bugs related to data access, normalization, and logic have been resolved.

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

### ✅ Completed Enhancement: Position-Aware Forensic Profiles
The "Provenance" (Group 2.D) and "Script Run" modules are no longer simple counters. They have been upgraded to full forensic matrices that report both **Count** and **Positions** for every property. This enhancement makes the `(See Provenance Profile for details)` instruction in the Threat-Hunting profile fully actionable, allowing an analyst to pinpoint the exact location of cross-script characters.

### ✅ Completed Enhancement: Emoji Qualification Profile
The `EmojiQualificationMap` (from `emoji-test.txt`) is now fully loaded and used to render a dedicated **"Emoji Qualification Profile"** table (Group 2.E). This table lists every RGI sequence found in the text and displays its official Unicode qualification status (e.g., "Fully-Qualified", "Unqualified", "Component"), providing a new layer of rendering and ambiguity analysis.


---

## 🔒 Privacy-First Design

This tool is **privacy-first**.
* **No Server:** All analysis, including the "deep scan" modules, runs 100% in *your* browser. The text you paste is **never** sent to a server.
* **No Analytics (by Default):** The application implements Google's Consent Mode v2. All analytics and ad tracking are **disabled by default** (set to 'denied') to ensure user privacy. Because there is no consent banner to "accept" tracking, this state is permanent.
* 

---
---
---
# `app.py` - Architecture & Logic Summary

This file is the "brain" of the Text...tics application. It runs in the browser via PyScript and is responsible for all data loading, analysis, and rendering.

## 1. Architecture: The "Orchestrator" Model

`app.py` functions as a single, powerful orchestrator. Its architecture can be broken down into six main phases:

1.  **Setup & Globals:** Defines all constants, data structures, and native browser APIs (like `RegExp` and `Intl.Segmenter`) that will be used.
2.  **Data Loading (Async):** On page load, it asynchronously fetches all 31 raw Unicode data files (`.txt`) specified in `pyscript.toml`.
3.  **Data Parsing:** It parses these raw text files into a set of optimized Python dictionaries and lists held in a single global `DATA_STORES` variable.
4.  **Event Listening:** It attaches a main event listener (`update_all`) to the `<textarea>` input.
5.  **Compute & Render Pipeline:** When the user types, `update_all` executes the full analysis pipeline. It calls a series of `compute_...` functions, which analyze the text against the `DATA_STORES`. The results (Python `dict`s) are then passed to `render_...` functions, which generate and inject HTML into the DOM.
6.  **Stage 2 Bridge:** At the end of the pipeline, it packages the core results (grapheme list, flag positions) and exports them to the `window.TEXTTICS_CORE_DATA` object for Stage 2 to consume.

## 2. Key Functions & Logic

### Globals & Setup

* **`MINOR_CATEGORIES_29`, `ALIASES`, `CCC_ALIASES`**: Dictionaries of constants for defining and labeling Unicode categories.
* **`REGEX_MATCHER`**: A dictionary that pre-compiles high-performance JavaScript `RegExp` objects for tasks like finding all `\p{White_Space}` or `\p{M}` (Marks).
* **`GRAPHEME_SEGMENTER`**: A global instance of `window.Intl.Segmenter` used for all Grapheme (UAX #29) analysis.
* **`DATA_STORES`**: The central, global `dict` that holds all parsed Unicode data. It contains sub-keys like `"Blocks"`, `"Confusables"`, `"RGISequenceSet"`, etc.

### Data Loading & Parsing (`async def load_unicode_data`)

* This is the main asynchronous entry point, triggered by `main()`.
* It uses `pyfetch` to `asyncio.gather` all 31 `.txt` files in parallel.
* It calls a series of specialized parser functions to populate `DATA_STORES`:
    * **`_parse_and_store_ranges(txt, store_key)`**: The workhorse parser for most UCD files (`Blocks.txt`, `DerivedAge.txt`, `Scripts.txt`, etc.). It parses `0041..005A ; Property` lines into efficient range-based lookup tables.
    * **`_parse_property_file(txt, property_map)`**: A more advanced parser for multi-property files like `PropList.txt`, sorting different properties into their correct `DATA_STORES` buckets.
    * **`_parse_confusables(txt)`**: Parses `confusables.txt` into the `DATA_STORES["Confusables"]` dictionary (`{cp: skeleton_string}`).
    * **`_parse_emoji_zwj_sequences(txt)`, `_parse_emoji_sequences(txt)`, `_parse_emoji_variation_sequences(txt)`**: These three functions build the "Emoji Powerhouse" RGI (Recommended for General Interchange) database, `DATA_STORES["RGISequenceSet"]`.
    * **`_parse_emoji_test(txt)`**: Parses `emoji-test.txt` into the `DATA_STORES["EmojiQualificationMap"]`.

### Normalization (`def normalize_extended`)

* A custom, multi-tier function that provides a robust `NFKC` normalization, which is essential for the "Quad-State" analysis.
* **Tiers 1 & 2:** Tries to use the full `unicodedata2` library, but falls back to the built-in `unicodedata` if necessary.
* **Tier 3:** Applies manual patches (like the `ENCLOSED_MAP`) to fix known gaps in the standard library, such as normalizing `⓼` to `8`.

### Core "Compute" Functions (The "Microscope")

These functions are called by `update_all` to analyze the raw text.

* **`compute_code_point_stats(t, emoji_counts)`**: Calculates all 30 "Logical" (Code Point) category counts.
* **`compute_grapheme_stats(t)`**: Calculates all "Perceptual" (Grapheme) category counts and the "Grapheme Structural Integrity" (Zalgo) metrics.
* **`compute_combining_class_stats(t)`**: Computes the "Zalgo" profile by counting combining marks by their class (`ccc=220`, `ccc=230`, etc.).
* **`compute_..._analysis(t)` (e.g., `compute_linebreak_analysis`)**: A suite of 10 different "Run-Length Encoding" (RLE) functions that power the "Structural Shape Profile." They iterate code-point-by-code-point and count runs of the same property (e.g., `ALetter`, `Numeric`).
* **`compute_forensic_stats_with_positions(t, cp_minor_stats)`**: The engine for the "Structural Integrity Profile." It iterates every code point and uses `_find_in_ranges` to check it against dozens of property tables (e.g., `BidiControl`, `Deprecated`, `IdentifierStatus`, `CompositionExclusions`), logging the position of every flag.
* **`compute_provenance_stats(t)`**: The engine for the "Provenance & Context Profile." It finds the `Script`, `Block`, `Age`, and `NumericType` for every code point, also logging positions.
* **`compute_emoji_analysis(t)`**: The "Emoji Powerhouse" engine. It performs a complex, multi-tier scan to accurately find RGI sequences and identify all emoji-related anomalies (e.g., `Forced Text Presentation`, `Broken Keycap Sequence`).
* **`compute_threat_analysis(t)`**: The engine for the "Threat-Hunting Profile." It manages the "Quad-State" pipeline, calls `normalize_extended` and `_generate_uts39_skeleton`, computes the SHA-256 hashes, and identifies high-level threats like Bidi overrides and Mixed Scripts.

### Core "Render" Functions (The "Hands")

These functions take the `dict`s from the "compute" functions and build HTML strings.

* **`render_cards(stats_dict, element_id)`**: Renders the "Core Metrics" cards.
* **`render_parallel_table(cp_stats, gr_stats, ...)`**: Renders the side-by-side "Dual-Atom" tables.
* **`render_matrix_table(stats_dict, element_id, ...)`**: The workhorse renderer for all "Matrix of Facts" tables (Integrity, Provenance, Shape, etc.). It correctly handles position lists and the `<details>` tag for long lists.
* **`render_emoji_qualification_table(emoji_list)`**: Renders the specific UI for the "Emoji Qualification Profile."
* **`render_threat_analysis(threat_results)`**: Renders all components of the "Threat-Hunting Profile."

### Orchestration & Entry Point

* **`@create_proxy def update_all(event=None)`**: The "main brain." This is the single function attached to the `<textarea>` `input` event. It runs the entire pipeline in order:
    1.  Gets the text.
    2.  Calls all `compute_...` functions.
    3.  Calls all `render_...` functions.
    4.  Packages and exports data for Stage 2 using `to_js`.
* **`async def main()`**: The application's entry point. It is called once by `asyncio.ensure_future(main())`. Its only jobs are to:
    1.  `await load_unicode_data()`.
    2.  Attach the `update_all` listener to the `<textarea>`.
    3.  Attach the `reveal_invisibles` listener to its button.
    4.  Enable the `<textarea>` and set its placeholder to "Ready."



---

## ✅ README ADDENDUM: Repertoire & Decode Health Enhancements

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
