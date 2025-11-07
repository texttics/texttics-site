# Text...tics: A Deterministic Code Point & Forensic Analyzer

This is a single-page web application that functions as a real-time, **deterministic** text analyzer. It is a **Physical Code Point Analyzer** and **Forensic Analysis** tool designed to give a literal, precise, and unfiltered view of the data in a string.

It uses **PyScript** to run Python 3.12 directly in the browser, leveraging the browser's native JavaScript `RegExp` engine and `Intl.Segmenter` API for high-performance, standards-based analysis without a server backend.

It provides a multi-layered, *literal* analysis of text composition, sequence (run) shape, script properties, and hidden forensic flags, all based on the official **Unicode Standard**. Its core feature is a **dual-unit analysis engine** that allows the user to switch between analyzing raw **Code Points** and user-perceived **Grapheme Clusters**.

## 🔬 Core Philosophy: What This Tool Is (and Is Not)

> **This tool is a Physical Code Point Analyzer, not a Linguistic Tool.**

* **IT IS:** A **deterministic** and **literal** microscope. Its purpose is to analyze the *physical code points* of a string exactly as they are. The analysis is 100% deterministic and based on static Unicode properties.

* **IT IS NOT:** A **linguistic** or **contextual** analyzer. It does not implement UAX #29 Word Boundaries and will not analyze "don't" as one "word." Instead, its **Sequence (Run) Analysis** will correctly identify "don't" as three physical runs: Letter (`L`), Punctuation (`P`), and Letter (`L`).

* **IT IS PRECISE (NOT BRITTLE):** The tool **intentionally avoids normalization** (like NFC or NFKC). It correctly distinguishes between `U+212B (ANGSTROM SIGN)` (a `Symbol, So`) and its canonical equivalent `U+00C5 (A-WITH-RING)` (a `Letter, Lu`). This precision in identifying the *actual* code points in memory is a core feature, not a flaw.

## 🚀 Features

* **Dual-Unit Character Analysis (Code Point vs. Grapheme):** A top-level toggle (`Code Points (Raw)` vs. `Graphemes (Perceived)`) switches the entire analysis unit for Module 1.

    * **1. Code Points (Raw) Mode (Default):** Analyzes every individual Unicode code point. This mode provides two further analysis models controlled by a sub-toggle:

        * **Honest (Full Partition) Mode:** 100% standards-compliant.
            1.  It counts the code points of *all* characters, including complex emoji (`👨‍💻` is tallied as 2 `So` + 1 `Cf`).
            2.  It *calculates* the `Cn` (Unassigned) category as the mathematical remainder.
            3.  This **guarantees** `Total Code Points == Sum(All 30 Minor Categories)`.

        * **Filtered (Legacy) Mode:** A "cleaner" view.
            1.  It pre-filters and *removes* all `\p{RGI_Emoji}` sequences before analysis.
            2.  It uses a regex to count `\p{Cn}`.
            3.  In this mode, `Total Code Points` will *not* equal the sum of all categories.

    * **2. Graphemes (Perceived) Mode:** Analyzes "user-perceived characters."
        1.  Uses the browser's native **`Intl.Segmenter`** (UAX #29) to algorithmically segment the string into **Extended Grapheme Clusters** (e.g., `e` + `◌́` is 1 grapheme; `👨‍👩‍👧‍👦` is 1 grapheme).
        2.  It then classifies each grapheme based on the `General_Category` of its *first* code point.
        3.  **Note:** When this mode is active, Modules 2, 3, and 4 (which are code-point-specific) are hidden to prevent logical contradictions.

* **Module 2: Sequence (Run) Analysis:** A structural analysis tool that performs a true **run-length analysis** to count uninterrupted sequences (runs) of the same character type. This module only appears in "Code Point" mode.
    * **Major Categories:** Counts runs of the 7 major categories (e.g., `Hello-100%` is `L` run, `P` run, `N` run, `P` run).
    * **Minor Categories:** Counts runs of the 30 minor categories (e.g., `Hello-100%` is `Lu` run, `Ll` run, `Pd` run, `Nd` run, `Po` run).

* **Module 3: Script & Security Analysis:** A module focused on the script properties of code points, with a focus on an English/Latin baseline and security. This module only appears in "Code Point" mode.
    * **Script Counters:** Provides counts for `Latin`, `Common` (punctuation, symbols), and `Inherited` (marks).
    * **`Other` (Calculated):** A calculated counter (`Total - Latin - Common - Inherited`) that serves as a primary detector for any non-Latin text.
    * **🔒 Homograph Detector: `Mixed-Script Runs`:** A deterministic security feature that detects **homograph attacks**. It counts any `Letter` (L) run that contains code points from *multiple* scripts (e.g., `paypaӏ`, which mixes `Latin` and `Cyrillic` characters, is flagged as 1 Mixed-Script Run).

* **NEW! Module 4: Forensic Analysis:** This module is dedicated to detecting "invisible," "deceptive," "corrupt," or "problematic" characters based on their deterministic Unicode properties. It provides counters for:
    * **Corruption & Error Flags:** `Unassigned (Void)`, `Surrogates (Broken)`, `Noncharacter`, and `Deprecated` code points.
    * **Invisible Ink Detectors:** `Ignorables (Invisible)` (like `U+200B Zero Width Space`) and `Deceptive Spaces` (like `U+200A Hair Space`).
    * **Hidden Manipulators:** `Bidi Controls` (used in Trojan Source attacks) and `Control (Cc)` characters (like `NULL` or `BELL`).
    * **Contextual Flags:** `Private Use (Black Box)` characters, which have no public meaning.

* **Privacy-First Analytics:** Implements Google's Consent Mode v2. All analytics and ad tracking are **disabled by default** (set to 'denied') to ensure user privacy.

## 💻 Tech Stack

* **HTML5:** Structures the application, including the new Module 4 UI.
* **CSS3:** Styles the application, including a distinct style for the new Forensic Analysis cards.
* **PyScript (2024.9.1):** Runs Python 3.12 in the browser.
* **Python 3.12 (via PyScript):**
    * All logic is contained within a single `<script type="py">` tag.
    * Orchestrates all application state and DOM manipulation.
    * Uses `pyodide.ffi.create_proxy` to create event handlers for UI elements.
    * Manipulates the DOM directly using `from pyscript import document`.
* **JavaScript (via PyScript `window` object):**
    * Python leverages the browser's JavaScript engines to perform all deterministic analysis:
    * **`RegExp` engine:** Used for all high-performance Unicode property classifications (e.g., `\p{L}`, `\p{Bidi_Control}`, `\p{Deprecated}`).
    * **`Intl.Segmenter` API:** Used to perform UAX #29-compliant grapheme cluster segmentation.
* **Google Analytics (GA4) & Google Tag Manager (GTM):** For website traffic analysis.
* **Google Consent Mode v2:** Implements a "default-deny" state. As there is no consent banner, tracking remains permanently disabled.

## ⚙️ How It Works

The application logic is a hybrid of Python (for orchestration) and JavaScript (for high-performance, standards-compliant analysis).

### Unicode-Aware App Logic

1.  A user types into the `<textarea>`.
2.  The `py-input="update_all"` attribute triggers the Python `update_all` function on every keypress.
3.  The `update_all` function reads the UI state:
    * `is_grapheme_mode`: (Bool) The state of the "Unit of Analysis" toggle.
    * `is_honest_mode`: (Bool) The state of the "Analysis Mode" sub-toggle.
    * `is_minor_seq`: (Bool) The state of the "Sequence (Run)" toggle.
    * `active_tab`: (String) Which tab is currently open.
4.  The `update_all` function then executes its main logic:
    * **IF `is_grapheme_mode == True`:**
        1.  Calls `compute_grapheme_stats(t)` (which uses `Intl.Segmenter`).
        2.  Calls `render_stats` to update Module 1.
        3.  Hides Module 2, Module 3, and **Module 4** via DOM manipulation.
    * **ELSE (`is_grapheme_mode == False`):**
        1.  Shows Module 2, Module 3, and **Module 4**.
        2.  Calls `compute_comprehensive_stats(t, is_honest_mode)` to run Module 1. This generates the crucial `minor_stats` dictionary.
        3.  Calls `compute_sequence_stats(t, is_minor_seq)` to run Module 2.
        4.  Calls `compute_script_stats(t, is_honest_mode)` and `compute_security_stats(t, is_honest_mode)` to run Module 3.
        5.  Calls **`compute_forensic_stats(t, is_honest_mode, minor_stats)`** to run Module 4, efficiently passing in the `minor_stats` (for `Cn`, `Cc`, `Cs`, `Co`) from Module 1.
        6.  Calls `render_stats` to inject all results into the appropriate UI sections (`#script-stats`, `#forensic-stats`, etc.).

### Analytics & Privacy Logic

1.  On page load, Google Tag Manager and the GA4 tag are loaded.
2.  Crucially, **before** the tags fully initialize, Google Consent Mode is set to **'denied'** by default for all tracking categories (`analytics_storage`, `ad_storage`, etc.).
3.  Because the application does not include a cookie/consent banner for users to click "Accept," this **'denied' state is permanent**, and no user-specific analytics data is collected.


## 🚀 Recent Additions & Feature Upgrades

### 1. New! Grapheme Forensic Analysis (Module 1.5)

The "Graphemes (Perceived)" mode has been significantly upgraded. While it still provides the original 3-tab analysis (Summary, Major, Minor) based on the *first* code point, it now **adds a new, dedicated "Grapheme Forensic Analysis" module.**

This new module addresses the "lossy" nature of the original classification by providing a "forensically honest" look at the *physical structure* of the grapheme clusters themselves. This is especially useful for detecting Zalgo text or other complex clusters.

This module is **only visible when "Graphemes (Perceived)" mode is active** and provides the following new statistics:
* **Total Graphemes:** The total count of "user-perceived characters."
* **Single-Code-Point:** A count of "simple" graphemes that consist of only one code point (e.g., `a`).
* **Multi-Code-Point:** A count of "complex" graphemes that are clusters of multiple code points (e.g., `e` + `◌́` or `x` + 8 marks).
* **Total Combining Marks:** A `\p{M}` count of all combining marks found *inside* all graphemes.
* **Max Marks in one Grapheme:** A "Zalgo detector" that reports the highest number of marks found in a single cluster.
* **Avg. Marks per Grapheme:** A statistical average of marks per grapheme.

### 2. New! Full UCD Profile Modules (Code Point Mode)

Two new modules have been added to the default "Code Points (Raw)" mode to provide a much deeper analysis based on the full Unicode Character Database (UAX #44).

* **Full UCD Profile (UAX #44):**
    This module uses the `RegExp` engine to count deterministic properties beyond the basic `General_Category`. It provides a much more useful, high-level profile of the text's composition, including:
    * **Binary Properties:** `Dash (binary)`, `Alphabetic (binary)`.
    * **Script Properties:** `Script: Cyrillic`, `Script: Greek`, `Script: Han`, `Script: Arabic`, `Script: Hebrew`, etc. This replaces the old, simplistic "Other" category with a precise, standards-based script-by-script breakdown.

* **UCD Deep Scan (Python):**
    This module performs a "deep scan" of every code point using Python's built-in `unicodedata` library. This allows it to access complex properties *not available* to the JavaScript `RegExp` engine, providing a true numeric and forensic analysis:
    * **`Numeric_Type` Counters:** Deterministically classifies all numeric characters into types like `Num Type: Decimal (Nd)` (e.g., `1`), `Num Type: Letter (Nl)` (e.g., Roman `V`), and `Num Type: Other (No)` (e.g., `½`).
    * **`Total Numeric Value`:** A powerful forensic tool that calculates the *actual mathematical sum* of all numeric characters in the string (e.g., `V`+`¼` = `5.25`).


### 3. New! UCD Deep Scan (Python) & Data-Driven Forensics (Module)

This module represents a significant leap in the app's capability, proving its "data-driven" forensic model. It uses Python's `unicodedata` library and asynchronously fetches raw data files from the Unicode Consortium (`IdentifierStatus.txt`) to perform checks that are impossible with `RegExp` alone.

This module provides the following deep-scan statistics in "Code Point Mode":

* **Numeric Type & Value Analysis:**
    * **`Total Numeric Value`:** A powerful forensic tool that calculates the *actual mathematical sum* of all numeric characters in the string (e.g., `V` + `¼` = `5.25`).
    * **`Numeric_Type` Counters:** Deterministically classifies all numeric characters into types like `Num Type: Decimal (Nd)` (e.g., `1`), `Num Type: Letter (Nl)` (e.g., Roman `V`), and `Num Type: Other (No)` (e.g., `½`).

* **Data-Driven Security Flags:**
    * **`Mixed-Number Systems`:** A security flag (derived from `unicodedata`) that detects when a string mixes decimal digits from different scripts (e.g., Latin `1` and Arabic-Indic `٠`), a common spoofing technique.
    * **`Restricted Characters`:** A powerful, data-driven flag. The app fetches `IdentifierStatus.txt` from Unicode, parses it, and then flags any character that is **not** on the `Allowed` list. This catches most "weird" or "problematic" symbols, punctuation, and spaces that are not recommended for identifiers.

### 4. New! Grapheme Forensic Analysis (Module 1.5)

The "Graphemes (Perceived)" mode has been significantly upgraded. While it still provides the original 3-tab analysis (based on the *first* code point), it now **adds a new, dedicated "Grapheme Forensic Analysis" module.**

This new module addresses the "lossy" nature of the original classification by providing a "forensically honest" look at the *physical structure* of the grapheme clusters themselves. This is especially useful for detecting Zalgo text or other complex clusters.

This module is **only visible when "Graphemes (Perceived)" mode is active** and provides the following new statistics:
* **Total Graphemes:** The total count of "user-perceived characters."
* **Single-Code-Point:** A count of "simple" graphemes that consist of only one code point (e.g., `a`).
* **Multi-Code-Point:** A count of "complex" graphemes that are clusters of multiple code points (e.g., `e` + `◌́` or `x` + 8 marks).
* **Total Combining Marks:** A `\p{M}` count of all combining marks found *inside* all graphemes.
* **Max Marks in one Grapheme:** A "Zalgo detector" that reports the highest number of marks found in a single cluster.
* **Avg. Marks per Grapheme:** A statistical average of marks per grapheme.
