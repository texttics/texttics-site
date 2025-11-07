# Text...tics: A Unicode-Aware Client-Side Text Analyzer

This is a single-page web application that functions as a real-time, **Unicode-compliant** text analyzer. It uses **PyScript** to run Python 3.12 directly in the browser, leveraging the browser's native JavaScript `RegExp` engine and `Intl.Segmenter` API for high-performance, standards-based analysis without a server backend.

It provides a multi-layered analysis of text composition, sequence (run) shape, and script properties, all based on the official **Unicode Standard**. Its core feature is a **dual-unit analysis engine** that allows the user to switch between analyzing raw **Code Points** and user-perceived **Grapheme Clusters**.

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
        3.  **Note:** When this mode is active, Modules 2 and 3 (which are code-point-specific) are hidden to prevent logical contradictions.

* **Sequence (Run) Analysis:** A structural analysis tool that performs a true **run-length analysis** to count uninterrupted sequences (runs) of the same character type. This module only appears in "Code Point" mode.
    * **Major Categories:** Counts runs of the 7 major categories (e.g., `Hello-100%` is `L` run, `P` run, `N` run, `P` run).
    * **Minor Categories:** Counts runs of the 30 minor categories (e.g., `Hello-100%` is `Lu` run, `Ll` run, `Pd` run, `Nd` run, `Po` run).

* **Script & Security Analysis:** A module focused on the script properties of code points, with a focus on an English/Latin baseline and security. This module only appears in "Code Point" mode.
    * **Script Counters:** Provides counts for `Latin`, `Common` (punctuation, symbols), and `Inherited` (marks).
    * **`Other` (Calculated):** A calculated counter (`Total - Latin - Common - Inherited`) that serves as a primary detector for any non-Latin text.
    * **🔒 Security Counter: `Mixed-Script Runs`:** A deterministic security feature that detects **homograph attacks**. It counts any `Letter` (L) run that contains code points from *multiple* scripts (e.g., `paypaӏ`, which mixes `Latin` and `Cyrillic` characters, is flagged as 1 Mixed-Script Run).

* **Privacy-First Analytics:** Implements Google's Consent Mode v2. All analytics and ad tracking are **disabled by default** (set to 'denied') to ensure user privacy.

## 💻 Tech Stack

* **HTML5:** Structures the application, including the new dual-unit toggle UI.
* **CSS3:** Styles the application, using CSS Grid for the counter layouts.
* **PyScript (2024.9.1):** Runs Python 3.12 in the browser.
* **Python 3.12 (via PyScript):**
    * All logic is contained within a single `<script type="py">` tag.
    * Orchestrates all application state and DOM manipulation.
    * Uses `pyodide.ffi.create_proxy` to create event handlers for UI elements.
    * Manipulates the DOM directly using `from pyscript import document`.
* **JavaScript (via PyScript `window` object):**
    * Python leverages the browser's JavaScript engines to perform all deterministic analysis:
    * **`RegExp` engine:** Used for all high-performance Unicode property classifications (e.g., `\p{L}`, `\p{sc=Latin}`).
    * **`Intl.Segmenter` API:** Used to perform UAX #29-compliant grapheme cluster segmentation.
* **Google Analytics (GA4) & Google Tag Manager (GTM):** For website traffic analysis.
* **Google Consent Mode v2:** Implements a "default-deny" state. As there is no consent banner, tracking remains permanently disabled.

## ⚙️ How It Works

The application logic is a hybrid of Python (for orchestration) and JavaScript (for high-performance, standards-compliant analysis).

### Unicode-Aware App Logic

1.  A user types into the `<textarea>`.
2.  The `py-input="update_all"` attribute triggers the Python `update_all` function on every keypress.
3.  The `update_all` function reads the UI state:
    * `is_grapheme_mode`: (Bool) The state of the new "Unit of Analysis" toggle.
    * `is_honest_mode`: (Bool) The state of the "Analysis Mode" sub-toggle.
    * `is_minor_seq`: (Bool) The state of the "Sequence (Run)" toggle.
    * `active_tab`: (String) Which tab is currently open.
4.  The `update_all` function then executes its main logic:
    * **IF `is_grapheme_mode == True`:**
        1.  Calls `compute_grapheme_stats(t)` (which uses `Intl.Segmenter`).
        2.  Calls `render_stats` to update Module 1.
        3.  Hides Module 2 and Module 3 (and their toggles) via DOM manipulation.
    * **ELSE (`is_grapheme_mode == False`):**
        1.  Shows Module 2 and Module 3 (and their toggles).
        2.  Calls `compute_comprehensive_stats(t, is_honest_mode)` (using `RegExp`) to run Module 1.
        3.  Calls `compute_sequence_stats(t, is_minor_seq)` to run Module 2.
        4.  Calls `compute_script_stats(t, is_honest_mode)` and `compute_security_stats(t, is_honest_mode)` to run Module 3.
        5.  Calls `render_stats` to inject all results into the UI.

### Analytics & Privacy Logic

1.  On page load, Google Tag Manager and the GA4 tag are loaded.
2.  Crucially, **before** the tags fully initialize, Google Consent Mode is set to **'denied'** by default for all tracking categories (`analytics_storage`, `ad_storage`, etc.).
3.  Because the application does not include a cookie/consent banner for users to click "Accept," this **'denied' state is permanent**, and no user-specific analytics data is collected.
