# Text...tics: A Unicode-Aware Client-Side Text Analyzer

This is a single-page web application that functions as a real-time, **Unicode-compliant** text analyzer. It uses **PyScript** to run Python 3.12 directly in the browser, leveraging the browser's native JavaScript `RegExp` engine for high-performance, C++-backed Unicode property matching without a server backend.

It provides a multi-layered analysis of text composition, token shape, and script properties, all based on the official **Unicode Standard**. Its core feature is a dual-mode analysis engine that offers both a mathematically perfect "honest" partition of all code points and a "filtered" view for legacy analysis.

## 🚀 Features

* **Dual-Mode Character Analysis (3-Tier):** A tabbed dashboard provides a detailed breakdown of all characters based on the **Unicode General Category (gc)**. A toggle switch controls two distinct analysis models:

    * **Honest (Full Partition) Mode (Default):** This mode is 100% standards-compliant and mathematically sound.
        1.  It counts the constituent code points of *all* characters, including complex emoji (e.g., `👨‍💻` is correctly tallied as 2 `So` Symbols and 1 `Cf` Format character).
        2.  It fixes the "`\p{Cn}` Gap" by *calculating* the `Cn` (Unassigned) category as the mathematical remainder.
        3.  This **guarantees** that `Total Code Points == Sum(All 30 Minor Categories)`.

    * **Filtered (Legacy) Mode:** This mode provides a "cleaner" view by filtering specific components.
        1.  It pre-filters and *removes* all `\p{RGI_Emoji}` sequences before analysis.
        2.  It uses a regex to count `\p{Cn}` (which can miss some unassigned code points).
        3.  In this mode, `Total Code Points` will *not* equal the sum of all categories, as components have been intentionally removed.

* **Condensed Word Shape (Token Shape Analysis):** A structural analysis tool that performs a true **run-length analysis** (also known as "Condensed Word Shape" in NLP) to count uninterrupted sequences (runs) of the same character type. A toggle switch allows for analysis at two granularities:
    * **Major Categories:** Counts runs of the 7 major categories (e.g., `Hello-100%` is `L` run, `P` run, `N` run, `P` run).
    * **Minor Categories:** Counts runs of the 30 minor categories (e.g., `Hello-100%` is `Lu` run, `Ll` run, `Pd` run, `Nd` run, `Po` run).

* **Script Analysis:** A module that counts all characters belonging to a specific Unicode **Script property** (e.g., `Latin`, `Cyrillic`, `Han`). This module also respects the "Honest" vs. "Filtered" analysis toggle.

* **Privacy-First Analytics:** Implements Google's Consent Mode v2. All analytics and ad tracking are **disabled by default** (set to 'denied') to ensure user privacy.

## 💻 Tech Stack

* **HTML5:** Structures the application, including the new dual-mode toggle UI.
* **CSS3:** Styles the application, using CSS Grid for the counter layouts.
* **PyScript (2024.9.1):** Runs Python 3.12 in the browser.
* **Python 3.12 (via PyScript):**
    * All logic is contained within a single `<script type="py">` tag.
    * Orchestrates all application state and DOM manipulation.
    * Uses `pyodide.ffi.create_proxy` to create event handlers for UI elements.
    * Manipulates the DOM directly using `from pyscript import document`.
* **JavaScript (via PyScript `window` object):**
    * Python leverages the browser's JavaScript **`RegExp` engine** to perform all Unicode-aware classifications. This hybrid C++/Python-in-JS approach provides exceptional performance, capable of analyzing massive inputs in real-time.
    * This is necessary because Pyodide's built-in Python `re` module does not support Unicode property escapes (e.g., `\p{L}`, `\p{Emoji}`).
* **Google Analytics (GA4) & Google Tag Manager (GTM):** For website traffic analysis.
* **Google Consent Mode v2:** Implements a "default-deny" state. As there is no consent banner, tracking remains permanently disabled.

## ⚙️ How It Works

The application logic is a hybrid of Python (for orchestration) and JavaScript (for high-performance Unicode regex).

### Unicode-Aware App Logic

1.  A user types into the `<textarea>`.
2.  The `py-input="update_all"` attribute triggers the Python `update_all` function on every keypress.
3.  The `update_all` function reads the UI state:
    * `is_honest_mode`: (Bool) The state of the new "Analysis Mode" toggle.
    * `is_minor_seq`: (Bool) The state of the "Token Shape" toggle.
    * `active_tab`: (String) Which tab is currently open.
4.  The `update_all` function then calls three other Python functions:
    1.  `compute_comprehensive_stats(t, is_honest_mode)`:
        * **If Honest Mode:**
            * **Pass 1:** Counts derived properties (`\p{RGI_Emoji}`, `\p{Whitespace}`) from the full text `t`.
            * **Pass 2:** Counts all **29 assigned Minor Categories** (e.g., `\p{Lu}`, `\p{Cf}`) against the *full text* `t`.
            * **Pass 3:** Calculates `Cn` (Unassigned) as the remainder: `Total Code Points - Sum(29 Categories)`.
        * **If Filtered (Legacy) Mode:**
            * **Pass 1:** Counts `\p{RGI_Emoji}` and *removes* them to create a `text_no_emoji`.
            * **Pass 2:** Counts all **30 Minor Categories** (using the flawed `\p{Cn}` regex) against the *filtered* `text_no_emoji`.
    2.  `compute_sequence_stats(t, is_minor)`: Uses a **state machine** to loop through `t` and implement a "Condensed Word Shape" (run-length) algorithm.
    3.  `compute_script_stats(t, is_honest_mode)`: Counts `\p{sc=...}` properties against either the full text `t` or the filtered `text_no_emoji`, based on the mode.
5.  The `update_all` function then calls `render_stats` to inject the results into the correct UI sections.

### Analytics & Privacy Logic

1.  On page load, Google Tag Manager and the GA4 tag are loaded.
2.  Crucially, **before** the tags fully initialize, Google Consent Mode is set to **'denied'** by default for all tracking categories (`analytics_storage`, `ad_storage`, etc.).
3.  Because the application does not include a cookie/consent banner for users to click "Accept," this **'denied' state is permanent**, and no user-specific analytics data is collected.
