# Text...tics: A Unicode-Aware Client-Side Text Analyzer

This is a single-page web application that functions as a real-time, **Unicode-compliant** text analyzer. It uses **PyScript** to run Python 3.12 directly in the browser, leveraging the browser's JavaScript engine for high-performance Unicode property matching without a server backend.

It provides a multi-layered analysis of text composition, token shape, and script properties, all based on the official **Unicode Standard**. It also implements a privacy-first analytics solution using Google Consent Mode v2, which is set to 'denied' by default.

## 🚀 Features

* **Comprehensive Character Analysis (3-Tier):** A tabbed dashboard provides a detailed breakdown of all characters based on the **Unicode General Category (gc)**.
    * **Summary:** An "intuitive" view of the most common categories (e.g., Total Code Points, RGI Emoji, Whitespace, Letters, Numbers, Punctuation, Symbols).
    * **Major Categories:** A formal breakdown of the 7 Major Unicode Categories (`L`, `M`, `N`, `P`, `S`, `Z`, `C`).
    * **Full Breakdown (30):** A granular report of all 30 Minor Unicode Categories (`Lu`, `Ll`, `Nd`, `Po`, etc.).

* **Token Shape Analysis (Class Runs):** A structural analysis tool that counts uninterrupted sequences (runs) of the same character type. A toggle switch allows for analysis at two different granularities:
    * **Major Categories:** Counts runs of the 7 major categories (e.g., `Hello-100%` is one `L` run, one `P` run, one `N` run, and one `P` run).
    * **Minor Categories:** Counts runs of the 30 minor categories (e.g., `Hello-100%` is one `Lu` run, one `Ll` run, one `Pd` run, one `Nd` run, and one `Po` run).

* **Script Analysis:** A new module that counts all characters belonging to a specific Unicode **Script property** (e.g., `Latin`, `Cyrillic`, `Han`, `Common`).

* **Privacy-First Analytics:** Implements Google's Consent Mode v2. All analytics and ad tracking are **disabled by default** (set to 'denied') to ensure user privacy.

## 💻 Tech Stack

* **HTML5:** Structures the application, including the new tab and toggle UI.
* **CSS3:** Styles the application, using CSS Grid for the counter layouts.
* **PyScript (2024.9.1):** Runs Python 3.12 in the browser.
* **Python 3.12 (via PyScript):**
    * All logic is contained within a single `<script type="py">` tag.
    * Orchestrates all application state and DOM manipulation.
    * Uses `pyodide.ffi.create_proxy` to create event handlers for UI elements.
    * Manipulates the DOM directly using `from pyscript import document`.
* **JavaScript (via PyScript `window` object):**
    * Python leverages the browser's JavaScript **`RegExp` engine** to perform all Unicode-aware classifications.
    * This is necessary because Pyodide's built-in Python `re` module does not support Unicode property escapes (e.g., `\p{L}`, `\p{Emoji}`).
* **Google Analytics (GA4) & Google Tag Manager (GTM):** For website traffic analysis.
* **Google Consent Mode v2:** Implements a "default-deny" state. As there is no consent banner, tracking remains permanently disabled.

## ⚙️ How It Works

The application logic is a hybrid of Python (for orchestration) and JavaScript (for high-performance Unicode regex), all running in the browser.

### Unicode-Aware App Logic

1.  A user types into the `<textarea>`.
2.  The `py-input="update_all"` attribute triggers the Python `update_all` function on every keypress.
3.  The `update_all` function reads the UI state (which tab is active, which toggle is set) and calls three other Python functions to gather data:
    1.  `compute_comprehensive_stats(t)`: Runs a **two-pass analysis**.
        * **Pass 1:** Counts "derived" properties like `\p{Emoji}` and `\p{Whitespace}` using JS `RegExp`.
        * **Pass 2:** *Removes* the emoji sequences from the string, then counts all **30 Minor Unicode Categories** (e.g., `\p{Lu}`, `\p{Nd}`) on the remaining text.
        * This data is aggregated into the three tiers (Summary, Major, Minor) for rendering.
    2.  `compute_sequence_stats(t, is_minor)`: Uses a **state machine** to loop through the text. On each character, it calls a `get_char_type` classifier. This classifier checks the character against either the 7 Major (`\p{L}`) or 30 Minor (`\p{Lu}`) regex objects, based on the `is_minor` toggle.
    3.  `compute_script_stats(t)`: Counts characters based on their Unicode `Script` property (e.g., `\p{sc=Latin}`).
4.  The `update_all` function then calls `render_stats` and `render_minor_stats` to inject the results into the correct `div`s.
5.  Clicking a tab (e.g., `[ Major Categories ]`) triggers the `select_tab` Python function (via `create_proxy`) to update the UI visibility.

### Analytics & Privacy Logic

1.  On page load, Google Tag Manager and the GA4 tag are loaded.
2.  Crucially, **before** the tags fully initialize, Google Consent Mode is set to **'denied'** by default for all tracking categories (`analytics_storage`, `ad_storage`, etc.).
3.  Because the application does not include a cookie/consent banner for users to click "Accept," this **'denied' state is permanent**, and no user-specific analytics data is collected.
