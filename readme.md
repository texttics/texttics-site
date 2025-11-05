# Client-Side Python Text Analyzer

This is a single-page web application that functions as a real-time, high-precision text analyzer. It uses **PyScript** to run Python directly in the browser without requiring a server backend.

It provides a detailed breakdown of the text's composition at both the character and sequence (token) level, and it implements a privacy-first analytics solution using Google Consent Mode v2.

## 🚀 Features

* **Granular Character Counters:** A top-row dashboard provides a real-time count of every character in the input, broken down into 8 distinct categories (Letters, Numbers, Punctuation, Spaces, Control Chars, Emoji, Symbols, and Total).
* **Sequence (Token) Counters:** A second-row dashboard counts uninterrupted sequences of the same character type, providing a structural analysis of the text's composition (e.g., `Hello-100%!` = 1 Letter seq, 1 Punctuation seq, 1 Number seq, 1 Symbol seq, 1 Punctuation seq).
* **Text Dissection by Character Count Decile:** Analyzes the total number of **non-space characters** and renders the text into 10 separate blocks, each containing exactly 10% of the non-space characters. This dissection is literal and will split mid-word.
* **Privacy-First Cookie Consent:** Implements Google's Consent Mode v2. All analytics and ad tracking are **disabled by default**. A cookie banner is shown, and tracking is only enabled *after* the user explicitly clicks "Accept."

## 💻 Tech Stack

* **HTML5:** Structures the application.
* **CSS3:** Styles the application, using CSS Grid for the counter and output layouts.
* **PyScript (2024.9.1):** Runs Python 3.12 in the browser for all text analysis logic.
* **Python 3.12:**
    * All logic is contained within a single `<script type="py">` tag.
    * Uses the `string` module to define character sets.
    * Manipulates the DOM directly using `from pyscript import document`.
* **Google Analytics (GA4) & Google Tag Manager (GTM):** For website traffic analysis.
* **Google Consent Mode v2:** Manages analytics consent based on user interaction, implementing a "default-deny" state to comply with privacy laws (e.g., GDPR).
* **Vanilla JavaScript:** Powers the cookie consent banner logic (showing/hiding the banner, setting `localStorage`, and sending consent updates to `gtag`).

## ⚙️ How It Works

The application has two parallel systems: the Python analyzer and the JavaScript-based consent manager.

### Python App Logic

1.  A user types into the `<textarea>`.
2.  The `py-input="update_all"` attribute triggers the Python `update_all` function on every keypress.
3.  The `update_all` function calls three other Python functions to update the UI:
    1.  `compute_stats(t)`: Loops through the text once to calculate the 8 granular **character** counts.
    2.  `compute_sequence_stats(t)`: Uses a **state machine** to loop through the text and count uninterrupted **sequences** of each character type.
    3.  `format_text(t)`: Calculates the total non-space character count, finds the 10 decile cutoffs, and generates the HTML for the two-column dissected text output.
4.  The generated HTML is injected into the three output `div`s: `#stats`, `#sequence-stats`, and `#formatted-output`.

### Analytics & Consent Logic

1.  On page load, Google Tag Manager and the GA4 tag are loaded.
2.  Crucially, **before** the tags fully initialize, Google Consent Mode is set to **'denied'** by default for all tracking categories (`analytics_storage`, `ad_storage`, etc.).
3.  A simple JavaScript function (`bindCookieBanner`) runs to check `localStorage` for a previous 'accept' choice.
4.  If no consent is found in `localStorage`, the cookie banner is displayed.
5.  If the user clicks the "Accept" button:
    * The `gtag('consent', 'update', ...)` command is sent, granting permission for all tracking types.
    * A value is saved to `localStorage` to hide the banner on future visits.
    * The banner is hidden.
6.  Only *after* this explicit consent is granted will GA4 and GTM begin to collect user-specific data for the session.
