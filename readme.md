# Client-Side Python Text Analyzer

This is a single-page web application that functions as a real-time, high-precision text analyzer. It uses **PyScript** to run Python directly in the browser without requiring a server backend.

It provides a detailed breakdown of the text's composition, both at the character level and at the "sequence" (token) level.

## 🚀 Features

### 1. Granular Character Counters
A top-row dashboard provides a real-time count of every character in the input, broken down into 8 distinct categories:
* **Characters (any):** The total character count (`len(text)`).
* **Letters:** All alphabetic characters.
* **Numbers:** All numeric digits (0-9).
* **Space (' '):** Only the standard space character.
* **Punctuation:** Characters like `!`, `.`, `?`, `,`, `-`, etc.
* **Control Chars:** Non-printing characters like newlines (`\n`) and tabs (`\t`).
* **Emoji:** A basic count of characters in common emoji ranges.
* **Symbols:** All other characters not in the above groups (e.g., `§`, `€`, `+`, `©`).

### 2. Sequence (Token) Counters
A second-row dashboard counts uninterrupted sequences of the same character type. This provides a structural analysis of the text's composition.
* **Example:** The text `"Hello-100%!"` would be counted as:
    * `Letters`: 1 (`Hello`)
    * `Punctuation`: 1 (`-`)
    * `Numbers`: 1 (`100`)
    * `Symbols`: 1 (`%`)
    * `Punctuation`: 1 (`!`)

### 3. Text Dissection by Character Count Decile
* Analyzes the total number of **non-space characters** in the text.
* Finds the 10%, 20%, 30%, etc., cutoffs based on this precise count.
* Renders the text into 10 separate blocks, with each block containing exactly 10% of the non-space characters.
* This dissection is **literal and precise**, meaning it will split text mid-word or mid-sentence to maintain the exact character count for each decile.
* The output is displayed in a two-column grid with the percentile label on the left.

## 💻 Tech Stack

* **HTML5:** Structures the application.
* **CSS3:** Styles the application, using CSS Grid for the counter and output layouts.
* **PyScript (2024.9.1):**
    * Runs Python 3.12 in the browser.
    * No external packages (like numpy) are required.
* **Python 3.12:**
    * All logic is contained within a single `<script type="py">` tag.
    * Uses the `string` module to define character sets (punctuation, control characters).
    * Manipulates the DOM directly using `from pyscript import document`.

## ⚙️ How It Works

1.  A user types into the `<textarea>`.
2.  The `py-input="update_all"` attribute triggers the Python `update_all` function on every keypress.
3.  The `update_all` function calls three other functions to update the UI:
    1.  `compute_stats(t)`: Loops through the text once to calculate the 8 granular **character** counts.
    2.  `compute_sequence_stats(t)`: Uses a **state machine** to loop through the text and count uninterrupted **sequences** of each character type.
    3.  `format_text(t)`: Calculates the total non-space character count, finds the 10 decile cutoffs, and generates the HTML for the two-column dissected text output.
4.  The generated HTML is injected into the three output `div`s: `#stats`, `#sequence-stats`, and `#formatted-output`.
