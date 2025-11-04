# Client-Side Python Text Analyzer

This is a single-page web application that functions as a real-time text analyzer. It uses **PyScript** to run Python (including the **numpy** library) directly in the browser without a server backend.

## 🚀 Features

* **Real-time Statistics:** Calculates the following as you type:
    * Words
    * Characters
    * Characters (no spaces)
    * Sentences
    * Paragraphs
    * Reading time
* **Text Dissection by Word Count Decile:**
    * Analyzes the entire text and calculates the total word count.
    * Finds the 10%, 20%, 30%, etc., word count cutoffs.
    * Re-renders the text below, splitting it into 10 separate blocks corresponding to each decile (0-10%, 10-20%, etc.).
    * This dissection respects sentence boundaries, ensuring no sentence is broken between two blocks.
    * The output is displayed in a two-column grid with the percentile label on the left and the text block on the right.

## 💻 Tech Stack

* **HTML5:** Structures the application.
* **CSS3:** Styles the application (including CSS Grid for the output).
* **PyScript (2024.9.1):**
    * Runs Python 3.12 in the browser.
    * Loads the `numpy` package via `<py-config>` for percentile calculations.
* **Python 3.12:**
    * All logic is contained within a `<script type="py">` tag inside the `index.html`.
    * Uses the `re` (regex) module for sentence splitting and word counting.
    * Uses `numpy` to calculate decile cutoffs.
    * Manipulates the DOM directly using `from pyscript import document`.

## ⚙️ How It Works

1.  A user types into the `<textarea>`.
2.  The `py-input="update_all"` attribute on the textarea triggers the `update_all` Python function on every keypress.
3.  The `update_all` function calls two other functions:
    1.  `compute_stats(t)`: Calculates the simple statistics and updates the top "cards".
    2.  `format_text(t)`: Performs the main text dissection logic (gets sentences, calculates total words, finds decile cutoffs) and generates the new HTML for the two-column grid output.
4.  The generated HTML is injected into the `<div id="formatted-output">`.
