/**
 * ui-glue.js
 *
 * This script provides the necessary JavaScript for WAI-ARIA component patterns
 * in the Text...tics application. It is designed to be lightweight and work
 * independently of the PyScript-driven analysis logic.
 *
 * Its primary responsibility is managing the "Dual-Atom Profile" tabs.
 */

document.addEventListener('DOMContentLoaded', () => {

  const tablist = document.querySelector('[role="tablist"][aria-label="Dual-Atom tabs"]');
  
  // Exit if the tab component doesn't exist on the page
  if (!tablist) {
    return;
  }

  const tabs = tablist.querySelectorAll('[role="tab"]');
  const panels = document.querySelectorAll('[role="tabpanel"]');

 // Hook up the Python Reveal Button
  // We dispatch a custom event that app.py will listen for
  const revealBtn = document.getElementById('btn-reveal');
  if (revealBtn) {
    revealBtn.addEventListener('click', () => {
      // Dispatch event to document so Python can catch it via py-click or addEventListener
      // But simpler: let's just let Python bind to the ID directly.
      // We don't strictly need JS code here if we bind in Python, 
      // but let's add a visual ripple effect or log here if you want.
      console.log("Requesting deobfuscation...");
    });
  }

  // --- 1. Click Event Handler ---
  
  tablist.addEventListener('click', (e) => {
    const clickedTab = e.target.closest('[role="tab"]');
    
    if (!clickedTab) {
      return; // Click was not on a tab
    }
    
    // Deactivate all other tabs
    tabs.forEach(tab => {
      tab.setAttribute('aria-selected', 'false');
      tab.setAttribute('tabindex', '-1');
    });

    // Deactivate all panels
    panels.forEach(panel => {
      panel.setAttribute('hidden', 'true');
    });

    // Activate the clicked tab
    clickedTab.setAttribute('aria-selected', 'true');
    clickedTab.setAttribute('tabindex', '0'); // Set focusable

    // Activate the associated panel
    const panelId = clickedTab.getAttribute('aria-controls');
    const activePanel = document.getElementById(panelId);
    if (activePanel) {
      activePanel.removeAttribute('hidden');
    }
  });

  // --- 2. Keyboard Navigation Handler ---
  
  tabs.forEach(tab => {
    tab.addEventListener('keydown', (e) => {
      let currentTab = e.currentTarget;
      let newTab;

      switch (e.key) {
        case 'ArrowLeft':
        case 'ArrowUp': // Often included for vertical tabs
          newTab = getPreviousTab(currentTab, tabs);
          break;
        case 'ArrowRight':
        case 'ArrowDown': // Often included for vertical tabs
          newTab = getNextTab(currentTab, tabs);
          break;
        case 'Home':
          newTab = tabs[0];
          break;
        case 'End':
          newTab = tabs[tabs.length - 1];
          break;
        default:
          return; // Do nothing for other keys
      }

      if (newTab) {
        e.preventDefault();
        
        // Move focus to the new tab
        newTab.focus();
        
        // And also select it (for this simple 2-tab UI, this is more intuitive)
        // This programmatically triggers the click handler above
        newTab.click();
      }
    });
  });

  function getNextTab(currentTab, tabArray) {
    const currentIndex = Array.from(tabArray).indexOf(currentTab);
    const nextIndex = (currentIndex + 1) % tabArray.length; // Wraps around
    return tabArray[nextIndex];
  }

  function getPreviousTab(currentTab, tabArray) {
    const currentIndex = Array.from(tabArray).indexOf(currentTab);
    const prevIndex = (currentIndex - 1 + tabArray.length) % tabArray.length; // Wraps around
    return tabArray[prevIndex];
  }

});

// ---
// 4. Structured Report Copy Logic
// ---
const copyButton = document.getElementById('copy-report-btn');
if (copyButton) {
  copyButton.addEventListener('click', handleCopyReport);
}

async function handleCopyReport() {
  const report = buildStructuredReport();

  try {
    await navigator.clipboard.writeText(report);

    // --- Visual Feedback ---
    const originalText = copyButton.innerText;
    copyButton.innerText = 'Copied!';
    copyButton.classList.add('copied');

    setTimeout(() => {
      copyButton.innerText = originalText;
      copyButton.classList.remove('copied');
    }, 2000);

  } catch (err) {
    console.error('Failed to copy report: ', err);
    copyButton.innerText = 'Error!';
  }
}

function buildStructuredReport() {
  const report = [];

  // --- Helper: safely get text from an element ---
  const getText = (selector) => {
    const el = document.querySelector(selector);
    return el ? el.textContent.trim() : '';
  };

  // --- Helper: safely get value from inputs ---
  const getVal = (selector) => {
    const el = document.querySelector(selector);
    return el ? el.value : '';
  };

  // --- Helper: Smart Card Scraper (Handles Standard & Repertoire Cards) ---
  const parseCards = (containerId) => {
    const lines = [];
    const container = document.getElementById(containerId);
    if (!container) return lines;

    container.querySelectorAll('.card').forEach(card => {
      // 1. Get the Label (always in <strong>)
      const label = card.querySelector('strong')?.textContent.trim() || 'Metric';

      // 2. Check for NEW "Repertoire Card" structure (Value class + Badge)
      const mainValueEl = card.querySelector('.card-main-value');
      
      if (mainValueEl) {
        // It's a Repertoire Card (e.g., "ASCII: 8 (38.1%)")
        const val = mainValueEl.textContent.trim();
        // Try to find a percentage badge OR a "Fully" badge
        const badgeEl = card.querySelector('.card-percentage') || card.querySelector('.card-badge-full');
        const badge = badgeEl ? `(${badgeEl.textContent.trim()})` : '';
        
        lines.push(`  ${label}: ${val} ${badge}`);
      } else {
        // 3. Fallback to "Standard Card" structure (Old style)
        // The value is usually in a <div> that isn't the strong label
        const divVal = card.querySelector('div')?.textContent.trim();
        if (divVal) {
           lines.push(`  ${label}: ${divVal}`);
        }
      }
    });
    return lines;
  };

  // --- Helper: Universal Table Scraper ---
  // Works for 2-col, 3-col, and 4-col tables. Uses textContent to handle hidden details.
  const parseTable = (tbodyId, prefix = '') => {
    const lines = [];
    const tbody = document.getElementById(tbodyId);
    if (!tbody) return lines;

    tbody.querySelectorAll('tr').forEach(row => {
      // Skip rows that are just "No data" placeholders
      if (row.querySelector('.placeholder-text')) return;

      const cells = Array.from(row.querySelectorAll('th, td'));
      if (cells.length === 0) return;

      // Map cell content to text, cleaning up newlines/tabs
      const cellTexts = cells.map(c => 
        c.textContent
         .replace(/[\n\r]+/g, ' ') // Replace newlines with space
         .replace(/\s+/g, ' ')     // Collapse multiple spaces
         .trim()
      );

      // Filter out empty rows (rare artifact protection)
      if (!cellTexts[0]) return;

      // Construct line: "Prefix: Metric, Count, Positions"
      // We join all detected columns with comma-space
      lines.push(`  ${prefix}${cellTexts.join(', ')}`);
    });
    return lines;
  };

  // ==========================================
  // BUILD THE REPORT SECTIONS
  // ==========================================

  report.push('--- Text...tics Structural Profile ---');
  report.push(`Timestamp: ${new Date().toISOString()}`);
  
  report.push('\n[ Analysis Configuration ]');
  report.push(`Input Text:\n"""\n${getVal('#text-input')}\n"""`);

  // --- Dual-Atom Fingerprint ---
  report.push('\n[ Dual-Atom Fingerprint ]');
  report.push(...parseCards('meta-totals-cards'));
  report.push(...parseCards('grapheme-integrity-cards'));
  // The CCC table is a standard matrix now
  report.push(...parseTable('ccc-matrix-body', 'Combining Class: ')); 
  // The Parallel tables are standard matrices now
  report.push(...parseTable('major-parallel-body', 'Major Category: '));
  report.push(...parseTable('minor-parallel-body', 'Minor Category: '));

  // --- Structural Shape ---
  report.push(`\n[ ${getText('#shape-title')} ]`);
  report.push(...parseTable('shape-matrix-body', 'Major Run: '));
  report.push(...parseTable('minor-shape-matrix-body', 'Minor Run: '));
  report.push(...parseTable('linebreak-run-matrix-body', 'LineBreak: '));
  report.push(...parseTable('bidi-run-matrix-body', 'Bidi Class: '));
  report.push(...parseTable('wordbreak-run-matrix-body', 'WordBreak: '));
  report.push(...parseTable('sentencebreak-run-matrix-body', 'SentenceBreak: '));
  report.push(...parseTable('graphemebreak-run-matrix-body', 'GraphemeBreak: '));
  report.push(...parseTable('eawidth-run-matrix-body', 'EA Width: '));
  report.push(...parseTable('vo-run-matrix-body', 'Vertical Orientation: '));

  // --- Structural Integrity ---
  report.push(`\n[ ${getText('#integrity-title')} ]`);
  // Note: This handles the "Decode Health Grade" badge row automatically
  // because parseTable extracts textContent from the <td> containing the badge.
  report.push(...parseTable('integrity-matrix-body', ''));

  // --- Provenance ---
  report.push(`\n[ ${getText('#prov-title')} ]`);
  report.push(...parseTable('provenance-matrix-body', ''));
  report.push(...parseTable('script-run-matrix-body', ''));

  // --- Emoji Qualification ---
  report.push('\n[ Emoji Qualification Profile ]');
  report.push(`  ${getText('#emoji-summary')}`); // "RGI Sequences: X..."
  report.push(...parseTable('emoji-qualification-body', '  Emoji: '));

  // --- Threat Hunting ---
  report.push(`\n[ ${getText('#threat-title')} ]`);
  
  // 1. Threat Flags
  // We pass an empty prefix because the keys (e.g. "Flag: ...", "DANGER: ...")
  // already contain their own labels.
  const threats = parseTable('threat-report-body', '');
  if (threats.length > 0) report.push(...threats);
  
  // 2. Hashes
  const hashes = parseTable('threat-hash-report-body', 'Hash: ');
  if (hashes.length > 0) report.push(...hashes);

  // 3. Perception vs Reality (Confusables)
  report.push('\n[ Perception vs. Reality (Forensic States) ]');
  // We grab the text directly from the PRE block to preserve the formatting
  const confusableText = getText('#confusable-diff-report');
  if (confusableText) {
    report.push(confusableText);
  } else if (window.latest_threat_data) {
    // Fallback to Python data if DOM is empty (rare)
    const t = window.latest_threat_data;
    report.push(`1. Forensic (Raw):   ${t.get('raw')}`);
    report.push(`2. NFKC:             ${t.get('nfkc')}`);
    report.push(`3. NFKC-Casefold:    ${t.get('nfkc_cf')}`);
    report.push(`4. UTS #39 Skeleton: ${t.get('skeleton')}`);
  }

  return report.join('\n');
}

// ---
// 5. Stage 2 "Macrostructure" Button
// ---
const stage2Btn = document.getElementById('btn-run-stage2');
if (stage2Btn) {
  stage2Btn.addEventListener('click', () => {
    // Open the new page in a new tab.
    // Its Python script will look for `window.opener` to find this tab.
    window.open('stage2.html', '_blank');
  });
}


/**
 * ==========================================
 * STAGE 2 INTERACTIVE BRIDGE API
 * ==========================================
 * This function is called by the Stage 2 popup window to highlight
 * a specific grapheme segment in the main Stage 1 <textarea>.
 *
 * @param {number} startGraphemeIndex - The 0-based index of the *first* grapheme in the segment.
 * @param {number} endGraphemeIndex - The 0-based *exclusive* index of the *end* grapheme.
 */
window.TEXTTICS_HIGHLIGHT_SEGMENT = (startGraphemeIndex, endGraphemeIndex) => {
  const textArea = document.getElementById('text-input');
  if (!textArea) {
    console.error('Stage 1: Cannot find #text-input textarea.');
    return;
  }
  
  const text = textArea.value;
  
  // 1. Find the Code Unit (UTF-16) indices for the grapheme range.
  // We must use Intl.Segmenter to be 100% consistent with the Python logic.
  let startCodeUnitIndex = 0;
  let endCodeUnitIndex = text.length;
  
  try {
    const segmenter = new Intl.Segmenter(undefined, { granularity: 'grapheme' });
    const graphemes = Array.from(segmenter.segment(text));
    
    if (graphemes.length > 0) {
      // Get the start index from the startGraphemeIndex-th grapheme
      if (startGraphemeIndex < graphemes.length) {
        startCodeUnitIndex = graphemes[startGraphemeIndex].index;
      }
      
      // Get the end index. endGraphemeIndex is *exclusive*.
      if (endGraphemeIndex < graphemes.length) {
        // The end index is the *start* of the endGraphemeIndex-th grapheme
        endCodeUnitIndex = graphemes[endGraphemeIndex].index;
      } else {
        // If it's the last segment, the end index is the total text length
        endCodeUnitIndex = text.length;
      }
    }
    
  } catch (e) {
    console.error('Stage 1: Error during grapheme segmentation:', e);
    // Fallback: Just select the whole text
    startCodeUnitIndex = 0;
    endCodeUnitIndex = text.length;
  }
  
  // 2. Select and focus the text
  // We must focus first, *then* set selection for it to work.
  textArea.focus();
  textArea.setSelectionRange(startCodeUnitIndex, endCodeUnitIndex);
};

/**
 * =============================================================================
 * TEXTTICS INTERACTIVE BRIDGE (HIGHLIGHTER ENGINE)
 * =============================================================================
 */

const getTextArea = () => document.getElementById('text-input');

/**
 * Mode A: Highlight by Grapheme Index (For Stage 2 / Macro View)
 * Used when the source is a "Visual Block" (e.g., "Grapheme #5")
 */
window.TEXTTICS_HIGHLIGHT_SEGMENT = (startGraphemeIndex, endGraphemeIndex) => {
  const textArea = getTextArea();
  if (!textArea) return;
  const text = textArea.value;

  // Use Intl.Segmenter to map Visual Index -> Code Unit Index
  try {
    const segmenter = new Intl.Segmenter(undefined, { granularity: 'grapheme' });
    const graphemes = Array.from(segmenter.segment(text));
    
    let startUnit = 0;
    let endUnit = text.length;

    if (graphemes.length > 0) {
      // Clamp and find start
      const safeStart = Math.min(startGraphemeIndex, graphemes.length - 1);
      startUnit = graphemes[safeStart].index;

      // Clamp and find end
      if (endGraphemeIndex < graphemes.length) {
        endUnit = graphemes[endGraphemeIndex].index;
      } else {
        endUnit = text.length; // End of string
      }
    }
    
    // Execute Selection
    textArea.focus();
    textArea.setSelectionRange(startUnit, endUnit);

  } catch (e) {
    console.error('Highlight Error (Grapheme):', e);
  }
};

/**
 * Mode B: Highlight by Code Point Index (For Stage 1 / Micro View)
 * Used when the source is a "Logical Atom" (e.g., "#52" in Integrity Profile)
 */
window.TEXTTICS_HIGHLIGHT_CODEPOINT = (codePointIndex) => {
  const textArea = getTextArea();
  if (!textArea) return;
  const text = textArea.value;

  try {
    // 1. Convert string to Array of Code Points (handles Surrogates correctly)
    // This is O(N), but unavoidable for accurate UTF-16 mapping without a map
    const codePoints = Array.from(text);

    // 2. Validate Index
    if (codePointIndex < 0 || codePointIndex >= codePoints.length) {
        console.warn(`Index ${codePointIndex} out of bounds.`);
        return;
    }

    // 3. Calculate UTF-16 Offset (The "Code Unit" Index)
    // We sum the length of all previous code points.
    // e.g., '😀' is 1 code point, but length 2.
    let startUnit = 0;
    for (let i = 0; i < codePointIndex; i++) {
        startUnit += codePoints[i].length;
    }

    // 4. Determine length of the target code point
    const length = codePoints[codePointIndex].length;

    // 5. Execute Selection
    textArea.focus();
    textArea.setSelectionRange(startUnit, startUnit + length);

  } catch (e) {
    console.error('Highlight Error (CodePoint):', e);
  }
};
