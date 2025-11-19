/**
 * ui-glue.js
 *
 * This script provides the necessary JavaScript for WAI-ARIA component patterns
 * in the Text...tics application. It is designed to be lightweight and work
 * independently of the PyScript-driven analysis logic.
 *
 * Its primary responsibility is managing the "Dual-Atom Profile" tabs.
 */

// ---
// 0. Shared Constants (Ported from Python for Report Generation)
// ---
const JS_INVISIBLE_MAPPING = {
    // --- Control Pictures ---
    0x2400: "[PIC:NUL]", 0x2401: "[PIC:SOH]", 0x2402: "[PIC:STX]", 0x2403: "[PIC:ETX]",
    0x2404: "[PIC:EOT]", 0x2405: "[PIC:ENQ]", 0x2406: "[PIC:ACK]", 0x2407: "[PIC:BEL]",
    0x2408: "[PIC:BS]",  0x2409: "[PIC:HT]",  0x240A: "[PIC:LF]",  0x240B: "[PIC:VT]",
    0x240C: "[PIC:FF]",  0x240D: "[PIC:CR]",  0x240E: "[PIC:SO]",  0x240F: "[PIC:SI]",
    0x2410: "[PIC:DLE]", 0x2411: "[PIC:DC1]", 0x2412: "[PIC:DC2]", 0x2413: "[PIC:DC3]",
    0x2414: "[PIC:DC4]", 0x2415: "[PIC:NAK]", 0x2416: "[PIC:SYN]", 0x2417: "[PIC:ETB]",
    0x2418: "[PIC:CAN]", 0x2419: "[PIC:EM]",  0x241A: "[PIC:SUB]", 0x241B: "[PIC:ESC]",
    0x241C: "[PIC:FS]",  0x241D: "[PIC:GS]",  0x241E: "[PIC:RS]",  0x241F: "[PIC:US]",
    0x2420: "[PIC:SP]",  0x2421: "[PIC:DEL]", 0x2422: "[PIC:BLANK]", 0x2423: "[PIC:OB]",
    0x2424: "[PIC:NL]",  0x2425: "[PIC:DEL2]", 0x2426: "[PIC:SUB2]",

    // --- Wave 4: Zombies & Khmer ---
    0x17B4: "[KHM:AQ]", 0x17B5: "[KHM:AA]",
    0x2061: "[FA]", 0x2062: "[IT]", 0x2063: "[IS]", 0xFFFC: "[OBJ]",
    0x206A: "[ISS]", 0x206B: "[ASS]", 0x206C: "[IAFS]", 
    0x206D: "[AAFS]", 0x206E: "[NDS]", 0x206F: "[NODS]",

    // --- Wave 3: C0/C1 Controls ---
    0x0000: "[NUL]", 0x001B: "[ESC]", 0x00AD: "[SHY]", 0x007F: "[DEL]", 0x0085: "[NEL]",
    // (We add ranges dynamically below for compactness, or paste full list)

    // --- Wave 1: Structural Invisibles ---
    0x061C: "[ALM]", 0x200E: "[LRM]", 0x200F: "[RLM]", 
    0x202A: "[LRE]", 0x202B: "[RLE]", 0x202C: "[PDF]", 0x202D: "[LRO]", 0x202E: "[RLO]",
    0x2066: "[LRI]", 0x2067: "[RLI]", 0x2068: "[FSI]", 0x2069: "[PDI]",
    0x034F: "[CGJ]", 0x180E: "[MVS]", 0x200B: "[ZWSP]", 0x200C: "[ZWNJ]", 0x200D: "[ZWJ]",
    0x2060: "[WJ]",  0xFEFF: "[BOM]", 0x2064: "[INV+]",
    0xFFF9: "[IAA]", 0xFFFA: "[IAS]", 0xFFFB: "[IAT]",
    
    // --- Wave 1: Spaces & Glue ---
    0x00A0: "[NBSP]", 0x2002: "[ENSP]", 0x2003: "[EMSP]", 0x2004: "[3/EM]", 0x2005: "[4/EM]",
    0x2006: "[6/EM]", 0x2007: "[FIGSP]", 0x2008: "[PUNCSP]", 0x2009: "[THIN]", 0x200A: "[HAIR]",
    0x202F: "[NNBSP]", 0x205F: "[MMSP]", 0x3000: "[IDSP]", 0x2028: "[LS]", 0x2029: "[PS]",

    // --- Wave 1: False Vacuums ---
    0x3164: "[HF]", 0xFFA0: "[HHF]", 0x115F: "[HCF]", 0x1160: "[HJF]", 0x2800: "[BRAILLE]",
    0x1680: "[OSM]", 0x2000: "[EQ]", 0x2001: "[MQ]",

    // --- Wave 1: Glue ---
    0x2011: "[NBH]", 0x2024: "[ODL]", 0x0F08: "[TIB:SS]", 0x0F0C: "[TIB:DT]",
    0x0F12: "[TIB:RGS]", 0x1802: "[MNG:C]", 0x1803: "[MNG:FS]", 0x1808: "[MNG:MC]",
    0x1809: "[MNG:MFS]",

    // --- Wave 1: Scoping ---
    0x13437: "[EGY:BS]", 0x13438: "[EGY:ES]", 0x1BCA0: "[SHORT:LO]", 0x1BCA1: "[SHORT:CO]",
    0x1BCA2: "[SHORT:DS]", 0x1BCA3: "[SHORT:UP]",
    0x1D173: "[MUS:BB]", 0x1D174: "[MUS:EB]", 0x1D175: "[MUS:BT]", 0x1D176: "[MUS:ET]",
    0x1D177: "[MUS:BS]", 0x1D178: "[MUS:ES]", 0x1D179: "[MUS:BP]", 0x1D17A: "[MUS:EP]",
    
    // --- Tags ---
    0xE0001: "[TAG:LANG]", 0xE007F: "[TAG:CANCEL]"
};

// Populate Ranges for C0/C1 (Wave 3)
for (let cp = 0x01; cp < 0x20; cp++) {
    if (!JS_INVISIBLE_MAPPING[cp] && ![0x09, 0x0A, 0x0D].includes(cp)) {
        JS_INVISIBLE_MAPPING[cp] = `[CTL:0x${cp.toString(16).toUpperCase().padStart(2,'0')}]`;
    }
}
for (let cp = 0x80; cp <= 0x9F; cp++) {
    if (!JS_INVISIBLE_MAPPING[cp]) {
        JS_INVISIBLE_MAPPING[cp] = `[CTL:0x${cp.toString(16).toUpperCase().padStart(2,'0')}]`;
    }
}

// Populate ASCII Tags (Wave 1)
for (let asc = 0x20; asc < 0x7F; asc++) {
    const tagCp = 0xE0000 + asc;
    const char = asc === 0x20 ? "SP" : String.fromCharCode(asc);
    JS_INVISIBLE_MAPPING[tagCp] = `[TAG:${char}]`;
}

// Helper Function
function getDeobfuscatedText(text) {
    if (!text) return "";
    let output = "";
    for (const char of text) {
        const cp = char.codePointAt(0);
        
        // 1. Explicit Map
        if (JS_INVISIBLE_MAPPING[cp]) {
            output += JS_INVISIBLE_MAPPING[cp];
        }
        // 2. Variation Selectors
        else if (cp >= 0xFE00 && cp <= 0xFE0F) {
            output += `[VS${cp - 0xFE00 + 1}]`;
        }
        else if (cp >= 0xE0100 && cp <= 0xE01EF) {
            output += `[VS${cp - 0xE0100 + 17}]`;
        }
        // 3. Generic Tag Plane fallback (if missed)
        else if (cp >= 0xE0000 && cp <= 0xE007F) {
            output += `[TAG:U+${cp.toString(16).toUpperCase()}]`;
        }
        // 4. Normal char
        else {
            output += char;
        }
    }
    return output;
}

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

    / --- DEOBFUSCATED VIEW ---
  report.push('\n[ Forensic Deobfuscation (Revealed) ]');
  const rawInput = getVal('#text-input');
  const revealed = getDeobfuscatedText(rawInput);
  report.push(revealed);

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
