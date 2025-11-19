/**
 * ui-glue.js
 *
 * This script provides the necessary JavaScript for WAI-ARIA component patterns
 * in the Text...tics application. It also handles the "Stage 1 Report" generation
 * and the JS-side de-obfuscation logic for that report.
 */

// ==========================================
// 0. FORENSIC DATA & DEOBFUSCATION ENGINE
// ==========================================

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

    // --- Wave 3: C0/C1 Controls (Explicit) ---
    0x0000: "[NUL]", 0x001B: "[ESC]", 0x00AD: "[SHY]", 0x007F: "[DEL]", 0x0085: "[NEL]",

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

// JS-Side Deobfuscator
function getDeobfuscatedText(text) {
    if (!text) return "";
    let output = "";
    // Iterate by code point (supports emoji/surrogates correctly)
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

// ==========================================
// 1. DOM & EVENT LISTENERS
// ==========================================

document.addEventListener('DOMContentLoaded', () => {

  const tablist = document.querySelector('[role="tablist"][aria-label="Dual-Atom tabs"]');
   
  // Exit if the tab component doesn't exist on the page
  if (!tablist) {
    return;
  }

  const tabs = tablist.querySelectorAll('[role="tab"]');
  const panels = document.querySelectorAll('[role="tabpanel"]');

  // Hook up the Python Reveal Button (Visual Ripple/Log)
  const revealBtn = document.getElementById('btn-reveal');
  if (revealBtn) {
    revealBtn.addEventListener('click', () => {
      console.log("Requesting deobfuscation...");
    });
  }

  // --- Click Event Handler ---
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

  // --- Keyboard Navigation Handler ---
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
        
        // And also select it
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

// ==========================================
// 2. STRUCTURED REPORT LOGIC
// ==========================================

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

  // --- Helper: Smart Card Scraper ---
  const parseCards = (containerId) => {
    const lines = [];
    const container = document.getElementById(containerId);
    if (!container) return lines;

    container.querySelectorAll('.card').forEach(card => {
      const label = card.querySelector('strong')?.textContent.trim() || 'Metric';

      const mainValueEl = card.querySelector('.card-main-value');
      if (mainValueEl) {
        const val = mainValueEl.textContent.trim();
        const badgeEl = card.querySelector('.card-percentage') || card.querySelector('.card-badge-full');
        const badge = badgeEl ? `(${badgeEl.textContent.trim()})` : '';
        lines.push(`  ${label}: ${val} ${badge}`);
      } else {
        const divVal = card.querySelector('div')?.textContent.trim();
        if (divVal) {
           lines.push(`  ${label}: ${divVal}`);
        }
      }
    });
    return lines;
  };

  // --- Helper: Universal Table Scraper (With Ledger Support) ---
  const parseTable = (tbodyId, prefix = '') => {
    const lines = [];
    const tbody = document.getElementById(tbodyId);
    if (!tbody) return lines;

    tbody.querySelectorAll('tr').forEach(row => {
      if (row.querySelector('.placeholder-text')) return;
      if (row.classList.contains('ledger-noise')) return; // Skip noise rows in main output

      // 1. Get Label
      const th = row.querySelector('th');
      const label = th ? th.textContent.trim() : '';

      // 2. Get Main Value (Badge or Count)
      const tdCount = row.querySelector('td:nth-child(2)');
      let value = '';
      if (tdCount) {
        // Prefer the badge text if it exists (e.g., "CRITICAL (Score: 114)")
        const badge = tdCount.querySelector('.integrity-badge');
        value = badge ? badge.textContent.trim() : tdCount.textContent.trim();
      }

      // 3. Get Details OR Ledger
      const tdDetails = row.querySelector('td:nth-child(3)');
      
      // CHECK FOR LEDGER (Nested Table)
      const nestedTable = tdDetails ? tdDetails.querySelector('table') : null;
      
      if (nestedTable) {
        // -- Header Line --
        lines.push(`  ${prefix}${label}: ${value}`);
        
        // -- Iterate Ledger Rows --
        nestedTable.querySelectorAll('tbody tr').forEach(subRow => {
          const cols = Array.from(subRow.querySelectorAll('td'));
          
          // Handle 3-column (Vector | Severity | Penalty)
          if (cols.length >= 3) {
             const vec = cols[0].textContent.trim();
             const sev = cols[1].textContent.trim();
             const pts = cols[2].textContent.trim();
             // Format: "    - Trojan Source [EXECUTION]: +40"
             lines.push(`      - ${vec} [${sev}]: ${pts}`);
          }
          // Handle 2-column Legacy (Vector | Penalty)
          else if (cols.length >= 2) {
            const vec = cols[0].textContent.trim();
            const pts = cols[cols.length - 1].textContent.trim();
            lines.push(`      - ${vec}: ${pts}`);
          }
        });
      } 
      else if (tdDetails) {
        // -- Standard Row --
        // Clean up newlines and multiple spaces
        const details = tdDetails.textContent
          .replace(/[\n\r]+/g, ' ')
          .replace(/\s+/g, ' ')
          .trim();
          
        lines.push(`  ${prefix}${label}: ${value}, ${details}`);
      }
    });
    return lines;
  };

  // --- Build Report Sections ---
  report.push('--- Text...tics Structural Profile ---');
  report.push(`Timestamp: ${new Date().toISOString()}`);
  
  report.push('\n[ Analysis Configuration ]');
  report.push(`Input Text:\n"""\n${getVal('#text-input')}\n"""`);

  // Dual-Atom
  report.push('\n[ Dual-Atom Fingerprint ]');
  report.push(...parseCards('meta-totals-cards'));
  report.push(...parseCards('grapheme-integrity-cards'));
  report.push(...parseTable('ccc-matrix-body', 'Combining Class: ')); 
  report.push(...parseTable('major-parallel-body', 'Major Category: '));
  report.push(...parseTable('minor-parallel-body', 'Minor Category: '));

  // Shape
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

  // Integrity
  report.push(`\n[ ${getText('#integrity-title')} ]`);
  report.push(...parseTable('integrity-matrix-body', ''));

  // Provenance
  report.push(`\n[ ${getText('#prov-title')} ]`);
  report.push(...parseTable('provenance-matrix-body', ''));
  report.push(...parseTable('script-run-matrix-body', ''));

  // Emoji
  report.push('\n[ Emoji Qualification Profile ]');
  report.push(`  ${getText('#emoji-summary')}`);
  report.push(...parseTable('emoji-qualification-body', '  Emoji: '));

  // Threat
  report.push(`\n[ ${getText('#threat-title')} ]`);
  const threats = parseTable('threat-report-body', '');
  if (threats.length > 0) report.push(...threats);
  
  const hashes = parseTable('threat-hash-report-body', 'Hash: ');
  if (hashes.length > 0) report.push(...hashes);

  // Perception
  report.push('\n[ Perception vs. Reality (Forensic States) ]');
  const confusableText = getText('#confusable-diff-report');
  if (confusableText) {
    report.push(confusableText);
  } else if (window.latest_threat_data) {
    const t = window.latest_threat_data;
    report.push(`1. Forensic (Raw):    ${t.get('raw')}`);
    report.push(`2. NFKC:              ${t.get('nfkc')}`);
    report.push(`3. NFKC-Casefold:     ${t.get('nfkc_cf')}`);
    report.push(`4. UTS #39 Skeleton:  ${t.get('skeleton')}`);
  }

  // --- NEW: DEOBFUSCATED VIEW ---
  report.push('\n[ Forensic Deobfuscation (Revealed) ]');
  const rawInput = getVal('#text-input');
  const revealed = getDeobfuscatedText(rawInput);
  report.push(revealed);
  // ------------------------------

  return report.join('\n');
}

// ---
// 3. STAGE 2 BUTTON
// ---
const stage2Btn = document.getElementById('btn-run-stage2');
if (stage2Btn) {
  stage2Btn.addEventListener('click', () => {
    window.open('stage2.html', '_blank');
  });
}


// ==========================================
// 4. INTERACTIVE BRIDGE (HIGHLIGHTER ENGINE)
// ==========================================

const getTextArea = () => document.getElementById('text-input');

/**
 * Mode A: Highlight by Grapheme Index (For Stage 2 / Macro View)
 */
window.TEXTTICS_HIGHLIGHT_SEGMENT = (startGraphemeIndex, endGraphemeIndex) => {
  const textArea = getTextArea();
  if (!textArea) return;
  const text = textArea.value;

  try {
    const segmenter = new Intl.Segmenter(undefined, { granularity: 'grapheme' });
    const graphemes = Array.from(segmenter.segment(text));
    
    let startUnit = 0;
    let endUnit = text.length;

    if (graphemes.length > 0) {
      const safeStart = Math.min(startGraphemeIndex, graphemes.length - 1);
      startUnit = graphemes[safeStart].index;

      if (endGraphemeIndex < graphemes.length) {
        endUnit = graphemes[endGraphemeIndex].index;
      } else {
        endUnit = text.length; 
      }
    }
    
    textArea.focus();
    textArea.setSelectionRange(startUnit, endUnit);

  } catch (e) {
    console.error('Highlight Error (Grapheme):', e);
  }
};

/**
 * Mode B: Highlight by Code Point Index (For Stage 1 / Micro View)
 */
window.TEXTTICS_HIGHLIGHT_CODEPOINT = (codePointIndex) => {
  const textArea = getTextArea();
  if (!textArea) return;
  const text = textArea.value;

  try {
    const codePoints = Array.from(text);

    if (codePointIndex < 0 || codePointIndex >= codePoints.length) {
        console.warn(`Index ${codePointIndex} out of bounds.`);
        return;
    }

    let startUnit = 0;
    for (let i = 0; i < codePointIndex; i++) {
        startUnit += codePoints[i].length;
    }

    const length = codePoints[codePointIndex].length;

    textArea.focus();
    textArea.setSelectionRange(startUnit, startUnit + length);

  } catch (e) {
    console.error('Highlight Error (CodePoint):', e);
  }
};
