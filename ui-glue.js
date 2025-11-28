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

// --- Shared Helper: Scrape Encoding Dashboard (v7.0 Forensic Detail) ---
function parseEncodingStrip() {
  const lines = [];
  
  // 1. Scrape Integrity Panel
  const integrityContainer = document.getElementById('encoding-integrity');
  // 2. Scrape Provenance Strip
  const provenanceContainer = document.getElementById('encoding-provenance');
  
  // If UI isn't ready, return empty
  if (!integrityContainer && !provenanceContainer) return lines;

  lines.push('\n[ ENCODING FOOTPRINT ]');
  
  // Combine cells from both containers
  const allCells = [
      ...(integrityContainer ? integrityContainer.querySelectorAll('.enc-cell') : []),
      ...(provenanceContainer ? provenanceContainer.querySelectorAll('.enc-cell') : [])
  ];

  if (allCells.length === 0) return lines;
  
  allCells.forEach(cell => {
      // 1. Get Basic Label (e.g. "GBK")
      let label = cell.querySelector('.enc-label')?.textContent.trim() || "UNKNOWN";
      
      // 2. Get Visual Values (e.g. "80%", "S:40%")
      const valPrim = cell.querySelector('.enc-val-primary')?.textContent.trim();
      const valSec = cell.querySelector('.enc-val-secondary')?.textContent.trim();
      
      // 3. Get Deep Forensic Context from Tooltip
      const title = cell.getAttribute('title') || "";
      let details = "";
      
      if (title) {
          const parts = title.split('\n');
          // Tooltip format: 
          // Line 0: Label
          // Line 1: Total Coverage: X%
          // Line 2: Signal Coverage / ASCII note
          // Line 3+: Unique/Exclusive details (Optional)
          
          // We want everything AFTER the Total Coverage line
          // Filter out the Label and Total lines to get the "Meat"
          const meaningfulParts = parts.slice(2).filter(p => p.trim() !== "");
          
          if (meaningfulParts.length > 0) {
              // Join with a separator for the report
              details = " | " + meaningfulParts.join(" | ");
          }
      }

      // Reconstruct value string: "100% (S:100%)"
      let valueStr = valPrim;
      if (valSec) valueStr += ` (${valSec})`;

      // Check for Unique Marker in Label
      let statusMarker = "";
      if (label.includes('◈')) {
          statusMarker = " [UNIQUE]";
          label = label.replace('◈', '').trim();
      }

      lines.push(`  ${label}: ${valueStr}${statusMarker}${details}`);
  });
  
    const synthesisRow = document.getElementById('encoding-synthesis');
    if (synthesisRow) {
        const badge = synthesisRow.querySelector('.syn-badge')?.textContent.trim();
        const text = synthesisRow.querySelector('.syn-text')?.textContent.trim();
        if (badge && text) {
            lines.push(`\n  [ SYNTHESIS ]`);
            lines.push(`  VERDICT: ${badge}`);
            lines.push(`  NOTE:    ${text}`);
        }
    }
    
  return lines;
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

 // ==========================================
  // 6. HUD CONSOLE BRIDGE (STRUCTURED)
  // ==========================================
  const hudContainer = document.getElementById('forensic-hud');
  
  // Primary Row Targets
  const pKey   = document.getElementById('c-p-key'); // [NEW] Label (e.g. "RGI SEQS:")
  const pDef   = document.getElementById('c-p-def');
  const pLogic = document.getElementById('c-p-logic');
  const pStd   = document.getElementById('c-p-std');

  // Secondary Row Targets
  const sKey   = document.getElementById('c-s-key'); // [NEW] Label
  const sDef   = document.getElementById('c-s-def');
  const sLogic = document.getElementById('c-s-logic');
  const sStd   = document.getElementById('c-s-std');

  const defaults = {
    pKey: "PRIMARY:",
    pDef: "Hover over a metric for definition.",
    sKey: "SECONDARY:",
    sDef: "Secondary context will appear here."
  };

  if (hudContainer && pDef) {
    
    hudContainer.addEventListener('mouseover', (e) => {
      const col = e.target.closest('.hud-col');
      if (col) {
        // Populate Primary
        const l1 = col.getAttribute('data-l1');
        if (l1) pKey.textContent = l1 + ":"; // Update Label
        
        pDef.textContent = col.getAttribute('data-d1') || "";
        pLogic.textContent = col.getAttribute('data-m1') || "";
        pStd.textContent = col.getAttribute('data-r1') || "";

        // Populate Secondary
        const l2 = col.getAttribute('data-l2');
        if (l2) sKey.textContent = l2 + ":"; // Update Label

        sDef.textContent = col.getAttribute('data-d2') || "";
        sLogic.textContent = col.getAttribute('data-m2') || "";
        sStd.textContent = col.getAttribute('data-r2') || "";
      }
    });

    hudContainer.addEventListener('mouseout', (e) => {
       if (!e.relatedTarget || !hudContainer.contains(e.relatedTarget)) {
          // Reset Primary
          pKey.textContent = defaults.pKey;
          pDef.textContent = defaults.pDef;
          pLogic.textContent = "";
          pStd.textContent = "";
          
          // Reset Secondary
          sKey.textContent = defaults.sKey;
          sDef.textContent = defaults.sDef;
          sLogic.textContent = "";
          sStd.textContent = "";
       }
    });
  }

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

// Big Report Function

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

  // --- Helper: Smart Card Scraper (Quad-Aware) ---
  const parseCards = (containerId) => {
    const lines = [];
    const container = document.getElementById(containerId);
    if (!container) return lines;

    container.querySelectorAll('.card').forEach(card => {
      if (card.classList.contains('metric-card')) {
          const label = card.querySelector('.card-header')?.textContent.trim() || 'Metric';
          const valEl = card.querySelector('.metric-value, .metric-value-warn');
          const val = valEl ? valEl.textContent.trim() : '0';
          
          const facts = [];
          card.querySelectorAll('.fact-row').forEach(row => {
              facts.push(row.textContent.trim().replace(/\s+/g, ' '));
          });
          
          const factStr = facts.length > 0 ? ` (${facts.join(', ')})` : "";
          lines.push(`  ${label}: ${val}${factStr}`);
      } else {
          const label = card.querySelector('strong')?.textContent.trim() || 'Metric';
          const mainValueEl = card.querySelector('.card-main-value');
          if (mainValueEl) {
            const val = mainValueEl.textContent.trim();
            const badgeEl = card.querySelector('.card-percentage') || card.querySelector('.card-badge-full');
            const badge = badgeEl ? `(${badgeEl.textContent.trim()})` : '';
            lines.push(`  ${label}: ${val} ${badge}`);
          } else {
            const divVal = card.querySelector('div')?.textContent.trim();
            if (divVal) lines.push(`  ${label}: ${divVal}`);
          }
      }
    });
    return lines;
  };

  // --- Helper: Universal Table Scraper ---
  const parseTable = (tbodyId, prefix = '') => {
    const lines = [];
    const tbody = document.getElementById(tbodyId);
    if (!tbody) return lines;

    tbody.querySelectorAll('tr').forEach(row => {
      if (row.querySelector('.placeholder-text')) return;
      if (row.classList.contains('ledger-noise')) return;

      const th = row.querySelector('th');
      const label = th ? th.textContent.trim() : '';

      const tdCount = row.querySelector('td:nth-child(2)');
      let value = '';
      if (tdCount) {
        const badge = tdCount.querySelector('.integrity-badge');
        value = badge ? badge.textContent.trim() : tdCount.textContent.trim();
      }

      const tdDetails = row.querySelector('td:nth-child(3)');
      const nestedTable = tdDetails ? tdDetails.querySelector('table') : null;
      
      if (nestedTable) {
        lines.push(`  ${prefix}${label}: ${value}`);
        nestedTable.querySelectorAll('tbody tr').forEach(subRow => {
          const cols = Array.from(subRow.querySelectorAll('td'));
          if (cols.length >= 3) {
             const vec = cols[0].textContent.trim();
             const sev = cols[1].textContent.trim();
             const pts = cols[2].textContent.trim();
             lines.push(`      - ${vec} [${sev}]: ${pts}`);
          } else if (cols.length >= 2) {
            const vec = cols[0].textContent.trim();
            const pts = cols[cols.length - 1].textContent.trim();
            lines.push(`      - ${vec}: ${pts}`);
          }
        });
      } else if (tdDetails) {
        let detailsText = "";
        const detailsEl = tdDetails.querySelector('details');
        if (detailsEl) {
            const summary = detailsEl.querySelector('summary') ? detailsEl.querySelector('summary').textContent.trim() : "";
            const hidden = detailsEl.querySelector('div') ? detailsEl.querySelector('div').textContent.trim() : "";
            detailsText = `${summary} ${hidden}`;
        } else {
            detailsText = tdDetails.textContent;
        }
        const cleanDetails = detailsText.replace(/[\n\r]+/g, ' ').replace(/\s+/g, ' ').trim();
        lines.push(`  ${prefix}${label}: ${value}, ${cleanDetails}`);
      }
    });
    return lines;
  };

  // --- Helper: Scrape Encoding Dashboard ---
  const parseEncodingStrip = () => {
    const lines = [];
    const integrityContainer = document.getElementById('encoding-integrity');
    const provenanceContainer = document.getElementById('encoding-provenance');
    if (!integrityContainer && !provenanceContainer) return lines;

    lines.push('\n[ Encoding Compatibility Footprint ]');
    const allCells = [
        ...(integrityContainer ? integrityContainer.querySelectorAll('.enc-cell') : []),
        ...(provenanceContainer ? provenanceContainer.querySelectorAll('.enc-cell') : [])
    ];
    if (allCells.length === 0) return lines;
    
    allCells.forEach(cell => {
        let label = cell.querySelector('.enc-label')?.textContent.trim() || "UNK";
        const valPrim = cell.querySelector('.enc-val-primary')?.textContent.trim();
        const valSec = cell.querySelector('.enc-val-secondary')?.textContent.trim();
        let valueStr = valPrim;
        if (valSec) valueStr += ` (${valSec})`;
        let statusMarker = label.includes('◈') ? " [UNIQUE]" : "";
        lines.push(`  ${label.replace('◈', '').trim()}: ${valueStr}${statusMarker}`);
    });
    return lines;
  };
    
  // --- START REPORT ASSEMBLY ---
  report.push('--- Text...tics Structural Profile ---');
  report.push(`Timestamp: ${new Date().toISOString()}`);
  
  report.push('\n[ Analysis Configuration ]');
  report.push(`Input Text:\n"""\n${getVal('#text-input')}\n"""`);
  
  // --- VERIFICATION BENCH (Conditional) ---
  const verdictBox = document.getElementById('verdict-display');
  const isBenchActive = verdictBox && !verdictBox.classList.contains('hidden');
  
  report.push('\n[ Verification Bench ]');
  if (isBenchActive) {
      report.push(`  Verdict: ${getText('#verdict-title')}`);
      report.push(`  Detail:  ${getText('#verdict-desc')}`);
      
      // Scrape Metrics
      const scrapeMetric = (id) => {
          const el = document.getElementById(id);
          if (!el) return "N/A";
          const val = el.querySelector('.v-metric-val')?.textContent.trim();
          const det = el.querySelector('.v-metric-detail')?.textContent.trim();
          return val ? `${val} (${det})` : el.textContent.trim();
      };
      
      report.push(`  RAW:     ${scrapeMetric('vm-raw')}`);
      report.push(`  NFKC:    ${scrapeMetric('vm-nfkc')}`);
      report.push(`  SKEL:    ${getText('#vm-skel')}`);
  } else {
      report.push('  (Inactive - Select text to compare)');
  }

  // Dual-Atom
  report.push('\n[ Dual-Atom Profile ]');
  report.push(...parseCards('meta-totals-cards'));
  report.push('\n[ Grapheme Integrity ]');
  report.push(...parseCards('grapheme-integrity-cards'));
  
  report.push('\n[ Combining Class Profile (Zalgo) ]');
  report.push(...parseTable('ccc-matrix-body', 'Combining Class: ')); 
  
  report.push('\n[ Major Category: Code Points (Logical) | Graphemes (Perceptual) ]');
  report.push(...parseTable('major-parallel-body', 'Major Category: '));
  
  report.push('\n[ Minor Category: Code Points (Logical) | Graphemes (Perceptual) ]');
  report.push(...parseTable('minor-parallel-body', 'Minor Category: '));

  // Shape (Explicit Scraper for 2-Column Tables)
  report.push(`\n[ ${getText('#shape-title') || 'Structural Shape Profile'} ]`);
  const shapeSections = [
      { id: 'shape-matrix-body', title: 'Major Run Analysis' },
      { id: 'minor-shape-matrix-body', title: 'Minor Run Analysis' },
      { id: 'linebreak-run-matrix-body', title: 'Line Break (UAX #14)' },
      { id: 'bidi-run-matrix-body', title: 'Bidi Class (UAX #9)' },
      { id: 'wordbreak-run-matrix-body', title: 'Word Break (UAX #29)' },
      { id: 'sentencebreak-run-matrix-body', title: 'Sentence Break (UAX #29)' },
      { id: 'graphemebreak-run-matrix-body', title: 'Grapheme Break (UAX #29)' },
      { id: 'eawidth-run-matrix-body', title: 'East Asian Width' },
      { id: 'vo-run-matrix-body', title: 'Vertical Orientation' }
  ];
  
  shapeSections.forEach(sec => {
      const tbody = document.getElementById(sec.id);
      if (tbody && tbody.querySelectorAll('tr').length > 0) {
          const sectionRows = [];
          tbody.querySelectorAll('tr').forEach(row => {
              if (row.querySelector('.placeholder-text')) return;
              
              // Direct Scrape: Label (th) and Value (td)
              const label = row.querySelector('th')?.textContent.trim();
              const val = row.querySelector('td')?.textContent.trim();
              
              if (label && val) {
                  sectionRows.push(`  ${label}: ${val}`);
              }
          });
          
          if (sectionRows.length > 0) {
              report.push(`  -- ${sec.title} --`);
              report.push(...sectionRows);
          }
      }
  });

  // Integrity
  report.push(`\n[ ${getText('#integrity-title') || 'Structural Integrity Profile'} ]`);
  report.push(...parseTable('integrity-matrix-body', ''));
  
  // Invisible Atlas (New)
  report.push('\n[ Invisible Character Atlas ]');
  const atlasBody = document.getElementById('invisible-atlas-body');
  if (atlasBody) {
      const rows = atlasBody.querySelectorAll('tr');
      if (rows.length > 0 && !rows[0].classList.contains('placeholder-text')) {
          report.push('  Symbol | Code | Count | Category | Name');
          rows.forEach(row => {
             const cells = row.querySelectorAll('td');
             if (cells.length >= 5) {
                 // 0:Visual, 1:Code, 2:Name, 3:Count, 4:Badge
                 const vis = cells[0].textContent.trim();
                 const code = cells[1].textContent.trim();
                 const name = cells[2].textContent.trim();
                 const count = cells[3].textContent.trim();
                 const cat = cells[4].textContent.trim();
                 report.push(`  ${vis.padEnd(8)} | ${code.padEnd(8)} | ${count.padEnd(4)} | ${cat.padEnd(10)} | ${name}`);
             }
          });
      } else {
          report.push('  No invisible characters detected.');
      }
  }

  // Provenance
  report.push(`\n[ ${getText('#prov-title') || 'Provenance & Context Profile'} ]`);
  report.push(...parseTable('provenance-matrix-body', ''));
  
  report.push('\n[ Script Run-Length Analysis ]');
  report.push(...parseTable('script-run-matrix-body', ''));

  // Emoji
  report.push('\n[ Emoji Qualification Profile ]');
  report.push(`  ${getText('#emoji-summary')}`);
  
  const emojiBody = document.getElementById('emoji-qualification-body');
  if (emojiBody) {
      const rows = emojiBody.querySelectorAll('tr');
      if (rows.length > 0 && !rows[0].classList.contains('placeholder-text')) {
          report.push(`  Format: Sequence | Kind | Base | RGI | Status | Count | Positions`);
          rows.forEach(row => {
              if (row.querySelector('div[style*="grid"]')) return; // Skip legend
              const cells = Array.from(row.querySelectorAll('td'));
              if (cells.length >= 7) {
                  const seq = cells[0].textContent.trim();
                  const kind = cells[1].textContent.trim();
                  const base = cells[2].textContent.trim();
                  const rgi = cells[3].textContent.trim();
                  const stat = cells[4].textContent.trim();
                  const cnt = cells[5].textContent.trim();
                  let pos = cells[6].textContent.trim();
                  const details = cells[6].querySelector('details');
                  if (details) {
                      const summary = details.querySelector('summary').textContent.trim();
                      const hidden = details.querySelector('div').textContent.trim();
                      pos = `${summary} ${hidden}`.replace(/\s+/g, ' ');
                  }
                  report.push(`  ${seq.padEnd(4)} | ${kind.padEnd(10)} | ${base} | ${rgi} | ${stat.padEnd(10)} | ${cnt} | ${pos}`);
              }
          });
      } else {
          report.push("  No emoji sequences found.");
      }
  }

  // Threat
  report.push(`\n[ ${getText('#threat-title') || 'Threat-Hunting Profile'} ]`);
  const threats = parseTable('threat-report-body', '');
  if (threats.length > 0) report.push(...threats);
  
  const hashes = parseTable('threat-hash-report-body', 'Hash: ');
  if (hashes.length > 0) report.push(...hashes);

  // Adversarial Dashboard
  const advBody = document.getElementById('adv-target-body');
  if (advBody && advBody.offsetParent !== null) {
      report.push('\n[ Suspicion Dashboard (Adversarial Forensics) ]');
      const peakRow = document.getElementById('adv-peak-row');
      if (peakRow && peakRow.style.display !== 'none') {
          const pTok = getText('#adv-peak-token');
          const pScore = getText('#adv-peak-score');
          report.push(`  PARANOIA PEAK (Top Offender): ${pTok} [${pScore}]`);
      }
      report.push(`  ADVERSARIAL FINDINGS:`);
      const rows = advBody.querySelectorAll('.target-row');
      if (rows.length === 0) {
          report.push("  No anomalies detected.");
      } else {
          rows.forEach(row => {
              const score = row.querySelector('.th-badge')?.textContent.trim() || "0";
              const token = row.querySelector('.t-token')?.textContent.trim() || "UNKNOWN";
              const verdict = row.querySelector('.t-verdict')?.textContent.trim() || "";
              report.push(`  • [${score}] ${token.padEnd(20)} | ${verdict}`);
              const descRows = row.querySelectorAll('.th-desc');
              descRows.forEach(d => {
                  report.push(`      - ${d.textContent.trim()}`);
              });
              report.push('');
          });
      }
  }

  // Perception (X-Ray)
  report.push('\n[ Perception vs. Reality (Forensic States) ]');
  if (window.latest_threat_data) {
    const t = window.latest_threat_data;
    report.push(`  1. Forensic (Raw):    ${t.get('raw')}`);
    report.push(`  2. NFKC:              ${t.get('nfkc')}`);
    report.push(`  3. NFKC-Casefold:     ${t.get('nfkc_cf')}`);
    report.push(`  4. UTS #39 Skeleton:  ${t.get('skeleton')}`);
  }

  const xrayContainer = document.querySelector('.xray-container');
  if (xrayContainer) {
      report.push(`\n  [ X-Ray Alignment Analysis ]`);
      const cols = xrayContainer.querySelectorAll('.xray-col');
      let driftCount = 0;
      cols.forEach(col => {
          if (col.classList.contains('xray-drift')) {
              const rawChar = col.querySelector('.x-raw')?.textContent.trim();
              const skelChar = col.querySelector('.x-skel')?.textContent.trim();
              const title = col.getAttribute('title') || "";
              report.push(`  ! DRIFT: ${rawChar} --> ${skelChar}  (${title})`);
              driftCount++;
          }
      });
      if (driftCount === 0) {
          report.push("  No visual drift detected (Clean alignment).");
      }
  }

  // Encoding
  report.push(...parseEncodingStrip());
    
  report.push('\n[ Forensic Deobfuscation (Revealed) ]');
  const rawInput = getVal('#text-input');
  if (typeof getDeobfuscatedText === 'function') {
      const revealed = getDeobfuscatedText(rawInput);
      report.push(revealed);
  }

  return report.join('\n');
}
// End of big function

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

/**
 * FORENSIC CENTER: Forces the scroll viewport to center the glyph.
 * Call this immediately after rendering the inspector HTML.
 */
window.TEXTTICS_CENTER_GLYPH = () => {
  requestAnimationFrame(() => {
    const viewport = document.querySelector('.glyph-viewport');
    const glyph = document.querySelector('.inspector-glyph');
    
    if (viewport && glyph) {
      // Calculate the center position
      // (Glyph Height - Viewport Height) / 2 = Top offset needed
      const scrollTop = (glyph.scrollHeight - viewport.clientHeight) / 2;
      const scrollLeft = (glyph.scrollWidth - viewport.clientWidth) / 2;
      
      // Apply instantly
      if (scrollTop > 0) viewport.scrollTop = scrollTop;
      if (scrollLeft > 0) viewport.scrollLeft = scrollLeft;
      
      // Optional: Log for debugging
      // console.log(`Centered Glyph: Top=${scrollTop}, Left=${scrollLeft}`);
    }
  });
};

// ==========================================
// 5. UAX #29 COUNTER BRIDGE
// ==========================================
window.TEXTTICS_CALC_UAX_COUNTS = (text) => {
  if (!text) return [0, 0];
  try {
    // Run segmentation natively in JS to avoid PyProxy overhead/errors
    const wordSeg = new Intl.Segmenter("en", { granularity: 'word' });
    const sentSeg = new Intl.Segmenter("en", { granularity: 'sentence' });
    
    let wCount = 0;
    // .segment() returns an iterable, we can loop directly
    for (const seg of wordSeg.segment(text)) {
      if (seg.isWordLike) wCount++;
    }
    
    let sCount = 0;
    for (const seg of sentSeg.segment(text)) {
      sCount++;
    }
    
    return [wCount, sCount];
  } catch (e) {
    console.error("UAX Calc Error:", e);
    return [-1, -1]; // Signal error to Python
  }
};

// ==========================================
  // 7. JUMP LIST AUTO-EXPAND LOGIC
  // ==========================================
  const jumpLinks = document.querySelectorAll('.jump-list a');
  
  jumpLinks.forEach(link => {
    link.addEventListener('click', (e) => {
      // 1. Get the target ID from the href (e.g., "#dual-atom" -> "dual-atom")
      const href = link.getAttribute('href');
      if (!href || !href.startsWith('#')) return;
      
      const targetId = href.substring(1);
      const targetEl = document.getElementById(targetId);

      // 2. If the target is a <details> element, force it OPEN
      if (targetEl && targetEl.tagName === 'DETAILS') {
        targetEl.open = true;
        
        // Optional: Wait a tiny tick to ensure expansion renders before the jump
        // (The browser default jump happens after this synchronous code finishes)
      }
    });
  });

// ==========================================
  // 8. PROFILE TOGGLE LOGIC (Dual-Action)
  // ==========================================
  const toggleBtn = document.getElementById('btn-toggle-profiles');
  // Select ONLY the data profiles (exclude Dashboard/Inspector)
  const reportSections = document.querySelectorAll('.fingerprint-section');

  if (toggleBtn) {
    toggleBtn.addEventListener('click', () => {
      // Check state: Is there at least one section closed?
      const isAnyClosed = Array.from(reportSections).some(el => !el.hasAttribute('open'));

      if (isAnyClosed) {
        // Action: EXPAND ALL
        reportSections.forEach(el => el.open = true);
        toggleBtn.innerText = "↕ Collapse All Profiles";
      } else {
        // Action: COLLAPSE ALL
        reportSections.forEach(el => el.open = false);
        toggleBtn.innerText = "↕ Expand All Profiles";
      }
    });
  }

// ==========================================
  // 9. GRANULAR COPY LOGIC
  // ==========================================

  // Helper: Copy text to clipboard with visual feedback
  async function copyToClipboard(text, btnId) {
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
      const btn = document.getElementById(btnId);
      if(btn) {
        const originalText = btn.innerText;
        btn.innerText = "Copied!";
        setTimeout(() => btn.innerText = originalText, 2000);
      }
    } catch (err) {
      console.error("Copy failed", err);
    }
  }

  // A. Copy HUD Data (Updated: Includes Encoding Strip)
  const btnCopyHud = document.getElementById('btn-copy-hud');
  if (btnCopyHud) {
    btnCopyHud.addEventListener('click', () => {
      const hud = document.getElementById('forensic-hud');
      if (!hud) return;
      
      let report = "[ HUD Data ]\n";
      const cols = hud.querySelectorAll('.hud-col');
      
      // Part 1: Vertical Columns (Alphanumeric, etc.)
      cols.forEach(col => {
        const header = col.querySelector('.hud-row-sci')?.textContent.trim() || "METRIC";
        const groups = col.querySelectorAll('.hud-metric-group');
        
        if (groups.length > 0) {
            report += `\n[${header}]\n`; 
            groups.forEach(group => {
                const label = group.querySelector('.hud-label')?.textContent.trim() || "VAL";
                const val = group.querySelector('.hud-val')?.textContent.trim() || "-";
                report += `  ${label}: ${val}\n`;
            });
        }
      });

      // Part 2: Encoding Strip (NEW)
      // We call the helper function we just added
      const encodingLines = parseEncodingStrip();
      if (encodingLines.length > 0) {
          report += encodingLines.join("\n");
      }
      
      copyToClipboard(report, 'btn-copy-hud');
    });
  }

 // B. Copy Inspector Data (Structured Forensic Format)
  const btnCopyInsp = document.getElementById('btn-copy-inspector');
  if (btnCopyInsp) {
    btnCopyInsp.addEventListener('click', () => {
      const root = document.getElementById('inspector-panel-content');
      if (!root) return;

      // Helper to safely get text
      const txt = (sel) => root.querySelector(sel)?.textContent.trim() || "";
      
      // 1. HEADER: Target Identity
      const glyph = txt('.inspector-glyph');
      const cp = txt('.inspector-codepoint');
      const name = txt('.inspector-header');
      
      let report = `[ Character Inspector Data ]\n`;
      report += `--------------------------------------------------\n`;
      report += `TARGET:   ${glyph}  (${cp})\n`;
      report += `NAME:     ${name}\n`;
      report += `--------------------------------------------------\n\n`;

      // 2. RISK ASSESSMENT (Verdict & Matrix)
      const verdict = txt('.risk-verdict-text');
      const level = txt('.risk-header-top');
      
      report += `[ RISK ASSESSMENT ]\n`;
      report += `Verdict:  ${level} - ${verdict}\n`;
      
      // Scrape the Diagnostic Matrix rows
      root.querySelectorAll('.risk-row').forEach(row => {
          const label = row.querySelector('.risk-facet')?.textContent.trim() || "";
          const status = row.querySelector('.risk-status')?.textContent.trim() || "";
          const detail = row.querySelector('.risk-detail')?.textContent.trim() || "";
          // Format: "Visibility: PASS (Standard ASCII)"
          if(label) report += `${label.padEnd(12, ' ')}: ${status} (${detail})\n`;
      });
      report += `\n`;

      // 3. IDENTITY DETAILS
      // We scrape the spec-chips or matrix items if present
      report += `[ IDENTITY PROFILE ]\n`;
      root.querySelectorAll('.col-identity .matrix-item').forEach(item => {
          const val = item.querySelector('.matrix-val')?.textContent.trim();
          const sub = item.querySelector('.matrix-sub')?.textContent.trim();
          if(val && sub) report += `${sub.padEnd(15, ' ')}: ${val}\n`;
      });
      report += `\n`;

      // 4. LOOKALIKES (If present)
      const lookalikes = root.querySelector('.ghost-section.lookalikes');
      if (lookalikes) {
          const count = lookalikes.querySelector('.ghost-key')?.textContent.trim();
          report += `[ CONFUSABLES ]\n`;
          report += `${count}\n`;
          // Grab chips
          const chips = [];
          lookalikes.querySelectorAll('.lookalike-chip').forEach(chip => {
             const lkGlyph = chip.querySelector('.lk-glyph')?.textContent;
             const lkCp = chip.querySelector('.lk-cp')?.textContent;
             chips.push(`${lkGlyph} (${lkCp})`);
          });
          if(chips.length > 0) report += `Candidates: ${chips.join(', ')}\n`;
          report += `\n`;
      }

      // 5. CLUSTER COMPONENTS (Table)
      report += `[ CLUSTER COMPONENTS ]\n`;
      const rows = root.querySelectorAll('.structure-table tbody tr');
      if (rows.length > 0) {
          // Header
          report += `CP`.padEnd(10) + `Cat`.padEnd(6) + `CCC`.padEnd(6) + `Name\n`;
          rows.forEach(row => {
              const cells = row.querySelectorAll('td');
              if(cells.length >= 4) {
                  const cCp = cells[0].textContent.trim().padEnd(10);
                  const cCat = cells[1].textContent.trim().padEnd(6);
                  const cCcc = cells[2].textContent.trim().padEnd(6);
                  const cName = cells[3].textContent.trim();
                  report += `${cCp}${cCat}${cCcc}${cName}\n`;
              }
          });
      } else {
          report += "Atomic Character (No Decomposition)\n";
      }
      report += `\n`;

      // 6. FORENSIC ENCODINGS
      report += `[ ENCODINGS ]\n`;
      root.querySelectorAll('.byte-row').forEach(row => {
          const label = row.querySelector('.label')?.textContent.replace(':','').trim();
          // Get the text node following the label
          const val = row.innerText.split(':')[1]?.trim() || ""; 
          if(label) report += `${label.padEnd(12, ' ')}: ${val}\n`;
      });

      copyToClipboard(report, 'btn-copy-inspector');
    });
  }

// D. Copy All Data (Aggregator)
  const btnCopyAll = document.getElementById('btn-copy-all-everything');
  if (btnCopyAll) {
    btnCopyAll.addEventListener('click', () => {
      let megaReport = "";
      const separator = "\n\n==================================================\n\n";

      // 1. Get HUD Data
      const hud = document.getElementById('forensic-hud');
      if (hud) {
        let hudText = "[ HUD Metrics ]\n";
        const cols = hud.querySelectorAll('.hud-col');
        cols.forEach(col => {
          const header = col.querySelector('.hud-row-sci')?.textContent.trim() || "METRIC";
          const groups = col.querySelectorAll('.hud-metric-group');
          if (groups.length > 0) {
              hudText += `\n[${header}]\n`;
              groups.forEach(group => {
                  const label = group.querySelector('.hud-label')?.textContent.trim() || "VAL";
                  const val = group.querySelector('.hud-val')?.textContent.trim() || "-";
                  hudText += `  ${label}: ${val}\n`;
              });
          }
        });
        megaReport += hudText;
      }

      // 2. Get Inspector Data
      const inspector = document.getElementById('inspector-panel-content');
      if (inspector) {
        megaReport += separator + "[ Character Inspector Data ]\n";
        
        // Check if the inspector is showing the default placeholder or an error
        const isPlaceholder = inspector.querySelector('.inspector-placeholder');
        const isError = inspector.querySelector('.status-error');
        const hasContent = inspector.innerText.trim().length > 0;
        
        if (!isPlaceholder && !isError && hasContent) {
            // Active: Dump the data
            megaReport += inspector.innerText; 
        } else {
            // Inactive: Show standard placeholder
            megaReport += "  (Inactive - Select a character to inspect)";
        }
      }

      // 3. Get Full Profile Data
      // We call the existing buildStructuredReport function
      const fullProfile = buildStructuredReport(); 
      megaReport += separator + "[ Full Structural Profile ]\n" + fullProfile;

      copyToClipboard(megaReport, 'btn-copy-all-everything');
    });
  }

// ==========================================
  // 10. FORENSIC LEGEND TOGGLE
  // ==========================================
  const legendBtn = document.getElementById('btn-legend-toggle');
  const legendContent = document.getElementById('enc-legend-content');
  const legendKey = 'texttics_legend_open'; // localStorage key

  if (legendBtn && legendContent) {
    
    // 1. Check saved state
    const savedState = localStorage.getItem(legendKey);
    if (savedState === 'true') {
      legendContent.classList.add('active');
      legendContent.removeAttribute('hidden');
      legendBtn.setAttribute('aria-expanded', 'true');
    }

    // 2. Toggle Handler
    legendBtn.addEventListener('click', () => {
      const isHidden = legendContent.hasAttribute('hidden');
      
      if (isHidden) {
        // OPEN IT
        legendContent.classList.add('active');
        legendContent.removeAttribute('hidden');
        legendBtn.setAttribute('aria-expanded', 'true');
        localStorage.setItem(legendKey, 'true');
      } else {
        // CLOSE IT
        legendContent.classList.remove('active');
        legendContent.setAttribute('hidden', '');
        legendBtn.setAttribute('aria-expanded', 'false');
        localStorage.setItem(legendKey, 'false');
      }
    });
  }

// ==========================================
// 11. FORENSIC HIGHLIGHTER ENGINE (Range & Stepper)
// ==========================================

/**
 * Converts Logical Code Point Indices (Python) to DOM UTF-16 Indices (JS)
 * and selects the range.
 * @param {number} startCP - Inclusive start index (Code Points)
 * @param {number} endCP   - Exclusive end index (Code Points)
 */
window.TEXTTICS_HIGHLIGHT_RANGE = (startCP, endCP) => {
  const textArea = document.getElementById('text-input');
  if (!textArea) return;
  const text = textArea.value;

  let domStart = 0;
  let domEnd = 0;
  let cpIndex = 0;
  let foundStart = false;

  // Iterate by codepoint to map indices
  for (const char of text) {
    if (cpIndex === startCP) {
      domStart = domEnd;
      foundStart = true;
    }
    if (cpIndex === endCP) {
      break; // Reached exclusive end
    }

    // Advance DOM index by UTF-16 units (1 or 2)
    domEnd += char.length;
    cpIndex++;
  }
  
  // Handle edge case where range ends at EOF
  if (cpIndex === startCP) domStart = domEnd;

  textArea.focus();
  textArea.setSelectionRange(domStart, domEnd);
  
  // Force scroll to selection
  textArea.blur();
  textArea.focus();
};

/**
 * Bridge to Python Stepper
 * Passes the metric key and the current DOM cursor position.
 */
window.hud_jump = (key) => {
  const textArea = document.getElementById('text-input');
  // Use selectionStart to ensure we step forward from the beginning of current highlight
  // or selectionEnd if you prefer stepping from the end. 
  // Standard UX usually steps from the *end* of the current selection to find the next one.
  const currentPos = textArea.selectionEnd; 
  
  if (window.cycle_hud_metric) {
    window.cycle_hud_metric(key, currentPos);
  } else {
    console.warn("Python bridge 'cycle_hud_metric' not ready.");
  }
};

// ==========================================
// 12. SAFE COPY BRIDGE (From Python)
// ==========================================

/**
 * Handles the "Copy Safe Slice" action triggered from the Python renderer.
 * @param {string} safeText - The sanitized string passed from Python.
 * @param {HTMLElement} btnElement - The button element that was clicked.
 */
window.TEXTTICS_COPY_SAFE = async (safeText, btnElement) => {
  if (!safeText) return;

  try {
    await navigator.clipboard.writeText(safeText);

    // Visual Feedback
    const originalText = btnElement.innerText;
    btnElement.innerText = "Copied!";
    btnElement.classList.add('copied'); // Re-use the existing .copied style

    // Revert after 2 seconds
    setTimeout(() => {
      btnElement.innerText = originalText;
      btnElement.classList.remove('copied');
    }, 2000);

  } catch (err) {
    console.error("Safe Copy Failed:", err);
    btnElement.innerText = "Error!";
  }
};

// ==========================================
// 13. FORENSIC WORKBENCH BRIDGE
// ==========================================

document.addEventListener('DOMContentLoaded', () => {
    
    // --- A. Sanitization Handlers (Forensic Engine V2) ---
    // Wired to window.TEXTTICS_SANITIZE in app.py
    
    const btnStrict = document.getElementById('btn-sanitize-strict');
    const btnCons = document.getElementById('btn-sanitize-conservative');

    if (btnStrict) {
        btnStrict.addEventListener('click', () => {
            if (window.TEXTTICS_SANITIZE) {
                window.TEXTTICS_SANITIZE("strict");
            } else {
                console.warn("Python bridge 'TEXTTICS_SANITIZE' not ready.");
            }
        });
    }

    if (btnCons) {
        btnCons.addEventListener('click', () => {
            if (window.TEXTTICS_SANITIZE) {
                window.TEXTTICS_SANITIZE("smart");
            } else {
                console.warn("Python bridge 'TEXTTICS_SANITIZE' not ready.");
            }
        });
    }

    // --- B. Encapsulation Handlers ---
    // Expects window.py_get_code_snippet(lang) -> string
    const handleEscape = (lang) => {
        if (window.py_get_code_snippet) {
            const code = window.py_get_code_snippet(lang);
            if (code) {
                copyToClipboard(code, lang === 'python' ? 'btn-copy-py' : 'btn-copy-js');
            }
        } else {
            console.warn("Python bridge 'py_get_code_snippet' missing.");
        }
    };

    const btnPy = document.getElementById('btn-copy-py');
    if (btnPy) btnPy.addEventListener('click', () => handleEscape('python'));

    const btnJs = document.getElementById('btn-copy-js');
    if (btnJs) btnJs.addEventListener('click', () => handleEscape('javascript'));


    // --- C. Evidence Handler ---
    // Expects window.py_generate_evidence() -> triggers download
    const btnJson = document.getElementById('btn-export-json');
    if (btnJson) {
        btnJson.addEventListener('click', () => {
            if (window.py_generate_evidence) {
                window.py_generate_evidence(); 
            } else {
                console.warn("Python bridge 'py_generate_evidence' missing.");
            }
        });
    }
});
