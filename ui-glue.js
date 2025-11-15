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
  // This helper builds the structured text string you wanted
  let report = [];

  // --- Helper Functions ---
  const getText = (selector) => document.querySelector(selector)?.innerText || '';
  const getVal = (selector) => document.querySelector(selector)?.value || '';

  const parseCards = (elementId) => {
    const lines = [];
    const cardContainer = document.getElementById(elementId);
    if (cardContainer) {
      cardContainer.querySelectorAll('.card').forEach(card => {
        const label = card.querySelector('strong')?.innerText || 'Unknown';
        const value = card.querySelector('div')?.innerText || 'N/A';
        lines.push(`  ${label}: ${value}`);
      });
    }
    return lines;
  };

const parseTable = (tbodyId, sectionTitle) => {
  const lines = [];
  const tbody = document.getElementById(tbodyId);
  if (tbody) {
    tbody.querySelectorAll('tr').forEach(row => {
      const cells = row.querySelectorAll('th, td');
      if (cells.length === 0 || row.querySelector('.placeholder-text')) {
        return;
      }

      const metric = cells[0].innerText;
      const count = cells[1].innerText;

      // optional Positions column
      const hasPositions = cells.length > 2 && cells[2].innerText;
      const positions = hasPositions ? cells[2].innerText : null;

      // ✅ Build prefix only if sectionTitle is non-empty
      const prefix = sectionTitle ? `${sectionTitle}: ` : '';

      if (hasPositions) {
        lines.push(`  ${prefix}${metric}, ${count}, Positions: ${positions}`);
      } else {
        lines.push(`  ${prefix}${metric}, ${count}`);
      }
    });
  }
  return lines;
};

  const parseParallelTable = (tbodyId, sectionTitle) => {
    const lines = [];
    const tbody = document.getElementById(tbodyId);
    if (tbody) {
      tbody.querySelectorAll('tr').forEach(row => {
        const cells = row.querySelectorAll('th, td');
        if (cells.length === 3) {
          lines.push(`  ${sectionTitle}: ${cells[0].innerText} (Code Points: ${cells[1].innerText}, Graphemes: ${cells[2].innerText})`);
        }
      });
    }
    return lines;
  };

  // --- 1. Build the Report ---
  report.push('--- Text...tics Structural Profile ---');
  report.push(`Timestamp: ${new Date().toISOString()}`);
  report.push('\n[ Analysis Configuration ]');
  report.push(`Input Text:\n"""\n${getVal('#text-input')}\n"""`);

  // --- 2. Dual-Atom Profile ---
  report.push('\n[ Dual-Atom Fingerprint ]');
  report.push(...parseCards('meta-totals-cards'));
  report.push(...parseCards('grapheme-integrity-cards'));
  report.push(...parseTable('ccc-matrix-body', 'Combining Class'));
  report.push(...parseParallelTable('major-parallel-body', 'Major Category'));
  report.push(...parseParallelTable('minor-parallel-body', 'Minor Category'));

  // --- 3. Structural Shape ---
  report.push(`\n[ ${getText('#shape-title')} ]`);
  report.push(...parseTable('shape-matrix-body', 'Major Run'));
  report.push(...parseTable('minor-shape-matrix-body', 'Minor Run'));
  report.push(...parseTable('linebreak-run-matrix-body', 'LineBreak Run'));
  report.push(...parseTable('bidi-run-matrix-body', 'Bidi Class Run'));
  report.push(...parseTable('wordbreak-run-matrix-body', 'WordBreak Run'));
  report.push(...parseTable('sentencebreak-run-matrix-body', 'SentenceBreak Run'));
  report.push(...parseTable('graphemebreak-run-matrix-body', 'GraphemeBreak Run'));
  report.push(...parseTable('eawidth-run-matrix-body', 'EastAsianWidth Run'));
  report.push(...parseTable('vo-run-matrix-body', 'VerticalOrientation Run'));

  // --- 4. Forensic Integrity ---
  report.push(`\n[ ${getText('#integrity-title')} ]`);
  report.push(...parseTable('integrity-matrix-body', ''));

  // --- 5. Provenance & Context ---
  report.push(`\n[ ${getText('#prov-title')} ]`);
  report.push(...parseTable('provenance-matrix-body', 'Property'));
  report.push(...parseTable('script-run-matrix-body', 'Script Run'));

  report.push(`\n[ Emoji Qualification Profile ]`);

  // CUSTOM PARSER for 4-column Emoji table
  const emojiTbody = document.getElementById('emoji-qualification-body');
  if (emojiTbody) {
      emojiTbody.querySelectorAll('tr').forEach(row => {
          // Note: The `innerText` property automatically handles the <details> logic,
          // so we just replace newlines from the <summary>/<div> structure with a space.
          const cells = row.querySelectorAll('th, td');
          if (cells.length === 4) {
              const sequence = cells[0].innerText;
              const status = cells[1].innerText;
              const count = cells[2].innerText;
              const positions = cells[3].innerText.replace(/\n/g, ' '); 
  
              report.push(`    Emoji: ${sequence} (${status}), ${count}, Positions: ${positions}`);
          }
      });
  }
  

  // --- 6. Threat-Hunting ---
  report.push(`\n[ ${getText('#threat-title')} ]`);
  
  // 6.A - Scrape the threat flags from the correct table
  // THIS IS THE FIX
  const threatMatrixRows = parseTable('threat-report-body', 'Flag');
  if (threatMatrixRows.length > 0) {
    report.push(...threatMatrixRows);
  }
  
  // 6.B - Scrape the hash table
  // Note: We re-use 'parseTable' but give it a custom title
  const hashRows = parseTable('threat-hash-report-body', 'Hash');
  if (hashRows.length > 0) {
    report.push(...hashRows);
  }

// --- 7. Perception vs. Reality (Forensic States) ---
  if (window.latest_threat_data) {
      const t = window.latest_threat_data;
      
      // Note: 't' is a Python Dictionary Proxy, so we must use .get() 
      // instead of dot notation (t.raw)
      report.push('\n[ Perception vs. Reality (Forensic States) ]');
      report.push(`1. Forensic (Raw):   ${t.get('raw')}`);
      report.push(`2. NFKC:             ${t.get('nfkc')}`);
      report.push(`3. NFKC-Casefold:    ${t.get('nfkc_cf')}`);
      report.push(`4. UTS #39 Skeleton: ${t.get('skeleton')}`);
  }

  return report.join('\n');
}
