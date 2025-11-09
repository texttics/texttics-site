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

            // Check if it has a 'Positions' column
            if (cells.length > 2 && cells[2].innerText) {
              const positions = cells[2].innerText;
              lines.push(`  ${sectionTitle}: ${metric}, ${count}, Positions: ${positions}`);
            } else {
              lines.push(`  ${sectionTitle}: ${metric}, ${count}`);
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
  report.push(...parseParallelTable('major-parallel-body', 'Major Category'));
  report.push(...parseParallelTable('minor-parallel-body', 'Minor Category'));

  // --- 3. Structural Shape ---
  report.push(`\n[ ${getText('#shape-title')} ]`);
  report.push(...parseTable('shape-matrix-body', 'Major Run'));
  report.push(...parseTable('minor-shape-matrix-body', 'Minor Run'));

  // --- 4. Forensic Integrity ---
  report.push(`\n[ ${getText('#integrity-title')} ]`);
  report.push(...parseTable('integrity-matrix-body', 'Flag'));

  // --- 5. Provenance & Context ---
  report.push(`\n[ ${getText('#prov-title')} ]`);
  report.push(...parseTable('provenance-matrix-body', 'Property'));

  // --- 6. Threat-Hunting (Placeholder) ---
  report.push(`\n[ ${getText('#threat-title')} ]`);
  report.push('  (No data from this section yet)');

  return report.join('\n');
}
