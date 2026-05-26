// Elements
const yearEl = document.querySelector('[data-year]');
const toast = document.querySelector('.toast');
const tabs = [...document.querySelectorAll('.tab-button')];
const panels = [...document.querySelectorAll('[data-panel]')];
const copyButtons = [...document.querySelectorAll('[data-copy-target]')];
const tabGlider = document.getElementById('tab-glider');
const revealElements = [...document.querySelectorAll('.reveal')];

// Secrets Simulator Elements
const btnScan = document.getElementById('btn-scan');
const envOpenAI = document.getElementById('env-line-openai');
const envGitHub = document.getElementById('env-line-github');
const vaultEmpty = document.getElementById('vault-empty');
const vaultInventory = document.getElementById('vault-inventory');

// MCP Simulator Elements
const btnMcp = document.getElementById('btn-mcp');
const mcpStage1 = document.getElementById('mcp-stage-1');
const mcpStage2 = document.getElementById('mcp-stage-2');
const mcpStage3 = document.getElementById('mcp-stage-3');
const mcpStatus1 = document.querySelector('.status-1');
const mcpStatus2 = document.querySelector('.status-2');
const mcpStatus3 = document.querySelector('.status-3');
const mcpProgress = document.getElementById('mcp-progress');

// 1. Toast Notification Helper
function showToast(message) {
  if (!toast) return;
  toast.textContent = message;
  toast.classList.add('is-visible');
  window.clearTimeout(showToast.timer);
  showToast.timer = window.setTimeout(() => toast.classList.remove('is-visible'), 2000);
}

// 2. Scroll-triggered Page Reveals
if ('IntersectionObserver' in window && revealElements.length) {
  const revealObserver = new IntersectionObserver((entries) => {
    entries.forEach((entry) => {
      if (entry.isIntersecting) {
        entry.target.classList.add('revealed');
        revealObserver.unobserve(entry.target);
      }
    });
  }, {
    root: null,
    rootMargin: '0px 0px -10% 0px',
    threshold: 0.05,
  });

  revealElements.forEach((el) => revealObserver.observe(el));
}

// 3. Tab Glider Alignment & Activation
function updateTabGlider(activeTab) {
  if (!tabGlider || !activeTab) return;
  tabGlider.style.left = `${activeTab.offsetLeft}px`;
  tabGlider.style.width = `${activeTab.offsetWidth}px`;
}

function activateTab(tabName) {
  const activeTab = tabs.find((tab) => tab.dataset.tab === tabName);
  if (!activeTab) return;

  tabs.forEach((tab) => {
    const active = tab === activeTab;
    tab.classList.toggle('is-active', active);
    tab.setAttribute('aria-selected', active ? 'true' : 'false');
    tab.tabIndex = active ? 0 : -1;
  });

  panels.forEach((panel) => {
    const active = panel.dataset.panel === tabName;
    panel.classList.toggle('is-active', active);
    panel.hidden = !active;
  });

  updateTabGlider(activeTab);
}

tabs.forEach((tab) => {
  tab.addEventListener('click', () => activateTab(tab.dataset.tab));
});

window.addEventListener('resize', () => {
  const activeTab = tabs.find((tab) => tab.classList.contains('is-active'));
  if (activeTab) updateTabGlider(activeTab);
});

// 4. Secret Redaction Simulator
if (btnScan) {
  btnScan.addEventListener('click', () => {
    btnScan.disabled = true;
    btnScan.textContent = 'Previewing...';
    btnScan.style.color = 'var(--text-dim)';
    btnScan.style.borderColor = 'var(--border)';

    // Step 1: Animate Scan/Redaction
    window.setTimeout(() => {
      if (envOpenAI) {
        envOpenAI.classList.remove('danger');
        envOpenAI.classList.add('secured');
        envOpenAI.innerHTML = 'OPENAI_API_KEY="# imported by bootstrap [alias: openai_api_key]"';
      }
    }, 1000);

    window.setTimeout(() => {
      if (envGitHub) {
        envGitHub.classList.remove('danger');
        envGitHub.classList.add('secured');
        envGitHub.innerHTML = 'GITHUB_TOKEN="# imported by bootstrap [alias: github_token]"';
      }
    }, 1800);

    // Step 2: Populate Vault Records
    window.setTimeout(() => {
      if (vaultEmpty) vaultEmpty.style.display = 'none';

      // Append OpenAI key metadata card
      const openAiCard = document.createElement('div');
      openAiCard.className = 'vault-record';
      openAiCard.innerHTML = `
        <div class="vault-record-details">
          <span class="vault-record-name">openai</span>
          <span class="vault-record-meta">alias: primary &bull; tag: prod-key</span>
        </div>
        <span class="vault-record-status encrypted">encrypted</span>
      `;
      vaultInventory.appendChild(openAiCard);
      showToast('Vault: OpenAI credential imported securely');
    }, 1200);

    window.setTimeout(() => {
      // Append GitHub token metadata card
      const githubCard = document.createElement('div');
      githubCard.className = 'vault-record';
      githubCard.innerHTML = `
        <div class="vault-record-details">
          <span class="vault-record-name">github</span>
          <span class="vault-record-meta">alias: primary &bull; tag: personal</span>
        </div>
        <span class="vault-record-status encrypted">encrypted</span>
      `;
      vaultInventory.appendChild(githubCard);
      showToast('Vault: GitHub credential imported securely');
      
      btnScan.textContent = 'Bootstrap Report Ready';
      btnScan.style.color = 'var(--accent-emerald)';
      btnScan.style.borderColor = 'var(--accent-emerald)';
    }, 2000);
  });
}

// 5. MCP Tool Lifecycle Timeline Simulator
let mcpTimelineTimer = null;
if (btnMcp) {
  btnMcp.addEventListener('click', () => {
    btnMcp.disabled = true;
    btnMcp.textContent = 'Brokering...';
    window.clearTimeout(mcpTimelineTimer);

    // Reset Timeline visual stages
    const stages = [mcpStage1, mcpStage2, mcpStage3];
    stages.forEach(stage => {
      if (stage) stage.classList.remove('is-active');
    });
    if (mcpStatus1) { mcpStatus1.textContent = 'Idle'; mcpStatus1.className = 'mcp-stage-badge status-1'; }
    if (mcpStatus2) { mcpStatus2.textContent = 'Idle'; mcpStatus2.className = 'mcp-stage-badge status-2'; }
    if (mcpStatus3) { mcpStatus3.textContent = 'Idle'; mcpStatus3.className = 'mcp-stage-badge status-3'; }
    if (mcpProgress) {
      mcpProgress.style.transition = 'none';
      mcpProgress.style.transform = 'scaleX(0)';
    }

    // Step 1: Agent Tool Request
    window.setTimeout(() => {
      if (mcpStage1) mcpStage1.classList.add('is-active');
      if (mcpStatus1) {
        mcpStatus1.textContent = 'Calling tool...';
        mcpStatus1.classList.add('running');
      }
    }, 200);

    window.setTimeout(() => {
      if (mcpStatus1) {
        mcpStatus1.textContent = 'get_ephemeral_env()';
        mcpStatus1.classList.remove('running');
        mcpStatus1.classList.add('success');
      }
    }, 1200);

    // Step 2: Policy Allow Check
    window.setTimeout(() => {
      if (mcpStage2) mcpStage2.classList.add('is-active');
      if (mcpStatus2) {
        mcpStatus2.textContent = 'Evaluating policy...';
        mcpStatus2.classList.add('running');
      }
    }, 1500);

    window.setTimeout(() => {
      if (mcpStatus2) {
        mcpStatus2.textContent = 'Authorized (policy.yaml)';
        mcpStatus2.classList.remove('running');
        mcpStatus2.classList.add('success');
      }
      showToast('Vault: Access request approved by policy doctor');
    }, 2500);

    // Step 3: Materialization Injection
    window.setTimeout(() => {
      if (mcpStage3) mcpStage3.classList.add('is-active');
      if (mcpStatus3) {
        mcpStatus3.textContent = 'Active (TTL 15s)';
        mcpStatus3.classList.add('running');
      }

      // Inpage progress timer animation (scale from 1 to 0 over 15s)
      if (mcpProgress) {
        mcpProgress.style.transition = 'none';
        mcpProgress.style.transform = 'scaleX(1)';
        
        // Force reflow
        mcpProgress.offsetHeight;
        
        mcpProgress.style.transition = 'transform 15s linear';
        mcpProgress.style.transform = 'scaleX(0)';
      }
    }, 2800);

    // Step 4: Expiration Cleanup
    mcpTimelineTimer = window.setTimeout(() => {
      if (mcpStatus3) {
        mcpStatus3.textContent = 'Expired / Revoked';
        mcpStatus3.classList.remove('running');
        mcpStatus3.style.color = 'var(--text-dim)';
        mcpStatus3.style.borderColor = 'var(--border)';
        mcpStatus3.style.background = 'transparent';
      }
      if (mcpStage3) mcpStage3.classList.remove('is-active');
      
      btnMcp.disabled = false;
      btnMcp.textContent = 'Request Token via MCP';
      showToast('Vault: Key materialized lifecycle ended, variable scrubbed');
    }, 17800); // 2800ms offset + 15000ms duration
  });
}

// 6. Secure Clipboard Copies
copyButtons.forEach((button) => {
  button.addEventListener('click', async () => {
    const targetId = button.dataset.copyTarget;
    const codeEl = document.getElementById(targetId);
    if (!codeEl) return;

    const codeText = codeEl.textContent.trim();
    if (!codeText) return;

    try {
      await navigator.clipboard.writeText(codeText);
      showToast('Commands copied to clipboard');

      const originalText = button.textContent;
      button.textContent = 'Copied!';
      button.style.borderColor = 'var(--accent-blue)';
      button.style.color = 'var(--accent-blue)';

      window.setTimeout(() => {
        button.textContent = originalText;
        button.style.borderColor = '';
        button.style.color = '';
      }, 1500);
    } catch {
      showToast('Copy failed, select manually');
    }
  });
});

// 7. Initialization
activateTab('users');

if (yearEl) {
  yearEl.textContent = String(new Date().getFullYear());
}

window.addEventListener('load', () => {
  document.documentElement.classList.add('ready');
});
