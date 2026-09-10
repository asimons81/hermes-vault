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
      button.style.borderColor = 'var(--accent-red)';
      button.style.color = 'var(--accent-red)';

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

// 8. Scroll Progress Bar & Floating Back-To-Top Button
const scrollProgress = document.getElementById('scroll-progress');
const btnBackToTop = document.getElementById('btn-back-to-top');

function handleScroll() {
  const scrollTop = window.scrollY || document.documentElement.scrollTop;
  const docHeight = document.documentElement.scrollHeight - document.documentElement.clientHeight;
  const scrollPercent = docHeight > 0 ? (scrollTop / docHeight) * 100 : 0;

  if (scrollProgress) {
    scrollProgress.style.width = `${scrollPercent}%`;
  }

  if (btnBackToTop) {
    if (scrollTop > 400) {
      btnBackToTop.classList.add('is-visible');
    } else {
      btnBackToTop.classList.remove('is-visible');
    }
  }
}

window.addEventListener('scroll', handleScroll, { passive: true });

if (btnBackToTop) {
  btnBackToTop.addEventListener('click', () => {
    window.scrollTo({ top: 0, behavior: 'smooth' });
  });
}

// 9. Dynamic Mouse Spotlight Effect on Spotlight Cards
const spotlightCards = document.querySelectorAll('.spotlight-card');
spotlightCards.forEach((card) => {
  card.addEventListener('mousemove', (e) => {
    const rect = card.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;
    card.style.setProperty('--mouse-x', `${x}px`);
    card.style.setProperty('--mouse-y', `${y}px`);
  });
});

// 10. Hero Quick Install Copy Button
const btnHeroCopy = document.getElementById('btn-hero-copy');
const heroCmdText = document.getElementById('hero-cmd-text');

if (btnHeroCopy && heroCmdText) {
  btnHeroCopy.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(heroCmdText.textContent.trim());
      showToast('Install command copied to clipboard');
      const span = btnHeroCopy.querySelector('span');
      if (span) {
        const orig = span.textContent;
        span.textContent = 'Copied!';
        setTimeout(() => { span.textContent = orig; }, 1800);
      }
    } catch {
      showToast('Copy failed, select text manually');
    }
  });
}

// 11. Policy Doctor & Permission Simulator Logic
const simAgentSelect = document.getElementById('sim-agent-select');
const simSecretSelect = document.getElementById('sim-secret-select');
const simActionSelect = document.getElementById('sim-action-select');
const policyVerdict = document.getElementById('policy-verdict');
const policyExplanation = document.getElementById('policy-explanation');
const polDrift = document.getElementById('pol-drift');
const polLease = document.getElementById('pol-lease');
const polAudit = document.getElementById('pol-audit');
const policyYamlCode = document.getElementById('policy-yaml-code');

function updatePolicySimulator() {
  if (!simAgentSelect || !simSecretSelect || !simActionSelect) return;

  const agent = simAgentSelect.value;
  const secret = simSecretSelect.value;
  const action = simActionSelect.value;

  let allow = false;
  let explanationText = '';
  let driftText = 'Clean (0)';
  let leaseText = 'None Required';
  let auditText = 'Chain Signed';
  let yamlSnippet = '';

  if (agent === 'hermes') {
    if (action === 'delete') {
      allow = false;
      explanationText = `Action <code>delete</code> on <code>${secret}</code> is destructive and rejected by default; requires explicit <code>--yes</code> confirmation token.`;
      driftText = 'Safety Gate';
      yamlSnippet = `agents:\n  hermes:\n    capabilities: [read, verify, rotate]\n    services:\n      ${secret}: [get_env, verify]\n# destructive actions locked to local CLI operator token`;
    } else {
      allow = true;
      explanationText = `Agent <code>hermes</code> is authorized to execute <code>${action}</code> on <code>${secret}</code> under explicit operator capabilities rule.`;
      leaseText = action === 'get_env' ? '15m TTL' : 'Direct Call';
      yamlSnippet = `agents:\n  hermes:\n    capabilities: [read, verify, rotate]\n    services:\n      ${secret}: [get_env, verify, rotate]`;
    }
  } else if (agent === 'claude') {
    if (action === 'get_env' || action === 'verify') {
      allow = true;
      explanationText = `Agent <code>claude-code</code> is authorized for <code>${action}</code> on <code>${secret}</code> via lease-enforced handoff rule.`;
      leaseText = 'Lease Required (15m TTL)';
      yamlSnippet = `agents:\n  claude-code:\n    capabilities: [read]\n    services:\n      ${secret}: [get_env, verify]\n    policy_constraints:\n      require_lease_for_env: true`;
    } else {
      allow = false;
      explanationText = `DENIED: Agent <code>claude-code</code> lacks capability <code>${action}</code> on service <code>${secret}</code> (least-privilege constraint).`;
      driftText = 'Denied Action';
      yamlSnippet = `agents:\n  claude-code:\n    capabilities: [read] # missing '${action}'\n    services:\n      ${secret}: [get_env]`;
    }
  } else { // untrusted
    allow = false;
    explanationText = `DENIED: Agent <code>untrusted-bot</code> is not defined in <code>policy.yaml</code>; zero-trust default deny rule applied.`;
    driftText = 'Zero-Trust Gate';
    auditText = 'Security Alert Logged';
    yamlSnippet = `# policy.yaml\ndefault_action: DENY\nuntrusted_agent_behavior: BLOCK_AND_AUDIT`;
  }

  if (policyVerdict) {
    policyVerdict.textContent = allow ? 'AUTHORIZED' : 'DENIED';
    policyVerdict.className = `verdict-badge ${allow ? 'verdict-allow' : 'verdict-deny'}`;
  }

  if (policyExplanation) {
    policyExplanation.innerHTML = explanationText;
  }

  if (polDrift) polDrift.textContent = driftText;
  if (polLease) polLease.textContent = leaseText;
  if (polAudit) polAudit.textContent = auditText;
  if (policyYamlCode) policyYamlCode.textContent = yamlSnippet;
}

if (simAgentSelect && simSecretSelect && simActionSelect) {
  simAgentSelect.addEventListener('change', updatePolicySimulator);
  simSecretSelect.addEventListener('change', updatePolicySimulator);
  simActionSelect.addEventListener('change', updatePolicySimulator);
}

// 12. Interactive Command Customizer Logic
const optInstallerPills = document.querySelectorAll('#opt-installer .opt-pill');
const optFlagsPills = document.querySelectorAll('#opt-flags .opt-pill');
const usersCodeEl = document.getElementById('users-code');

function updateCommandCustomizer() {
  if (!usersCodeEl) return;

  const activeInstallerEl = document.querySelector('#opt-installer .opt-pill.is-active');
  const installer = activeInstallerEl ? activeInstallerEl.dataset.val : 'uv';

  const activeFlags = [...document.querySelectorAll('#opt-flags .opt-pill.is-active')].map(p => p.dataset.val);

  let cmdLines = [];

  if (installer === 'uv') {
    cmdLines.push('uv tool install git+https://github.com/asimons81/hermes-vault.git@v0.25.1');
  } else if (installer === 'pipx') {
    cmdLines.push('pipx install git+https://github.com/asimons81/hermes-vault.git@v0.25.1');
  } else {
    cmdLines.push('git clone https://github.com/asimons81/hermes-vault.git && cd hermes-vault && uv sync');
  }

  cmdLines.push('hermes-vault setup');

  let bootstrapCmd = 'hermes-vault bootstrap --from-env .env --agent hermes';
  if (activeFlags.includes('dry-run')) bootstrapCmd += ' --dry-run';
  cmdLines.push(bootstrapCmd);

  cmdLines.push('hermes-vault health');

  let auditCmd = 'hermes-vault audit-verify';
  if (activeFlags.includes('integrity')) auditCmd += ' --with-integrity';
  cmdLines.push(auditCmd);

  if (activeFlags.includes('desktop')) {
    cmdLines.push('HERMES_VAULT_DESKTOP_MUTATIONS=1 hermes-vault-desktop --allow-mutations');
  } else {
    cmdLines.push('hermes-vault policy explain hermes openai --action get_env');
  }

  usersCodeEl.textContent = cmdLines.join('\n');
}

optInstallerPills.forEach((pill) => {
  pill.addEventListener('click', () => {
    optInstallerPills.forEach(p => p.classList.remove('is-active'));
    pill.classList.add('is-active');
    updateCommandCustomizer();
  });
});

optFlagsPills.forEach((pill) => {
  pill.addEventListener('click', () => {
    pill.classList.toggle('is-active');
    updateCommandCustomizer();
  });
});

// 13. Release Timeline Filters
const releaseFilterPills = document.querySelectorAll('#release-filters .filter-pill');
const releaseFeaturedCard = document.querySelector('.release-featured');
const releaseRows = document.querySelectorAll('.release-row');

releaseFilterPills.forEach((pill) => {
  pill.addEventListener('click', () => {
    const filter = pill.dataset.filter;

    releaseFilterPills.forEach(p => p.classList.remove('is-active'));
    pill.classList.add('is-active');

    if (releaseFeaturedCard) {
      const featCat = releaseFeaturedCard.dataset.category;
      if (filter === 'all' || featCat === filter) {
        releaseFeaturedCard.style.display = 'block';
      } else {
        releaseFeaturedCard.style.display = 'none';
      }
    }

    releaseRows.forEach((row) => {
      const rowCat = row.dataset.category;
      if (filter === 'all' || rowCat === filter) {
        row.style.display = 'flex';
      } else {
        row.style.display = 'none';
      }
    });
  });
});

