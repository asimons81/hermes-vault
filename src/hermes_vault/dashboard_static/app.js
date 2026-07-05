const params = new URLSearchParams(window.location.search);
const token = params.get("token") || sessionStorage.getItem("hv-dashboard-token") || "";
const apiBase = params.get("api_base") || sessionStorage.getItem("hv-dashboard-api-base") || "";
if (token) {
  sessionStorage.setItem("hv-dashboard-token", token);
  if (apiBase) sessionStorage.setItem("hv-dashboard-api-base", apiBase);
  if (params.has("token")) {
    params.delete("token");
    params.delete("api_base");
    const query = params.toString();
    window.history.replaceState({}, "", `${window.location.pathname}${query ? `?${query}` : ""}`);
  }
}

const introVersion = "dashboard-v1";
const introKey = `hv-console-intro-${introVersion}`;
const introSeenDelayMs = 4550;
const intro = document.querySelector("#intro");
if (intro && (params.get("no_intro") === "1" || localStorage.getItem(introKey) === "seen")) {
  intro.classList.add("skip");
} else if (intro) {
  let introRecorded = false;
  const recordIntroSeen = () => {
    if (introRecorded) return;
    introRecorded = true;
    localStorage.setItem(introKey, "seen");
  };
  intro.addEventListener("animationend", (event) => {
    if (event.animationName === "intro-exit") recordIntroSeen();
  });
  window.setTimeout(recordIntroSeen, introSeenDelayMs);
}

const state = {
  view: "overview",
  loading: true,
  overview: null,
  credentials: [],
  leases: [],
  verificationResults: {},
  policy: null,
  profiles: [],
  audit: [],
  requests: [],
  agentContext: null,
  policyExplain: null,
  filters: {
    credentials: "",
    credentialStatus: "",
    credentialSort: "service",
    leases: "",
    leaseStatus: "",
    leaseSort: "expires_at",
    audit: "",
    auditSort: "timestamp",
  },
  onboardingPreview: null,
  recovery: {},
  recoveryDrill: null,
};

const qs = (selector) => document.querySelector(selector);
const qsa = (selector) => Array.from(document.querySelectorAll(selector));

function api(path, options = {}) {
  return fetch(`${apiBase}${path}`, {
    ...options,
    headers: {
      "Authorization": `Bearer ${token}`,
      "Content-Type": "application/json",
      ...(options.headers || {}),
    },
  }).then(async (response) => {
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(payload.error || `Request failed with ${response.status}`);
    }
    return payload;
  });
}

function fmt(value) {
  if (value === null || value === undefined || value === "") return "-";
  return String(value);
}

function escapeHtml(value) {
  return fmt(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function shortDate(value) {
  if (!value) return "-";
  return String(value).slice(0, 19).replace("T", " ");
}

function credentialKey(service, alias) {
  return `${service || ""}::${alias || "default"}`;
}

function updateNavGlider() {
  const activeBtn = qs(".nav-item.active");
  const glider = qs("#nav-indicator");
  if (!activeBtn || !glider) return;
  const parentRect = activeBtn.parentElement.getBoundingClientRect();
  const rect = activeBtn.getBoundingClientRect();
  glider.style.opacity = "1";
  glider.style.height = `${rect.height}px`;
  glider.style.width = `${rect.width}px`;
  glider.style.transform = `translate(${rect.left - parentRect.left}px, ${rect.top - parentRect.top}px)`;
}

function formatExpiry(expiryStr) {
  if (!expiryStr) return "-";
  const expiry = new Date(expiryStr);
  const now = new Date();
  const diffTime = expiry - now;
  const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
  const formattedDate = shortDate(expiryStr);
  if (diffDays < 0) {
    return `<span style="color: var(--red); font-weight: bold;">Expired (${Math.abs(diffDays)}d ago)</span><br><span style="font-size:11px; opacity:0.6">${formattedDate}</span>`;
  } else if (diffDays <= 30) {
    return `<span style="color: var(--gold); font-weight: bold;">Expires in ${diffDays}d</span><br><span style="font-size:11px; opacity:0.6">${formattedDate}</span>`;
  }
  return `<span>${formattedDate}</span>`;
}

function searchable(record, fields) {
  return fields.map((field) => {
    const value = record[field];
    return Array.isArray(value) ? value.join(" ") : fmt(value);
  }).join(" ").toLowerCase();
}

function matchesText(record, fields, query) {
  const value = (query || "").trim().toLowerCase();
  return !value || searchable(record, fields).includes(value);
}

function sortBy(records, field, direction = "asc") {
  const factor = direction === "desc" ? -1 : 1;
  return [...records].sort((a, b) => {
    const left = fmt(a[field]).toLowerCase();
    const right = fmt(b[field]).toLowerCase();
    if (left < right) return -1 * factor;
    if (left > right) return 1 * factor;
    return 0;
  });
}

function verificationLabel(result) {
  if (!result) return "-";
  const verification = (result.metadata && result.metadata.verification_result) || {};
  const category = verification.category || "unknown";
  if (category === "unknown" && /No provider-specific verifier/.test(result.reason || "")) {
    return "Not verifiable yet";
  }
  if (category === "valid") return "Verified";
  return category.replaceAll("_", " ");
}

function verificationTone(result) {
  if (!result) return "";
  const verification = (result.metadata && result.metadata.verification_result) || {};
  if (verification.category === "valid") return "active";
  if (verification.category === "invalid_or_expired") return "invalid";
  return "unknown";
}

function verificationDetail(result) {
  if (!result) return "";
  const verification = (result.metadata && result.metadata.verification_result) || {};
  return verification.reason || result.reason || "";
}

function setConnection(label, tone = "ready") {
  const connection = qs("#connection");
  connection.textContent = label;
  connection.closest(".rail-status").dataset.tone = tone;
}

function setButtonBusy(button, busy, label) {
  if (!button) return;
  if (!button.dataset.idleLabel) button.dataset.idleLabel = button.textContent.trim();
  button.classList.toggle("is-busy", busy);
  button.disabled = busy;
  button.textContent = busy ? label : button.dataset.idleLabel;
}

function itemNode({ title, detail = "", tone = "", meta = "" }) {
  const node = document.createElement("div");
  node.className = `item ${tone}`.trim();
  const safeMeta = meta ? `<span>${escapeHtml(meta)}</span>` : "";
  node.innerHTML = `
    <div>
      <strong>${escapeHtml(title)}</strong>
      ${detail ? `<p>${escapeHtml(detail)}</p>` : ""}
    </div>
    ${safeMeta}
  `;
  return node;
}

function renderItems(target, items, emptyText) {
  target.innerHTML = "";
  if (!items.length) {
    target.append(itemNode({ title: emptyText, tone: "good" }));
    return;
  }
  for (const item of items) target.append(item);
}

function renderTable(target, columns, rows, emptyText) {
  const header = columns.map((column) => `<th>${escapeHtml(column)}</th>`).join("");
  const body = rows.length
    ? rows.join("")
    : `<tr class="empty-row"><td colspan="${columns.length}">${escapeHtml(emptyText)}</td></tr>`;
  target.innerHTML = `
    <table>
      <thead><tr>${header}</tr></thead>
      <tbody>${body}</tbody>
    </table>
  `;
}

function runtimeDiagnostic() {
  const runtime = (state.overview && state.overview.runtime)
    || (state.credentialsRuntime)
    || {};
  const home = runtime.runtime_home || "-";
  const dbPath = runtime.db_path || "-";
  const policyPath = runtime.policy_path || "-";
  const passphraseSource = runtime.passphrase_source || "-";
  const homeSource = runtime.home_source || "-";
  const isTempRuntime = Boolean(runtime.is_temp_runtime);
  const profile = runtime.profile || "default";
  const profileHome = runtime.profile_home || home;
  const policySource = runtime.policy_source || "profile";
  return { home, dbPath, policyPath, passphraseSource, homeSource, isTempRuntime, profile, profileHome, policySource };
}

function keyValidation() {
  return (state.overview && state.overview.runtime && state.overview.runtime.key_validation)
    || (state.credentialsRuntime && state.credentialsRuntime.key_validation)
    || { status: "unknown", ok: true, reason: "" };
}

function keyValid() {
  const validation = keyValidation();
  return validation.ok !== false;
}

function renderKeyWarning() {
  const warning = qs("#key-warning");
  const validation = keyValidation();
  const invalid = validation.ok === false;
  const degraded = validation.status === "degraded";
  const visible = invalid || degraded;
  warning.hidden = !visible;
  warning.dataset.tone = invalid ? "error" : "warning";
  if (invalid) {
    warning.querySelector("strong").textContent = "Vault key mismatch";
    warning.querySelector("p").textContent = `${validation.reason || "Vault key material is not valid."} Stop the dashboard and relaunch with the correct Hermes Vault passphrase.`;
  } else if (degraded) {
    warning.querySelector("strong").textContent = "Vault key validated with credential warnings";
    warning.querySelector("p").textContent = `${validation.reason || "Some credential records could not be decrypted."} Secret-backed actions remain available, but affected credentials may fail until repaired.`;
  }
  qsa("[data-secret-action='true']").forEach((button) => {
    button.disabled = invalid;
    button.title = invalid ? "Unavailable until the dashboard is relaunched with the correct vault passphrase." : "";
  });
}

function renderLoading() {
  qsa(".stack").forEach((target) => {
    target.innerHTML = `
      <div class="skeleton-line"></div>
      <div class="skeleton-line short"></div>
      <div class="skeleton-line"></div>
    `;
  });
  qsa(".table").forEach((target) => {
    target.innerHTML = `
      <div class="table-loading">
        <div class="skeleton-line"></div>
        <div class="skeleton-line"></div>
        <div class="skeleton-line short"></div>
      </div>
    `;
  });
}

async function loadAll(button) {
  state.loading = true;
  setButtonBusy(button, true, "Refreshing");
  setConnection("Refreshing", "busy");
  renderLoading();
  try {
    const [overview, credentials, policy, audit, profiles, leases, requests] = await Promise.all([
      api("/api/overview"),
      api("/api/credentials"),
      api("/api/policy"),
      api("/api/audit?limit=60"),
      api("/api/profiles"),
      api("/api/leases"),
      api("/api/requests"),
    ]);
    state.overview = overview;
    state.credentials = credentials.credentials || [];
    state.credentialsRuntime = credentials.runtime || null;
    state.policy = policy;
    state.audit = audit.entries || [];
    state.profiles = profiles.profiles || [];
    state.leases = leases.leases || [];
    state.requests = requests.requests || [];
    render();
    setConnection("Local session", "ready");
  } catch (error) {
    setConnection("Session error", "error");
    qs("#action-output").textContent = error.message;
    throw error;
  } finally {
    state.loading = false;
    setButtonBusy(button, false);
  }
}

function render() {
  renderKeyWarning();
  renderProfileBadge();
  renderOverview();
  renderOnboarding();
  renderCredentials();
  renderPolicy();
  renderCommand();
  renderLeases();
  renderAudit();
  renderRecoverySummary();
  updateNavGlider();
}

function renderProfileBadge() {
  const badge = qs("#profile-badge");
  if (!badge) return;
  const diagnostic = runtimeDiagnostic();
  const profiles = state.profiles || [];
  const options = profiles.map((profile) => `
    <option value="${escapeHtml(profile.name)}" ${profile.active ? "selected" : ""}>${escapeHtml(profile.name)}</option>
  `).join("");
  badge.innerHTML = `
    <label>
      <span>Profile</span>
      <select id="profile-select" aria-label="Vault profile">${options || `<option value="${escapeHtml(diagnostic.profile)}">${escapeHtml(diagnostic.profile)}</option>`}</select>
    </label>
    <div>Vault: ${escapeHtml(diagnostic.profileHome)}</div>
    <div>Policy: ${escapeHtml(diagnostic.policySource)}</div>
  `;
}

function renderOverview() {
  const overview = state.overview || {};
  const health = overview.health || {};
  const doctor = overview.policy_doctor || {};
  qs("#metric-credentials").textContent = overview.credential_count || 0;
  qs("#metric-services").textContent = (overview.services || []).length;
  qs("#metric-health").textContent = (health.findings || []).length;
  qs("#metric-policy").textContent = doctor.finding_count || 0;
  qs("#metric-leases").textContent = overview.lease_count || 0;

  const healthItems = (health.findings || []).slice(0, 8).map((finding) => itemNode({
    title: fmt(finding.kind),
    detail: `${fmt(finding.service)}/${fmt(finding.alias)} - ${fmt(finding.detail)}`,
    tone: "warning",
  }));
  renderItems(qs("#health-summary"), healthItems, health.healthy ? "Vault health is clear." : "No current health findings.");

  const mcp = overview.mcp || {};
  const allowedAgents = (mcp.allowed_agents || []).join(", ") || "-";
  qs("#mcp-summary").innerHTML = "";
  qs("#mcp-summary").append(itemNode({
    title: mcp.binding_enabled ? "Bound mode" : "Unrestricted mode",
    detail: `Default agent: ${fmt(mcp.default_agent)}. Allowed agents: ${allowedAgents}`,
    tone: mcp.binding_enabled ? "good" : "warning",
  }));
}

function renderOnboarding() {
  const target = qs("#onboarding-summary");
  if (!target) return;
  const preview = state.onboardingPreview;
  if (!preview) {
    target.innerHTML = `
      <article class="summary-card"><span>Importable</span><strong>-</strong></article>
      <article class="summary-card"><span>Skipped</span><strong>-</strong></article>
      <article class="summary-card"><span>Policy Findings</span><strong>-</strong></article>
      <article class="summary-card"><span>Boundary</span><strong>Dry-run</strong></article>
    `;
    return;
  }
  const importPreview = preview.import_preview || {};
  const policy = preview.policy_doctor_summary || {};
  target.innerHTML = `
    <article class="summary-card"><span>Importable</span><strong>${escapeHtml(importPreview.importable_count || 0)}</strong></article>
    <article class="summary-card"><span>Skipped</span><strong>${escapeHtml(importPreview.skipped_count || 0)}</strong></article>
    <article class="summary-card"><span>Policy Findings</span><strong>${escapeHtml(policy.finding_count || 0)}</strong></article>
    <article class="summary-card"><span>Raw Values</span><strong>${preview.raw_values_returned ? "Returned" : "Redacted"}</strong></article>
  `;
}

function renderTagChips(tags) {
  const safeTags = Array.isArray(tags) ? tags : [];
  if (!safeTags.length) return "-";
  return `<span class="tag-list">${safeTags.map((tag) => `<span class="tag-chip">${escapeHtml(tag)}</span>`).join("")}</span>`;
}

function renderCredentials() {
  const filtered = sortBy(
    state.credentials.filter((record) => {
      const statusOk = !state.filters.credentialStatus || record.status === state.filters.credentialStatus;
      return statusOk && matchesText(record, ["service", "alias", "credential_type", "status", "tags", "notes"], state.filters.credentials);
    }),
    state.filters.credentialSort || "service",
    state.filters.credentialSort === "last_verified_at" || state.filters.credentialSort === "expiry" ? "desc" : "asc",
  );
  const rows = filtered.map((record) => `
    <tr>
      <td><strong>${escapeHtml(record.service)}</strong></td>
      <td>${escapeHtml(record.alias)}</td>
      <td>${escapeHtml(record.credential_type)}</td>
      <td>${renderTagChips(record.tags)}</td>
      <td>
        ${record.notes ? `<p class="cell-note metadata-note">${escapeHtml(record.notes)}</p>` : "-"}
      </td>
      <td><span class="status ${escapeHtml(record.status)}">${escapeHtml(record.status)}</span></td>
      <td>
        <span class="status ${escapeHtml(verificationTone(state.verificationResults[credentialKey(record.service, record.alias)]))}">${escapeHtml(verificationLabel(state.verificationResults[credentialKey(record.service, record.alias)]))}</span>
        ${verificationDetail(state.verificationResults[credentialKey(record.service, record.alias)]) ? `<p class="cell-note">${escapeHtml(verificationDetail(state.verificationResults[credentialKey(record.service, record.alias)]))}</p>` : ""}
      </td>
      <td>${escapeHtml(shortDate(record.last_verified_at))}</td>
      <td>${formatExpiry(record.expiry)}</td>
      <td><button class="ghost-button compact" type="button" data-secret-action="true" data-verify-service="${escapeHtml(record.service)}" data-verify-alias="${escapeHtml(record.alias)}" ${keyValid() ? "" : "disabled"}>Verify</button></td>
    </tr>
  `);
  if (rows.length) {
    renderTable(
      qs("#credential-table"),
      ["Service", "Alias", "Type", "Tags", "Notes", "Status", "Verification", "Last Verified", "Expiry", "Action"],
      rows,
      state.credentials.length ? "No credentials match the current filters." : "No credentials in the vault.",
    );
    return;
  }

  const diagnostic = runtimeDiagnostic();
  qs("#credential-table").innerHTML = `
    <div class="empty-diagnostic">
      <strong>No credentials found in this runtime.</strong>
      <p>${diagnostic.isTempRuntime ? "This looks like a temporary/demo runtime. " : ""}Hermes Vault is reading the runtime below. If you expected credentials, relaunch without a demo <code>HERMES_VAULT_HOME</code> or verify that the passphrase matches this vault.</p>
      <dl>
        <dt>Profile</dt><dd>${escapeHtml(diagnostic.profile)}</dd>
        <dt>Runtime home</dt><dd>${escapeHtml(diagnostic.home)}</dd>
        <dt>Home source</dt><dd>${escapeHtml(diagnostic.homeSource)}</dd>
        <dt>Vault database</dt><dd>${escapeHtml(diagnostic.dbPath)}</dd>
        <dt>Policy file</dt><dd>${escapeHtml(diagnostic.policyPath)}</dd>
        <dt>Passphrase source</dt><dd>${escapeHtml(diagnostic.passphraseSource)}</dd>
      </dl>
    </div>
  `;
}

function renderPolicy() {
  const doctor = (state.policy && state.policy.doctor) || {};
  const findings = (doctor.findings || []).map((finding) => itemNode({
    title: `${fmt(finding.severity)}: ${fmt(finding.kind)}`,
    detail: `${fmt(finding.agent_id)} - ${fmt(finding.detail)}`,
    tone: "warning",
  }));
  renderItems(qs("#policy-findings"), findings, "Policy doctor has no findings.");

  const agents = ((state.policy && state.policy.agents) || []).map((agent) => {
    const elevatedAccess = Boolean(agent["raw_" + "s" + "ecret_access"]);
    return itemNode({
      title: agent.agent_id,
      detail: Object.keys(agent.services || {}).join(", ") || "No services",
      tone: elevatedAccess ? "warning" : "",
      meta: elevatedAccess ? "elevated" : "restricted",
    });
  });
  renderItems(qs("#agent-list"), agents, "No agents configured.");
}

function renderCommand() {
  renderAgentContext();
  renderPolicyExplain();
  renderRequestInbox();
  renderRecoveryDrill();
}

function renderAgentContext() {
  const summary = qs("#agent-context-summary");
  const servicesTarget = qs("#agent-context-services");
  if (!summary || !servicesTarget) return;
  const context = state.agentContext;
  if (!context) {
    summary.innerHTML = `
      <article class="summary-card"><span>Agent</span><strong>-</strong></article>
      <article class="summary-card"><span>Services</span><strong>-</strong></article>
      <article class="summary-card"><span>Boundary</span><strong>Redacted</strong></article>
    `;
    servicesTarget.innerHTML = "";
    return;
  }
  const services = Array.isArray(context.services) ? context.services : [];
  const leases = Array.isArray(context.leases) ? context.leases : [];
  const requests = Array.isArray(context.access_requests) ? context.access_requests : [];
  summary.innerHTML = `
    <article class="summary-card"><span>Agent</span><strong>${escapeHtml(context.agent_id)}</strong></article>
    <article class="summary-card"><span>Services</span><strong>${escapeHtml(services.length)}</strong></article>
    <article class="summary-card"><span>Leases</span><strong>${escapeHtml(leases.length)}</strong></article>
    <article class="summary-card"><span>Requests</span><strong>${escapeHtml(requests.length)}</strong></article>
  `;
  const items = services.map((service) => itemNode({
    title: service.service || "service",
    detail: `Actions: ${(service.actions || []).join(", ") || "-"}. TTL: ${service.max_ttl_seconds || "-"}. Lease required: ${service.require_lease_for_env ? "yes" : "no"}.`,
    tone: service.require_lease_for_env ? "warning" : "",
    meta: service.raw_secret_access ? "elevated" : "env",
  }));
  renderItems(servicesTarget, items, "No services are visible to this agent.");
}

function renderPolicyExplain() {
  const target = qs("#policy-explain-summary");
  if (!target) return;
  const explain = state.policyExplain;
  if (!explain) {
    target.innerHTML = `
      <article class="summary-card"><span>Decision</span><strong>-</strong></article>
      <article class="summary-card"><span>Lease</span><strong>-</strong></article>
      <article class="summary-card"><span>TTL</span><strong>-</strong></article>
    `;
    return;
  }
  target.innerHTML = `
    <article class="summary-card"><span>Decision</span><strong>${explain.allowed ? "Allowed" : "Denied"}</strong></article>
    <article class="summary-card"><span>Reason</span><strong>${escapeHtml(explain.reason || "-")}</strong></article>
    <article class="summary-card"><span>Lease</span><strong>${explain.requires_lease ? "Required" : "Optional"}</strong></article>
    <article class="summary-card"><span>Effective TTL</span><strong>${escapeHtml(explain.effective_ttl_seconds || "-")}</strong></article>
  `;
}

function renderRequestInbox() {
  const target = qs("#request-inbox");
  if (!target) return;
  const rows = (state.requests || []).map((request) => {
    const pending = request.status === "pending";
    return `
      <tr>
        <td><strong>${escapeHtml(request.agent_id)}</strong><p class="cell-note metadata-note">${escapeHtml(request.id)}</p></td>
        <td>${escapeHtml(request.service)}</td>
        <td>${escapeHtml(request.alias || "default")}</td>
        <td>${escapeHtml(request.action)}</td>
        <td><span class="status ${escapeHtml(request.status)}">${escapeHtml(request.status)}</span></td>
        <td>${request.purpose ? `<p class="cell-note metadata-note">${escapeHtml(request.purpose)}</p>` : "-"}</td>
        <td>${escapeHtml(shortDate(request.created_at))}</td>
        <td>
          <div class="request-actions">
            <button class="ghost-button compact" type="button" data-request-deny="${escapeHtml(request.id)}" ${pending ? "" : "disabled"}>Deny</button>
            <button class="primary-button compact" type="button" data-request-approve="${escapeHtml(request.id)}" ${pending ? "" : "disabled"}>Approve</button>
            <label><input type="checkbox" data-request-lease="${escapeHtml(request.id)}" ${pending ? "" : "disabled"} /> Lease</label>
          </div>
        </td>
      </tr>
    `;
  });
  renderTable(
    target,
    ["Agent", "Service", "Alias", "Action", "Status", "Purpose", "Created", "Decision"],
    rows,
    "No access requests yet.",
  );
}

function renderRecoveryDrill() {
  const target = qs("#recovery-drill-summary");
  if (!target) return;
  const drill = state.recoveryDrill;
  if (!drill) {
    target.innerHTML = `
      <article class="summary-card"><span>Status</span><strong>-</strong></article>
      <article class="summary-card"><span>Findings</span><strong>-</strong></article>
      <article class="summary-card"><span>Diff Entries</span><strong>-</strong></article>
    `;
    return;
  }
  target.innerHTML = `
    <article class="summary-card"><span>Status</span><strong>${drill.healthy ? "Healthy" : "Review"}</strong></article>
    <article class="summary-card"><span>Findings</span><strong>${escapeHtml((drill.findings || []).length)}</strong></article>
    <article class="summary-card"><span>Diff Entries</span><strong>${escapeHtml((drill.diff || {}).count || 0)}</strong></article>
  `;
}

function renderLeases() {
  const leases = sortBy(
    (state.leases || []).filter((lease) => {
      const statusOk = !state.filters.leaseStatus || lease.status === state.filters.leaseStatus;
      return statusOk && matchesText(lease, ["service", "alias", "agent_id", "status", "purpose", "reason"], state.filters.leases);
    }),
    state.filters.leaseSort || "expires_at",
    state.filters.leaseSort === "expires_at" ? "asc" : "asc",
  );
  const rows = leases.map((lease) => `
    <tr>
      <td><strong>${escapeHtml(lease.service)}</strong></td>
      <td>${escapeHtml(lease.alias)}</td>
      <td>${escapeHtml(lease.agent_id)}</td>
      <td><span class="status ${escapeHtml(lease.status)}">${escapeHtml(lease.status)}</span></td>
      <td>${escapeHtml(lease.purpose)}</td>
      <td>${escapeHtml(String(lease.ttl_seconds || "-"))}</td>
      <td>${formatExpiry(lease.expires_at)}</td>
      <td>${escapeHtml(lease.renew_count ?? 0)}</td>
      <td>${lease.reason ? `<p class="cell-note metadata-note">${escapeHtml(lease.reason)}</p>` : "-"}</td>
    </tr>
  `);
  renderTable(
    qs("#lease-table"),
    ["Service", "Alias", "Agent", "Status", "Purpose", "TTL", "Expiry", "Renews", "Reason"],
    rows,
    (state.leases || []).length ? "No leases match the current filters." : "No leases have been issued yet.",
  );
}

function renderAudit() {
  const entries = sortBy(
    state.audit.filter((entry) => matchesText(entry, ["timestamp", "agent_id", "action", "service", "decision", "reason"], state.filters.audit)),
    state.filters.auditSort || "timestamp",
    state.filters.auditSort === "timestamp" ? "desc" : "asc",
  );
  const rows = entries.map((entry) => `
    <tr>
      <td>${escapeHtml(shortDate(entry.timestamp))}</td>
      <td><strong>${escapeHtml(entry.agent_id)}</strong></td>
      <td>${escapeHtml(entry.action)}</td>
      <td>${escapeHtml(entry.service)}</td>
      <td><span class="status ${escapeHtml(entry.decision)}">${escapeHtml(entry.decision)}</span></td>
      <td>${escapeHtml(entry.reason)}</td>
    </tr>
  `);
  renderTable(
    qs("#audit-table"),
    ["Time", "Agent", "Action", "Service", "Decision", "Reason"],
    rows,
    state.audit.length ? "No audit entries match the current filters." : "No audit entries yet.",
  );
}

function renderRecoverySummary() {
  const target = qs("#recovery-summary");
  if (!target) return;
  const recovery = state.recovery || {};
  const verify = recovery.backup_verify;
  const restore = recovery.restore_dry_run;
  const diff = recovery.backup_diff;
  target.innerHTML = `
    <article class="summary-card"><span>Verify</span><strong>${verify ? (verify.decryptable ? "OK" : "Check") : "-"}</strong></article>
    <article class="summary-card"><span>Restore Dry-Run</span><strong>${restore ? (restore.decryptable ? "OK" : "Check") : "-"}</strong></article>
    <article class="summary-card"><span>Diff Entries</span><strong>${diff ? escapeHtml(diff.count || 0) : "-"}</strong></article>
  `;
}

async function runAction(action, payload = {}, button) {
  const output = state.view === "command" ? qs("#command-output") : qs("#action-output");
  setButtonBusy(button, true, "Running");
  setConnection("Action running", "busy");
  output.classList.remove("error");
  output.textContent = `Running ${action}...`;
  try {
    const result = await api(`/api/actions/${action}`, {
      method: "POST",
      body: JSON.stringify(payload),
    });
    if (action === "verify") {
      for (const item of result.results || []) {
        const alias = (item.metadata && item.metadata.alias) || payload.alias || "default";
        const service = (item.metadata && item.metadata.record_service) || payload.service || item.service;
        state.verificationResults[credentialKey(service, alias)] = item;
      }
    }
    if (action === "onboarding_preview") {
      state.onboardingPreview = result;
    }
    if (["backup_verify", "restore_dry_run", "backup_diff"].includes(action)) {
      state.recovery[action] = result;
    }
    if (action === "policy_explain") {
      state.policyExplain = result;
    }
    if (action === "request_access") {
      state.requests = [result.metadata.request, ...(state.requests || [])].filter(Boolean);
    }
    if (action === "request_approve" || action === "request_deny") {
      const updated = result.metadata && result.metadata.request;
      if (updated) {
        state.requests = (state.requests || []).map((request) => request.id === updated.id ? updated : request);
      }
    }
    if (action === "recovery_drill") {
      state.recoveryDrill = result;
    }
    output.textContent = JSON.stringify(result, null, 2);
    await loadAll();
  } catch (error) {
    output.classList.add("error");
    output.textContent = String(error.message || error);
    setConnection("Action failed", "error");
  } finally {
    setButtonBusy(button, false);
  }
}

async function loadAgentContext(button) {
  const output = qs("#command-output");
  const agentId = qs("#agent-context-agent").value.trim();
  if (!agentId) {
    output.classList.add("error");
    output.textContent = "Agent is required.";
    return;
  }
  setButtonBusy(button, true, "Loading");
  setConnection("Loading context", "busy");
  output.classList.remove("error");
  try {
    const result = await api(`/api/agent-context?agent_id=${encodeURIComponent(agentId)}`);
    state.agentContext = result;
    output.textContent = JSON.stringify(result, null, 2);
    renderCommand();
    setConnection("Local session", "ready");
  } catch (error) {
    output.classList.add("error");
    output.textContent = String(error.message || error);
    setConnection("Action failed", "error");
  } finally {
    setButtonBusy(button, false);
  }
}

async function refreshRequests(button) {
  const output = qs("#command-output");
  setButtonBusy(button, true, "Refreshing");
  setConnection("Refreshing requests", "busy");
  try {
    const result = await api("/api/requests");
    state.requests = result.requests || [];
    renderRequestInbox();
    output.classList.remove("error");
    output.textContent = JSON.stringify(result, null, 2);
    setConnection("Local session", "ready");
  } catch (error) {
    output.classList.add("error");
    output.textContent = String(error.message || error);
    setConnection("Action failed", "error");
  } finally {
    setButtonBusy(button, false);
  }
}

qsa(".nav-item").forEach((button) => {
  button.addEventListener("click", () => {
    state.view = button.dataset.view;
    qsa(".nav-item").forEach((item) => item.classList.toggle("active", item === button));
    qsa(".view").forEach((view) => view.classList.toggle("active", view.id === state.view));
    qs("#view-title").textContent = button.textContent;
    updateNavGlider();
  });
});

window.addEventListener("resize", updateNavGlider);
window.addEventListener("load", () => {
  setTimeout(updateNavGlider, 100);
});

document.body.addEventListener("change", async (event) => {
  const target = event.target.closest("#profile-select");
  if (!target) return;
  const profile = target.value;
  setConnection("Switching profile", "busy");
  try {
    await api("/api/profile/select", {
      method: "POST",
      body: JSON.stringify({ profile }),
    });
    state.verificationResults = {};
    await loadAll();
    setConnection("Local session", "ready");
  } catch (error) {
    qs("#action-output").classList.add("error");
    qs("#action-output").textContent = String(error.message || error);
    setConnection("Profile switch failed", "error");
    await loadAll();
  }
});

document.body.addEventListener("input", (event) => {
  const target = event.target.closest("[data-filter]");
  if (!target) return;
  state.filters[target.dataset.filter] = target.value;
  renderCredentials();
  renderLeases();
  renderAudit();
});

document.body.addEventListener("change", (event) => {
  const target = event.target.closest("[data-filter]");
  if (!target) return;
  state.filters[target.dataset.filter] = target.value;
  renderCredentials();
  renderLeases();
  renderAudit();
});

document.body.addEventListener("click", (event) => {
  const target = event.target.closest("button");
  if (!target || target.disabled) return;
  if (target.id === "refresh") {
    loadAll(target).catch(() => {});
  } else if (target.dataset.action === "health") {
    runAction("health", {}, target);
  } else if (target.dataset.action === "policy_doctor") {
    runAction("policy_doctor", {}, target);
  } else if (target.dataset.action === "verify-all") {
    runAction("verify", { all: true }, target);
  } else if (target.dataset.verifyService) {
    runAction("verify", { service: target.dataset.verifyService, alias: target.dataset.verifyAlias }, target);
  } else if (target.dataset.action === "maintenance-dry") {
    runAction("maintenance", { dry_run: true }, target);
  } else if (target.dataset.action === "oauth-refresh-dry") {
    runAction("oauth_refresh", { dry_run: true, service: qs("#oauth-service").value, alias: qs("#oauth-alias").value || "default" }, target);
  } else if (target.dataset.action === "backup-verify") {
    runAction("backup_verify", { input: qs("#backup-path").value }, target);
  } else if (target.dataset.action === "restore-dry-run") {
    runAction("restore_dry_run", { input: qs("#backup-path").value }, target);
  } else if (target.dataset.action === "backup-diff") {
    runAction("backup_diff", { input: qs("#backup-path").value }, target);
  } else if (target.dataset.action === "onboarding-preview") {
    runAction("onboarding_preview", {
      from_env: qs("#onboarding-env-path").value,
      agent: qs("#onboarding-agent").value || "hermes",
      map: qs("#onboarding-map").value,
    }, target);
  } else if (target.dataset.action === "agent-context") {
    loadAgentContext(target);
  } else if (target.dataset.action === "policy-explain") {
    runAction("policy_explain", {
      agent_id: qs("#policy-explain-agent").value,
      service: qs("#policy-explain-service").value,
      action: qs("#policy-explain-action").value,
      ttl_seconds: qs("#policy-explain-ttl").value,
    }, target);
  } else if (target.dataset.action === "request-access") {
    runAction("request_access", {
      agent_id: qs("#request-agent").value,
      service: qs("#request-service").value,
      alias: qs("#request-alias").value || "default",
      action: "get_env",
      purpose: qs("#request-purpose").value,
      ttl_seconds: qs("#request-ttl").value,
    }, target);
  } else if (target.dataset.action === "requests-refresh") {
    refreshRequests(target);
  } else if (target.dataset.requestApprove) {
    const lease = qsa("[data-request-lease]").find((item) => item.dataset.requestLease === target.dataset.requestApprove);
    runAction("request_approve", {
      request_id: target.dataset.requestApprove,
      reason: "Approved from dashboard command center.",
      issue_lease: Boolean(lease && lease.checked),
    }, target);
  } else if (target.dataset.requestDeny) {
    runAction("request_deny", {
      request_id: target.dataset.requestDeny,
      reason: "Denied from dashboard command center.",
    }, target);
  } else if (target.dataset.action === "recovery-drill") {
    runAction("recovery_drill", { backup_path: qs("#recovery-drill-path").value }, target);
  }
});

renderLoading();
loadAll(qs("#refresh")).catch(() => {});
