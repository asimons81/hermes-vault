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
  verificationResults: {},
  policy: null,
  audit: [],
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
  return { home, dbPath, policyPath, passphraseSource, homeSource, isTempRuntime };
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
    const [overview, credentials, policy, audit] = await Promise.all([
      api("/api/overview"),
      api("/api/credentials"),
      api("/api/policy"),
      api("/api/audit?limit=60"),
    ]);
    state.overview = overview;
    state.credentials = credentials.credentials || [];
    state.credentialsRuntime = credentials.runtime || null;
    state.policy = policy;
    state.audit = audit.entries || [];
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
  renderOverview();
  renderCredentials();
  renderPolicy();
  renderAudit();
}

function renderOverview() {
  const overview = state.overview || {};
  const health = overview.health || {};
  const doctor = overview.policy_doctor || {};
  qs("#metric-credentials").textContent = overview.credential_count || 0;
  qs("#metric-services").textContent = (overview.services || []).length;
  qs("#metric-health").textContent = (health.findings || []).length;
  qs("#metric-policy").textContent = doctor.finding_count || 0;

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

function renderCredentials() {
  const rows = state.credentials.map((record) => `
    <tr>
      <td><strong>${escapeHtml(record.service)}</strong></td>
      <td>${escapeHtml(record.alias)}</td>
      <td>${escapeHtml(record.credential_type)}</td>
      <td><span class="status ${escapeHtml(record.status)}">${escapeHtml(record.status)}</span></td>
      <td>
        <span class="status ${escapeHtml(verificationTone(state.verificationResults[credentialKey(record.service, record.alias)]))}">${escapeHtml(verificationLabel(state.verificationResults[credentialKey(record.service, record.alias)]))}</span>
        ${verificationDetail(state.verificationResults[credentialKey(record.service, record.alias)]) ? `<p class="cell-note">${escapeHtml(verificationDetail(state.verificationResults[credentialKey(record.service, record.alias)]))}</p>` : ""}
      </td>
      <td>${escapeHtml(shortDate(record.last_verified_at))}</td>
      <td>${escapeHtml(shortDate(record.expiry))}</td>
      <td><button class="ghost-button compact" type="button" data-secret-action="true" data-verify-service="${escapeHtml(record.service)}" data-verify-alias="${escapeHtml(record.alias)}" ${keyValid() ? "" : "disabled"}>Verify</button></td>
    </tr>
  `);
  if (rows.length) {
    renderTable(
      qs("#credential-table"),
      ["Service", "Alias", "Type", "Status", "Verification", "Last Verified", "Expiry", "Action"],
      rows,
      "No credentials in the vault.",
    );
    return;
  }

  const diagnostic = runtimeDiagnostic();
  qs("#credential-table").innerHTML = `
    <div class="empty-diagnostic">
      <strong>No credentials found in this runtime.</strong>
      <p>${diagnostic.isTempRuntime ? "This looks like a temporary/demo runtime. " : ""}Hermes Vault is reading the runtime below. If you expected credentials, relaunch without a demo <code>HERMES_VAULT_HOME</code> or verify that the passphrase matches this vault.</p>
      <dl>
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

function renderAudit() {
  const rows = state.audit.map((entry) => `
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
    "No audit entries yet.",
  );
}

async function runAction(action, payload = {}, button) {
  const output = qs("#action-output");
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

qsa(".nav-item").forEach((button) => {
  button.addEventListener("click", () => {
    state.view = button.dataset.view;
    qsa(".nav-item").forEach((item) => item.classList.toggle("active", item === button));
    qsa(".view").forEach((view) => view.classList.toggle("active", view.id === state.view));
    qs("#view-title").textContent = button.textContent;
  });
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
  }
});

renderLoading();
loadAll(qs("#refresh")).catch(() => {});
