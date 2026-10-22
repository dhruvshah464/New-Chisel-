const $ = (id) => document.getElementById(id);
const tokenKey = "aisec_token";
const projectKey = "aisec_project";

function token() {
  return localStorage.getItem(tokenKey) || "";
}

function parseJson(value, fallback) {
  if (value && typeof value === "object") return value;
  try {
    return JSON.parse(value || "null") || fallback;
  } catch {
    return fallback;
  }
}

function text(node, value) {
  node.textContent = value == null ? "" : String(value);
}

function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
}

function add(parent, tag, attrs, content) {
  const node = document.createElement(tag);
  Object.entries(attrs || {}).forEach(([key, val]) => {
    if (key === "class") node.className = val;
    else if (key.startsWith("data-") || key === "aria-current" || key === "type") node.setAttribute(key, val);
    else node[key] = val;
  });
  if (content != null) node.textContent = content;
  parent.appendChild(node);
  return node;
}

async function api(path, opts = {}) {
  const headers = Object.assign({ Accept: "application/json" }, opts.headers || {});
  if (token()) headers.Authorization = "Bearer " + token();
  const res = await fetch(path, Object.assign({}, opts, { headers }));
  const raw = await res.text();
  let body = {};
  try {
    body = raw ? JSON.parse(raw) : {};
  } catch {
    body = { error: raw };
  }
  if (!res.ok) throw new Error(body.error || res.statusText);
  return body;
}

function show(msg, ok) {
  const el = $("status");
  if (!el) return;
  el.className = "status" + (ok ? " ok" : "");
  el.textContent = msg || "";
}

function showGate(msg) {
  const el = $("gate-status");
  if (el) el.textContent = msg || "";
}

function locked() {
  $("gate").classList.remove("hidden");
  $("app").classList.add("hidden");
}

function unlocked() {
  $("gate").classList.add("hidden");
  $("app").classList.remove("hidden");
}

function setView(name) {
  document.querySelectorAll(".desk").forEach((el) => {
    el.classList.toggle("is-on", el.dataset.view === name);
  });
  document.querySelectorAll(".nav button").forEach((btn) => {
    if (btn.dataset.view === name) btn.setAttribute("aria-current", "page");
    else btn.removeAttribute("aria-current");
  });
  if (name === "ledger") loadAudit().catch((e) => show(e.message));
  if (name === "runs") loadRuns().catch((e) => show(e.message));
}

async function localUnlock() {
  const body = await api("/v1/local-unlock", { method: "POST" });
  if (body.token) localStorage.setItem(tokenKey, body.token);
  await api("/v1/session", { method: "POST" });
  unlocked();
  await refresh();
}

async function bootstrap() {
  try {
    const body = await api("/v1/bootstrap", { method: "POST" });
    localStorage.setItem(tokenKey, body.token);
    localStorage.setItem(projectKey, body.project_id);
    $("token").value = body.token;
    await api("/v1/session", { method: "POST" });
    showGate("Owner token is in this browser. Copy it now; the server will not show it again.");
    unlocked();
    await refresh();
  } catch (err) {
    if (err.message === "already bootstrapped") {
      showGate("This machine is already open. Use Open on this computer.");
      return localUnlock().catch((unlockErr) => showGate(unlockErr.message));
    }
    showGate(err.message);
  }
}

async function saveToken() {
  const value = $("token").value.trim();
  if (!value) {
    showGate("Paste an aisec_ token.");
    return;
  }
  localStorage.setItem(tokenKey, value);
  await api("/v1/session", { method: "POST" });
  unlocked();
  await refresh();
}

function signOut() {
  localStorage.removeItem(tokenKey);
  $("token").value = "";
  locked();
}

async function refresh() {
  show("");
  const me = await api("/v1/me");
  text($("who"), (me.org_name || "org") + " · " + (me.token_prefix || "") + "…");
  const select = $("project");
  clear(select);
  (me.projects || []).forEach((p) => {
    add(select, "option", { value: p.id }, p.name);
  });
  const saved = localStorage.getItem(projectKey);
  if (saved) select.value = saved;
  if (select.value) localStorage.setItem(projectKey, select.value);
  await loadInbox();
  await loadRuns();
}

function projectId() {
  return $("project").value;
}

function isOpenStatus(status) {
  return status === "open" || status === "in_progress" || status === "retesting";
}

async function loadInbox() {
  const project = projectId();
  const list = $("findings");
  const empty = $("findings-empty");
  clear(list);
  if (!project) return;
  const filter = document.querySelector("#finding-filter button.is-on");
  const status = (filter && filter.dataset.status) || "";
  const data = await api("/v1/findings?project=" + encodeURIComponent(project));
  let rows = data.findings || [];
  if (status === "open") rows = rows.filter((f) => isOpenStatus(f.status));
  if (status === "closed") rows = rows.filter((f) => !isOpenStatus(f.status));
  empty.classList.toggle("hidden", rows.length > 0);
  rows.forEach((f) => {
    const li = add(list, "li");
    const btn = add(li, "button", { class: "row", type: "button" });
    btn.onclick = () => openFinding(f.id);
    add(btn, "span", { class: "title" }, f.title || f.scenario_id);
    const chip = add(btn, "span", { class: "chip " + (f.status || "") }, f.status || "");
    const due = f.due_at && isOpenStatus(f.status) ? " · due " + f.due_at.slice(0, 16).replace("T", " ") : "";
    add(btn, "span", { class: "meta" }, (f.severity || "—") + " · " + (f.scenario_id || "") + due);
    void chip;
  });
}

function fillMeta(dl, pairs) {
  clear(dl);
  pairs.forEach(([key, value]) => {
    add(dl, "dt", {}, key);
    add(dl, "dd", {}, value == null || value === "" ? "—" : value);
  });
}

async function openFinding(id) {
  const data = await api("/v1/findings/" + id);
  const f = data.finding;
  $("finding-id").value = id;
  text($("finding-title"), f.title || f.scenario_id);
  const owasp = parseJson(f.owasp, []);
    fillMeta($("finding-meta"), [
    ["Status", f.status],
    ["Severity", f.severity],
    ["OWASP", Array.isArray(owasp) ? owasp.join(" ") : String(owasp || "—")],
    ["Due", f.due_at || "—"],
    ["Assignee", f.assignee || "—"],
    ["Opened from", f.created_from_run_id],
    ["Latest run", f.latest_run_id],
  ]);
  $("new-status").value = f.status;
  $("assignee").value = f.assignee || "";
  text($("finding-body"), (f.body || "") + (data.retest ? "\n\nRetest (on your machine):\n" + data.retest : ""));
  const events = $("finding-events");
  clear(events);
  (data.events || []).forEach((ev) => {
    const li = add(events, "li");
    add(li, "div", {}, ev.kind + (ev.actor ? " · " + ev.actor : ""));
    add(li, "div", { class: "when" }, ev.created_at || "");
  });
  if (f.latest_run_id) showEvidence("report", f.latest_run_id, $("report"), $("attest-view"));
}

async function mutateFinding(path, fields) {
  const id = $("finding-id").value;
  if (!id) {
    show("Select a finding first.");
    return;
  }
  const body = new FormData();
  Object.entries(fields).forEach(([k, v]) => body.set(k, v));
  await api("/v1/findings/" + id + path, { method: "POST", body });
  await loadInbox();
  await openFinding(id);
  show("Saved.", true);
}

async function markRetest() {
  const id = $("finding-id").value;
  if (!id) return;
  const data = await api("/v1/findings/" + id + "/retest", { method: "POST" });
  text($("finding-body"), data.command || "");
  await loadInbox();
  show("Marked retesting. Run the command on the machine that holds the agent.", true);
}

async function exportFinding() {
  const id = $("finding-id").value;
  if (!id) return;
  const body = new FormData();
  body.set("destination", "github");
  body.set("repo", $("gh-repo").value);
  const data = await api("/v1/findings/" + id + "/export", { method: "POST", body });
  show(data.dry_run ? "Dry run (no GITHUB_TOKEN). Title: " + data.title : "Opened " + data.html_url, true);
}

async function addComment() {
  const textValue = $("comment").value.trim();
  if (!textValue) return;
  await mutateFinding("/comment", { text: textValue });
  $("comment").value = "";
}

function evidenceUrl(kind, runId) {
  if (kind === "certificate") return "/v1/runs/" + encodeURIComponent(runId) + "/certificate";
  if (kind === "attestation") return "/v1/runs/" + encodeURIComponent(runId) + "/attestation";
  return "/v1/runs/" + encodeURIComponent(runId) + "/report";
}

async function showEvidence(kind, runId, frame, attestEl) {
  if (!runId) return;
  if (kind === "attestation") {
    frame.classList.add("hidden");
    attestEl.classList.remove("hidden");
    const data = await api("/v1/runs/" + encodeURIComponent(runId) + "/attestation");
    text(attestEl, JSON.stringify(data, null, 2));
    return;
  }
  attestEl.classList.add("hidden");
  frame.classList.remove("hidden");
  frame.src = evidenceUrl(kind, runId);
}

function bindTabs(rootId, frame, attestEl, getRunId) {
  document.querySelectorAll("#" + rootId + " button").forEach((btn) => {
    btn.onclick = () => {
      document.querySelectorAll("#" + rootId + " button").forEach((b) => b.setAttribute("aria-current", b === btn ? "true" : "false"));
      const runId = getRunId();
      if (runId) showEvidence(btn.dataset.kind, runId, frame, attestEl).catch((e) => show(e.message));
    };
  });
}

let selectedRun = "";

async function loadBaseline() {
  const project = projectId();
  const el = $("baseline");
  if (!project || !el) return;
  const data = await api("/v1/projects/" + encodeURIComponent(project) + "/baseline");
  clear(el);
  if (data.status !== "ok") {
    add(el, "p", { class: "empty" }, "Need two uploaded packs in this project to compare.");
    return;
  }
  const rows = [
    ["Older → newer", (data.older_run_id || "") + " → " + (data.newer_run_id || "")],
    ["Tool-level fixes", (data.tool_fixes_that_held_on_both || []).join(", ") || "none"],
    ["Model-only splits", (data.model_only_splits || []).join(", ") || "none"],
    ["Regressions", (data.regressions || []).join(", ") || "none"],
  ];
  rows.forEach(([label, value]) => {
    const item = add(el, "div", { class: "item" });
    add(item, "div", { class: "kicker" }, label);
    add(item, "div", {}, value);
  });
}

async function loadRuns() {
  const project = projectId();
  const tbody = $("runs");
  const empty = $("runs-empty");
  if (!tbody) return;
  clear(tbody);
  if (!project) return;
  await loadBaseline().catch((e) => {
    const el = $("baseline");
    if (el) {
      clear(el);
      add(el, "p", { class: "empty" }, e.message);
    }
  });
  const data = await api("/v1/runs?project=" + encodeURIComponent(project));
  const rows = data.runs || [];
  if (empty) empty.classList.toggle("hidden", rows.length > 0);
  rows.forEach((r) => {
    const summary = parseJson(r.summary, {});
    const tr = add(tbody, "tr");
    tr.onclick = () => {
      selectedRun = r.run_id;
      tbody.querySelectorAll("tr").forEach((row) => row.classList.toggle("is-on", row === tr));
      showEvidence("report", r.run_id, $("run-frame"), $("run-attest")).catch((e) => show(e.message));
    };
    add(tr, "td", { class: "mono" }, r.run_id);
    add(tr, "td", { class: "mono" }, (r.manifest_sha256 || "").slice(0, 12) + "…");
    const exit = summary.exit_code;
    add(tr, "td", {}, exit == null ? "—" : String(exit));
    const actions = add(tr, "td");
    const open = add(actions, "button", { type: "button" }, "Open");
    open.onclick = (ev) => {
      ev.stopPropagation();
      selectedRun = r.run_id;
      setView("inbox");
      showEvidence("report", r.run_id, $("report"), $("attest-view")).catch((e) => show(e.message));
    };
  });
}

async function uploadPack() {
  const file = $("pack-file").files && $("pack-file").files[0];
  const project = projectId();
  if (!file) {
    show("Choose a signed .tar.gz.");
    return;
  }
  const body = new FormData();
  body.set("project", project);
  body.set("pack", file, file.name);
  const result = await api("/v1/runs", { method: "POST", body });
  show(
    result.duplicate
      ? "Already held: " + result.run_id
      : "Ingested " + result.run_id + " · opened " + (result.findings_opened || 0) + " ticket(s).",
    true
  );
  await loadInbox();
  await loadRuns();
}

async function loadAudit() {
  const tbody = $("audit");
  if (!tbody) return;
  clear(tbody);
  const data = await api("/v1/audit");
  (data.events || []).forEach((ev) => {
    const tr = add(tbody, "tr");
    add(tr, "td", { class: "mono" }, (ev.created_at || "").replace("T", " ").slice(0, 19));
    add(tr, "td", { class: "mono" }, ev.actor || "");
    add(tr, "td", {}, ev.action || "");
    add(tr, "td", { class: "mono" }, typeof ev.detail === "string" ? ev.detail : JSON.stringify(ev.detail || {}));
  });
}

$("bootstrap").onclick = () => bootstrap();
$("local-unlock").onclick = () => localUnlock().catch((e) => showGate(e.message));
$("save-token").onclick = () => saveToken().catch((e) => showGate(e.message));
$("sign-out").onclick = signOut;
$("project").onchange = () => {
  localStorage.setItem(projectKey, $("project").value);
  loadInbox().catch((e) => show(e.message));
  loadRuns().catch((e) => show(e.message));
};
document.querySelectorAll(".nav button").forEach((btn) => {
  btn.onclick = () => setView(btn.dataset.view);
});
document.querySelectorAll("#finding-filter button").forEach((btn) => {
  btn.onclick = () => {
    document.querySelectorAll("#finding-filter button").forEach((b) => b.classList.toggle("is-on", b === btn));
    loadInbox().catch((e) => show(e.message));
  };
});
$("set-status").onclick = () =>
  mutateFinding("/status", { status: $("new-status").value, reason: $("reason").value }).catch((e) => show(e.message));
$("set-assignee").onclick = () => mutateFinding("/assign", { assignee: $("assignee").value }).catch((e) => show(e.message));
$("retest").onclick = () => markRetest().catch((e) => show(e.message));
$("export").onclick = () => exportFinding().catch((e) => show(e.message));
$("add-comment").onclick = () => addComment().catch((e) => show(e.message));
$("upload-pack").onclick = () => uploadPack().catch((e) => show(e.message));
bindTabs("run-tabs", $("run-frame"), $("run-attest"), () => selectedRun);
document.querySelectorAll("#evidence-tabs button").forEach((btn) => {
  btn.onclick = async () => {
    document.querySelectorAll("#evidence-tabs button").forEach((b) => b.setAttribute("aria-current", b === btn ? "true" : "false"));
    const id = $("finding-id").value;
    if (!id) return;
    const data = await api("/v1/findings/" + id);
    const runId = data.finding && data.finding.latest_run_id;
    if (runId) await showEvidence(btn.dataset.kind, runId, $("report"), $("attest-view"));
  };
});

$("token").value = token();
(async () => {
  if (token()) {
    unlocked();
    try {
      await refresh();
      return;
    } catch (err) {
      locked();
      showGate(err.message);
    }
  }
  try {
    await localUnlock();
  } catch {
    locked();
  }
})();
