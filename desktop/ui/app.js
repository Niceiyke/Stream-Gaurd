// StreamGuard desktop status shell (spec 22 / engineering step 12).
//
// Thin client: polls the single Tauri command `status_snapshot` every 2000 ms
// and renders the JSON `StatusSnapshot` exactly as the engine serializes it.
//
// Field contract (must stay in lockstep with `streamguard_service::status`):
//   StatusSnapshot: { session_prefix:u32, protecting:bool, mode:str,
//                     paths:[PathStatus], aggregate_kbps:u32,
//                     active_path:u8|null, counters:StatusCounters,
//                     warnings:[string] }
//   PathStatus:     { path_id:u8, name:string|null, reachable:bool, rtt_ms,
//                     srtt_ms, jitter_ms, loss:f32, available_kbps:u32,
//                     stability_secs:u64 }
//   Mode:           "SinglePath" | "ActiveStandby" | "Bonding"
//   StatusCounters: frames_to_host, datagrams_to_gateway, duplicates_dropped,
//                   keepalives, path_selects, path_failures, soft_failures,
//                   probes_sent, duplicates_sent, weight_sets,
//                   status_auth_failures (all u64) + uplink{path:count}

"use strict";

const POLL_MS = 2000;

const el = (id) => document.getElementById(id);

// DOM element handles.
const dom = {
  connState: el("conn-state"),
  protecting: el("protecting"),
  mode: el("mode"),
  aggregate: el("aggregate-kbps"),
  prefix: el("session-prefix"),
  activePath: el("active-path"),
  pathsBody: el("paths-body"),
  warningsList: el("warnings-list"),
  errorBar: el("error-bar"),
  counters: {
    framesToHost: el("c-frames-to-host"),
    datagrams: el("c-datagrams-to-gateway"),
    dupsDropped: el("c-duplicates-dropped"),
    keepalives: el("c-keepalives"),
    pathSelects: el("c-path-selects"),
    pathFailures: el("c-path-failures"),
    softFailures: el("c-soft-failures"),
    probesSent: el("c-probes-sent"),
    dupsSent: el("c-duplicates-sent"),
    weightSets: el("c-weight-sets"),
    authFailures: el("c-auth-failures"),
  },
};

/** Call the Tauri IPC. `window.__TAURI__` is injected via withGlobalTauri.
 *  Returns the parsed snapshot or throws. */
async function fetchSnapshot() {
  return await window.__TAURI__.core.invoke("status_snapshot");
}

/** Decorate a stray numeric field as a display string. */
function fmtNum(v, suffix = "") {
  if (v === undefined || v === null) return "—";
  return `${Number(v).toLocaleString()}${suffix}`;
}

function setConnState(state, text) {
  dom.connState.dataset.state = state;
  dom.connState.textContent = text;
}

function render(snapshot) {
  // Status card.
  const protecting = Boolean(snapshot.protecting);
  dom.protecting.textContent = protecting ? "ON" : "OFF";
  dom.protecting.className = "badge " + (protecting ? "badge-on" : "badge-off");
  dom.mode.textContent = snapshot.mode || "—";
  dom.aggregate.textContent = fmtNum(snapshot.aggregate_kbps, " kbps");
  dom.prefix.textContent =
    snapshot.session_prefix === undefined || snapshot.session_prefix === null
      ? "—"
      : "0x" + Number(snapshot.session_prefix).toString(16).padStart(8, "0");
  dom.activePath.textContent =
    snapshot.active_path === null || snapshot.active_path === undefined
      ? "—"
      : `path ${snapshot.active_path}`;

  // Counters subset.
  const c = snapshot.counters || {};
  dom.counters.framesToHost.textContent = fmtNum(c.frames_to_host);
  dom.counters.datagrams.textContent = fmtNum(c.datagrams_to_gateway);
  dom.counters.dupsDropped.textContent = fmtNum(c.duplicates_dropped);
  dom.counters.keepalives.textContent = fmtNum(c.keepalives);
  dom.counters.pathSelects.textContent = fmtNum(c.path_selects);
  dom.counters.pathFailures.textContent = fmtNum(c.path_failures);
  dom.counters.softFailures.textContent = fmtNum(c.soft_failures);
  dom.counters.probesSent.textContent = fmtNum(c.probes_sent);
  dom.counters.dupsSent.textContent = fmtNum(c.duplicates_sent);
  dom.counters.weightSets.textContent = fmtNum(c.weight_sets);
  dom.counters.authFailures.textContent = fmtNum(c.status_auth_failures);

  // Path table.
  const paths = Array.isArray(snapshot.paths) ? snapshot.paths : [];
  dom.pathsBody.innerHTML = "";
  if (paths.length === 0) {
    const tr = document.createElement("tr");
    tr.innerHTML = '<td colspan="9" class="empty">no paths reported</td>';
    dom.pathsBody.appendChild(tr);
  } else {
    for (const p of paths) {
      const tr = document.createElement("tr");
      const name = p.name || "—";
      const reachable = p.reachable ? "reachable" : "down";
      const rtt = p.rtt_ms === undefined ? "—" : p.rtt_ms;
      const srtt = p.srtt_ms === undefined ? "—" : p.srtt_ms;
      const jitter = p.jitter_ms === undefined ? "—" : p.jitter_ms;
      const loss = p.loss === undefined ? "—" : (p.loss * 100).toFixed(1);
      const kbps = p.available_kbps ? p.available_kbps : "—";
      const stab = p.stability_secs === undefined ? "—" : p.stability_secs;
      tr.innerHTML =
        `<td><span class="badge badge-path">path ${p.path_id}</span></td>` +
        `<td>${name}</td>` +
        `<td><span class="badge ${reachable === "reachable" ? "badge-on" : "badge-off"}">${reachable}</span></td>` +
        `<td>${rtt}</td>` +
        `<td>${srtt}</td>` +
        `<td>${jitter}</td>` +
        `<td>${loss}</td>` +
        `<td>${kbps}</td>` +
        `<td>${stab}</td>`;
      dom.pathsBody.appendChild(tr);
    }
  }

  // Warnings.
  const warnings = Array.isArray(snapshot.warnings) ? snapshot.warnings : [];
  dom.warningsList.innerHTML = "";
  if (warnings.length === 0) {
    const li = document.createElement("li");
    li.className = "empty";
    li.textContent = "none";
    dom.warningsList.appendChild(li);
  } else {
    for (const w of warnings) {
      const li = document.createElement("li");
      li.textContent = w;
      dom.warningsList.appendChild(li);
    }
  }
}

function showError(message) {
  dom.errorBar.hidden = false;
  dom.errorBar.textContent = `IPC unreachable: ${message}`;
}

async function tick() {
  try {
    const snapshot = await fetchSnapshot();
    render(snapshot);
    setConnState("online", "connected");
    dom.errorBar.hidden = true;
  } catch (err) {
    showError(err && err.message ? err.message : String(err));
    setConnState("offline", "service not connected");
  } finally {
    setTimeout(tick, POLL_MS);
  }
}

// Kick off the polling loop once the Tauri IPC bridge is installed.
tick();
