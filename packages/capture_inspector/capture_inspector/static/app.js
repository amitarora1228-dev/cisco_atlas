"use strict";

const $ = (id) => document.getElementById(id);
let lastReport = "";
let lastData = null;
let certsOnly = false;   // "Certs" sidebar view: only flows with cert/decryption info
let flowPage = 0;        // current page in the flows table (0-based)
const PAGE_SIZE = 100;   // max rows rendered per page (perf)

// --- engine status ---
fetch("/api/health")
  .then((r) => r.json())
  .then((d) => {
    const el = $("tshark-status");
    if (d.tshark && d.tshark !== "NOT FOUND") {
      el.textContent = "tshark ready";
      el.className = "pill pill-ok";
    } else {
      el.textContent = "tshark NOT found — install Wireshark";
      el.className = "pill pill-bad";
    }
  })
  .catch(() => {
    const el = $("tshark-status");
    el.textContent = "engine unreachable";
    el.className = "pill pill-bad";
  });

// --- file drop wiring ---
function wireDrop(dropId, inputId, nameId) {
  const drop = $(dropId);
  const input = $(inputId);
  const name = $(nameId);

  input.addEventListener("change", () => setFile(input.files[0]));

  ["dragenter", "dragover"].forEach((ev) =>
    drop.addEventListener(ev, (e) => {
      e.preventDefault();
      drop.classList.add("drag");
    })
  );
  ["dragleave", "drop"].forEach((ev) =>
    drop.addEventListener(ev, (e) => {
      e.preventDefault();
      drop.classList.remove("drag");
    })
  );
  drop.addEventListener("drop", (e) => {
    const f = e.dataTransfer.files[0];
    if (f) {
      input.files = e.dataTransfer.files;
      setFile(f);
    }
  });

  function setFile(f) {
    if (!f) return;
    name.textContent = f.name + " (" + (f.size / 1024 / 1024).toFixed(2) + " MB)";
    drop.classList.add("has-file");
  }
}
wireDrop("drop-pcap", "pcap", "pcap-name");
wireDrop("drop-har", "har", "har-name");
wireDrop("drop-keylog", "keylog", "keylog-name");

// Secure Access tunnel check only makes sense when SA mode is on.
(function wireSaMode() {
  const master = $("sa-mode");
  const tunnel = $("sa-tunnel");
  if (!master || !tunnel) return;
  const sync = () => {
    tunnel.disabled = !master.checked;
    if (!master.checked) tunnel.checked = false;
  };
  master.addEventListener("change", sync);
  sync();
})();

// --- analyze ---
$("run").addEventListener("click", async () => {
  const pcap = $("pcap").files[0];
  const har = $("har").files[0];
  if (!pcap && !har) {
    setStatus("Provide at least a PCAP or HAR file.", true);
    return;
  }

  const fd = new FormData();
  if (pcap) fd.append("pcap", pcap);
  if (har) fd.append("har", har);
  const keylog = $("keylog").files[0];
  if (keylog) fd.append("keylog", keylog);
  ["domain", "src_ip", "dst_ip", "policy", "expected", "actual", "timestamp"].forEach(
    (k) => fd.append(k, $(k).value || "")
  );
  fd.append("resolve_certs", $("resolve-certs").checked ? "1" : "");
  fd.append("secure_access", $("sa-mode").checked ? "1" : "");
  fd.append("sa_tunnel", ($("sa-mode").checked && $("sa-tunnel").checked) ? "1" : "");

  const resolving = $("resolve-certs").checked;
  setStatus(resolving
    ? "Analyzing… (parsing capture, dissecting TLS, resolving certificate names online)"
    : "Analyzing… (parsing capture, dissecting TLS, comparing certificates)");
  $("run").disabled = true;
  startProgress(resolving);

  try {
    const res = await fetch("/api/analyze", { method: "POST", body: fd });
    const data = await res.json();
    if (!res.ok) {
      setStatus(data.error || "Analysis failed.", true);
      stopProgress(false);
      return;
    }
    render(data);
    setStatus("Done.");
    stopProgress(true);
  } catch (err) {
    setStatus("Request failed: " + err.message, true);
    stopProgress(false);
  } finally {
    $("run").disabled = false;
  }
});

// --- progress bar (simulated; the analyze call is a single request) ---
let _progTimer = null;
function startProgress(resolving) {
  const wrap = $("progress");
  const bar = $("progress-bar");
  const label = $("progress-label");
  if (!wrap || !bar) return;
  if (_progTimer) clearInterval(_progTimer);
  wrap.classList.remove("hidden");
  wrap.classList.remove("progress-done", "progress-error");
  const stages = [
    [12, "Reading capture file…"],
    [30, "Parsing packets & flows…"],
    [55, "Dissecting TLS handshakes…"],
    [75, "Comparing certificates…"],
    [88, resolving ? "Resolving certificate names online…" : "Classifying findings…"],
  ];
  let pct = 4;
  let stageIdx = 0;
  bar.style.width = pct + "%";
  label.textContent = "Starting…";
  _progTimer = setInterval(() => {
    // ease toward the next stage target, then hold near 92% until the response lands
    const target = stageIdx < stages.length ? stages[stageIdx][0] : 92;
    pct += Math.max(0.4, (target - pct) * 0.18);
    if (stageIdx < stages.length && pct >= target - 0.5) {
      label.textContent = stages[stageIdx][1];
      stageIdx++;
    }
    if (pct > 92) pct = 92;
    bar.style.width = pct.toFixed(1) + "%";
  }, 180);
}
function stopProgress(success) {
  const wrap = $("progress");
  const bar = $("progress-bar");
  const label = $("progress-label");
  if (!wrap || !bar) return;
  if (_progTimer) {
    clearInterval(_progTimer);
    _progTimer = null;
  }
  if (success) {
    wrap.classList.add("progress-done");
    bar.style.width = "100%";
    label.textContent = "Complete";
  } else {
    wrap.classList.add("progress-error");
    label.textContent = "Failed";
  }
  setTimeout(() => {
    wrap.classList.add("hidden");
    bar.style.width = "0%";
  }, success ? 700 : 1500);
}

function setStatus(msg, isErr) {
  const el = $("status");
  el.textContent = msg;
  el.style.color = isErr ? "var(--red)" : "var(--muted)";
}

function esc(s) {
  return (s == null ? "" : String(s)).replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));
}

// Human-readable byte size.
function fmtBytes(n) {
  n = Number(n) || 0;
  if (n < 1024) return n + " B";
  if (n < 1048576) return (n / 1024).toFixed(1) + " KB";
  if (n < 1073741824) return (n / 1048576).toFixed(1) + " MB";
  return (n / 1073741824).toFixed(2) + " GB";
}

// Response-time colour bucket: 0–60 ms green, 61–120 ms orange, >120 ms red.
function rtClass(ms) {
  if (ms == null) return "";
  if (ms <= 60) return "rt-green";
  if (ms <= 120) return "rt-orange";
  return "rt-red";
}

// Coloured response-time pill (ms). Returns "" when no timing is available.
function rtPill(ms, label) {
  if (ms == null) return "";
  const txt = (ms >= 100 ? Math.round(ms) : ms.toFixed(1)) + " ms";
  const tip = "Response time " + txt + " — green \u2264 60 ms, orange 61\u2013120 ms, red > 120 ms";
  return `<span class="rt-pill ${rtClass(ms)}" title="${esc(tip)}">${esc(label ? label + " " : "")}${esc(txt)}</span>`;
}

const DECRYPT_BADGE = {
  decrypted: { cls: "badge-decrypted", label: "Decrypted", title: "Leaf certificate re-signed by a proxy/SWG CA (Cisco Secure Access) — SSL inspection active." },
  passthrough: { cls: "badge-passthrough", label: "Pass-through", title: "Leaf certificate from the real public CA — traffic NOT decrypted (bypass)." },
  tunnel: { cls: "badge-tunnel", label: "Tunnel", title: "Opaque HTTP CONNECT tunnel — payload not decrypted by passive capture." },
  encrypted: { cls: "badge-encrypted", label: "TLS 1.3 (cert hidden)", title: "TLS 1.3 encrypts the certificate — invisible to passive capture; decryption cannot be confirmed." },
};

const DECRYPT_LABEL = {
  decrypted: "Decrypted by proxy/SWG (cert re-signed by corporate CA)",
  passthrough: "Pass-through / not decrypted (real public CA presented)",
  tunnel: "Opaque CONNECT tunnel (payload not decrypted)",
  encrypted: "TLS 1.3 — certificate encrypted, cannot confirm decryption",
};

function decryptBadge(status) {
  const b = DECRYPT_BADGE[status];
  if (!b) return "";
  return ` <span class="badge ${b.cls}" title="${esc(b.title)}">${esc(b.label)}</span>`;
}

// Text for the "Certificate" table column.
// IMPORTANT: this column shows ONLY what the capture actually contains
// (authoritative evidence). A live online lookup is shown as a clearly separate
// "live lookup" chip so it can never be mistaken for the captured certificate.
function certCellText(f) {
  // 1) Real certificate observed on the wire (TLS 1.2 or decrypted) — evidence.
  if (f.subject) {
    const sa = f.secure_access_signed ? ' <span class="cert-tag cert-tag-sa">Cisco SA</span>' : "";
    const iss = f.issuer ? `\nissuer=${f.issuer}` : "";
    return `<span title="From the capture — CN=${esc(f.subject)}${esc(iss)}${f.cert_valid ? "\\nvalid " + esc(f.cert_valid) : ""}">${esc(f.subject)}</span>${sa}`;
  }

  // 2) No certificate in the capture. State the capture truth first.
  let base = "";
  const isTls13Hidden =
    (f.is_connect_tunnel && f.tunnel_server_hello && (f.tunnel_tls_version || "").indexOf("1.3") !== -1) ||
    (!f.is_connect_tunnel && (f.negotiated_version || "").indexOf("1.3") !== -1);
  if (isTls13Hidden) {
    base = `<span class="cert-tag cert-tag-enc" title="A certificate IS exchanged, but TLS 1.3 encrypts the server Certificate (RFC 8446) — not observable from a passive capture.">encrypted (TLS 1.3)</span>`;
  } else {
    base = '<span class="muted">—</span>';
  }

  // 3) If an online lookup was run, append it as a clearly-separate chip.
  //    It is NOT capture evidence and may differ from the real cert.
  if (f.resolved_cert && f.resolved_cert.subject) {
    const rc = f.resolved_cert;
    const tip = `LIVE LOOKUP — not from the capture. Connected to ${rc.host} just now; it served `
      + `CN=${rc.subject}, issuer=${rc.issuer || "?"}. This may differ from the certificate actually used `
      + `in the capture (load balancers often serve a default cert).`;
    base += ` <span class="cert-tag cert-tag-live" title="${esc(tip)}">\uD83C\uDF10 live: ${esc(rc.subject)}</span>`;
  }
  return base;
}

function flowBadges(f) {
  let out = decryptBadge(f.decryption_status);
  // Tunnel carrying an inner TLS 1.3 handshake: make it explicit that a cert
  // IS used but TLS 1.3 transmits it encrypted (not a gap in the tool).
  if (f.is_connect_tunnel && f.tunnel_server_hello && (f.tunnel_tls_version || "").indexOf("1.3") !== -1) {
    out += ` <span class="badge badge-encrypted" title="A certificate IS exchanged, but TLS 1.3 sends the server Certificate encrypted (after ServerHello) — invisible to passive capture by design (RFC 8446). Same whether inspection is ON or OFF.">cert used · encrypted by TLS 1.3</span>`;
  }
  if (f.secure_access_signed) {
    const t = f.secure_access_chain && f.secure_access_chain.path
      ? "Certificate chains to Cisco Secure Access Root CA: " + f.secure_access_chain.path
      : "Certificate issued by the Cisco Secure Access PKI.";
    out += ` <span class="badge badge-ca-secaccess" title="${esc(t)}">Cisco Secure Access CA</span>`;
  }
  return out;
}

// Slowdowns that never surface as an error: nothing fails, so there is no
// alert, no reset and no status code to show. Tagging them in the flow table is
// the only way to answer "where is this happening?" — otherwise the finding
// says the capture was slow but never points at a connection.
// `already` is the text the Issue cell will print anyway; a tag repeating it
// would just be clutter, so each one is skipped when it is already covered.
function slowTags(f, already) {
  const said = (already || "").toLowerCase();
  let out = "";
  const wf = f.window_full;
  if (typeof wf === "number" && wf > 0 && said.indexOf("receive window") === -1) {
    const rtt = f.tcp_handshake_ms;
    const pace = rtt ? ` Each pause lasted about ${Math.round(rtt)} ms (one round trip).` : "";
    out += ` <span class="slow-tag" title="The sender had to stop ${wf} time(s) because the receiver's buffer allowance was full — like a funnel that has to drain before you can keep pouring.${pace} Nothing failed and nothing was lost; the sender was waiting for permission, not for bandwidth. Open this flow for the full explanation.">waiting on receiver ×${wf}</span>`;
  }
  if (f.hello_retry_request && said.indexOf("extra round trip") === -1) {
    const offered = Array.isArray(f.hrr_offered_groups) ? f.hrr_offered_groups.join(" or ") : "";
    const forced = f.hrr_selected_group || "another method";
    const rtt = f.tcp_handshake_ms;
    const cost = rtt ? ` That costs about ${Math.round(rtt)} ms on every new connection here.` : "";
    out += ` <span class="slow-tag" title="Setting up encryption took two attempts instead of one: the client guessed ${offered || "a method"}, the server refused and made it start again with ${forced}.${cost} The connection works fine — it is just slower to open. Open this flow for the full explanation.">extra setup trip</span>`;
  }
  return out;
}

// --- Summary UI helpers (2026 dashboard look) ---
function svgIcon(name) {
  const P = {
    ok: '<circle cx="12" cy="12" r="9"/><path d="m8.4 12.4 2.5 2.5 4.7-5.2"/>',
    warn: '<path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/><line x1="12" y1="9" x2="12" y2="13.5"/><circle cx="12" cy="17" r="0.7" fill="currentColor" stroke="none"/>',
    alert: '<path d="M7.9 2h8.2L22 7.9v8.2L16.1 22H7.9L2 16.1V7.9L7.9 2z"/><line x1="12" y1="8" x2="12" y2="12.5"/><circle cx="12" cy="16" r="0.7" fill="currentColor" stroke="none"/>',
    eye: '<path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7z"/><circle cx="12" cy="12" r="3"/>',
    action: '<path d="M13 2 4.5 12.5a.7.7 0 0 0 .5 1.1H11l-1 8.4 8.5-10.5a.7.7 0 0 0-.5-1.1H12l1-8.4z"/>',
    note: '<line x1="9" y1="6" x2="20" y2="6"/><line x1="9" y1="12" x2="20" y2="12"/><line x1="9" y1="18" x2="20" y2="18"/><circle cx="4.6" cy="6" r="1" fill="currentColor" stroke="none"/><circle cx="4.6" cy="12" r="1" fill="currentColor" stroke="none"/><circle cx="4.6" cy="18" r="1" fill="currentColor" stroke="none"/>',
    bulb: '<path d="M9 18h6"/><path d="M10 22h4"/><path d="M15.1 14c.2-1 .6-1.7 1.4-2.5A4.6 4.6 0 0 0 18 8 6 6 0 0 0 6 8c0 1 .2 2.2 1.5 3.5.8.8 1.2 1.5 1.4 2.5"/>',
    link: '<path d="M9.5 12.5h5"/><path d="M8.5 16H7a4 4 0 0 1 0-8h1.5"/><path d="M15.5 8H17a4 4 0 0 1 0 8h-1.5"/>',
    info: '<circle cx="12" cy="12" r="9"/><line x1="12" y1="11" x2="12" y2="16.5"/><circle cx="12" cy="7.6" r="0.8" fill="currentColor" stroke="none"/>',
    shield: '<path d="M12 2.5 4.5 5.5v5.5c0 4.6 3.2 8.4 7.5 9.9 4.3-1.5 7.5-5.3 7.5-9.9V5.5L12 2.5z"/>',
    server: '<rect x="3" y="4" width="18" height="7" rx="1.6"/><rect x="3" y="13" width="18" height="7" rx="1.6"/><line x1="6.8" y1="7.5" x2="6.82" y2="7.5"/><line x1="6.8" y1="16.5" x2="6.82" y2="16.5"/>',
    globe: '<circle cx="12" cy="12" r="9"/><line x1="3" y1="12" x2="21" y2="12"/><path d="M12 3c2.5 2.6 3.8 5.7 3.8 9s-1.3 6.4-3.8 9c-2.5-2.6-3.8-5.7-3.8-9S9.5 5.6 12 3z"/>',
    lock: '<rect x="4.5" y="10.5" width="15" height="10" rx="2.2"/><path d="M8 10.5V7a4 4 0 0 1 8 0v3.5"/>',
    key: '<circle cx="8" cy="15" r="3.4"/><path d="M10.4 12.6 20 3"/><path d="M15.5 7.5 18 10"/><path d="M17.5 5.5 20 8"/>',
    plug: '<path d="M9 2v6"/><path d="M15 2v6"/><path d="M6 8h12v2.5a6 6 0 0 1-12 0V8z"/><path d="M12 16.5V22"/>',
    activity: '<path d="M3 12h4l2.5 7 4-14 2.5 7H21"/>',
  };
  return `<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${P[name] || ""}</svg>`;
}

// Renders the "How to fix" remediation playbook for a tech group. Each step is a
// concrete action; a leading "Secure Access:" / "<Vendor>:" label is emphasized.
function remediationHtml(steps) {
  if (!steps || !steps.length) return "";
  const items = steps.map((raw) => {
    const s = String(raw);
    const ci = s.indexOf(":");
    const label = ci > 0 ? s.slice(0, ci + 1) : "";
    const isLabel = ci > 0 && ci <= 20 && /^[A-Za-z][A-Za-z ]*:$/.test(label);
    const body = isLabel
      ? `<b class="fix-lbl">${esc(label)}</b> ${esc(s.slice(ci + 1).trim())}`
      : esc(s);
    return `<li>${body}</li>`;
  }).join("");
  return `<details class="tgx-fix">
    <summary><span class="fix-ico">${svgIcon("action")}</span>How to fix <span class="fix-count">${steps.length} step${steps.length !== 1 ? "s" : ""}</span></summary>
    <ol class="fix-list">${items}</ol>
  </details>`;
}

function execVerdict(findings) {
  const c = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  (findings || []).forEach((f) => { if (c[f.severity] != null) c[f.severity]++; });
  const prio = c.critical + c.high;
  if (prio) return { tone: "alert", title: "Needs your attention", chip: `${prio} priority issue${prio !== 1 ? "s" : ""}`, counts: c };
  if (c.medium) return { tone: "warn", title: "Worth a closer look", chip: `${c.medium} item${c.medium !== 1 ? "s" : ""} to review`, counts: c };
  if (c.low) return { tone: "ok", title: "Looking healthy", chip: "Minor notes only", counts: c };
  return { tone: "ok", title: "Working as expected", chip: "No problems found", counts: c };
}

function insightTile(icon, label, bodyHtml) {
  return `<div class="ins">
    <span class="ins-ico ins-${icon}">${svgIcon(icon)}</span>
    <div class="ins-body"><span class="ins-label">${esc(label)}</span><div class="ins-text">${bodyHtml}</div></div>
  </div>`;
}

// Highlight the Cisco Secure Client / Umbrella roaming module's own self-report
// (STARTMSG) when it was captured in clear on loopback: the SWG proxy + org it
// is bound to and how many web connections it steered vs let bypass (go direct).
// What the capture itself shows was inspected, rendered next to the agent's own
// counters. Those counters cannot carry a percentage (different populations,
// cumulative since the agent started), so this is the figure that answers the
// question they appear to answer — and it belongs beside them, not buried in a
// findings group at the bottom of the page.
function coverageHighlight(cov) {
  if (!cov) return "";
  const has = (k) => cov[k] != null;
  const pctTile = (val, lab, warn) =>
    `<div class="roam-stat ${warn ? "roam-stat-warn" : ""}"><b>${val}</b><span>${lab}</span></div>`;

  const tiles = [];
  if (has("web_excluded_pct")) {
    tiles.push(pctTile(cov.web_excluded_pct + "%", `web destinations NOT inspected (${cov.web_excluded_dests} of ${cov.web_total_dests})`, cov.web_excluded_pct >= 25));
  }
  if (has("dns_excluded_pct")) {
    tiles.push(pctTile(cov.dns_excluded_pct + "%", `DNS queries NOT via Umbrella (${cov.dns_direct} of ${cov.dns_total})`, cov.dns_excluded_pct >= 25));
  }
  if (!tiles.length) return "";

  const rows = (cov.rows || []).map(r =>
    `<tr class="${/^0 /.test(r.count) ? "cov-zero" : ""}"><td>${esc(r.name)}</td><td class="cov-n">${esc(r.count)}</td><td class="cov-w">${esc(r.why)}</td></tr>`
  ).join("");
  const ex = (cov.web_examples || []).length
    ? `<p class="roam-hl-note">Not inspected: ${(cov.web_examples || []).map(esc).join(", ")}.</p>` : "";

  return `<div class="roam-hl cov-hl">
    <div class="roam-hl-head">
      <span class="roam-hl-ico">${svgIcon("eye")}</span>
      <div>
        <span class="roam-hl-eyebrow">Measured from this capture \u00b7 not from the agent's counters</span>
        <h3 class="roam-hl-title">Inspection coverage</h3>
      </div>
    </div>
    <div class="roam-hl-stats">${tiles.join("")}</div>
    ${ex}
    ${rows ? `<table class="cov-table"><tbody>${rows}</tbody></table>` : ""}
    <p class="roam-hl-caption">Web is counted per <b>destination</b>: a host seen going through the SWG even once was inspected, so only hosts never observed steered count as excluded. DNS is counted per query. Zero rows are shown on purpose \u2014 “QUIC: 0” means nothing slipped past that way, which is a result, not an absence.</p>
  </div>`;
}

function roamingHighlight(rr) {
  if (!rr) return "";
  const num = (n) => (n == null ? null : Number(n).toLocaleString());
  const https = rr.https_connections, http = rr.http_connections, byp = rr.bypassed_connections;
  const orgMatch = /swg-url-proxy-https-(\d+)\./.exec(rr.umbrella_proxy || "");
  const org = orgMatch ? orgMatch[1] : null;
  const grew = (rr.bypassed_first != null && rr.bypassed_last != null && rr.bypassed_last > rr.bypassed_first);
  const delta = grew ? rr.bypassed_last - rr.bypassed_first : null;

  const stat = (val, lab, cls) =>
    val == null ? "" : `<div class="roam-stat ${cls || ""}"><b>${val}</b><span>${lab}</span></div>`;

  // NO "% of web bypassed" tile. The steered counters are HTTP and HTTPS only,
  // while a bypass also covers internal hosts and protocols the module cannot
  // proxy at all (QUIC/UDP) — dividing them would mix populations and present
  // the result as a web ratio the capture cannot back up. The fourth tile shows
  // the one figure that genuinely belongs to this capture: how much the bypass
  // counter moved while it was running.
  // The caveats live in one caption and one collapsed note rather than inside
  // every tile label: repeating them made the panel unreadable, which defeats
  // the point of stating them at all.
  return `<div class="roam-hl">
    <div class="roam-hl-head">
      <span class="roam-hl-ico">${svgIcon("shield")}</span>
      <div>
        <span class="roam-hl-eyebrow">Secure Client roaming · agent self-report (read in clear from loopback)</span>
        <h3 class="roam-hl-title">SWG / Secure Access steering${org ? ` · org ${esc(org)}` : ""}</h3>
      </div>
    </div>
    <div class="roam-hl-stats">
      ${stat(num(https), "HTTPS steered")}
      ${stat(num(http), "HTTP steered")}
      ${stat(num(byp), "bypassed · all protocols")}
      ${delta != null ? stat("+" + num(delta), "during this capture", "roam-stat-warn") : ""}
    </div>
    <p class="roam-hl-caption">First three are the agent's running totals <b>since it started</b> — not this capture.${delta != null ? " Only the last one was measured here." : ""}</p>
    ${rr.umbrella_proxy ? `<div class="roam-hl-proxy"><span>proxy</span><code>${esc(rr.umbrella_proxy)}</code></div>` : ""}
    ${grew ? `<p class="roam-hl-note">The bypassed counter went ${num(rr.bypassed_first)} → ${num(rr.bypassed_last)} while HTTP/HTTPS steering stayed flat, so the activity in this window went direct.</p>` : ""}
    <details class="roam-why">
      <summary>Why there is no percentage here</summary>
      <p>“Steered” counts HTTP and HTTPS only; “bypassed” counts everything the module let through untouched — cert-pinned SaaS, internal/RFC1918 destinations, and protocols it cannot proxy at all such as QUIC/UDP. They are not the same population, and nothing on the wire lets us split the bypassed total by protocol, so any ratio between them would be meaningless. For a real coverage figure see the <b>inspection coverage</b> findings, which are measured from this capture per destination.</p>
    </details>
  </div>`;
}

// A friendly callout card for a correlation / note line.
//   link — evidence successfully connected (blue)
//   gap  — a connection we could NOT make / out-of-window caveat (amber)
//   note — informational context / caveat (neutral violet)
function corrCard(text, kind) {
  const ICON = { link: "link", gap: "warn", note: "info" };
  const pretty = esc(text)
    .replace(/\u2194/g, '<span class="corr-arrow">\u2194</span>')
    .replace(/\[([^\]]+)\]/g, '<code class="corr-keys">[$1]</code>');
  return `<div class="corr corr-${kind}">
    <span class="corr-ico">${svgIcon(ICON[kind])}</span>
    <p class="corr-text">${pretty}</p>
  </div>`;
}

function severityBar(counts) {
  const order = ["critical", "high", "medium", "low", "info"];
  const total = order.reduce((a, k) => a + (counts[k] || 0), 0);
  if (!total) return "";
  const segs = order.filter((k) => counts[k]).map((k) =>
    `<span class="sb-seg sb-${k}" style="flex:${counts[k]}" title="${counts[k]} ${k}"></span>`).join("");
  const legend = order.filter((k) => counts[k]).map((k) =>
    `<span class="sb-leg"><span class="sb-dot dot-${k}"></span>${counts[k]} <em>${k}</em></span>`).join("");
  return `<div class="sevmix"><div class="sb-track">${segs}</div><div class="sb-legend">${legend}</div></div>`;
}

function render(data) {
  $("results").classList.remove("hidden");
  lastData = data;
  lastReport = data.report_text || "";
  flowPage = 0;
  $("download").disabled = !lastReport;

  // summary
  const s = data.summary;
  const ev = (s.primary_evidence || []).map((e) => `<li>${esc(e)}</li>`).join("");

  // --- Executive summary: a friendly verdict hero + insight tiles ---
  const secondaryList = (s.plain_secondary || []).map((x) => `<li>${esc(x)}</li>`).join("");
  const verdict = execVerdict(data.findings);
  const insights = [];
  if (s.plain_impact) insights.push(insightTile("eye", "What this means for you", esc(s.plain_impact)));
  if (s.recommended_action) insights.push(insightTile("action", "What to do", esc(s.recommended_action)));
  if (secondaryList) insights.push(insightTile("note", "Also worth noting", `<ul class="ins-list">${secondaryList}</ul>`));
  const reducedBanner = data.reduced ? `
    <div class="reduced-banner">
      <span class="reduced-ico">${svgIcon("warn")}</span>
      <div>
        <b>Large capture — reduced analysis.</b>
        Only TLS/DTLS handshakes, DNS, QUIC setup, TCP control (SYN/FIN/RST) and ICMP frames were decoded.
        TLS posture, certificates, DNS and connection health are accurate; per-flow byte/packet totals
        exclude bulk payload (HTTP bodies, media) and read low by design.
      </div>
    </div>` : "";
  const dec = data.decryption;
  const decryptionBanner = (dec && dec.keylog_used) ? `
    <div class="decrypt-banner">
      <span class="decrypt-ico">${svgIcon("ok")}</span>
      <div>
        <b>TLS key log applied — sessions decrypted.</b>
        The SSLKEYLOGFILE was used to decrypt TLS. Real certificates and inner protocol details
        are visible even on TLS 1.3${dec.inner_tls_recovered ? ` — inner TLS recovered on <b>${dec.inner_tls_recovered}</b> tunneled flow${dec.inner_tls_recovered !== 1 ? "s" : ""}` : ""}${dec.tunnels ? ` across ${dec.tunnels} CONNECT tunnel${dec.tunnels !== 1 ? "s" : ""}` : ""}.
      </div>
    </div>` : "";
  $("summary-card").innerHTML = decryptionBanner + reducedBanner + `
    <div class="exec-hero hero-${verdict.tone}">
      <span class="exec-hero-ico">${svgIcon(verdict.tone)}</span>
      <div class="exec-hero-main">
        <span class="exec-eyebrow">Executive summary · in plain words</span>
        <h2 class="exec-verdict">${esc(verdict.title)}</h2>
      </div>
      <span class="exec-chip chip-${verdict.tone}">${esc(verdict.chip)}</span>
    </div>
    <p class="exec-lead">${esc(s.plain_summary || s.diagnosis)}</p>
    ${s.plain_scope ? `<p class="exec-scope">${esc(s.plain_scope)}</p>` : ""}
    ${roamingHighlight(data.roaming_report)}
    ${coverageHighlight(data.steering_coverage)}
    ${insights.length ? `<div class="exec-insights">${insights.join("")}</div>` : ""}
  `;

  // --- Technical summary: confidence, severity mix, ranked problem groups ---
  const groups = s.tech_groups || [];
  const groupHtml = groups.map((g) => {
    const sv = esc(g.severity);
    const scope = g.flow_count ? `${g.flow_count} flow${g.flow_count !== 1 ? "s" : ""}`
      : (g.count ? `${g.count} finding${g.count !== 1 ? "s" : ""}` : "");
    return `<div class="tgx tgx-${sv}">
      <div class="tgx-head">
        <span class="tgx-dot dot-${sv}"></span>
        <span class="tgx-label">${esc(g.label)}</span>
        ${scope ? `<span class="tgx-scope">${scope}</span>` : ""}
        <span class="sev-pill sp-${sv}">${sv === "info" ? "INFO" : esc(sv.toUpperCase())}</span>
      </div>
      <div class="tgx-body">
        ${g.why ? `<p class="tgx-why">${esc(g.why)}</p>` : ""}
        ${g.example_plain ? `<p class="tgx-eg">${svgIcon("bulb")}<span>${esc(g.example_plain)}</span></p>` : ""}
        ${g.example ? `<div class="tgx-ev"><span class="tgx-ev-tag">Evidence</span><code>${esc(g.example)}</code></div>` : ""}
        ${remediationHtml(g.remediation)}
      </div>
    </div>`;
  }).join("");
  $("tech-summary-card").innerHTML = `
    <div class="tech-head">
      <div class="tech-head-main">
        <span class="exec-eyebrow eyebrow-tech">Technical summary · for engineers</span>
        <p class="tech-diag">${esc(s.diagnosis)}</p>
      </div>
      <span class="conf conf-${esc(s.confidence)}" title="How strongly the evidence supports this conclusion">${esc(s.confidence)} confidence</span>
    </div>
    ${severityBar(verdict.counts)}
    ${groupHtml ? `<div class="tech-section-label">Problems detected · most severe first</div><div class="tgx-list">${groupHtml}</div>` : ""}
    ${ev ? `<div class="tech-section-label">Key evidence from the capture</div><ul class="ev-list ev-list-tech">${ev}</ul>` : ""}
  `;

  renderTable();
  renderDns(data.dns);
  renderHosts(data.hosts);

  // report — rich, colour-coded HTML rendering of the analysis
  $("report").innerHTML = renderReportHtml(data);
  $("results").scrollIntoView({ behavior: "smooth" });
}

// Build a styled HTML report from the analysis JSON (replaces the plain-text dump).
function renderReportHtml(data) {
  const s = data.summary || {};
  const findings = (data.findings || []).slice().sort(
    (a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9)
  );
  const sevPill = (sv) => `<span class="sev-pill sp-${esc(sv)}">${sv === "info" ? "INFO" : esc((sv || "").toUpperCase())}</span>`;

  let html = "";

  // 1 — Executive (plain) summary
  html += `<section class="rp-sec">
    <h3 class="rp-h">Executive summary</h3>
    <p class="rp-lead">${esc(s.plain_summary || s.diagnosis || "")}</p>
    ${s.plain_scope ? `<p class="rp-muted">${esc(s.plain_scope)}</p>` : ""}
    ${s.plain_impact ? `<p><b>Impact:</b> ${esc(s.plain_impact)}</p>` : ""}
    ${s.recommended_action ? `<p><b>Recommended action:</b> ${esc(s.recommended_action)}</p>` : ""}
  </section>`;

  // 2 — Problems detected: ranked groups, each with its findings nested inside
  const groups = s.tech_groups || [];
  const findingCard = (f) => {
    const evi = (f.evidence || []).map((e) => `<li class="mono">${esc(e)}</li>`).join("");
    return `<div class="rp-finding rp-${esc(f.severity)}">
      <div class="rp-finding-head">${sevPill(f.severity)}<span class="rp-finding-title">${esc(f.title)}</span>
        ${f.flow_key ? `<span class="rp-flowkey mono">${esc(f.flow_key)}</span>` : ""}</div>
      ${f.detail ? `<p class="rp-finding-detail">${esc(f.detail)}</p>` : ""}
      ${evi ? `<ul class="rp-evi">${evi}</ul>` : ""}
    </div>`;
  };

  // Index findings by category so each group owns its own evidence
  const byCat = {};
  findings.forEach((f) => { (byCat[f.category] = byCat[f.category] || []).push(f); });
  const usedCats = new Set();

  html += `<section class="rp-sec">
    <h3 class="rp-h">Problems detected
      <span class="rp-count">${groups.length}</span>
      <span class="conf conf-${esc(s.confidence)}">Confidence: ${esc(s.confidence)}</span></h3>
    <p class="rp-muted">${esc(s.diagnosis || "")}</p>`;

  groups.forEach((g) => {
    usedCats.add(g.category);
    const gf = (byCat[g.category] || []).slice().sort(
      (a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9)
    );
    const open = g.severity === "critical" || g.severity === "high" ? " open" : "";
    const CAP = 6;
    const shown = gf.slice(0, CAP);
    const extra = gf.length - shown.length;
    html += `<details class="rp-group-block tg-${esc(g.severity)}"${open}>
      <summary class="rp-group-sum">
        ${sevPill(g.severity)}
        <span class="tg-label">${esc(g.label)}</span>
        <span class="rp-group-meta">${g.flow_count ? g.flow_count + " flow(s)" : (gf.length + " event(s)")}</span>
      </summary>
      ${g.why ? `<p class="tg-why">${esc(g.why)}</p>` : ""}
      ${g.example_plain ? `<p class="tg-eg">${esc(g.example_plain)}</p>` : ""}
      ${shown.length ? `<div class="rp-group-findings">${shown.map(findingCard).join("")}</div>` : ""}
      ${extra > 0 ? `<p class="rp-more">+${extra} more similar event(s) of this type</p>` : ""}
      ${remediationHtml(g.remediation)}
    </details>`;
  });

  // Any findings whose category had no matching group (safety net)
  const orphan = findings.filter((f) => !usedCats.has(f.category));
  if (orphan.length) {
    html += `<details class="rp-group-block tg-info">
      <summary class="rp-group-sum">${sevPill("info")}<span class="tg-label">Other observations</span>
        <span class="rp-group-meta">${orphan.length} event(s)</span></summary>
      <div class="rp-group-findings">${orphan.map(findingCard).join("")}</div>
    </details>`;
  }
  html += `</section>`;

  // 4 — DNS summary
  const dns = data.dns && data.dns.summary;
  if (dns && dns.total) {
    html += `<section class="rp-sec"><h3 class="rp-h">DNS</h3>
      <p>${dns.total} lookup(s) · <b class="rp-red">${dns.blocked_count || 0}</b> blocked ·
         <b class="rp-orange">${dns.issue_count || 0}</b> with issues.
      ${dns.blocked && dns.blocked.length ? `Blocked: <span class="mono">${esc(dns.blocked.join(", "))}</span>` : ""}</p>
    </section>`;
  }

  // 5 — Correlations & notes
  const corrItems = (data.correlations || []).map((c) => {
    const gap = /no matching|fall outside|outside the PCAP|continued after|DNS-stage failure/i.test(c);
    return corrCard(c, gap ? "gap" : "link");
  });
  const noteItems = (data.notes || []).map((n) => corrCard(n, "note"));
  const corrAll = corrItems.concat(noteItems);
  if (corrAll.length) {
    html += `<section class="rp-sec"><h3 class="rp-h">How the evidence connects <span class="rp-count">${corrAll.length}</span></h3>
      <div class="corr-list">${corrAll.join("")}</div></section>`;
  }

  // 6 — Raw text report (collapsible, for export parity)
  if (data.report_text) {
    html += `<details class="rp-raw"><summary>Show raw text report</summary><pre>${esc(data.report_text)}</pre></details>`;
  }

  return html;
}

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4, ok: 5 };

// Classify a flow into a traffic channel for at-a-glance colouring:
//   dns  (blue)  — DNS resolution, including DoH/DoT to known public resolvers
//   web  (green) — web traffic Secure Access CAN inspect (HTTP/HTTPS, CONNECT)
//   quic (red)   — QUIC / HTTP-3: highlighted because the SWG does NOT intercept
//                  it, so it passes through uninspected (effectively non-web)
//   other(amber) — everything else (non-web TCP/UDP)
function trafficChannel(f) {
  const dp = f.dst_port, sp = f.src_port;
  const isPort = (p) => dp === p || sp === p;
  const l7 = (f.l7_protocol || "").toLowerCase();
  // DNS in any transport: classic :53, DoT :853, mDNS/LLMNR, or any known
  // public resolver (Umbrella/OpenDNS, Google, Cloudflare, Quad9) even over
  // DoH/DNSCrypt on 443 — e.g. 208.67.222.222:443 is an Umbrella DNS lookup.
  if (isPort(53) || isPort(853) || l7 === "dns" || l7 === "mdns" || l7 === "llmnr" || f.dns_resolver) return "dns";
  // QUIC / HTTP-3 — flagged on its own because Secure Access does NOT decrypt it.
  if (f.is_quic || l7 === "quic") return "quic";
  // Web traffic the SWG can inspect: HTTP(S), explicit-proxy CONNECT tunnels.
  if (isPort(443) || isPort(80) || isPort(8080) || f.is_connect_tunnel ||
      l7 === "http" || l7 === "http/2" || l7 === "http/3" || l7 === "tls") return "web";
  return "other"; // non-web
}

const CHANNEL_META = {
  dns:   { label: "DNS",  title: "DNS resolution (incl. DoH/DoT to a known public resolver)" },
  web:   { label: "WEB",  title: "Web traffic — HTTP/HTTPS the SWG can inspect (port 80/443)" },
  quic:  { label: "QUIC", title: "QUIC / HTTP-3 (UDP/443) — NOT intercepted by Secure Access; passes through uninspected" },
  other: { label: "NET",  title: "Non-web traffic (other TCP/UDP protocol)" },
};

function channelChip(row) {
  const m = CHANNEL_META[row.channel] || CHANNEL_META.other;
  if (!m.label) return "";
  const proto = row.data && row.data.l7_protocol;
  // For non-web flows the bare "NET" tag isn't helpful — show the real protocol.
  const text = (row.channel === "other" && proto) ? proto.toUpperCase() : m.label;
  const lb = row.loopback ? ' <span class="lb-tag" title="Loopback (127.0.0.1) — local listener of the Cisco Secure Client roaming module, not on-the-wire traffic">loopback</span>' : "";
  const pa = row.privateAccess ? ' <span class="pa-tag" title="Cisco Secure Access — Private Access (Zero Trust / ZTNA). Source/destination is in the 100.64.0.0/10 CGNAT pool. This is the Zero Trust proxy path to a private resource — NOT SWG/web traffic, and it tunnels arbitrary protocols.">ZTA</span>' : "";
  const intern = (row.internal && !row.privateAccess && !row.loopback) ? ' <span class="int-tag" title="Internal traffic: both endpoints are private (RFC 1918 / link-local / ULA). Private→private LAN traffic never goes through the Secure Access SWG (SIA), so TLS-decryption / web-policy / pinning verdicts do not apply.">internal</span>' : "";
  return `<span class="chan-chip chan-${row.channel}" title="${esc(m.title)}">${esc(text)}</span>${lb}${pa}${intern}`;
}

function buildRows(data) {
  const rows = [];

  // PCAP flows
  (data.flows || []).forEach((f) => {
    const sev = f.has_problem ? f.worst_severity || "low" : "ok";
    const channel = trafficChannel(f);
    // Give DNS flows a meaningful name instead of "(no SNI)": the queried
    // domain, or — when the query is encrypted (DoH/DoT) — the resolver.
    let domain = f.sni || f.connect_target;
    if (!domain) {
      if (channel === "dns") domain = f.dns_query || (f.dns_resolver ? "encrypted DNS \u2192 " + f.dns_resolver : "DNS query");
      else if (f.dns_lookup && f.dns_lookup.name) domain = f.dns_lookup.name + "  (DNS)";
      else if (f.resolved_host) domain = f.resolved_host + "  (NRB)";
      else domain = "(no SNI)";
    }
    let proto;
    if (f.is_quic) proto = "QUIC/HTTP3";
    else if (f.is_connect_tunnel) proto = "HTTP CONNECT" + (f.tunnel_tls_version ? " / " + f.tunnel_tls_version : (f.negotiated_version ? " / " + f.negotiated_version : ""));
    else {
      const base = f.l7_protocol || f.transport.toUpperCase();
      proto = base + (f.negotiated_version ? " / " + f.negotiated_version : "");
    }
    const dst = f.is_connect_tunnel && f.connect_target
      ? f.connect_target + "  (via " + (f.proxy_provider || ("proxy " + (f.proxy_ip || ""))) + ")"
      : (f.proxy_provider ? f.dst + "  \u2014 " + f.proxy_provider
        : (f.dns_resolver ? f.dst + "  \u2014 " + f.dns_resolver : f.dst));
    rows.push({
      kind: "flow",
      sev,
      problem: !!f.has_problem,
      time: f.time,
      time_rel: f.time_rel,
      src: f.src,
      dst: dst,
      domain: domain,
      channel: channel,
      loopback: !!f.loopback,
      privateAccess: !!f.is_private_access,
      internal: !!f.is_internal,
      cert: certCellText(f),
      proto: proto,
      status: f.tls_status,
      blocked: !!f.block_category,
      blockCategory: f.block_category || null,
      error: f.block_category
        ? "Blocked: " + f.block_category
        : (f.error_summary || (f.has_problem ? (f.findings[0] && f.findings[0].title) : "—")),
      data: f,
    });
  });

  // HAR failed entries
  (data.har_entries || []).forEach((h) => {
    const sev =
      h.category === "cert_trust" || h.category === "public_cert" || h.category === "pinning_signal" || h.category === "proxy"
        ? "high"
        : "medium";
    rows.push({
      kind: "har",
      sev,
      problem: true,
      time: h.time,
      src: "browser",
      dst: h.server_ip || "—",
      domain: h.host || "—",
      cert: "",
      proto: "HTTP" + (h.http_version ? " " + h.http_version : ""),
      status: h.status ? "HTTP " + h.status + (h.status_text ? " " + h.status_text : "") : "failed",
      blocked: !!h.block_type,
      blockCategory: h.block_type || null,
      error: h.error_label || h.error || ("HTTP " + h.status),
      data: h,
    });
  });

  rows.sort((a, b) => {
    const s = (SEV_ORDER[a.sev] ?? 9) - (SEV_ORDER[b.sev] ?? 9);
    if (s !== 0) return s;
    return (a.time_rel ?? 1e9) - (b.time_rel ?? 1e9);
  });
  return rows;
}

function renderTable() {
  if (!lastData) return;
  const onlyProblems = $("only-problems").checked;
  const q = ($("flow-filter").value || "").toLowerCase().trim();
  const body = $("flow-body");
  let rows = buildRows(lastData);

  if (onlyProblems) rows = rows.filter((r) => r.problem);
  if (certsOnly)
    rows = rows.filter(
      (r) => r.kind === "flow" && (r.data.issuer || r.data.secure_access_signed ||
        ["decrypted", "passthrough", "encrypted"].includes(r.data.decryption_status))
    );
  if (q)
    rows = rows.filter((r) =>
      [r.domain, r.src, r.dst, r.status, r.error].join(" ").toLowerCase().includes(q)
    );

  body.innerHTML = "";
  if (!rows.length) {
    $("flow-empty").classList.remove("hidden");
    $("flow-table").classList.add("hidden");
    renderPager(0, 0, 0);
    return;
  }
  $("flow-empty").classList.add("hidden");
  $("flow-table").classList.remove("hidden");

  // --- pagination ---
  const totalPages = Math.ceil(rows.length / PAGE_SIZE);
  if (flowPage >= totalPages) flowPage = totalPages - 1;
  if (flowPage < 0) flowPage = 0;
  const start = flowPage * PAGE_SIZE;
  const pageRows = rows.slice(start, start + PAGE_SIZE);

  const frag = document.createDocumentFragment();
  pageRows.forEach((r) => {
    const tr = document.createElement("tr");
    tr.className = "row sev-" + r.sev + (r.kind === "flow" && r.channel ? " chan-row-" + r.channel : "") + (r.loopback ? " row-loopback" : "");
    const errClass = r.sev === "ok" || r.sev === "info" ? "err-cell okish"
      : (r.sev === "medium" ? "err-cell warnish"
      : (r.sev === "low" ? "err-cell lowish" : "err-cell"));
    // Reduced client MSS tag for the Error / Issue column. NOTE: amber, not red —
    // a reduced MSS is the normal mechanism that lets traffic pass (it sizes
    // packets to the smallest-MTU hop, preventing fragmentation). It is NOT a
    // failure; traffic flows fine. Only worth checking if large transfers stall.
    const _mss = r.kind === "flow" ? r.data.client_mss : null;
    const mssTag = (typeof _mss === "number" && _mss > 0 && _mss < 1460)
      ? ` <span class="mtu-tag" title="Reduced TCP MSS (${_mss}) → effective path MTU ~${_mss + 40} bytes. It does NOT block traffic, but a reduced path MTU can cause slowness, and if it is not honored end-to-end (PMTUD blocked, no clamping) it causes retransmissions and stalls. Open this flow for what it means and the possible causes.">MTU/MSS ${_mss}</span>`
      : "";
    // Slowdowns that are NOT failures. They produce no alert, no RST and no
    // error text, so without their own tag the Error column would read "—" and
    // the operator could never see WHICH connection the slowdown happened on.
    const perfTag = r.kind === "flow" ? slowTags(r.data, r.error) : "";
    tr.innerHTML = `
      <td><span class="caret">▶</span></td>
      <td class="time-cell mono">${esc(r.time || "—")}${r.time_rel != null ? `<br><span class="muted">t+${r.time_rel}s</span>` : ""}</td>
      <td><span class="sev-pill sp-${r.sev}">${r.sev === "ok" ? "OK" : esc(r.sev)}</span></td>
      <td class="mono">${esc(r.src)}</td>
      <td class="mono">${esc(r.dst)}</td>
      <td class="sni-cell">${esc(r.domain)}${r.kind === "flow" ? channelChip(r) : ""}${r.kind === "har" ? ' <span class="badge badge-har">HAR</span>' : (r.kind === "flow" ? flowBadges(r.data) : "")}</td>
      <td class="cert-cell mono">${r.cert || '<span class="muted">—</span>'}</td>
      <td>${esc(r.proto)}</td>
      <td>${esc(r.status)}${r.kind === "flow" && r.data.response_ms != null ? "<br>" + rtPill(r.data.response_ms) : ""}</td>
      <td class="${errClass}">${r.blocked ? `<span class="block-badge" title="Reached the Secure Access block page — this is a policy block, not a TLS failure">\u26d4 ${esc(r.blockCategory)}</span>` : (r.error ? esc(r.error) : ((mssTag || perfTag) ? "" : "—"))}${mssTag}${perfTag}</td>`;

    const detail = document.createElement("tr");
    detail.className = "detail-row hidden";
    // Lazy: build the (expensive) detail HTML only on first expand.
    let built = false;
    tr.addEventListener("click", () => {
      if (!built) {
        detail.innerHTML = `<td colspan="10">${r.kind === "flow" ? flowDetail(r.data) : harDetail(r.data)}</td>`;
        built = true;
      }
      tr.classList.toggle("open");
      detail.classList.toggle("hidden");
    });

    frag.appendChild(tr);
    frag.appendChild(detail);
  });
  body.appendChild(frag);
  renderPager(rows.length, totalPages, start + pageRows.length);
}

function renderPager(total, totalPages, shownEnd) {
  const pager = $("flow-pager");
  if (!pager) return;
  if (total <= PAGE_SIZE) {
    pager.classList.add("hidden");
    pager.innerHTML = "";
    return;
  }
  pager.classList.remove("hidden");
  const start = flowPage * PAGE_SIZE + 1;
  pager.innerHTML = `
    <button class="pg-btn" id="pg-prev" ${flowPage === 0 ? "disabled" : ""}>‹ Prev</button>
    <span class="pg-info">Showing <b>${start}–${shownEnd}</b> of <b>${total}</b> · page ${flowPage + 1}/${totalPages}</span>
    <button class="pg-btn" id="pg-next" ${flowPage >= totalPages - 1 ? "disabled" : ""}>Next ›</button>`;
  const prev = $("pg-prev"), next = $("pg-next");
  if (prev) prev.addEventListener("click", () => { if (flowPage > 0) { flowPage--; renderTable(); scrollToEl("sec-flows"); } });
  if (next) next.addEventListener("click", () => { if (flowPage < totalPages - 1) { flowPage++; renderTable(); scrollToEl("sec-flows"); } });
}

// --- DNS panel ---------------------------------------------------------------
function renderDns(dns) {
  const sec = $("sec-dns");
  if (!dns || !dns.records || !dns.records.length) {
    sec.classList.add("hidden");
    return;
  }
  sec.classList.remove("hidden");

  const sm = dns.summary || {};
  const navDns = $("nav-dns");
  if (sm.blocked_count || sm.issue_count) {
    navDns.classList.add("nav-alert");
  } else {
    navDns.classList.remove("nav-alert");
  }

  const parts = [`<span class="dns-stat">${sm.total || dns.records.length} name(s)</span>`];
  if (sm.blocked_count) parts.push(`<span class="dns-stat dns-stat-block">${sm.blocked_count} DNS-blocked by Secure Access</span>`);
  if (sm.issue_count) parts.push(`<span class="dns-stat dns-stat-issue">${sm.issue_count} resolution issue(s)</span>`);
  if (!sm.blocked_count && !sm.issue_count) parts.push(`<span class="dns-stat dns-stat-ok">all resolved cleanly</span>`);
  $("dns-summary").innerHTML = parts.join(" ");

  renderDnsTable(dns.records);
}

function renderDnsTable(records) {
  const onlyFlagged = $("dns-only-flagged").checked;
  let rows = records;
  if (onlyFlagged) rows = rows.filter((r) => r.blocked || r.issue);

  const body = $("dns-body");
  body.innerHTML = "";
  if (!rows.length) {
    $("dns-table").classList.add("hidden");
    $("dns-empty").classList.remove("hidden");
    return;
  }
  $("dns-table").classList.remove("hidden");
  $("dns-empty").classList.add("hidden");

  rows.forEach((r) => {
    let result, cls, status;
    if (r.blocked) {
      result = `<span class="dns-pill dns-pill-block">BLOCKED</span>`;
      cls = "dns-row-block";
      status = esc(r.block_category || "Secure Access block page")
        + (r.block_ip ? ` <span class="muted">(${esc(r.block_ip)})</span>` : "");
    } else if (r.issue) {
      result = `<span class="dns-pill dns-pill-issue">${esc(r.issue)}</span>`;
      cls = "dns-row-issue";
      status = esc(r.issue_detail || "");
    } else {
      result = `<span class="dns-pill dns-pill-ok">resolved</span>`;
      cls = "";
      status = r.response_time != null ? rtPill(r.response_time * 1000) : "";
    }
    const answers = (r.addresses || []).join(", ")
      + (r.cnames && r.cnames.length ? `  <span class="muted">CNAME ${esc(r.cnames.join(", "))}</span>` : "");
    const tr = document.createElement("tr");
    tr.className = "row " + cls;
    tr.innerHTML = `
      <td class="mono">${esc(r.name)}</td>
      <td>${result}</td>
      <td class="mono">${answers || '<span class="muted">—</span>'}</td>
      <td>${status || '<span class="muted">—</span>'}</td>`;
    body.appendChild(tr);
  });
}

// --- Host inventory (asset view) ---
function renderHosts(hosts) {
  const sec = $("sec-hosts");
  if (!hosts || !hosts.length) {
    sec.classList.add("hidden");
    return;
  }
  sec.classList.remove("hidden");

  const probCount = hosts.filter((h) => h.has_problem).length;
  const navHosts = $("nav-hosts");
  if (probCount) navHosts.classList.add("nav-alert"); else navHosts.classList.remove("nav-alert");

  const intercepted = hosts.filter((h) => h.proxy_ca || h.intercept_vendor).length;
  const parts = [`<span class="dns-stat">${hosts.length} host${hosts.length !== 1 ? "s" : ""}</span>`];
  if (probCount) parts.push(`<span class="dns-stat dns-stat-issue">${probCount} with issues</span>`);
  if (intercepted) parts.push(`<span class="dns-stat dns-stat-block">${intercepted} TLS-intercepted</span>`);
  if (!probCount) parts.push(`<span class="dns-stat dns-stat-ok">no host-level issues</span>`);
  $("host-summary").innerHTML = parts.join(" ");

  renderHostTable(hosts);
}

function hostIcon(h) {
  if (h.loopback || h.intercept_vendor) return "lock"; // local interception point
  if (h.is_private_access) return "key";                // Private Access
  if (h.is_internal) return "server";                   // internal asset
  return "globe";                                        // external destination
}

function renderHostTable(hosts) {
  const onlyProblems = $("hosts-only-problems").checked;
  const q = ($("host-filter").value || "").toLowerCase().trim();
  let rows = hosts;
  if (onlyProblems) rows = rows.filter((h) => h.has_problem);
  if (q) rows = rows.filter((h) =>
    [h.ip, h.primary_host, (h.hostnames || []).join(" "), (h.cert_issuers || []).join(" ")]
      .join(" ").toLowerCase().includes(q));

  const list = $("host-list");
  list.innerHTML = "";
  if (!rows.length) {
    list.classList.add("hidden");
    $("host-empty").classList.remove("hidden");
    return;
  }
  list.classList.remove("hidden");
  $("host-empty").classList.add("hidden");

  const frag = document.createDocumentFragment();
  rows.forEach((h) => {
    const sev = h.worst_severity || "ok";
    const card = document.createElement("div");
    card.className = "hcard sev-" + sev + (h.loopback ? " hcard-loopback" : "");

    const hostLabel = h.primary_host
      ? `<span class="hcard-host">${esc(h.primary_host)}</span><span class="hcard-ip mono">${esc(h.ip)}</span>`
      : `<span class="hcard-host mono">${esc(h.ip)}</span>`;
    const moreNames = h.hostname_count > 1
      ? `<span class="hcard-morenames" title="${esc((h.hostnames || []).slice(0, 12).join(", "))}">+${h.hostname_count - 1} name${h.hostname_count - 1 !== 1 ? "s" : ""}</span>` : "";

    const chips = [];
    const ports = (h.ports || []).slice(0, 4).join(", ");
    if (ports) chips.push(`<span class="hmeta">${svgIcon("plug")}${esc(ports)}</span>`);
    const protoBits = [];
    const tls = (h.tls_versions || [])[0];
    if (tls) protoBits.push(tls);
    const proto = (h.protocols || [])[0];
    if (proto) protoBits.push(proto);
    if (protoBits.length) chips.push(`<span class="hmeta">${svgIcon("shield")}${esc(protoBits.join(" \u00b7 "))}</span>`);
    chips.push(`<span class="hmeta">${svgIcon("activity")}${h.flow_count} flow${h.flow_count !== 1 ? "s" : ""} \u00b7 ${fmtBytes(h.bytes)}</span>`);

    const badges = [];
    if (h.block_category) badges.push(`<span class="block-badge">\u26d4 ${esc(h.block_category)}</span>`);
    if (h.intercept_vendor) badges.push(`<span class="host-badge hb-intercept" title="${esc(h.intercept_vendor)}">local intercept</span>`);
    else if (h.proxy_ca) badges.push(`<span class="host-badge hb-proxy">TLS intercepted</span>`);
    if (h.is_private_access) badges.push(`<span class="host-badge hb-pa">Private Access</span>`);
    else if (h.is_internal) badges.push(`<span class="host-badge hb-int">internal</span>`);
    const sevPill = `<span class="sev-pill sp-${sev}">${sev === "ok" ? "OK" : esc(sev)}</span>`;

    const head = document.createElement("button");
    head.type = "button";
    head.className = "hcard-head";
    head.innerHTML = `
      <span class="hcard-caret">\u25B6</span>
      <span class="hcard-icon ic-${hostIcon(h)}">${svgIcon(hostIcon(h))}</span>
      <span class="hcard-id">
        ${hostLabel}
        <span class="hcard-chips">${chips.join("")}${moreNames}</span>
      </span>
      <span class="hcard-status">${badges.join(" ")} ${sevPill}</span>`;

    const body = document.createElement("div");
    body.className = "hcard-body hidden";
    let built = false;
    head.addEventListener("click", () => {
      if (!built) { body.innerHTML = hostDetail(h); built = true; }
      card.classList.toggle("open");
      body.classList.toggle("hidden");
    });

    card.appendChild(head);
    card.appendChild(body);
    frag.appendChild(card);
  });
  list.appendChild(frag);
}

// Human-readable "first / last seen" for a host: real clock time of day (as
// shown in the Flows table) plus how long the host was active. Falls back to a
// duration when only relative timings are present.
function seenWindow(h) {
  const clk = (c) => (c ? String(c).split(".")[0] : "");   // drop milliseconds
  const dur = (h.first_seen != null && h.last_seen != null)
    ? Math.max(0, h.last_seen - h.first_seen) : null;
  let durTxt = "";
  if (dur != null) {
    if (dur < 1) durTxt = Math.round(dur * 1000) + " ms";
    else if (dur < 60) durTxt = (Math.round(dur * 10) / 10) + " s";
    else { const t = Math.round(dur); durTxt = Math.floor(t / 60) + " m " + (t % 60) + " s"; }
  }
  const a = clk(h.first_seen_clock), b = clk(h.last_seen_clock);
  let when = "";
  if (a) when = (b && b !== a) ? `${a} \u2192 ${b}` : a;
  if (when && durTxt) return `${when} \u00b7 active ${durTxt}`;
  if (when) return when;
  return durTxt ? `active ${durTxt}` : "";
}

function hostDetail(h) {
  const kv = (label, val, hint) => val
    ? `<div class="hkv"><span class="hkv-k${hint ? " hkv-help" : ""}"${hint ? ` title="${esc(hint)}"` : ""}>${esc(label)}</span><span class="hkv-v mono">${val}</span></div>`
    : "";
  const join = (arr, sep) => (arr || []).filter(Boolean).map((x) => esc(x)).join(sep || ", ");
  const group = (title, inner) => inner && inner.trim()
    ? `<div class="hgroup"><div class="hgroup-title">${esc(title)}</div><div class="hkv-grid">${inner}</div></div>` : "";

  const identity = [
    kv("IP address", esc(h.ip), "The network address of this host (the destination your client connected to)."),
    kv("Primary host", h.primary_host ? esc(h.primary_host) : "", "The most representative name for this IP, taken from the TLS SNI, a DNS answer or the certificate."),
    kv("Clients (src)", join(h.clients), "Which device(s) on your side opened connections to this host."),
    kv("Type", h.loopback ? "loopback (local interception)"
      : h.is_private_access ? "Private Access"
      : h.is_internal ? "internal / RFC1918" : "external destination",
      "Where this host sits: an external internet destination, an internal/private (RFC1918) address, a Private Access resource, or the local loopback used by an on-device TLS interceptor."),
  ].join("");

  const ttlInfo = (!h.loopback && h.ttl != null)
    ? `${h.ttl}${h.hop_distance != null ? ` \u00b7 \u2248${h.hop_distance} hop${h.hop_distance !== 1 ? "s" : ""} away` : ""}`
    : "";
  const network = [
    kv("Ports", join(h.ports), "Destination ports your client tried to reach on this host."),
    kv("Open ports (SYN/ACK)", join(h.open_ports), "Ports this host actually answered on \u2014 it replied with a TCP SYN/ACK, so the port is confirmed reachable and open (not merely attempted)."),
    kv("Transports", join(h.transports), "Transport protocols used with this host (TCP, UDP, QUIC)."),
    kv("Protocols", join(h.protocols), "Application protocols detected on this host (HTTP, TLS, DNS, QUIC\u2026)."),
    kv("TTL / hop-limit", ttlInfo, "The IP TTL / IPv6 hop-limit seen on this host's replies, and roughly how many network hops away it is. Estimate \u2014 a proxy or middlebox can rewrite the TTL."),
    (!h.loopback && h.os_guess) ? kv("OS estimate", esc(h.os_guess),
      "A rough guess of the host's OS family from its initial TTL (64\u2248Linux/Unix/macOS, 128\u2248Windows, 255\u2248network gear). Estimate only \u2014 not hard evidence.") : "",
  ].join("");

  const crypto = [
    kv("TLS versions", join(h.tls_versions), "The TLS version(s) negotiated with this host. TLS 1.0/1.1 are outdated; 1.2/1.3 are current."),
    kv("JA3 (client)", join(h.ja3, "<br>"), "Fingerprint of your client's TLS stack. Useful to tell apart browsers, agents and interceptors."),
    kv("JA3S (server)", join(h.ja3s, "<br>"), "Fingerprint of this host's TLS stack. A change here can reveal that a proxy re-terminated the connection."),
  ].join("");

  const cert = [
    kv("Issuers", join(h.cert_issuers, "<br>"), "Who issued the certificate this host presented. A corporate/proxy CA here means the TLS session was decrypted and re-signed."),
    h.proxy_ca ? kv("Interception", "certificate re-signed by proxy/CA",
      "The certificate was re-signed by a proxy or corporate CA \u2014 evidence that TLS was decrypted (inspected) in transit.") : "",
    h.intercept_vendor ? kv("Local vendor", esc(h.intercept_vendor),
      "The on-device software that decrypted this TLS session locally (identified from its signing certificate).") : "",
    h.block_category ? kv("Blocked", esc(h.block_category),
      "This host was blocked by policy and served a block page \u2014 a policy decision, not a TLS/network failure.") : "",
  ].join("");

  const seen = seenWindow(h);
  const enc = (h.bytes_enc || h.bytes_clear)
    ? `${fmtBytes(h.bytes_enc || 0)} encrypted \u00b7 ${fmtBytes(h.bytes_clear || 0)} cleartext (${h.cleartext_pct || 0}% clear)`
    : "";
  const traffic = [
    kv("Sessions", `${h.sessions_in || 0} incoming \u00b7 ${h.sessions_out || 0} outgoing`,
      "Connections opened toward this host (incoming) vs. opened by it back to your side (outgoing)."),
    kv("Sent (host \u2192 client)", h.bytes_sent != null ? `${fmtBytes(h.bytes_sent)} \u00b7 ${h.pkts_sent || 0} pkts` : "",
      "Data this host sent down to your client (downloads, server responses)."),
    kv("Received (client \u2192 host)", h.bytes_recv != null ? `${fmtBytes(h.bytes_recv)} \u00b7 ${h.pkts_recv || 0} pkts` : "",
      "Data your client uploaded to this host (requests, uploads)."),
    kv("Encryption", enc,
      "How much of the traffic was encrypted (TLS/QUIC) vs. cleartext. A high cleartext share to an external host can mean data is exposed on the wire."),
    kv("Total", `${fmtBytes(h.bytes)} \u00b7 ${h.pkts != null ? h.pkts + " pkts \u00b7 " : ""}${h.flow_count} flow${h.flow_count !== 1 ? "s" : ""}`,
      "Total volume exchanged with this host across all its connections."),
    kv("First / last seen", seen,
      "Clock time of the first and last packet with this host, and how long it stayed active \u2014 helps you line these events up with what the user was doing. Times are UTC (same as the Flows table)."),
  ].join("");

  const names = (h.hostnames && h.hostnames.length)
    ? `<div class="hgroup"><div class="hgroup-title">Hostnames (${h.hostnames.length})</div><div class="hnames mono">${h.hostnames.map((n) => `<span>${esc(n)}</span>`).join("")}</div></div>`
    : "";

  return `<div class="host-detail">
    ${group("Identity", identity)}
    ${names}
    ${group("Network", network)}
    ${group("TLS / crypto", crypto)}
    ${group("Certificate", cert)}
    ${group("Traffic", traffic)}
  </div>`;
}

function resolvedCertBlock(rc, f) {
  if (!rc) return "";
  if (rc.error) {
    return `<div class="resolved-box">
      <div class="resolved-head">🌐 Live online lookup <span class="resolved-tag">not from capture</span></div>
      <div class="muted mono">${esc(rc.host)} — ${esc(rc.error)}</div>
    </div>`;
  }
  const tag = rc.secure_access ? "Cisco Secure Access PKI" : (rc.proxy_ca ? "proxy/corporate CA" : "public CA");
  // Does the live cert actually cover the SNI we asked about?
  const sni = (f && (f.sni || f.tunnel_sni)) || rc.host || "";
  const names = [rc.subject].concat(rc.san || []).map((s) => (s || "").toLowerCase());
  const covers = names.some((n) => n === sni.toLowerCase() || (n.startsWith("*.") && sni.toLowerCase().endsWith(n.slice(1))));
  const mismatch = sni && rc.subject && !covers
    ? `<div class="resolved-warn">⚠ The served name (<b>${esc(rc.subject)}</b>) does not match the requested host (<b>${esc(sni)}</b>) — likely a shared front-end/load-balancer default certificate, not necessarily the one used in the capture.</div>`
    : "";
  return `<div class="resolved-box">
    <div class="resolved-head">🌐 Live online lookup <span class="resolved-tag">not from capture</span></div>
    <div class="muted" style="margin:2px 0 6px">Connected to <span class="mono">${esc(rc.host)}</span> just now (from this machine) to read the certificate it currently serves. This is a live probe — it is not evidence from the capture and may differ from the certificate actually used.</div>
    ${kv("Served CN", rc.subject)}
    ${kv("Issuer", (rc.issuer || "?") + " (" + tag + ")")}
    ${kv("SAN", rc.san)}
    ${kv("Validity", rc.valid)}
    ${mismatch}
  </div>`;
}

function kv(label, value) {
  if (value == null || value === "" || (Array.isArray(value) && !value.length)) return "";
  const v = Array.isArray(value) ? value.join(", ") : value;
  return `<div class="kv"><b>${esc(label)}</b><span class="mono">${esc(v)}</span></div>`;
}

// Renders the DNS lookup (seen earlier in the same capture) that resolved to
// this flow's destination IP — the hostname the client actually requested,
// plus any CNAME chain, which resolver answered, and the lookup timing.
function dnsLookupKv(f) {
  const d = f.dns_lookup;
  if (!d || !d.name) return "";
  const ip = f.dst ? String(f.dst).split(":")[0] : "";
  let chain = esc(d.name);
  if (d.cnames && d.cnames.length) chain += " \u2192 " + d.cnames.map(esc).join(" \u2192 ");
  chain += '  \u2192  <span class="mono">' + esc(ip) + "</span>";
  const resolver = d.resolver
    ? (d.resolver_name ? esc(d.resolver_name) + " (" + esc(d.resolver) + ")" : esc(d.resolver))
    : null;
  const timing = [];
  if (d.query_time != null) timing.push("queried at t+" + Number(d.query_time).toFixed(3) + "s");
  if (d.response_time != null) timing.push("answered in " + (Number(d.response_time) * 1000).toFixed(1) + " ms");
  const blocked = d.blocked
    ? `<div class="kv"><b>DNS verdict</b><span style="color:var(--bad)">\u26d4 ${esc(d.block_category || "blocked")}</span></div>`
    : "";
  return `<div class="kv"><b>DNS lookup</b><span>${chain}</span></div>`
    + (resolver ? `<div class="kv"><b>Resolved via</b><span>${resolver}</span></div>` : "")
    + (timing.length ? `<div class="kv"><b>Lookup timing</b><span class="muted">${esc(timing.join(" \u00b7 "))}</span></div>` : "")
    + blocked;
}

function flowDetail(f) {
  const findings = (f.findings || [])
    .map(
      (x) => `<div class="fnd sev-${esc(x.severity)}">
        <span class="sev-tag sp-${esc(x.severity)}">${esc(x.severity)}</span>${esc(x.title)}
        <div class="muted" style="margin-top:3px">${esc(x.detail)}</div>
        ${(x.evidence || []).map((e) => `<div class="muted mono" style="margin-top:3px">↳ ${esc(e)}</div>`).join("")}
      </div>`
    )
    .join("");
  const alerts = (f.alerts || []).map((a) => `${a.desc} (${a.level}) @pkt ${a.packet} t=${a.time}s`).join(" · ");
  return `<div class="detail-inner">
    <div class="detail-block">
      <h4>Connection</h4>
      ${kv("Flow", f.key)}
      ${kv("Time", f.time)}
      ${kv("Packets", (f.pkt_range || "") + " (" + f.pkt_count + ")")}
      ${kv("Source", f.src)}
      ${kv("Destination", f.dst)}
      ${kv("CONNECT target", f.connect_target)}
      ${kv("Proxy", f.proxy_ip)}
      ${kv("Proxy identity", f.proxy_provider)}
      ${f.is_private_access ? kv("Access type", "Cisco Secure Access \u2014 Private Access (Zero Trust / ZTNA, CGNAT 100.64.0.0/10) \u2014 not SWG") : ""}
      ${(f.is_internal && !f.is_private_access) ? kv("Access type", "Internal (private \u2192 private) \u2014 LAN traffic, does not pass through the Secure Access SWG (SIA)") : ""}
      ${kv("Tunnel status", f.connect_status ? f.connect_status + " " + (f.connect_phrase || "") : null)}
      ${kv("Inner TLS", f.tunnel_tls_version ? f.tunnel_tls_version + (f.tunnel_server_hello ? " (handshake completed)" : " (ClientHello only)") : null)}
      ${kv("Inner SNI", f.tunnel_sni)}
      ${kv("Domain/SNI", f.sni)}
      ${kv("Protocol", f.is_quic ? "QUIC/HTTP3 (UDP/443)" : (f.is_connect_tunnel ? "HTTP CONNECT tunnel" : f.transport.toUpperCase()))}
      ${kv("Detected protocol", f.l7_protocol)}
      ${kv("DNS query", f.dns_query)}
      ${kv("Resolved host (NRB)", f.resolved_host)}
      ${kv("DNS resolver", f.dns_resolver)}
      ${dnsLookupKv(f)}
      ${kv("ALPN", f.alpn)}
      ${kv("TCP round-trip (SYN\u2192SYN/ACK)", f.tcp_handshake_ms != null ? f.tcp_handshake_ms + " ms" : null)}
      ${kv("TLS setup (ClientHello\u2192ServerHello)", f.tls_setup_ms != null ? f.tls_setup_ms + " ms" : null)}
    </div>
    <div class="detail-block">
      <h4>TLS / certificate</h4>
      ${kv("TLS status", f.tls_status)}
      ${kv("Version", f.negotiated_version)}
      ${kv("Cipher", f.cipher)}
      ${kv("Key exchange", f.key_share_group)}
      ${f.ja3 ? `<div class="kv"><b>JA3 (client)</b><span class="mono" title="Fingerprint of the client TLS stack, computed from the cleartext ClientHello — identifies the app/library even on TLS 1.3.">${esc(f.ja3)}</span></div>` : ""}
      ${f.ja3s ? `<div class="kv"><b>JA3S (server)</b><span class="mono" title="Fingerprint of the server's TLS stack from the ServerHello. Many different destinations sharing one JA3S means a single TLS terminator — evidence of proxy/SWG decryption.">${esc(f.ja3s)}</span></div>` : ""}
      ${kv("Subject", f.subject)}
      ${kv("Issuer", f.issuer)}
      ${kv("Issuer type", f.proxy_ca ? "PROXY / corporate CA" : (f.issuer ? "public/other CA" : null))}
      ${kv("Inspection", DECRYPT_LABEL[f.decryption_status] || null)}
      ${f.secure_access_chain ? kv("Secure Access chain", f.secure_access_chain.path + (f.secure_access_chain.root_seen ? "  [Root CA present in capture]" : "  [matched to known Root CA]")) : ""}
      ${kv("Validity", f.cert_valid)}
      ${kv("SAN", f.san)}
      ${f.resolved_cert ? resolvedCertBlock(f.resolved_cert, f) : ""}
      ${kv("Alerts", alerts || null)}
      ${kv("TCP RST", f.rst || null)}
      ${kv("Retransmissions", f.retransmissions || null)}
      ${kv("Lost segments", f.lost_segments || null)}
      ${kv("Out-of-order", f.out_of_order || null)}
      ${kv("Duplicate ACKs", f.dup_acks || null)}
      ${kv("Zero-window events", f.zero_window || null)}
      ${kv("Paused waiting on receiver", f.window_full ? f.window_full + " time(s) \u2014 the receiver's buffer allowance filled up; nothing was lost" : null)}
      ${kv("Encryption setup retried", f.hello_retry_request ? "yes \u2014 server refused " + ((f.hrr_offered_groups || []).join(" and ") || "the first choice") + ", client restarted with " + (f.hrr_selected_group || "another method") + " (one extra round trip)" : null)}
      ${kv("ACKed-but-unseen segments", f.ack_lost_segment || null)}
      ${f.pkts_c2s != null && (f.pkts_c2s || f.pkts_s2c) ? kv("Direction", "client\u2192server " + f.pkts_c2s + " pkts / " + (f.bytes_c2s || 0) + "B \u00b7 server\u2192client " + f.pkts_s2c + " pkts / " + (f.bytes_s2c || 0) + "B") : ""}
    </div>
    ${connectionLadder(f)}
    ${mtuBlock(f)}
    ${findings ? `<div class="detail-findings"><h4 style="color:var(--accent);text-transform:uppercase;font-size:12px">Findings</h4>${findings}</div>` : ""}
  </div>`;
}

// Explain the reduced path MTU / TCP MSS for a single flow. Shown in the flow
// detail when the client advertised a sub-1460 MSS. Honest framing: a reduced
// MSS does NOT block traffic (it is the mechanism that lets it pass), but it CAN
// cause slowness, and an unhandled MTU mismatch (black hole) causes real loss.
function mtuBlock(f) {
  const mss = f.client_mss;
  if (typeof mss !== "number" || mss <= 0 || mss >= 1460) return "";
  const mtu = mss + 40;
  const gap = 1500 - mtu;
  const retx = f.retransmissions || 0;
  const lost = f.lost_segments || 0;
  const corr = (retx || lost)
    ? `<p class="mtu-corr mtu-corr-warn"><b>On this flow:</b> ${retx ? retx + " retransmission(s)" : ""}${retx && lost ? " and " : ""}${lost ? lost + " lost segment(s)" : ""} were seen. Retransmissions have several possible causes (congestion, plain packet loss, or an MTU black hole), so they are <i>consistent with</i> a path-MTU problem but do not prove one from a single capture point. Worth checking if large transfers feel slow or stall.</p>`
    : `<p class="mtu-corr">No retransmissions or lost segments were seen on this flow — here the reduced MSS appears to be working as intended (no sign of an MTU black hole).</p>`;
  return `<div class="detail-block mtu-block">
    <h4>Path MTU / TCP MSS</h4>
    <div class="mtu-figure"><span class="mtu-num">MSS ${mss}</span><span class="mtu-arrow">\u2192</span><span class="mtu-num">MTU ~${mtu} B</span><span class="mtu-gap">${gap} B below the 1500 standard</span></div>
    <p><b>What it is:</b> the client advertised a TCP MSS of ${mss} (instead of the usual 1460) in its SYN to this destination. Since MSS = MTU \u2212 40 (RFC 879), the smallest-MTU hop on the path to this server is about ${mtu} bytes \u2014 below a standard 1500-byte Ethernet link.</p>
    <p><b>Does it block traffic?</b> No. A reduced MSS is the normal mechanism that sizes packets to fit the smallest hop so they pass <i>without</i> fragmentation. By itself it is not an error and not packet loss.</p>
    <p><b>When it CAN cause problems:</b> (1) slightly lower throughput \u2014 each packet carries less payload for the same overhead; (2) if the reduced MTU is <i>not</i> honored end-to-end (PMTUD blocked \u2014 the ICMP \u201cfragmentation needed\u201d message filtered \u2014 and no MSS clamping), large packets are silently dropped. That \u201cMTU black hole\u201d shows up as retransmissions, slow or stalled transfers, and timeouts.</p>
    ${corr}
    <p><b>Possible causes of the reduced path MTU:</b></p>
    <ul class="mtu-causes">
      <li>A tunnel that adds overhead: VPN / Cisco Secure Access / SIG, GRE, IPsec.</li>
      <li>A carrier or access link with a smaller MTU: PPPoE/DSL (~1492), MPLS, mobile 4G/5G.</li>
      <li>A router beyond the ISP with a lower interface MTU.</li>
      <li>MSS clamping applied by a middlebox/firewall on the handshake (the fallback when PMTUD is blocked).</li>
      <li>The client\u2019s own network interface MTU set below 1500.</li>
    </ul>
    <p class="muted">From a single capture point you cannot tell <i>which</i> hop or <i>which</i> mechanism is responsible \u2014 only that the path MTU to this destination is reduced. References: RFC 1191 (PMTUD), RFC 879 / 6691 (TCP MSS).</p>
  </div>`;
}

// Render the left<->right packet ladder of a single connection as a sequence
// diagram: the client owns the LEFT lifeline, the server the RIGHT one, and each
// packet is an arrow that crosses between them in its real direction (client->
// server points right, server->client points left). The arrow draws itself from
// sender to receiver, so the motion itself encodes who sent what, in order.
function connectionLadder(f) {
  const tl = f.timeline;
  if (!tl || !tl.events || !tl.events.length) return "";
  const client = esc(f.src || "client");
  const server = esc((f.is_connect_tunnel && f.connect_target) ? f.connect_target : (f.dst || "server"));
  const rows = tl.events.map((e, i) => {
    if (e.gap != null) {
      return `<div class="lad-gap" style="--i:${i}">\u22ef ${e.gap} packet(s) omitted \u22ef</div>`;
    }
    const dir = e.dir === "c2s" ? "c2s" : "s2c";
    const anom = (e.anomalies || []).length
      ? `<span class="lad-anom">${e.anomalies.map(esc).join(", ")}</span>` : "";
    return `<div class="lad-row dir-${dir}${anom ? " lad-bad" : ""}" style="--i:${i}">
      <span class="lad-t">${e.t}s</span>
      <span class="lad-wire">
        <span class="lad-dot"></span>
        <span class="lad-label kind-${esc(e.kind)}">${esc(e.label)}</span>
        ${anom}
      </span>
    </div>`;
  }).join("");
  const note = tl.omitted
    ? `${tl.total} packets \u00b7 middle ${tl.omitted} omitted`
    : `${tl.total} packet${tl.total === 1 ? "" : "s"}`;
  // Local-interception chain detail: expose the two hops of the
  // app -> local agent -> real destination chain right on the ladder.
  let chain = "";
  if (f.intercept_vendor) {
    const outbound = f.chain_outbound_key
      ? `<div class="lad-chain-hop"><span class="lad-chain-arrow">\u2193 re-encrypted &amp; sent out</span>
           <span class="lad-chain-leg">outbound leg: <code>${esc(f.chain_outbound_key)}</code></span></div>`
      : `<div class="lad-chain-hop lad-chain-missing">outbound leg not captured (agent forwarded it on a path this capture did not see)</div>`;
    chain = `<div class="lad-chain">
      <div class="lad-chain-title">Local interception chain \u00b7 <b>${esc(f.intercept_vendor)}</b></div>
      <div class="lad-chain-hop"><span class="lad-chain-badge">1</span> app \u2192 local agent on <code>127.0.0.1</code> <span class="lad-chain-leg">(this loopback leg \u2014 TLS terminated &amp; DECRYPTED here)</span></div>
      <div class="lad-chain-hop"><span class="lad-chain-badge">2</span> local agent \u2192 real destination</div>
      ${outbound}
      <div class="lad-chain-foot">Correlated by hostname + time, not cryptographic proof.</div>
    </div>`;
  } else if (f.chain_loopback_key) {
    chain = `<div class="lad-chain">
      <div class="lad-chain-title">Outbound leg of a local interception chain</div>
      <div class="lad-chain-hop">A decrypted copy of this traffic was seen on loopback first \u2014 loopback leg: <code>${esc(f.chain_loopback_key)}</code>.</div>
      <div class="lad-chain-foot">Correlated by hostname + time, not cryptographic proof.</div>
    </div>`;
  }
  return `<div class="detail-block ladder-block">
    <h4>Connection flow <span class="lad-note">(${note})</span></h4>
    ${chain}
    <div class="ladder">
      <div class="lad-head"><span class="lad-ep lad-ep-c">${client}</span><span class="lad-ep lad-ep-s">${server}</span></div>
      <div class="lad-body">${rows}</div>
    </div>
  </div>`;
}

function harDetail(h) {
  return `<div class="detail-inner">
    <div class="detail-block">
      <h4>Request</h4>
      ${kv("Time", h.time)}
      ${kv("Method", h.method)}
      ${kv("Host", h.host)}
      ${kv("URL", h.url)}
      ${kv("HTTP", h.http_version)}
      ${kv("Duration", h.duration_ms != null ? h.duration_ms + " ms" : null)}
    </div>
    <div class="detail-block">
      <h4>Result</h4>
      ${kv("Status", h.status + (h.status_text ? " " + h.status_text : ""))}
      ${kv("Server IP", h.server_ip)}
      ${kv("Error", h.error)}
      ${kv("Classified as", h.error_label)}
      ${kv("Category", h.category)}
    </div>
    ${h.block_info ? blockInfoDetail(h.block_info) : ""}
  </div>`;
}

// Render the Secure Access block-page metadata recovered from a HAR redirect.
// This is the detail that is ONLY visible in HAR (in a PCAP it is encrypted).
function blockInfoDetail(b) {
  const claims = b.claims || {};
  // Friendly labels for the Cisco Secure Access blockinfo JWT claims.
  const LABELS = {
    btype: "Block family", url: "Original request URL", ruleid: "DLP rule ID",
    org: "Organization ID", oid: "Origin ID", bid: "Build/policy ID",
    prf: "Profile ID", bpid: "Block policy ID", t: "Token / timestamp",
    bc: "Block category", ftc: "File type category", fnames: "Uploaded file name(s)",
    host: "Original host", dst: "Destination",
  };
  const ORDER = ["btype", "url", "ruleid", "fnames", "ftc", "bc", "org", "oid", "bid", "prf", "bpid", "t"];
  const keys = Object.keys(claims);
  keys.sort((a, c) => {
    const ia = ORDER.indexOf(a), ic = ORDER.indexOf(c);
    return (ia < 0 ? 99 : ia) - (ic < 0 ? 99 : ic);
  });
  const rows = keys
    .filter((k) => claims[k] !== "" && claims[k] !== null && claims[k] !== undefined)
    .map((k) => kv(LABELS[k] || k, typeof claims[k] === "object" ? JSON.stringify(claims[k]) : String(claims[k])))
    .join("");
  const origin = b.original_url || (claims.url ?? "");
  return `<div class="detail-block">
      <h4 style="color:#b3261e">\u26d4 Secure Access block page</h4>
      ${kv("Block type", b.block_type)}
      ${origin ? kv("Original request", origin) : ""}
      ${kv("Proxy server", b.server)}
      ${kv("Block URL", b.url)}
      ${rows ? `<div class="muted" style="margin-top:6px">Decoded blockinfo (JWT payload \u2014 no key needed):</div>${rows}` : ""}
    </div>`;
}

// --- table filters ---
$("only-problems").addEventListener("change", () => { flowPage = 0; renderTable(); });
$("flow-filter").addEventListener("input", () => { flowPage = 0; renderTable(); });
$("dns-only-flagged").addEventListener("change", () => {
  if (lastData && lastData.dns) renderDnsTable(lastData.dns.records);
});
$("hosts-only-problems").addEventListener("change", () => {
  if (lastData && lastData.hosts) renderHostTable(lastData.hosts);
});
$("host-filter").addEventListener("input", () => {
  if (lastData && lastData.hosts) renderHostTable(lastData.hosts);
});

// --- sidebar navigation (functional) ---
function setActiveNav(id) {
  document.querySelectorAll(".sidebar .nav-item").forEach((n) => n.classList.remove("active"));
  const el = $(id);
  if (el) el.classList.add("active");
}
function scrollToEl(id) {
  const el = $(id);
  if (el) el.scrollIntoView({ behavior: "smooth", block: "start" });
}
function resultsReady() {
  return lastData && !$("results").classList.contains("hidden");
}
// Learn guide is always available (no analysis needed)
function showLearn() {
  const sec = $("sec-learn");
  if (sec) sec.classList.remove("hidden");
  setActiveNav("nav-learn");
  scrollToEl("sec-learn");
}
function hideLearn() {
  const sec = $("sec-learn");
  if (sec) sec.classList.add("hidden");
}

$("nav-inspect").addEventListener("click", () => {
  setActiveNav("nav-inspect");
  hideLearn();
  certsOnly = false;
  flowPage = 0;
  if (resultsReady()) renderTable();
  scrollToEl("sec-evidence");
});
$("nav-flows").addEventListener("click", () => {
  if (!resultsReady()) { scrollToEl("sec-evidence"); return; }
  setActiveNav("nav-flows");
  hideLearn();
  certsOnly = false;
  flowPage = 0;
  renderTable();
  scrollToEl("sec-flows");
});
$("nav-certs").addEventListener("click", () => {
  if (!resultsReady()) { scrollToEl("sec-evidence"); return; }
  setActiveNav("nav-certs");
  hideLearn();
  certsOnly = true;
  flowPage = 0;
  renderTable();
  scrollToEl("sec-flows");
});
$("nav-hosts").addEventListener("click", () => {
  if (!resultsReady()) { scrollToEl("sec-evidence"); return; }
  setActiveNav("nav-hosts");
  hideLearn();
  scrollToEl("sec-hosts");
});
$("nav-dns").addEventListener("click", () => {
  if (!resultsReady()) { scrollToEl("sec-evidence"); return; }
  setActiveNav("nav-dns");
  hideLearn();
  scrollToEl("sec-dns");
});
$("nav-report").addEventListener("click", () => {
  if (!resultsReady()) { scrollToEl("sec-evidence"); return; }
  setActiveNav("nav-report");
  hideLearn();
  scrollToEl("sec-report");
});
$("nav-learn").addEventListener("click", showLearn);
$("learn-cta").addEventListener("click", showLearn);

// --- help popover ---
$("help-btn").addEventListener("click", (e) => {
  e.stopPropagation();
  $("help-pop").classList.toggle("hidden");
});
document.addEventListener("click", (e) => {
  const pop = $("help-pop");
  if (!pop.classList.contains("hidden") && !pop.contains(e.target) && e.target !== $("help-btn")) {
    pop.classList.add("hidden");
  }
});

// --- TLS key log how-to modal ---
(function wireKeylogHelp() {
  const overlay = $("keylog-help");
  if (!overlay) return;
  const open = () => overlay.classList.remove("hidden");
  const close = () => overlay.classList.add("hidden");
  $("keylog-help-btn").addEventListener("click", open);
  $("kh-close").addEventListener("click", close);
  overlay.addEventListener("click", (e) => { if (e.target === overlay) close(); });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") close(); });
  overlay.querySelectorAll(".kh-tab").forEach((tab) => {
    tab.addEventListener("click", () => {
      const os = tab.dataset.os;
      overlay.querySelectorAll(".kh-tab").forEach((t) => t.classList.toggle("active", t === tab));
      overlay.querySelectorAll(".kh-panel").forEach((p) => p.classList.toggle("hidden", p.dataset.os !== os));
    });
  });
})();

// --- download ---
$("download").addEventListener("click", () => {
  const blob = new Blob([lastReport], { type: "text/plain" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "tls-inspector-report.txt";
  a.click();
  URL.revokeObjectURL(url);
});
