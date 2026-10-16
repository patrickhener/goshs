// ══ SHARED STATE AND HELPERS ══

export const ST = {
  sortCol: "name",
  sortAsc: true,
  dnsEvents: [],
  smtpEvents: [],
  smbEvents: [],
  ldapEvents: [],
  httpEvents: [],
  dnsCnt: { total: 0, A: 0, MX: 0, TXT: 0, other: 0 },
  httpCnt: 0,
  pendingUploads: [],
  shareTarget: "",
  ws: null,
  theme: localStorage.getItem("goshs-theme") || "dark",
};

export function esc(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

export function updateCollabBadge() {
  const badge = document.getElementById("collab-badge");
  const total =
    ST.httpCnt +
    ST.dnsEvents.length +
    ST.smtpEvents.length +
    ST.smbEvents.length +
    ST.ldapEvents.length;
  badge.textContent = total;
  if (total > 0) badge.classList.add("show");
  else badge.classList.remove("show");
}

export function updateBadge(id, count) {
  document.getElementById(id).textContent = count;
}

export function downloadJSON(data, filename) {
  const blob = new Blob([JSON.stringify(data, null, 2)], {
    type: "application/json",
  });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

export function fmtBytes(b) {
  if (b < 1024) return b + " B";
  if (b < 1048576) return (b / 1024).toFixed(1) + " KB";
  if (b < 1073741824) return (b / 1048576).toFixed(1) + " MB";
  return (b / 1073741824).toFixed(2) + " GB";
}

// Copy text to the clipboard, working in non-secure contexts too.
// navigator.clipboard is only exposed over HTTPS or on localhost; over plain
// HTTP to a remote host (the common case for goshs) it is undefined, so fall
// back to a hidden textarea + execCommand("copy"). Returns a Promise.
export function copyText(text) {
  if (navigator.clipboard && window.isSecureContext) {
    return navigator.clipboard.writeText(text);
  }
  return new Promise(function (resolve, reject) {
    try {
      var ta = document.createElement("textarea");
      ta.value = text;
      ta.setAttribute("readonly", "");
      ta.style.position = "fixed";
      ta.style.top = "0";
      ta.style.left = "0";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.focus();
      ta.select();
      var ok = document.execCommand("copy");
      document.body.removeChild(ta);
      ok ? resolve() : reject(new Error("execCommand copy failed"));
    } catch (e) {
      reject(e);
    }
  });
}

export function tickTTL() {
  var meta = document.querySelector('meta[name="ttl-deadline"]');
  var deadline = meta ? parseInt(meta.content, 10) : 0;
  var label = document.getElementById("ttl-remaining");
  var box = document.getElementById("ttl-indicator");
  if (!deadline || !label || !box) return;
  function fmt(sec) {
    if (sec < 0) sec = 0;
    var d = Math.floor(sec / 86400);
    var h = Math.floor((sec % 86400) / 3600);
    var m = Math.floor((sec % 3600) / 60);
    var s = sec % 60;
    var p = function (n) {
      return (n < 10 ? "0" : "") + n;
    };
    if (d > 0) return d + "d " + p(h) + ":" + p(m) + ":" + p(s);
    if (h > 0) return p(h) + ":" + p(m) + ":" + p(s);
    return p(m) + ":" + p(s);
  }
  function tick() {
    var remaining = Math.round((deadline - Date.now()) / 1000);
    label.textContent = fmt(remaining);
    // Warn visually under a minute left.
    box.classList.toggle("ttl-expiring", remaining <= 60);
    if (remaining <= 0) {
      label.textContent = "00:00";
      clearInterval(timer);
    }
  }
  tick();
  var timer = setInterval(tick, 1000);
}
