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
  const total = ST.httpCnt + ST.dnsEvents.length + ST.smtpEvents.length + ST.smbEvents.length + ST.ldapEvents.length;
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
