// ══ THEME ══
import { ST } from './state.js';
import { toast } from './modals.js';

export function initTheme() {
  applyTheme(ST.theme);
}

export function toggleTheme() {
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
export function filterEmbedded() {
  const q = document.getElementById("emb-search").value.toLowerCase();
  document.querySelectorAll("#emb-tbody tr[data-name]").forEach((tr) => {
    const name = (tr.dataset.name || "").toLowerCase();
    tr.style.display = !q || name.includes(q) ? "" : "none";
  });
}

const embSortDir = { name: true, size: true, mtime: true };
export function sortEmbedded(col) {
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

export function copyEmbLink(name) {
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
export function switchPanel(name, el) {
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
export function switchCollab(name, el) {
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
