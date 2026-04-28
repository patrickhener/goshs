// ══ MODALS AND TOASTS ══
import { esc } from './state.js';

// We need closeCtx from context-menu for Escape key - use a late-binding approach
let _closeCtx = () => {};
export function registerCloseCtx(fn) { _closeCtx = fn; }

export function openModal(id) {
  document.getElementById(id).classList.add("open");
}

export function closeModal(id) {
  document.getElementById(id).classList.remove("open");
  if (id === "share-modal") {
    location.reload();
  }
}

export function toast(msg, type = "success") {
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

// Global event listeners for modals
document.addEventListener("click", (e) => {
  if (e.target.classList.contains("modal-backdrop")) closeModal(e.target.id);
});
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") {
    document
      .querySelectorAll(".modal-backdrop.open")
      .forEach((m) => m.classList.remove("open"));
    _closeCtx();
  }
});
