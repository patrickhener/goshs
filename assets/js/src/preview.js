// ══ FILE PREVIEW ══
import { ST, esc, fmtBytes } from './state.js';
import { openModal } from './modals.js';
import { toast } from './modals.js';

export const PREVIEWABLE = {
  md: "markdown",
  jpg: "image", jpeg: "image", png: "image", gif: "image",
  svg: "image", webp: "image", bmp: "image", ico: "image",
  mp4: "video", webm: "video",
  mp3: "audio", wav: "audio", ogg: "audio",
  pdf: "pdf",
  csv: "csv",
  txt: "text", json: "text", xml: "text", yaml: "text", yml: "text",
  go: "text", py: "text", js: "text", sh: "text", log: "text",
  css: "text", html: "text", rb: "text", java: "text", c: "text",
  cpp: "text", h: "text", rs: "text", toml: "text", ini: "text",
  cfg: "text", conf: "text", env: "text", ts: "text", sql: "text",
  bat: "text", ps1: "text", php: "text", pl: "text", swift: "text",
  kt: "text", dart: "text", lua: "text", r: "text", tex: "text",
  scss: "text", sass: "text", less: "text",
};

export function getPreviewType(name) {
  const ext = name.split(".").pop().toLowerCase();
  return PREVIEWABLE[ext] || null;
}

export function previewFile(name) {
  const type = getPreviewType(name);
  if (!type) return;
  const container = document.getElementById("md-content");
  const title = document.getElementById("md-title");
  container.innerHTML = "";
  title.textContent = name;

  switch (type) {
    case "image":
      var img = document.createElement("img");
      img.src = name;
      img.style.maxWidth = "100%";
      img.style.borderRadius = "4px";
      container.appendChild(img);
      openModal("md-modal");
      break;
    case "video":
      var vid = document.createElement("video");
      vid.src = name;
      vid.controls = true;
      vid.style.maxWidth = "100%";
      vid.style.borderRadius = "4px";
      container.appendChild(vid);
      openModal("md-modal");
      break;
    case "audio":
      var aud = document.createElement("audio");
      aud.src = name;
      aud.controls = true;
      aud.style.width = "100%";
      container.appendChild(aud);
      openModal("md-modal");
      break;
    case "pdf":
      var iframe = document.createElement("iframe");
      iframe.src = name;
      iframe.style.width = "100%";
      iframe.style.height = "80vh";
      iframe.style.border = "none";
      iframe.style.borderRadius = "4px";
      container.appendChild(iframe);
      openModal("md-modal");
      break;
    case "markdown":
      fetch(name)
        .then((r) => { if (!r.ok) throw new Error(r.statusText); return r.text(); })
        .then((text) => {
          container.innerHTML = DOMPurify.sanitize(marked.parse(text));
          openModal("md-modal");
        })
        .catch(() => toast("Failed to load preview", "error"));
      break;
    case "csv":
      fetch(name)
        .then((r) => { if (!r.ok) throw new Error(r.statusText); return r.text(); })
        .then((text) => {
          var rows = text.trim().split("\n");
          var table = document.createElement("table");
          table.className = "preview-csv";
          rows.forEach(function (row, i) {
            var tr = document.createElement("tr");
            row.split(",").forEach(function (cell) {
              var el = document.createElement(i === 0 ? "th" : "td");
              el.textContent = cell.replace(/^"|"$/g, "");
              tr.appendChild(el);
            });
            table.appendChild(tr);
          });
          container.appendChild(table);
          openModal("md-modal");
        })
        .catch(() => toast("Failed to load preview", "error"));
      break;
    case "text":
      fetch(name)
        .then((r) => { if (!r.ok) throw new Error(r.statusText); return r.text(); })
        .then((text) => {
          var ext = name.split(".").pop().toLowerCase();
          var code = document.createElement("code");
          code.className = "language-" + ext;
          code.textContent = text;
          var pre = document.createElement("pre");
          pre.className = "preview-code";
          pre.appendChild(code);
          container.appendChild(pre);
          hljs.highlightElement(code);
          openModal("md-modal");
        })
        .catch(() => toast("Failed to load preview", "error"));
      break;
  }
}

export function initPreview() {
  const tbody = document.getElementById("file-tbody");
  if (tbody) {
    tbody.addEventListener("click", (e) => {
      if (e.ctrlKey || e.metaKey || e.button !== 0) return;
      const a = e.target.closest('a[href]');
      if (!a || a.hasAttribute("download")) return;
      const href = a.getAttribute("href") || "";
      if (getPreviewType(href)) {
        e.preventDefault();
        previewFile(href);
      }
    });
  }
}
