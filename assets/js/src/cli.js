// ══ CLI ══
import { ST } from './state.js';

const cliHistory = [];
let cliHistIdx = -1;

export function initCliHistory() {
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
export function cliOutput(msg) {
  if (msg.content) {
    appendCLI(msg.content, "");
  } else {
    appendCLI("something went wrong", "err");
  }
}
