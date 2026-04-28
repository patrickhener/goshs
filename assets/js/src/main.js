// ══ ENTRY POINT ══
import './globals.js';
import { ST } from './state.js';
import { initTheme } from './theme.js';
import { connectWS, registerWSHandlers } from './ws.js';
import { initCollab } from './collab.js';
import { initFiles } from './files.js';
import { initClipboard } from './clipboard.js';
import { initCliHistory } from './cli.js';
import { initCatcher } from './catcher.js';
import { initContextMenu } from './context-menu.js';
import { initSharedLinks } from './share.js';
import { initPreview } from './preview.js';

document.addEventListener("DOMContentLoaded", () => {
  const activeTab = sessionStorage.getItem("activeTab");
  if (activeTab) {
    sessionStorage.removeItem("activeTab");
    const btn = document.getElementById(activeTab);
    if (btn) btn.click();
  }
  initTheme();
  initPreview();
  initFiles();
  initClipboard();
  initCliHistory();
  initContextMenu();
  initSharedLinks();
  initCatcher();

  // Register WS handlers before connecting
  const collabHandlers = initCollab();
  registerWSHandlers(collabHandlers);
  connectWS();
});
