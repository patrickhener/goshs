![Version](https://img.shields.io/badge/Version-v2.0.1-green)
[![GitHub](https://img.shields.io/github/license/patrickhener/goshs)](https://github.com/patrickhener/goshs/blob/master/LICENSE)
![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/patrickhener/goshs)
[![GitHub issues](https://img.shields.io/github/issues-raw/patrickhener/goshs)](https://github.com/patrickhener/goshs/issues)
![goreleaser](https://github.com/patrickhener/goshs/workflows/goreleaser/badge.svg)
[![Go Report Card](https://goreportcard.com/badge/github.com/patrickhener/goshs)](https://goreportcard.com/report/github.com/patrickhener/goshs)
[![codecov](https://codecov.io/gh/patrickhener/goshs/branch/main/graph/badge.svg)](https://codecov.io/gh/patrickhener/goshs)
[![GitHub stars](https://img.shields.io/github/stars/patrickhener/goshs?style=social)](https://github.com/patrickhener/goshs/stargazers)

<img src="https://github.com/patrickhener/image-cdn/blob/main/goshs-banner-light.png?raw=true" alt="goshs-logo" height="100">

You're mid-engagement. You need to transfer a file, catch an SMB hash, or stand up a quick HTTPS server — and `python3 -m http.server` won't cut it.

**goshs** is a single-binary file server built for the moments when you need more than Python's SimpleHTTPServer but don't want to configure Apache. HTTP/S, WebDAV, SFTP, SMB, basic auth, share links, DNS/SMTP callbacks, NTLM hash capture + cracking — all from one command.

![intro](https://github.com/patrickhener/image-cdn/blob/main/goshs.gif?raw=true)

<kbd><img src="https://github.com/patrickhener/image-cdn/blob/main/goshs-screenshot-v2.png?raw=true" alt="goshs-screenshot-light"></kbd>
<kbd><img src="https://github.com/patrickhener/image-cdn/blob/main/goshs-screenshot-v2-dark.png?raw=true" alt="goshs-screenshot-dark"></kbd>

# Quick Start

```bash
# Serve the current directory on port 8000
goshs

# Serve with HTTPS (self-signed) and basic auth
goshs -s -ss -b user:password

# Capture SMB hashes
goshs -smb -smb-domain CORP

# Catch DNS callbacks and receive emails
goshs -dns -dns-ip 1.2.3.4 -smtp -smtp-domain your-domain.com
```

# Documentation

For a detailed documentation go to [goshs.de](https://goshs.de)

# Features

| | |
|---|---|
| 📁 **File Operations** | Download, upload (drag & drop, POST/PUT), delete, bulk ZIP, QR codes |
| 🔌 **Protocols** | HTTP/S, WebDAV, SFTP, SMB |
| 🔒 **Auth & Security** | Basic auth, certificate auth, TLS (self-signed, Let's Encrypt, custom cert), IP whitelist, file-based ACLs |
| ⚙️ **Server Modes** | Read-only, upload-only, no-delete, silent, invisible, CLI command execution |
| 🔗 **Share Links** | Token-based sharing, download limit, time limit |
| 🎯 **Collaboration / CTF** | DNS server, SMTP server, SMB NTLM hash capture + cracking, redirect endpoint |
| 🔔 **Integration** | Webhooks, tunnel via localhost.run, config file, JSON API, mDNS |
| 🛠️ **Misc** | Dark/light themes, clipboard, self-update, log output, embed files, drop privileges |

# Installation

| Method | |
|---|---|
| 🦫 **Go** | `go install goshs.de/goshs/v2@latest` |
| 🐉 **Kali** | `sudo apt install goshs` |
| 🍺 **Homebrew** | `brew install goshs` |
| 🪟 **Scoop** | `scoop bucket add extras && scoop install extras/goshs` |
| 🐳 **Docker** | `docker run --rm -it -p 8000:8000 -v "$PWD:/pwd" patrickhener/goshs:latest -d /pwd` |
| 📦 **Release** | [Download from GitHub Releases](https://github.com/patrickhener/goshs/releases) |

<details>
<summary>🔧 Build yourself</summary>

Building requirements are [uglify-js](https://www.npmjs.com/package/uglify-js) and [sass](https://sass-lang.com/install). After installing these packages run:

```bash
git clone https://github.com/patrickhener/goshs.git
cd goshs
make build-all
```

</details>

# Code Contributors

[![Contributors](https://contrib.rocks/image?repo=patrickhener/goshs)](https://github.com/patrickhener/goshs/graphs/contributors)

# Security Contributors

These are the awesome contributors that made `goshs` even more secure :heart:

<table><tr>
  <td align="center"><a href="https://github.com/marduc812"><img src="https://github.com/marduc812.png?size=50" width="50" height="50"></a></td>
  <td align="center"><a href="https://github.com/autobot23920"><img src="https://github.com/autobot23920.png?size=50" width="50" height="50"></a></td>
  <td align="center"><a href="https://github.com/R1ZZG0D"><img src="https://github.com/R1ZZG0D.png?size=50" width="50" height="50"></a></td>
  <td align="center"><a href="https://github.com/jaisurya-me"><img src="https://github.com/jaisurya-me.png?size=50" width="50" height="50"></a></td>
  <td align="center"><a href="https://github.com/Guilhem7">Guilhem7</a></td>
</tr></table>

# Community

Join the Discord Community and start connecting.

[![Join Discord](https://invidget.switchblade.xyz/3ZnskY8HcJ)](https://discord.gg/3ZnskY8HcJ)

# Star History

[![Star History Chart](https://api.star-history.com/svg?repos=patrickhener/goshs&type=date&legend=top-left)](https://www.star-history.com/#patrickhener/goshs&type=date&legend=top-left)

# Credits

A special thank you goes to *sc0tfree* for inspiring this project with his project [updog](https://github.com/sc0tfree/updog) written in Python.
