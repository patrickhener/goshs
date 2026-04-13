![Version](https://img.shields.io/badge/Version-v2.0.0-beta.6-green)
[![GitHub](https://img.shields.io/github/license/patrickhener/goshs)](https://github.com/patrickhener/goshs/blob/master/LICENSE)
![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/patrickhener/goshs)
[![GitHub issues](https://img.shields.io/github/issues-raw/patrickhener/goshs)](https://github.com/patrickhener/goshs/issues)
![goreleaser](https://github.com/patrickhener/goshs/workflows/goreleaser/badge.svg)
[![Go Report Card](https://goreportcard.com/badge/github.com/patrickhener/goshs)](https://goreportcard.com/report/github.com/patrickhener/goshs)
[![GitHub stars](https://img.shields.io/github/stars/patrickhener/goshs?style=social)](https://github.com/patrickhener/goshs/stargazers)

<img src="https://github.com/patrickhener/image-cdn/blob/main/goshs-banner-light.png?raw=true" alt="goshs-logo" height="100">

goshs is a replacement for Python's `SimpleHTTPServer`. It is a feature-rich file server supporting HTTP/S, WebDAV, SFTP, and SMB — with built-in authentication, share links, webhooks, and collaboration features for penetration testing and CTF challenges.

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

## Release
You can download the executable from the [release section](https://github.com/patrickhener/goshs/releases)

## Go

```bash
go install github.com/patrickhener/goshs@latest
```

## Build yourself

Building requirements are [uglify-js](https://www.npmjs.com/package/uglify-js) and [sass](https://sass-lang.com/install). After installing these packages you can easily just:

```bash
git clone https://github.com/patrickhener/goshs.git
cd goshs
make build-all
```

## Kali repositories

When using Kali you can easily just install it via CLI, if it is not already installed:

```
sudo apt install goshs
```

## Windows scoop package

If you are using the [scoop package manager](https://scoop.sh/) under Windows, you can install goshs this way:

```
scoop bucket add extras
scoop install extras/goshs
```

## macOS homebrew

```
brew install goshs
```

## Run with docker

```
docker run --rm -it -p 8000:8000 -v "$PWD:/pwd" patrickhener/goshs:latest -d /pwd
```

# Code Contributors

These are the awesome code contributors of `goshs`:

[![](https://github.com/aWZHY0yQH81uOYvH.png?size=50)](https://github.com/aWZHY0yQH81uOYvH)
[![](https://github.com/Hazegard.png?size=50)](https://github.com/Hazegard)
[![](https://github.com/closehandle.png?size=50)](https://github.com/closehandle)
[![](https://github.com/abgordon.png?size=50)](https://github.com/abgordon)

- [parzel](https://github.com/parzel)
- [ty3gx](https://github.com/ty3gx)

# Security issues shout out

These are the awesome contributors that made `goshs` even more secure :heart:

[![](https://github.com/marduc812.png?size=50)](https://github.com/marduc812)
[![](https://github.com/autobot23920.png?size=50)](https://github.com/autobot23920)
[![](https://github.com/R1ZZG0D.png?size=50)](https://github.com/R1ZZG0D)
[![](https://github.com/jaisurya-me.png?size=50)](https://github.com/jaisurya-me)

- [Guilhem7](https://github.com/Guilhem7)

# Community

Join the Discord Community and start connecting.

[![Join Discord](https://invidget.switchblade.xyz/3ZnskY8HcJ)](https://discord.gg/3ZnskY8HcJ)

# Star History

[![Star History Chart](https://api.star-history.com/svg?repos=patrickhener/goshs&type=date&legend=top-left)](https://www.star-history.com/#patrickhener/goshs&type=date&legend=top-left)

# Credits

A special thank you goes to *sc0tfree* for inspiring this project with his project [updog](https://github.com/sc0tfree/updog) written in Python.
