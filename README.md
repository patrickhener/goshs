![Version](https://img.shields.io/badge/Version-v0.1.8-green)
[![GitHub](https://img.shields.io/github/license/patrickhener/goshs)](https://github.com/patrickhener/goshs/blob/master/LICENSE)
![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/patrickhener/goshs)
[![GitHub issues](https://img.shields.io/github/issues-raw/patrickhener/goshs)](https://github.com/patrickhener/goshs/issues)
![goreleaser](https://github.com/patrickhener/goshs/workflows/goreleaser/badge.svg)
[![Go Report Card](https://goreportcard.com/badge/github.com/patrickhener/goshs)](https://goreportcard.com/report/github.com/patrickhener/goshs)

<img src="https://github.com/patrickhener/image-cdn/blob/main/goshs-logo-github.png" alt="goshs-logo" width="85">

goshs is a replacement for Python's `SimpleHTTPServer`. It allows uploading and downloading via HTTP/S with either self-signed certificate or user provided certificate and you can use HTTP basic auth.

<kbd><img src="https://github.com/patrickhener/image-cdn/blob/main/goshs-screenshot.png" alt="goshs-screenshot"></kbd>

# Features
* Download or view files
  * Bulk download as .zip file
* Upload files (Drag & Drop)
* Basic Authentication
* Transport Layer Security (HTTPS)
  * self-signed
  * provide own certificate
* Non persistent clipboard
  * Download clipboard entries as .json file
* WebDAV support
* Read-Only and Upload-Only mode

# Installation

## Release
You can download the executable from the [release section](https://github.com/patrickhener/goshs/releases)

## Go

```bash
go get -u github.com/patrickhener/goshs
go install github.com/patrickhener/goshs
```

## Build yourself

```bash
git clone https://github.com/patrickhener/goshs.git
cd goshs
make build
```

# Usage

```bash
goshs v0.1.5
Usage: ./goshs [options]

Web server options:
  -i,  --ip           The ip/if-name to listen on             (default: 0.0.0.0)
  -p,  --port         The port to listen on                   (default: 8000)
  -d,  --dir          The web root directory                  (default: current working path)
  -w,  --webdav       Also serve using webdav protocol        (default: false)
  -wp, --webdav-port  The port to listen on for webdav        (default: 8001)
  -ro, --read-only    Read only mode, no upload possible      (default: false)
  -uo, --upload-only  Upload only mode, no download possible  (default: false)

TLS options:
  -s,  --ssl          Use TLS
  -ss, --self-signed  Use a self-signed certificate
  -sk, --server-key   Path to server key
  -sc, --server-cert  Path to server certificate

Authentication options:
  -b, --basic-auth    Use basic authentication (user:pass)

Misc options:
  -v  Print the current goshs version

Usage examples:
  Start with default values:    ./goshs
  Start with wevdav support:    ./goshs -w
  Start with different port:    ./goshs -p 8080
  Start with self-signed cert:  ./goshs -s -ss
  Start with custom cert:       ./goshs -s -sk <path to key> -sc <path to cert>
  Start with basic auth:        ./goshs -b secret-user:$up3r$3cur3
```

# Examples

**Serve from your current directory**

`goshs`

**Serve from your current directory with webdav enabled on custom port**

`goshs -w -wp 8081`

**Serve from another directory**

`goshs -d /path/to/directory`

**Serve from port 1337**

`goshs -p 1337`

**Password protect the service**

`goshs -b secret-user:VeryS3cureP4$$w0rd`

*Please note:* goshs uses HTTP basic authentication. It is recommended to use SSL option with basic authentication to prevent from credentials beeing transfered in cleartext over the line.

**Use TLS connection**

*Self-Signed*

`goshs -s -ss`

*Provide own certificate*

`goshs -s -sk server.key -sc server.crt`

# Credits

A special thank you goes to *sc0tfree* for inspiring this project with his project [updog](https://github.com/sc0tfree/updog) written in Python.

# Tutorial Series

I wrote several blog posts how and why I implemented all of this. You can find it [here](https://hesec.de/tags/goshs/) if you are interested about the technical background.
