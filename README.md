![Version](https://img.shields.io/badge/Version-v0.0.5-green) [![GitHub](https://img.shields.io/github/license/patrickhener/goshs)](https://github.com/patrickhener/goshs/blob/master/LICENSE) ![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/patrickhener/goshs) [![GitHub issues](https://img.shields.io/github/issues-raw/patrickhener/goshs)](https://github.com/patrickhener/goshs/issues) ![goreleaser](https://github.com/patrickhener/goshs/workflows/goreleaser/badge.svg)

<img src="https://github.com/patrickhener/image-cdn/blob/main/goshs-logo-github.png" alt="goshs-logo" width="85">

goshs is a replacement for Python's `SimpleHTTPServer`. It allows uploading and downloading via HTTP/S with either self-signed certificate or user provided certificate and you can use HTTP basic auth.

> <kbd><img src="https://github.com/patrickhener/image-cdn/blob/main/goshs-screenshot.png" alt="goshs-screenshot"></kbd>

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
Usage: goshs [options]

Web server options:
	-i	The ip to listen on	(default: 0.0.0.0)
	-p	The port to listen on	(default: 8000)
	-d	The web root directory	(default: current working path)

TLS options:
	-s	Use TLS
	-ss	Use a self-signed certificate
	-sk	Path to server key
	-sc	Path to server certificate

Authentication options:
	-P	Use basic authentication password (user: gopher)

Misc options:
	-v	Print the current goshs version
```

# Examples

**Serve from your current directory**

`goshs`

**Serve from another directory**

`goshs -d /path/to/directory`

**Serve from port 1337**

`goshs -p 1337`

**Password protect the service**

`goshs -P VeryS3cureP4$$w0rd`

*Please note:* goshs uses HTTP basic authentication. It is recommended to use SSL option with basic authentication to prevent from credentials beeing transfered in cleartext over the line. User is `gopher`.

**Use TLS connection**

*Self-Signed*

`goshs -s -ss`

*Provide own certificate*

`goshs -s -sk server.key -sc server.crt`

# Credits

A special thank you goes to *sc0tfree* for inspiring this project with his project [updog](https://github.com/sc0tfree/updog) written in Python.

# Tutorial Series

I wrote several blog posts how and why I implemented all of this. You can find it [here](https://hesec.de/tags/goshs/) if you are interested about the technical background.
