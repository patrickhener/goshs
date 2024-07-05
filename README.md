![Version](https://img.shields.io/badge/Version-v0.3.9-green)
[![GitHub](https://img.shields.io/github/license/patrickhener/goshs)](https://github.com/patrickhener/goshs/blob/master/LICENSE)
![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/patrickhener/goshs)
[![GitHub issues](https://img.shields.io/github/issues-raw/patrickhener/goshs)](https://github.com/patrickhener/goshs/issues)
![goreleaser](https://github.com/patrickhener/goshs/workflows/goreleaser/badge.svg)
[![Go Report Card](https://goreportcard.com/badge/github.com/patrickhener/goshs)](https://goreportcard.com/report/github.com/patrickhener/goshs)

<img src="https://github.com/patrickhener/image-cdn/blob/main/goshs-banner-light.png" alt="goshs-logo" height="100">

goshs is a replacement for Python's `SimpleHTTPServer`. It allows uploading and downloading via HTTP/S with either self-signed certificate or user provided certificate and you can use HTTP basic auth.

![intro](https://github.com/patrickhener/image-cdn/blob/main/goshs.gif)

<kbd><img src="https://github.com/patrickhener/image-cdn/blob/main/goshs-screenshot.png" alt="goshs-screenshot-light"></kbd>
<kbd><img src="https://github.com/patrickhener/image-cdn/blob/main/goshs-screenshot-dark.png" alt="goshs-screenshot-dark"></kbd>


# Documentation

For a detailed documentation go to [goshs.de](https://goshs.de)

# Features
* Download or view files
  * Bulk download as .zip file
* Upload files (Drag & Drop)
* Delete files
  * Individually
  * Bulk delete
* Basic Authentication
* Transport Layer Security (HTTPS)
  * self-signed
  * let's encrypt
  * provide own certificate
* Non persistent clipboard
  * Download clipboard entries as .json file
* WebDAV support
* Read-Only and Upload-Only mode
* Silent mode (no webserver output)
* Retrieve json on cli
* Drop user privileges before execution (Unix only)
  * Example: Run on port 80, but process is "www-data"
* Themes
  * Dark Mode
  * Light Mode
* Command Line
  * Run Commands on the system hosting `goshs`
* File Based ACLs
  * You can place a `.goshs` in any folder to apply custom ACLs
  * You can apply custom basic auth per folder
  * You can restrict access to specific files completely
* Embed files on compile time

# Installation

## Release
You can download the executable from the [release section](https://github.com/patrickhener/goshs/releases)

## Go

```bash
go get -u github.com/patrickhener/goshs
go install github.com/patrickhener/goshs@latest
```

## Build yourself

Building requirements are [ugilfy-js](https://www.npmjs.com/package/uglify-js) and [sass](https://sass-lang.com/install). After installing this packages you can easily just:

```bash
git clone https://github.com/patrickhener/goshs.git
cd goshs
make build-all
```



# Credits

A special thank you goes to *sc0tfree* for inspiring this project with his project [updog](https://github.com/sc0tfree/updog) written in Python.
