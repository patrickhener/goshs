![Version](https://img.shields.io/badge/Version-v0.3.9-green)
[![GitHub](https://img.shields.io/github/license/patrickhener/goshs)](https://github.com/patrickhener/goshs/blob/master/LICENSE)
![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/patrickhener/goshs)
[![GitHub issues](https://img.shields.io/github/issues-raw/patrickhener/goshs)](https://github.com/patrickhener/goshs/issues)
![goreleaser](https://github.com/patrickhener/goshs/workflows/goreleaser/badge.svg)
[![Go Report Card](https://goreportcard.com/badge/github.com/patrickhener/goshs)](https://goreportcard.com/report/github.com/patrickhener/goshs)

<img src="https://github.com/patrickhener/image-cdn/blob/main/goshs-logo-github.png" alt="goshs-logo" width="85">

goshs is a replacement for Python's `SimpleHTTPServer`. It allows uploading and downloading via HTTP/S with either self-signed certificate or user provided certificate and you can use HTTP basic auth.

<kbd><img src="https://github.com/patrickhener/image-cdn/blob/main/goshs-screenshot.png" alt="goshs-screenshot-light"></kbd>
<kbd><img src="https://github.com/patrickhener/image-cdn/blob/main/goshs-screenshot-dark.png" alt="goshs-screenshot-dark"></kbd>

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

# Usage

```bash
> goshs -h

goshs v0.3.4
Usage: goshs [options]

Web server options:
  -i,  --ip           The ip/if-name to listen on             (default: 0.0.0.0)
  -p,  --port         The port to listen on                   (default: 8000)
  -d,  --dir          The web root directory                  (default: current working path)
  -w,  --webdav       Also serve using webdav protocol        (default: false)
  -wp, --webdav-port  The port to listen on for webdav        (default: 8001)
  -ro, --read-only    Read only mode, no upload possible      (default: false)
  -uo, --upload-only  Upload only mode, no download possible  (default: false)
  -si, --silent       Running without dir listing             (default: false)
  -c,  --cli          Enable cli (only with auth and tls)     (default: false)
  -e,  --embedded     Show embedded files in UI               (default: false)

TLS options:
  -s,  --ssl           Use TLS
  -ss, --self-signed   Use a self-signed certificate
  -sk, --server-key    Path to server key
  -sc, --server-cert   Path to server certificate
  -sl,  --lets-encrypt Use Let's Encrypt as certification service
  -sld, --le-domains   Domain(s) to request from Let's Encrypt		(comma separated list)
  -sle, --le-email     Email to use with Let's Encrypt
  -slh, --le-http      Port to use for Let's Encrypt HTTP Challenge	(default: 80)
  -slt, --le-tls       Port to use for Let's Encrypt TLS ALPN Challenge (default: 443)


Authentication options:
  -b, --basic-auth    Use basic authentication (user:pass - user can be empty)
  -H, --hash          Hash a password for file based ACLs

Misc options:
  -u  --user          Drop privs to user (unix only)          (default: current user)
  -V  --verbose       Activate verbose log output             (default: false)
  -v                  Print the current goshs version

Usage examples:
  Start with default values:    	./goshs
  Start with wevdav support:    	./goshs -w
  Start with different port:    	./goshs -p 8080
  Start with self-signed cert:  	./goshs -s -ss
  Start with let's encrypt:		./goshs -s -sl -sle your@mail.com -sld your.domain.com,your.seconddomain.com
  Start with custom cert:       	./goshs -s -sk <path to key> -sc <path to cert>
  Start with basic auth:        	./goshs -b secret-user:$up3r$3cur3
  Start with basic auth empty user:	./goshs -b :$up3r$3cur3
  Start with cli enabled:               ./goshs -b secret-user:$up3r$3cur3 -s -ss -c
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

*Let's encrypt*

`./goshs -s -sl -sle your@mail.com -sld your.domain.com,your.seconddomain.com`

You will have to make sure that your IP is reachable via the domain name by creating an A entry with you DNS service provider first.

Then the example command will create two files called `key` and `cert` if the request for a certificate is successful. *Please note:* for this to work let's encrypt needs to reach goshs at port 80 and 443. So you will need to start it as root. There are several options you can choose from to circumvent running goshs as root after obtaining a valid certificate:
  
  - Drop user privileges using `-u` (preferred)
  - Run it once as root until you obtain the certificate. Then stop it and rerun it using `key` and `cert` like: `./goshs -s -sk key -sc cert` as non-root user
  - Use `-slh` and `-slt` to choose different challenge ports and proxy port 80 and 443 to them
  
 After stopping goshs you can reuse the files `key` and `cert` to restart the server with a valid certificate like: `./goshs -s -sk key -sc -cert` until they are invalidated due to certificate lifetime (90 days).

*Provide own certificate*

`goshs -s -sk server.key -sc server.crt`

**Run in silent mode**  
This mode will omit the dir listing on the web interface. Also you will not have access to the clipboard or upload form. Still you could upload a file using the corresponding post request (see examples).

`goshs -si`

**Retrieve the directory listing in json format**  
You can now retrieve the directory listing in *json* format. This is meant to be used with curl for example in environments where you do not have a browser on hand.



```bash
curl -s localhost:8000/?json | jq
[
  {
    "name": ".git/",
    "is_dir": true,
    "is_symlink": false,
    "symlink_target": "",
    "extension": "",
    "size_bytes": 4096,
    "last_modified": "2023-02-28T15:38:11.982+01:00"
  },
  {
    "name": ".github/",
    "is_dir": true,
    "is_symlink": false,
    "symlink_target": "",
    "extension": "",
    "size_bytes": 4096,
    "last_modified": "2023-02-28T10:27:35.524+01:00"
  },
  {
    "name": ".gitignore",
    "is_dir": false,
    "is_symlink": false,
    "symlink_target": "",
    "extension": ".gitignore",
    "size_bytes": 48,
    "last_modified": "2023-02-20T07:58:46.436+01:00"
  },
  ... snip ...
```

Or with path:

```bash
curl -s localhost:8000/utils?json | jq
[
  {
    "name": "utils.go",
    "is_dir": false,
    "is_symlink": false,
    "symlink_target": "",
    "extension": ".go",
    "size_bytes": 2218,
    "last_modified": "2023-02-28T15:28:54.783+01:00"
  },
  {
    "name": "utils_test.go",
    "is_dir": false,
    "is_symlink": false,
    "symlink_target": "",
    "extension": ".go",
    "size_bytes": 2012,
    "last_modified": "2023-02-28T15:28:12.748+01:00"
  }
]
```

**Drop user privs**  
You might wanna bind to port `80` but rather not have the process running as root. So you can use `-u/--user` to drop privileges:

```bash
user@host:~/projects/goshs$ sudo ./goshs -p 80 --u user
INFO   [2023-05-26 11:56:19] Serving on interface lo bound to 127.0.0.1:80 
INFO   [2023-05-26 11:56:19] Serving HTTP from /home/user/goshs  
INFO   [2023-05-26 11:56:19] Dropping privileges to user 'user'           
```

```bash
user@host:~$ ps aux | grep goshs
root       35975  0.0  0.0  10828  5028 pts/0    S+   11:56   0:00 sudo ./goshs -p 80 --u user
user       35976  0.0  0.1 1166136 8460 pts/0    Sl+  11:56   0:00 ./goshs -p 80 --u user
```

**Run with cli mode enabled**  
CLI mode will let you run commands on the system hosting `goshs` and return the output to you.

`goshs -b secret-user:$up3r$3cur3 -s -ss -c`

**File Based ACLs**  
You can apply file based access control lists per folder by placing a file called `.goshs` in that folder. The files content is like:

```json
{
  "auth":"<user>:<hash>",
  "block":[
    "file1",
    "file2",
    "folder/"
  ]
}
```

The hash you have to use can be generated with `goshs -H` or `goshs --hash`. This will generate a bCrypt hash. The username can be left empty.

```bash
goshs --hash
Enter password: *******
Hash: $2a$14$hh50ncgjLAOQT3KI1RlVYus3gMecE4/Ul2HakUp6iiBCnl2c5M0da
```

The `block` mode will **hide** the folders and files from the listing **and restrict access** to them regardless. Please be aware that a file inside a blocked folder will be accessible unless you define a new `.goshs` file within that blocked folder.

**Embed files on compile time**

You can embed files at compile time and ship them with your version of `goshs`. Any file that is in the folder `embedded` will be compiled into the binary and will be available while running. There is a file called `example.txt` in the folder by default to demonstrate the feature.

To compile just use `make build-<os>`, like for example `make build-linux` for a version running on linux. Be sure to checkout and understand the section [Build yourself](#build-yourself).

You can then retrieve the file browsing to `/file/path?embedded` or use the flag `-e` / `--embedded` to show the embedded files in the frontend.

```
user@host:~$ ./goshs -e
INFO   [2024-06-27 18:50:03] Download embedded file at: /example.txt?embedded 
INFO   [2024-06-27 18:50:03] Serving on interface eth0 bound to 10.137.0.27:8000 
INFO   [2024-06-27 18:50:03] Serving on interface lo bound to 127.0.0.1:8000 
INFO   [2024-06-27 18:50:03] Serving HTTP from /
INFO   [2024-06-27 18:50:56] 127.0.0.1:48784 - [200] - "GET /example.txt?embedded HTTP/1.1" 
```

```
user@host:~$ curl http://127.0.0.1:8000/example.txt?embedded
This is an example for an embedded file on compilation time. If you place any other file here before compiling using the Makefile, then it will be added to the goshs binary and will be available when running it.
```

# Credits

A special thank you goes to *sc0tfree* for inspiring this project with his project [updog](https://github.com/sc0tfree/updog) written in Python.
