Name:           goshs
Version:        v2.0.8
Release:        1%{?dist}
Summary:        Beyond Python's http.server — single-binary file server for pentesters

License:        MIT
URL:            https://github.com/patrickhener/goshs
Source0:        %{url}/archive/refs/tags/v%{version}.tar.gz#/%{name}-%{version}.tar.gz

BuildRequires:  golang >= 1.26

%description
A single-binary file server for pentesters, CTF players, and sysadmins.

HTTP/S, WebDAV, SFTP, SMB, LDAP/S, NTLM hash capture, DNS/SMTP
callbacks — all from one command, zero dependencies.

Features:
- File sharing: upload/download, drag & drop, QR codes, bulk ZIP, share links
- Protocols: HTTP/S, WebDAV, SFTP, SMB, LDAP/S
- Auth: basic auth, certificate auth, TLS (self-signed, Let's Encrypt, custom)
- Red team: SMB/LDAP NTLM hash capture + cracking, JNDI/Log4Shell,
  DNS/SMTP out-of-band callbacks, reverse shell catcher, redirect endpoint
- Tunnel via localhost.run, webhooks, mDNS, IP allowlist, shell completion

%prep
%autosetup

%build
export CGO_ENABLED=0
go mod download
go build -trimpath -ldflags="-s -w" -o %{name} .

%install
install -Dm 0755 %{name} %{buildroot}%{_bindir}/%{name}

%files
%license LICENSE
%doc README.md
%{_bindir}/%{name}

%changelog
* Tue May 13 2026 Patrick Hener <patrickhener@gmx.de> - 2.0.8-1
- Add more packaging
* Tue May 13 2026 Patrick Hener <patrickhener@gmx.de> - 2.0.7-1
- Initial COPR package
