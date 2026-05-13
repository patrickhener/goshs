# goshs fish completion

# Disable file completion by default
complete -c goshs -f

# --completion flag with shell name as value
complete -c goshs -l completion -d 'Install shell tab completion' -r -a 'bash fish zsh'

# Web server
complete -c goshs -s i -l ip           -d 'IP or interface to listen on (default: 0.0.0.0)'
complete -c goshs -s p -l port         -d 'Port to listen on (default: 8000)'
complete -c goshs -s d -l dir          -d 'Web root directory (default: cwd)' -r -F
complete -c goshs -s w -l webdav       -d 'Also serve using WebDAV protocol'
complete -c goshs -l webdav-port        -d 'WebDAV port (default: 8001)'
complete -c goshs -l read-only          -d 'Read only mode'
complete -c goshs -l upload-only        -d 'Upload only mode'
complete -c goshs -l upload-folder      -d 'Specify a different upload folder' -r -F
complete -c goshs -l max-upload         -d 'Maximum upload size in bytes (0=unlimited)'
complete -c goshs -l no-clipboard       -d 'Disable clipboard sharing'
complete -c goshs -l no-delete          -d 'Disable delete option'
complete -c goshs -l silent             -d 'Run without directory listing'
complete -c goshs -s I -l invisible     -d 'Invisible mode'
complete -c goshs -s c -l cli           -d 'Enable CLI (requires auth and TLS)'
complete -c goshs -l catcher            -d 'Enable reverse shell catcher'
complete -c goshs -s e -l embedded      -d 'Show embedded files in UI'
complete -c goshs -s o -l output        -d 'Write output to logfile' -r -F
complete -c goshs -s t -l tunnel        -d 'Enable tunnel'

# TLS
complete -c goshs -s s -l ssl           -d 'Use TLS'
complete -c goshs -l self-signed         -d 'Use a self-signed certificate'
complete -c goshs -l server-key          -d 'Path to server key' -r -F
complete -c goshs -l server-cert         -d 'Path to server certificate' -r -F
complete -c goshs -l pkcs12              -d 'Path to server p12' -r -F
complete -c goshs -l p12-no-pass         -d 'Server p12 has empty password'
complete -c goshs -l lets-encrypt        -d 'Use Let\'s Encrypt'
complete -c goshs -l le-domains          -d 'Domains for Let\'s Encrypt (comma separated)'
complete -c goshs -l le-email            -d 'Email for Let\'s Encrypt'
complete -c goshs -l le-http             -d 'Port for Let\'s Encrypt HTTP challenge (default: 80)'
complete -c goshs -l le-tls              -d 'Port for Let\'s Encrypt TLS ALPN challenge (default: 443)'

# SFTP
complete -c goshs -l sftp                -d 'Activate SFTP server'
complete -c goshs -l sftp-port           -d 'SFTP port (default: 2022)'
complete -c goshs -l sftp-keyfile        -d 'Authorized_keys file for pubkey auth' -r -F
complete -c goshs -l sftp-host-keyfile   -d 'SSH host key file' -r -F

# SMB
complete -c goshs -l smb                 -d 'Activate SMB server'
complete -c goshs -l smb-port            -d 'SMB port (default: 445)'
complete -c goshs -l smb-domain          -d 'Domain for SMB authentication'
complete -c goshs -l smb-share           -d 'Share name for SMB'
complete -c goshs -l smb-wordlist        -d 'Wordlist for hash cracking' -r -F

# LDAP
complete -c goshs -l ldap                -d 'Activate LDAP credential capture server'
complete -c goshs -l ldap-port           -d 'LDAP port (default: 389)'
complete -c goshs -l ldap-jndi           -d 'Enable JNDI mode for Log4Shell'
complete -c goshs -l ldap-jndi-base      -d 'Override codeBase URL for JNDI payloads'
complete -c goshs -l ldap-wordlist       -d 'Wordlist for LDAP NTLM hash cracking' -r -F

# Auth
complete -c goshs -s b -l basic-auth     -d 'Basic auth (user:pass)'
complete -c goshs -l cert-auth            -d 'Certificate based authentication' -r -F
complete -c goshs -s H -l hash           -d 'Hash a password for file based ACLs'

# Restrictions
complete -c goshs -l ip-whitelist         -d 'Comma separated list of IPs to whitelist'
complete -c goshs -l trusted-proxy-whitelist -d 'Comma separated list of trusted proxies'

# Collaboration
complete -c goshs -l dns                  -d 'Enable DNS server'
complete -c goshs -l dns-port             -d 'DNS server port (default: 8053)'
complete -c goshs -l dns-ip               -d 'DNS server reply IP (default: 127.0.0.1)'
complete -c goshs -l smtp                 -d 'Enable SMTP server'
complete -c goshs -l smtp-port            -d 'SMTP server port (default: 2525)'
complete -c goshs -l smtp-domain          -d 'SMTP server domain'

# Webhook
complete -c goshs -s W -l webhook         -d 'Enable webhook support'
complete -c goshs -l webhook-url           -d 'URL to send webhook requests to'
complete -c goshs -l webhook-events        -d 'Comma separated list of events to notify'
complete -c goshs -l webhook-provider      -d 'Webhook provider' -a 'Discord Mattermost Slack'

# Misc
complete -c goshs -s C -l config          -d 'Config file path' -r -F
complete -c goshs -s P -l print-config    -d 'Print sample config to STDOUT'
complete -c goshs -s u -l user            -d 'Drop privs to user (unix only)'
complete -c goshs -l update               -d 'Update goshs to most recent version'
complete -c goshs -s m -l mdns            -d 'Enable zeroconf mDNS registration'
complete -c goshs -s V -l verbose         -d 'Activate verbose log output'
complete -c goshs -s v                    -d 'Print the current goshs version'
