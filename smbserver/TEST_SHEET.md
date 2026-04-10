# Testcases with Authentication

| Case                       | smbclient.py | Samba Client (smbclient) | Nautilus | Windows 10 NTLMv2 | Windows 10 NTLMv1 | Windows 10 NTLMv1+SSP | Windows 11 NTLMv2 | Windows 11 NTLMv1 | Windows 11 NTLMv1+SSP |
| -------------------------- | ------------ | ------------------------ | -------- | ----------------- | ----------------- | --------------------- | ----------------- | ----------------- | --------------------- |
| Get Hash                   | [x]          | [x]                      | [x]      | [x]               | [x]               | [x]                   | [x]               | [N]               | [N]                   |
| Connection                 | [x]          | [x]                      | [x]      | [x]               | [x]               | [x]                   | [x]               | [N]               | [N]                   |
| Create File                | [x]          | [x]                      | [x]      | [x]               | [x]               | [x]                   | [x]               | [N]               | [N]                   |
| Display file               | [x]          | [N]                      | [x]      | [x]               | [x]               | [x]                   | [x]               | [N]               | [N]                   |
| Create Directory           | [x]          | [x]                      | [x]      | [x]               | [x]               | [x]                   | [x]               | [N]               | [N]                   |
| Get File                   | [x]          | [x]                      | [x]      | [x]               | [x]               | [x]                   | [x]               | [N]               | [N]                   |
| Delete File                | [x]          | [x]                      | [x]      | [x]               | [x]               | [x]                   | [x]               | [N]               | [N]                   |
| Delete Directory           | [x]          | [x]                      | [x]      | [x]               | [x]               | [x]                   | [x]               | [N]               | [N]                   |
| Different Webroot          | [x]          | [x]                      | [x]      | [x]               | [x]               | [x]                   | [x]               | [N]               | [N]                   |
| Read-Only Mode             | [x]          | [x]                      | [x]      | [x]               | [x]               | [x]                   | [x]               | [N]               | [N]                   |
| Upload-Only Mode           | [x]          | [x]                      | [x]      | [x]               | [x]               | [x]                   | [x]               | [N]               | [N]                   |
| No-Delete Mode             | [x]          | [x]                      | [x]      | [x]               | [x]               | [x]                   | [x]               | [N]               | [N]                   |

# Testcases without Authentication

| Case                       | smbclient.py | Samba Client (smbclient) | Nautilus | Windows 10 NTLMv2 | Windows 10 NTLMv1 | Windows 10 NTLMv1+SSP | Windows 11 NTLMv2 | Windows 11 NTLMv1 | Windows 11 NTLMv1+SSP |
| -------------------------- | ------------ | ------------------------ | -------- | ----------------- | ----------------- | --------------------- | ----------------- | ----------------- | --------------------- |
| Get Hash                   | [x]          | [x]                      | [x]      | [x]               | [x]               | [x]                   | [x]               | [N]               | [N]                   |
| Connection                 | [x]          | [x]                      | [x]      | [x]               | [x]               | [x]                   | [N]               | [N]               | [N]                   |
| Create File                | [x]          | [x]                      | [x]      | [x]               | [x]               | [x]                   | [N]               | [N]               | [N]                   |
| Display file (cat)         | [x]          | [N]                      | [x]      | [x]               | [x]               | [x]                   | [N]               | [N]               | [N]                   |
| Create Directory           | [x]          | [x]                      | [x]      | [x]               | [x]               | [x]                   | [N]               | [N]               | [N]                   |
| Get File                   | [x]          | [x]                      | [x]      | [x]               | [x]               | [x]                   | [N]               | [N]               | [N]                   |
| Delete File                | [x]          | [x]                      | [x]      | [x]               | [x]               | [x]                   | [N]               | [N]               | [N]                   |
| Delete Directory           | [x]          | [x]                      | [x]      | [x]               | [x]               | [x]                   | [N]               | [N]               | [N]                   |
| Different Webroot          | [x]          | [x]                      | [x]      | [x]               | [x]               | [x]                   | [N]               | [N]               | [N]                   |
| Read-Only Mode             | [x]          | [x]                      | [x]      | [x]               | [x]               | [x]                   | [N]               | [N]               | [N]                   |
| Upload-Only Mode           | [x]          | [x]                      | [x]      | [x]               | [x]               | [x]                   | [N]               | [N]               | [N]                   |
| No-Delete Mode             | [x]          | [x]                      | [x]      | [x]               | [x]               | [x]                   | [N]               | [N]               | [N]                   |

# Legend

x = Works, B = Bug, N = not available

# Buggy but working

- Win11 operations sometimes take a good time but will eventually succeed

# Accepted not working

- Win11 only works if you provide authentication - Hash extraction works though
- Win11 only supports NetNTLMv2
- No SMB1 (LM) mode - XP is EOL since 2014
