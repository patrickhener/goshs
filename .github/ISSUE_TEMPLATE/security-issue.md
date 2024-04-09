---
name: Security Issue
about: Report a security issue
title: "[SECURITY] "
labels: Security Issue
assignees: patrickhener

---

**What is the cause of the security issue? Please describe.**
A clear and concise description of what the problem is. Ex. Goshs is susceptible to directory traversal due to unsanitized user input in function [...]

**What is the impact? Please elaborate**
A clear and concise description of the impact. Ex. An attacker could read any file outside the hosted directory.


**Give a Proof-of-Concept**
*Request*

```
GET /../../../etc/passwd HTTP/1.1
...
```

*Response*

```
HTTP/1.1 200 OK
content-type: [...]
```

*Run command*
`curl --path-as-is "http://localhost:8000/../../../etc/passwd"`

**Additional context**
Add any other context or screenshots about the security issue here.
