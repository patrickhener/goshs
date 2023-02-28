package ca

import (
	"strings"
	"testing"
)

const (
	certSha256 string = "65853DC369E138125B42FCE21DFF13CD93B5A0E3D2EB61107EF3378106759940"
	certSha1   string = "AB51F4B4D3336129576C5CA46408A6A79EA62FB2"
)

var (
	cert []byte = []byte(`BEGIN CERTIFICATE-----
MIIFPjCCAyagAwIBAgIULNlw3eSpMdJrm7aUVg/IwfHTuXMwDQYJKoZIhvcNAQEL
BQAwFjEUMBIGA1UEAwwLZXhhbXBsZS5jb20wHhcNMjMwMjI4MDk0NjUxWhcNMzMw
MjI1MDk0NjUxWjAWMRQwEgYDVQQDDAtleGFtcGxlLmNvbTCCAiIwDQYJKoZIhvcN
AQEBBQADggIPADCCAgoCggIBAM4GQRgDUfOWewaw37E74uf6nqiQaWLRJy+DtQxh
WAI/TOEXlSamTW0wsMoHRAkAvOBje1BmgHRhOUIuzSGmwDNjosz2zyrCONgRWfcJ
yN96EtPa/4lEvlHTiN2NdV4mDN3XcW9j2n+K5mWh3oDVz0wp+A2byDmg1EdmL/X8
hGVvTMyUFt6prprdnALdGZqblsZAaLYg++r7uEDBihVw6DWunoiq2TnxNIXTdTIo
5UeFnKCSBDWseN0+FeQ5Xq9mAQfzwk5YeY2ser4iWl0FlZdYwrj+EBYT+I4MTCWG
B7YxcsX6pWSoWhvv5V9sRtH1KkiH5RaNQ/b9v9Pl5sdRq7ofUWxxGAEq+LmOExIq
if3JWpMq6AQVrMJTylFQv2AD9S9+9T7azTIfAxifveQrbwkgIUZX2e5bB2iKhQEH
tFyNYd7eyomCHt//3iRFyq64AtfmbQRaj2UsW63/wOMLAgM5ood1pnWt/1GGsH8U
XusELZS2ov+RI/Si661B3VMZhtTY/jFLYqbM09IfeGpXriRQxiwvXCsiJvyZaRE+
NHR+F6CfZp/3935SBIKU6ljdBrLCzTRCQ8eoysOSXAcYD7MUMMQNPwK+nOWStYGc
tk+qSgU3B3xiL9/yDsdM5Ov4mArKpbXP9DYnfDw97+D+8xFPAl0VEgj7dH8b0Q+c
w7hxAgMBAAGjgYMwgYAwHQYDVR0OBBYEFEY+2jaoCj7pWl5ggiYRxIdw/YIsMB8G
A1UdIwQYMBaAFEY+2jaoCj7pWl5ggiYRxIdw/YIsMA8GA1UdEwEB/wQFMAMBAf8w
LQYDVR0RBCYwJIILZXhhbXBsZS5jb22CD3d3dy5leGFtcGxlLm5ldIcECgAAATAN
BgkqhkiG9w0BAQsFAAOCAgEAY0BOskg82Ty//ADLyiXVhwEV/lLILH0BWWWVv05i
frrUs2fA3ORkUoRaiJxAzDvEV98AjD52Ty6WYtgNscmrQxxz0gn3xUWZXdj6L5PE
C6xj4lH0M/bNW6TUWhBqaVsaUCaoEhze4ieTcUHZlF61tkscdfUf8cIwi4vyNA3v
LIzXgJxIYw+wD5K1MEtVOPX3x9oO2Ceu3dLQv7MWULVjir1Pm2/3YhfGJgttFNHu
fbFWrPRG/m1MiMniGxQb3Oa1IjPZU70elP3GGG+irojxWcFYW+MopeXelVxbC63I
z7uc7cbmmcsD2GIkv1td4pe84UYy+pCsKQ8vXykwnjcFfjkrPSxdz1tVjrz4V60e
jVekhGgIHQAm/PyLLssQDykiX6ySxurU8bCcpqaA6dBzlUEX+Ym9xr2l155U6OsP
k4HWPGqf2/xMaXq/7g9HfqPhj9tZ/x2wyZ6Mx2rMtRV+6hX1XGa4tZU0f5MziEnX
Lkf4fEY4kc28UdEZRiG+D8cK6k0N8fHkKo4M09f+PJp/4sqa2g2kj8aqEFzSu2uq
v/cKeJ20txB/Egu9OGCS3aFqQ9zV+rqkEko2agLbqY/Aks3e/jaAIwURvxNS83l4
rJ90pXPe6awWutwMfmwlzqv0UYLu0IGHZiN8uTPiQ0nkR2kps3MruAsj1K9PaNpq
rtI=
-----END CERTIFICATE-----`)
)

func TestSum(t *testing.T) {

	sha256, sha1 := Sum(cert)
	sha256Clean := strings.ReplaceAll(sha256, " ", "")
	sha1Clean := strings.ReplaceAll(sha1, " ", "")

	if sha256Clean != certSha256 || sha1Clean != certSha1 {
		t.Errorf("Certificate Fingerprint was wrong: got sha256 %s sha1 %s, want sha256 %s and sha1 %s", sha256Clean, sha1Clean, certSha256, certSha1)
	}
}
