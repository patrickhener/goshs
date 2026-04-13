package httpserver

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewIPWhitelist_Empty(t *testing.T) {
	wl, err := NewIPWhitelist("", false, "")
	require.NoError(t, err)
	require.NotNil(t, wl)
	require.False(t, wl.Enabled)
	require.Empty(t, wl.Networks)
}

func TestNewIPWhitelist_SingleIPv4(t *testing.T) {
	wl, err := NewIPWhitelist("192.168.1.1", true, "")
	require.NoError(t, err)
	require.Len(t, wl.Networks, 1)
}

func TestNewIPWhitelist_CIDRRange(t *testing.T) {
	wl, err := NewIPWhitelist("10.0.0.0/8", true, "")
	require.NoError(t, err)
	require.Len(t, wl.Networks, 1)
}

func TestNewIPWhitelist_Multiple(t *testing.T) {
	wl, err := NewIPWhitelist("192.168.1.0/24, 10.0.0.1", true, "")
	require.NoError(t, err)
	require.Len(t, wl.Networks, 2)
}

func TestNewIPWhitelist_IPv6(t *testing.T) {
	wl, err := NewIPWhitelist("::1", true, "")
	require.NoError(t, err)
	require.Len(t, wl.Networks, 1)
}

func TestNewIPWhitelist_Invalid(t *testing.T) {
	_, err := NewIPWhitelist("not-an-ip", true, "")
	require.Error(t, err)
}

func TestNewIPWhitelist_TrustedProxies(t *testing.T) {
	wl, err := NewIPWhitelist("192.168.1.0/24", true, "10.0.0.1, 172.16.0.0/12")
	require.NoError(t, err)
	require.Len(t, wl.TrustedProxies, 2)
}

func TestNewIPWhitelist_InvalidTrustedProxy(t *testing.T) {
	_, err := NewIPWhitelist("192.168.1.0/24", true, "not-a-proxy")
	require.Error(t, err)
}

func TestIsAllowed_DisabledWhitelist(t *testing.T) {
	wl := &Whitelist{Enabled: false}
	require.True(t, wl.IsAllowed("1.2.3.4"), "disabled whitelist should allow all IPs")
}

func TestIsAllowed_AllowedIP(t *testing.T) {
	wl, err := NewIPWhitelist("192.168.1.0/24", true, "")
	require.NoError(t, err)
	wl.Enabled = true
	require.True(t, wl.IsAllowed("192.168.1.100"))
}

func TestIsAllowed_DeniedIP(t *testing.T) {
	wl, err := NewIPWhitelist("192.168.1.0/24", true, "")
	require.NoError(t, err)
	wl.Enabled = true
	require.False(t, wl.IsAllowed("10.0.0.1"))
}

func TestIsAllowed_ExactIP(t *testing.T) {
	wl, err := NewIPWhitelist("192.168.1.5", true, "")
	require.NoError(t, err)
	wl.Enabled = true
	require.True(t, wl.IsAllowed("192.168.1.5"))
	require.False(t, wl.IsAllowed("192.168.1.6"))
}

func TestIsAllowed_InvalidIP(t *testing.T) {
	wl, err := NewIPWhitelist("192.168.1.0/24", true, "")
	require.NoError(t, err)
	wl.Enabled = true
	require.False(t, wl.IsAllowed("not-an-ip"))
}

func TestIsTrustedProxy_Trusted(t *testing.T) {
	// Must provide a non-empty cidr to avoid the early-return that skips proxy parsing.
	wl, err := NewIPWhitelist("192.168.0.0/24", true, "10.0.0.1")
	require.NoError(t, err)
	require.True(t, wl.IsTrustedProxy("10.0.0.1"))
}

func TestIsTrustedProxy_NotTrusted(t *testing.T) {
	wl, err := NewIPWhitelist("192.168.0.0/24", true, "10.0.0.1")
	require.NoError(t, err)
	require.False(t, wl.IsTrustedProxy("10.0.0.2"))
}

func TestIsTrustedProxy_Empty(t *testing.T) {
	wl := &Whitelist{}
	require.False(t, wl.IsTrustedProxy("10.0.0.1"))
}

func TestGetClientIP_DirectConnection(t *testing.T) {
	wl := &Whitelist{}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "192.168.1.5:12345"
	ip := GetClientIP(r, wl)
	require.Equal(t, "192.168.1.5", ip)
}

func TestGetClientIP_XForwardedFor_TrustedProxy(t *testing.T) {
	wl, err := NewIPWhitelist("192.168.0.0/24", true, "10.0.0.1")
	require.NoError(t, err)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.0.1:12345"
	r.Header.Set("X-Forwarded-For", "203.0.113.1, 10.0.0.1")
	ip := GetClientIP(r, wl)
	require.Equal(t, "203.0.113.1", ip)
}

func TestGetClientIP_XRealIP_TrustedProxy(t *testing.T) {
	wl, err := NewIPWhitelist("192.168.0.0/24", true, "10.0.0.1")
	require.NoError(t, err)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.0.1:12345"
	r.Header.Set("X-Real-IP", "203.0.113.2")
	ip := GetClientIP(r, wl)
	require.Equal(t, "203.0.113.2", ip)
}

func TestGetClientIP_UntrustedProxy_IgnoresHeaders(t *testing.T) {
	wl := &Whitelist{}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.0.1:12345"
	r.Header.Set("X-Forwarded-For", "203.0.113.1")
	ip := GetClientIP(r, wl)
	require.Equal(t, "10.0.0.1", ip)
}
