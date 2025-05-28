package httpserver

import (
	"fmt"
	"net"
	"strings"
)

type Whitelist struct {
	Networks       []*net.IPNet
	TrustedProxies []*net.IPNet
	Enabled        bool
}

func NewIPWhitelist(cidrs string, enabled bool, trustedProxies string) (*Whitelist, error) {
	whitelist := &Whitelist{Enabled: enabled}
	if cidrs == "" {
		return &Whitelist{}, nil
	}

	cidrsList := strings.Split(cidrs, ",")

	for _, cidr := range cidrsList {
		cidr = strings.TrimSpace(cidr)

		if cidr == "" {
			continue
		}

		if !strings.Contains(cidr, "/") {
			if strings.Contains(cidr, ":") {
				// IPv6 address without CIDR notation
				cidr += "/128"
			} else {
				// IPv4 address without CIDR notation
				cidr += "/32"
			}
		}

		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR notation '%s': %v", cidr, err)
		}

		whitelist.Networks = append(whitelist.Networks, network)
	}

	proxyList := strings.Split(trustedProxies, ",")

	for _, proxy := range proxyList {
		proxy = strings.TrimSpace(proxy)

		if proxy == "" {
			continue
		}

		if !strings.Contains(proxy, "/") {
			if strings.Contains(proxy, ":") {
				proxy += "/128"
			} else {
				proxy += "/32"
			}
		}

		_, network, err := net.ParseCIDR(proxy)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR notation '%s' : %v", proxy, err)
		}

		whitelist.TrustedProxies = append(whitelist.TrustedProxies, network)
	}

	return whitelist, nil
}

func (w *Whitelist) IsAllowed(ipStr string) bool {
	if !w.Enabled {
		return true // No whitelist configured, allow all
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false // Invalid IP address
	}

	for _, network := range w.Networks {
		if network.Contains(ip) {
			return true // IP is in the whitelist
		}
	}
	return false // IP is not in the whitelist
}

func (w *Whitelist) IsTrustedProxy(ipStr string) bool {
	parsedIP := net.ParseIP(ipStr)
	for _, cidr := range w.TrustedProxies {
		if cidr.Contains(parsedIP) {
			return true
		}
	}
	return false
}
