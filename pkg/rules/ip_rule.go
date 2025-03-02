package rules

import (
	"net"
	"net/http"
	"strings"
)

// IPRule implements a rule that matches based on client IP address
type IPRule struct {
	name     string
	message  string
	ipRange  string // IP or CIDR range
	ipNet    *net.IPNet
	singleIP net.IP
	enabled  bool
}

// NewIPRule creates a new IP-based rule
func NewIPRule(ipRange, name, message string) *IPRule {
	r := &IPRule{
		name:    name,
		message: message,
		ipRange: ipRange,
		enabled: true,
	}

	// Check if it's a CIDR range
	if strings.Contains(ipRange, "/") {
		_, ipNet, err := net.ParseCIDR(ipRange)
		if err == nil {
			r.ipNet = ipNet
			return r
		}
	}

	// Otherwise treat as a single IP
	ip := net.ParseIP(ipRange)
	if ip != nil {
		r.singleIP = ip
	}

	return r
}

// Match checks if the client IP matches this rule
func (r *IPRule) Match(req *http.Request) (bool, *BlockReason) {
	if !r.enabled {
		return false, nil
	}

	// Extract client IP from request
	clientIP := extractClientIP(req)
	if clientIP == nil {
		return false, nil
	}

	// Check for match
	if r.ipNet != nil {
		// Check if IP is in CIDR range
		if r.ipNet.Contains(clientIP) {
			return true, &BlockReason{
				Rule:    r.name,
				Message: r.message,
			}
		}
	} else if r.singleIP != nil {
		// Check if IP matches single IP
		if r.singleIP.Equal(clientIP) {
			return true, &BlockReason{
				Rule:    r.name,
				Message: r.message,
			}
		}
	}

	return false, nil
}

// Name returns the rule name
func (r *IPRule) Name() string {
	return r.name
}

// SetEnabled enables or disables the rule
func (r *IPRule) SetEnabled(enabled bool) {
	r.enabled = enabled
}

// IsEnabled returns whether the rule is enabled
func (r *IPRule) IsEnabled() bool {
	return r.enabled
}

// extractClientIP extracts the client IP from a request
func extractClientIP(r *http.Request) net.IP {
	// Check X-Forwarded-For header first
	forwardedFor := r.Header.Get("X-Forwarded-For")
	if forwardedFor != "" {
		// X-Forwarded-For can contain multiple IPs, take the first one
		ips := strings.Split(forwardedFor, ",")
		ip := net.ParseIP(strings.TrimSpace(ips[0]))
		if ip != nil {
			return ip
		}
	}

	// Fall back to RemoteAddr
	if r.RemoteAddr != "" {
		// RemoteAddr includes port, so need to split
		ipStr, _, err := net.SplitHostPort(r.RemoteAddr)
		if err == nil {
			ip := net.ParseIP(ipStr)
			if ip != nil {
				return ip
			}
		}

		// In case RemoteAddr doesn't have a port
		ip := net.ParseIP(r.RemoteAddr)
		if ip != nil {
			return ip
		}
	}

	return nil
}
