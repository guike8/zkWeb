// SPDX-License-Identifier: AGPL-3.0-or-later
// Package httppolicy contains request guards shared by worker and local clients.
// Static host checks do not resolve names; a proxy must enforce its own policy
// on DNS results when it performs destination resolution.
package httppolicy

import (
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// ParseOrigin accepts a public HTTPS origin with no credentials or URL suffix.
// DNS names must use ASCII labels and no trailing dot. No DNS query is made.
func ParseOrigin(target string) (*url.URL, error) {
	u, err := url.Parse(target)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil ||
		u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" ||
		u.RawFragment != "" || u.Opaque != "" || strings.HasSuffix(u.Host, ":") || strings.Contains(target, "#") {
		return nil, errors.New("target must be an HTTPS origin without credentials, path, query, or fragment")
	}
	if strings.HasPrefix(u.Host, "[") {
		ip, err := netip.ParseAddr(u.Hostname())
		if err != nil || !ip.Is6() {
			return nil, errors.New("invalid bracketed target address")
		}
	} else if strings.Contains(u.Hostname(), ":") {
		return nil, errors.New("IPv6 target addresses must be bracketed")
	}
	if u.Port() != "" {
		port, err := strconv.ParseUint(u.Port(), 10, 16)
		if err != nil || port == 0 {
			return nil, errors.New("invalid target port")
		}
	}
	if !PublicHostname(u.Hostname()) {
		return nil, errors.New("target must use a public address or eligible DNS name")
	}
	return u, nil
}

var excludedNetworks = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"), netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"), netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("3fff::/20"),
}

// PublicIP rejects private, local, special-use and transition address ranges.
func PublicIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.Zone() != "" {
		return false
	}
	if ip.Is6() && !netip.MustParsePrefix("2000::/3").Contains(ip) {
		return false
	}
	for _, prefix := range excludedNetworks {
		if prefix.Contains(ip) {
			return false
		}
	}
	return true
}

// PublicHostname performs only static checks. Passing this check does not mean
// that a DNS name resolves publicly; remote resolvers/proxies must check results.
// Canonical public IP literals and multi-label ASCII DNS names are eligible.
func PublicHostname(host string) bool {
	if ip, err := netip.ParseAddr(host); err == nil {
		return PublicIP(ip)
	}
	if len(host) == 0 || len(host) > 253 || strings.HasSuffix(host, ".") {
		return false
	}
	lower := strings.ToLower(host)
	for _, suffix := range []string{"localhost", "local", "localdomain", "internal", "home.arpa"} {
		if lower == suffix || strings.HasSuffix(lower, "."+suffix) {
			return false
		}
	}
	labels := strings.Split(lower, ".")
	if len(labels) < 2 {
		return false
	}
	// Numeric last labels are excluded so legacy inet_aton-style IPv4 forms
	// cannot be interpreted by a proxy as short, octal or hexadecimal IPs.
	last := labels[len(labels)-1]
	if allDecimal(last) || strings.HasPrefix(last, "0x") {
		return false
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := range label {
			c := label[i]
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
				return false
			}
		}
	}
	return true
}

func allDecimal(value string) bool {
	if value == "" {
		return false
	}
	for i := range value {
		if value[i] < '0' || value[i] > '9' {
			return false
		}
	}
	return true
}

// ValidateRequest checks shared HTTP semantics without reading or changing body
// bytes. Header values may repeat; duplicate spellings of the same name may not.
func ValidateRequest(method, requestPath string, headers http.Header) error {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions:
	default:
		return errors.New("unsupported HTTP method")
	}
	path, err := url.Parse(requestPath)
	if err != nil || !strings.HasPrefix(requestPath, "/") || strings.HasPrefix(requestPath, "//") ||
		strings.ContainsAny(requestPath, "\\#\r\n") || path.IsAbs() || path.Host != "" || path.User != nil || path.Fragment != "" {
		return errors.New("path must be relative to the configured origin and begin with one slash")
	}
	seen := make(map[string]bool)
	for name, values := range headers {
		canonical := http.CanonicalHeaderKey(name)
		if !validHeaderName(name) || forbiddenHeader(canonical) || seen[canonical] || len(values) == 0 {
			return errors.New("invalid or reserved request header")
		}
		seen[canonical] = true
		for _, value := range values {
			if !validHeaderValue(value) {
				return errors.New("invalid request header value")
			}
		}
	}
	return nil
}

func validHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for i := range name {
		c := name[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c))) {
			return false
		}
	}
	return true
}

func validHeaderValue(value string) bool {
	for i := range value {
		if value[i] == 127 || (value[i] < 32 && value[i] != '\t') {
			return false
		}
	}
	return true
}

func forbiddenHeader(name string) bool {
	switch name {
	case "Host", "Content-Length", "Connection", "Proxy-Connection", "Keep-Alive", "Te", "Trailer", "Transfer-Encoding", "Upgrade", "Proxy-Authorization", "Proxy-Authenticate":
		return true
	}
	return false
}

// ResponseHeaders copies end-to-end headers while dropping hop-by-hop fields,
// including extra field names nominated by Connection. Set-Cookie is retained;
// whether cookies are stored belongs to the caller's session policy.
func ResponseHeaders(headers http.Header) http.Header {
	blocked := make(map[string]bool)
	for name, values := range headers {
		if !strings.EqualFold(name, "Connection") {
			continue
		}
		for _, value := range values {
			for _, token := range strings.Split(value, ",") {
				blocked[http.CanonicalHeaderKey(strings.TrimSpace(token))] = true
			}
		}
	}
	clean := make(http.Header)
	for name, values := range headers {
		canonical := http.CanonicalHeaderKey(name)
		if !forbiddenHeader(canonical) && !blocked[canonical] {
			clean[canonical] = append(clean[canonical], values...)
		}
	}
	return clean
}
