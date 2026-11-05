// SPDX-License-Identifier: AGPL-3.0-or-later
package httppolicy

import (
	"net/http"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func TestParseOriginRejectsAmbiguousOrLocalTargets(t *testing.T) {
	for _, target := range []string{
		"", "http://example.com", "https://example.com/", "https://example.com/path",
		"https://private-token@example.com", "https://example.com?", "https://example.com?q=1",
		"https://example.com#", "https://example.com#fragment", "https://example.com:",
		"https://example.com:0", "https://example.com:65536", "https://example.com:abc",
		"https://example.com.", "https://localhost", "https://LOCALHOST", "https://api.localhost",
		"https://localhost.localdomain", "https://printer.local", "https://api.internal", "https://router.home.arpa",
		"https://127.0.0.1", "https://10.0.0.1", "https://[::1]", "https://[::ffff:127.0.0.1]",
		"https://[fe80::1%25en0]", "https://[64:ff9b::a9fe:a9fe]", "https://[2002:7f00:1::]",
		"https://2130706433", "https://127.1", "https://0177.0.0.1", "https://0x7f000001",
		"https://0x7f.0.0.1", "https://127.0.0.0x1", "https://8.8.8.08", "https://api..example",
		"https://-api.example", "https://api-.example", "https://api_1.example", "https://café.example",
		"https://[example.com]", "https://2001:4860::8888:443",
	} {
		if _, err := ParseOrigin(target); err == nil {
			t.Errorf("accepted forbidden origin %q", target)
		} else if strings.Contains(err.Error(), "private-token") {
			t.Fatal("origin diagnostics leaked credentials")
		}
	}
}

func TestParseOriginAllowsStaticEligibleTargetsWithoutDNS(t *testing.T) {
	for _, target := range []string{
		"https://example.com", "https://API.Example.COM:8443", "https://api.example",
		"https://cannot-resolve.invalid", "https://xn--caf-dma.example", "https://8.8.8.8",
		"https://[2606:4700:4700::1111]", "https://[2606:4700:4700::1111]:8443",
	} {
		u, err := ParseOrigin(target)
		if err != nil || u.String() != target {
			t.Errorf("eligible origin changed or rejected: %q, %v", target, err)
		}
	}
}

func TestPublicHostnameBoundsAndAddressPolicy(t *testing.T) {
	for _, host := range []string{
		"", "name", "example.com.", strings.Repeat("a", 64) + ".example",
		strings.Repeat("a.", 126) + "example", "name%zone.example", "a.b/evil", "a.b\\evil",
		"64:ff9b:1::7f00:1", "2001:db8::1", "3fff::1", "100.64.0.1", "169.254.169.254",
	} {
		if PublicHostname(host) {
			t.Errorf("accepted invalid host %q", host)
		}
	}
	if PublicIP(netip.Addr{}) {
		t.Fatal("accepted an invalid IP address")
	}
	if !PublicHostname(strings.Repeat("a", 63) + ".example") {
		t.Fatal("rejected maximum DNS label length")
	}
}

func TestValidateRequestPreservesRepeatedHeadersAndEscapedPaths(t *testing.T) {
	headers := http.Header{
		"Authorization": {"Bearer explicit"},
		"X-Tag":         {"one", "two"},
		"Cookie":        {"session=explicit"},
		"X-Empty":       {""},
	}
	before := headers.Clone()
	for _, method := range []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"} {
		if err := ValidateRequest(method, "/items/a%2Fb?q=one%20two&v=2", headers); err != nil {
			t.Errorf("rejected %s request: %v", method, err)
		}
	}
	if !reflect.DeepEqual(before, headers) {
		t.Fatal("validation changed request headers")
	}
}

func TestValidateRequestRejectsOriginEscapeAndHeaderInjection(t *testing.T) {
	for _, method := range []string{"", "get", "TRACE", "CONNECT", "POST\r\n"} {
		if ValidateRequest(method, "/", nil) == nil {
			t.Errorf("accepted unsupported method %q", method)
		}
	}
	for _, path := range []string{
		"", "relative", "https://evil.example/", "//evil.example/", "/\\evil.example",
		"/a#fragment", "/%xx", "/a\r\nHost: evil.example", "/a\x00b",
	} {
		if ValidateRequest("GET", path, nil) == nil {
			t.Errorf("accepted invalid path %q", path)
		}
	}
	invalid := []http.Header{
		{"X-Tag": {"one"}, "x-tag": {"two"}},
		{"Bad Name": {"value"}}, {"X-Tag": {"one\r\nInjected: yes"}},
		{"X-Tag": {"bad\x00value"}}, {"X-Tag": {"bad\x7fvalue"}}, {"X-Tag": nil},
	}
	for _, name := range []string{"Host", "Content-Length", "Connection", "Proxy-Connection", "Keep-Alive", "TE", "Trailer", "Transfer-Encoding", "Upgrade", "Proxy-Authorization", "Proxy-Authenticate"} {
		invalid = append(invalid, http.Header{name: {"value"}})
	}
	for _, headers := range invalid {
		if ValidateRequest("GET", "/", headers) == nil {
			t.Errorf("accepted unsafe header map %#v", headers)
		}
	}
}

func TestResponseHeadersRemoveConnectionFieldsAndCopyValues(t *testing.T) {
	original := http.Header{
		"connection":         {"keep-alive, X-Private", "X-Other"},
		"Keep-Alive":         {"timeout=5"},
		"Proxy-Authenticate": {"Basic"},
		"Content-Length":     {"2"},
		"X-Private":          {"hidden"},
		"X-Other":            {"hidden"},
		"X-Tag":              {"one", "two"},
		"Set-Cookie":         {"one=1", "two=2"},
		"Content-Type":       {"application/octet-stream"},
	}
	clean := ResponseHeaders(original)
	want := http.Header{
		"X-Tag":        {"one", "two"},
		"Set-Cookie":   {"one=1", "two=2"},
		"Content-Type": {"application/octet-stream"},
	}
	if !reflect.DeepEqual(clean, want) {
		t.Fatalf("wrong end-to-end headers: %#v", clean)
	}
	clean["X-Tag"][0] = "changed"
	if original["X-Tag"][0] != "one" {
		t.Fatal("response values alias upstream storage")
	}
}
