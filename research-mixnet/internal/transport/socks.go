// SPDX-License-Identifier: AGPL-3.0-or-later
// Adapted from zkapi-clientd/internal/relay/{socks5,tor}.go.
// Original work Copyright (c) 2026 Open Anonymity Team, MIT licensed;
// see MIT-NOTICE for the retained permission and warranty notice.

// Package transport provides explicit proxy routes without a direct fallback.
package transport

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	handshakeTimeout = 20 * time.Second
	// Tor's SOCKS extensions identify the modern isolation format with this
	// username; the per-client isolation value belongs in the password.
	torIsolationUser = "<torS0X>0"
)

// SOCKS is a TCP route through a numeric loopback SOCKS5 endpoint. In Tor mode,
// each instance has a fresh authentication identity, retained across its dials.
// The Tor SOCKS port must enable IsolateSOCKSAuth; this client cannot verify the
// proxy's configuration or promise a distinct exit for different identities.
type SOCKS struct {
	address  string
	mode     string
	identity string
}

// NewSOCKS accepts tor:// or socks5:// followed only by a numeric loopback
// address and a nonzero port. It opens no connection and inherits no proxy or
// authentication settings from the environment.
func NewSOCKS(endpoint string) (*SOCKS, error) {
	u, err := url.Parse(endpoint)
	if err != nil || (u.Scheme != "tor" && u.Scheme != "socks5") ||
		u.User != nil || u.Path != "" || u.RawPath != "" || u.RawQuery != "" ||
		u.ForceQuery || u.Fragment != "" || u.RawFragment != "" || u.Opaque != "" ||
		strings.Contains(endpoint, "#") {
		return nil, errors.New("proxy must be tor:// or socks5:// with a numeric loopback address and port only")
	}
	ip, err := netip.ParseAddr(u.Hostname())
	if err != nil || !ip.IsLoopback() || ip.Zone() != "" {
		return nil, errors.New("proxy must use a numeric loopback address")
	}
	port, err := strconv.ParseUint(u.Port(), 10, 16)
	if err != nil || port == 0 || strings.HasSuffix(u.Host, ":") {
		return nil, errors.New("proxy must specify a nonzero port")
	}
	proxy := &SOCKS{address: net.JoinHostPort(ip.String(), strconv.FormatUint(port, 10)), mode: u.Scheme}
	if proxy.mode == "tor" {
		var entropy [32]byte
		if _, err := rand.Read(entropy[:]); err != nil {
			return nil, errors.New("cannot create Tor isolation identity")
		}
		proxy.identity = hex.EncodeToString(entropy[:])
	}
	return proxy, nil
}

// Mode reports tor or socks5. It never exposes the isolation identity.
func (s *SOCKS) Mode() string { return s.mode }

// DialContext asks the configured proxy to connect to address. Destination
// names use SOCKS domain addressing, so no local destination lookup occurs.
// Only the loopback proxy is dialed, exactly once. All failures stop this route.
func (s *SOCKS) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if network != "tcp" {
		return nil, errors.New("SOCKS5 requires TCP")
	}
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return nil, errors.New("invalid SOCKS5 destination")
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return nil, errors.New("invalid SOCKS5 destination port")
	}
	addressType := byte(3)
	destination := []byte(host)
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.Zone() != "" {
			return nil, errors.New("invalid SOCKS5 destination address")
		}
		ip = ip.Unmap()
		destination = ip.AsSlice()
		if ip.Is4() {
			addressType = 1
		} else {
			addressType = 4
		}
	} else if !validDomain(host) {
		return nil, errors.New("invalid SOCKS5 destination name")
	}

	conn, err := (&net.Dialer{Timeout: handshakeTimeout}).DialContext(ctx, "tcp", s.address)
	if err != nil {
		return nil, contextError(ctx, "SOCKS5 proxy unavailable")
	}
	ok := false
	defer func() {
		if !ok {
			_ = conn.Close()
		}
	}()
	closed := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = conn.Close()
		close(closed)
	})
	defer func() {
		if !stop() {
			<-closed
		}
	}()
	deadline := time.Now().Add(handshakeTimeout)
	if ctxDeadline, exists := ctx.Deadline(); exists && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, contextError(ctx, "cannot set SOCKS5 handshake deadline")
	}

	method := byte(0)
	if s.mode == "tor" {
		method = 2 // Offer only RFC 1929; no downgrade to unauthenticated Tor.
	}
	if !writeAll(conn, []byte{5, 1, method}) {
		return nil, contextError(ctx, "SOCKS5 greeting failed")
	}
	var reply [4]byte
	if _, err := io.ReadFull(conn, reply[:2]); err != nil {
		return nil, contextError(ctx, "SOCKS5 greeting reply truncated")
	}
	if reply[0] != 5 || reply[1] != method {
		return nil, errors.New("SOCKS5 proxy rejected required authentication method")
	}
	if method == 2 {
		auth := append([]byte{1, byte(len(torIsolationUser))}, torIsolationUser...)
		auth = append(auth, byte(len(s.identity)))
		auth = append(auth, s.identity...)
		if !writeAll(conn, auth) {
			return nil, contextError(ctx, "Tor isolation authentication failed")
		}
		if _, err := io.ReadFull(conn, reply[:2]); err != nil {
			return nil, contextError(ctx, "Tor isolation authentication reply truncated")
		}
		if reply[0] != 1 || reply[1] != 0 {
			return nil, errors.New("Tor isolation authentication rejected")
		}
	}
	request := []byte{5, 1, 0, addressType}
	if addressType == 3 {
		request = append(request, byte(len(destination)))
	}
	request = append(request, destination...)
	request = append(request, byte(port>>8), byte(port))
	if !writeAll(conn, request) {
		return nil, contextError(ctx, "SOCKS5 connect request failed")
	}
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		return nil, contextError(ctx, "SOCKS5 connect reply truncated")
	}
	if reply[0] != 5 || reply[1] != 0 || reply[2] != 0 {
		return nil, errors.New("SOCKS5 connect rejected")
	}
	remaining := 0
	switch reply[3] {
	case 1:
		remaining = 4
	case 4:
		remaining = 16
	case 3:
		var length [1]byte
		if _, err := io.ReadFull(conn, length[:]); err != nil || length[0] == 0 {
			return nil, contextError(ctx, "SOCKS5 connect reply invalid")
		}
		remaining = int(length[0])
	default:
		return nil, errors.New("SOCKS5 connect reply address type invalid")
	}
	if _, err := io.CopyN(io.Discard, conn, int64(remaining+2)); err != nil {
		return nil, contextError(ctx, "SOCKS5 connect reply truncated")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return nil, contextError(ctx, "cannot clear SOCKS5 handshake deadline")
	}
	ok = true
	return conn, nil
}

func validDomain(host string) bool {
	if len(host) == 0 || len(host) > 255 || strings.ContainsAny(host, ":/\\?#@%") {
		return false
	}
	for i := range host {
		if host[i] <= 32 || host[i] >= 127 {
			return false
		}
	}
	return true
}

func writeAll(writer io.Writer, data []byte) bool {
	_, err := io.Copy(writer, bytes.NewReader(data))
	return err == nil
}

func contextError(ctx context.Context, message string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return errors.New(message)
}
