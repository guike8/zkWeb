// SPDX-License-Identifier: AGPL-3.0-or-later
package transport

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

type observedRequest struct {
	host     string
	port     int
	identity string
	typeByte byte
}

func proxyServer(t *testing.T, connections int, handler func(net.Conn) error) (string, <-chan error) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	results := make(chan error, connections)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		for range connections {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
			err = handler(conn)
			_ = conn.Close()
			results <- err
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		select {
		case <-finished:
		case <-time.After(3 * time.Second):
			t.Error("proxy handler did not stop")
		}
	})
	return listener.Addr().String(), results
}

func readRequest(conn net.Conn, method byte) (observedRequest, error) {
	var result observedRequest
	var greeting [3]byte
	if _, err := io.ReadFull(conn, greeting[:]); err != nil {
		return result, err
	}
	if greeting != [3]byte{5, 1, method} {
		return result, errors.New("unexpected greeting or authentication downgrade")
	}
	if _, err := conn.Write([]byte{5, method}); err != nil {
		return result, err
	}
	if method == 2 {
		var head [2]byte
		if _, err := io.ReadFull(conn, head[:]); err != nil || head[0] != 1 || head[1] == 0 {
			return result, errors.New("invalid authentication header")
		}
		username := make([]byte, int(head[1]))
		if _, err := io.ReadFull(conn, username); err != nil {
			return result, err
		}
		var length [1]byte
		if _, err := io.ReadFull(conn, length[:]); err != nil {
			return result, err
		}
		password := make([]byte, int(length[0]))
		if _, err := io.ReadFull(conn, password); err != nil {
			return result, errors.New("invalid isolation password")
		}
		entropy, err := hex.DecodeString(string(password))
		if string(username) != "<torS0X>0" || len(password) != 64 || err != nil || len(entropy) != 32 {
			return result, errors.New("invalid modern Tor isolation wire format")
		}
		result.identity = string(password)
		if _, err := conn.Write([]byte{1, 0}); err != nil {
			return result, err
		}
	}
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil || header[0] != 5 || header[1] != 1 || header[2] != 0 {
		return result, errors.New("invalid connect request")
	}
	result.typeByte = header[3]
	length := 0
	switch header[3] {
	case 1:
		length = 4
	case 4:
		length = 16
	case 3:
		var size [1]byte
		if _, err := io.ReadFull(conn, size[:]); err != nil || size[0] == 0 {
			return result, errors.New("invalid domain length")
		}
		length = int(size[0])
	default:
		return result, errors.New("invalid address type")
	}
	address := make([]byte, length)
	if _, err := io.ReadFull(conn, address); err != nil {
		return result, err
	}
	if header[3] == 3 {
		result.host = string(address)
	} else {
		result.host = net.IP(address).String()
	}
	var port [2]byte
	if _, err := io.ReadFull(conn, port[:]); err != nil {
		return result, err
	}
	result.port = int(port[0])<<8 | int(port[1])
	return result, nil
}

func successfulReply(conn net.Conn) error {
	// Deliberately fragment the reply to exercise full protocol reads.
	for _, value := range []byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0} {
		if _, err := conn.Write([]byte{value}); err != nil {
			return err
		}
	}
	return nil
}

func TestProxyEndpointValidation(t *testing.T) {
	for _, endpoint := range []string{
		"", "https://127.0.0.1:9050", "socks5://localhost:9050", "tor://example.com:9050",
		"tor://192.168.1.1:9050", "tor://127.0.0.1", "tor://127.0.0.1:0", "tor://127.0.0.1:65536",
		"tor://user:secret@127.0.0.1:9050", "tor://127.0.0.1:9050/", "tor://127.0.0.1:9050?",
		"tor://127.0.0.1:9050#", "tor://127.0.0.1:9050#secret", "tor://[::1%25lo0]:9050",
	} {
		if _, err := NewSOCKS(endpoint); err == nil {
			t.Errorf("accepted invalid proxy %q", endpoint)
		}
	}
	for _, endpoint := range []string{"tor://127.0.0.1:9050", "socks5://[::1]:1080"} {
		proxy, err := NewSOCKS(endpoint)
		if err != nil || proxy.Mode() != strings.Split(endpoint, ":")[0] {
			t.Errorf("valid endpoint refused: %v", err)
		}
	}
}

func TestSOCKSRemoteDNSAndIPAddresses(t *testing.T) {
	for _, test := range []struct {
		host string
		kind byte
	}{
		{"does-not-resolve.invalid", 3}, {"8.8.8.8", 1}, {"2606:4700:4700::1111", 4},
	} {
		t.Run(test.host, func(t *testing.T) {
			seen := make(chan observedRequest, 1)
			endpoint, results := proxyServer(t, 1, func(conn net.Conn) error {
				request, err := readRequest(conn, 0)
				if err != nil {
					return err
				}
				seen <- request
				if err := successfulReply(conn); err != nil {
					return err
				}
				_, err = conn.Write([]byte("connected"))
				return err
			})
			proxy, _ := NewSOCKS("socks5://" + endpoint)
			conn, err := proxy.DialContext(context.Background(), "tcp", net.JoinHostPort(test.host, "443"))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			data := make([]byte, len("connected"))
			if _, err := io.ReadFull(conn, data); err != nil || string(data) != "connected" {
				t.Fatalf("connected stream unusable: %v", err)
			}
			if err := <-results; err != nil {
				t.Fatal(err)
			}
			request := <-seen
			if request.host != test.host || request.port != 443 || request.typeByte != test.kind {
				t.Fatal("destination did not reach the proxy intact")
			}
		})
	}
}

func TestTorIdentityIsStableWithinInstanceAndSeparateAcrossInstances(t *testing.T) {
	identities := make(chan string, 3)
	endpoint, results := proxyServer(t, 3, func(conn net.Conn) error {
		request, err := readRequest(conn, 2)
		if err != nil {
			return err
		}
		identities <- request.identity
		return successfulReply(conn)
	})
	first, err := NewSOCKS("tor://" + endpoint)
	if err != nil {
		t.Fatal(err)
	}
	second, _ := NewSOCKS("tor://" + endpoint)
	for _, proxy := range []*SOCKS{first, first, second} {
		conn, err := proxy.DialContext(context.Background(), "tcp", "unresolved.invalid:443")
		if err != nil {
			t.Fatal(err)
		}
		conn.Close()
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	a, b, c := <-identities, <-identities, <-identities
	if len(a) != 64 || a != b || a == c {
		t.Fatal("Tor identities crossed instance boundaries or changed within an instance")
	}
}

func TestTorRejectsNoAuthDowngrade(t *testing.T) {
	endpoint, results := proxyServer(t, 1, func(conn net.Conn) error {
		var greeting [3]byte
		if _, err := io.ReadFull(conn, greeting[:]); err != nil || greeting != [3]byte{5, 1, 2} {
			return errors.New("Tor did not require authentication")
		}
		_, err := conn.Write([]byte{5, 0})
		return err
	})
	proxy, _ := NewSOCKS("tor://" + endpoint)
	if conn, err := proxy.DialContext(context.Background(), "tcp", "unresolved.invalid:443"); err == nil {
		conn.Close()
		t.Fatal("accepted unauthenticated Tor downgrade")
	}
	if err := <-results; err != nil {
		t.Fatal(err)
	}
}

func TestTorRejectsMalformedAuthenticationReplies(t *testing.T) {
	for index, response := range [][]byte{{1, 1}, {2, 0}, {1}, {}} {
		t.Run(strconv.Itoa(index), func(t *testing.T) {
			endpoint, results := proxyServer(t, 1, func(conn net.Conn) error {
				var greeting [3]byte
				if _, err := io.ReadFull(conn, greeting[:]); err != nil || greeting != [3]byte{5, 1, 2} {
					return errors.New("Tor did not require authentication")
				}
				if _, err := conn.Write([]byte{5, 2}); err != nil {
					return err
				}
				auth := make([]byte, 2+len(torIsolationUser)+1+64)
				if _, err := io.ReadFull(conn, auth); err != nil {
					return err
				}
				if auth[0] != 1 || int(auth[1]) != len(torIsolationUser) || string(auth[2:2+len(torIsolationUser)]) != "<torS0X>0" || auth[2+len(torIsolationUser)] != 64 {
					return errors.New("invalid modern Tor authentication framing")
				}
				_, err := conn.Write(response)
				return err
			})
			proxy, _ := NewSOCKS("tor://" + endpoint)
			if conn, err := proxy.DialContext(context.Background(), "tcp", "unresolved.invalid:443"); err == nil {
				conn.Close()
				t.Fatal("accepted malformed Tor authentication reply")
			}
			if err := <-results; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestProxyFailureCannotConnectDirectly(t *testing.T) {
	proxyListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxy, _ := NewSOCKS("socks5://" + proxyListener.Addr().String())
	proxyListener.Close()
	destination, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer destination.Close()
	if conn, err := proxy.DialContext(context.Background(), "tcp", destination.Addr().String()); err == nil {
		conn.Close()
		t.Fatal("failed proxy fell back to direct destination")
	}
	_ = destination.(*net.TCPListener).SetDeadline(time.Now().Add(50 * time.Millisecond))
	if conn, err := destination.Accept(); err == nil {
		conn.Close()
		t.Fatal("destination was dialed directly")
	}
}

func TestMalformedConnectRepliesFailClosed(t *testing.T) {
	for i, reply := range [][]byte{
		{5, 1, 0, 1, 127, 0, 0, 1, 0, 0},
		{4, 0, 0, 1, 127, 0, 0, 1, 0, 0},
		{5, 0, 1, 1, 127, 0, 0, 1, 0, 0},
		{5, 0, 0, 9}, {5, 0, 0, 1, 127}, {5, 0, 0, 3, 0}, {5, 0, 0, 4, 0},
	} {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			endpoint, results := proxyServer(t, 1, func(conn net.Conn) error {
				if _, err := readRequest(conn, 0); err != nil {
					return err
				}
				_, err := conn.Write(reply)
				return err
			})
			proxy, _ := NewSOCKS("socks5://" + endpoint)
			if conn, err := proxy.DialContext(context.Background(), "tcp", "unresolved.invalid:443"); err == nil {
				conn.Close()
				t.Fatal("accepted malformed connect response")
			}
			if err := <-results; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCancellationClosesStalledHandshake(t *testing.T) {
	started, stopped := make(chan struct{}), make(chan struct{})
	endpoint, results := proxyServer(t, 1, func(conn net.Conn) error {
		var greeting [3]byte
		if _, err := io.ReadFull(conn, greeting[:]); err != nil {
			return err
		}
		close(started)
		_, _ = io.Copy(io.Discard, conn)
		close(stopped)
		return nil
	})
	proxy, _ := NewSOCKS("tor://" + endpoint)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		conn, err := proxy.DialContext(ctx, "tcp", "unresolved.invalid:443")
		if conn != nil {
			conn.Close()
		}
		done <- err
	}()
	select {
	case <-started:
		cancel()
	case <-time.After(time.Second):
		t.Fatal("proxy handshake never started")
	}
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation was lost: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not stop handshake")
	}
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("cancellation retained proxy socket")
	}
	if err := <-results; err != nil {
		t.Fatal(err)
	}
}

func TestDestinationValidationBeforeProxyDial(t *testing.T) {
	proxy, _ := NewSOCKS("socks5://127.0.0.1:1")
	for _, destination := range []string{"missing-port", ":443", "example.com:0", "example.com:65536", "bad name.invalid:443", "[fe80::1%lo0]:443", strings.Repeat("a", 256) + ":443"} {
		if conn, err := proxy.DialContext(context.Background(), "tcp", destination); err == nil {
			conn.Close()
			t.Errorf("accepted invalid destination %q", destination)
		}
	}
	if conn, err := proxy.DialContext(context.Background(), "udp", "example.com:443"); err == nil {
		conn.Close()
		t.Fatal("accepted UDP on TCP-only transport")
	}
}

type partialWriter struct{ bytes.Buffer }

func (w *partialWriter) Write(raw []byte) (int, error) {
	if len(raw) > 1 {
		raw = raw[:1]
	}
	return w.Buffer.Write(raw)
}

func TestHandshakeWritesDoNotAcceptShortWrites(t *testing.T) {
	writer := &partialWriter{}
	if writeAll(writer, []byte{5, 1, 2}) {
		t.Fatal("accepted a short protocol write without error")
	}
	if got := fmt.Sprint(writer.Bytes()); got != "[5]" {
		t.Fatal("unexpected short-write fixture")
	}
}
