// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	privateProtocol    = "zkweb-private-query-v1"
	privateOutputLimit = 1 << 20
	privateReadyLimit  = 64 << 10
)

var errPrivateBackendUnavailable = errors.New("private-request backend unavailable")

type privateBackendRunner func(context.Context, string, []string, io.Writer) error

func privateCommand(ctx context.Context, mode string, args []string, out io.Writer) error {
	return privateWithBackend(ctx, mode, args, out, runPrivateBackend, os.Executable)
}

// The optional backend owns cryptography and HTTP. This boundary passes only
// explicit local arguments to one fixed sibling executable, without a shell.
func privateWithBackend(ctx context.Context, mode string, args []string, out io.Writer, runBackend privateBackendRunner, executable executableResolver) error {
	f := flag.NewFlagSet("private-"+mode, flag.ContinueOnError)
	f.SetOutput(io.Discard)
	var output, serverDir, clientDir, listen, endpoint string
	var index int
	var timeout time.Duration
	switch mode {
	case "setup":
		f.StringVar(&output, "output", "", "required new setup directory; client secret keys remain in its client subdirectory")
		f.DurationVar(&timeout, "timeout", 10*time.Minute, "setup deadline (30s–30m)")
	case "serve":
		f.StringVar(&serverDir, "server-dir", "", "required directory containing public setup and evaluation keys only")
		f.StringVar(&listen, "listen", "127.0.0.1:0", "numeric loopback address and port; 0 selects an available port")
	case "query":
		f.StringVar(&clientDir, "client-dir", "", "required client directory containing the local decryption key")
		f.StringVar(&endpoint, "url", "", "required numeric-loopback HTTP origin from private-serve")
		f.IntVar(&index, "index", -1, "required private record selector (0–3); encrypted locally before transmission")
		f.DurationVar(&timeout, "timeout", 5*time.Minute, "query deadline (1s–10m)")
	default:
		return errors.New("unknown private-request command")
	}
	if err := f.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			if _, err := fmt.Fprintf(out, "usage: zkweb private-%s [options]\n", mode); err != nil {
				return errors.New("cannot write private-request help")
			}
			f.SetOutput(out)
			f.PrintDefaults()
			return nil
		}
		return errors.New("invalid private-request arguments; use the command's --help")
	}
	if f.NArg() != 0 {
		return errors.New("private-request commands accept no positional arguments")
	}
	backendArgs := []string{mode}
	switch mode {
	case "setup":
		var err error
		output, err = privateAbsoluteDir(output)
		if err != nil || timeout < 30*time.Second || timeout > 30*time.Minute {
			return errors.New("private-setup requires --output and a 30s–30m deadline")
		}
		backendArgs = append(backendArgs, "--output", output)
	case "serve":
		var err error
		serverDir, err = privateAbsoluteDir(serverDir)
		if err != nil {
			return errors.New("private-serve requires --server-dir")
		}
		listen, err = privateListenAddress(listen)
		if err != nil {
			return errors.New("private-serve requires a numeric loopback address and a port from 0 to 65535")
		}
		backendArgs = append(backendArgs, "--server-dir", serverDir, "--listen", listen)
	case "query":
		var err error
		clientDir, err = privateAbsoluteDir(clientDir)
		if err != nil || index < 0 || index > 3 || timeout < time.Second || timeout > 10*time.Minute {
			return errors.New("private-query requires --client-dir, --index 0–3 and a 1s–10m deadline")
		}
		endpoint, err = privateHTTPOrigin(endpoint)
		if err != nil {
			return errors.New("private-query requires a numeric loopback HTTP origin with a port and no URL suffix or credentials")
		}
		backendArgs = append(backendArgs, "--client-dir", clientDir, "--url", endpoint, "--index", strconv.Itoa(index))
	}
	path, err := executable()
	if err != nil || !filepath.IsAbs(path) {
		return errors.New("cannot locate the private-request backend beside zkweb")
	}
	backend := filepath.Join(filepath.Dir(path), "zkweb-private")
	var runCtx context.Context
	var cancel context.CancelFunc
	if mode == "serve" {
		runCtx, cancel = context.WithCancel(ctx)
	} else {
		runCtx, cancel = context.WithTimeout(ctx, timeout)
	}
	defer cancel()
	if runCtx.Err() != nil {
		return errors.New("private-request operation timed out or was canceled")
	}
	var result privateBuffer
	result.limit = privateOutputLimit
	result.cancel = cancel
	var writer io.Writer = &result
	var ready *privateReadyWriter
	if mode == "serve" {
		ready = &privateReadyWriter{out: out, listen: listen, cancel: cancel}
		writer = ready
	}
	if err := runBackend(runCtx, backend, backendArgs, writer); err != nil {
		if errors.Is(err, errPrivateBackendUnavailable) {
			return errors.New("optional private-request backend is unavailable; run make build-private and keep it beside zkweb")
		}
		if runCtx.Err() != nil {
			return errors.New("private-request operation timed out or was canceled")
		}
		return errors.New("private-request operation failed; check the setup, endpoint and optional backend")
	}
	if mode == "serve" {
		if !ready.emitted || len(bytes.TrimSpace(ready.pending)) != 0 {
			return errors.New("private server returned an invalid readiness response")
		}
		return nil
	}
	encoded, err := validatePrivateResult(mode, result.Bytes(), index)
	if err != nil {
		return errors.New("private-request backend returned an invalid result")
	}
	if n, err := out.Write(append(encoded, '\n')); err != nil || n != len(encoded)+1 {
		return errors.New("cannot write private-request result")
	}
	return nil
}

func privateAbsoluteDir(path string) (string, error) {
	if path == "" || strings.ContainsRune(path, 0) {
		return "", errors.New("directory required")
	}
	return filepath.Abs(path)
}

func privateListenAddress(address string) (string, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return "", err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !ip.Unmap().IsLoopback() || ip.Zone() != "" {
		return "", errors.New("loopback address required")
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		return "", errors.New("invalid port")
	}
	return net.JoinHostPort(ip.Unmap().String(), strconv.FormatUint(port, 10)), nil
}

func privateHTTPOrigin(target string) (string, error) {
	u, err := url.Parse(target)
	if err != nil || u.Scheme != "http" || u.User != nil || u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" || u.Opaque != "" || strings.Contains(target, "#") {
		return "", errors.New("HTTP origin required")
	}
	address, err := privateListenAddress(u.Host)
	if err != nil {
		return "", err
	}
	_, port, _ := net.SplitHostPort(address)
	if port == "0" {
		return "", errors.New("destination port required")
	}
	return "http://" + address, nil
}

func privateProfileID(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32
}

func privateObject(raw []byte, fields ...string) error {
	if len(raw) == 0 || !utf8.Valid(raw) {
		return errors.New("invalid result")
	}
	object, err := fetchObject(raw)
	if err != nil || len(object) != len(fields) {
		return errors.New("invalid result")
	}
	for _, name := range fields {
		if _, exists := object[name]; !exists {
			return errors.New("invalid result")
		}
	}
	return nil
}

func validatePrivateResult(mode string, raw []byte, expectedIndex int) ([]byte, error) {
	if len(raw) > privateOutputLimit {
		return nil, errors.New("result limit")
	}
	if mode == "setup" {
		if privateObject(raw, "format", "client_dir", "server_dir", "profile_id", "protocol") != nil {
			return nil, errors.New("invalid setup result")
		}
		var report struct {
			Format    string `json:"format"`
			ClientDir string `json:"client_dir"`
			ServerDir string `json:"server_dir"`
			ProfileID string `json:"profile_id"`
			Protocol  string `json:"protocol"`
		}
		if json.Unmarshal(raw, &report) != nil || report.Format != "zkweb-private-setup-v1" || report.Protocol != privateProtocol || !privateProfileID(report.ProfileID) || !filepath.IsAbs(report.ClientDir) || !filepath.IsAbs(report.ServerDir) {
			return nil, errors.New("invalid setup result")
		}
		return json.Marshal(report)
	}
	if privateObject(raw, "format", "index", "value") != nil {
		return nil, errors.New("invalid query result")
	}
	var report struct {
		Format string `json:"format"`
		Index  uint8  `json:"index"`
		Value  uint8  `json:"value"`
	}
	if json.Unmarshal(raw, &report) != nil || report.Format != "zkweb-private-result-v1" || int(report.Index) != expectedIndex {
		return nil, errors.New("invalid query result")
	}
	return json.Marshal(report)
}

type privateBuffer struct {
	bytes.Buffer
	limit  int
	cancel context.CancelFunc
}

func (b *privateBuffer) Write(data []byte) (int, error) {
	if len(data) > b.limit-b.Len() {
		b.cancel()
		return 0, errors.New("private output limit")
	}
	return b.Buffer.Write(data)
}

type privateReadyWriter struct {
	out     io.Writer
	listen  string
	cancel  context.CancelFunc
	pending []byte
	total   int
	emitted bool
}

func (w *privateReadyWriter) Write(data []byte) (int, error) {
	w.total += len(data)
	if w.total > privateOutputLimit {
		w.cancel()
		return 0, errors.New("private output limit")
	}
	w.pending = append(w.pending, data...)
	for {
		newline := bytes.IndexByte(w.pending, '\n')
		if newline < 0 {
			break
		}
		line := w.pending[:newline]
		w.pending = w.pending[newline+1:]
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		if w.emitted || len(line) > privateReadyLimit || privateObject(line, "event", "url", "profile_id", "protocol") != nil {
			w.cancel()
			return 0, errors.New("invalid readiness response")
		}
		var report struct {
			Event     string `json:"event"`
			URL       string `json:"url"`
			ProfileID string `json:"profile_id"`
			Protocol  string `json:"protocol"`
		}
		if json.Unmarshal(line, &report) != nil || report.Event != "ready" || report.Protocol != privateProtocol || !privateProfileID(report.ProfileID) {
			w.cancel()
			return 0, errors.New("invalid readiness response")
		}
		canonical, err := privateHTTPOrigin(report.URL)
		if err != nil {
			w.cancel()
			return 0, errors.New("invalid readiness response")
		}
		listenHost, listenPort, _ := net.SplitHostPort(w.listen)
		u, _ := url.Parse(canonical)
		if u.Hostname() != listenHost || (listenPort != "0" && u.Port() != listenPort) {
			w.cancel()
			return 0, errors.New("unexpected readiness endpoint")
		}
		report.URL = canonical
		encoded, _ := json.Marshal(report)
		if n, err := w.out.Write(append(encoded, '\n')); err != nil || n != len(encoded)+1 {
			w.cancel()
			return 0, errors.New("cannot write readiness response")
		}
		w.emitted = true
	}
	if len(w.pending) > privateReadyLimit {
		w.cancel()
		return 0, errors.New("readiness response limit")
	}
	return len(data), nil
}

func runPrivateBackend(ctx context.Context, backend string, args []string, out io.Writer) error {
	if !filepath.IsAbs(backend) {
		return errPrivateBackendUnavailable
	}
	info, err := os.Stat(backend)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		return errPrivateBackendUnavailable
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	command := exec.CommandContext(runCtx, backend, args...)
	command.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", "RAYON_NUM_THREADS=4"}
	command.Stderr = io.Discard
	command.WaitDelay = time.Second
	command.Stdout = &privateProcessOutput{out: out, cancel: cancel}
	if err := command.Run(); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errors.New("private backend failed")
	}
	return nil
}

type privateProcessOutput struct {
	out    io.Writer
	cancel context.CancelFunc
	total  int
}

func (w *privateProcessOutput) Write(data []byte) (int, error) {
	if len(data) > privateOutputLimit-w.total {
		w.cancel()
		return 0, errors.New("private output limit")
	}
	w.total += len(data)
	n, err := w.out.Write(data)
	if err != nil || n != len(data) {
		w.cancel()
		if err == nil {
			err = io.ErrShortWrite
		}
		return n, err
	}
	return n, nil
}
