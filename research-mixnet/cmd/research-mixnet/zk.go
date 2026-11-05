// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
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
	zkProtocol    = "zkweb-zk-authorized-crud-v1"
	zkBodyLimit   = 64 << 10
	zkOutputLimit = 1 << 20
)

var errZKBackendUnavailable = errors.New("ZK listener backend unavailable")

type zkBackendRunner func(context.Context, string, []string, io.Writer) error

func zkCommand(ctx context.Context, mode string, args []string, out io.Writer) error {
	return zkWithBackend(ctx, mode, args, out, runZKBackend, os.Executable)
}

// Explicit local arguments go to one fixed sibling executable, without a shell.
// Credentials remain in the client profile; only the backend constructs proofs.
func zkWithBackend(ctx context.Context, mode string, args []string, out io.Writer, runner zkBackendRunner, executable executableResolver) error {
	f := flag.NewFlagSet("zk-"+mode, flag.ContinueOnError)
	f.SetOutput(io.Discard)
	var output, serverDir, stateFile, clientDir, endpoint, listen, method, key, data, dataFile string
	var members int
	var timeout time.Duration
	switch mode {
	case "setup":
		f.StringVar(&output, "output", "", "required new offline setup directory")
		f.IntVar(&members, "members", 4, "authorized group members (1–16)")
		f.DurationVar(&timeout, "timeout", 10*time.Minute, "setup deadline (30s–30m)")
	case "listen":
		f.StringVar(&serverDir, "server-dir", "", "required server profile with verifying key only")
		f.StringVar(&stateFile, "state-file", "", "required persistent record-state file")
		f.StringVar(&listen, "listen", "127.0.0.1:0", "numeric loopback IP:port; 0 selects an available port")
	case "request":
		f.StringVar(&clientDir, "client-dir", "", "required client profile with private membership credential")
		f.StringVar(&endpoint, "url", "", "required numeric-loopback HTTP origin from zk-listen")
		f.StringVar(&method, "method", "", "required POST, GET, PUT or DELETE")
		f.StringVar(&key, "key", "", "required record key: 1–128 ASCII letters, digits, underscores or hyphens")
		f.StringVar(&data, "data", "", "UTF-8 body for POST/PUT; choose exactly one of --data or --data-file")
		f.StringVar(&dataFile, "data-file", "", "binary body file for POST/PUT")
		f.DurationVar(&timeout, "timeout", time.Minute, "total request deadline (1s–5m); timeouts do not undo writes")
	default:
		return errors.New("unknown ZK listener command")
	}
	if err := f.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			if _, err := fmt.Fprintf(out, "usage: zkweb zk-%s [options]\n", mode); err != nil {
				return errors.New("cannot write ZK help")
			}
			f.SetOutput(out)
			f.PrintDefaults()
			return nil
		}
		return errors.New("invalid ZK listener arguments; use the command's --help")
	}
	if f.NArg() != 0 {
		return errors.New("ZK listener commands accept no positional arguments")
	}
	provided := make(map[string]bool)
	f.Visit(func(option *flag.Flag) { provided[option.Name] = true })
	backendArgs := []string{mode}
	switch mode {
	case "setup":
		var err error
		output, err = privateAbsoluteDir(output)
		if err != nil || members < 1 || members > 16 || timeout < 30*time.Second || timeout > 30*time.Minute {
			return errors.New("zk-setup requires --output, 1–16 members and a 30s–30m deadline")
		}
		backendArgs = append(backendArgs, "--output", output, "--members", strconv.Itoa(members))
	case "listen":
		var err error
		serverDir, err = privateAbsoluteDir(serverDir)
		if err != nil {
			return errors.New("zk-listen requires --server-dir")
		}
		stateFile, err = privateAbsoluteDir(stateFile)
		if err != nil {
			return errors.New("zk-listen requires --state-file")
		}
		listen, err = privateListenAddress(listen)
		if err != nil {
			return errors.New("zk-listen requires a numeric loopback IP:port")
		}
		backendArgs = append(backendArgs, "--server-dir", serverDir, "--state-file", stateFile, "--listen", listen)
	case "request":
		var err error
		clientDir, err = privateAbsoluteDir(clientDir)
		if err != nil {
			return errors.New("zk-request requires --client-dir")
		}
		endpoint, err = privateHTTPOrigin(endpoint)
		method = strings.ToUpper(method)
		if err != nil || !zkMethod(method) || !zkKey(key) || timeout < time.Second || timeout > 5*time.Minute {
			return errors.New("zk-request requires a numeric loopback HTTP origin, CRUD method, valid key and 1s–5m deadline")
		}
		var payload []byte
		if method == "POST" || method == "PUT" {
			if provided["data"] == provided["data-file"] {
				return errors.New("POST/PUT requires exactly one of --data or --data-file")
			}
			if provided["data"] {
				if !utf8.ValidString(data) || len(data) > zkBodyLimit {
					return errors.New("request text must be valid UTF-8 of at most 64 KiB")
				}
				payload = []byte(data)
			} else {
				payload, err = zkReadDataFile(dataFile)
				if err != nil {
					return errors.New("request data file must be a readable regular file of at most 64 KiB")
				}
			}
		} else if provided["data"] || provided["data-file"] {
			return errors.New("GET/DELETE accepts no data argument")
		}
		backendArgs = append(backendArgs, "--client-dir", clientDir, "--url", endpoint, "--method", method, "--key", key, "--data-base64", base64.StdEncoding.EncodeToString(payload))
	}
	path, err := executable()
	if err != nil || !filepath.IsAbs(path) {
		return errors.New("cannot locate the ZK listener backend beside zkweb")
	}
	backend := filepath.Join(filepath.Dir(path), "zkweb-zk-listener")
	var runCtx context.Context
	var cancel context.CancelFunc
	if mode == "listen" {
		runCtx, cancel = context.WithCancel(ctx)
	} else {
		runCtx, cancel = context.WithTimeout(ctx, timeout)
	}
	defer cancel()
	if runCtx.Err() != nil {
		return errors.New("ZK listener operation canceled before launch")
	}
	result := privateBuffer{limit: zkOutputLimit, cancel: cancel}
	var writer io.Writer = &result
	var ready *zkReadyWriter
	if mode == "listen" {
		ready = &zkReadyWriter{out: out, listen: listen, cancel: cancel}
		writer = ready
	}
	if err := runner(runCtx, backend, backendArgs, writer); err != nil {
		if errors.Is(err, errZKBackendUnavailable) {
			return errors.New("optional ZK listener backend unavailable; run make build-zk and keep it beside zkweb")
		}
		if mode == "request" {
			return errors.New("ZK request delivery unknown; do not retry automatically")
		}
		if runCtx.Err() != nil {
			return errors.New("ZK listener operation timed out or was canceled")
		}
		return errors.New("ZK listener operation failed; check the profile and listener")
	}
	if mode == "listen" {
		if !ready.emitted || len(bytes.TrimSpace(ready.pending)) != 0 {
			return errors.New("ZK listener returned invalid readiness")
		}
		return nil
	}
	encoded, err := validateZKResult(mode, result.Bytes(), method, key, members)
	if err != nil {
		if mode == "request" {
			return errors.New("ZK request delivery unknown; do not retry automatically")
		}
		return errors.New("ZK backend returned invalid setup metadata")
	}
	if n, err := out.Write(append(encoded, '\n')); err != nil || n != len(encoded)+1 {
		if mode == "request" {
			return errors.New("ZK request delivery unknown; do not retry automatically")
		}
		return errors.New("cannot write ZK setup result")
	}
	return nil
}

func zkMethod(method string) bool {
	return method == "POST" || method == "GET" || method == "PUT" || method == "DELETE"
}
func zkKey(key string) bool {
	if len(key) < 1 || len(key) > 128 {
		return false
	}
	for _, value := range []byte(key) {
		if !((value >= 'A' && value <= 'Z') || (value >= 'a' && value <= 'z') || (value >= '0' && value <= '9') || value == '_' || value == '-') {
			return false
		}
	}
	return true
}
func zkReadDataFile(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("regular file required")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err = file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > zkBodyLimit {
		return nil, errors.New("invalid body file")
	}
	data, err := io.ReadAll(io.LimitReader(file, zkBodyLimit+1))
	if err != nil || len(data) > zkBodyLimit {
		return nil, errors.New("invalid body file")
	}
	return data, nil
}

func validateZKResult(mode string, raw []byte, method, key string, members int) ([]byte, error) {
	if len(raw) > zkOutputLimit {
		return nil, errors.New("result exceeds limit")
	}
	if mode == "setup" {
		if privateObject(raw, "format", "server_dir", "client_dirs", "profile_id", "protocol", "members") != nil {
			return nil, errors.New("invalid setup result")
		}
		var report struct {
			Format     string   `json:"format"`
			ServerDir  string   `json:"server_dir"`
			ClientDirs []string `json:"client_dirs"`
			ProfileID  string   `json:"profile_id"`
			Protocol   string   `json:"protocol"`
			Members    int      `json:"members"`
		}
		if json.Unmarshal(raw, &report) != nil || report.Format != "zkweb-zk-setup-v1" || report.Protocol != zkProtocol || !privateProfileID(report.ProfileID) || !filepath.IsAbs(report.ServerDir) || report.Members != members || members < 1 || members > 16 || len(report.ClientDirs) != members {
			return nil, errors.New("invalid setup result")
		}
		seen := map[string]bool{report.ServerDir: true}
		for _, path := range report.ClientDirs {
			if !filepath.IsAbs(path) || seen[path] {
				return nil, errors.New("invalid client profile path")
			}
			seen[path] = true
		}
		return json.Marshal(report)
	}
	if privateObject(raw, "format", "method", "key", "status", "body_base64") != nil {
		return nil, errors.New("invalid request result")
	}
	var report struct {
		Format string `json:"format"`
		Method string `json:"method"`
		Key    string `json:"key"`
		Status uint16 `json:"status"`
		Body   string `json:"body_base64"`
	}
	if json.Unmarshal(raw, &report) != nil || report.Format != "zkweb-zk-result-v1" || report.Method != method || report.Key != key {
		return nil, errors.New("invalid request result")
	}
	validStatus := (method == "POST" && (report.Status == 201 || report.Status == 409 || report.Status == 507)) || (method != "POST" && zkMethod(method) && (report.Status == 200 || report.Status == 404))
	body, err := base64.StdEncoding.DecodeString(report.Body)
	if !validStatus || err != nil || len(body) > zkBodyLimit || base64.StdEncoding.EncodeToString(body) != report.Body {
		return nil, errors.New("invalid request result")
	}
	return json.Marshal(report)
}

type zkReadyWriter struct {
	out     io.Writer
	listen  string
	cancel  context.CancelFunc
	pending []byte
	total   int
	emitted bool
}

func (writer *zkReadyWriter) Write(data []byte) (int, error) {
	writer.total += len(data)
	if writer.total > zkOutputLimit {
		writer.cancel()
		return 0, errors.New("ZK readiness limit")
	}
	writer.pending = append(writer.pending, data...)
	for {
		newline := bytes.IndexByte(writer.pending, '\n')
		if newline < 0 {
			break
		}
		line := writer.pending[:newline]
		writer.pending = writer.pending[newline+1:]
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		if writer.emitted || len(line) > privateReadyLimit || privateObject(line, "event", "url", "profile_id", "protocol") != nil {
			writer.cancel()
			return 0, errors.New("invalid ZK readiness")
		}
		var report struct {
			Event     string `json:"event"`
			URL       string `json:"url"`
			ProfileID string `json:"profile_id"`
			Protocol  string `json:"protocol"`
		}
		if json.Unmarshal(line, &report) != nil || report.Event != "ready" || report.Protocol != zkProtocol || !privateProfileID(report.ProfileID) {
			writer.cancel()
			return 0, errors.New("invalid ZK readiness")
		}
		canonical, err := privateHTTPOrigin(report.URL)
		if err != nil {
			writer.cancel()
			return 0, errors.New("invalid ZK listener URL")
		}
		listenHost, listenPort, _ := net.SplitHostPort(writer.listen)
		u, _ := url.Parse(canonical)
		if u.Hostname() != listenHost || (listenPort != "0" && u.Port() != listenPort) {
			writer.cancel()
			return 0, errors.New("unexpected ZK listener URL")
		}
		report.URL = canonical
		encoded, _ := json.Marshal(report)
		if n, err := writer.out.Write(append(encoded, '\n')); err != nil || n != len(encoded)+1 {
			writer.cancel()
			return 0, errors.New("cannot write ZK readiness")
		}
		writer.emitted = true
	}
	if len(writer.pending) > privateReadyLimit {
		writer.cancel()
		return 0, errors.New("ZK readiness limit")
	}
	return len(data), nil
}

func runZKBackend(ctx context.Context, backend string, args []string, out io.Writer) error {
	if !filepath.IsAbs(backend) {
		return errZKBackendUnavailable
	}
	info, err := os.Stat(backend)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		return errZKBackendUnavailable
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	command := exec.CommandContext(runCtx, backend, args...)
	command.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", "RAYON_NUM_THREADS=4"}
	command.Stderr = io.Discard
	command.Stdout = &privateProcessOutput{out: out, cancel: cancel}
	command.WaitDelay = time.Second
	if err := command.Run(); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errors.New("ZK backend failed")
	}
	return nil
}
