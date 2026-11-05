// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const zkAPIBodyLimit = 1 << 20
const zkAPIHeaderBytes = 8 << 10
const zkAPIHeaderCount = 32

type zkAPIHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type zkHeaderFlags []string

func (headers *zkHeaderFlags) String() string         { return "" }
func (headers *zkHeaderFlags) Set(value string) error { *headers = append(*headers, value); return nil }

func zkAPICommand(ctx context.Context, args []string, out io.Writer) error {
	return zkAPIWithBackend(ctx, args, out, runZKBackend, os.Executable)
}

func zkAPIWithBackend(ctx context.Context, args []string, out io.Writer, runner zkBackendRunner, executable executableResolver) error {
	f := flag.NewFlagSet("zk-api", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	var clientDir, endpoint, upstream, method, requestPath, data, dataFile string
	var headers zkHeaderFlags
	var timeout time.Duration
	f.StringVar(&clientDir, "client-dir", "", "required private member profile")
	f.StringVar(&endpoint, "url", "", "required numeric-loopback HTTP gateway origin")
	f.StringVar(&upstream, "upstream", "", "required expected HTTPS upstream origin")
	f.StringVar(&method, "method", "GET", "GET, HEAD, POST, PUT, PATCH, DELETE or OPTIONS")
	f.StringVar(&requestPath, "path", "", "required exact origin-relative path and optional query")
	f.Var(&headers, "header", "explicit proof-bound upstream header, repeatable as 'Name: value'")
	f.StringVar(&data, "data", "", "UTF-8 request body; choose data or data-file")
	f.StringVar(&dataFile, "data-file", "", "binary request body file, at most 1 MiB")
	f.DurationVar(&timeout, "timeout", time.Minute, "total deadline (1s–5m); a timeout does not undo a write")
	if err := f.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			if _, err := fmt.Fprintln(out, "usage: zkweb zk-api --client-dir DIR --url GATEWAY --upstream HTTPS_ORIGIN --path /path [options]"); err != nil {
				return errors.New("cannot write ZK API help")
			}
			f.SetOutput(out)
			f.PrintDefaults()
			return nil
		}
		return errors.New("invalid ZK API arguments; use zk-api --help")
	}
	provided := map[string]bool{}
	f.Visit(func(option *flag.Flag) { provided[option.Name] = true })
	var err error
	clientDir, err = privateAbsoluteDir(clientDir)
	if err != nil || f.NArg() != 0 || timeout < time.Second || timeout > 5*time.Minute {
		return errors.New("zk-api requires a client profile, named arguments and a 1s–5m deadline")
	}
	endpoint, err = privateHTTPOrigin(endpoint)
	if err != nil {
		return errors.New("zk-api requires a numeric-loopback HTTP gateway origin")
	}
	upstream, err = zkCanonicalUpstream(upstream)
	if err != nil {
		return errors.New("zk-api requires an expected HTTPS origin without credentials or URL suffix")
	}
	method = strings.ToUpper(method)
	if !zkAPIMethod(method) || zkAPIPath(requestPath) != nil {
		return errors.New("invalid ZK API method or exact path/query")
	}
	boundHeaders := make([]zkAPIHeader, 0, len(headers))
	for _, header := range headers {
		name, value, found := strings.Cut(header, ":")
		if !found {
			return errors.New("headers must use Name: value")
		}
		boundHeaders = append(boundHeaders, zkAPIHeader{Name: name, Value: value})
	}
	boundHeaders, err = zkCanonicalAPIHeaders(boundHeaders)
	if err != nil {
		return errors.New("invalid, reserved or oversized proof-bound headers")
	}
	if provided["data"] && provided["data-file"] {
		return errors.New("choose exactly one of --data or --data-file")
	}
	if (method == "GET" || method == "HEAD") && (provided["data"] || provided["data-file"]) {
		return errors.New("GET/HEAD accepts no data argument")
	}
	if (method == "POST" || method == "PUT" || method == "PATCH") && !provided["data"] && !provided["data-file"] {
		return errors.New("POST/PUT/PATCH requires --data or --data-file, including an explicit empty value")
	}
	var body []byte
	if provided["data"] {
		if !utf8.ValidString(data) || len(data) > zkAPIBodyLimit {
			return errors.New("text body must be valid UTF-8 of at most 1 MiB")
		}
		body = []byte(data)
	} else if provided["data-file"] {
		body, err = zkAPIReadBody(dataFile)
		if err != nil {
			return errors.New("data file must be a readable regular file of at most 1 MiB")
		}
	}
	path, err := executable()
	if err != nil || !filepath.IsAbs(path) {
		return errors.New("cannot locate the ZK backend beside zkweb")
	}
	// Large binary bodies never travel in process arguments or a shell command.
	file, err := os.CreateTemp("", "zkweb-api-body-*")
	if err != nil {
		return errors.New("cannot prepare private request body file")
	}
	name := file.Name()
	defer os.Remove(name)
	if _, err := file.Write(body); err != nil {
		file.Close()
		return errors.New("cannot prepare request body")
	}
	if err := file.Close(); err != nil {
		return errors.New("cannot close request body file")
	}
	encodedHeaders, _ := json.Marshal(boundHeaders)
	backendArgs := []string{"api-request", "--client-dir", clientDir, "--url", endpoint, "--upstream", upstream, "--method", method, "--path", requestPath, "--headers-base64", base64.StdEncoding.EncodeToString(encodedHeaders), "--body-file", name}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if runCtx.Err() != nil {
		return errors.New("ZK API operation canceled before launch")
	}
	result := privateBuffer{limit: zkOutputLimit, cancel: cancel}
	if err := runner(runCtx, filepath.Join(filepath.Dir(path), "zkweb-zk-listener"), backendArgs, &result); err != nil {
		if errors.Is(err, errZKBackendUnavailable) {
			return errors.New("optional ZK listener backend unavailable; run make build-zk")
		}
		return errors.New("ZK API delivery unknown; do not retry automatically")
	}
	encoded, err := validateZKAPIResult(result.Bytes(), method, requestPath, upstream)
	if err != nil {
		return errors.New("ZK API delivery unknown; do not retry automatically")
	}
	if n, err := out.Write(append(encoded, '\n')); err != nil || n != len(encoded)+1 {
		return errors.New("ZK API delivery unknown; do not retry automatically")
	}
	return nil
}

func zkAPIMethod(method string) bool {
	switch method {
	case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS":
		return true
	}
	return false
}

func zkCanonicalUpstream(input string) (string, error) {
	u, err := url.Parse(input)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(input, "#") || u.Opaque != "" || strings.HasSuffix(u.Host, ":") {
		return "", errors.New("invalid HTTPS origin")
	}
	host := strings.ToLower(u.Hostname())
	if strings.HasPrefix(u.Host, "[") {
		ip, parseErr := netip.ParseAddr(host)
		if parseErr != nil || !ip.Is6() {
			return "", errors.New("invalid bracketed host")
		}
	} else if strings.Contains(host, ":") {
		return "", errors.New("IPv6 addresses must be bracketed")
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.Zone() != "" {
			return "", errors.New("zone not allowed")
		}
		host = ip.String()
	} else {
		if len(host) > 253 || strings.HasSuffix(host, ".") {
			return "", errors.New("invalid DNS host")
		}
		labels := strings.Split(host, ".")
		last := labels[len(labels)-1]
		if last == "" || strings.HasPrefix(last, "0x") {
			return "", errors.New("invalid DNS host")
		}
		allDigits := true
		for _, value := range []byte(last) {
			if value < '0' || value > '9' {
				allDigits = false
			}
		}
		if allDigits {
			return "", errors.New("noncanonical address")
		}
		for _, label := range labels {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return "", errors.New("invalid DNS label")
			}
			for _, value := range []byte(label) {
				if !((value >= 'a' && value <= 'z') || (value >= '0' && value <= '9') || value == '-') {
					return "", errors.New("ASCII DNS required")
				}
			}
		}
	}
	port := u.Port()
	if port != "" {
		numeric, err := strconv.ParseUint(port, 10, 16)
		if err != nil || numeric == 0 {
			return "", errors.New("invalid port")
		}
		port = strconv.FormatUint(numeric, 10)
	}
	if port == "443" {
		port = ""
	}
	if port != "" {
		host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return "https://" + host, nil
}

func zkAPIPath(path string) error {
	if len(path) == 0 || len(path) > 8192 || !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") || strings.ContainsAny(path, "\\#\r\n\t ") {
		return errors.New("invalid path")
	}
	for _, value := range []byte(path) {
		if value < 33 || value > 126 {
			return errors.New("ASCII escaped path required")
		}
	}
	u, err := url.Parse(path)
	if err != nil || u.IsAbs() || u.Host != "" || u.User != nil || u.Fragment != "" {
		return errors.New("invalid relative path")
	}
	for _, part := range strings.Split(u.EscapedPath(), "/") {
		if part == "." || part == ".." {
			return errors.New("dot segments forbidden")
		}
	}
	lowerPath := strings.ToLower(u.EscapedPath())
	for _, escape := range []string{"%2e", "%2f", "%5c", "%25"} {
		if strings.Contains(lowerPath, escape) {
			return errors.New("normalization escape forbidden")
		}
	}
	return nil
}

func zkAPIHeaderToken(name string) bool {
	if name == "" {
		return false
	}
	for _, value := range []byte(name) {
		if !((value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') || (value >= '0' && value <= '9') || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(value))) {
			return false
		}
	}
	return true
}
func zkAPIHeaderValue(value string) bool {
	for _, char := range []byte(value) {
		if char < 32 || char > 126 {
			return false
		}
	}
	return true
}
func zkAPIForbidden(name string) bool {
	if strings.HasPrefix(name, "x-zkweb-") || strings.HasPrefix(name, "x-forwarded-") {
		return true
	}
	switch name {
	case "host", "content-length", "connection", "proxy-connection", "keep-alive", "te", "trailer", "transfer-encoding", "upgrade", "expect", "proxy-authorization", "proxy-authenticate", "authorization", "cookie", "set-cookie", "forwarded", "via", "x-real-ip", "accept-encoding":
		return true
	}
	return false
}
func zkCanonicalAPIHeaders(headers []zkAPIHeader) ([]zkAPIHeader, error) {
	if len(headers) > zkAPIHeaderCount {
		return nil, errors.New("too many headers")
	}
	canonical := make([]zkAPIHeader, 0, len(headers))
	bytes := 0
	for _, header := range headers {
		name, value := strings.ToLower(header.Name), strings.Trim(header.Value, " ")
		if !zkAPIHeaderToken(name) || zkAPIForbidden(name) || !zkAPIHeaderValue(value) {
			return nil, errors.New("invalid header")
		}
		bytes += len(name) + len(value)
		if bytes > zkAPIHeaderBytes {
			return nil, errors.New("headers exceed limit")
		}
		canonical = append(canonical, zkAPIHeader{Name: name, Value: value})
	}
	sort.SliceStable(canonical, func(i, j int) bool { return canonical[i].Name < canonical[j].Name })
	encoded, _ := json.Marshal(canonical)
	if len(encoded) > zkAPIHeaderBytes {
		return nil, errors.New("headers exceed serialized limit")
	}
	return canonical, nil
}

func zkAPIReadBody(path string) ([]byte, error) {
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
	if err != nil || !info.Mode().IsRegular() || info.Size() > zkAPIBodyLimit {
		return nil, errors.New("invalid file")
	}
	body, err := io.ReadAll(io.LimitReader(file, zkAPIBodyLimit+1))
	if err != nil || len(body) > zkAPIBodyLimit {
		return nil, errors.New("body exceeds limit")
	}
	return body, nil
}

func validateZKAPIResult(raw []byte, method, path, upstream string) ([]byte, error) {
	if len(raw) > zkOutputLimit || privateObject(raw, "format", "method", "path", "upstream", "status", "headers", "body_base64") != nil {
		return nil, errors.New("invalid API result")
	}
	var result struct {
		Format   string        `json:"format"`
		Method   string        `json:"method"`
		Path     string        `json:"path"`
		Upstream string        `json:"upstream"`
		Status   uint16        `json:"status"`
		Headers  []zkAPIHeader `json:"headers"`
		Body     string        `json:"body_base64"`
	}
	if json.Unmarshal(raw, &result) != nil || result.Format != "zkweb-zk-api-result-v1" || result.Method != method || result.Path != path || result.Status < 200 || result.Status > 599 || len(result.Headers) > zkAPIHeaderCount {
		return nil, errors.New("invalid API result")
	}
	canonical, err := zkCanonicalUpstream(result.Upstream)
	if err != nil || canonical != upstream {
		return nil, errors.New("unexpected upstream origin")
	}
	result.Upstream = canonical
	count := 0
	for _, header := range result.Headers {
		if !zkAPIHeaderToken(header.Name) || !zkAPIHeaderValue(header.Value) {
			return nil, errors.New("invalid response header")
		}
		count += len(header.Name) + len(header.Value)
	}
	body, err := base64.StdEncoding.DecodeString(result.Body)
	if count > zkAPIHeaderBytes || err != nil || len(body) > zkAPIBodyLimit || base64.StdEncoding.EncodeToString(body) != result.Body {
		return nil, errors.New("invalid response body")
	}
	return json.Marshal(result)
}
