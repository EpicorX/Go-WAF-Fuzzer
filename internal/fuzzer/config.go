package fuzzer

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const defaultUsage = `Go-WAF-Fuzzer

Concurrent WAF regression tester for authorized environments.

Usage:
  go run ./cmd/go-waf-fuzzer [flags]

Examples:
  go run ./examples/mock-server
  go run ./cmd/go-waf-fuzzer -ack-authorized-testing
  go run ./cmd/go-waf-fuzzer -ack-authorized-testing -mode json -method POST

Key flags:
  -url string
        target URL (default "http://127.0.0.1:8080/inspect")
  -payloads string
        newline corpus file, or label<TAB>payload format (default "examples/payloads.txt")
  -workers int
        concurrent worker count (default 8)
  -method string
        HTTP method (default "GET")
  -mode string
        request mode: query, form, json (default "query")
  -param string
        query/form/json field name carrying the payload (default "input")
  -timeout duration
        per-request timeout (default 3s)
  -block-codes string
        comma-separated blocked status codes (default "403")
  -allow-codes string
        comma-separated allowed status codes (default "200")
  -header value
        repeatable custom header in 'Key: Value' format
  -json-out string
        write a structured JSON report to this file
  -ack-authorized-testing
        required safety acknowledgement before any run
  -allow-remote
        allow non-local/private targets after acknowledgement
  -review-samples int
        number of non-blocked/error samples to print (default 8)
`

var errUnauthorizedUsage = errors.New("refusing to run without -ack-authorized-testing")

type Config struct {
	TargetURL            string
	PayloadFile          string
	Workers              int
	Method               string
	Mode                 string
	Parameter            string
	Timeout              time.Duration
	Headers              map[string]string
	BlockCodes           map[int]struct{}
	AllowCodes           map[int]struct{}
	JSONOutput           string
	AckAuthorizedTesting bool
	AllowRemote          bool
	ReviewSamples        int
}

type headerFlag []string

func (h *headerFlag) String() string {
	return strings.Join(*h, ", ")
}

func (h *headerFlag) Set(value string) error {
	*h = append(*h, value)
	return nil
}

func Usage() string {
	return defaultUsage
}

func ParseConfig(args []string) (Config, error) {
	fs := flag.NewFlagSet("go-waf-fuzzer", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	cfg := Config{}
	headers := headerFlag{}
	blockCodes := "403"
	allowCodes := "200"

	fs.StringVar(&cfg.TargetURL, "url", "http://127.0.0.1:8080/inspect", "")
	fs.StringVar(&cfg.PayloadFile, "payloads", "examples/payloads.txt", "")
	fs.IntVar(&cfg.Workers, "workers", 8, "")
	fs.StringVar(&cfg.Method, "method", "GET", "")
	fs.StringVar(&cfg.Mode, "mode", "query", "")
	fs.StringVar(&cfg.Parameter, "param", "input", "")
	fs.DurationVar(&cfg.Timeout, "timeout", 3*time.Second, "")
	fs.StringVar(&blockCodes, "block-codes", blockCodes, "")
	fs.StringVar(&allowCodes, "allow-codes", allowCodes, "")
	fs.Var(&headers, "header", "")
	fs.StringVar(&cfg.JSONOutput, "json-out", "", "")
	fs.BoolVar(&cfg.AckAuthorizedTesting, "ack-authorized-testing", false, "")
	fs.BoolVar(&cfg.AllowRemote, "allow-remote", false, "")
	fs.IntVar(&cfg.ReviewSamples, "review-samples", 8, "")

	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}

	cfg.Method = strings.ToUpper(strings.TrimSpace(cfg.Method))
	cfg.Mode = strings.ToLower(strings.TrimSpace(cfg.Mode))
	cfg.TargetURL = strings.TrimSpace(cfg.TargetURL)
	cfg.PayloadFile = strings.TrimSpace(cfg.PayloadFile)
	cfg.Parameter = strings.TrimSpace(cfg.Parameter)
	cfg.JSONOutput = strings.TrimSpace(cfg.JSONOutput)

	headersMap, err := parseHeaders(headers)
	if err != nil {
		return Config{}, err
	}

	blockSet, err := parseStatusCodes(blockCodes)
	if err != nil {
		return Config{}, fmt.Errorf("parse block-codes: %w", err)
	}

	allowSet, err := parseStatusCodes(allowCodes)
	if err != nil {
		return Config{}, fmt.Errorf("parse allow-codes: %w", err)
	}

	cfg.Headers = headersMap
	cfg.BlockCodes = blockSet
	cfg.AllowCodes = allowSet

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

func (c Config) Validate() error {
	if !c.AckAuthorizedTesting {
		return errUnauthorizedUsage
	}

	if c.TargetURL == "" {
		return errors.New("target URL is required")
	}

	if c.PayloadFile == "" {
		return errors.New("payload file is required")
	}

	if c.Parameter == "" {
		return errors.New("param cannot be empty")
	}

	if c.Workers <= 0 {
		return errors.New("workers must be greater than zero")
	}

	if c.ReviewSamples < 0 {
		return errors.New("review-samples cannot be negative")
	}

	switch c.Mode {
	case "query", "form", "json":
	default:
		return fmt.Errorf("unsupported mode %q", c.Mode)
	}

	targetURL, err := url.Parse(c.TargetURL)
	if err != nil {
		return fmt.Errorf("invalid target URL: %w", err)
	}

	if targetURL.Scheme != "http" && targetURL.Scheme != "https" {
		return fmt.Errorf("unsupported URL scheme %q", targetURL.Scheme)
	}

	if targetURL.Hostname() == "" {
		return errors.New("target URL must include a host")
	}

	if !c.AllowRemote && !isLocalOrPrivateHost(targetURL.Hostname()) {
		return fmt.Errorf("target host %q is not local/private; rerun with -allow-remote only for authorized lab targets", targetURL.Hostname())
	}

	if len(c.BlockCodes) == 0 {
		return errors.New("at least one block status code is required")
	}

	if len(c.AllowCodes) == 0 {
		return errors.New("at least one allow status code is required")
	}

	return nil
}

func parseHeaders(values []string) (map[string]string, error) {
	headers := make(map[string]string, len(values))
	for _, value := range values {
		parts := strings.SplitN(value, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid header %q, want 'Key: Value'", value)
		}

		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		if key == "" {
			return nil, fmt.Errorf("invalid header %q, key cannot be empty", value)
		}

		headers[key] = val
	}

	return headers, nil
}

func parseStatusCodes(raw string) (map[int]struct{}, error) {
	result := make(map[int]struct{})
	for _, piece := range strings.Split(raw, ",") {
		piece = strings.TrimSpace(piece)
		if piece == "" {
			continue
		}

		code, err := strconv.Atoi(piece)
		if err != nil {
			return nil, fmt.Errorf("invalid status code %q", piece)
		}

		if code < 100 || code > 599 {
			return nil, fmt.Errorf("status code %d is out of range", code)
		}

		result[code] = struct{}{}
	}

	return result, nil
}

func isLocalOrPrivateHost(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return false
	}

	if host == "localhost" {
		return true
	}

	if strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".internal") || strings.HasSuffix(host, ".lan") {
		return true
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}

	return ip.IsLoopback() || ip.IsPrivate()
}
