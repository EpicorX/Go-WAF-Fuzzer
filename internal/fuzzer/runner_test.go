package fuzzer

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRunAggregatesResults(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		payload := r.URL.Query().Get("input")
		switch {
		case strings.Contains(payload, "probe"):
			http.Error(w, "blocked", http.StatusForbidden)
		case strings.Contains(payload, "unstable"):
			http.Error(w, "unexpected", http.StatusInternalServerError)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	cfg := Config{
		TargetURL:            server.URL,
		PayloadFile:          "payloads.txt",
		Workers:              3,
		Method:               "GET",
		Mode:                 "query",
		Parameter:            "input",
		Timeout:              2 * time.Second,
		AckAuthorizedTesting: true,
		BlockCodes:           map[int]struct{}{http.StatusForbidden: {}},
		AllowCodes:           map[int]struct{}{http.StatusOK: {}},
		ReviewSamples:        10,
	}

	payloads := []PayloadCase{
		{Label: "baseline", Payload: "hello"},
		{Label: "blocked", Payload: "xss-probe-string"},
		{Label: "unexpected", Payload: "unstable-signal"},
	}

	summary, err := Run(context.Background(), cfg, payloads)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	if summary.Total != 3 {
		t.Fatalf("expected total=3, got %d", summary.Total)
	}
	if summary.Blocked != 1 {
		t.Fatalf("expected blocked=1, got %d", summary.Blocked)
	}
	if summary.Allowed != 1 {
		t.Fatalf("expected allowed=1, got %d", summary.Allowed)
	}
	if summary.Unexpected != 1 {
		t.Fatalf("expected unexpected=1, got %d", summary.Unexpected)
	}
	if summary.Errors != 0 {
		t.Fatalf("expected errors=0, got %d", summary.Errors)
	}
	if got := summary.StatusCounts[http.StatusForbidden]; got != 1 {
		t.Fatalf("expected 403 count=1, got %d", got)
	}
}
