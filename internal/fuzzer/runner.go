package fuzzer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"sync"
	"time"
)

const (
	DecisionBlocked    = "blocked"
	DecisionAllowed    = "allowed"
	DecisionUnexpected = "unexpected"
	DecisionError      = "error"
)

type Result struct {
	Label      string
	Line       int
	Payload    string
	StatusCode int
	Decision   string
	Duration   time.Duration
	Error      string
}

type Summary struct {
	StartedAt     time.Time
	CompletedAt   time.Time
	Total         int
	Blocked       int
	Allowed       int
	Unexpected    int
	Errors        int
	BlockRate     float64
	AllowRate     float64
	AvgLatency    time.Duration
	Fastest       time.Duration
	Slowest       time.Duration
	StatusCounts  map[int]int
	ReviewSamples []Result
	Results       []Result
}

func Run(ctx context.Context, cfg Config, payloads []PayloadCase) (Summary, error) {
	baseURL, err := url.Parse(cfg.TargetURL)
	if err != nil {
		return Summary{}, fmt.Errorf("parse target URL: %w", err)
	}

	client := &http.Client{Timeout: cfg.Timeout}
	jobs := make(chan PayloadCase)
	results := make(chan Result, len(payloads))

	startedAt := time.Now()
	var wg sync.WaitGroup

	for i := 0; i < cfg.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for payload := range jobs {
				results <- executeOne(ctx, client, baseURL, cfg, payload)
			}
		}()
	}

	go func() {
		defer close(jobs)
		for _, payload := range payloads {
			select {
			case <-ctx.Done():
				return
			case jobs <- payload:
			}
		}
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	collected := make([]Result, 0, len(payloads))
	for result := range results {
		collected = append(collected, result)
	}

	sort.Slice(collected, func(i, j int) bool {
		return collected[i].Line < collected[j].Line
	})

	if err := ctx.Err(); err != nil && err != context.Canceled {
		return Summary{}, err
	}

	summary := summarize(startedAt, time.Now(), collected, cfg.ReviewSamples)
	return summary, nil
}

func executeOne(ctx context.Context, client *http.Client, baseURL *url.URL, cfg Config, payload PayloadCase) Result {
	started := time.Now()
	result := Result{
		Label:   payload.Label,
		Line:    payload.Line,
		Payload: payload.Payload,
	}

	req, err := buildRequest(ctx, baseURL, cfg, payload.Payload)
	if err != nil {
		result.Decision = DecisionError
		result.Error = err.Error()
		result.Duration = time.Since(started)
		return result
	}

	resp, err := client.Do(req)
	if err != nil {
		result.Decision = DecisionError
		result.Error = err.Error()
		result.Duration = time.Since(started)
		return result
	}
	defer resp.Body.Close()

	_, _ = io.Copy(io.Discard, resp.Body)

	result.StatusCode = resp.StatusCode
	result.Decision = classifyStatus(resp.StatusCode, cfg.BlockCodes, cfg.AllowCodes)
	result.Duration = time.Since(started)
	return result
}

func buildRequest(ctx context.Context, baseURL *url.URL, cfg Config, payload string) (*http.Request, error) {
	cloned := *baseURL

	var body io.Reader
	switch cfg.Mode {
	case "query":
		query := cloned.Query()
		query.Set(cfg.Parameter, payload)
		cloned.RawQuery = query.Encode()
	case "form":
		form := url.Values{}
		form.Set(cfg.Parameter, payload)
		body = bytes.NewBufferString(form.Encode())
	case "json":
		rawBody, err := json.Marshal(map[string]string{cfg.Parameter: payload})
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(rawBody)
	default:
		return nil, fmt.Errorf("unsupported mode %q", cfg.Mode)
	}

	req, err := http.NewRequestWithContext(ctx, cfg.Method, cloned.String(), body)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", "Go-WAF-Fuzzer/1.0")

	switch cfg.Mode {
	case "form":
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	case "json":
		req.Header.Set("Content-Type", "application/json")
	}

	for key, value := range cfg.Headers {
		req.Header.Set(key, value)
	}

	return req, nil
}

func classifyStatus(code int, blocked map[int]struct{}, allowed map[int]struct{}) string {
	if _, ok := blocked[code]; ok {
		return DecisionBlocked
	}
	if _, ok := allowed[code]; ok {
		return DecisionAllowed
	}
	return DecisionUnexpected
}

func summarize(startedAt, completedAt time.Time, results []Result, reviewLimit int) Summary {
	summary := Summary{
		StartedAt:    startedAt,
		CompletedAt:  completedAt,
		Total:        len(results),
		StatusCounts: make(map[int]int),
		Results:      results,
	}

	var totalLatency time.Duration
	for _, result := range results {
		totalLatency += result.Duration
		if summary.Fastest == 0 || result.Duration < summary.Fastest {
			summary.Fastest = result.Duration
		}
		if result.Duration > summary.Slowest {
			summary.Slowest = result.Duration
		}
		if result.StatusCode > 0 {
			summary.StatusCounts[result.StatusCode]++
		}

		switch result.Decision {
		case DecisionBlocked:
			summary.Blocked++
		case DecisionAllowed:
			summary.Allowed++
		case DecisionUnexpected:
			summary.Unexpected++
		case DecisionError:
			summary.Errors++
		}
	}

	if summary.Total > 0 {
		summary.BlockRate = (float64(summary.Blocked) / float64(summary.Total)) * 100
		summary.AllowRate = (float64(summary.Allowed) / float64(summary.Total)) * 100
		summary.AvgLatency = totalLatency / time.Duration(summary.Total)
	}

	summary.ReviewSamples = selectReviewSamples(results, reviewLimit)
	return summary
}

func selectReviewSamples(results []Result, limit int) []Result {
	if limit <= 0 {
		return nil
	}

	selected := make([]Result, 0, limit)
	for _, result := range results {
		if result.Decision == DecisionBlocked {
			continue
		}

		selected = append(selected, result)
		if len(selected) == limit {
			return selected
		}
	}

	return selected
}
