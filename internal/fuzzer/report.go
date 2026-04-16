package fuzzer

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

type jsonReport struct {
	GeneratedAt   string       `json:"generated_at"`
	Config        jsonConfig   `json:"config"`
	Summary       jsonSummary  `json:"summary"`
	ReviewSamples []jsonResult `json:"review_samples"`
}

type jsonConfig struct {
	TargetURL   string            `json:"target_url"`
	PayloadFile string            `json:"payload_file"`
	Method      string            `json:"method"`
	Mode        string            `json:"mode"`
	Parameter   string            `json:"parameter"`
	Workers     int               `json:"workers"`
	Timeout     string            `json:"timeout"`
	BlockCodes  []int             `json:"block_codes"`
	AllowCodes  []int             `json:"allow_codes"`
	Headers     map[string]string `json:"headers,omitempty"`
}

type jsonSummary struct {
	Total        int            `json:"total"`
	Blocked      int            `json:"blocked"`
	Allowed      int            `json:"allowed"`
	Unexpected   int            `json:"unexpected"`
	Errors       int            `json:"errors"`
	BlockRate    string         `json:"block_rate"`
	AllowRate    string         `json:"allow_rate"`
	AvgLatency   string         `json:"avg_latency"`
	Fastest      string         `json:"fastest"`
	Slowest      string         `json:"slowest"`
	StatusCounts map[string]int `json:"status_counts"`
	StartedAt    string         `json:"started_at"`
	CompletedAt  string         `json:"completed_at"`
}

type jsonResult struct {
	Label      string `json:"label"`
	Line       int    `json:"line"`
	Payload    string `json:"payload"`
	StatusCode int    `json:"status_code,omitempty"`
	Decision   string `json:"decision"`
	Duration   string `json:"duration"`
	Error      string `json:"error,omitempty"`
}

func RenderConsole(cfg Config, summary Summary) string {
	var builder strings.Builder

	builder.WriteString("WAF Regression Summary\n\n")
	builder.WriteString(renderTable(
		[]string{"Metric", "Value"},
		[][]string{
			{"Target", cfg.TargetURL},
			{"Method", cfg.Method},
			{"Mode", cfg.Mode},
			{"Payload file", cfg.PayloadFile},
			{"Payloads", strconv.Itoa(summary.Total)},
			{"Blocked", fmt.Sprintf("%d (%.1f%%)", summary.Blocked, summary.BlockRate)},
			{"Allowed", fmt.Sprintf("%d (%.1f%%)", summary.Allowed, summary.AllowRate)},
			{"Unexpected", strconv.Itoa(summary.Unexpected)},
			{"Errors", strconv.Itoa(summary.Errors)},
			{"Avg latency", formatDuration(summary.AvgLatency)},
			{"Fastest", formatDuration(summary.Fastest)},
			{"Slowest", formatDuration(summary.Slowest)},
		},
	))

	if len(summary.StatusCounts) > 0 {
		builder.WriteString("\nStatus Breakdown\n\n")
		rows := make([][]string, 0, len(summary.StatusCounts))
		for _, code := range sortedStatusCodes(summary.StatusCounts) {
			rows = append(rows, []string{strconv.Itoa(code), strconv.Itoa(summary.StatusCounts[code])})
		}
		builder.WriteString(renderTable([]string{"HTTP Status", "Count"}, rows))
	}

	if len(summary.ReviewSamples) > 0 {
		builder.WriteString("\nReview Samples\n\n")
		rows := make([][]string, 0, len(summary.ReviewSamples))
		for _, sample := range summary.ReviewSamples {
			status := "-"
			if sample.StatusCode > 0 {
				status = strconv.Itoa(sample.StatusCode)
			}
			rows = append(rows, []string{
				sample.Label,
				sample.Decision,
				status,
				formatDuration(sample.Duration),
				compact(sample.Payload, 56),
			})
		}
		builder.WriteString(renderTable([]string{"Label", "Decision", "Status", "Latency", "Payload"}, rows))
	}

	return builder.String()
}

func WriteJSONReport(cfg Config, summary Summary) error {
	report := jsonReport{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Config: jsonConfig{
			TargetURL:   cfg.TargetURL,
			PayloadFile: cfg.PayloadFile,
			Method:      cfg.Method,
			Mode:        cfg.Mode,
			Parameter:   cfg.Parameter,
			Workers:     cfg.Workers,
			Timeout:     cfg.Timeout.String(),
			BlockCodes:  sortedStatusSet(cfg.BlockCodes),
			AllowCodes:  sortedStatusSet(cfg.AllowCodes),
			Headers:     cfg.Headers,
		},
		Summary: jsonSummary{
			Total:        summary.Total,
			Blocked:      summary.Blocked,
			Allowed:      summary.Allowed,
			Unexpected:   summary.Unexpected,
			Errors:       summary.Errors,
			BlockRate:    fmt.Sprintf("%.1f%%", summary.BlockRate),
			AllowRate:    fmt.Sprintf("%.1f%%", summary.AllowRate),
			AvgLatency:   formatDuration(summary.AvgLatency),
			Fastest:      formatDuration(summary.Fastest),
			Slowest:      formatDuration(summary.Slowest),
			StatusCounts: stringifyStatusCounts(summary.StatusCounts),
			StartedAt:    summary.StartedAt.UTC().Format(time.RFC3339),
			CompletedAt:  summary.CompletedAt.UTC().Format(time.RFC3339),
		},
		ReviewSamples: toJSONResults(summary.ReviewSamples),
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(cfg.JSONOutput, data, 0o644)
}

func renderTable(headers []string, rows [][]string) string {
	widths := make([]int, len(headers))
	for i, header := range headers {
		widths[i] = len(header)
	}

	for _, row := range rows {
		for i, cell := range row {
			if i >= len(widths) {
				continue
			}
			if len(cell) > widths[i] {
				widths[i] = len(cell)
			}
		}
	}

	var builder strings.Builder
	writeRow(&builder, headers, widths)
	writeSeparator(&builder, widths)
	for _, row := range rows {
		writeRow(&builder, row, widths)
	}

	return builder.String()
}

func writeRow(builder *strings.Builder, row []string, widths []int) {
	for i, width := range widths {
		cell := ""
		if i < len(row) {
			cell = row[i]
		}
		builder.WriteString(cell)
		if pad := width - len(cell); pad > 0 {
			builder.WriteString(strings.Repeat(" ", pad))
		}
		if i < len(widths)-1 {
			builder.WriteString("  ")
		}
	}
	builder.WriteByte('\n')
}

func writeSeparator(builder *strings.Builder, widths []int) {
	for i, width := range widths {
		builder.WriteString(strings.Repeat("-", width))
		if i < len(widths)-1 {
			builder.WriteString("  ")
		}
	}
	builder.WriteByte('\n')
}

func sortedStatusCodes(counts map[int]int) []int {
	codes := make([]int, 0, len(counts))
	for code := range counts {
		codes = append(codes, code)
	}
	sort.Ints(codes)
	return codes
}

func sortedStatusSet(values map[int]struct{}) []int {
	codes := make([]int, 0, len(values))
	for code := range values {
		codes = append(codes, code)
	}
	sort.Ints(codes)
	return codes
}

func stringifyStatusCounts(counts map[int]int) map[string]int {
	out := make(map[string]int, len(counts))
	for code, count := range counts {
		out[strconv.Itoa(code)] = count
	}
	return out
}

func toJSONResults(results []Result) []jsonResult {
	out := make([]jsonResult, 0, len(results))
	for _, result := range results {
		out = append(out, jsonResult{
			Label:      result.Label,
			Line:       result.Line,
			Payload:    result.Payload,
			StatusCode: result.StatusCode,
			Decision:   result.Decision,
			Duration:   formatDuration(result.Duration),
			Error:      result.Error,
		})
	}
	return out
}

func compact(value string, limit int) string {
	if limit <= 0 || len(value) <= limit {
		return value
	}

	if limit <= 3 {
		return value[:limit]
	}

	return value[:limit-3] + "..."
}

func formatDuration(value time.Duration) string {
	if value <= 0 {
		return "0s"
	}
	return value.Round(time.Millisecond).String()
}
