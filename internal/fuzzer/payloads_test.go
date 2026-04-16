package fuzzer

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadPayloads(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "payloads.txt")

	content := "# comment\n\nbaseline\thello-world\nplain-payload\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write payload file: %v", err)
	}

	payloads, err := LoadPayloads(path)
	if err != nil {
		t.Fatalf("LoadPayloads returned error: %v", err)
	}

	if len(payloads) != 2 {
		t.Fatalf("expected 2 payloads, got %d", len(payloads))
	}

	if payloads[0].Label != "baseline" || payloads[0].Payload != "hello-world" {
		t.Fatalf("unexpected first payload: %#v", payloads[0])
	}

	if payloads[1].Label != "case-002" || payloads[1].Payload != "plain-payload" {
		t.Fatalf("unexpected second payload: %#v", payloads[1])
	}
}
