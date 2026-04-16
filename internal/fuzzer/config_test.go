package fuzzer

import "testing"

func TestValidateRejectsRemoteTargetWithoutFlag(t *testing.T) {
	cfg := Config{
		TargetURL:            "https://example.com/inspect",
		PayloadFile:          "examples/payloads.txt",
		Workers:              4,
		Method:               "GET",
		Mode:                 "query",
		Parameter:            "input",
		AckAuthorizedTesting: true,
		BlockCodes:           map[int]struct{}{403: {}},
		AllowCodes:           map[int]struct{}{200: {}},
		ReviewSamples:        4,
	}

	if err := cfg.Validate(); err == nil {
		t.Fatal("expected remote target validation error")
	}
}
