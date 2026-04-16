package fuzzer

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

type PayloadCase struct {
	Label   string
	Payload string
	Line    int
}

func LoadPayloads(path string) ([]PayloadCase, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var (
		cases   []PayloadCase
		lineNo  int
		counter int
	)

	for scanner.Scan() {
		lineNo++
		rawLine := scanner.Text()
		trimmed := strings.TrimSpace(rawLine)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		counter++
		item := PayloadCase{
			Label: fmt.Sprintf("case-%03d", counter),
			Line:  lineNo,
		}

		if strings.Contains(rawLine, "\t") {
			parts := strings.SplitN(rawLine, "\t", 2)
			label := strings.TrimSpace(parts[0])
			payload := strings.TrimSpace(parts[1])
			if label != "" {
				item.Label = label
			}
			item.Payload = payload
		} else {
			item.Payload = trimmed
		}

		if item.Payload == "" {
			return nil, fmt.Errorf("line %d has an empty payload", lineNo)
		}

		cases = append(cases, item)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	if len(cases) == 0 {
		return nil, fmt.Errorf("no payloads found in %s", path)
	}

	return cases, nil
}
