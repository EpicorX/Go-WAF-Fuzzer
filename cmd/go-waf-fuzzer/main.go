package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/EpicorX/Go-WAF-Fuzzer/internal/fuzzer"
)

func main() {
	cfg, err := fuzzer.ParseConfig(os.Args[1:])
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Print(fuzzer.Usage())
			return
		}

		fmt.Fprintln(os.Stderr, err)
		fmt.Fprintln(os.Stderr)
		fmt.Fprint(os.Stderr, fuzzer.Usage())
		os.Exit(2)
	}

	payloads, err := fuzzer.LoadPayloads(cfg.PayloadFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load payloads: %v\n", err)
		os.Exit(1)
	}

	summary, err := fuzzer.Run(context.Background(), cfg, payloads)
	if err != nil {
		fmt.Fprintf(os.Stderr, "run regression suite: %v\n", err)
		os.Exit(1)
	}

	fmt.Print(fuzzer.RenderConsole(cfg, summary))

	if cfg.JSONOutput != "" {
		if err := fuzzer.WriteJSONReport(cfg, summary); err != nil {
			fmt.Fprintf(os.Stderr, "\nwrite json report: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("\nJSON report written to %s\n", cfg.JSONOutput)
	}
}
