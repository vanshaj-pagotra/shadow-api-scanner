package main

import (
	"flag"
	"fmt"
	"os"

	"shadow-api-scanner/engine"
	"shadow-api-scanner/parser"
	"shadow-api-scanner/report"
	"shadow-api-scanner/spec"
)

func main() {
	// Define command-line flags
	logFile := flag.String("log", "testdata/access.log", "path to Nginx/Apache access log")
	specFile := flag.String("spec", "testdata/abha_api_v3.yaml", "path to OpenAPI/Swagger spec (YAML)")
	outFile := flag.String("out", "output/report.html", "output HTML report file")
	flag.Parse()

	// Parse the access log
	fmt.Printf("Parsing log file: %s\n", *logFile)
	entries, err := parser.ParseLog(*logFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf(" %d log entries loaded\n", len(entries))

	// Load the API spec
	fmt.Printf("Loading spec file: %s\n", *specFile)
	endpoints, err := spec.LoadSpec(*specFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf(" %d documented endpoints found\n", len(endpoints))

	// Find active API attack surface
	fmt.Println("Running reconcilation...")
	findings := engine.Reconcile(entries, endpoints)
	shadowCount := 0
	docCount := 0
	for _, f := range findings {
		if !f.IsDocumented {
			shadowCount++
		} else {
			docCount++
		}
	}
	fmt.Printf(" %d documented API(s) and %d shadow API(s) mapped\n", docCount, shadowCount)

	// Write the HTML report
	fmt.Printf("Writing report:		%s\n", *outFile)
	err = report.Generate(*outFile, *specFile, *logFile, len(entries), findings)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("\nDone.")
}
