package engine

import (
	"regexp"
	"strings"

	"shadow-api-scanner/parser"
	"shadow-api-scanner/spec"
)

// Finding represents an API endpoint in the attack surface
type Finding struct {
	Method        string
	Path          string
	IsDocumented  bool
	Tag           string
	Summary       string
	OWASPCategory string
}

// compiledEndpoint pairs a spec endpoint with its compiled regex pattern
type compiledEndpoint struct {
	Method  string
	Pattern *regexp.Regexp
}

// templateToRegex converts an OpenAPI path template into a compiled regex
func templateToRegex(path string) *regexp.Regexp {
	paramPattern := regexp.MustCompile(`\{[^}]+\}`)
	regexStr := paramPattern.ReplaceAllString(path, `([^/]+)`)
	return regexp.MustCompile(`^` + regexStr + `$`)
}

// compileSpecEndpoints converts all spec endpoints into regex-based matchers
func compileSpecEndpoints(endpoints []spec.SpecEndpoint) []compiledEndpoint {
	compiled := make([]compiledEndpoint, 0, len(endpoints))
	for _, ep := range endpoints {
		compiled = append(compiled, compiledEndpoint{
			Method:  ep.Method,
			Pattern: templateToRegex(ep.Path),
		})
	}
	return compiled
}

// determineOWASPCategory assigns an OWASP Top 10 category to Shadow APIs
func determineOWASPCategory(path string) string {
	lowerPath := strings.ToLower(path)
	if strings.Contains(lowerPath, "/admin/") || strings.Contains(lowerPath, "/internal/") {
		return "API5:2023 Broken Function Level Authorization"
	}
	if strings.Contains(lowerPath, "/debug/") || strings.Contains(lowerPath, "/config/") || strings.Contains(lowerPath, "/dump") {
		return "API8:2023 Security Misconfiguration"
	}
	return "API9:2023 Improper Inventory Management"
}

// isDocumented checks if a log entry matches any documented spec endpoint
func isDocumented(entry parser.LogEntry, compiled []compiledEndpoint) bool {
	for _, ep := range compiled {
		if ep.Method == entry.Method && ep.Pattern.MatchString(entry.Path) {
			return true
		}
	}
	return false
}

// buildDocumentedFindings converts the spec endpoints into documented Findings
func buildDocumentedFindings(endpoints []spec.SpecEndpoint) []Finding {
	var findings []Finding
	for _, ep := range endpoints {
		findings = append(findings, Finding{
			Method:       ep.Method,
			Path:         ep.Path,
			IsDocumented: true,
			Tag:          ep.Tag,
			Summary:      ep.Summary,
		})
	}
	return findings
}

// findShadowAPIs scans logs for requests that don't match the spec
func findShadowAPIs(entries []parser.LogEntry, compiled []compiledEndpoint) []Finding {
	var shadowFindings []Finding
	seenUndoc := make(map[string]bool)

	for _, entry := range entries {
		// Only flag successful requests - 404s are not active APIs
		if entry.Status < 200 || entry.Status >= 300 {
			continue
		}

		if !isDocumented(entry, compiled) {
			key := entry.Method + ":" + entry.Path
			if !seenUndoc[key] {
				seenUndoc[key] = true
				shadowFindings = append(shadowFindings, Finding{
					Method:        entry.Method,
					Path:          entry.Path,
					IsDocumented:  false,
					Tag:           "Undocumented",
					OWASPCategory: determineOWASPCategory(entry.Path),
				})
			}
		}
	}

	return shadowFindings
}

// Reconcile maps out the entire active API attack surface
func Reconcile(entries []parser.LogEntry, endpoints []spec.SpecEndpoint) []Finding {
	compiled := compileSpecEndpoints(endpoints)
	
	// 1. Get all documented APIs
	findings := buildDocumentedFindings(endpoints)

	// 2. Add undocumented Shadow APIs found in logs
	shadows := findShadowAPIs(entries, compiled)
	findings = append(findings, shadows...)

	return findings
}
