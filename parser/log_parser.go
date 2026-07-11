package parser

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
)

// LogEntry represents a single parsed line from an Nginx/Apache access log
type LogEntry struct {
	IP        string
	Method    string
	Path      string
	Protocol  string
	Status    int
	Bytes     int
	UserAgent string
}

// Combined Log Format pattern:
// IP - - [timestamp] "Method /path HTTP/1.1" STATUS BYTES "referrer" "user-agent"
var logPattern = regexp.MustCompile(
	`^(\S+)\s+\S+\s+\S+\s+\[.*?\]\s+"(\w+)\s+(\S+)\s+(\S+)"\s+(\d+)\s+(\d+)\s+"[^"]*"\s+"([^"]*)"`,
)

// ParseLog reads an access log file and returns a slice of LogEntry
func ParseLog(filePath string) ([]LogEntry, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("could not open log file: %w", err)
	}
	defer file.Close()

	var entries []LogEntry
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		entry, err := parseLine(line)
		if err != nil {
			// skip malformed lines silently
			continue
		}
		entries = append(entries, entry)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading log file: %w", err)
	}
	return entries, nil
}

// parseLine extracts fields from a single log line
func parseLine(line string) (LogEntry, error) {
	matches := logPattern.FindStringSubmatch(line)
	if matches == nil {
		return LogEntry{}, fmt.Errorf("line did not match log pattern")
	}

	var status, bytes int
	fmt.Sscanf(matches[5], "%d", &status)
	fmt.Sscanf(matches[6], "%d", &bytes)

	return LogEntry{
		IP:        matches[1],
		Method:    matches[2],
		Path:      matches[3],
		Protocol:  matches[4],
		Status:    status,
		Bytes:     bytes,
		UserAgent: matches[7],
	}, nil
}
