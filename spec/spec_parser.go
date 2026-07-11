package spec

import (
	"fmt"
	"net/url"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// SpecEndpoint represents one documented API endpoint from the spec
type SpecEndpoint struct {
	Method  string
	Path    string
	Tag     string
	Summary string
}

type serverObj struct {
	URL string `yaml:"url"`
}

// rawSpec maps the top-level fields we care about from the YAML file
type rawSpec struct {
	Swagger  string                          `yaml:"swagger"`
	OpenAPI  string                          `yaml:"openapi"`
	BasePath string                          `yaml:"basePath"`
	Servers  []serverObj                     `yaml:"servers"`
	Paths    map[string]map[string]yaml.Node `yaml:"paths"`
}

// methodDetails helps us extract tags and summary without fully parsing the complex OpenAPI schema
type methodDetails struct {
	Tags    []string `yaml:"tags"`
	Summary string   `yaml:"summary"`
}

// getBasePathPrefix extracts the base path from Swagger 2.0 or OpenAPI 3.0
func getBasePathPrefix(raw rawSpec) string {
	if raw.BasePath != "" && raw.BasePath != "/" {
		return raw.BasePath
	}
	if len(raw.Servers) > 0 {
		// Parse the first server URL to extract the path component
		u, err := url.Parse(raw.Servers[0].URL)
		if err == nil && u.Path != "" && u.Path != "/" {
			return u.Path
		}
	}
	return ""
}

// LoadSpec reads a YAML or JSON spec and returns all documented endpoints
func LoadSpec(filePath string) ([]SpecEndpoint, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("could not read spec file: %w", err)
	}

	var raw rawSpec
	lowerPath := strings.ToLower(filePath)

	if strings.HasSuffix(lowerPath, ".yaml") || strings.HasSuffix(lowerPath, ".yml") {
		if err := yaml.Unmarshal(data, &raw); err != nil {
			return nil, fmt.Errorf("could not parse YAML: %w", err)
		}
	} else if strings.HasSuffix(lowerPath, ".json") {
		// yaml.v3 natively supports JSON parsing as it is a subset of YAML
		if err := yaml.Unmarshal(data, &raw); err != nil {
			return nil, fmt.Errorf("could not parse JSON: %w", err)
		}
	} else {
		return nil, fmt.Errorf("unsupported format: only YAML and JSON are supported")
	}

	// Detect which spec version this is
	if raw.Swagger == "2.0" || strings.HasPrefix(raw.Swagger, "2.") {
		fmt.Println("Parsing Swagger 2.0 spec")
	} else if strings.HasPrefix(raw.OpenAPI, "3.") {
		fmt.Println("Parsing OpenAPI", raw.OpenAPI)
	} else {
		return nil, fmt.Errorf("unrecognised spec: must be Swagger 2.0 or OpenAPI 3.x")
	}

	prefix := getBasePathPrefix(raw)
	return extractEndpoints(raw.Paths, prefix), nil
}

// extractEndpoints pulls every method+path combo from the paths map, along with metadata
func extractEndpoints(paths map[string]map[string]yaml.Node, prefix string) []SpecEndpoint {
	var endpoints []SpecEndpoint

	for path, methods := range paths {
		fullPath := path
		if prefix != "" && !strings.HasPrefix(path, prefix) {
			fullPath = strings.TrimRight(prefix, "/") + "/" + strings.TrimLeft(path, "/")
		}

		for method, node := range methods {
			// Skip top-level keys that aren't HTTP methods (e.g. 'parameters', '$ref')
			switch strings.ToLower(method) {
			case "get", "post", "put", "delete", "patch", "options", "head", "trace":
				var details methodDetails
				_ = node.Decode(&details)

				tag := "Uncategorized"
				if len(details.Tags) > 0 {
					tag = details.Tags[0]
				}

				endpoints = append(endpoints, SpecEndpoint{
					Method:  strings.ToUpper(method),
					Path:    fullPath,
					Tag:     tag,
					Summary: details.Summary,
				})
			}
		}
	}

	return endpoints
}
