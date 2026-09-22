// Redfish enrichment: requests each unique configured Redfish path once per
// host, reuses the JSON payload across fields, and resolves RFC 6901 JSON
// pointers into CSV values. Numbers are decoded as json.Number so values keep
// their original literal form.

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

func decodeJSONPointerToken(token string) string {
	return strings.NewReplacer("~1", "/", "~0", "~").Replace(token)
}

func resolveJSONPointer(document any, pointer string) (bool, any) {
	if pointer == "" {
		return true, document
	}
	if !strings.HasPrefix(pointer, "/") {
		return false, nil
	}

	current := document
	for _, rawToken := range strings.Split(pointer, "/")[1:] {
		token := decodeJSONPointerToken(rawToken)

		switch node := current.(type) {
		case []any:
			if !isAllDigits(token) {
				return false, nil
			}
			index, err := strconv.Atoi(token)
			if err != nil || index < 0 || index >= len(node) {
				return false, nil
			}
			current = node[index]
		case map[string]any:
			value, ok := node[token]
			if !ok {
				return false, nil
			}
			current = value
		default:
			return false, nil
		}
	}

	return true, current
}

func normalizeJSONValue(value any) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case bool:
		if typed {
			return "true"
		}
		return "false"
	case json.Number:
		return typed.String()
	case string:
		return strings.TrimSpace(typed)
	}

	encoded, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	return string(encoded)
}

func flattenJSONValues(value any) []string {
	if items, ok := value.([]any); ok {
		var flattened []string
		for _, item := range items {
			flattened = append(flattened, flattenJSONValues(item)...)
		}
		return flattened
	}
	return []string{normalizeJSONValue(value)}
}

func extractRedfishFields(payloadByPath map[string]any, fieldSpecs []RedfishField) map[string]string {
	extracted := make(map[string]string, len(fieldSpecs))

	for _, spec := range fieldSpecs {
		mode := fieldMode(spec.Mode)
		separator := fieldSeparator(spec.Separator)
		paths := candidateRedfishPaths(spec)
		pointers := candidateRedfishPointers(spec)

		if mode == "all" {
			var collected []string
			for _, path := range paths {
				payload, ok := payloadByPath[normalizePath(path)]
				if !ok {
					continue
				}
				for _, pointer := range pointers {
					found, rawValue := resolveJSONPointer(payload, pointer)
					if !found {
						continue
					}
					for _, value := range flattenJSONValues(rawValue) {
						if value != "" && !isFilteredValue(value, spec.ExcludeValues) {
							collected = append(collected, value)
						}
					}
				}
			}

			if len(collected) == 0 {
				extracted[spec.Name] = missingValue
			} else {
				extracted[spec.Name] = strings.Join(collected, separator)
			}
			continue
		}

		found := false
		for _, path := range paths {
			payload, ok := payloadByPath[normalizePath(path)]
			if !ok {
				continue
			}
			for _, pointer := range pointers {
				resolved, rawValue := resolveJSONPointer(payload, pointer)
				if !resolved {
					continue
				}

				var values []string
				for _, value := range flattenJSONValues(rawValue) {
					if value != "" && !isFilteredValue(value, spec.ExcludeValues) {
						values = append(values, value)
					}
				}
				if len(values) == 0 {
					continue
				}

				extracted[spec.Name] = values[0]
				found = true
				break
			}
			if found {
				break
			}
		}

		if !found {
			extracted[spec.Name] = missingValue
		}
	}

	return extracted
}

func fetchRedfishFieldsForHost(client *http.Client, ip, scheme string, fieldSpecs []RedfishField) (map[string]string, string) {
	if len(fieldSpecs) == 0 {
		return nil, ""
	}

	var uniquePaths []string
	seenPaths := make(map[string]bool)
	for _, spec := range fieldSpecs {
		for _, path := range candidateRedfishPaths(spec) {
			normalizedPath := normalizePath(path)
			if !seenPaths[normalizedPath] {
				seenPaths[normalizedPath] = true
				uniquePaths = append(uniquePaths, normalizedPath)
			}
		}
	}

	payloadByPath := make(map[string]any, len(uniquePaths))
	var requestErrors []string

	for _, normalizedPath := range uniquePaths {
		url := fmt.Sprintf("%s://%s%s", scheme, ip, normalizedPath)

		resp, err := client.Get(url)
		if err != nil {
			requestErrors = append(requestErrors, fmt.Sprintf("%s: %s", normalizedPath, err))
			continue
		}

		body, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			requestErrors = append(requestErrors, fmt.Sprintf("%s: %s", normalizedPath, readErr))
			continue
		}

		if resp.StatusCode >= 400 {
			requestErrors = append(requestErrors, fmt.Sprintf("%s: HTTP %d", normalizedPath, resp.StatusCode))
		}

		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.UseNumber()
		var payload any
		if err := decoder.Decode(&payload); err != nil {
			requestErrors = append(requestErrors, fmt.Sprintf("%s: response was not JSON", normalizedPath))
			continue
		}
		payloadByPath[normalizedPath] = payload
	}

	extracted := extractRedfishFields(payloadByPath, fieldSpecs)
	return extracted, strings.Join(requestErrors, "; ")
}

func normalizePath(path string) string {
	if strings.HasPrefix(path, "/") {
		return path
	}
	return "/" + path
}
