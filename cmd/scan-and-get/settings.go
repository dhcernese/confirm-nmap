// Settings file: loads and validates the JSON configuration shared with the
// Python implementation (request, nmap, execution, redfish and xml_fields
// blocks) and provides the helpers that resolve the optional/aliased keys such
// as xpath vs xpaths, path vs request_paths, and mode/separator defaults.

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// XMLField mirrors one entry of settings.xml_fields.
type XMLField struct {
	Name          string   `json:"name"`
	XPath         string   `json:"xpath"`
	XPaths        []string `json:"xpaths"`
	Mode          string   `json:"mode"`
	Separator     *string  `json:"separator"`
	ExcludeValues []string `json:"exclude_values"`
}

// RedfishField mirrors one entry of settings.redfish.fields.
type RedfishField struct {
	Name          string   `json:"name"`
	Path          string   `json:"path"`
	RequestPath   string   `json:"request_path"`
	Paths         []string `json:"paths"`
	RequestPaths  []string `json:"request_paths"`
	JSONPointer   string   `json:"json_pointer"`
	Pointer       string   `json:"pointer"`
	JSONPointers  []string `json:"json_pointers"`
	Pointers      []string `json:"pointers"`
	Mode          string   `json:"mode"`
	Separator     *string  `json:"separator"`
	ExcludeValues []string `json:"exclude_values"`
}

type RequestSettings struct {
	Scheme  string   `json:"scheme"`
	Path    string   `json:"path"`
	Timeout *float64 `json:"timeout"`
}

type NmapSettings struct {
	Args     *string `json:"args"`
	ArgsFile *string `json:"args_file"`
}

type ExecutionSettings struct {
	Workers       *int `json:"workers"`
	MaxTargets    *int `json:"max_targets"`
	ProgressEvery *int `json:"progress_every"`
}

type RedfishSettings struct {
	Enabled *bool          `json:"enabled"`
	Timeout *float64       `json:"timeout"`
	Fields  []RedfishField `json:"fields"`
}

type Settings struct {
	Request   RequestSettings   `json:"request"`
	Nmap      NmapSettings      `json:"nmap"`
	Execution ExecutionSettings `json:"execution"`
	Redfish   *RedfishSettings  `json:"redfish"`
	XMLFields []XMLField        `json:"xml_fields"`
}

func loadSettings(settingsPath string) (*Settings, error) {
	raw, err := os.ReadFile(settingsPath)
	if err != nil {
		return nil, fmt.Errorf("could not read settings file '%s': %w", settingsPath, err)
	}

	var settings Settings
	if err := json.Unmarshal(raw, &settings); err != nil {
		return nil, fmt.Errorf("invalid JSON in settings file '%s': %w", settingsPath, err)
	}

	if err := validateSettings(&settings); err != nil {
		return nil, err
	}

	return &settings, nil
}

func validateSettings(settings *Settings) error {
	if len(settings.XMLFields) == 0 {
		return fmt.Errorf("settings must define a non-empty 'xml_fields' array")
	}

	for idx, field := range settings.XMLFields {
		if field.Name == "" {
			return fmt.Errorf("xml_fields[%d].name must be a non-empty string", idx)
		}

		hasXPaths := len(field.XPaths) > 0
		for _, path := range field.XPaths {
			if path == "" {
				hasXPaths = false
				break
			}
		}
		if field.XPath == "" && !hasXPaths {
			return fmt.Errorf("xml_fields[%d] must define either non-empty 'xpath' or non-empty 'xpaths'", idx)
		}

		if field.Mode != "" && field.Mode != "first" && field.Mode != "all" {
			return fmt.Errorf("xml_fields[%d].mode must be 'first' or 'all'", idx)
		}
	}

	if settings.Nmap.Args != nil && strings.TrimSpace(*settings.Nmap.Args) == "" {
		return fmt.Errorf("nmap.args must be a non-empty string")
	}
	if settings.Nmap.ArgsFile != nil && strings.TrimSpace(*settings.Nmap.ArgsFile) == "" {
		return fmt.Errorf("nmap.args_file must be a non-empty string")
	}

	if settings.Redfish == nil {
		return nil
	}

	for idx, field := range settings.Redfish.Fields {
		if field.Name == "" {
			return fmt.Errorf("redfish.fields[%d].name must be a non-empty string", idx)
		}
		if len(candidateRedfishPaths(field)) == 0 {
			return fmt.Errorf(
				"redfish.fields[%d] must define at least one non-empty path using path/request_path or paths/request_paths",
				idx,
			)
		}
		if len(candidateRedfishPointers(field)) == 0 {
			return fmt.Errorf(
				"redfish.fields[%d] must define at least one non-empty JSON pointer using json_pointer/pointer or json_pointers/pointers",
				idx,
			)
		}
		if field.Mode != "" && field.Mode != "first" && field.Mode != "all" {
			return fmt.Errorf("redfish.fields[%d].mode must be 'first' or 'all'", idx)
		}
	}

	return nil
}

func candidateXPaths(field XMLField) []string {
	if len(field.XPaths) > 0 {
		return field.XPaths
	}
	return []string{field.XPath}
}

func candidateRedfishPaths(field RedfishField) []string {
	for _, list := range [][]string{field.RequestPaths, field.Paths} {
		if values := nonEmpty(list); len(values) > 0 {
			return values
		}
	}
	for _, value := range []string{field.RequestPath, field.Path} {
		if value != "" {
			return []string{value}
		}
	}
	return nil
}

func candidateRedfishPointers(field RedfishField) []string {
	for _, list := range [][]string{field.JSONPointers, field.Pointers} {
		if values := nonEmpty(list); len(values) > 0 {
			return values
		}
	}
	for _, value := range []string{field.JSONPointer, field.Pointer} {
		if value != "" {
			return []string{value}
		}
	}
	return nil
}

func nonEmpty(values []string) []string {
	var out []string
	for _, value := range values {
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}

func fieldMode(mode string) string {
	if mode == "" {
		return "first"
	}
	return mode
}

func fieldSeparator(separator *string) string {
	if separator == nil {
		return defaultSeparator
	}
	return *separator
}

func isFilteredValue(value string, excludeValues []string) bool {
	for _, excluded := range excludeValues {
		if value == excluded {
			return true
		}
	}
	return false
}

func resolveRelativeToSettings(settingsPath, candidatePath string) string {
	if filepath.IsAbs(candidatePath) {
		return candidatePath
	}
	absSettings, err := filepath.Abs(settingsPath)
	if err != nil {
		absSettings = settingsPath
	}
	return filepath.Join(filepath.Dir(absSettings), candidatePath)
}
