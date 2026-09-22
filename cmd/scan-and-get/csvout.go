// CSV output: writes the dry-run discovery file (ip, url) and the full result
// file, whose columns are ip, the optional --debug diagnostic columns, then one
// column per configured xml_fields and redfish.fields entry. Rows use CRLF to
// match the Python csv module.

package main

import (
	"encoding/csv"
	"fmt"
	"os"
)

func writeCSVResults(
	results []httpResult,
	xmlFieldSpecs []XMLField,
	redfishFieldSpecs []RedfishField,
	csvPath string,
	debug bool,
	redfishOnly bool,
) error {
	headers := []string{"ip"}
	if debug {
		headers = append(headers, "url", "error")
		if !redfishOnly {
			headers = append(headers, "xml_parse_error")
		}
		headers = append(headers, "redfish_error")
	}
	for _, spec := range xmlFieldSpecs {
		headers = append(headers, spec.Name)
	}
	for _, spec := range redfishFieldSpecs {
		headers = append(headers, spec.Name)
	}

	file, err := os.Create(csvPath)
	if err != nil {
		return fmt.Errorf("could not write CSV file '%s': %w", csvPath, err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	writer.UseCRLF = true

	if err := writer.Write(headers); err != nil {
		return fmt.Errorf("could not write CSV file '%s': %w", csvPath, err)
	}

	for _, result := range results {
		row := []string{result.ip}
		if debug {
			row = append(row, result.url, result.err)
			if !redfishOnly {
				row = append(row, result.parseError)
			}
			row = append(row, result.redfishError)
		}
		for _, spec := range xmlFieldSpecs {
			row = append(row, result.parsedFields[spec.Name])
		}
		for _, spec := range redfishFieldSpecs {
			row = append(row, result.redfishFields[spec.Name])
		}

		if err := writer.Write(row); err != nil {
			return fmt.Errorf("could not write CSV file '%s': %w", csvPath, err)
		}
	}

	writer.Flush()
	if err := writer.Error(); err != nil {
		return fmt.Errorf("could not write CSV file '%s': %w", csvPath, err)
	}

	return file.Close()
}

func writeDiscoveryCSV(hosts []string, scheme, path, csvPath string) error {
	file, err := os.Create(csvPath)
	if err != nil {
		return fmt.Errorf("could not write CSV file '%s': %w", csvPath, err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	writer.UseCRLF = true

	if err := writer.Write([]string{"ip", "url"}); err != nil {
		return fmt.Errorf("could not write CSV file '%s': %w", csvPath, err)
	}

	normalizedPath := normalizePath(path)
	for _, ip := range hosts {
		row := []string{ip, fmt.Sprintf("%s://%s%s", scheme, ip, normalizedPath)}
		if err := writer.Write(row); err != nil {
			return fmt.Errorf("could not write CSV file '%s': %w", csvPath, err)
		}
	}

	writer.Flush()
	if err := writer.Error(); err != nil {
		return fmt.Errorf("could not write CSV file '%s': %w", csvPath, err)
	}

	return file.Close()
}
