// XML handling: parses a response body into a namespace-stripped element tree
// that mirrors Python's ElementTree semantics (.text and itertext()), then
// resolves each configured xml_fields entry against it, applying the mode,
// separator and exclude_values rules.

package main

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"
)

// xnode is a namespace-stripped XML element, equivalent to an ElementTree Element.
type xnode struct {
	tag      string
	attrs    map[string]string
	text     string // character data before the first child element (ElementTree .text)
	allText  string // character data of the whole subtree (ElementTree itertext())
	children []*xnode
	parent   *xnode
}

func parseXMLDocument(xmlText string) (*xnode, error) {
	decoder := xml.NewDecoder(strings.NewReader(xmlText))
	decoder.CharsetReader = charsetReader

	var (
		root  *xnode
		stack []*xnode
	)

	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}

		switch element := token.(type) {
		case xml.StartElement:
			node := &xnode{tag: element.Name.Local, attrs: make(map[string]string, len(element.Attr))}
			for _, attr := range element.Attr {
				if attr.Name.Local == "xmlns" || attr.Name.Space == "xmlns" {
					continue
				}
				node.attrs[attr.Name.Local] = attr.Value
			}

			if len(stack) > 0 {
				parent := stack[len(stack)-1]
				node.parent = parent
				parent.children = append(parent.children, node)
			} else if root != nil {
				return nil, errors.New("junk after document element")
			} else {
				root = node
			}
			stack = append(stack, node)

		case xml.EndElement:
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}

		case xml.CharData:
			if len(stack) == 0 {
				continue
			}
			data := string(element)
			current := stack[len(stack)-1]
			if len(current.children) == 0 {
				current.text += data
			}
			for _, ancestor := range stack {
				ancestor.allText += data
			}
		}
	}

	if root == nil {
		return nil, errors.New("no element found")
	}

	return root, nil
}

// charsetReader supports the single-byte encodings BMC firmware commonly declares.
func charsetReader(charset string, input io.Reader) (io.Reader, error) {
	switch strings.ToLower(charset) {
	case "", "utf-8", "utf8", "us-ascii", "ascii":
		return input, nil
	case "iso-8859-1", "iso8859-1", "latin1", "latin-1", "windows-1252", "cp1252":
		data, err := io.ReadAll(input)
		if err != nil {
			return nil, err
		}
		runes := make([]rune, len(data))
		for i, b := range data {
			runes[i] = rune(b)
		}
		return strings.NewReader(string(runes)), nil
	}
	return nil, fmt.Errorf("unsupported charset %q", charset)
}

func parseXMLFields(xmlText string, fieldSpecs []XMLField) (map[string]string, string) {
	root, err := parseXMLDocument(xmlText)
	if err != nil {
		return nil, fmt.Sprintf("xml parse error: %s", err)
	}

	extracted := make(map[string]string, len(fieldSpecs))
	for _, spec := range fieldSpecs {
		mode := fieldMode(spec.Mode)
		separator := fieldSeparator(spec.Separator)
		xpaths := candidateXPaths(spec)

		if mode == "all" {
			var collected []string
			for _, xpath := range xpaths {
				for _, node := range findAll(root, xpath) {
					value := strings.TrimSpace(node.text)
					if value != "" && !isFilteredValue(value, spec.ExcludeValues) {
						collected = append(collected, value)
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
		for _, xpath := range xpaths {
			nodes := findAll(root, xpath)
			if len(nodes) == 0 {
				continue
			}

			value := strings.TrimSpace(nodes[0].text)
			if value == "" || isFilteredValue(value, spec.ExcludeValues) {
				continue
			}

			extracted[spec.Name] = value
			found = true
			break
		}

		if !found {
			extracted[spec.Name] = missingValue
		}
	}

	return extracted, ""
}
