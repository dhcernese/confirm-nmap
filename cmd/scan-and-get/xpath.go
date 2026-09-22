// XPath evaluator: implements the subset of ElementTree XPath used by
// settings.json, because the Go standard library has no XPath support.
// Supported: relative paths, "//" descendant steps, "*" wildcards, ".." parent
// steps, and the predicates [n], [last()], [@attr], [@attr='value'], [tag],
// [tag='value'] and [.='value'].

package main

import (
	"fmt"
	"strconv"
	"strings"
)

type predicateKind int

const (
	predIndex predicateKind = iota
	predLast
	predAttr
	predAttrValue
	predChild
	predChildValue
	predSelfValue
)

type xpredicate struct {
	kind  predicateKind
	index int
	name  string
	value string
}

type xstep struct {
	descendant bool
	name       string
	predicates []xpredicate
}

func compileXPath(path string) ([]xstep, error) {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return nil, fmt.Errorf("empty XPath expression")
	}
	if strings.HasPrefix(trimmed, "/") {
		return nil, fmt.Errorf("absolute XPath expressions are not supported: %q", path)
	}

	segments := splitXPathSegments(trimmed)

	var (
		steps             []xstep
		pendingDescendant bool
	)

	for index, segment := range segments {
		if segment == "" {
			if index == 0 {
				return nil, fmt.Errorf("absolute XPath expressions are not supported: %q", path)
			}
			pendingDescendant = true
			continue
		}

		if segment == "." {
			continue
		}

		name, rawPredicates, err := splitPredicates(segment)
		if err != nil {
			return nil, fmt.Errorf("invalid XPath %q: %w", path, err)
		}

		step := xstep{descendant: pendingDescendant, name: name}
		for _, rawPredicate := range rawPredicates {
			predicate, err := parsePredicate(rawPredicate)
			if err != nil {
				return nil, fmt.Errorf("invalid XPath %q: %w", path, err)
			}
			step.predicates = append(step.predicates, predicate)
		}

		steps = append(steps, step)
		pendingDescendant = false
	}

	if pendingDescendant {
		return nil, fmt.Errorf("invalid XPath %q: expression cannot end with a separator", path)
	}

	return steps, nil
}

func splitXPathSegments(path string) []string {
	var (
		segments []string
		current  strings.Builder
		depth    int
		quote    rune
	)

	for _, r := range path {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			}
			current.WriteRune(r)
		case r == '\'' || r == '"':
			quote = r
			current.WriteRune(r)
		case r == '[':
			depth++
			current.WriteRune(r)
		case r == ']':
			depth--
			current.WriteRune(r)
		case r == '/' && depth == 0:
			segments = append(segments, current.String())
			current.Reset()
		default:
			current.WriteRune(r)
		}
	}

	segments = append(segments, current.String())
	return segments
}

func splitPredicates(segment string) (string, []string, error) {
	var (
		name          strings.Builder
		rawPredicates []string
		current       strings.Builder
		depth         int
		quote         rune
	)

	for _, r := range segment {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			}
			current.WriteRune(r)
		case depth == 0 && r == '[':
			depth++
		case depth > 0 && (r == '\'' || r == '"'):
			quote = r
			current.WriteRune(r)
		case depth > 0 && r == '[':
			depth++
			current.WriteRune(r)
		case depth > 0 && r == ']':
			depth--
			if depth == 0 {
				rawPredicates = append(rawPredicates, current.String())
				current.Reset()
			} else {
				current.WriteRune(r)
			}
		case depth > 0:
			current.WriteRune(r)
		default:
			name.WriteRune(r)
		}
	}

	if depth != 0 || quote != 0 {
		return "", nil, fmt.Errorf("unbalanced predicate in %q", segment)
	}

	tag := strings.TrimSpace(name.String())
	if tag == "" {
		return "", nil, fmt.Errorf("missing element name in %q", segment)
	}

	return tag, rawPredicates, nil
}

func parsePredicate(raw string) (xpredicate, error) {
	expression := strings.TrimSpace(raw)

	if expression == "last()" {
		return xpredicate{kind: predLast}, nil
	}

	if isAllDigits(expression) {
		index, err := strconv.Atoi(expression)
		if err != nil || index < 1 {
			return xpredicate{}, fmt.Errorf("unsupported position predicate [%s]", raw)
		}
		return xpredicate{kind: predIndex, index: index}, nil
	}

	if equals := strings.Index(expression, "="); equals >= 0 {
		left := strings.TrimSpace(expression[:equals])
		right := strings.TrimSpace(expression[equals+1:])

		value, err := unquotePredicateValue(right)
		if err != nil {
			return xpredicate{}, err
		}

		switch {
		case strings.HasPrefix(left, "@"):
			attribute := strings.TrimSpace(left[1:])
			if attribute == "" {
				return xpredicate{}, fmt.Errorf("missing attribute name in predicate [%s]", raw)
			}
			return xpredicate{kind: predAttrValue, name: attribute, value: value}, nil
		case left == ".":
			return xpredicate{kind: predSelfValue, value: value}, nil
		case isSimpleName(left):
			return xpredicate{kind: predChildValue, name: left, value: value}, nil
		}

		return xpredicate{}, fmt.Errorf("unsupported predicate [%s]", raw)
	}

	if strings.HasPrefix(expression, "@") {
		attribute := strings.TrimSpace(expression[1:])
		if attribute == "" {
			return xpredicate{}, fmt.Errorf("missing attribute name in predicate [%s]", raw)
		}
		return xpredicate{kind: predAttr, name: attribute}, nil
	}

	if isSimpleName(expression) {
		return xpredicate{kind: predChild, name: expression}, nil
	}

	return xpredicate{}, fmt.Errorf("unsupported predicate [%s]", raw)
}

func unquotePredicateValue(value string) (string, error) {
	if len(value) >= 2 {
		first := value[0]
		last := value[len(value)-1]
		if (first == '\'' || first == '"') && first == last {
			return value[1 : len(value)-1], nil
		}
	}
	return "", fmt.Errorf("predicate comparison value must be quoted: %s", value)
}

func isAllDigits(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func isSimpleName(value string) bool {
	if value == "" {
		return false
	}
	return !strings.ContainsAny(value, " \t\r\n[]()'\"/@=")
}

func findAll(context *xnode, path string) []*xnode {
	steps, err := compileXPath(path)
	if err != nil {
		return nil
	}
	return evaluateSteps(context, steps)
}

func evaluateSteps(context *xnode, steps []xstep) []*xnode {
	current := []*xnode{context}

	for _, step := range steps {
		var next []*xnode

		switch {
		case step.name == "..":
			seen := make(map[*xnode]bool)
			for _, node := range current {
				if node.parent != nil && !seen[node.parent] {
					seen[node.parent] = true
					next = append(next, node.parent)
				}
			}
		case step.descendant:
			for _, node := range current {
				next = appendDescendants(next, node, step.name)
			}
		default:
			for _, node := range current {
				for _, child := range node.children {
					if step.name == "*" || child.tag == step.name {
						next = append(next, child)
					}
				}
			}
		}

		for _, predicate := range step.predicates {
			next = applyPredicate(next, predicate)
		}

		current = next
		if len(current) == 0 {
			return nil
		}
	}

	return current
}

func appendDescendants(out []*xnode, node *xnode, name string) []*xnode {
	for _, child := range node.children {
		if name == "*" || child.tag == name {
			out = append(out, child)
		}
		out = appendDescendants(out, child, name)
	}
	return out
}

func applyPredicate(nodes []*xnode, predicate xpredicate) []*xnode {
	var out []*xnode

	switch predicate.kind {
	case predIndex:
		positions := make(map[*xnode]int)
		for _, node := range nodes {
			positions[node.parent]++
			if positions[node.parent] == predicate.index {
				out = append(out, node)
			}
		}

	case predLast:
		lastByParent := make(map[*xnode]*xnode)
		for _, node := range nodes {
			lastByParent[node.parent] = node
		}
		for _, node := range nodes {
			if lastByParent[node.parent] == node {
				out = append(out, node)
			}
		}

	case predAttr:
		for _, node := range nodes {
			if _, ok := node.attrs[predicate.name]; ok {
				out = append(out, node)
			}
		}

	case predAttrValue:
		for _, node := range nodes {
			if node.attrs[predicate.name] == predicate.value {
				out = append(out, node)
			}
		}

	case predChild:
		for _, node := range nodes {
			for _, child := range node.children {
				if child.tag == predicate.name {
					out = append(out, node)
					break
				}
			}
		}

	case predChildValue:
		for _, node := range nodes {
			for _, child := range node.children {
				if child.tag == predicate.name && child.allText == predicate.value {
					out = append(out, node)
					break
				}
			}
		}

	case predSelfValue:
		for _, node := range nodes {
			if node.allText == predicate.value {
				out = append(out, node)
			}
		}
	}

	return out
}
