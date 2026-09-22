// Nmap discovery: locates the nmap executable, resolves scan arguments from the
// CLI, an args file or settings, runs the grepable scan and extracts target
// hosts. Host selection stays open-port aware so a -Pn scan cannot fall back to
// blindly trusting every "Status: Up" line in a large CIDR.

package main

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"unicode"
)

var (
	upHostPattern    = regexp.MustCompile(`^Host:\s+(\d+\.\d+\.\d+\.\d+)\b.*Status:\s+Up\s*$`)
	openPortPattern  = regexp.MustCompile(`\b\d+/open/`)
	hostPrefixMatch  = regexp.MustCompile(`^Host:\s+(\d+\.\d+\.\d+\.\d+)\b`)
	errNmapNotFound  = errors.New("nmap executable not found. Install Nmap for Windows or pass --nmap-path")
	nmapCommonPaths  = []string{`C:\Program Files (x86)\Nmap\nmap.exe`, `C:\Program Files\Nmap\nmap.exe`}
	errUnbalancedArg = errors.New("unbalanced quote in Nmap arguments")
)

// parseNmapArgs splits a command line into tokens, honouring single and double quotes.
func parseNmapArgs(nmapArgs string) ([]string, error) {
	var (
		tokens  []string
		current strings.Builder
		inToken bool
		quote   rune
	)

	for _, r := range strings.TrimSpace(nmapArgs) {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				current.WriteRune(r)
			}
		case r == '"' || r == '\'':
			quote = r
			inToken = true
		case unicode.IsSpace(r):
			if inToken {
				tokens = append(tokens, current.String())
				current.Reset()
				inToken = false
			}
		default:
			current.WriteRune(r)
			inToken = true
		}
	}

	if quote != 0 {
		return nil, errUnbalancedArg
	}
	if inToken {
		tokens = append(tokens, current.String())
	}

	return tokens, nil
}

func loadNmapArgsFromFile(filePath string) (string, error) {
	raw, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("could not read Nmap args file '%s': %w", filePath, err)
	}

	content := strings.TrimSpace(string(raw))
	if content == "" {
		return "", fmt.Errorf("Nmap args file '%s' is empty", filePath)
	}

	return content, nil
}

func resolveNmapArgs(cliNmapArgs, cliNmapArgsFile string, nmapSettings NmapSettings, settingsPath string) (string, []string, error) {
	if cliNmapArgs != "" {
		tokens, err := parseNmapArgs(cliNmapArgs)
		return cliNmapArgs, tokens, err
	}

	argsFile := cliNmapArgsFile
	if argsFile == "" && nmapSettings.ArgsFile != nil && *nmapSettings.ArgsFile != "" {
		argsFile = resolveRelativeToSettings(settingsPath, *nmapSettings.ArgsFile)
	}

	if argsFile != "" {
		nmapArgs, err := loadNmapArgsFromFile(argsFile)
		if err != nil {
			return "", nil, err
		}
		tokens, err := parseNmapArgs(nmapArgs)
		return nmapArgs, tokens, err
	}

	configuredArgs := defaultNmapArgs
	if nmapSettings.Args != nil {
		configuredArgs = *nmapSettings.Args
	}
	if strings.TrimSpace(configuredArgs) == "" {
		return "", nil, errors.New("nmap.args must be a non-empty string when nmap.args_file is not set")
	}

	tokens, err := parseNmapArgs(configuredArgs)
	return configuredArgs, tokens, err
}

func findNmap(explicitPath string) (string, error) {
	if explicitPath != "" {
		return explicitPath, nil
	}

	if pathHit, err := exec.LookPath("nmap"); err == nil {
		return pathHit, nil
	}

	for _, candidate := range nmapCommonPaths {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate, nil
		}
	}

	return "", errNmapNotFound
}

func discoverUpHosts(nmapExe, cidr string, nmapArgTokens []string, requireOpenPortOutput bool) ([]string, error) {
	args := make([]string, 0, len(nmapArgTokens)+3)
	args = append(args, nmapArgTokens...)
	args = append(args, cidr, "-oG", "-")

	cmd := exec.Command(nmapExe, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return nil, fmt.Errorf("nmap failed with exit code %d:\n%s", exitErr.ExitCode(), strings.TrimSpace(stderr.String()))
		}
		return nil, fmt.Errorf("could not execute nmap: %w", err)
	}

	var lines []string
	for _, line := range strings.Split(stdout.String(), "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			lines = append(lines, trimmed)
		}
	}

	hasPortOutput := false
	for _, line := range lines {
		if strings.HasPrefix(line, "Host:") && strings.Contains(line, "Ports:") {
			hasPortOutput = true
			break
		}
	}

	if requireOpenPortOutput && !hasPortOutput {
		return nil, errors.New(
			"unsafe Nmap discovery output: '-Pn' was requested, but grepable output contains no 'Ports:' lines. " +
				"Refusing to trust 'Status: Up' entries because the scan arguments may have been mangled or Nmap did not emit port results.",
		)
	}

	var hosts []string
	seenHosts := make(map[string]bool)

	appendHost := func(ip string) {
		if !seenHosts[ip] {
			seenHosts[ip] = true
			hosts = append(hosts, ip)
		}
	}

	isOpenPortLine := func(line string) bool {
		return strings.HasPrefix(line, "Host:") && strings.Contains(line, "Ports:") && openPortPattern.MatchString(line)
	}

	for _, line := range lines {
		if requireOpenPortOutput {
			if isOpenPortLine(line) {
				if match := hostPrefixMatch.FindStringSubmatch(line); match != nil {
					appendHost(match[1])
				}
			}
			continue
		}

		if match := upHostPattern.FindStringSubmatch(line); match != nil &&
			!strings.Contains(line, "Ports:") && !hasPortOutput {
			appendHost(match[1])
			continue
		}

		if isOpenPortLine(line) {
			if match := hostPrefixMatch.FindStringSubmatch(line); match != nil {
				appendHost(match[1])
			}
		}
	}

	return hosts, nil
}

// fallbackHostFromSingleCIDR returns the single address of an IPv4 /32 CIDR.
func fallbackHostFromSingleCIDR(cidr string) string {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return ""
	}
	if !prefix.Addr().Is4() || prefix.Bits() != 32 {
		return ""
	}
	return prefix.Masked().Addr().String()
}
