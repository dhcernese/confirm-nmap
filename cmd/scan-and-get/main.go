// Command scan-and-get runs an Nmap discovery scan against a CIDR, issues
// unauthenticated HTTP(S) GET requests to every discovered host, extracts
// configured XML and Redfish JSON fields, and writes the values to CSV.
//
// It is a dependency-free Go port of scan_and_get.py and uses only the Go
// standard library. This file owns CLI flag parsing, the CLI-over-settings
// precedence rules, the safety checks, and the console report.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"time"
)

const (
	defaultScheme        = "https"
	defaultPath          = "/xmldata?item=All"
	defaultTimeout       = 5.0
	defaultWorkers       = 32
	defaultMaxTargets    = 2048
	defaultProgressEvery = 50
	defaultNmapArgs      = "-sn"
	defaultSeparator     = " | "
	missingValue         = "<missing>"
)

type options struct {
	cidr          string
	path          string
	scheme        string
	timeout       float64
	nmapPath      string
	nmapArgs      string
	nmapArgsFile  string
	settings      string
	csvOutput     string
	workers       int
	maxTargets    int
	progressEvery int
	dryRun        bool
	debug         bool
	noRedfish     bool
	redfishOnly   bool
	provided      map[string]bool
}

func main() {
	os.Exit(run())
}

func parseArgs() (*options, error) {
	opts := &options{provided: make(map[string]bool)}

	flagSet := flag.NewFlagSet("scan-and-get", flag.ContinueOnError)
	flagSet.SetOutput(os.Stderr)
	flagSet.Usage = func() {
		fmt.Fprintln(os.Stderr, "Run Nmap against a CIDR and perform unauthenticated GET requests on discovered hosts.")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Usage: scan-and-get --cidr <cidr> [options]")
		fmt.Fprintln(os.Stderr)
		flagSet.PrintDefaults()
	}

	flagSet.StringVar(&opts.cidr, "cidr", "", "Target CIDR (example: 10.152.161.0/24)")
	flagSet.StringVar(&opts.path, "path", "", "Path/query for GET request. Overrides settings JSON if provided.")
	flagSet.StringVar(&opts.scheme, "scheme", "", "Protocol for GET requests (http or https). Overrides settings JSON if provided.")
	flagSet.Float64Var(&opts.timeout, "timeout", 0, "HTTP timeout in seconds. Overrides settings JSON if provided.")
	flagSet.StringVar(&opts.nmapPath, "nmap-path", "", "Optional full path to nmap executable.")
	flagSet.StringVar(&opts.nmapArgs, "nmap-args", "", "Nmap args for discovery scan. Overrides settings JSON if provided.")
	flagSet.StringVar(&opts.nmapArgsFile, "nmap-args-file", "", "Path to a plain-text file containing Nmap args. Overrides settings JSON if provided.")
	flagSet.StringVar(&opts.settings, "settings", "settings.json", "Path to JSON settings file")
	flagSet.StringVar(&opts.csvOutput, "csv-output", "scan_results.csv", "Path for CSV output file")
	flagSet.IntVar(&opts.workers, "workers", 0, "Concurrent HTTP workers. Overrides settings JSON if provided.")
	flagSet.IntVar(&opts.maxTargets, "max-targets", 0, "Maximum number of hosts to request before aborting. Overrides settings JSON if provided.")
	flagSet.IntVar(&opts.progressEvery, "progress-every", 0, "Print progress after every N completed HTTP requests. Overrides settings JSON if provided.")
	flagSet.BoolVar(&opts.dryRun, "dry-run", false, "Discover targets and write discovery CSV without issuing HTTP requests.")
	flagSet.BoolVar(&opts.debug, "debug", false, "Include debug columns in CSV output (url, error, xml_parse_error, redfish_error).")
	flagSet.BoolVar(&opts.noRedfish, "no-redfish", false, "Skip unauthenticated Redfish enrichment queries.")
	flagSet.BoolVar(&opts.redfishOnly, "redfish-only", false, "Skip XML endpoint requests/parsing and output only Redfish fields.")

	if err := flagSet.Parse(os.Args[1:]); err != nil {
		return nil, err
	}

	flagSet.Visit(func(f *flag.Flag) { opts.provided[f.Name] = true })

	if opts.cidr == "" {
		flagSet.Usage()
		return nil, errors.New("the following argument is required: --cidr")
	}

	if opts.provided["scheme"] && opts.scheme != "http" && opts.scheme != "https" {
		return nil, fmt.Errorf("argument --scheme: invalid choice: %q (choose from 'http', 'https')", opts.scheme)
	}

	return opts, nil
}

func run() int {
	opts, err := parseArgs()
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintf(os.Stderr, "[error] %s\n", err)
		return 2
	}

	settings, err := loadSettings(opts.settings)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[error] %s\n", err)
		return 1
	}

	if opts.redfishOnly && opts.noRedfish {
		fmt.Fprintln(os.Stderr, "[error] --redfish-only cannot be combined with --no-redfish.")
		return 1
	}

	scheme := pickString(opts.provided["scheme"], opts.scheme, settings.Request.Scheme, defaultScheme)
	path := pickString(opts.provided["path"], opts.path, settings.Request.Path, defaultPath)
	timeout := pickFloat(opts.provided["timeout"], opts.timeout, settings.Request.Timeout, defaultTimeout)
	workers := pickInt(opts.provided["workers"], opts.workers, settings.Execution.Workers, defaultWorkers)
	maxTargets := pickInt(opts.provided["max-targets"], opts.maxTargets, settings.Execution.MaxTargets, defaultMaxTargets)
	progressEvery := pickInt(opts.provided["progress-every"], opts.progressEvery, settings.Execution.ProgressEvery, defaultProgressEvery)

	_, nmapArgTokens, err := resolveNmapArgs(opts.nmapArgs, opts.nmapArgsFile, settings.Nmap, opts.settings)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[error] %s\n", err)
		return 1
	}

	var xmlFields []XMLField
	if !opts.redfishOnly {
		xmlFields = settings.XMLFields
	}

	redfishSettings := settings.Redfish
	redfishConfigEnabled := true
	redfishTimeout := timeout
	var redfishFields []RedfishField
	if redfishSettings != nil {
		if redfishSettings.Enabled != nil {
			redfishConfigEnabled = *redfishSettings.Enabled
		}
		if redfishSettings.Timeout != nil {
			redfishTimeout = *redfishSettings.Timeout
		}
	}

	redfishEnabled := (opts.redfishOnly || redfishConfigEnabled) && !opts.noRedfish
	if redfishEnabled && redfishSettings != nil {
		redfishFields = redfishSettings.Fields
	}

	if opts.redfishOnly && len(redfishFields) == 0 {
		fmt.Fprintln(os.Stderr, "[error] --redfish-only requested but no redfish.fields are configured in settings.")
		return 1
	}

	requireOpenPortOutput := contains(nmapArgTokens, "-Pn")

	var hosts []string
	nmapExe, err := findNmap(opts.nmapPath)
	if err == nil {
		hosts, err = discoverUpHosts(nmapExe, opts.cidr, nmapArgTokens, requireOpenPortOutput)
	}
	if err != nil {
		// A missing/unlaunchable nmap binary falls back to a single /32 target.
		fallbackHost := ""
		if errors.Is(err, errNmapNotFound) || errors.Is(err, fs.ErrNotExist) {
			fallbackHost = fallbackHostFromSingleCIDR(opts.cidr)
		}
		if fallbackHost == "" {
			fmt.Fprintf(os.Stderr, "[error] %s\n", err)
			return 1
		}
		fmt.Printf("[warn] %s\n", err)
		fmt.Printf("[warn] Falling back to direct host request for %s from /32 CIDR.\n", fallbackHost)
		hosts = []string{fallbackHost}
	}

	if len(hosts) == 0 {
		fmt.Println("No hosts reported as Up by nmap.")
		return 0
	}

	fmt.Printf("Discovered %d up host(s): %s\n", len(hosts), strings.Join(hosts, ", "))

	if opts.dryRun {
		if err := writeDiscoveryCSV(hosts, scheme, path, opts.csvOutput); err != nil {
			fmt.Fprintf(os.Stderr, "[error] %s\n", err)
			return 1
		}
		fmt.Printf("\nDry run complete. Discovery CSV written: %s\n", opts.csvOutput)
		return 0
	}

	if len(hosts) > maxTargets {
		fmt.Fprintf(os.Stderr, "[error] refusing to issue HTTP requests to %d hosts; max_targets is %d.\n", len(hosts), maxTargets)
		fmt.Fprintln(os.Stderr, "[error] tighten Nmap discovery so only real responders are returned, or raise --max-targets intentionally.")
		return 1
	}

	results := fetchEndpoint(hosts, fetchConfig{
		scheme:        scheme,
		path:          path,
		timeout:       secondsToDuration(timeout),
		xmlFields:     xmlFields,
		redfishFields: redfishFields,
		redfishTime:   secondsToDuration(redfishTimeout),
		workers:       workers,
		progressEvery: progressEvery,
		redfishOnly:   opts.redfishOnly,
	})

	printResults(results, xmlFields, redfishFields)

	if err := writeCSVResults(results, xmlFields, redfishFields, opts.csvOutput, opts.debug, opts.redfishOnly); err != nil {
		fmt.Fprintf(os.Stderr, "[error] %s\n", err)
		return 1
	}
	fmt.Printf("\nCSV written: %s\n", opts.csvOutput)

	return 0
}

func printResults(results []httpResult, xmlFields []XMLField, redfishFields []RedfishField) {
	fmt.Println("\nHTTP GET results")
	fmt.Println("----------------")

	printRedfish := func(result httpResult) {
		for _, spec := range redfishFields {
			if value, ok := result.redfishFields[spec.Name]; ok {
				fmt.Printf("        %s: %s\n", spec.Name, value)
			}
		}
		if result.redfishError != "" {
			fmt.Printf("        Redfish: %s\n", result.redfishError)
		}
	}

	for _, result := range results {
		if !result.ok {
			fmt.Printf("[error] %s -> %s (%s)\n", result.ip, result.url, result.err)
			printRedfish(result)
			continue
		}

		fmt.Printf("[ok]    %s -> %s (status=%s)\n", result.ip, result.url, formatStatus(result))
		if result.parseError != "" {
			fmt.Printf("        XML parse: %s\n", result.parseError)
		} else {
			for _, spec := range xmlFields {
				if value, ok := result.parsedFields[spec.Name]; ok {
					fmt.Printf("        %s: %s\n", spec.Name, value)
				}
			}
		}
		printRedfish(result)
	}
}

func formatStatus(result httpResult) string {
	if result.statusCode == 0 {
		return "None"
	}
	return fmt.Sprintf("%d", result.statusCode)
}

func secondsToDuration(seconds float64) time.Duration {
	return time.Duration(seconds * float64(time.Second))
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func pickString(overridden bool, override, configured, fallback string) string {
	if overridden && override != "" {
		return override
	}
	if configured != "" {
		return configured
	}
	return fallback
}

func pickFloat(overridden bool, override float64, configured *float64, fallback float64) float64 {
	if overridden {
		return override
	}
	if configured != nil {
		return *configured
	}
	return fallback
}

func pickInt(overridden bool, override int, configured *int, fallback int) int {
	if overridden {
		return override
	}
	if configured != nil {
		return *configured
	}
	return fallback
}
