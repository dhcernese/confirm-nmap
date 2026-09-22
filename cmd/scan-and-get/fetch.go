// HTTP fetch layer: runs the per-host XML and Redfish requests through a bounded
// worker pool, preserving discovery order in the results and printing periodic
// progress. TLS verification is disabled because BMC/iLO endpoints normally
// present self-signed certificates.

package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

type httpResult struct {
	ip            string
	url           string
	ok            bool
	statusCode    int
	err           string
	parsedFields  map[string]string
	parseError    string
	redfishFields map[string]string
	redfishError  string
}

type fetchConfig struct {
	scheme        string
	path          string
	timeout       time.Duration
	xmlFields     []XMLField
	redfishFields []RedfishField
	redfishTime   time.Duration
	workers       int
	progressEvery int
	redfishOnly   bool
}

// newHTTPClient builds a client that skips TLS verification, matching the Python
// implementation: BMC/iLO endpoints normally present self-signed certificates.
func newHTTPClient(scheme string, timeout time.Duration, maxConns int) *http.Client {
	transport := &http.Transport{
		MaxIdleConns:        maxConns,
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     30 * time.Second,
	}
	if scheme == "https" {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402 - self-signed BMC certificates
	}
	return &http.Client{Timeout: timeout, Transport: transport}
}

func fetchEndpoint(hosts []string, config fetchConfig) []httpResult {
	workers := config.workers
	if workers < 1 {
		workers = 1
	}

	xmlClient := newHTTPClient(config.scheme, config.timeout, workers)
	redfishClient := newHTTPClient(config.scheme, config.redfishTime, workers)
	defer xmlClient.CloseIdleConnections()
	defer redfishClient.CloseIdleConnections()

	results := make([]httpResult, len(hosts))
	totalHosts := len(hosts)

	var (
		progressMutex  sync.Mutex
		completedCount int
		waitGroup      sync.WaitGroup
	)
	semaphore := make(chan struct{}, workers)

	for index, ip := range hosts {
		waitGroup.Add(1)
		semaphore <- struct{}{}

		go func(index int, ip string) {
			defer waitGroup.Done()
			defer func() { <-semaphore }()

			results[index] = fetchOne(ip, xmlClient, redfishClient, config)

			progressMutex.Lock()
			completedCount++
			current := completedCount
			progressMutex.Unlock()

			if config.progressEvery > 0 && (current%config.progressEvery == 0 || current == totalHosts) {
				fmt.Printf("[progress] completed HTTP requests for %d/%d hosts\n", current, totalHosts)
			}
		}(index, ip)
	}

	waitGroup.Wait()
	return results
}

func fetchOne(ip string, xmlClient, redfishClient *http.Client, config fetchConfig) httpResult {
	url := fmt.Sprintf("%s://%s%s", config.scheme, ip, normalizePath(config.path))

	if config.redfishOnly {
		redfishValues, redfishError := fetchRedfishFieldsForHost(redfishClient, ip, config.scheme, config.redfishFields)
		return httpResult{
			ip:            ip,
			url:           fmt.Sprintf("%s://%s", config.scheme, ip),
			ok:            true,
			redfishFields: redfishValues,
			redfishError:  redfishError,
		}
	}

	resp, err := xmlClient.Get(url)
	if err != nil {
		fmt.Printf("[error] %s -> %s (%s)\n", ip, url, err)
		redfishValues, redfishError := fetchRedfishFieldsForHost(redfishClient, ip, config.scheme, config.redfishFields)
		return httpResult{
			ip:            ip,
			url:           url,
			ok:            false,
			err:           err.Error(),
			redfishFields: redfishValues,
			redfishError:  redfishError,
		}
	}

	body, readErr := io.ReadAll(resp.Body)
	statusCode := resp.StatusCode
	resp.Body.Close()
	if readErr != nil {
		fmt.Printf("[error] %s -> %s (%s)\n", ip, url, readErr)
		redfishValues, redfishError := fetchRedfishFieldsForHost(redfishClient, ip, config.scheme, config.redfishFields)
		return httpResult{
			ip:            ip,
			url:           url,
			ok:            false,
			err:           readErr.Error(),
			redfishFields: redfishValues,
			redfishError:  redfishError,
		}
	}

	parsedFields, parseError := parseXMLFields(string(body), config.xmlFields)
	redfishValues, redfishError := fetchRedfishFieldsForHost(redfishClient, ip, config.scheme, config.redfishFields)

	return httpResult{
		ip:            ip,
		url:           url,
		ok:            true,
		statusCode:    statusCode,
		parsedFields:  parsedFields,
		parseError:    parseError,
		redfishFields: redfishValues,
		redfishError:  redfishError,
	}
}
