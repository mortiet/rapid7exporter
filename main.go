package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v2"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// ----------------------------------------------------------------------
// Config & Data Structures
// ----------------------------------------------------------------------

// Config holds all configuration options.
type Config struct {
	Retention    int               `yaml:"retention"` // in days
	LatestScan   bool              `yaml:"latestScan"`
	UpdatePeriod int               `yaml:"updatePeriod"` // in minutes
	LogLevel     string            `yaml:"loglevel"`
	Severities   []string          `yaml:"severities"`
	DummyApps    []App             `yaml:"dummyApps"`
	RenameApps   map[string]string `yaml:"renameApps"` // mapping: original app name -> new app name
	CacheDir     string            `yaml:"cacheDir"`   // folder to cache raw API responses
}

// App represents a single app from the apps API (or a dummy app).
type App struct {
	ID   string `yaml:"id" json:"id"`
	Name string `yaml:"name" json:"name"`
}

// AppsResponse represents the JSON response from the apps API.
type AppsResponse struct {
	Data []App `json:"data"`
}

// Vulnerability represents a single vulnerability record.
type Vulnerability struct {
	ID  string `json:"id"`
	App struct {
		ID string `json:"id"`
	} `json:"app"`
	Severity        string `json:"severity"`
	FirstDiscovered string `json:"first_discovered"` // e.g., "2024-05-10T15:28:53.806326"
	LastDiscovered  string `json:"last_discovered"`  // e.g., "2024-11-27T16:31:49.876236"
	Variances       []struct {
		OriginalExchange struct {
			Request string `json:"request"`
		} `json:"original_exchange"`
	} `json:"variances"`
}

type Metadata struct {
	Index      int    `json:"index"`
	Size       int    `json:"size"`
	Sort       string `json:"sort"`
	TotalData  int    `json:"total_data"`
	TotalPages int    `json:"total_pages"`
	PageToken  string `json:"page_token"`
}

type Link struct {
	Rel  string `json:"rel"`
	Href string `json:"href"`
}

type VulnerabilitiesResponse struct {
	Data     []Vulnerability `json:"data"`
	Metadata Metadata        `json:"metadata"`
	Links    []Link          `json:"links"`
}

// ----------------------------------------------------------------------
// Global Variables and Prometheus Metric
// ----------------------------------------------------------------------

var (
	// appMap caches the mapping from app ID to app name (from Rapid7 API).
	appMap   = make(map[string]string)
	appMapMu sync.RWMutex

	// renameAppsMap holds the mapping to transform app names.
	renameAppsMap map[string]string

	// vulnerabilityCountGauge aggregates vulnerability counts by app name (transformed),
	// severity, and state. The state label is "live" for live data and "dummy" for dummy apps.
	vulnerabilityCountGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "rapid7_vulnerabilities_count",
			Help: "Count of vulnerabilities per app by severity and state (live or dummy).",
		},
		[]string{"app_name", "severity", "state"},
	)

	mu sync.Mutex

	// Allowed severities and dummy apps as determined by configuration.
	allowedSeverities []string
	dummyAppsList     []App

	// Cache directory for raw API responses.
	cacheDir string
)

// ----------------------------------------------------------------------
// Helper Functions for Caching
// ----------------------------------------------------------------------

func getCachedResponse(filename string, maxAge time.Duration) ([]byte, error) {
	info, err := os.Stat(filename)
	if err != nil {
		return nil, err
	}
	if time.Since(info.ModTime()) > maxAge {
		return nil, fmt.Errorf("cache expired")
	}
	return ioutil.ReadFile(filename)
}

func saveCache(filename string, data []byte) error {
	return ioutil.WriteFile(filename, data, 0644)
}

// ----------------------------------------------------------------------
// Other Helper Functions
// ----------------------------------------------------------------------

// maskURL masks sensitive tokens (if any) from a URL before logging.
func maskURL(u string) string {
	parsed, err := url.Parse(u)
	if err != nil {
		return u
	}
	q := parsed.Query()
	if q.Has("page_token") {
		q.Set("page_token", "****")
		parsed.RawQuery = q.Encode()
	}
	return parsed.String()
}

// isAllowedSeverity returns true if sev is in the allowed list (case‑insensitive).
func isAllowedSeverity(sev string, allowed []string) bool {
	for _, a := range allowed {
		if strings.EqualFold(a, sev) {
			return true
		}
	}
	return false
}

// updateGauge aggregates counts by transformed app name and updates the gauge.
// For live data, the state label is set to "live".
// For dummy apps, only a "LOW" severity entry with value 0 is added with state "dummy".
func updateGauge(aggregatedCounts map[string]map[string]int, dummyApps []App, allowed []string) {
	mu.Lock()
	defer mu.Unlock()

	// Reset the gauge.
	vulnerabilityCountGauge.Reset()

	// Build a new map grouping by transformed app name.
	finalCounts := make(map[string]map[string]int)
	for appID, severityCounts := range aggregatedCounts {
		appMapMu.RLock()
		appName, exists := appMap[appID]
		appMapMu.RUnlock()
		if !exists {
			appName = "unknown"
		}
		// Apply transformation if configured.
		if newName, ok := renameAppsMap[appName]; ok {
			appName = newName
		}
		if _, exists := finalCounts[appName]; !exists {
			finalCounts[appName] = make(map[string]int)
		}
		for sev, count := range severityCounts {
			finalCounts[appName][sev] += count
		}
	}

	// Update gauge for live data.
	for appName, severityCounts := range finalCounts {
		for sev, count := range severityCounts {
			vulnerabilityCountGauge.With(prometheus.Labels{
				"app_name": appName,
				"severity": sev,
				"state":    "live",
			}).Set(float64(count))
		}
	}

	// Add dummy apps: for each dummy app (by its transformed name) that is not already present, add only a "LOW" entry with 0.
	for _, dummyApp := range dummyApps {
		dummyName := dummyApp.Name
		if newName, ok := renameAppsMap[dummyName]; ok {
			dummyName = newName
		}
		if _, exists := finalCounts[dummyName]; !exists {
			// Add dummy app with state "dummy" and LOW severity 0.
			vulnerabilityCountGauge.With(prometheus.Labels{
				"app_name": dummyName,
				"severity": "LOW",
				"state":    "dummy",
			}).Set(0)
		}
	}
}

// extractScanID parses the given HTTP request text (from a variance) and returns the scan id.
func extractScanID(requestText string) string {
	lines := strings.Split(requestText, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "X-RTC-SCANID:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}

// ----------------------------------------------------------------------
// Fetching Data
// ----------------------------------------------------------------------

// fetchApps retrieves the list of apps from the Rapid7 Apps API and updates appMap.
// If caching is enabled (cacheDir is set), it will reuse the cached response if it is not older than (updatePeriod - 10 minutes).
func fetchApps(apiKey string, cacheDuration time.Duration) {
	appsURL := "https://eu.api.insight.rapid7.com/ias/v1/apps"
	log.Info().Msgf("Fetching apps from URL: %s", maskURL(appsURL))

	var data []byte
	var err error
	cacheFile := ""
	if cacheDir != "" && cacheDuration > 0 {
		os.MkdirAll(cacheDir, 0755)
		cacheFile = cacheDir + "/apps.json"
		data, err = getCachedResponse(cacheFile, cacheDuration)
		if err == nil {
			log.Info().Msg("Using cached apps data")
		}
	}

	if data == nil {
		req, err := http.NewRequest("GET", appsURL, nil)
		if err != nil {
			log.Error().Err(err).Msg("Error creating request for apps API")
			return
		}
		req.Header.Set("X-Api-Key", apiKey)
		req.Header.Set("Content-Type", "application/json")

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			log.Error().Err(err).Msg("Error making request to apps API")
			return
		}
		defer resp.Body.Close()

		data, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Error().Err(err).Msg("Error reading apps API response")
			return
		}

		if cacheFile != "" {
			if err := saveCache(cacheFile, data); err != nil {
				log.Error().Err(err).Msg("Error saving apps cache")
			} else {
				log.Info().Msg("Saved apps data to cache")
			}
		}
	}

	var appsResp AppsResponse
	if err := json.Unmarshal(data, &appsResp); err != nil {
		log.Error().Err(err).Msg("Error decoding apps API response")
		return
	}

	newMap := make(map[string]string)
	for _, app := range appsResp.Data {
		newMap[app.ID] = app.Name
	}

	appMapMu.Lock()
	appMap = newMap
	appMapMu.Unlock()

	log.Info().Msgf("Fetched %d apps from the apps API", len(newMap))
}

// fetchVulnerabilities retrieves vulnerabilities page by page from the Rapid7 API.
// It applies the retention filter (if set) and allowed severities filtering.
// If latestScan is false, all vulnerabilities (that pass filters) are aggregated by app.
// If latestScan is true, vulnerabilities are grouped by app and by scan (using scan id) and only the latest scan is used.
// For performance, if cacheDir is set, raw JSON responses are cached and reused if not older than (updatePeriod - 10 minutes).
func fetchVulnerabilities(apiKey string, retentionDays int, latestScan bool, cacheDuration time.Duration) {
	baseURL := "https://eu.api.insight.rapid7.com/ias/v1/vulnerabilities"
	currentIndex := 0
	client := &http.Client{}

	var retentionTime time.Time
	if retentionDays > 0 {
		retentionTime = time.Now().Add(-time.Duration(retentionDays) * 24 * time.Hour)
		log.Info().Msgf("Using retention filter: only including vulnerabilities discovered on or after %s", retentionTime.Format(time.RFC3339))
	} else {
		log.Info().Msg("No retention filter set; including all vulnerabilities")
	}

	// ----- Normal Processing -----
	if !latestScan {
		aggregatedCounts := make(map[string]map[string]int)
		for {
			currentURL := baseURL + "?index=" + strconv.Itoa(currentIndex) + "&size=50&sort=vulnerability.severity,desc"
			log.Info().Msgf("Fetching vulnerabilities from URL: %s", maskURL(currentURL))
			var data []byte
			var err error
			cacheFile := ""
			if cacheDir != "" && cacheDuration > 0 {
				vulnCacheDir := cacheDir + "/vulnerabilities"
				os.MkdirAll(vulnCacheDir, 0755)
				cacheFile = vulnCacheDir + "/vulnerabilities_page_" + strconv.Itoa(currentIndex) + ".json"
				data, err = getCachedResponse(cacheFile, cacheDuration)
				if err == nil {
					log.Info().Msgf("Using cached vulnerabilities data for page %d", currentIndex)
				}
			}

			if data == nil {
				req, err := http.NewRequest("GET", currentURL, nil)
				if err != nil {
					log.Error().Err(err).Msgf("Error creating request for URL: %s", currentURL)
					return
				}
				req.Header.Set("X-Api-Key", apiKey)
				req.Header.Set("Content-Type", "application/json")

				resp, err := client.Do(req)
				if err != nil {
					log.Error().Err(err).Msgf("Error making request to URL: %s", currentURL)
					return
				}

				data, err = ioutil.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil {
					log.Error().Err(err).Msgf("Error reading response from URL: %s", currentURL)
					return
				}

				if cacheFile != "" {
					if err := saveCache(cacheFile, data); err != nil {
						log.Error().Err(err).Msg("Error saving vulnerabilities cache")
					} else {
						log.Info().Msgf("Saved vulnerabilities page %d to cache", currentIndex)
					}
				}
			}

			var vResp VulnerabilitiesResponse
			if err := json.Unmarshal(data, &vResp); err != nil {
				log.Error().Err(err).Msgf("Error decoding JSON response from URL: %s", currentURL)
				return
			}

			log.Info().Msgf("Fetched %d vulnerabilities from page index %d", len(vResp.Data), currentIndex)

			for _, vuln := range vResp.Data {
				// Apply retention filter.
				if retentionDays > 0 {
					timeStr := vuln.FirstDiscovered
					if len(timeStr) > 0 {
						lastChar := timeStr[len(timeStr)-1]
						if lastChar >= '0' && lastChar <= '9' {
							timeStr += "Z"
						}
					}
					discovered, err := time.Parse(time.RFC3339Nano, timeStr)
					if err != nil {
						discovered, err = time.Parse(time.RFC3339, timeStr)
						if err != nil {
							log.Error().Err(err).Msgf("Error parsing first_discovered for vulnerability %s", vuln.ID)
							continue
						}
					}
					if discovered.Before(retentionTime) {
						log.Debug().Msgf("Skipping vulnerability %s discovered at %s (before retention cutoff)", vuln.ID, vuln.FirstDiscovered)
						continue
					}
				}

				// Filter by allowed severities.
				if len(allowedSeverities) > 0 && !isAllowedSeverity(vuln.Severity, allowedSeverities) {
					continue
				}

				appID := vuln.App.ID
				if appID == "" {
					continue
				}
				if _, exists := aggregatedCounts[appID]; !exists {
					aggregatedCounts[appID] = make(map[string]int)
				}
				aggregatedCounts[appID][vuln.Severity]++
			}

			updateGauge(aggregatedCounts, dummyAppsList, allowedSeverities)
			log.Info().Msgf("Updated aggregated counts for %d apps so far", len(aggregatedCounts))

			if currentIndex+1 < vResp.Metadata.TotalPages {
				currentIndex++
				log.Info().Msgf("Moving to next page, index: %d", currentIndex)
			} else {
				log.Info().Msg("No more pages to fetch for vulnerabilities")
				break
			}
		}
		return
	}

	// ----- Latest Scan Processing -----
	type ScanAggregation struct {
		SeverityCounts    map[string]int
		MaxLastDiscovered time.Time
	}
	appScanAgg := make(map[string]map[string]*ScanAggregation)
	for {
		currentURL := baseURL + "?index=" + strconv.Itoa(currentIndex) + "&size=50&sort=vulnerability.severity,desc"
		log.Info().Msgf("Fetching vulnerabilities from URL: %s", maskURL(currentURL))
		var data []byte
		var err error
		cacheFile := ""
		if cacheDir != "" && cacheDuration > 0 {
			vulnCacheDir := cacheDir + "/vulnerabilities"
			os.MkdirAll(vulnCacheDir, 0755)
			cacheFile = vulnCacheDir + "/vulnerabilities_page_" + strconv.Itoa(currentIndex) + ".json"
			data, err = getCachedResponse(cacheFile, cacheDuration)
			if err == nil {
				log.Info().Msgf("Using cached vulnerabilities data for page %d", currentIndex)
			}
		}
		if data == nil {
			req, err := http.NewRequest("GET", currentURL, nil)
			if err != nil {
				log.Error().Err(err).Msgf("Error creating request for URL: %s", currentURL)
				return
			}
			req.Header.Set("X-Api-Key", apiKey)
			req.Header.Set("Content-Type", "application/json")

			resp, err := client.Do(req)
			if err != nil {
				log.Error().Err(err).Msgf("Error making request to URL: %s", currentURL)
				return
			}
			data, err = ioutil.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				log.Error().Err(err).Msgf("Error reading response from URL: %s", currentURL)
				return
			}
			if cacheFile != "" {
				if err := saveCache(cacheFile, data); err != nil {
					log.Error().Err(err).Msg("Error saving vulnerabilities cache")
				} else {
					log.Info().Msgf("Saved vulnerabilities page %d to cache", currentIndex)
				}
			}
		}
		var vResp VulnerabilitiesResponse
		if err := json.Unmarshal(data, &vResp); err != nil {
			log.Error().Err(err).Msgf("Error decoding JSON response from URL: %s", currentURL)
			return
		}

		log.Info().Msgf("Fetched %d vulnerabilities from page index %d", len(vResp.Data), currentIndex)

		for _, vuln := range vResp.Data {
			// Apply retention filter.
			if retentionDays > 0 {
				timeStr := vuln.FirstDiscovered
				if len(timeStr) > 0 {
					lastChar := timeStr[len(timeStr)-1]
					if lastChar >= '0' && lastChar <= '9' {
						timeStr += "Z"
					}
				}
				discovered, err := time.Parse(time.RFC3339Nano, timeStr)
				if err != nil {
					discovered, err = time.Parse(time.RFC3339, timeStr)
					if err != nil {
						log.Error().Err(err).Msgf("Error parsing first_discovered for vulnerability %s", vuln.ID)
						continue
					}
				}
				if discovered.Before(retentionTime) {
					log.Debug().Msgf("Skipping vulnerability %s discovered at %s (before retention cutoff)", vuln.ID, vuln.FirstDiscovered)
					continue
				}
			}

			// Filter by allowed severities.
			if len(allowedSeverities) > 0 && !isAllowedSeverity(vuln.Severity, allowedSeverities) {
				continue
			}

			appID := vuln.App.ID
			if appID == "" {
				continue
			}

			// Extract scan id.
			scanID := ""
			for _, variance := range vuln.Variances {
				scanID = extractScanID(variance.OriginalExchange.Request)
				if scanID != "" {
					break
				}
			}
			if scanID == "" {
				log.Debug().Msgf("No scan id found for vulnerability %s; skipping", vuln.ID)
				continue
			}

			// Parse last_discovered.
			timeStr := vuln.LastDiscovered
			if len(timeStr) > 0 {
				lastChar := timeStr[len(timeStr)-1]
				if lastChar >= '0' && lastChar <= '9' {
					timeStr += "Z"
				}
			}
			lastDiscovered, err := time.Parse(time.RFC3339Nano, timeStr)
			if err != nil {
				lastDiscovered, err = time.Parse(time.RFC3339, timeStr)
				if err != nil {
					log.Error().Err(err).Msgf("Error parsing last_discovered for vulnerability %s", vuln.ID)
					continue
				}
			}

			if _, exists := appScanAgg[appID]; !exists {
				appScanAgg[appID] = make(map[string]*ScanAggregation)
			}
			agg, exists := appScanAgg[appID][scanID]
			if !exists {
				agg = &ScanAggregation{
					SeverityCounts:    make(map[string]int),
					MaxLastDiscovered: lastDiscovered,
				}
				appScanAgg[appID][scanID] = agg
			}
			agg.SeverityCounts[vuln.Severity]++
			if lastDiscovered.After(agg.MaxLastDiscovered) {
				agg.MaxLastDiscovered = lastDiscovered
			}
		}

		if currentIndex+1 < vResp.Metadata.TotalPages {
			currentIndex++
			log.Info().Msgf("Moving to next page, index: %d", currentIndex)
		} else {
			log.Info().Msg("No more pages to fetch for vulnerabilities")
			break
		}
	}

	// For each app, choose the scan with the latest last_discovered.
	aggregatedCounts := make(map[string]map[string]int)
	for appID, scanMap := range appScanAgg {
		var chosenScanID string
		var maxTime time.Time
		for scanID, agg := range scanMap {
			if agg.MaxLastDiscovered.After(maxTime) {
				maxTime = agg.MaxLastDiscovered
				chosenScanID = scanID
			}
		}
		if chosenScanID != "" {
			aggregatedCounts[appID] = scanMap[chosenScanID].SeverityCounts
		}
	}

	updateGauge(aggregatedCounts, dummyAppsList, allowedSeverities)
	log.Info().Msgf("Updated aggregated counts for %d apps using latest scan filtering", len(aggregatedCounts))
}

// ----------------------------------------------------------------------
// Main Function
// ----------------------------------------------------------------------

func main() {
	var (
		retentionDays int
		latestScan    bool
		updatePeriod  int
		logLevelStr   string
		severitiesStr string
		configFile    string
		cacheDirFlag  string
	)
	flag.IntVar(&retentionDays, "retention", 0, "Retention days from current date (include only vulnerabilities discovered on or after now minus these many days; 0 means no filtering)")
	flag.BoolVar(&latestScan, "latestScan", false, "When set, only vulnerabilities from the latest scan of each app will be processed")
	flag.IntVar(&updatePeriod, "updatePeriod", 10, "Update period in minutes for fetching data")
	flag.StringVar(&logLevelStr, "loglevel", "warn", "Log level (debug, info, warn, error, fatal, panic)")
	flag.StringVar(&severitiesStr, "severities", "", "Comma-separated list of severities to include (e.g., CRITICAL,HIGH,MEDIUM,LOW)")
	flag.StringVar(&configFile, "config", "", "Path to YAML config file (overrides other flags if provided)")
	flag.StringVar(&cacheDirFlag, "cacheDir", "", "Directory to cache raw API responses from Rapid7 (optional)")
	flag.Parse()

	// Load configuration from YAML if provided.
	if configFile != "" {
		data, err := ioutil.ReadFile(configFile)
		if err != nil {
			log.Fatal().Err(err).Msg("Error reading config file")
		}
		var cfg Config
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			log.Fatal().Err(err).Msg("Error parsing YAML config file")
		}
		retentionDays = cfg.Retention
		latestScan = cfg.LatestScan
		updatePeriod = cfg.UpdatePeriod
		logLevelStr = cfg.LogLevel
		allowedSeverities = cfg.Severities
		dummyAppsList = cfg.DummyApps
		renameAppsMap = cfg.RenameApps
		cacheDir = cfg.CacheDir
		log.Info().Msg("Loaded configuration from file")
	} else {
		if severitiesStr != "" {
			parts := strings.Split(severitiesStr, ",")
			for i := range parts {
				parts[i] = strings.TrimSpace(parts[i])
			}
			allowedSeverities = parts
		} else {
			allowedSeverities = []string{}
		}
		dummyAppsList = []App{}
		renameAppsMap = make(map[string]string)
		cacheDir = cacheDirFlag
	}

	// Configure zerolog for colorful, human-friendly output.
	consoleWriter := zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339}
	log.Logger = log.Output(consoleWriter)
	level, err := zerolog.ParseLevel(logLevelStr)
	if err != nil {
		log.Warn().Msgf("Invalid log level '%s', defaulting to 'warn'", logLevelStr)
		level = zerolog.WarnLevel
	}
	zerolog.SetGlobalLevel(level)

	apiKey := os.Getenv("RAPID7_API_KEY")
	if apiKey == "" {
		log.Fatal().Msg("RAPID7_API_KEY environment variable not set")
	}

	prometheus.MustRegister(vulnerabilityCountGauge)

	// Calculate cache duration as (updatePeriod - 10 minutes) if updatePeriod > 10.
	var cacheDuration time.Duration
	if updatePeriod > 10 {
		cacheDuration = time.Duration(updatePeriod-10) * time.Minute
		log.Info().Msgf("Using cache duration: %v", cacheDuration)
	} else {
		cacheDuration = 0
		log.Info().Msg("Update period too short; caching disabled")
	}

	// Periodically update apps.
	go func() {
		for {
			fetchApps(apiKey, cacheDuration)
			time.Sleep(time.Duration(updatePeriod) * time.Minute)
		}
	}()

	// Periodically update vulnerabilities.
	go func() {
		for {
			fetchVulnerabilities(apiKey, retentionDays, latestScan, cacheDuration)
			time.Sleep(time.Duration(updatePeriod) * time.Minute)
		}
	}()

	http.Handle("/metrics", promhttp.Handler())
	log.Info().Msg("Rapid7 vulnerability exporter running on :9090/metrics")
	if err := http.ListenAndServe(":9090", nil); err != nil {
		log.Fatal().Err(err).Msg("Failed to start HTTP server")
	}
}
