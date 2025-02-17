package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"regexp"
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

// EnvPattern holds a regex pattern and the corresponding environment label.
type EnvPattern struct {
	Pattern string `yaml:"pattern"`
	Env     string `yaml:"env"`
}

// GroupPattern holds a regex pattern and the corresponding group label.
type GroupPattern struct {
	Pattern string `yaml:"pattern"`
	Group   string `yaml:"group"`
}

// RenamePattern holds a regex pattern and the corresponding new app name.
type RenamePattern struct {
	Pattern string `yaml:"pattern"`
	NewName string `yaml:"newName"`
}

// Config holds all configuration options.
type Config struct {
	Retention      int             `yaml:"retention"` // in days
	LatestScan     bool            `yaml:"latestScan"`
	UpdatePeriod   int             `yaml:"updatePeriod"` // in minutes
	LogLevel       string          `yaml:"loglevel"`
	Severities     []string        `yaml:"severities"`
	DummyApps      []App           `yaml:"dummyApps"`
	RenamePatterns []RenamePattern `yaml:"renamePatterns"` // pattern-based renaming
	CacheDir       string          `yaml:"cacheDir"`       // folder to cache raw API responses
	EnvPatterns    []EnvPattern    `yaml:"envPatterns"`    // for environment labeling
	GroupPatterns  []GroupPattern  `yaml:"groupPatterns"`  // for app grouping
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

	// renamePatterns holds the rename patterns (instead of a simple map).
	renamePatterns []RenamePattern

	// vulnerabilityCountGauge aggregates vulnerability counts by app name (transformed),
	// severity, state ("live" or "dummy"), scan_date, env and group.
	vulnerabilityCountGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "rapid7_vulnerabilities_count",
			Help: "Count of vulnerabilities per app by severity, state (live/dummy), scan_date, env, and group.",
		},
		[]string{"app_name", "severity", "state", "scan_date", "env", "group"},
	)

	mu sync.Mutex

	// Allowed severities and dummy apps from configuration.
	allowedSeverities []string
	dummyAppsList     []App

	// Cache directory for raw API responses.
	cacheDir string

	// Environment and group patterns.
	envPatterns   []EnvPattern
	groupPatterns []GroupPattern
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

// isAllowedSeverity returns true if sev is in the allowed list (case-insensitive).
func isAllowedSeverity(sev string, allowed []string) bool {
	for _, a := range allowed {
		if strings.EqualFold(a, sev) {
			return true
		}
	}
	return false
}

// getScanDate returns the scan date in YYYY-MM-DD format from a vulnerability's LastDiscovered.
func getScanDate(v Vulnerability) string {
	timeStr := v.LastDiscovered
	if len(timeStr) > 0 {
		lastChar := timeStr[len(timeStr)-1]
		if lastChar >= '0' && lastChar <= '9' {
			timeStr += "Z"
		}
	}
	t, err := time.Parse(time.RFC3339Nano, timeStr)
	if err != nil {
		t, err = time.Parse(time.RFC3339, timeStr)
		if err != nil {
			return "unknown"
		}
	}
	return t.Format("2006-01-02")
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

// getEnvironment checks the app name against the list of environment patterns.
func getEnvironment(appName string, patterns []EnvPattern) (string, bool) {
	for _, ep := range patterns {
		matched, err := regexp.MatchString(ep.Pattern, appName)
		if err == nil && matched {
			return ep.Env, true
		}
	}
	return "", false
}

// getGroup checks the app name against the list of group patterns.
func getGroup(appName string, patterns []GroupPattern) (string, bool) {
	for _, gp := range patterns {
		matched, err := regexp.MatchString(gp.Pattern, appName)
		if err == nil && matched {
			return gp.Group, true
		}
	}
	return "", false
}

// applyRename applies rename patterns to an app name.
// For each rename pattern, if the regex pattern matches, it replaces the matched part
// with the provided newName (using regexp.ReplaceAllString) and returns the result.
// If no pattern matches, the original app name is returned.
func applyRename(appName string, patterns []RenamePattern) string {
	for _, rp := range patterns {
		re, err := regexp.Compile(rp.Pattern)
		if err != nil {
			log.Error().Err(err).Msgf("Invalid rename pattern: %s", rp.Pattern)
			continue
		}
		if re.MatchString(appName) {
			return re.ReplaceAllString(appName, rp.NewName)
		}
	}
	return appName
}

// ----------------------------------------------------------------------
// Gauge Update Functions
// ----------------------------------------------------------------------

// updateGaugeNormal aggregates live data from normal processing.
// aggregatedCounts is a map: appID -> scan_date -> severity -> count.
func updateGaugeNormal(aggregatedCounts map[string]map[string]map[string]int, dummyApps []App, allowed []string) {
	mu.Lock()
	defer mu.Unlock()
	vulnerabilityCountGauge.Reset()
	// finalCounts: compositeKey = finalName|env|group -> scan_date -> severity -> count.
	finalCounts := make(map[string]map[string]map[string]int)
	for appID, dateMap := range aggregatedCounts {
		appMapMu.RLock()
		origName, exists := appMap[appID]
		appMapMu.RUnlock()
		if !exists {
			origName = "unknown"
		}
		finalName := applyRename(origName, renamePatterns)
		envVal, _ := getEnvironment(origName, envPatterns)
		groupVal, _ := getGroup(origName, groupPatterns)
		compositeKey := finalName + "|" + envVal + "|" + groupVal
		if _, exists := finalCounts[compositeKey]; !exists {
			finalCounts[compositeKey] = make(map[string]map[string]int)
		}
		for scanDate, sevMap := range dateMap {
			if _, exists := finalCounts[compositeKey][scanDate]; !exists {
				finalCounts[compositeKey][scanDate] = make(map[string]int)
			}
			for sev, count := range sevMap {
				finalCounts[compositeKey][scanDate][sev] += count
			}
		}
	}
	// Update gauge for live data.
	for compositeKey, dateMap := range finalCounts {
		parts := strings.SplitN(compositeKey, "|", 3)
		finalName := parts[0]
		envVal := ""
		groupVal := ""
		if len(parts) > 1 {
			envVal = parts[1]
		}
		if len(parts) > 2 {
			groupVal = parts[2]
		}
		for scanDate, sevMap := range dateMap {
			for sev, count := range sevMap {
				vulnerabilityCountGauge.With(prometheus.Labels{
					"app_name":  finalName,
					"severity":  sev,
					"state":     "live",
					"scan_date": scanDate,
					"env":       envVal,
					"group":     groupVal,
				}).Set(float64(count))
			}
		}
	}
	// Add dummy apps: add only a "LOW" entry with state "dummy", scan_date "n/a", and env/group from pattern matching.
	for _, dummyApp := range dummyApps {
		origName := dummyApp.Name
		finalName := applyRename(origName, renamePatterns)
		envVal, _ := getEnvironment(origName, envPatterns)
		groupVal, _ := getGroup(origName, groupPatterns)
		compositeKey := finalName + "|" + envVal + "|" + groupVal
		found := false
		for _, dateMap := range finalCounts {
			if _, exists := dateMap[compositeKey]; exists {
				found = true
				break
			}
		}
		if !found {
			vulnerabilityCountGauge.With(prometheus.Labels{
				"app_name":  finalName,
				"severity":  "LOW",
				"state":     "dummy",
				"scan_date": "n/a",
				"env":       envVal,
				"group":     groupVal,
			}).Set(0)
		}
	}
}

// updateGaugeLatest aggregates live data from latest scan processing.
// aggregatedCounts is a map: appID -> severity -> count.
// chosenScanDates maps appID to the chosen scan date (formatted as "YYYY-MM-DD").
// Grouping is done by composite key: finalName|env|group.
func updateGaugeLatest(aggregatedCounts map[string]map[string]int, chosenScanDates map[string]string, dummyApps []App, allowed []string) {
	mu.Lock()
	defer mu.Unlock()
	vulnerabilityCountGauge.Reset()
	finalCounts := make(map[string]map[string]int) // finalCounts[compositeKey][severity]
	finalScanDates := make(map[string]string)      // finalScanDates[compositeKey] = latest scan date
	for appID, sevMap := range aggregatedCounts {
		appMapMu.RLock()
		origName, exists := appMap[appID]
		appMapMu.RUnlock()
		if !exists {
			origName = "unknown"
		}
		finalName := applyRename(origName, renamePatterns)
		envVal, _ := getEnvironment(origName, envPatterns)
		groupVal, _ := getGroup(origName, groupPatterns)
		compositeKey := finalName + "|" + envVal + "|" + groupVal
		if _, exists := finalCounts[compositeKey]; !exists {
			finalCounts[compositeKey] = make(map[string]int)
		}
		for sev, count := range sevMap {
			finalCounts[compositeKey][sev] += count
		}
		scanDate, ok := chosenScanDates[appID]
		if !ok {
			scanDate = "unknown"
		}
		if cur, exists := finalScanDates[compositeKey]; !exists {
			finalScanDates[compositeKey] = scanDate
		} else {
			if scanDate > cur {
				finalScanDates[compositeKey] = scanDate
			}
		}
	}
	// Update gauge for live data.
	for compositeKey, sevMap := range finalCounts {
		parts := strings.SplitN(compositeKey, "|", 3)
		finalName := parts[0]
		envVal := ""
		groupVal := ""
		if len(parts) > 1 {
			envVal = parts[1]
		}
		if len(parts) > 2 {
			groupVal = parts[2]
		}
		scanDate := finalScanDates[compositeKey]
		for sev, count := range sevMap {
			vulnerabilityCountGauge.With(prometheus.Labels{
				"app_name":  finalName,
				"severity":  sev,
				"state":     "live",
				"scan_date": scanDate,
				"env":       envVal,
				"group":     groupVal,
			}).Set(float64(count))
		}
	}
	// Add dummy apps.
	for _, dummyApp := range dummyApps {
		origName := dummyApp.Name
		finalName := applyRename(origName, renamePatterns)
		envVal, _ := getEnvironment(origName, envPatterns)
		groupVal, _ := getGroup(origName, groupPatterns)
		compositeKey := finalName + "|" + envVal + "|" + groupVal
		if _, exists := finalCounts[compositeKey]; !exists {
			vulnerabilityCountGauge.With(prometheus.Labels{
				"app_name":  finalName,
				"severity":  "LOW",
				"state":     "dummy",
				"scan_date": "n/a",
				"env":       envVal,
				"group":     groupVal,
			}).Set(0)
		}
	}
}

// ----------------------------------------------------------------------
// Fetching Data: Vulnerabilities and Apps
// ----------------------------------------------------------------------

// fetchApps retrieves the list of apps from the Rapid7 Apps API and updates appMap.
// If caching is enabled, it reuses cached data if it’s not older than (updatePeriod - 10 minutes).
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

// fetchVulnerabilities retrieves vulnerabilities from the Rapid7 API.
// It applies retention and severity filters. In normal mode, data is grouped by app and scan_date;
// in latestScan mode, data is grouped by app and scan (using scanID) and only the latest scan is chosen.
// Raw responses are cached if enabled.
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
	// ----- Normal Processing: Group by app and scan_date -----
	if !latestScan {
		aggregatedCounts := make(map[string]map[string]map[string]int) // appID -> scan_date -> severity -> count
		for {
			currentURL := baseURL + "?index=" + strconv.Itoa(currentIndex) + "&size=50&sort=vulnerability.severity,desc"
			log.Info().Msgf("Fetching vulnerabilities from URL: %s", maskURL(currentURL))
			var data []byte
			var err error
			cacheFile := ""
			if cacheDir != "" && cacheDuration > 0 {
				vulnCacheDir := cacheDir + "/vulnerabilities"
				os.MkdirAll(vulnCacheDir, 0755)
				cacheFile = fmt.Sprintf("%s/vulnerabilities_page_%d.json", vulnCacheDir, currentIndex)
				data, err = getCachedResponse(cacheFile, cacheDuration)
				if err == nil {
					log.Info().Msgf("Using cached vulnerabilities data for page %d", currentIndex)
				}
			}
			if data == nil {
				var req *http.Request
				req, err = http.NewRequest("GET", currentURL, nil)
				if err != nil {
					log.Error().Err(err).Msgf("Error creating request for URL: %s", currentURL)
					return
				}
				req.Header.Set("X-Api-Key", apiKey)
				req.Header.Set("Content-Type", "application/json")
				var resp *http.Response
				resp, err = client.Do(req)
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
				// Retention filter.
				if retentionDays > 0 {
					timeStr := vuln.FirstDiscovered
					if len(timeStr) > 0 {
						lastChar := timeStr[len(timeStr)-1]
						if lastChar >= '0' && lastChar <= '9' {
							timeStr += "Z"
						}
					}
					var discovered time.Time
					discovered, err = time.Parse(time.RFC3339Nano, timeStr)
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
				scanDate := getScanDate(vuln)
				if _, exists := aggregatedCounts[appID]; !exists {
					aggregatedCounts[appID] = make(map[string]map[string]int)
				}
				if _, exists := aggregatedCounts[appID][scanDate]; !exists {
					aggregatedCounts[appID][scanDate] = make(map[string]int)
				}
				aggregatedCounts[appID][scanDate][vuln.Severity]++
			}
			updateGaugeNormal(aggregatedCounts, dummyAppsList, allowedSeverities)
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

	// ----- Latest Scan Processing: Group by app and scan (using scanID) -----
	type ScanAggregation struct {
		SeverityCounts    map[string]int
		MaxLastDiscovered time.Time
	}
	appScanAgg := make(map[string]map[string]*ScanAggregation) // appID -> scanID -> aggregation
	chosenScanDates := make(map[string]string)                 // appID -> chosen scan date
	for {
		currentURL := baseURL + "?index=" + strconv.Itoa(currentIndex) + "&size=50&sort=vulnerability.severity,desc"
		log.Info().Msgf("Fetching vulnerabilities from URL: %s", maskURL(currentURL))
		var data []byte
		var err error
		cacheFile := ""
		if cacheDir != "" && cacheDuration > 0 {
			vulnCacheDir := cacheDir + "/vulnerabilities"
			os.MkdirAll(vulnCacheDir, 0755)
			cacheFile = fmt.Sprintf("%s/vulnerabilities_page_%d.json", vulnCacheDir, currentIndex)
			data, err = getCachedResponse(cacheFile, cacheDuration)
			if err == nil {
				log.Info().Msgf("Using cached vulnerabilities data for page %d", currentIndex)
			}
		}
		if data == nil {
			var req *http.Request
			req, err = http.NewRequest("GET", currentURL, nil)
			if err != nil {
				log.Error().Err(err).Msgf("Error creating request for URL: %s", currentURL)
				return
			}
			req.Header.Set("X-Api-Key", apiKey)
			req.Header.Set("Content-Type", "application/json")
			var resp *http.Response
			resp, err = client.Do(req)
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
			// Retention filter.
			if retentionDays > 0 {
				timeStr := vuln.FirstDiscovered
				if len(timeStr) > 0 {
					lastChar := timeStr[len(timeStr)-1]
					if lastChar >= '0' && lastChar <= '9' {
						timeStr += "Z"
					}
				}
				var discovered time.Time
				discovered, err = time.Parse(time.RFC3339Nano, timeStr)
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
			var lastDiscovered time.Time
			lastDiscovered, err = time.Parse(time.RFC3339Nano, timeStr)
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
	aggregatedCounts := make(map[string]map[string]int) // appID -> severity -> count
	chosenScanDates = make(map[string]string)           // appID -> chosen scan date
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
			chosenScanDates[appID] = maxTime.Format("2006-01-02")
		}
	}
	updateGaugeLatest(aggregatedCounts, chosenScanDates, dummyAppsList, allowedSeverities)
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

	// If the CONFIG_FILE environment variable is set, override the config file flag.
	if envConfig := os.Getenv("CONFIG_FILE"); envConfig != "" {
		configFile = envConfig
	}

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
		renamePatterns = cfg.RenamePatterns
		cacheDir = cfg.CacheDir
		envPatterns = cfg.EnvPatterns
		groupPatterns = cfg.GroupPatterns
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
		renamePatterns = []RenamePattern{}
		cacheDir = cacheDirFlag
		envPatterns = []EnvPattern{}
		groupPatterns = []GroupPattern{}
	}

	// Configure zerolog.
	consoleWriter := zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339}
	log.Logger = log.Output(consoleWriter)
	parsedLevel, err := zerolog.ParseLevel(logLevelStr)
	if err != nil {
		log.Warn().Msgf("Invalid log level '%s', defaulting to 'warn'", logLevelStr)
		parsedLevel = zerolog.WarnLevel
	}
	zerolog.SetGlobalLevel(parsedLevel)

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
	log.Info().Msg("rapid7exporter running on :9090/metrics")
	if err := http.ListenAndServe(":9090", nil); err != nil {
		log.Fatal().Err(err).Msg("Failed to start HTTP server")
	}
}
