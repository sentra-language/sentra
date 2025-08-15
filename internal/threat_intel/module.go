package threat_intel

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ThreatIntelModule provides threat intelligence capabilities
type ThreatIntelModule struct {
	apiKeys     map[string]string
	cache       map[string]*CachedResult
	cacheMutex  sync.RWMutex
	httpClient  *http.Client
	sources     []ThreatSource
}

// Value interface for VM compatibility
type Value interface{}

// CachedResult represents a cached threat intelligence result
type CachedResult struct {
	Result    *ThreatResult
	Timestamp time.Time
	TTL       time.Duration
}

// ThreatResult represents threat intelligence data
type ThreatResult struct {
	Indicator    string                 `json:"indicator"`
	Type         string                 `json:"type"`
	Reputation   string                 `json:"reputation"`
	Score        int                    `json:"score"`
	Sources      []string               `json:"sources"`
	FirstSeen    time.Time              `json:"first_seen"`
	LastSeen     time.Time              `json:"last_seen"`
	Malicious    bool                   `json:"malicious"`
	Categories   []string               `json:"categories"`
	Geography    string                 `json:"geography"`
	ASN          string                 `json:"asn"`
	Details      map[string]interface{} `json:"details"`
}

// ThreatSource represents a threat intelligence source
type ThreatSource struct {
	Name        string
	BaseURL     string
	APIKey      string
	RateLimit   int
	Enabled     bool
	LastRequest time.Time
}

// IOCPattern represents patterns for extracting IOCs
type IOCPattern struct {
	Name    string
	Pattern *regexp.Regexp
	Type    string
}

// NewThreatIntelModule creates a new threat intelligence module
func NewThreatIntelModule() *ThreatIntelModule {
	return &ThreatIntelModule{
		apiKeys: make(map[string]string),
		cache:   make(map[string]*CachedResult),
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		sources: []ThreatSource{
			{
				Name:      "VirusTotal",
				BaseURL:   "https://www.virustotal.com/vtapi/v2/",
				Enabled:   false,
				RateLimit: 4, // requests per minute for free tier
			},
			{
				Name:      "AbuseIPDB",
				BaseURL:   "https://api.abuseipdb.com/api/v2/",
				Enabled:   false,
				RateLimit: 1000, // requests per day
			},
			{
				Name:      "AlienVault",
				BaseURL:   "https://otx.alienvault.com/api/v1/",
				Enabled:   false,
				RateLimit: 10000, // requests per hour
			},
		},
	}
}

// SetAPIKey sets an API key for a threat intelligence source
func (tim *ThreatIntelModule) SetAPIKey(source, apiKey string) bool {
	tim.apiKeys[strings.ToLower(source)] = apiKey
	
	// Enable the source if API key is provided
	for i := range tim.sources {
		if strings.EqualFold(tim.sources[i].Name, source) {
			tim.sources[i].APIKey = apiKey
			tim.sources[i].Enabled = true
			return true
		}
	}
	return false
}

// LookupIP performs threat intelligence lookup for IP addresses
func (tim *ThreatIntelModule) LookupIP(ip string) *ThreatResult {
	if !tim.isValidIP(ip) {
		return nil
	}
	
	// Check cache first
	if cached := tim.getCached(ip); cached != nil {
		return cached
	}
	
	result := &ThreatResult{
		Indicator:  ip,
		Type:       "ip",
		Sources:    []string{},
		Categories: []string{},
		Details:    make(map[string]interface{}),
		FirstSeen:  time.Now(),
		LastSeen:   time.Now(),
	}
	
	// Perform lookups from enabled sources
	for _, source := range tim.sources {
		if !source.Enabled {
			continue
		}
		
		switch strings.ToLower(source.Name) {
		case "virustotal":
			tim.queryVirusTotal(ip, result)
		case "abuseipdb":
			tim.queryAbuseIPDB(ip, result)
		case "alienvault":
			tim.queryAlienVault(ip, result)
		}
	}
	
	// Determine overall reputation
	tim.calculateReputation(result)
	
	// Cache result
	tim.setCached(ip, result, 1*time.Hour)
	
	return result
}

// LookupHash performs threat intelligence lookup for file hashes
func (tim *ThreatIntelModule) LookupHash(hash string) *ThreatResult {
	hash = strings.ToLower(strings.TrimSpace(hash))
	
	if !tim.isValidHash(hash) {
		return nil
	}
	
	// Check cache first
	if cached := tim.getCached(hash); cached != nil {
		return cached
	}
	
	result := &ThreatResult{
		Indicator:  hash,
		Type:       tim.getHashType(hash),
		Sources:    []string{},
		Categories: []string{},
		Details:    make(map[string]interface{}),
		FirstSeen:  time.Now(),
		LastSeen:   time.Now(),
	}
	
	// Perform lookups from enabled sources
	for _, source := range tim.sources {
		if !source.Enabled {
			continue
		}
		
		switch strings.ToLower(source.Name) {
		case "virustotal":
			tim.queryVirusTotalHash(hash, result)
		}
	}
	
	// Determine overall reputation
	tim.calculateReputation(result)
	
	// Cache result
	tim.setCached(hash, result, 4*time.Hour)
	
	return result
}

// LookupDomain performs threat intelligence lookup for domains
func (tim *ThreatIntelModule) LookupDomain(domain string) *ThreatResult {
	domain = strings.ToLower(strings.TrimSpace(domain))
	
	if !tim.isValidDomain(domain) {
		return nil
	}
	
	// Check cache first
	if cached := tim.getCached(domain); cached != nil {
		return cached
	}
	
	result := &ThreatResult{
		Indicator:  domain,
		Type:       "domain",
		Sources:    []string{},
		Categories: []string{},
		Details:    make(map[string]interface{}),
		FirstSeen:  time.Now(),
		LastSeen:   time.Now(),
	}
	
	// Perform lookups from enabled sources
	for _, source := range tim.sources {
		if !source.Enabled {
			continue
		}
		
		switch strings.ToLower(source.Name) {
		case "virustotal":
			tim.queryVirusTotalDomain(domain, result)
		case "alienvault":
			tim.queryAlienVaultDomain(domain, result)
		}
	}
	
	// Determine overall reputation
	tim.calculateReputation(result)
	
	// Cache result
	tim.setCached(domain, result, 2*time.Hour)
	
	return result
}

// ExtractIOCs extracts indicators of compromise from text
func (tim *ThreatIntelModule) ExtractIOCs(text string) map[string][]string {
	patterns := []IOCPattern{
		{
			Name:    "IPv4",
			Pattern: regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`),
			Type:    "ip",
		},
		{
			Name:    "MD5",
			Pattern: regexp.MustCompile(`\b[a-fA-F0-9]{32}\b`),
			Type:    "hash",
		},
		{
			Name:    "SHA1",
			Pattern: regexp.MustCompile(`\b[a-fA-F0-9]{40}\b`),
			Type:    "hash",
		},
		{
			Name:    "SHA256",
			Pattern: regexp.MustCompile(`\b[a-fA-F0-9]{64}\b`),
			Type:    "hash",
		},
		{
			Name:    "Domain",
			Pattern: regexp.MustCompile(`\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b`),
			Type:    "domain",
		},
		{
			Name:    "URL",
			Pattern: regexp.MustCompile(`https?://[^\s<>"{}|\\^` + "`" + `\[\]]+`),
			Type:    "url",
		},
		{
			Name:    "Email",
			Pattern: regexp.MustCompile(`\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b`),
			Type:    "email",
		},
	}
	
	results := make(map[string][]string)
	
	for _, pattern := range patterns {
		matches := pattern.Pattern.FindAllString(text, -1)
		if len(matches) > 0 {
			// Remove duplicates
			unique := make(map[string]bool)
			for _, match := range matches {
				// Additional validation
				if tim.validateIOC(match, pattern.Type) {
					unique[strings.ToLower(match)] = true
				}
			}
			
			for ioc := range unique {
				results[pattern.Type] = append(results[pattern.Type], ioc)
			}
		}
	}
	
	return results
}

// BulkLookup performs bulk threat intelligence lookups
func (tim *ThreatIntelModule) BulkLookup(indicators []string) map[string]*ThreatResult {
	results := make(map[string]*ThreatResult)
	
	for _, indicator := range indicators {
		indicator = strings.TrimSpace(indicator)
		if indicator == "" {
			continue
		}
		
		var result *ThreatResult
		
		if tim.isValidIP(indicator) {
			result = tim.LookupIP(indicator)
		} else if tim.isValidHash(indicator) {
			result = tim.LookupHash(indicator)
		} else if tim.isValidDomain(indicator) {
			result = tim.LookupDomain(indicator)
		}
		
		if result != nil {
			results[indicator] = result
		}
	}
	
	return results
}

// GetReputation gets overall reputation for an indicator
func (tim *ThreatIntelModule) GetReputation(indicator string) string {
	indicator = strings.TrimSpace(indicator)
	
	var result *ThreatResult
	
	if tim.isValidIP(indicator) {
		result = tim.LookupIP(indicator)
	} else if tim.isValidHash(indicator) {
		result = tim.LookupHash(indicator)
	} else if tim.isValidDomain(indicator) {
		result = tim.LookupDomain(indicator)
	}
	
	if result != nil {
		return result.Reputation
	}
	
	return "unknown"
}

// Helper methods

func (tim *ThreatIntelModule) isValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

func (tim *ThreatIntelModule) isValidHash(hash string) bool {
	hash = strings.ToLower(strings.TrimSpace(hash))
	switch len(hash) {
	case 32: // MD5
		_, err := hex.DecodeString(hash)
		return err == nil
	case 40: // SHA1
		_, err := hex.DecodeString(hash)
		return err == nil
	case 64: // SHA256
		_, err := hex.DecodeString(hash)
		return err == nil
	default:
		return false
	}
}

func (tim *ThreatIntelModule) getHashType(hash string) string {
	switch len(hash) {
	case 32:
		return "md5"
	case 40:
		return "sha1"
	case 64:
		return "sha256"
	default:
		return "hash"
	}
}

func (tim *ThreatIntelModule) isValidDomain(domain string) bool {
	if len(domain) > 253 {
		return false
	}
	
	// Simple domain validation
	domainRegex := regexp.MustCompile(`^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	return domainRegex.MatchString(domain)
}

func (tim *ThreatIntelModule) validateIOC(ioc, iocType string) bool {
	switch iocType {
	case "ip":
		return tim.isValidIP(ioc) && !tim.isPrivateIP(ioc)
	case "hash":
		return tim.isValidHash(ioc)
	case "domain":
		return tim.isValidDomain(ioc) && !tim.isCommonDomain(ioc)
	case "url":
		return len(ioc) > 7 && (strings.HasPrefix(ioc, "http://") || strings.HasPrefix(ioc, "https://"))
	case "email":
		return strings.Contains(ioc, "@") && strings.Contains(ioc, ".")
	default:
		return true
	}
}

func (tim *ThreatIntelModule) isPrivateIP(ip string) bool {
	privateRanges := []string{
		"127.0.0.0/8",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
	}
	
	for _, cidr := range privateRanges {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(net.ParseIP(ip)) {
			return true
		}
	}
	return false
}

func (tim *ThreatIntelModule) isCommonDomain(domain string) bool {
	common := []string{"google.com", "facebook.com", "twitter.com", "microsoft.com", "apple.com"}
	for _, d := range common {
		if strings.HasSuffix(domain, d) {
			return true
		}
	}
	return false
}

func (tim *ThreatIntelModule) getCached(key string) *ThreatResult {
	tim.cacheMutex.RLock()
	defer tim.cacheMutex.RUnlock()
	
	if cached, exists := tim.cache[key]; exists {
		if time.Since(cached.Timestamp) < cached.TTL {
			return cached.Result
		}
		// Remove expired entry
		delete(tim.cache, key)
	}
	return nil
}

func (tim *ThreatIntelModule) setCached(key string, result *ThreatResult, ttl time.Duration) {
	tim.cacheMutex.Lock()
	defer tim.cacheMutex.Unlock()
	
	tim.cache[key] = &CachedResult{
		Result:    result,
		Timestamp: time.Now(),
		TTL:       ttl,
	}
}

func (tim *ThreatIntelModule) calculateReputation(result *ThreatResult) {
	if result.Score >= 75 {
		result.Reputation = "malicious"
		result.Malicious = true
	} else if result.Score >= 50 {
		result.Reputation = "suspicious"
	} else if result.Score >= 25 {
		result.Reputation = "questionable"
	} else {
		result.Reputation = "clean"
	}
	
	if len(result.Sources) == 0 {
		result.Reputation = "unknown"
	}
}

// Placeholder API query methods (these would contain actual API calls)
func (tim *ThreatIntelModule) queryVirusTotal(ip string, result *ThreatResult) {
	// Simulated VirusTotal response
	result.Sources = append(result.Sources, "VirusTotal")
	result.Score += 20
}

func (tim *ThreatIntelModule) queryAbuseIPDB(ip string, result *ThreatResult) {
	// Simulated AbuseIPDB response
	result.Sources = append(result.Sources, "AbuseIPDB")
	result.Score += 30
}

func (tim *ThreatIntelModule) queryAlienVault(ip string, result *ThreatResult) {
	// Simulated AlienVault response
	result.Sources = append(result.Sources, "AlienVault")
	result.Score += 25
}

func (tim *ThreatIntelModule) queryVirusTotalHash(hash string, result *ThreatResult) {
	// Simulated VirusTotal hash lookup
	result.Sources = append(result.Sources, "VirusTotal")
	result.Score += 40
}

func (tim *ThreatIntelModule) queryVirusTotalDomain(domain string, result *ThreatResult) {
	// Simulated VirusTotal domain lookup
	result.Sources = append(result.Sources, "VirusTotal")
	result.Score += 15
}

func (tim *ThreatIntelModule) queryAlienVaultDomain(domain string, result *ThreatResult) {
	// Simulated AlienVault domain lookup
	result.Sources = append(result.Sources, "AlienVault")
	result.Score += 20
}

// Hash generation utilities
func (tim *ThreatIntelModule) GenerateMD5(data string) string {
	hash := md5.Sum([]byte(data))
	return hex.EncodeToString(hash[:])
}

func (tim *ThreatIntelModule) GenerateSHA1(data string) string {
	hash := sha1.Sum([]byte(data))
	return hex.EncodeToString(hash[:])
}

func (tim *ThreatIntelModule) GenerateSHA256(data string) string {
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}