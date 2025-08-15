// internal/cloud/cspm.go
package cloud

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// CSPMModule provides Cloud Security Posture Management capabilities
type CSPMModule struct {
	providers map[string]*CloudProvider
	policies  map[string]*SecurityPolicy
	findings  []SecurityFinding
}

// CloudProvider represents a cloud service provider
type CloudProvider struct {
	Name        string
	Type        string // AWS, Azure, GCP
	Credentials map[string]string
	Resources   []CloudResource
}

// CloudResource represents a cloud resource
type CloudResource struct {
	ID           string
	Type         string
	Name         string
	Region       string
	Tags         map[string]string
	Config       map[string]interface{}
	LastScanned  time.Time
	Compliance   ComplianceStatus
}

// SecurityPolicy represents a security policy or benchmark
type SecurityPolicy struct {
	ID          string
	Name        string
	Description string
	Provider    string
	Rules       []PolicyRule
	Severity    string
}

// PolicyRule represents a single rule in a policy
type PolicyRule struct {
	ID          string
	Description string
	Check       func(CloudResource) bool
	Remediation string
}

// SecurityFinding represents a security issue found
type SecurityFinding struct {
	ID           string
	ResourceID   string
	PolicyID     string
	RuleID       string
	Severity     string
	Description  string
	Remediation  string
	FoundAt      time.Time
	Status       string // open, resolved, ignored
}

// ComplianceStatus represents compliance state
type ComplianceStatus struct {
	Compliant    bool
	Score        float64
	FailedChecks []string
	PassedChecks []string
}

// NewCSPMModule creates a new CSPM module
func NewCSPMModule() *CSPMModule {
	cspm := &CSPMModule{
		providers: make(map[string]*CloudProvider),
		policies:  make(map[string]*SecurityPolicy),
		findings:  []SecurityFinding{},
	}
	
	// Initialize default policies
	cspm.initializeDefaultPolicies()
	
	return cspm
}

// initializeDefaultPolicies sets up common security policies
func (c *CSPMModule) initializeDefaultPolicies() {
	// AWS CIS Benchmark policies
	c.policies["aws-cis-1.4"] = &SecurityPolicy{
		ID:          "aws-cis-1.4",
		Name:        "AWS CIS Benchmark v1.4",
		Description: "Center for Internet Security AWS Foundations Benchmark",
		Provider:    "AWS",
		Severity:    "HIGH",
		Rules: []PolicyRule{
			{
				ID:          "cis-1.1",
				Description: "Ensure MFA is enabled for root account",
				Check: func(r CloudResource) bool {
					if r.Type != "aws:iam:root" {
						return true
					}
					mfa, ok := r.Config["mfa_enabled"].(bool)
					return ok && mfa
				},
				Remediation: "Enable MFA for root account in IAM console",
			},
			{
				ID:          "cis-2.1",
				Description: "Ensure S3 bucket logging is enabled",
				Check: func(r CloudResource) bool {
					if r.Type != "aws:s3:bucket" {
						return true
					}
					logging, ok := r.Config["logging_enabled"].(bool)
					return ok && logging
				},
				Remediation: "Enable server access logging for S3 bucket",
			},
			{
				ID:          "cis-2.2",
				Description: "Ensure S3 bucket public access is blocked",
				Check: func(r CloudResource) bool {
					if r.Type != "aws:s3:bucket" {
						return true
					}
					public, ok := r.Config["public_access_blocked"].(bool)
					return ok && public
				},
				Remediation: "Block public access in S3 bucket settings",
			},
			{
				ID:          "cis-3.1",
				Description: "Ensure CloudTrail is enabled in all regions",
				Check: func(r CloudResource) bool {
					if r.Type != "aws:cloudtrail:trail" {
						return true
					}
					multiRegion, ok := r.Config["is_multi_region"].(bool)
					return ok && multiRegion
				},
				Remediation: "Enable multi-region CloudTrail",
			},
		},
	}
	
	// Azure Security Center policies
	c.policies["azure-sc-baseline"] = &SecurityPolicy{
		ID:          "azure-sc-baseline",
		Name:        "Azure Security Center Baseline",
		Description: "Azure Security Center recommended baseline",
		Provider:    "Azure",
		Severity:    "HIGH",
		Rules: []PolicyRule{
			{
				ID:          "azure-1.1",
				Description: "Ensure storage accounts use encryption",
				Check: func(r CloudResource) bool {
					if r.Type != "azure:storage:account" {
						return true
					}
					encrypted, ok := r.Config["encryption_enabled"].(bool)
					return ok && encrypted
				},
				Remediation: "Enable encryption for storage account",
			},
			{
				ID:          "azure-2.1",
				Description: "Ensure network security groups are restrictive",
				Check: func(r CloudResource) bool {
					if r.Type != "azure:network:nsg" {
						return true
					}
					// Check for overly permissive rules
					rules, ok := r.Config["inbound_rules"].([]interface{})
					if !ok {
						return false
					}
					for _, rule := range rules {
						if r, ok := rule.(map[string]interface{}); ok {
							if src, ok := r["source"].(string); ok && src == "*" {
								if port, ok := r["port"].(string); ok && (port == "22" || port == "3389") {
									return false
								}
							}
						}
					}
					return true
				},
				Remediation: "Restrict NSG rules to specific IP ranges",
			},
		},
	}
	
	// GCP Security Command Center policies
	c.policies["gcp-scc-baseline"] = &SecurityPolicy{
		ID:          "gcp-scc-baseline",
		Name:        "GCP Security Command Center Baseline",
		Description: "Google Cloud Platform security baseline",
		Provider:    "GCP",
		Severity:    "HIGH",
		Rules: []PolicyRule{
			{
				ID:          "gcp-1.1",
				Description: "Ensure Cloud Storage buckets are not public",
				Check: func(r CloudResource) bool {
					if r.Type != "gcp:storage:bucket" {
						return true
					}
					public, ok := r.Config["public_access"].(bool)
					return ok && !public
				},
				Remediation: "Remove public access from Cloud Storage bucket",
			},
			{
				ID:          "gcp-2.1",
				Description: "Ensure Compute instances use service accounts",
				Check: func(r CloudResource) bool {
					if r.Type != "gcp:compute:instance" {
						return true
					}
					sa, ok := r.Config["service_account"].(string)
					return ok && sa != ""
				},
				Remediation: "Assign service account to Compute instance",
			},
		},
	}
}

// AddProvider adds a cloud provider configuration
func (c *CSPMModule) AddProvider(name, providerType string, credentials map[string]string) error {
	if _, exists := c.providers[name]; exists {
		return fmt.Errorf("provider %s already exists", name)
	}
	
	c.providers[name] = &CloudProvider{
		Name:        name,
		Type:        providerType,
		Credentials: credentials,
		Resources:   []CloudResource{},
	}
	
	return nil
}

// ScanProvider scans a cloud provider for resources and compliance
func (c *CSPMModule) ScanProvider(providerName string) (*ComplianceReport, error) {
	provider, exists := c.providers[providerName]
	if !exists {
		return nil, fmt.Errorf("provider %s not found", providerName)
	}
	
	// Simulate resource discovery
	resources := c.discoverResources(provider)
	provider.Resources = resources
	
	// Run security policies
	report := &ComplianceReport{
		Provider:  providerName,
		Timestamp: time.Now(),
		Resources: len(resources),
	}
	
	for _, policy := range c.policies {
		if policy.Provider != provider.Type && policy.Provider != "*" {
			continue
		}
		
		policyResult := c.evaluatePolicy(policy, resources)
		report.PolicyResults = append(report.PolicyResults, policyResult)
	}
	
	// Calculate overall compliance score
	report.calculateScore()
	
	return report, nil
}

// discoverResources simulates resource discovery
func (c *CSPMModule) discoverResources(provider *CloudProvider) []CloudResource {
	// In a real implementation, this would use cloud provider APIs
	// For demonstration, we'll simulate some resources
	
	resources := []CloudResource{}
	
	switch provider.Type {
	case "AWS":
		resources = append(resources, CloudResource{
			ID:     "bucket-001",
			Type:   "aws:s3:bucket",
			Name:   "sensitive-data-bucket",
			Region: "us-east-1",
			Config: map[string]interface{}{
				"logging_enabled":       true,
				"public_access_blocked": false, // Non-compliant
				"encryption":           "AES256",
			},
			LastScanned: time.Now(),
		})
		resources = append(resources, CloudResource{
			ID:     "trail-001",
			Type:   "aws:cloudtrail:trail",
			Name:   "main-trail",
			Region: "us-east-1",
			Config: map[string]interface{}{
				"is_multi_region": false, // Non-compliant
				"is_logging":      true,
			},
			LastScanned: time.Now(),
		})
		
	case "Azure":
		resources = append(resources, CloudResource{
			ID:     "storage-001",
			Type:   "azure:storage:account",
			Name:   "productiondata",
			Region: "eastus",
			Config: map[string]interface{}{
				"encryption_enabled": true,
				"https_only":        true,
			},
			LastScanned: time.Now(),
		})
		
	case "GCP":
		resources = append(resources, CloudResource{
			ID:     "bucket-001",
			Type:   "gcp:storage:bucket",
			Name:   "app-uploads",
			Region: "us-central1",
			Config: map[string]interface{}{
				"public_access": true, // Non-compliant
				"versioning":    true,
			},
			LastScanned: time.Now(),
		})
	}
	
	return resources
}

// evaluatePolicy evaluates a security policy against resources
func (c *CSPMModule) evaluatePolicy(policy *SecurityPolicy, resources []CloudResource) *PolicyResult {
	result := &PolicyResult{
		PolicyID:     policy.ID,
		PolicyName:   policy.Name,
		TotalChecks:  0,
		PassedChecks: 0,
		FailedChecks: 0,
		Findings:     []SecurityFinding{},
	}
	
	for _, resource := range resources {
		for _, rule := range policy.Rules {
			result.TotalChecks++
			
			if rule.Check(resource) {
				result.PassedChecks++
			} else {
				result.FailedChecks++
				
				// Create finding
				finding := SecurityFinding{
					ID:          fmt.Sprintf("finding-%d", len(c.findings)+1),
					ResourceID:  resource.ID,
					PolicyID:    policy.ID,
					RuleID:      rule.ID,
					Severity:    policy.Severity,
					Description: fmt.Sprintf("%s - Resource: %s", rule.Description, resource.Name),
					Remediation: rule.Remediation,
					FoundAt:     time.Now(),
					Status:      "open",
				}
				
				c.findings = append(c.findings, finding)
				result.Findings = append(result.Findings, finding)
			}
		}
	}
	
	if result.TotalChecks > 0 {
		result.ComplianceScore = float64(result.PassedChecks) / float64(result.TotalChecks) * 100
	}
	
	return result
}

// ComplianceReport represents a compliance scan report
type ComplianceReport struct {
	Provider         string
	Timestamp        time.Time
	Resources        int
	PolicyResults    []*PolicyResult
	OverallScore     float64
	CriticalFindings int
	HighFindings     int
	MediumFindings   int
	LowFindings      int
}

// PolicyResult represents the result of evaluating a policy
type PolicyResult struct {
	PolicyID        string
	PolicyName      string
	TotalChecks     int
	PassedChecks    int
	FailedChecks    int
	ComplianceScore float64
	Findings        []SecurityFinding
}

// calculateScore calculates the overall compliance score
func (r *ComplianceReport) calculateScore() {
	if len(r.PolicyResults) == 0 {
		return
	}
	
	totalScore := 0.0
	for _, result := range r.PolicyResults {
		totalScore += result.ComplianceScore
		
		// Count findings by severity
		for _, finding := range result.Findings {
			switch finding.Severity {
			case "CRITICAL":
				r.CriticalFindings++
			case "HIGH":
				r.HighFindings++
			case "MEDIUM":
				r.MediumFindings++
			case "LOW":
				r.LowFindings++
			}
		}
	}
	
	r.OverallScore = totalScore / float64(len(r.PolicyResults))
}

// GetFindings returns all security findings
func (c *CSPMModule) GetFindings(status string) []SecurityFinding {
	if status == "" {
		return c.findings
	}
	
	filtered := []SecurityFinding{}
	for _, finding := range c.findings {
		if finding.Status == status {
			filtered = append(filtered, finding)
		}
	}
	return filtered
}

// ResolveFinding marks a finding as resolved
func (c *CSPMModule) ResolveFinding(findingID string) error {
	for i := range c.findings {
		if c.findings[i].ID == findingID {
			c.findings[i].Status = "resolved"
			return nil
		}
	}
	return fmt.Errorf("finding %s not found", findingID)
}

// GenerateReport generates a compliance report
func (c *CSPMModule) GenerateReport(format string) (string, error) {
	report := struct {
		Providers []string
		Policies  int
		Findings  struct {
			Total    int
			Open     int
			Resolved int
			Critical int
			High     int
			Medium   int
			Low      int
		}
		Timestamp time.Time
	}{
		Providers: []string{},
		Policies:  len(c.policies),
		Timestamp: time.Now(),
	}
	
	// Collect provider names
	for name := range c.providers {
		report.Providers = append(report.Providers, name)
	}
	
	// Count findings
	for _, finding := range c.findings {
		report.Findings.Total++
		if finding.Status == "open" {
			report.Findings.Open++
		} else if finding.Status == "resolved" {
			report.Findings.Resolved++
		}
		
		switch finding.Severity {
		case "CRITICAL":
			report.Findings.Critical++
		case "HIGH":
			report.Findings.High++
		case "MEDIUM":
			report.Findings.Medium++
		case "LOW":
			report.Findings.Low++
		}
	}
	
	switch format {
	case "json":
		data, err := json.MarshalIndent(report, "", "  ")
		return string(data), err
		
	default:
		return fmt.Sprintf(`Cloud Security Posture Report
=============================
Generated: %s

Providers: %s
Policies: %d

Findings Summary:
- Total: %d
- Open: %d
- Resolved: %d

By Severity:
- Critical: %d
- High: %d
- Medium: %d
- Low: %d
`,
			report.Timestamp.Format(time.RFC3339),
			strings.Join(report.Providers, ", "),
			report.Policies,
			report.Findings.Total,
			report.Findings.Open,
			report.Findings.Resolved,
			report.Findings.Critical,
			report.Findings.High,
			report.Findings.Medium,
			report.Findings.Low,
		), nil
	}
}

// ValidateIAMPolicy validates IAM policies for security issues
func (c *CSPMModule) ValidateIAMPolicy(policyJSON string) ([]string, error) {
	issues := []string{}
	
	// Check for overly permissive actions
	if strings.Contains(policyJSON, `"*"`) {
		if strings.Contains(policyJSON, `"Action"`) || strings.Contains(policyJSON, `"Resource"`) {
			issues = append(issues, "Policy contains wildcard (*) permissions")
		}
	}
	
	// Check for admin access
	adminPatterns := []string{
		`"iam:*"`,
		`"AdministratorAccess"`,
		`"PowerUserAccess"`,
	}
	for _, pattern := range adminPatterns {
		if strings.Contains(policyJSON, pattern) {
			issues = append(issues, fmt.Sprintf("Policy grants administrative access: %s", pattern))
		}
	}
	
	// Check for missing conditions
	if !strings.Contains(policyJSON, `"Condition"`) {
		issues = append(issues, "Policy lacks conditional access controls")
	}
	
	// Check for external principals
	externalPattern := regexp.MustCompile(`"Principal":\s*{\s*"AWS":\s*"\*"`)
	if externalPattern.MatchString(policyJSON) {
		issues = append(issues, "Policy allows access from any AWS principal")
	}
	
	return issues, nil
}