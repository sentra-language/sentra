// Package reporting provides comprehensive security reporting for Sentra
package reporting

import (
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"html/template"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// ReportingModule provides security reporting capabilities
type ReportingModule struct {
	Reports     map[string]*SecurityReport
	Templates   map[string]*ReportTemplate
	Findings    []SecurityFinding
	Metrics     *SecurityMetrics
	Config      *ReportConfig
	mu          sync.RWMutex
}

// SecurityReport represents a complete security assessment report
type SecurityReport struct {
	ID              string                 `json:"id" xml:"id"`
	Title           string                 `json:"title" xml:"title"`
	Description     string                 `json:"description" xml:"description"`
	ScanDate        time.Time             `json:"scan_date" xml:"scan_date"`
	GeneratedDate   time.Time             `json:"generated_date" xml:"generated_date"`
	Scanner         string                 `json:"scanner" xml:"scanner"`
	Version         string                 `json:"version" xml:"version"`
	Target          TargetInfo            `json:"target" xml:"target"`
	Executive       ExecutiveSummary      `json:"executive_summary" xml:"executive_summary"`
	Findings        []SecurityFinding     `json:"findings" xml:"findings"`
	Metrics         SecurityMetrics       `json:"metrics" xml:"metrics"`
	Recommendations []Recommendation      `json:"recommendations" xml:"recommendations"`
	Appendices      map[string]interface{} `json:"appendices" xml:"appendices"`
	Status          string                 `json:"status" xml:"status"`
}

// TargetInfo contains information about the scan target
type TargetInfo struct {
	Type        string   `json:"type" xml:"type"`             // host, network, application, etc.
	Name        string   `json:"name" xml:"name"`
	Description string   `json:"description" xml:"description"`
	URLs        []string `json:"urls" xml:"urls"`
	IPs         []string `json:"ips" xml:"ips"`
	Ports       []int    `json:"ports" xml:"ports"`
	Technology  []string `json:"technology" xml:"technology"`
}

// ExecutiveSummary provides high-level summary for executives
type ExecutiveSummary struct {
	Overview        string               `json:"overview" xml:"overview"`
	RiskLevel       string               `json:"risk_level" xml:"risk_level"`
	CriticalIssues  int                  `json:"critical_issues" xml:"critical_issues"`
	HighIssues      int                  `json:"high_issues" xml:"high_issues"`
	MediumIssues    int                  `json:"medium_issues" xml:"medium_issues"`
	LowIssues       int                  `json:"low_issues" xml:"low_issues"`
	TopRisks        []string             `json:"top_risks" xml:"top_risks"`
	BusinessImpact  string               `json:"business_impact" xml:"business_impact"`
	ComplianceGaps  []ComplianceGap      `json:"compliance_gaps" xml:"compliance_gaps"`
	Timeline        string               `json:"timeline" xml:"timeline"`
}

// SecurityFinding represents a security vulnerability or issue
type SecurityFinding struct {
	ID             string                 `json:"id" xml:"id"`
	Title          string                 `json:"title" xml:"title"`
	Description    string                 `json:"description" xml:"description"`
	Severity       string                 `json:"severity" xml:"severity"`       // CRITICAL, HIGH, MEDIUM, LOW, INFO
	CVSS           CVSSScore             `json:"cvss" xml:"cvss"`
	Category       string                 `json:"category" xml:"category"`       // OWASP, CWE, etc.
	CWE            string                 `json:"cwe" xml:"cwe"`
	CVE            string                 `json:"cve" xml:"cve"`
	Location       FindingLocation       `json:"location" xml:"location"`
	Evidence       []Evidence            `json:"evidence" xml:"evidence"`
	Impact         string                 `json:"impact" xml:"impact"`
	Likelihood     string                 `json:"likelihood" xml:"likelihood"`
	Risk           string                 `json:"risk" xml:"risk"`
	Solution       string                 `json:"solution" xml:"solution"`
	References     []string              `json:"references" xml:"references"`
	FirstFound     time.Time             `json:"first_found" xml:"first_found"`
	LastSeen       time.Time             `json:"last_seen" xml:"last_seen"`
	Status         string                 `json:"status" xml:"status"`           // OPEN, FIXED, FALSE_POSITIVE, ACCEPTED
	Validated      bool                   `json:"validated" xml:"validated"`
	Tags           []string              `json:"tags" xml:"tags"`
	Custom         map[string]interface{} `json:"custom" xml:"custom"`
}

// CVSSScore represents CVSS scoring information
type CVSSScore struct {
	Version string  `json:"version" xml:"version"`
	Vector  string  `json:"vector" xml:"vector"`
	Score   float64 `json:"score" xml:"score"`
	Severity string  `json:"severity" xml:"severity"`
}

// FindingLocation specifies where a finding was discovered
type FindingLocation struct {
	Type       string `json:"type" xml:"type"`         // URL, FILE, HOST, PORT, etc.
	Target     string `json:"target" xml:"target"`
	Method     string `json:"method" xml:"method"`
	Parameter  string `json:"parameter" xml:"parameter"`
	LineNumber int    `json:"line_number" xml:"line_number"`
	Code       string `json:"code" xml:"code"`
}

// Evidence contains proof of the security finding
type Evidence struct {
	Type        string `json:"type" xml:"type"`         // REQUEST, RESPONSE, LOG, SCREENSHOT
	Data        string `json:"data" xml:"data"`
	Description string `json:"description" xml:"description"`
	Timestamp   time.Time `json:"timestamp" xml:"timestamp"`
}

// SecurityMetrics contains quantitative security metrics
type SecurityMetrics struct {
	TotalFindings      int                    `json:"total_findings" xml:"total_findings"`
	SeverityBreakdown  map[string]int         `json:"severity_breakdown" xml:"severity_breakdown"`
	CategoryBreakdown  map[string]int         `json:"category_breakdown" xml:"category_breakdown"`
	RiskScore          float64                `json:"risk_score" xml:"risk_score"`
	ComplianceScore    float64                `json:"compliance_score" xml:"compliance_score"`
	TrendData          []TrendPoint           `json:"trend_data" xml:"trend_data"`
	Performance        PerformanceMetrics     `json:"performance" xml:"performance"`
	Coverage           CoverageMetrics        `json:"coverage" xml:"coverage"`
}

// TrendPoint represents a point in trend analysis
type TrendPoint struct {
	Date     time.Time `json:"date" xml:"date"`
	Critical int       `json:"critical" xml:"critical"`
	High     int       `json:"high" xml:"high"`
	Medium   int       `json:"medium" xml:"medium"`
	Low      int       `json:"low" xml:"low"`
}

// PerformanceMetrics contains performance statistics
type PerformanceMetrics struct {
	ScanDuration     time.Duration `json:"scan_duration" xml:"scan_duration"`
	RequestsPerSecond float64       `json:"requests_per_second" xml:"requests_per_second"`
	ErrorRate        float64       `json:"error_rate" xml:"error_rate"`
	Coverage         float64       `json:"coverage" xml:"coverage"`
}

// CoverageMetrics contains coverage analysis
type CoverageMetrics struct {
	URLsCovered       int     `json:"urls_covered" xml:"urls_covered"`
	ParametersTested  int     `json:"parameters_tested" xml:"parameters_tested"`
	TestCaseExecuted  int     `json:"test_cases_executed" xml:"test_cases_executed"`
	CoveragePercent   float64 `json:"coverage_percent" xml:"coverage_percent"`
}

// Recommendation provides remediation guidance
type Recommendation struct {
	ID          string   `json:"id" xml:"id"`
	Title       string   `json:"title" xml:"title"`
	Description string   `json:"description" xml:"description"`
	Priority    string   `json:"priority" xml:"priority"`
	Effort      string   `json:"effort" xml:"effort"`
	Category    string   `json:"category" xml:"category"`
	Steps       []string `json:"steps" xml:"steps"`
	References  []string `json:"references" xml:"references"`
	FindingIDs  []string `json:"finding_ids" xml:"finding_ids"`
}

// ComplianceGap represents compliance framework gaps
type ComplianceGap struct {
	Framework   string   `json:"framework" xml:"framework"`    // OWASP, PCI-DSS, SOX, etc.
	Requirement string   `json:"requirement" xml:"requirement"`
	Gap         string   `json:"gap" xml:"gap"`
	Severity    string   `json:"severity" xml:"severity"`
	FindingIDs  []string `json:"finding_ids" xml:"finding_ids"`
}

// ReportTemplate defines report generation templates
type ReportTemplate struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Format      string `json:"format"` // HTML, PDF, JSON, XML, CSV
	Template    string `json:"template"`
	Stylesheet  string `json:"stylesheet"`
	Custom      bool   `json:"custom"`
}

// ReportConfig contains reporting configuration
type ReportConfig struct {
	OutputDirectory   string            `json:"output_directory"`
	DefaultFormat     string            `json:"default_format"`
	IncludeRawData    bool              `json:"include_raw_data"`
	CompressReports   bool              `json:"compress_reports"`
	CustomFields      map[string]string `json:"custom_fields"`
	ComplianceFrameworks []string       `json:"compliance_frameworks"`
}

// NewReportingModule creates a new reporting module
func NewReportingModule() *ReportingModule {
	module := &ReportingModule{
		Reports:   make(map[string]*SecurityReport),
		Templates: make(map[string]*ReportTemplate),
		Findings:  make([]SecurityFinding, 0),
		Metrics:   &SecurityMetrics{
			SeverityBreakdown: make(map[string]int),
			CategoryBreakdown: make(map[string]int),
			TrendData:         make([]TrendPoint, 0),
		},
		Config: &ReportConfig{
			OutputDirectory:      "./reports",
			DefaultFormat:        "JSON",
			IncludeRawData:       true,
			CompressReports:      false,
			CustomFields:         make(map[string]string),
			ComplianceFrameworks: []string{"OWASP Top 10", "CWE Top 25"},
		},
	}

	// Initialize default templates
	module.initializeDefaultTemplates()
	
	return module
}

// initializeDefaultTemplates sets up built-in report templates
func (rm *ReportingModule) initializeDefaultTemplates() {
	// JSON Template
	rm.Templates["json"] = &ReportTemplate{
		ID:          "json",
		Name:        "JSON Report",
		Description: "Structured JSON format for API consumption",
		Format:      "JSON",
		Custom:      false,
	}

	// XML Template
	rm.Templates["xml"] = &ReportTemplate{
		ID:          "xml",
		Name:        "XML Report",
		Description: "Structured XML format for integration",
		Format:      "XML",
		Custom:      false,
	}

	// CSV Template
	rm.Templates["csv"] = &ReportTemplate{
		ID:          "csv",
		Name:        "CSV Report",
		Description: "Comma-separated values for spreadsheet import",
		Format:      "CSV",
		Custom:      false,
	}

	// HTML Template
	htmlTemplate := `
<!DOCTYPE html>
<html>
<head>
    <title>{{.Title}} - Security Assessment Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .header { background: #2c3e50; color: white; padding: 20px; }
        .summary { background: #ecf0f1; padding: 15px; margin: 20px 0; }
        .finding { border-left: 4px solid #e74c3c; margin: 10px 0; padding: 10px; }
        .critical { border-color: #c0392b; background: #fdf2f2; }
        .high { border-color: #e74c3c; background: #fef5f5; }
        .medium { border-color: #f39c12; background: #fef9e7; }
        .low { border-color: #27ae60; background: #eafaf1; }
        .info { border-color: #3498db; background: #eaf7ff; }
    </style>
</head>
<body>
    <div class="header">
        <h1>{{.Title}}</h1>
        <p>Generated on {{.GeneratedDate.Format "2006-01-02 15:04:05"}}</p>
    </div>
    
    <div class="summary">
        <h2>Executive Summary</h2>
        <p><strong>Risk Level:</strong> {{.Executive.RiskLevel}}</p>
        <p><strong>Critical Issues:</strong> {{.Executive.CriticalIssues}}</p>
        <p><strong>High Issues:</strong> {{.Executive.HighIssues}}</p>
        <p><strong>Medium Issues:</strong> {{.Executive.MediumIssues}}</p>
        <p><strong>Low Issues:</strong> {{.Executive.LowIssues}}</p>
    </div>
    
    <h2>Security Findings</h2>
    {{range .Findings}}
    <div class="finding {{.Severity | lower}}">
        <h3>{{.Title}} ({{.Severity}})</h3>
        <p><strong>Description:</strong> {{.Description}}</p>
        <p><strong>Location:</strong> {{.Location.Target}}</p>
        <p><strong>Impact:</strong> {{.Impact}}</p>
        <p><strong>Solution:</strong> {{.Solution}}</p>
    </div>
    {{end}}
</body>
</html>
`

	rm.Templates["html"] = &ReportTemplate{
		ID:          "html",
		Name:        "HTML Report",
		Description: "Web-based HTML report with styling",
		Format:      "HTML",
		Template:    htmlTemplate,
		Custom:      false,
	}
}

// CreateReport creates a new security report
func (rm *ReportingModule) CreateReport(id, title, description string, target TargetInfo) *SecurityReport {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	report := &SecurityReport{
		ID:            id,
		Title:         title,
		Description:   description,
		ScanDate:      time.Now(),
		GeneratedDate: time.Now(),
		Scanner:       "Sentra Security Scanner",
		Version:       "1.0",
		Target:        target,
		Executive:     ExecutiveSummary{},
		Findings:      make([]SecurityFinding, 0),
		Metrics:       *rm.Metrics,
		Recommendations: make([]Recommendation, 0),
		Appendices:    make(map[string]interface{}),
		Status:        "DRAFT",
	}

	rm.Reports[id] = report
	return report
}

// AddFinding adds a security finding to a report
func (rm *ReportingModule) AddFinding(reportID string, finding SecurityFinding) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	report, exists := rm.Reports[reportID]
	if !exists {
		return fmt.Errorf("report not found: %s", reportID)
	}

	// Set finding ID if not provided
	if finding.ID == "" {
		finding.ID = fmt.Sprintf("FIND-%d", len(report.Findings)+1)
	}

	// Set timestamps
	if finding.FirstFound.IsZero() {
		finding.FirstFound = time.Now()
	}
	finding.LastSeen = time.Now()

	// Calculate CVSS if not provided
	if finding.CVSS.Score == 0 {
		finding.CVSS = rm.calculateCVSS(finding)
	}

	// Add to report
	report.Findings = append(report.Findings, finding)

	// Update metrics
	rm.updateMetrics(report)

	// Add to global findings list
	rm.Findings = append(rm.Findings, finding)

	return nil
}

// calculateCVSS calculates CVSS score based on finding characteristics
func (rm *ReportingModule) calculateCVSS(finding SecurityFinding) CVSSScore {
	// Simplified CVSS calculation
	var score float64

	switch strings.ToUpper(finding.Severity) {
	case "CRITICAL":
		score = 9.0 + (float64(len(finding.Evidence)) * 0.2)
		if score > 10.0 {
			score = 10.0
		}
	case "HIGH":
		score = 7.0 + (float64(len(finding.Evidence)) * 0.3)
		if score > 8.9 {
			score = 8.9
		}
	case "MEDIUM":
		score = 4.0 + (float64(len(finding.Evidence)) * 0.5)
		if score > 6.9 {
			score = 6.9
		}
	case "LOW":
		score = 0.1 + (float64(len(finding.Evidence)) * 0.3)
		if score > 3.9 {
			score = 3.9
		}
	default:
		score = 0.0
	}

	return CVSSScore{
		Version:  "3.1",
		Vector:   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // Simplified
		Score:    score,
		Severity: finding.Severity,
	}
}

// updateMetrics updates report metrics based on findings
func (rm *ReportingModule) updateMetrics(report *SecurityReport) {
	metrics := &report.Metrics
	metrics.TotalFindings = len(report.Findings)
	
	// Reset counters
	metrics.SeverityBreakdown = make(map[string]int)
	metrics.CategoryBreakdown = make(map[string]int)

	// Count by severity and category
	for _, finding := range report.Findings {
		metrics.SeverityBreakdown[finding.Severity]++
		metrics.CategoryBreakdown[finding.Category]++
	}

	// Calculate risk score (0-100)
	critical := metrics.SeverityBreakdown["CRITICAL"]
	high := metrics.SeverityBreakdown["HIGH"]
	medium := metrics.SeverityBreakdown["MEDIUM"]
	low := metrics.SeverityBreakdown["LOW"]

	metrics.RiskScore = float64(critical*10 + high*7 + medium*4 + low*1)
	if metrics.RiskScore > 100 {
		metrics.RiskScore = 100
	}

	// Update executive summary
	report.Executive.CriticalIssues = critical
	report.Executive.HighIssues = high
	report.Executive.MediumIssues = medium
	report.Executive.LowIssues = low

	// Determine overall risk level
	if critical > 0 {
		report.Executive.RiskLevel = "CRITICAL"
	} else if high > 2 {
		report.Executive.RiskLevel = "HIGH"
	} else if high > 0 || medium > 5 {
		report.Executive.RiskLevel = "MEDIUM"
	} else {
		report.Executive.RiskLevel = "LOW"
	}
}

// GenerateExecutiveSummary generates executive summary content
func (rm *ReportingModule) GenerateExecutiveSummary(reportID string) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	report, exists := rm.Reports[reportID]
	if !exists {
		return fmt.Errorf("report not found: %s", reportID)
	}

	exec := &report.Executive

	// Generate overview
	exec.Overview = fmt.Sprintf(
		"A comprehensive security assessment was conducted on %s. The assessment identified %d security findings across %d categories.",
		report.Target.Name,
		len(report.Findings),
		len(report.Metrics.CategoryBreakdown),
	)

	// Identify top risks
	topRisks := make([]string, 0)
	for _, finding := range report.Findings {
		if finding.Severity == "CRITICAL" || finding.Severity == "HIGH" {
			topRisks = append(topRisks, finding.Title)
		}
		if len(topRisks) >= 5 {
			break
		}
	}
	exec.TopRisks = topRisks

	// Generate business impact
	if exec.CriticalIssues > 0 {
		exec.BusinessImpact = "Critical vulnerabilities pose immediate risk to business operations and data security. Immediate remediation is required."
	} else if exec.HighIssues > 0 {
		exec.BusinessImpact = "High-risk vulnerabilities could lead to significant security incidents. Prompt attention is recommended."
	} else {
		exec.BusinessImpact = "The security posture is generally acceptable with manageable risk levels."
	}

	// Generate timeline
	urgentIssues := exec.CriticalIssues + exec.HighIssues
	if urgentIssues > 0 {
		exec.Timeline = fmt.Sprintf("Address %d critical/high issues within 30 days", urgentIssues)
	} else {
		exec.Timeline = "Address medium and low issues within 90 days"
	}

	return nil
}

// AddRecommendation adds a remediation recommendation
func (rm *ReportingModule) AddRecommendation(reportID string, recommendation Recommendation) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	report, exists := rm.Reports[reportID]
	if !exists {
		return fmt.Errorf("report not found: %s", reportID)
	}

	if recommendation.ID == "" {
		recommendation.ID = fmt.Sprintf("REC-%d", len(report.Recommendations)+1)
	}

	report.Recommendations = append(report.Recommendations, recommendation)
	return nil
}

// ExportReport exports a report in the specified format
func (rm *ReportingModule) ExportReport(reportID, format, filename string) error {
	rm.mu.RLock()
	report, exists := rm.Reports[reportID]
	rm.mu.RUnlock()

	if !exists {
		return fmt.Errorf("report not found: %s", reportID)
	}

	// Ensure output directory exists
	if err := os.MkdirAll(rm.Config.OutputDirectory, 0755); err != nil {
		return err
	}

	// Full path for output file
	fullPath := filepath.Join(rm.Config.OutputDirectory, filename)

	switch strings.ToUpper(format) {
	case "JSON":
		return rm.exportJSON(report, fullPath)
	case "XML":
		return rm.exportXML(report, fullPath)
	case "CSV":
		return rm.exportCSV(report, fullPath)
	case "HTML":
		return rm.exportHTML(report, fullPath)
	default:
		return fmt.Errorf("unsupported format: %s", format)
	}
}

// exportJSON exports report as JSON
func (rm *ReportingModule) exportJSON(report *SecurityReport, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

// exportXML exports report as XML
func (rm *ReportingModule) exportXML(report *SecurityReport, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	file.WriteString(xml.Header)
	encoder := xml.NewEncoder(file)
	encoder.Indent("", "  ")
	return encoder.Encode(report)
}

// exportCSV exports findings as CSV
func (rm *ReportingModule) exportCSV(report *SecurityReport, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write header
	header := []string{
		"ID", "Title", "Severity", "Category", "CWE", "CVE",
		"Location", "Impact", "Solution", "First Found", "Status",
	}
	if err := writer.Write(header); err != nil {
		return err
	}

	// Write findings
	for _, finding := range report.Findings {
		record := []string{
			finding.ID,
			finding.Title,
			finding.Severity,
			finding.Category,
			finding.CWE,
			finding.CVE,
			finding.Location.Target,
			finding.Impact,
			finding.Solution,
			finding.FirstFound.Format("2006-01-02 15:04:05"),
			finding.Status,
		}
		if err := writer.Write(record); err != nil {
			return err
		}
	}

	return nil
}

// exportHTML exports report as HTML
func (rm *ReportingModule) exportHTML(report *SecurityReport, filename string) error {
	htmlTemplate, exists := rm.Templates["html"]
	if !exists {
		return fmt.Errorf("HTML template not found")
	}

	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"lower": strings.ToLower,
	}).Parse(htmlTemplate.Template)
	if err != nil {
		return err
	}

	return tmpl.Execute(file, report)
}

// AnalyzeTrends analyzes security trends over time
func (rm *ReportingModule) AnalyzeTrends(days int) []TrendPoint {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	trends := make([]TrendPoint, 0)
	
	// Group findings by date
	findingsByDate := make(map[string]map[string]int)
	
	cutoff := time.Now().AddDate(0, 0, -days)
	
	for _, finding := range rm.Findings {
		if finding.FirstFound.Before(cutoff) {
			continue
		}
		
		dateKey := finding.FirstFound.Format("2006-01-02")
		if findingsByDate[dateKey] == nil {
			findingsByDate[dateKey] = make(map[string]int)
		}
		findingsByDate[dateKey][finding.Severity]++
	}

	// Convert to trend points
	for dateStr, counts := range findingsByDate {
		if date, err := time.Parse("2006-01-02", dateStr); err == nil {
			point := TrendPoint{
				Date:     date,
				Critical: counts["CRITICAL"],
				High:     counts["HIGH"],
				Medium:   counts["MEDIUM"],
				Low:      counts["LOW"],
			}
			trends = append(trends, point)
		}
	}

	// Sort by date
	sort.Slice(trends, func(i, j int) bool {
		return trends[i].Date.Before(trends[j].Date)
	})

	return trends
}

// GenerateComplianceReport generates compliance framework mapping
func (rm *ReportingModule) GenerateComplianceReport(reportID string, frameworks []string) (map[string][]ComplianceGap, error) {
	rm.mu.RLock()
	report, exists := rm.Reports[reportID]
	rm.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("report not found: %s", reportID)
	}

	complianceGaps := make(map[string][]ComplianceGap)

	for _, framework := range frameworks {
		gaps := rm.mapToComplianceFramework(framework, report.Findings)
		if len(gaps) > 0 {
			complianceGaps[framework] = gaps
		}
	}

	return complianceGaps, nil
}

// mapToComplianceFramework maps findings to compliance framework requirements
func (rm *ReportingModule) mapToComplianceFramework(framework string, findings []SecurityFinding) []ComplianceGap {
	var gaps []ComplianceGap

	switch framework {
	case "OWASP Top 10":
		gaps = rm.mapToOWASP(findings)
	case "CWE Top 25":
		gaps = rm.mapToCWE(findings)
	case "PCI-DSS":
		gaps = rm.mapToPCIDSS(findings)
	}

	return gaps
}

// mapToOWASP maps findings to OWASP Top 10
func (rm *ReportingModule) mapToOWASP(findings []SecurityFinding) []ComplianceGap {
	gaps := make([]ComplianceGap, 0)
	
	owaspCategories := map[string]string{
		"A01": "Broken Access Control",
		"A02": "Cryptographic Failures", 
		"A03": "Injection",
		"A04": "Insecure Design",
		"A05": "Security Misconfiguration",
		"A06": "Vulnerable and Outdated Components",
		"A07": "Identification and Authentication Failures",
		"A08": "Software and Data Integrity Failures",
		"A09": "Security Logging and Monitoring Failures",
		"A10": "Server-Side Request Forgery",
	}

	categoryFindings := make(map[string][]string)
	
	for _, finding := range findings {
		// Simple mapping based on finding category/title
		category := rm.mapFindingToOWASP(finding)
		if category != "" {
			categoryFindings[category] = append(categoryFindings[category], finding.ID)
		}
	}

	for owaspID, requirement := range owaspCategories {
		if findingIDs, exists := categoryFindings[owaspID]; exists {
			gap := ComplianceGap{
				Framework:   "OWASP Top 10",
				Requirement: fmt.Sprintf("%s: %s", owaspID, requirement),
				Gap:         fmt.Sprintf("Vulnerabilities found in %s category", requirement),
				Severity:    "HIGH",
				FindingIDs:  findingIDs,
			}
			gaps = append(gaps, gap)
		}
	}

	return gaps
}

// mapFindingToOWASP maps individual findings to OWASP categories
func (rm *ReportingModule) mapFindingToOWASP(finding SecurityFinding) string {
	title := strings.ToLower(finding.Title)
	category := strings.ToLower(finding.Category)

	if strings.Contains(title, "injection") || strings.Contains(category, "injection") {
		return "A03"
	}
	if strings.Contains(title, "authentication") || strings.Contains(category, "auth") {
		return "A07"
	}
	if strings.Contains(title, "crypto") || strings.Contains(category, "crypto") {
		return "A02"
	}
	if strings.Contains(title, "access") || strings.Contains(category, "access") {
		return "A01"
	}
	if strings.Contains(title, "config") || strings.Contains(category, "config") {
		return "A05"
	}

	return ""
}

// mapToCWE maps findings to CWE categories
func (rm *ReportingModule) mapToCWE(findings []SecurityFinding) []ComplianceGap {
	gaps := make([]ComplianceGap, 0)
	
	// Group by CWE
	cweFindings := make(map[string][]string)
	
	for _, finding := range findings {
		if finding.CWE != "" {
			cweFindings[finding.CWE] = append(cweFindings[finding.CWE], finding.ID)
		}
	}

	for cwe, findingIDs := range cweFindings {
		gap := ComplianceGap{
			Framework:   "CWE Top 25",
			Requirement: fmt.Sprintf("CWE-%s", cwe),
			Gap:         fmt.Sprintf("Vulnerabilities found for CWE-%s", cwe),
			Severity:    "MEDIUM",
			FindingIDs:  findingIDs,
		}
		gaps = append(gaps, gap)
	}

	return gaps
}

// mapToPCIDSS maps findings to PCI-DSS requirements
func (rm *ReportingModule) mapToPCIDSS(findings []SecurityFinding) []ComplianceGap {
	// Simplified PCI-DSS mapping
	return []ComplianceGap{}
}

// GetReportSummary returns a summary of all reports
func (rm *ReportingModule) GetReportSummary() map[string]interface{} {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	totalFindings := 0
	totalReports := len(rm.Reports)
	severityCounts := make(map[string]int)

	for _, report := range rm.Reports {
		totalFindings += len(report.Findings)
		for _, finding := range report.Findings {
			severityCounts[finding.Severity]++
		}
	}

	return map[string]interface{}{
		"total_reports":      totalReports,
		"total_findings":     totalFindings,
		"severity_breakdown": severityCounts,
		"reports":           rm.getReportList(),
	}
}

// getReportList returns basic info about all reports
func (rm *ReportingModule) getReportList() []map[string]interface{} {
	reports := make([]map[string]interface{}, 0)
	
	for _, report := range rm.Reports {
		info := map[string]interface{}{
			"id":             report.ID,
			"title":          report.Title,
			"scan_date":      report.ScanDate,
			"total_findings": len(report.Findings),
			"risk_level":     report.Executive.RiskLevel,
			"status":         report.Status,
		}
		reports = append(reports, info)
	}

	return reports
}

// DeleteReport removes a report
func (rm *ReportingModule) DeleteReport(reportID string) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if _, exists := rm.Reports[reportID]; !exists {
		return fmt.Errorf("report not found: %s", reportID)
	}

	delete(rm.Reports, reportID)
	return nil
}

// UpdateConfig updates reporting configuration
func (rm *ReportingModule) UpdateConfig(config ReportConfig) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	
	rm.Config = &config
}

// StreamReport streams a report to a writer
func (rm *ReportingModule) StreamReport(reportID string, format string, writer io.Writer) error {
	rm.mu.RLock()
	report, exists := rm.Reports[reportID]
	rm.mu.RUnlock()

	if !exists {
		return fmt.Errorf("report not found: %s", reportID)
	}

	switch strings.ToUpper(format) {
	case "JSON":
		encoder := json.NewEncoder(writer)
		encoder.SetIndent("", "  ")
		return encoder.Encode(report)
	case "XML":
		_, err := writer.Write([]byte(xml.Header))
		if err != nil {
			return err
		}
		encoder := xml.NewEncoder(writer)
		encoder.Indent("", "  ")
		return encoder.Encode(report)
	default:
		return fmt.Errorf("unsupported streaming format: %s", format)
	}
}