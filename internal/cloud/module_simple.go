// internal/cloud/module_simple.go
package cloud

import (
	"fmt"
	"time"
)

// GetCloudModule returns a cloud security module instance for the VM
func GetCloudModule() interface{} {
	return NewCSPMModule()
}

// CloudProviderAdd adds a cloud provider to the CSPM module
func CloudProviderAdd(cspm interface{}, name string, providerType string, credentials map[string]string) error {
	module, ok := cspm.(*CSPMModule)
	if !ok {
		return fmt.Errorf("invalid CSPM module")
	}
	return module.AddProvider(name, providerType, credentials)
}

// CloudScan performs a security scan on a cloud provider
func CloudScan(cspm interface{}, providerName string) (map[string]interface{}, error) {
	module, ok := cspm.(*CSPMModule)
	if !ok {
		return nil, fmt.Errorf("invalid CSPM module")
	}
	
	report, err := module.ScanProvider(providerName)
	if err != nil {
		return nil, err
	}
	
	// Convert to generic map
	result := make(map[string]interface{})
	result["provider"] = report.Provider
	result["timestamp"] = report.Timestamp.String()
	result["resources"] = report.Resources
	result["resources_scanned"] = report.Resources  // Add alias for compatibility
	result["overall_score"] = report.OverallScore
	result["compliance_score"] = report.OverallScore  // Add alias for compatibility
	result["critical_findings"] = report.CriticalFindings
	result["high_findings"] = report.HighFindings
	result["medium_findings"] = report.MediumFindings
	result["low_findings"] = report.LowFindings
	
	// Convert policy results
	policies := []interface{}{}
	for _, pr := range report.PolicyResults {
		policyMap := make(map[string]interface{})
		policyMap["policy_id"] = pr.PolicyID
		policyMap["policy_name"] = pr.PolicyName
		policyMap["total_checks"] = pr.TotalChecks
		policyMap["passed_checks"] = pr.PassedChecks
		policyMap["failed_checks"] = pr.FailedChecks
		policyMap["compliance_score"] = pr.ComplianceScore
		
		// Add findings
		findings := []interface{}{}
		for _, f := range pr.Findings {
			findingMap := make(map[string]interface{})
			findingMap["id"] = f.ID
			findingMap["resource_id"] = f.ResourceID
			findingMap["severity"] = f.Severity
			findingMap["description"] = f.Description
			findingMap["remediation"] = f.Remediation
			findingMap["status"] = f.Status
			findings = append(findings, findingMap)
		}
		policyMap["findings"] = findings
		policies = append(policies, policyMap)
	}
	result["policy_results"] = policies
	result["policies"] = policies  // Add alias for compatibility
	
	return result, nil
}

// CloudGetFindings retrieves security findings by status
func CloudGetFindings(cspm interface{}, status string) []map[string]interface{} {
	module, ok := cspm.(*CSPMModule)
	if !ok {
		return nil
	}
	
	findings := module.GetFindings(status)
	result := []map[string]interface{}{}
	
	for _, f := range findings {
		findingMap := make(map[string]interface{})
		findingMap["id"] = f.ID
		findingMap["resource_id"] = f.ResourceID
		findingMap["policy_id"] = f.PolicyID
		findingMap["rule_id"] = f.RuleID
		findingMap["severity"] = f.Severity
		findingMap["description"] = f.Description
		findingMap["remediation"] = f.Remediation
		findingMap["status"] = f.Status
		findingMap["found_at"] = f.FoundAt.String()
		result = append(result, findingMap)
	}
	
	return result
}

// CloudResolveFinding marks a finding as resolved
func CloudResolveFinding(cspm interface{}, findingID string) error {
	module, ok := cspm.(*CSPMModule)
	if !ok {
		return fmt.Errorf("invalid CSPM module")
	}
	return module.ResolveFinding(findingID)
}

// CloudComplianceReport generates a compliance report
func CloudComplianceReport(cspm interface{}, format string) (string, error) {
	module, ok := cspm.(*CSPMModule)
	if !ok {
		return "", fmt.Errorf("invalid CSPM module")
	}
	return module.GenerateReport(format)
}

// CloudValidateIAM validates an IAM policy for security issues
func CloudValidateIAM(cspm interface{}, policyJSON string) ([]string, error) {
	module, ok := cspm.(*CSPMModule)
	if !ok {
		return nil, fmt.Errorf("invalid CSPM module")
	}
	return module.ValidateIAMPolicy(policyJSON)
}

// CloudCostAnalysis performs cost analysis for a cloud provider
func CloudCostAnalysis(providerName string) map[string]interface{} {
	// Simulate cost analysis
	costReport := make(map[string]interface{})
	costReport["provider"] = providerName
	costReport["total_cost"] = 1234.56
	costReport["compute_cost"] = 800.00
	costReport["storage_cost"] = 200.00
	costReport["network_cost"] = 234.56
	costReport["unused_resources"] = 5
	costReport["potential_savings"] = 150.00
	
	recommendations := []string{
		"Consider using Reserved Instances for long-running compute",
		"Enable S3 Intelligent-Tiering for infrequently accessed data",
		"Review and remove unattached EBS volumes",
		"Use Auto Scaling to optimize compute resources",
	}
	costReport["recommendations"] = recommendations
	
	return costReport
}

// CloudBenchmarkRun runs a compliance benchmark
func CloudBenchmarkRun(provider, benchmark string) map[string]interface{} {
	// Simulate running a compliance benchmark
	result := make(map[string]interface{})
	result["provider"] = provider
	result["benchmark"] = benchmark
	result["score"] = 85.5
	result["passed"] = 170
	result["failed"] = 30
	result["skipped"] = 10
	
	return result
}

// CloudAutoRemediate performs auto-remediation for a finding
func CloudAutoRemediate(findingID string) map[string]interface{} {
	// Simulate auto-remediation
	result := make(map[string]interface{})
	result["finding_id"] = findingID
	result["status"] = "remediated"
	result["action_taken"] = "Applied security group rule to block public access"
	result["timestamp"] = time.Now().Format(time.RFC3339)
	
	return result
}