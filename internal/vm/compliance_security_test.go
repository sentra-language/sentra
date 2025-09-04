package vm

import (
	"testing"
)

func TestComplianceFrameworkFunctions(t *testing.T) {
	vm := NewVM(nil)
	
	t.Run("compliance_assess_framework", func(t *testing.T) {
		fn, exists := vm.globalMap["compliance_assess_framework"]
		if !exists {
			t.Fatal("compliance_assess_framework function not found")
		}
		
		builtin := vm.globals[fn].(*NativeFunction)
		result, err := builtin.Function([]Value{"SOC2", "TechCorp", "IT Systems"})
		
		if err != nil {
			t.Fatalf("compliance_assess_framework failed: %v", err)
		}
		
		resultMap, ok := result.(*Map)
		if !ok {
			t.Fatal("compliance_assess_framework should return a map")
		}
		
		if resultMap.Items["framework"] != "SOC2" {
			t.Errorf("Expected framework 'SOC2', got %v", resultMap.Items["framework"])
		}
		
		if resultMap.Items["organization"] != "TechCorp" {
			t.Errorf("Expected organization 'TechCorp', got %v", resultMap.Items["organization"])
		}
		
		if resultMap.Items["overall_score"] != 75 {
			t.Errorf("Expected overall_score 75, got %v", resultMap.Items["overall_score"])
		}
		
		controls, ok := resultMap.Items["controls"].(*Array)
		if !ok {
			t.Error("Expected controls to be an array")
		}
		
		if len(controls.Elements) != 2 {
			t.Errorf("Expected 2 controls, got %d", len(controls.Elements))
		}
	})
	
	t.Run("compliance_gap_analysis", func(t *testing.T) {
		fn, exists := vm.globalMap["compliance_gap_analysis"]
		if !exists {
			t.Fatal("compliance_gap_analysis function not found")
		}
		
		builtin := vm.globals[fn].(*NativeFunction)
		result, err := builtin.Function([]Value{"SOC2", "ISO27001"})
		
		if err != nil {
			t.Fatalf("compliance_gap_analysis failed: %v", err)
		}
		
		resultMap, ok := result.(*Map)
		if !ok {
			t.Fatal("compliance_gap_analysis should return a map")
		}
		
		if resultMap.Items["current_framework"] != "SOC2" {
			t.Errorf("Expected current_framework 'SOC2', got %v", resultMap.Items["current_framework"])
		}
		
		if resultMap.Items["target_framework"] != "ISO27001" {
			t.Errorf("Expected target_framework 'ISO27001', got %v", resultMap.Items["target_framework"])
		}
		
		if resultMap.Items["total_estimated_cost"] != "$90,000" {
			t.Errorf("Expected total_estimated_cost '$90,000', got %v", resultMap.Items["total_estimated_cost"])
		}
		
		gaps, ok := resultMap.Items["identified_gaps"].(*Array)
		if !ok {
			t.Error("Expected identified_gaps to be an array")
		}
		
		if len(gaps.Elements) != 3 {
			t.Errorf("Expected 3 gaps, got %d", len(gaps.Elements))
		}
	})
	
	t.Run("compliance_evidence_management", func(t *testing.T) {
		fn, exists := vm.globalMap["compliance_evidence_management"]
		if !exists {
			t.Fatal("compliance_evidence_management function not found")
		}
		
		builtin := vm.globals[fn].(*NativeFunction)
		result, err := builtin.Function([]Value{"CC6.1", "collect"})
		
		if err != nil {
			t.Fatalf("compliance_evidence_management failed: %v", err)
		}
		
		resultMap, ok := result.(*Map)
		if !ok {
			t.Fatal("compliance_evidence_management should return a map")
		}
		
		if resultMap.Items["control_id"] != "CC6.1" {
			t.Errorf("Expected control_id 'CC6.1', got %v", resultMap.Items["control_id"])
		}
		
		if resultMap.Items["action"] != "collect" {
			t.Errorf("Expected action 'collect', got %v", resultMap.Items["action"])
		}
		
		if resultMap.Items["total_evidence"] != 3 {
			t.Errorf("Expected total_evidence 3, got %v", resultMap.Items["total_evidence"])
		}
		
		evidence, ok := resultMap.Items["collected_evidence"].(*Array)
		if !ok {
			t.Error("Expected collected_evidence to be an array")
		}
		
		if len(evidence.Elements) != 3 {
			t.Errorf("Expected 3 evidence items, got %d", len(evidence.Elements))
		}
	})
	
	t.Run("compliance_risk_assessment", func(t *testing.T) {
		fn, exists := vm.globalMap["compliance_risk_assessment"]
		if !exists {
			t.Fatal("compliance_risk_assessment function not found")
		}
		
		builtin := vm.globals[fn].(*NativeFunction)
		result, err := builtin.Function([]Value{"GDPR", "database"})
		
		if err != nil {
			t.Fatalf("compliance_risk_assessment failed: %v", err)
		}
		
		resultMap, ok := result.(*Map)
		if !ok {
			t.Fatal("compliance_risk_assessment should return a map")
		}
		
		if resultMap.Items["framework"] != "GDPR" {
			t.Errorf("Expected framework 'GDPR', got %v", resultMap.Items["framework"])
		}
		
		if resultMap.Items["overall_risk_score"] != 60 {
			t.Errorf("Expected overall_risk_score 60, got %v", resultMap.Items["overall_risk_score"])
		}
		
		if resultMap.Items["high_risks"] != 1 {
			t.Errorf("Expected high_risks 1, got %v", resultMap.Items["high_risks"])
		}
		
		if resultMap.Items["medium_risks"] != 2 {
			t.Errorf("Expected medium_risks 2, got %v", resultMap.Items["medium_risks"])
		}
		
		risks, ok := resultMap.Items["identified_risks"].(*Array)
		if !ok {
			t.Error("Expected identified_risks to be an array")
		}
		
		if len(risks.Elements) != 3 {
			t.Errorf("Expected 3 risks, got %d", len(risks.Elements))
		}
	})
	
	t.Run("compliance_audit_trail", func(t *testing.T) {
		fn, exists := vm.globalMap["compliance_audit_trail"]
		if !exists {
			t.Fatal("compliance_audit_trail function not found")
		}
		
		builtin := vm.globals[fn].(*NativeFunction)
		result, err := builtin.Function([]Value{"2024-01-01", "2024-01-31", "all"})
		
		if err != nil {
			t.Fatalf("compliance_audit_trail failed: %v", err)
		}
		
		resultMap, ok := result.(*Map)
		if !ok {
			t.Fatal("compliance_audit_trail should return a map")
		}
		
		if resultMap.Items["start_date"] != "2024-01-01" {
			t.Errorf("Expected start_date '2024-01-01', got %v", resultMap.Items["start_date"])
		}
		
		if resultMap.Items["end_date"] != "2024-01-31" {
			t.Errorf("Expected end_date '2024-01-31', got %v", resultMap.Items["end_date"])
		}
		
		if resultMap.Items["total_entries"] != 3 {
			t.Errorf("Expected total_entries 3, got %v", resultMap.Items["total_entries"])
		}
		
		auditEntries, ok := resultMap.Items["audit_entries"].(*Array)
		if !ok {
			t.Error("Expected audit_entries to be an array")
		}
		
		if len(auditEntries.Elements) != 3 {
			t.Errorf("Expected 3 audit entries, got %d", len(auditEntries.Elements))
		}
	})
	
	t.Run("compliance_reporting", func(t *testing.T) {
		fn, exists := vm.globalMap["compliance_reporting"]
		if !exists {
			t.Fatal("compliance_reporting function not found")
		}
		
		builtin := vm.globals[fn].(*NativeFunction)
		result, err := builtin.Function([]Value{"SOC2", "executive_summary", "Q1-2024"})
		
		if err != nil {
			t.Fatalf("compliance_reporting failed: %v", err)
		}
		
		resultMap, ok := result.(*Map)
		if !ok {
			t.Fatal("compliance_reporting should return a map")
		}
		
		if resultMap.Items["framework"] != "SOC2" {
			t.Errorf("Expected framework 'SOC2', got %v", resultMap.Items["framework"])
		}
		
		if resultMap.Items["report_type"] != "executive_summary" {
			t.Errorf("Expected report_type 'executive_summary', got %v", resultMap.Items["report_type"])
		}
		
		if resultMap.Items["compliance_score"] != 78 {
			t.Errorf("Expected compliance_score 78, got %v", resultMap.Items["compliance_score"])
		}
		
		if resultMap.Items["report_status"] != "final" {
			t.Errorf("Expected report_status 'final', got %v", resultMap.Items["report_status"])
		}
		
		controlSummary, ok := resultMap.Items["control_summary"].(*Map)
		if !ok {
			t.Error("Expected control_summary to be a map")
		}
		
		if controlSummary.Items["total_controls"] != 25 {
			t.Errorf("Expected total_controls 25, got %v", controlSummary.Items["total_controls"])
		}
	})
	
	t.Run("compliance_remediation_tracking", func(t *testing.T) {
		fn, exists := vm.globalMap["compliance_remediation_tracking"]
		if !exists {
			t.Fatal("compliance_remediation_tracking function not found")
		}
		
		builtin := vm.globals[fn].(*NativeFunction)
		result, err := builtin.Function([]Value{"TRACK-2024-001"})
		
		if err != nil {
			t.Fatalf("compliance_remediation_tracking failed: %v", err)
		}
		
		resultMap, ok := result.(*Map)
		if !ok {
			t.Fatal("compliance_remediation_tracking should return a map")
		}
		
		if resultMap.Items["tracking_id"] != "TRACK-2024-001" {
			t.Errorf("Expected tracking_id 'TRACK-2024-001', got %v", resultMap.Items["tracking_id"])
		}
		
		if resultMap.Items["total_items"] != 3 {
			t.Errorf("Expected total_items 3, got %v", resultMap.Items["total_items"])
		}
		
		if resultMap.Items["completed_items"] != 1 {
			t.Errorf("Expected completed_items 1, got %v", resultMap.Items["completed_items"])
		}
		
		if resultMap.Items["overall_progress"] != 55 {
			t.Errorf("Expected overall_progress 55, got %v", resultMap.Items["overall_progress"])
		}
		
		remediationItems, ok := resultMap.Items["remediation_items"].(*Array)
		if !ok {
			t.Error("Expected remediation_items to be an array")
		}
		
		if len(remediationItems.Elements) != 3 {
			t.Errorf("Expected 3 remediation items, got %d", len(remediationItems.Elements))
		}
	})
}