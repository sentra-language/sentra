package vm

import (
	"testing"
)

func TestIoTSecurityFunctions(t *testing.T) {
	vm := NewEnhancedVM(nil)
	
	t.Run("iot_scan_device", func(t *testing.T) {
		fn, exists := vm.globalMap["iot_scan_device"]
		if !exists {
			t.Fatal("iot_scan_device function not found")
		}
		
		builtin := vm.globals[fn].(*NativeFunction)
		result, err := builtin.Function([]Value{"smart_sensor", "iot_device_001"})
		
		if err != nil {
			t.Fatalf("iot_scan_device failed: %v", err)
		}
		
		resultMap, ok := result.(*Map)
		if !ok {
			t.Fatal("iot_scan_device should return a map")
		}
		
		if resultMap.Items["device_id"] != "iot_device_001" {
			t.Errorf("Expected device_id 'iot_device_001', got %v", resultMap.Items["device_id"])
		}
		
		if resultMap.Items["device_type"] != "smart_sensor" {
			t.Errorf("Expected device_type 'smart_sensor', got %v", resultMap.Items["device_type"])
		}
		
		if resultMap.Items["risk_score"] != 75 {
			t.Errorf("Expected risk_score 75, got %v", resultMap.Items["risk_score"])
		}
		
		vulnerabilities, ok := resultMap.Items["vulnerabilities"].(*Array)
		if !ok {
			t.Error("Expected vulnerabilities to be an array")
		}
		
		if len(vulnerabilities.Elements) != 2 {
			t.Errorf("Expected 2 vulnerabilities, got %d", len(vulnerabilities.Elements))
		}
	})
	
	t.Run("iot_network_analysis", func(t *testing.T) {
		fn, exists := vm.globalMap["iot_network_analysis"]
		if !exists {
			t.Fatal("iot_network_analysis function not found")
		}
		
		builtin := vm.globals[fn].(*NativeFunction)
		result, err := builtin.Function([]Value{"iot_device_001"})
		
		if err != nil {
			t.Fatalf("iot_network_analysis failed: %v", err)
		}
		
		resultMap, ok := result.(*Map)
		if !ok {
			t.Fatal("iot_network_analysis should return a map")
		}
		
		if resultMap.Items["total_connections"] != 47 {
			t.Errorf("Expected total_connections 47, got %v", resultMap.Items["total_connections"])
		}
		
		if resultMap.Items["network_risk_score"] != 68 {
			t.Errorf("Expected network_risk_score 68, got %v", resultMap.Items["network_risk_score"])
		}
		
		suspiciousActivities, ok := resultMap.Items["suspicious_activities"].(*Array)
		if !ok {
			t.Error("Expected suspicious_activities to be an array")
		}
		
		if len(suspiciousActivities.Elements) != 2 {
			t.Errorf("Expected 2 suspicious activities, got %d", len(suspiciousActivities.Elements))
		}
	})
	
	t.Run("iot_firmware_analysis", func(t *testing.T) {
		fn, exists := vm.globalMap["iot_firmware_analysis"]
		if !exists {
			t.Fatal("iot_firmware_analysis function not found")
		}
		
		builtin := vm.globals[fn].(*NativeFunction)
		result, err := builtin.Function([]Value{"iot_device_001", "/firmware/sensor_v1.4.2.bin"})
		
		if err != nil {
			t.Fatalf("iot_firmware_analysis failed: %v", err)
		}
		
		resultMap, ok := result.(*Map)
		if !ok {
			t.Fatal("iot_firmware_analysis should return a map")
		}
		
		if resultMap.Items["security_score"] != 32 {
			t.Errorf("Expected security_score 32, got %v", resultMap.Items["security_score"])
		}
		
		if resultMap.Items["critical_count"] != 1 {
			t.Errorf("Expected critical_count 1, got %v", resultMap.Items["critical_count"])
		}
		
		if resultMap.Items["high_count"] != 2 {
			t.Errorf("Expected high_count 2, got %v", resultMap.Items["high_count"])
		}
		
		findings, ok := resultMap.Items["security_findings"].(*Array)
		if !ok {
			t.Error("Expected security_findings to be an array")
		}
		
		if len(findings.Elements) != 3 {
			t.Errorf("Expected 3 security findings, got %d", len(findings.Elements))
		}
	})
	
	t.Run("iot_protocol_security", func(t *testing.T) {
		fn, exists := vm.globalMap["iot_protocol_security"]
		if !exists {
			t.Fatal("iot_protocol_security function not found")
		}
		
		builtin := vm.globals[fn].(*NativeFunction)
		result, err := builtin.Function([]Value{"iot_device_001", "MQTT"})
		
		if err != nil {
			t.Fatalf("iot_protocol_security failed: %v", err)
		}
		
		resultMap, ok := result.(*Map)
		if !ok {
			t.Fatal("iot_protocol_security should return a map")
		}
		
		if resultMap.Items["protocol"] != "MQTT" {
			t.Errorf("Expected protocol 'MQTT', got %v", resultMap.Items["protocol"])
		}
		
		if resultMap.Items["protocol_security_score"] != 25 {
			t.Errorf("Expected protocol_security_score 25, got %v", resultMap.Items["protocol_security_score"])
		}
		
		issues, ok := resultMap.Items["security_issues"].(*Array)
		if !ok {
			t.Error("Expected security_issues to be an array")
		}
		
		if len(issues.Elements) != 2 {
			t.Errorf("Expected 2 security issues, got %d", len(issues.Elements))
		}
	})
	
	t.Run("iot_device_authentication", func(t *testing.T) {
		fn, exists := vm.globalMap["iot_device_authentication"]
		if !exists {
			t.Fatal("iot_device_authentication function not found")
		}
		
		builtin := vm.globals[fn].(*NativeFunction)
		result, err := builtin.Function([]Value{"iot_device_001"})
		
		if err != nil {
			t.Fatalf("iot_device_authentication failed: %v", err)
		}
		
		resultMap, ok := result.(*Map)
		if !ok {
			t.Fatal("iot_device_authentication should return a map")
		}
		
		if resultMap.Items["authentication_score"] != 35 {
			t.Errorf("Expected authentication_score 35, got %v", resultMap.Items["authentication_score"])
		}
		
		authMethods, ok := resultMap.Items["authentication_methods"].(*Array)
		if !ok {
			t.Error("Expected authentication_methods to be an array")
		}
		
		if len(authMethods.Elements) != 2 {
			t.Errorf("Expected 2 authentication methods, got %d", len(authMethods.Elements))
		}
		
		recommendations, ok := resultMap.Items["recommendations"].(*Array)
		if !ok {
			t.Error("Expected recommendations to be an array")
		}
		
		if len(recommendations.Elements) != 4 {
			t.Errorf("Expected 4 recommendations, got %d", len(recommendations.Elements))
		}
	})
	
	t.Run("iot_data_protection", func(t *testing.T) {
		fn, exists := vm.globalMap["iot_data_protection"]
		if !exists {
			t.Fatal("iot_data_protection function not found")
		}
		
		builtin := vm.globals[fn].(*NativeFunction)
		result, err := builtin.Function([]Value{"iot_device_001"})
		
		if err != nil {
			t.Fatalf("iot_data_protection failed: %v", err)
		}
		
		resultMap, ok := result.(*Map)
		if !ok {
			t.Fatal("iot_data_protection should return a map")
		}
		
		if resultMap.Items["data_protection_score"] != 45 {
			t.Errorf("Expected data_protection_score 45, got %v", resultMap.Items["data_protection_score"])
		}
		
		if resultMap.Items["encrypted_flows"] != 1 {
			t.Errorf("Expected encrypted_flows 1, got %v", resultMap.Items["encrypted_flows"])
		}
		
		if resultMap.Items["unencrypted_flows"] != 2 {
			t.Errorf("Expected unencrypted_flows 2, got %v", resultMap.Items["unencrypted_flows"])
		}
		
		dataFlows, ok := resultMap.Items["data_flows"].(*Array)
		if !ok {
			t.Error("Expected data_flows to be an array")
		}
		
		if len(dataFlows.Elements) != 3 {
			t.Errorf("Expected 3 data flows, got %d", len(dataFlows.Elements))
		}
	})
	
	t.Run("iot_compliance_check", func(t *testing.T) {
		fn, exists := vm.globalMap["iot_compliance_check"]
		if !exists {
			t.Fatal("iot_compliance_check function not found")
		}
		
		builtin := vm.globals[fn].(*NativeFunction)
		result, err := builtin.Function([]Value{"iot_device_001", "NIST"})
		
		if err != nil {
			t.Fatalf("iot_compliance_check failed: %v", err)
		}
		
		resultMap, ok := result.(*Map)
		if !ok {
			t.Fatal("iot_compliance_check should return a map")
		}
		
		if resultMap.Items["compliance_standard"] != "NIST" {
			t.Errorf("Expected compliance_standard 'NIST', got %v", resultMap.Items["compliance_standard"])
		}
		
		if resultMap.Items["compliance_score"] != 33 {
			t.Errorf("Expected compliance_score 33, got %v", resultMap.Items["compliance_score"])
		}
		
		if resultMap.Items["overall_compliance"] != "NON_COMPLIANT" {
			t.Errorf("Expected overall_compliance 'NON_COMPLIANT', got %v", resultMap.Items["overall_compliance"])
		}
		
		checks, ok := resultMap.Items["checks"].(*Array)
		if !ok {
			t.Error("Expected checks to be an array")
		}
		
		if len(checks.Elements) != 3 {
			t.Errorf("Expected 3 checks, got %d", len(checks.Elements))
		}
	})
	
	t.Run("iot_threat_modeling", func(t *testing.T) {
		fn, exists := vm.globalMap["iot_threat_modeling"]
		if !exists {
			t.Fatal("iot_threat_modeling function not found")
		}
		
		builtin := vm.globals[fn].(*NativeFunction)
		result, err := builtin.Function([]Value{"iot_device_001"})
		
		if err != nil {
			t.Fatalf("iot_threat_modeling failed: %v", err)
		}
		
		resultMap, ok := result.(*Map)
		if !ok {
			t.Fatal("iot_threat_modeling should return a map")
		}
		
		if resultMap.Items["threat_model"] != "STRIDE" {
			t.Errorf("Expected threat_model 'STRIDE', got %v", resultMap.Items["threat_model"])
		}
		
		if resultMap.Items["overall_risk"] != "CRITICAL" {
			t.Errorf("Expected overall_risk 'CRITICAL', got %v", resultMap.Items["overall_risk"])
		}
		
		if resultMap.Items["critical_threats"] != 1 {
			t.Errorf("Expected critical_threats 1, got %v", resultMap.Items["critical_threats"])
		}
		
		if resultMap.Items["high_threats"] != 2 {
			t.Errorf("Expected high_threats 2, got %v", resultMap.Items["high_threats"])
		}
		
		threats, ok := resultMap.Items["identified_threats"].(*Array)
		if !ok {
			t.Error("Expected identified_threats to be an array")
		}
		
		if len(threats.Elements) != 3 {
			t.Errorf("Expected 3 threats, got %d", len(threats.Elements))
		}
	})
}