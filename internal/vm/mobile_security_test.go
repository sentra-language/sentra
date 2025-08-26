package vm

import (
	"testing"
)

func TestMobileSecurityFunctions(t *testing.T) {
	vm := NewEnhancedVM(nil)
	
	t.Run("mobile_scan_device", func(t *testing.T) {
		fn, exists := vm.globalMap["mobile_scan_device"]
		if !exists {
			t.Fatal("mobile_scan_device function not found")
		}
		
		builtin := vm.globals[fn].(*NativeFunction)
		result, err := builtin.Function([]Value{"android", "device_123"})
		
		if err != nil {
			t.Fatalf("mobile_scan_device failed: %v", err)
		}
		
		resultMap, ok := result.(*Map)
		if !ok {
			t.Fatal("mobile_scan_device should return a map")
		}
		
		if resultMap.Items["device_id"] != "device_123" {
			t.Errorf("Expected device_id 'device_123', got %v", resultMap.Items["device_id"])
		}
		
		if resultMap.Items["device_type"] != "android" {
			t.Errorf("Expected device_type 'android', got %v", resultMap.Items["device_type"])
		}
		
		if resultMap.Items["risk_score"] != 65 {
			t.Errorf("Expected risk_score 65, got %v", resultMap.Items["risk_score"])
		}
		
		findings, ok := resultMap.Items["security_findings"].(*Array)
		if !ok {
			t.Error("Expected security_findings to be an array")
		}
		
		if len(findings.Elements) != 2 {
			t.Errorf("Expected 2 security findings, got %d", len(findings.Elements))
		}
	})
	
	t.Run("mobile_analyze_app", func(t *testing.T) {
		fn, exists := vm.globalMap["mobile_analyze_app"]
		if !exists {
			t.Fatal("mobile_analyze_app function not found")
		}
		
		builtin := vm.globals[fn].(*NativeFunction)
		result, err := builtin.Function([]Value{"device_123", "com.bank.mobile", "/data/app/com.bank.mobile"})
		
		if err != nil {
			t.Fatalf("mobile_analyze_app failed: %v", err)
		}
		
		resultMap, ok := result.(*Map)
		if !ok {
			t.Fatal("mobile_analyze_app should return a map")
		}
		
		if resultMap.Items["app_name"] != "MobileBank" {
			t.Errorf("Expected app_name 'MobileBank', got %v", resultMap.Items["app_name"])
		}
		
		if resultMap.Items["security_score"] != 72 {
			t.Errorf("Expected security_score 72, got %v", resultMap.Items["security_score"])
		}
		
		vulnerabilities, ok := resultMap.Items["vulnerabilities"].(*Array)
		if !ok {
			t.Error("Expected vulnerabilities to be an array")
		}
		
		if len(vulnerabilities.Elements) != 2 {
			t.Errorf("Expected 2 vulnerabilities, got %d", len(vulnerabilities.Elements))
		}
	})
	
	t.Run("mobile_check_permissions", func(t *testing.T) {
		fn, exists := vm.globalMap["mobile_check_permissions"]
		if !exists {
			t.Fatal("mobile_check_permissions function not found")
		}
		
		builtin := vm.globals[fn].(*NativeFunction)
		result, err := builtin.Function([]Value{"device_123", "com.bank.mobile"})
		
		if err != nil {
			t.Fatalf("mobile_check_permissions failed: %v", err)
		}
		
		resultMap, ok := result.(*Map)
		if !ok {
			t.Fatal("mobile_check_permissions should return a map")
		}
		
		if resultMap.Items["high_risk_count"] != 1 {
			t.Errorf("Expected high_risk_count 1, got %v", resultMap.Items["high_risk_count"])
		}
		
		if resultMap.Items["medium_risk_count"] != 1 {
			t.Errorf("Expected medium_risk_count 1, got %v", resultMap.Items["medium_risk_count"])
		}
		
		permissions, ok := resultMap.Items["permissions"].(*Array)
		if !ok {
			t.Error("Expected permissions to be an array")
		}
		
		if len(permissions.Elements) != 3 {
			t.Errorf("Expected 3 permissions, got %d", len(permissions.Elements))
		}
	})
	
	t.Run("mobile_network_security", func(t *testing.T) {
		fn, exists := vm.globalMap["mobile_network_security"]
		if !exists {
			t.Fatal("mobile_network_security function not found")
		}
		
		builtin := vm.globals[fn].(*NativeFunction)
		result, err := builtin.Function([]Value{"device_123"})
		
		if err != nil {
			t.Fatalf("mobile_network_security failed: %v", err)
		}
		
		resultMap, ok := result.(*Map)
		if !ok {
			t.Fatal("mobile_network_security should return a map")
		}
		
		if resultMap.Items["overall_network_risk"] != "MEDIUM" {
			t.Errorf("Expected overall_network_risk 'MEDIUM', got %v", resultMap.Items["overall_network_risk"])
		}
		
		if resultMap.Items["open_networks_detected"] != 1 {
			t.Errorf("Expected open_networks_detected 1, got %v", resultMap.Items["open_networks_detected"])
		}
		
		wifiNetworks, ok := resultMap.Items["wifi_networks"].(*Array)
		if !ok {
			t.Error("Expected wifi_networks to be an array")
		}
		
		if len(wifiNetworks.Elements) != 2 {
			t.Errorf("Expected 2 wifi networks, got %d", len(wifiNetworks.Elements))
		}
	})
	
	t.Run("mobile_compliance_check", func(t *testing.T) {
		fn, exists := vm.globalMap["mobile_compliance_check"]
		if !exists {
			t.Fatal("mobile_compliance_check function not found")
		}
		
		builtin := vm.globals[fn].(*NativeFunction)
		result, err := builtin.Function([]Value{"device_123", "GDPR"})
		
		if err != nil {
			t.Fatalf("mobile_compliance_check failed: %v", err)
		}
		
		resultMap, ok := result.(*Map)
		if !ok {
			t.Fatal("mobile_compliance_check should return a map")
		}
		
		if resultMap.Items["framework"] != "GDPR" {
			t.Errorf("Expected framework 'GDPR', got %v", resultMap.Items["framework"])
		}
		
		if resultMap.Items["compliance_score"] != 67 {
			t.Errorf("Expected compliance_score 67, got %v", resultMap.Items["compliance_score"])
		}
		
		if resultMap.Items["overall_compliance"] != "PARTIAL" {
			t.Errorf("Expected overall_compliance 'PARTIAL', got %v", resultMap.Items["overall_compliance"])
		}
	})
	
	t.Run("mobile_threat_detection", func(t *testing.T) {
		fn, exists := vm.globalMap["mobile_threat_detection"]
		if !exists {
			t.Fatal("mobile_threat_detection function not found")
		}
		
		builtin := vm.globals[fn].(*NativeFunction)
		result, err := builtin.Function([]Value{"device_123"})
		
		if err != nil {
			t.Fatalf("mobile_threat_detection failed: %v", err)
		}
		
		resultMap, ok := result.(*Map)
		if !ok {
			t.Fatal("mobile_threat_detection should return a map")
		}
		
		if resultMap.Items["overall_risk"] != "HIGH" {
			t.Errorf("Expected overall_risk 'HIGH', got %v", resultMap.Items["overall_risk"])
		}
		
		if resultMap.Items["threat_count"] != 2 {
			t.Errorf("Expected threat_count 2, got %v", resultMap.Items["threat_count"])
		}
		
		threats, ok := resultMap.Items["threats_detected"].(*Array)
		if !ok {
			t.Error("Expected threats_detected to be an array")
		}
		
		if len(threats.Elements) != 2 {
			t.Errorf("Expected 2 threats, got %d", len(threats.Elements))
		}
	})
	
	t.Run("mobile_data_protection", func(t *testing.T) {
		fn, exists := vm.globalMap["mobile_data_protection"]
		if !exists {
			t.Fatal("mobile_data_protection function not found")
		}
		
		builtin := vm.globals[fn].(*NativeFunction)
		result, err := builtin.Function([]Value{"device_123", "com.bank.mobile"})
		
		if err != nil {
			t.Fatalf("mobile_data_protection failed: %v", err)
		}
		
		resultMap, ok := result.(*Map)
		if !ok {
			t.Fatal("mobile_data_protection should return a map")
		}
		
		if resultMap.Items["protection_score"] != 67 {
			t.Errorf("Expected protection_score 67, got %v", resultMap.Items["protection_score"])
		}
		
		if resultMap.Items["encrypted_data"] != 2 {
			t.Errorf("Expected encrypted_data 2, got %v", resultMap.Items["encrypted_data"])
		}
		
		if resultMap.Items["unencrypted_data"] != 1 {
			t.Errorf("Expected unencrypted_data 1, got %v", resultMap.Items["unencrypted_data"])
		}
		
		dataTypes, ok := resultMap.Items["data_types"].(*Array)
		if !ok {
			t.Error("Expected data_types to be an array")
		}
		
		if len(dataTypes.Elements) != 3 {
			t.Errorf("Expected 3 data types, got %d", len(dataTypes.Elements))
		}
	})
	
	t.Run("mobile_forensic_analysis", func(t *testing.T) {
		fn, exists := vm.globalMap["mobile_forensic_analysis"]
		if !exists {
			t.Fatal("mobile_forensic_analysis function not found")
		}
		
		builtin := vm.globals[fn].(*NativeFunction)
		result, err := builtin.Function([]Value{"device_123"})
		
		if err != nil {
			t.Fatalf("mobile_forensic_analysis failed: %v", err)
		}
		
		resultMap, ok := result.(*Map)
		if !ok {
			t.Fatal("mobile_forensic_analysis should return a map")
		}
		
		if resultMap.Items["extraction_method"] != "logical" {
			t.Errorf("Expected extraction_method 'logical', got %v", resultMap.Items["extraction_method"])
		}
		
		if resultMap.Items["total_artifacts"] != 3 {
			t.Errorf("Expected total_artifacts 3, got %v", resultMap.Items["total_artifacts"])
		}
		
		if resultMap.Items["analysis_complete"] != true {
			t.Errorf("Expected analysis_complete true, got %v", resultMap.Items["analysis_complete"])
		}
		
		artifacts, ok := resultMap.Items["artifacts"].(*Array)
		if !ok {
			t.Error("Expected artifacts to be an array")
		}
		
		if len(artifacts.Elements) != 3 {
			t.Errorf("Expected 3 artifacts, got %d", len(artifacts.Elements))
		}
	})
}