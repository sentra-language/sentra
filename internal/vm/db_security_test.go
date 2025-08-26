package vm

import (
	"testing"
)

func TestDatabaseSecurityFunctions(t *testing.T) {
	vm := NewEnhancedVM(nil)
	
	t.Run("db_connect", func(t *testing.T) {
		fn, exists := vm.globalMap["db_connect"]
		if !exists {
			t.Fatal("db_connect function not found")
		}
		
		builtin := vm.globals[fn].(*NativeFunction)
		result, err := builtin.Function([]Value{"mysql", "localhost", "user:pass@localhost/testdb"})
		
		if err != nil {
			t.Fatalf("db_connect failed: %v", err)
		}
		
		resultMap, ok := result.(*Map)
		if !ok {
			t.Fatal("db_connect should return a map")
		}
		
		if resultMap.Items["type"] != "mysql" {
			t.Errorf("Expected type 'mysql', got %v", resultMap.Items["type"])
		}
		
		if resultMap.Items["host"] != "localhost" {
			t.Errorf("Expected host 'localhost', got %v", resultMap.Items["host"])
		}
		
		if resultMap.Items["status"] != "connected" {
			t.Errorf("Expected status 'connected', got %v", resultMap.Items["status"])
		}
	})
	
	t.Run("db_security_scan", func(t *testing.T) {
		fn, exists := vm.globalMap["db_security_scan"]
		if !exists {
			t.Fatal("db_security_scan function not found")
		}
		
		builtin := vm.globals[fn].(*NativeFunction)
		result, err := builtin.Function([]Value{"conn_123"})
		
		if err != nil {
			t.Fatalf("db_security_scan failed: %v", err)
		}
		
		resultMap, ok := result.(*Map)
		if !ok {
			t.Fatal("db_security_scan should return a map")
		}
		
		if resultMap.Items["connection_id"] != "conn_123" {
			t.Errorf("Expected connection_id 'conn_123', got %v", resultMap.Items["connection_id"])
		}
		
		findings, ok := resultMap.Items["findings"].(*Array)
		if !ok || len(findings.Elements) == 0 {
			t.Error("Expected findings array with elements")
		}
		
		if resultMap.Items["risk_score"] != 75.5 {
			t.Errorf("Expected risk_score 75.5, got %v", resultMap.Items["risk_score"])
		}
	})
	
	t.Run("db_test_injection", func(t *testing.T) {
		fn, exists := vm.globalMap["db_test_injection"]
		if !exists {
			t.Fatal("db_test_injection function not found")
		}
		
		builtin := vm.globals[fn].(*NativeFunction)
		
		// Test with safe query
		result1, err := builtin.Function([]Value{"conn_123", "SELECT * FROM users WHERE id = ?", "1"})
		if err != nil {
			t.Fatalf("db_test_injection failed: %v", err)
		}
		
		resultMap1, ok := result1.(*Map)
		if !ok {
			t.Fatal("db_test_injection should return a map")
		}
		
		if ToBool(resultMap1.Items["vulnerable"]) {
			t.Error("Safe query should not be marked as vulnerable")
		}
		
		// Test with malicious payload
		result2, err := builtin.Function([]Value{"conn_123", "SELECT * FROM users WHERE id = ?", "1' OR '1'='1"})
		if err != nil {
			t.Fatalf("db_test_injection failed: %v", err)
		}
		
		resultMap2, ok := result2.(*Map)
		if !ok {
			t.Fatal("db_test_injection should return a map")
		}
		
		if !ToBool(resultMap2.Items["vulnerable"]) {
			t.Error("Malicious payload should be marked as vulnerable")
		}
		
		if resultMap2.Items["risk_level"] != "CRITICAL" {
			t.Errorf("Expected risk_level 'CRITICAL', got %v", resultMap2.Items["risk_level"])
		}
	})
	
	t.Run("db_audit_privileges", func(t *testing.T) {
		fn, exists := vm.globalMap["db_audit_privileges"]
		if !exists {
			t.Fatal("db_audit_privileges function not found")
		}
		
		builtin := vm.globals[fn].(*NativeFunction)
		result, err := builtin.Function([]Value{"conn_123"})
		
		if err != nil {
			t.Fatalf("db_audit_privileges failed: %v", err)
		}
		
		resultMap, ok := result.(*Map)
		if !ok {
			t.Fatal("db_audit_privileges should return a map")
		}
		
		users, ok := resultMap.Items["users"].(*Array)
		if !ok || len(users.Elements) == 0 {
			t.Error("Expected users array with elements")
		}
		
		if resultMap.Items["total_users"] != 2 {
			t.Errorf("Expected total_users 2, got %v", resultMap.Items["total_users"])
		}
		
		if resultMap.Items["high_risk_users"] != 1 {
			t.Errorf("Expected high_risk_users 1, got %v", resultMap.Items["high_risk_users"])
		}
	})
	
	t.Run("db_check_encryption", func(t *testing.T) {
		fn, exists := vm.globalMap["db_check_encryption"]
		if !exists {
			t.Fatal("db_check_encryption function not found")
		}
		
		builtin := vm.globals[fn].(*NativeFunction)
		result, err := builtin.Function([]Value{"conn_123"})
		
		if err != nil {
			t.Fatalf("db_check_encryption failed: %v", err)
		}
		
		resultMap, ok := result.(*Map)
		if !ok {
			t.Fatal("db_check_encryption should return a map")
		}
		
		if !ToBool(resultMap.Items["ssl_connection"]) {
			t.Error("Expected ssl_connection to be true")
		}
		
		if resultMap.Items["tls_version"] != "TLSv1.2" {
			t.Errorf("Expected tls_version 'TLSv1.2', got %v", resultMap.Items["tls_version"])
		}
		
		if resultMap.Items["compliance_score"] != 60.0 {
			t.Errorf("Expected compliance_score 60.0, got %v", resultMap.Items["compliance_score"])
		}
	})
	
	t.Run("db_backup_security", func(t *testing.T) {
		fn, exists := vm.globalMap["db_backup_security"]
		if !exists {
			t.Fatal("db_backup_security function not found")
		}
		
		builtin := vm.globals[fn].(*NativeFunction)
		result, err := builtin.Function([]Value{"conn_123"})
		
		if err != nil {
			t.Fatalf("db_backup_security failed: %v", err)
		}
		
		resultMap, ok := result.(*Map)
		if !ok {
			t.Fatal("db_backup_security should return a map")
		}
		
		backups, ok := resultMap.Items["backups"].(*Array)
		if !ok || len(backups.Elements) == 0 {
			t.Error("Expected backups array with elements")
		}
		
		if resultMap.Items["total_backups"] != 2 {
			t.Errorf("Expected total_backups 2, got %v", resultMap.Items["total_backups"])
		}
		
		if resultMap.Items["secure_backups"] != 1 {
			t.Errorf("Expected secure_backups 1, got %v", resultMap.Items["secure_backups"])
		}
		
		if resultMap.Items["insecure_backups"] != 1 {
			t.Errorf("Expected insecure_backups 1, got %v", resultMap.Items["insecure_backups"])
		}
	})
	
	t.Run("db_compliance_check", func(t *testing.T) {
		fn, exists := vm.globalMap["db_compliance_check"]
		if !exists {
			t.Fatal("db_compliance_check function not found")
		}
		
		builtin := vm.globals[fn].(*NativeFunction)
		result, err := builtin.Function([]Value{"conn_123", "PCI-DSS"})
		
		if err != nil {
			t.Fatalf("db_compliance_check failed: %v", err)
		}
		
		resultMap, ok := result.(*Map)
		if !ok {
			t.Fatal("db_compliance_check should return a map")
		}
		
		if resultMap.Items["framework"] != "PCI-DSS" {
			t.Errorf("Expected framework 'PCI-DSS', got %v", resultMap.Items["framework"])
		}
		
		checks, ok := resultMap.Items["checks"].(*Array)
		if !ok || len(checks.Elements) == 0 {
			t.Error("Expected checks array with elements")
		}
		
		if resultMap.Items["compliance_score"] != 50.0 {
			t.Errorf("Expected compliance_score 50.0, got %v", resultMap.Items["compliance_score"])
		}
	})
}