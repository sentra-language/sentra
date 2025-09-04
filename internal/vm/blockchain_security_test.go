package vm

import (
	"testing"
)

func TestBlockchainSecurityFunctions(t *testing.T) {
	vm := NewVM(nil)
	
	t.Run("blockchain_connect", func(t *testing.T) {
		fn, exists := vm.globalMap["blockchain_connect"]
		if !exists {
			t.Fatal("blockchain_connect function not found")
		}
		
		builtin := vm.globals[fn].(*NativeFunction)
		result, err := builtin.Function([]Value{"ethereum", "https://eth-mainnet.g.alchemy.com/v2/key"})
		
		if err != nil {
			t.Fatalf("blockchain_connect failed: %v", err)
		}
		
		resultMap, ok := result.(*Map)
		if !ok {
			t.Fatal("blockchain_connect should return a map")
		}
		
		if resultMap.Items["network"] != "ethereum" {
			t.Errorf("Expected network 'ethereum', got %v", resultMap.Items["network"])
		}
		
		if resultMap.Items["status"] != "connected" {
			t.Errorf("Expected status 'connected', got %v", resultMap.Items["status"])
		}
		
		if resultMap.Items["chain_id"] != 1 {
			t.Errorf("Expected chain_id 1, got %v", resultMap.Items["chain_id"])
		}
	})
	
	t.Run("blockchain_analyze_transaction", func(t *testing.T) {
		fn, exists := vm.globalMap["blockchain_analyze_transaction"]
		if !exists {
			t.Fatal("blockchain_analyze_transaction function not found")
		}
		
		builtin := vm.globals[fn].(*NativeFunction)
		result, err := builtin.Function([]Value{"bc_123", "0xabcd1234"})
		
		if err != nil {
			t.Fatalf("blockchain_analyze_transaction failed: %v", err)
		}
		
		resultMap, ok := result.(*Map)
		if !ok {
			t.Fatal("blockchain_analyze_transaction should return a map")
		}
		
		if resultMap.Items["connection_id"] != "bc_123" {
			t.Errorf("Expected connection_id 'bc_123', got %v", resultMap.Items["connection_id"])
		}
		
		if resultMap.Items["transaction_hash"] != "0xabcd1234" {
			t.Errorf("Expected transaction_hash '0xabcd1234', got %v", resultMap.Items["transaction_hash"])
		}
		
		riskFactors, ok := resultMap.Items["risk_factors"].(*Array)
		if !ok {
			t.Error("Expected risk_factors to be an array")
		}
		
		if len(riskFactors.Elements) == 0 {
			t.Error("Expected at least one risk factor")
		}
	})
	
	t.Run("blockchain_audit_contract", func(t *testing.T) {
		fn, exists := vm.globalMap["blockchain_audit_contract"]
		if !exists {
			t.Fatal("blockchain_audit_contract function not found")
		}
		
		builtin := vm.globals[fn].(*NativeFunction)
		result, err := builtin.Function([]Value{"bc_123", "0x1234567890123456789012345678901234567890"})
		
		if err != nil {
			t.Fatalf("blockchain_audit_contract failed: %v", err)
		}
		
		resultMap, ok := result.(*Map)
		if !ok {
			t.Fatal("blockchain_audit_contract should return a map")
		}
		
		vulnerabilities, ok := resultMap.Items["vulnerabilities"].(*Array)
		if !ok {
			t.Error("Expected vulnerabilities to be an array")
		}
		
		if len(vulnerabilities.Elements) != 2 {
			t.Errorf("Expected 2 vulnerabilities, got %d", len(vulnerabilities.Elements))
		}
		
		if resultMap.Items["security_score"] != 65.0 {
			t.Errorf("Expected security_score 65.0, got %v", resultMap.Items["security_score"])
		}
		
		if resultMap.Items["high_count"] != 1 {
			t.Errorf("Expected high_count 1, got %v", resultMap.Items["high_count"])
		}
	})
	
	t.Run("blockchain_trace_funds", func(t *testing.T) {
		fn, exists := vm.globalMap["blockchain_trace_funds"]
		if !exists {
			t.Fatal("blockchain_trace_funds function not found")
		}
		
		builtin := vm.globals[fn].(*NativeFunction)
		result, err := builtin.Function([]Value{"bc_123", "0x1234567890123456789012345678901234567890", 3})
		
		if err != nil {
			t.Fatalf("blockchain_trace_funds failed: %v", err)
		}
		
		resultMap, ok := result.(*Map)
		if !ok {
			t.Fatal("blockchain_trace_funds should return a map")
		}
		
		if resultMap.Items["trace_depth"] != 3 {
			t.Errorf("Expected trace_depth 3, got %v", resultMap.Items["trace_depth"])
		}
		
		transactions, ok := resultMap.Items["transaction_path"].(*Array)
		if !ok {
			t.Error("Expected transaction_path to be an array")
		}
		
		if len(transactions.Elements) != 3 {
			t.Errorf("Expected 3 transactions, got %d", len(transactions.Elements))
		}
		
		if resultMap.Items["mixing_detected"] != false {
			t.Errorf("Expected mixing_detected false, got %v", resultMap.Items["mixing_detected"])
		}
	})
	
	t.Run("blockchain_check_wallet", func(t *testing.T) {
		fn, exists := vm.globalMap["blockchain_check_wallet"]
		if !exists {
			t.Fatal("blockchain_check_wallet function not found")
		}
		
		builtin := vm.globals[fn].(*NativeFunction)
		result, err := builtin.Function([]Value{"bc_123", "0x1234567890123456789012345678901234567890"})
		
		if err != nil {
			t.Fatalf("blockchain_check_wallet failed: %v", err)
		}
		
		resultMap, ok := result.(*Map)
		if !ok {
			t.Fatal("blockchain_check_wallet should return a map")
		}
		
		if resultMap.Items["transaction_count"] != 156 {
			t.Errorf("Expected transaction_count 156, got %v", resultMap.Items["transaction_count"])
		}
		
		if resultMap.Items["blacklisted"] != false {
			t.Errorf("Expected blacklisted false, got %v", resultMap.Items["blacklisted"])
		}
		
		riskIndicators, ok := resultMap.Items["risk_indicators"].(*Array)
		if !ok {
			t.Error("Expected risk_indicators to be an array")
		}
		
		if len(riskIndicators.Elements) != 2 {
			t.Errorf("Expected 2 risk indicators, got %d", len(riskIndicators.Elements))
		}
	})
	
	t.Run("blockchain_analyze_defi", func(t *testing.T) {
		fn, exists := vm.globalMap["blockchain_analyze_defi"]
		if !exists {
			t.Fatal("blockchain_analyze_defi function not found")
		}
		
		builtin := vm.globals[fn].(*NativeFunction)
		result, err := builtin.Function([]Value{"bc_123", "0x1234567890123456789012345678901234567890"})
		
		if err != nil {
			t.Fatalf("blockchain_analyze_defi failed: %v", err)
		}
		
		resultMap, ok := result.(*Map)
		if !ok {
			t.Fatal("blockchain_analyze_defi should return a map")
		}
		
		if resultMap.Items["protocol_name"] != "MockSwap" {
			t.Errorf("Expected protocol_name 'MockSwap', got %v", resultMap.Items["protocol_name"])
		}
		
		if resultMap.Items["liquidity_pools"] != 42 {
			t.Errorf("Expected liquidity_pools 42, got %v", resultMap.Items["liquidity_pools"])
		}
		
		securityIssues, ok := resultMap.Items["security_issues"].(*Array)
		if !ok {
			t.Error("Expected security_issues to be an array")
		}
		
		if len(securityIssues.Elements) != 2 {
			t.Errorf("Expected 2 security issues, got %d", len(securityIssues.Elements))
		}
		
		if resultMap.Items["security_score"] != 70.0 {
			t.Errorf("Expected security_score 70.0, got %v", resultMap.Items["security_score"])
		}
	})
	
	t.Run("blockchain_nft_analysis", func(t *testing.T) {
		fn, exists := vm.globalMap["blockchain_nft_analysis"]
		if !exists {
			t.Fatal("blockchain_nft_analysis function not found")
		}
		
		builtin := vm.globals[fn].(*NativeFunction)
		result, err := builtin.Function([]Value{"bc_123", "0x1234567890123456789012345678901234567890"})
		
		if err != nil {
			t.Fatalf("blockchain_nft_analysis failed: %v", err)
		}
		
		resultMap, ok := result.(*Map)
		if !ok {
			t.Fatal("blockchain_nft_analysis should return a map")
		}
		
		if resultMap.Items["collection_name"] != "CryptoArt Collection" {
			t.Errorf("Expected collection_name 'CryptoArt Collection', got %v", resultMap.Items["collection_name"])
		}
		
		if resultMap.Items["total_supply"] != 10000 {
			t.Errorf("Expected total_supply 10000, got %v", resultMap.Items["total_supply"])
		}
		
		securityChecks, ok := resultMap.Items["security_checks"].(*Array)
		if !ok {
			t.Error("Expected security_checks to be an array")
		}
		
		if len(securityChecks.Elements) != 2 {
			t.Errorf("Expected 2 security checks, got %d", len(securityChecks.Elements))
		}
		
		if resultMap.Items["authenticity_score"] != 85.0 {
			t.Errorf("Expected authenticity_score 85.0, got %v", resultMap.Items["authenticity_score"])
		}
	})
	
	t.Run("blockchain_compliance_check", func(t *testing.T) {
		fn, exists := vm.globalMap["blockchain_compliance_check"]
		if !exists {
			t.Fatal("blockchain_compliance_check function not found")
		}
		
		builtin := vm.globals[fn].(*NativeFunction)
		result, err := builtin.Function([]Value{"bc_123", "0x1234567890123456789012345678901234567890", "US"})
		
		if err != nil {
			t.Fatalf("blockchain_compliance_check failed: %v", err)
		}
		
		resultMap, ok := result.(*Map)
		if !ok {
			t.Fatal("blockchain_compliance_check should return a map")
		}
		
		if resultMap.Items["jurisdiction"] != "US" {
			t.Errorf("Expected jurisdiction 'US', got %v", resultMap.Items["jurisdiction"])
		}
		
		complianceChecks, ok := resultMap.Items["compliance_checks"].(*Array)
		if !ok {
			t.Error("Expected compliance_checks to be an array")
		}
		
		if len(complianceChecks.Elements) != 2 {
			t.Errorf("Expected 2 compliance checks, got %d", len(complianceChecks.Elements))
		}
		
		if resultMap.Items["overall_compliance"] != "PARTIAL" {
			t.Errorf("Expected overall_compliance 'PARTIAL', got %v", resultMap.Items["overall_compliance"])
		}
		
		if ToBool(resultMap.Items["requires_kyc"]) != true {
			t.Errorf("Expected requires_kyc true, got %v", resultMap.Items["requires_kyc"])
		}
	})
}