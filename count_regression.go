package main

import (
	"fmt"
	"os/exec"
	"time"
)

func main() {
	scripts := []string{
		"advanced_functions.sn",
		"algorithms.sn",
		"api_final_demo.sn",
		"api_manual_test.sn",
		"api_safe_demo.sn",
		"api_security_demo.sn",
		"api_simple_test.sn",
		"api_working_demo.sn",
		"arrays_and_maps.sn",
		"complete_test.sn",
		"concurrency_debug.sn",
		"concurrency_minimal.sn",
		"concurrency_simple.sn",
		"concurrency_test.sn",
		"concurrency_test_new.sn",
		"container_minimal.sn",
		"container_simple.sn",
		"control_flow.sn",
		"crypto_utils.sn",
		"debug_test.sn",
		"error_handling.sn",
		"exploit_demo.sn",
		"exploit_framework.sn",
		"firewall_rules.sn",
		"hello.sn",
		"log_analyzer.sn",
		"math.sn",
		"math_test.sn",
		"memory_basic.sn",
		"memory_simple.sn",
		"ml_security_demo.sn",
		"modules_example.sn",
		"nested_fn.sn",
		"network_scan.sn",
		"network_scanner.sn",
		"network_security_test.sn",
		"recursion.sn",
		"security_app_honeypot.sn",
		"security_app_ids.sn",
		"security_demo.sn",
		"security_hash.sn",
		"sentra_showcase.sn",
		"siem_demo.sn",
		"siem_demo_fixed.sn",
		"siem_working_demo.sn",
		"sockets.sn",
		"stdlib_demo.sn",
		"stdlib_simple.sn",
		"test_simple_function.sn",
		"threat_detection.sn",
		"threat_intel_demo.sn",
		"threat_intel_simple.sn",
		"vulnerability_scanner.sn",
	}
	
	passing := 0
	failing := 0
	
	for _, script := range scripts {
		fmt.Printf("Testing %s... ", script)
		cmd := exec.Command("C:\\Program Files\\Go\\bin\\go.exe", "run", "cmd/sentra/main.go", "run", "examples/"+script)
		
		done := make(chan error)
		go func() {
			done <- cmd.Run()
		}()
		
		select {
		case err := <-done:
			if err != nil {
				fmt.Printf("✗ FAILED\n")
				failing++
			} else {
				fmt.Printf("✓ PASSED\n")
				passing++
			}
		case <-time.After(3 * time.Second):
			cmd.Process.Kill()
			fmt.Printf("⏱ TIMEOUT\n")
			failing++
		}
	}
	
	total := passing + failing
	percentage := float64(passing) * 100 / float64(total)
	
	fmt.Printf("\n================================================================================\n")
	fmt.Printf("Results: %d passed, %d failed out of %d total (%.1f%%)\n", passing, failing, total, percentage)
}