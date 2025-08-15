// internal/testing/simple_module.go
package testing

import (
	"fmt"
	"strings"
	"sentra/internal/vm"
)

// GetSimpleTestFunctions returns basic assertion functions for testing
func GetSimpleTestFunctions() map[string]*vm.NativeFunction {
	testsPassed := 0
	testsFailed := 0
	
	return map[string]*vm.NativeFunction{
		"assert": {
			Name:  "assert",
			Arity: 2,
			Function: func(args []vm.Value) (vm.Value, error) {
				condition := vm.ToBool(args[0])
				message := vm.ToString(args[1])
				
				if !condition {
					testsFailed++
					return false, fmt.Errorf("❌ Assertion failed: %s", message)
				}
				testsPassed++
				return true, nil
			},
		},
		
		"assert_equal": {
			Name:  "assert_equal",
			Arity: 3,
			Function: func(args []vm.Value) (vm.Value, error) {
				expected := args[0]
				actual := args[1]
				message := vm.ToString(args[2])
				
				if !vm.ValuesEqual(expected, actual) {
					testsFailed++
					return false, fmt.Errorf("❌ assert_equal failed: %s\n  Expected: %v\n  Actual: %v", 
						message, expected, actual)
				}
				testsPassed++
				return true, nil
			},
		},
		
		"assert_not_equal": {
			Name:  "assert_not_equal",
			Arity: 3,
			Function: func(args []vm.Value) (vm.Value, error) {
				expected := args[0]
				actual := args[1]
				message := vm.ToString(args[2])
				
				if vm.ValuesEqual(expected, actual) {
					testsFailed++
					return false, fmt.Errorf("❌ assert_not_equal failed: %s\n  Values are equal: %v", 
						message, expected)
				}
				testsPassed++
				return true, nil
			},
		},
		
		"assert_true": {
			Name:  "assert_true",
			Arity: 2,
			Function: func(args []vm.Value) (vm.Value, error) {
				condition := vm.ToBool(args[0])
				message := vm.ToString(args[1])
				
				if !condition {
					testsFailed++
					return false, fmt.Errorf("❌ assert_true failed: %s", message)
				}
				testsPassed++
				return true, nil
			},
		},
		
		"assert_false": {
			Name:  "assert_false",
			Arity: 2,
			Function: func(args []vm.Value) (vm.Value, error) {
				condition := vm.ToBool(args[0])
				message := vm.ToString(args[1])
				
				if condition {
					testsFailed++
					return false, fmt.Errorf("❌ assert_false failed: %s", message)
				}
				testsPassed++
				return true, nil
			},
		},
		
		"assert_nil": {
			Name:  "assert_nil",
			Arity: 2,
			Function: func(args []vm.Value) (vm.Value, error) {
				value := args[0]
				message := vm.ToString(args[1])
				
				if value != nil {
					testsFailed++
					return false, fmt.Errorf("❌ assert_nil failed: %s\n  Value is not nil: %v", 
						message, value)
				}
				testsPassed++
				return true, nil
			},
		},
		
		"assert_not_nil": {
			Name:  "assert_not_nil",
			Arity: 2,
			Function: func(args []vm.Value) (vm.Value, error) {
				value := args[0]
				message := vm.ToString(args[1])
				
				if value == nil {
					testsFailed++
					return false, fmt.Errorf("❌ assert_not_nil failed: %s\n  Value is nil", message)
				}
				testsPassed++
				return true, nil
			},
		},
		
		"assert_contains": {
			Name:  "assert_contains",
			Arity: 3,
			Function: func(args []vm.Value) (vm.Value, error) {
				container := args[0]
				item := args[1]
				message := vm.ToString(args[2])
				
				// Check if container is array
				if arr, ok := container.(*vm.Array); ok {
					for _, elem := range arr.Elements {
						if vm.ValuesEqual(elem, item) {
							testsPassed++
							return true, nil
						}
					}
					testsFailed++
					return false, fmt.Errorf("❌ assert_contains failed: %s\n  Array does not contain: %v", 
						message, item)
				}
				
				// Check if container is string
				if str, ok := container.(string); ok {
					itemStr := vm.ToString(item)
					if strings.Contains(str, itemStr) {
						testsPassed++
						return true, nil
					}
					testsFailed++
					return false, fmt.Errorf("❌ assert_contains failed: %s\n  String '%s' does not contain: '%s'", 
						message, str, itemStr)
				}
				
				testsFailed++
				return false, fmt.Errorf("❌ assert_contains: unsupported container type")
			},
		},
		
		"test_summary": {
			Name:  "test_summary",
			Arity: 0,
			Function: func(args []vm.Value) (vm.Value, error) {
				total := testsPassed + testsFailed
				fmt.Printf("\n" + strings.Repeat("=", 60) + "\n")
				fmt.Printf("📊 Test Results Summary\n")
				fmt.Printf(strings.Repeat("=", 60) + "\n")
				fmt.Printf("Total Tests:    %d\n", total)
				fmt.Printf("\033[32m✓ Passed:       %d\033[0m\n", testsPassed)
				if testsFailed > 0 {
					fmt.Printf("\033[31m✗ Failed:       %d\033[0m\n", testsFailed)
				}
				
				if testsFailed == 0 {
					fmt.Printf("\n\033[32m🎉 All tests passed!\033[0m\n")
				} else {
					fmt.Printf("\n\033[31m❌ Some tests failed.\033[0m\n")
				}
				
				// Return results as a map
				result := vm.NewMap()
				result.Items["total"] = float64(total)
				result.Items["passed"] = float64(testsPassed)
				result.Items["failed"] = float64(testsFailed)
				result.Items["success"] = testsFailed == 0
				
				return result, nil
			},
		},
	}
}