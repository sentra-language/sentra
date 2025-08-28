# Sentra Examples

This directory contains example programs and test cases demonstrating various features of the Sentra programming language.

## Directory Structure

### Core Examples (`*.sn`)
- **hello.sn** - Basic "Hello World" program
- **math.sn** - Mathematical operations and functions
- **arrays_and_maps.sn** - Working with collections
- **control_flow.sn** - If statements, loops, and conditionals
- **advanced_functions.sn** - Closures, higher-order functions
- **algorithms.sn** - Common algorithms implementation
- **error_handling.sn** - Try-catch exception handling
- **concurrency_showcase.sn** - Concurrent programming examples

### Security Examples
- **security_hash.sn** - Cryptographic hashing
- **threat_detection.sn** - Basic threat detection patterns
- **network_scanner.sn** - Network scanning utilities
- **os_security.sn** - Operating system security functions

### Standard Library Examples
- **stdlib_demo.sn** - Standard library function showcase
- **stdlib_simple.sn** - Basic stdlib usage

### Import System (`imports/`)
Examples demonstrating the module import/export system:
- **test_simple_import.sn** - Basic import functionality
- **test_export_import.sn** - Export and import between modules
- **test_complex_import_*.sn** - Complex nested imports

### Module System (`modules/`)
Examples of module creation and usage:
- **test_module_bugs.sn** - Documents known VM bugs and workarounds
- **test_simple_module.sn** - Simple module example

### Debugging (`debugging/`)
Debug utilities and test cases:
- **debug_*.sn** - Various debugging scenarios

## Running Examples

To run any example:
```bash
./sentra run examples/hello.sn
```

## VM Bugs and Workarounds

The examples include documentation of known VM bugs:

1. **Negation Operator Bug**: `!function()` fails in modules
   - Workaround: Use `!(function())` with parentheses

2. **For-in Loop Bug**: Loop variables become `nil` in modules
   - Workaround: Use `while` loops instead of `for-in`

See `modules/test_module_bugs.sn` for detailed documentation.