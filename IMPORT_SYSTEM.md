# Sentra Import System Documentation

## Overview

Sentra supports modular programming through its import system, allowing you to organize code across multiple files and reuse functionality.

## Current Implementation Status

### Working Features

1. **Module Objects**: Create modules as objects with exported functions
```sentra
let MyModule = {
    "function1": fn(param) { ... },
    "function2": fn(param) { ... }
}
```

2. **Built-in Module Imports**: Import standard library modules
```sentra
import math
import string
import array
```

3. **Module Aliases**: Import modules with custom names
```sentra
import "http" as web
```

### In Development

File-based imports are being implemented. The syntax will support:

```sentra
// Import entire module
import "./path/to/module.sn" as ModuleName

// Import specific functions (planned)
import { function1, function2 } from "./path/to/module.sn"

// Export functions from modules (planned)
export fn myFunction() { ... }
export let myVariable = value
```

## Working Example: Multi-Module Application

The `example-project-simple` demonstrates a working modular structure using module objects:

```sentra
// Task Module
let Task = {
    "create": fn(title, priority) {
        return {
            "id": generate_id(),
            "title": title,
            "priority": priority,
            "status": "pending"
        }
    }
}

// Logger Module  
let Logger = {
    "info": fn(msg) { log("[INFO] " + msg) },
    "error": fn(msg) { log("[ERROR] " + msg) }
}

// Using modules
let task = Task.create("New Task", "High")
Logger.info("Created: " + task["title"])
```

## Project Structure Best Practices

```
project/
├── main.sn              # Entry point
├── sentra.toml         # Project configuration
├── src/
│   ├── app.sn         # Application logic
│   ├── controllers/   # Business logic
│   ├── models/        # Data structures
│   ├── services/      # External services
│   └── utils/         # Utilities
├── tests/             # Test files
└── lib/               # Shared libraries
```

## Module Patterns

### 1. Object Module Pattern (Currently Working)
```sentra
let Module = {
    "publicFunction": fn(x) { ... },
    "anotherFunction": fn(y) { ... },
    "constant": "value"
}
```

### 2. Namespace Pattern
```sentra
let MyNamespace = {
    "SubModule1": { ... },
    "SubModule2": { ... }
}
```

### 3. Factory Pattern
```sentra
let Factory = {
    "create": fn(type) {
        if type == "A" {
            return { "type": "A", "method": fn() {...} }
        } else if type == "B" {
            return { "type": "B", "method": fn() {...} }
        }
    }
}
```

## Import Resolution Order

When imports are fully implemented, Sentra will resolve in this order:

1. **Relative paths** (`./module.sn`, `../lib/module.sn`)
2. **Project root paths** (from project root directory)
3. **Standard library** (built-in modules like `math`, `string`)
4. **External packages** (from `sentra.mod` dependencies)

## Standard Library Modules

Available built-in modules:

- `math` - Mathematical functions
- `string` - String manipulation
- `array` - Array operations
- `io` - Input/output operations
- `json` - JSON parsing/serialization
- `time` - Time and date functions
- `http` - HTTP client/server
- `crypto` - Cryptographic functions
- `system` - System operations
- `database` - Database connectivity

## Future Import Features

### Export Syntax (Planned)
```sentra
// Export individual items
export fn processData(data) { ... }
export let VERSION = "1.0.0"
export const CONFIG = { ... }

// Export multiple items
export { function1, function2, constant1 }

// Export with renaming
export { internalName as publicName }
```

### Import Syntax (Planned)
```sentra
// Named imports
import { func1, func2 } from "./module.sn"

// Import all
import * as Module from "./module.sn"

// Combined
import DefaultExport, { named1, named2 } from "./module.sn"
```

## Working Example: Task Management System

See `example-project-simple/main.sn` for a complete working example that demonstrates:

- Module organization using objects
- Separation of concerns
- Module interdependencies
- Application structure

To run:
```bash
sentra run example-project-simple/main.sn
```

## Recommendations

1. **Use Module Objects**: Until file imports are complete, use module objects
2. **Organize by Feature**: Group related functionality
3. **Clear Naming**: Use descriptive module and function names
4. **Document Exports**: Comment what each module exports
5. **Avoid Circular Dependencies**: Plan module dependencies carefully

## Migration Path

When file imports are implemented, migration will be simple:

**Current (Module Objects):**
```sentra
let MyModule = {
    "func": fn() { ... }
}
MyModule.func()
```

**Future (File Imports):**
```sentra
// In mymodule.sn
export fn func() { ... }

// In main.sn
import "./mymodule.sn" as MyModule
MyModule.func()
```

## Testing Modules

Test individual modules by creating test files:

```sentra
// test_module.sn
// Import or define module
let Module = { ... }

// Test functions
fn test_function1() {
    assert(Module.function1(input) == expected)
}

// Run tests
test_function1()
log("All tests passed!")
```