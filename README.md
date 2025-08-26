# Sentra Programming Language

A high-performance, modern programming language with a stack-based virtual machine, built from scratch in Go.

## Features

### 🚀 Performance
- **Optimized VM**: Stack-based architecture with pre-allocated memory
- **Fast execution**: 14-40 microseconds per operation
- **Constant caching**: Pre-converted constants for faster access
- **Thread-safe collections**: Concurrent-safe arrays and maps
- **Memory efficient**: ~26KB per operation with minimal allocations

### 💻 Language Features
- **Dynamic typing** with runtime type checking
- **First-class functions** with closures and lambdas
- **Arrays and Maps** with built-in operations
- **Pattern matching** for elegant control flow
- **Module system** with import/export
- **Error handling** with try-catch-finally
- **Iterators** for collections
- **String interpolation** and manipulation
- **Logical operators** (&&, ||, !)

### 📚 Standard Library
70+ built-in functions across multiple modules:
- **Math**: Trigonometry, random numbers, mathematical constants
- **String**: Manipulation, splitting, joining, pattern matching
- **Array**: Sorting, filtering, mapping, reduction
- **IO**: File operations, directory management
- **JSON**: Encoding and decoding
- **HTTP**: Web requests
- **Time**: Date/time operations
- **Regex**: Pattern matching

## Installation

```bash
# Clone the repository
git clone https://github.com/sentra-language/sentra.git
cd sentra

# Build the interpreter
make sentra

# Run the REPL
./sentra repl

# Run a program
./sentra run program.sn
```

## Quick Start

### Hello World
```sentra
log("Hello, World!")
```

### Variables and Functions
```sentra
// Variables
let name = "Sentra"
let version = 1.0

// Functions
fn greet(name) {
    return "Hello, " + name + "!"
}

log(greet("World"))

// Arrow functions
let square = fn(x) => x * x
log(square(5))  // 25
```

### Arrays and Maps
```sentra
// Arrays
let numbers = [1, 2, 3, 4, 5]
let doubled = numbers.map(fn(x) => x * 2)

// Maps
let person = {
    "name": "Alice",
    "age": 30,
    "city": "New York"
}

log(person["name"])  // Alice
```

### Control Flow
```sentra
// If-else
if age >= 18 {
    log("Adult")
} else {
    log("Minor")
}

// Loops
for i in [1, 2, 3] {
    log(i)
}

while count < 10 {
    count = count + 1
}

// Pattern matching
match value {
    1 => log("One"),
    2 => log("Two"),
    _ => log("Other")
}
```

### Error Handling
```sentra
try {
    let result = riskyOperation()
    log(result)
} catch error {
    log("Error: " + error)
} finally {
    cleanup()
}
```

### Modules
```sentra
// Import built-in modules
import math
import string
import json

// Import with alias
import "http" as web

// Use module functions
let sqrt = math.sqrt(16)
let upper = string.upper("hello")
let data = json.encode({"key": "value"})
```

## Language Reference

### Data Types
- **Numbers**: `42`, `3.14`
- **Strings**: `"Hello"`, `'World'`
- **Booleans**: `true`, `false`
- **Null**: `null`
- **Arrays**: `[1, 2, 3]`
- **Maps**: `{"key": "value"}`
- **Functions**: `fn(x) => x * 2`

### Operators
- **Arithmetic**: `+`, `-`, `*`, `/`, `%`
- **Comparison**: `==`, `!=`, `<`, `>`, `<=`, `>=`
- **Logical**: `&&`, `||`, `!`
- **Assignment**: `=`

### Keywords
- `let`, `var`, `const` - Variable declarations
- `fn` - Function declaration
- `if`, `else` - Conditional statements
- `while`, `for` - Loops
- `match` - Pattern matching
- `try`, `catch`, `finally`, `throw` - Error handling
- `import`, `export` - Module system
- `return` - Function return
- `true`, `false`, `null` - Literals

## Built-in Modules

### Math Module
```sentra
import math

math.PI           // 3.14159...
math.E            // 2.71828...
math.abs(-5)      // 5
math.sqrt(16)     // 4
math.pow(2, 8)    // 256
math.sin(math.PI) // 0
math.random()     // Random [0, 1)
```

### String Module
```sentra
import string

string.upper("hello")        // "HELLO"
string.lower("WORLD")        // "world"
string.split("a,b,c", ",")   // ["a", "b", "c"]
string.join(["a", "b"], "-") // "a-b"
string.contains("hello", "ll") // true
```

### Array Module
```sentra
import array

array.push(arr, item)
array.pop(arr)
array.sort(arr)
array.reverse(arr)
array.map(arr, fn)
array.filter(arr, fn)
```

### IO Module
```sentra
import io

io.readfile("file.txt")
io.writefile("file.txt", content)
io.exists("file.txt")
io.listdir(".")
io.mkdir("newdir")
```

### JSON Module
```sentra
import json

let obj = {"name": "John", "age": 30}
let str = json.encode(obj)
let parsed = json.decode(str)
```

## Performance Benchmarks

| Operation | Time | Memory | Allocations |
|-----------|------|--------|-------------|
| Arithmetic | ~37μs | 26KB | 13 |
| Array Creation | ~14μs | 26KB | 13 |
| Map Operations | ~41μs | 26KB | 22 |

## Architecture

Sentra uses a four-stage compilation pipeline:

1. **Lexer**: Tokenizes source code
2. **Parser**: Generates Abstract Syntax Tree (AST)
3. **Compiler**: Transforms AST to bytecode
4. **VM**: Executes bytecode on stack-based virtual machine

### VM Features
- Stack-based architecture
- 70+ opcodes for all operations
- Call frames for function invocation
- Global and local variable scoping
- Closure support with upvalues
- Thread-safe operations

## Examples

See the `examples/` directory for more complex programs:
- `arrays_and_maps.sn` - Collection operations
- `advanced_functions.sn` - Closures and higher-order functions
- `control_flow.sn` - Conditionals and loops
- `modules_example.sn` - Module system usage
- `error_handling.sn` - Exception handling
- `algorithms.sn` - Classic algorithms

## Development

### Building from Source
```bash
make sentra
```

### Running Tests
```bash
make test
go test ./internal/vm -v
```

### Benchmarking
```bash
go test ./internal/vm -bench=. -benchmem
```

## Contributing

Contributions are welcome! Please feel free to submit pull requests.

## License

MIT License - See LICENSE file for details

## Acknowledgments

Built with Go 1.25.0, inspired by modern language design principles and optimized for performance.