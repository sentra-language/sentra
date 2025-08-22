<div style="border-left: 4px solid #0366d6; padding: 1em; background: #f1f8ff;">
<h1 style="margin-top: 0; color: #0366d6;">Sentra Programming Language 🚀</h1>
<strong style="color: #005cc5; font-size: 1.2em;">Code with Confidence!</strong>
<p style="margin: 1em 0; color: #24292e;">A blazing-fast, security-focused programming language with a powerful CLI, built from scratch in Go.</p>
<blockquote style="border-left: 3px solid #0366d6; padding-left: 1em; margin: 1em 0; color: #586069; font-style: italic;">
Sentra combines the simplicity of Python, the performance of Go, and security features built right into the core. Perfect for security automation, system scripting, and rapid application development.
</blockquote>
</div>

## 🎯 Quick Start

# 1. Clone and build Sentra
```bash
git clone https://github.com/sentra-language/sentra.git
```


```bash
cd sentra  && ./install.sh
```

<div style="border-left: 4px solid #f39c12; padding: 0.5em; background: #fff8e1;">
<strong>NOTE:</strong> To build new <code>sentra</code> binary run:
<pre>go build -o sentra ./cmd/sentra</pre>
</div>

# 2. Create your first project
```bash
sentra init my-awesome-app
```

```bash
cd my-awesome-app
```

# 3. Run your app

```bash
sentra run main.sn
```

# 4. Run tests

```bash
sentra test
```


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
- **Security**: Cryptography, hashing, threat detection
- **Network**: Port scanning, network analysis
- **Database**: SQL operations
- **SIEM**: Security event management
- **ML**: Machine learning for security

## 🛠️ Sentra CLI - Your Development Companion

The Sentra CLI is your primary interface for developing, testing, and deploying Sentra applications. It's designed to make your development workflow smooth and enjoyable.

## 📚 Language Guide

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

## 🎓 Real-World Examples

### Security Scanner
```sentra
// security_scanner.sn
import network
import security

fn scan_target(host) {
    log("🔍 Scanning " + host)
    
    // Port scanning
    let ports = network.scan_ports(host, [80, 443, 22, 3306])
    
    // Vulnerability detection
    for port in ports {
        if port.open {
            let vulns = security.check_vulnerabilities(host, port.number)
            if len(vulns) > 0 {
                log("⚠️ Found vulnerabilities on port " + port.number)
            }
        }
    }
}

scan_target("example.com")
```

### API Server
```sentra
// api_server.sn
import http
import json

let server = http.create_server(8080)

server.get("/api/users", fn(req, res) {
    let users = [
        {"id": 1, "name": "Alice"},
        {"id": 2, "name": "Bob"}
    ]
    res.json(users)
})

server.post("/api/users", fn(req, res) {
    let user = json.decode(req.body)
    // Save user
    res.status(201).json({"message": "User created", "user": user})
})

log("🚀 Server running on http://localhost:8080")
server.listen()
```

### Data Processing Pipeline
```sentra
// pipeline.sn
import io
import json
import array

// Read and process large dataset
let data = io.readfile("data.json")
let records = json.decode(data)

// Transform pipeline
let processed = records
    |> array.filter(fn(r) => r.active)
    |> array.map(fn(r) => {
        r.processed_at = time.now()
        return r
    })
    |> array.sort_by(fn(r) => r.priority)

// Save results
io.writefile("processed.json", json.encode(processed))
log("✅ Processed " + len(processed) + " records")
```

### Concurrent Task Runner
```sentra
// concurrent.sn
import async

fn fetch_data(urls) {
    let tasks = []
    
    for url in urls {
        tasks.push(async.spawn(fn() {
            let response = http.get(url)
            return {"url": url, "status": response.status}
        }))
    }
    
    let results = async.await_all(tasks)
    return results
}

let urls = [
    "https://api1.example.com",
    "https://api2.example.com",
    "https://api3.example.com"
]

let results = fetch_data(urls)
log("Fetched " + len(results) + " APIs concurrently")
```

### Contributing

We love contributions! Here's how to get started:

1. **Fork & Clone**: Fork the repo and clone locally
2. **Branch**: Create a feature branch (`git checkout -b feature/amazing`)
3. **Code**: Make your changes
4. **Test**: Add tests and ensure all pass
5. **Commit**: Commit with clear message
6. **Push**: Push to your fork
7. **PR**: Open a Pull Request

For Language Developers:

  # 1. Check status
  ./dev.sh status

  # 2. Enable development mode
  ./dev.sh enable

  # 3. Build your changes
  ./dev.sh build

  # 4. Install globally (points to your local version)
  ./dev.sh install

  # 5. Test everything works
  ./dev.sh test

  # When done developing, switch back:
  ./dev.sh disable


---

**Ready to code with confidence?** Get started with `sentra init my-app` today! 🚀