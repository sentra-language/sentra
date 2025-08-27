---
layout: default
title: Language Reference
parent: Reference
nav_order: 1
---

# Sentra Language Reference
{: .fs-9 }

Complete reference for Sentra's syntax, operators, control structures, and language features.
{: .fs-6 .fw-300 }

---

## Table of Contents
1. [Introduction](#introduction)
2. [Basic Syntax](#basic-syntax)
3. [Data Types](#data-types)
4. [Variables](#variables)
5. [Operators](#operators)
6. [Control Flow](#control-flow)
7. [Functions](#functions)
8. [Collections](#collections)
9. [Error Handling](#error-handling)
10. [Modules](#modules)
11. [Concurrency](#concurrency)
12. [Standard Library](#standard-library)

## Introduction

Sentra is a security-focused programming language with a stack-based virtual machine. It combines simplicity with powerful security capabilities, making it ideal for security automation, compliance checking, and defensive security tools.

### Design Principles
- **Security-First**: Built-in security functions and modules
- **Simple Syntax**: Easy to learn and write
- **Memory Safe**: Automatic memory management
- **Fast Execution**: Optimized VM with JIT-ready architecture

## Basic Syntax

### Comments
```sentra
// Single-line comment

/* 
   Multi-line comment
   Can span multiple lines
*/
```

### Program Structure
```sentra
// Variable declarations
let name = "Sentra"
var count = 0
const PI = 3.14159

// Function definition
fn greet(name) {
    return "Hello, " + name
}

// Main program logic
log(greet(name))
```

## Data Types

### Primitive Types

#### Numbers
```sentra
let integer = 42
let float = 3.14159
let negative = -17
let scientific = 1.5e10

// Arithmetic operations
let sum = 10 + 20       // 30
let diff = 100 - 45     // 55
let product = 6 * 7     // 42
let quotient = 100 / 4  // 25
let remainder = 17 % 5  // 2
```

#### Strings
```sentra
let single = "Hello"
let double = "World"
let concat = single + " " + double  // "Hello World"

// String operations
let length = len("Hello")           // 5
let upper = upper("hello")          // "HELLO"
let lower = lower("HELLO")          // "hello"
let trimmed = trim("  space  ")     // "space"
```

#### Booleans
```sentra
let isTrue = true
let isFalse = false

// Boolean operations
let and = true && false    // false
let or = true || false     // true
let not = !true            // false
```

#### Nil
```sentra
let nothing = nil

// Checking for nil
if nothing == nil {
    log("Value is nil")
}
```

### Type Checking
```sentra
let num = 42
log(type(num))        // "number"
log(type("hello"))    // "string"
log(type(true))       // "boolean"
log(type([]))         // "array"
log(type({}))         // "map"
```

## Variables

### Variable Declaration

#### let (Block-scoped)
```sentra
let x = 10
{
    let x = 20  // New variable in this scope
    log(x)      // 20
}
log(x)          // 10
```

#### var (Function-scoped)
```sentra
var y = 10
{
    var y = 20  // Same variable
    log(y)      // 20
}
log(y)          // 20
```

#### const (Constants)
```sentra
const MAX_SIZE = 100
// MAX_SIZE = 200  // Error: Cannot reassign constant
```

### Variable Assignment
```sentra
let x = 10
x = 20              // Reassignment
x = x + 5          // Compound operation
```

## Operators

### Arithmetic Operators
```sentra
let a = 10
let b = 3

log(a + b)    // 13 - Addition
log(a - b)    // 7  - Subtraction
log(a * b)    // 30 - Multiplication
log(a / b)    // 3.33... - Division
log(a % b)    // 1  - Modulo
```

### Comparison Operators
```sentra
let x = 10
let y = 20

log(x == y)   // false - Equal
log(x != y)   // true  - Not equal
log(x < y)    // true  - Less than
log(x > y)    // false - Greater than
log(x <= y)   // true  - Less than or equal
log(x >= y)   // false - Greater than or equal
```

### Logical Operators
```sentra
let a = true
let b = false

log(a && b)   // false - Logical AND
log(a || b)   // true  - Logical OR
log(!a)       // false - Logical NOT
```

### String Concatenation
```sentra
let greeting = "Hello" + " " + "World"  // "Hello World"
let name = "User"
let message = "Welcome, " + name        // "Welcome, User"
```

## Control Flow

### If-Else Statements
```sentra
let age = 18

if age >= 18 {
    log("Adult")
} else if age >= 13 {
    log("Teenager")
} else {
    log("Child")
}
```

### Match Statements
```sentra
let day = "Monday"

match day {
    "Monday", "Tuesday", "Wednesday", "Thursday", "Friday" => {
        log("Weekday")
    }
    "Saturday", "Sunday" => {
        log("Weekend")
    }
    _ => {
        log("Invalid day")
    }
}
```

### While Loops
```sentra
let i = 0
while i < 5 {
    log(i)
    i = i + 1
}
```

### For Loops
```sentra
// Traditional for loop
for (let i = 0; i < 5; i = i + 1) {
    log(i)
}

// Without initialization
let j = 0
for (; j < 5; j = j + 1) {
    log(j)
}

// Infinite loop with break
for (;;) {
    if condition {
        break
    }
}
```

### For-In Loops
```sentra
// Array iteration
let fruits = ["apple", "banana", "orange"]
for fruit in fruits {
    log(fruit)
}

// Map iteration
let prices = {"apple": 1.5, "banana": 0.75}
for key in prices {
    log(key + ": $" + prices[key])
}
```

### Break and Continue
```sentra
// Break example
for (let i = 0; i < 10; i = i + 1) {
    if i == 5 {
        break  // Exit loop
    }
    log(i)
}

// Continue example
for (let i = 0; i < 10; i = i + 1) {
    if i % 2 == 0 {
        continue  // Skip even numbers
    }
    log(i)
}
```

## Functions

### Function Declaration
```sentra
// Basic function
fn greet(name) {
    return "Hello, " + name
}

// Function with multiple parameters
fn add(a, b) {
    return a + b
}

// Function without return
fn printMessage(msg) {
    log(msg)
}
```

### Function Calls
```sentra
let result = add(5, 3)        // 8
let greeting = greet("Alice") // "Hello, Alice"
printMessage("Debug info")    // Prints to console
```

### Anonymous Functions (Lambdas)
```sentra
// Lambda syntax
let square = fn(x) { return x * x }
log(square(5))  // 25

// Passing functions as arguments
fn map(arr, func) {
    let result = []
    for item in arr {
        push(result, func(item))
    }
    return result
}

let numbers = [1, 2, 3, 4, 5]
let squared = map(numbers, fn(x) { return x * x })
log(squared)  // [1, 4, 9, 16, 25]
```

### Closures
```sentra
fn makeCounter() {
    let count = 0
    return fn() {
        count = count + 1
        return count
    }
}

let counter = makeCounter()
log(counter())  // 1
log(counter())  // 2
log(counter())  // 3
```

### Higher-Order Functions
```sentra
// Function returning function
fn createMultiplier(factor) {
    return fn(x) {
        return x * factor
    }
}

let double = createMultiplier(2)
let triple = createMultiplier(3)

log(double(5))   // 10
log(triple(5))   // 15

// Function accepting function
fn filter(arr, predicate) {
    let result = []
    for item in arr {
        if predicate(item) {
            push(result, item)
        }
    }
    return result
}

let numbers = [1, 2, 3, 4, 5, 6]
let evens = filter(numbers, fn(x) { return x % 2 == 0 })
log(evens)  // [2, 4, 6]
```

## Collections

### Arrays
```sentra
// Array creation
let empty = []
let numbers = [1, 2, 3, 4, 5]
let mixed = [1, "hello", true, nil]

// Array operations
push(numbers, 6)           // Add to end
let first = numbers[0]     // Access by index
numbers[0] = 10           // Modify element
let length = len(numbers)  // Get length

// Array methods
let popped = pop(numbers)  // Remove and return last element
let shifted = shift(numbers) // Remove and return first element
unshift(numbers, 0)        // Add to beginning

// Array iteration
for num in numbers {
    log(num)
}

// Array slicing (if supported)
let slice = numbers[1:3]   // Elements from index 1 to 2
```

### Maps (Objects/Dictionaries)
```sentra
// Map creation
let empty = {}
let person = {
    "name": "Alice",
    "age": 30,
    "city": "New York"
}

// Map operations
person["email"] = "alice@example.com"  // Add property
let name = person["name"]              // Access property
delete(person, "city")                 // Remove property
let hasAge = has(person, "age")       // Check if key exists

// Map iteration
for key in person {
    log(key + ": " + person[key])
}

// Nested maps
let company = {
    "name": "TechCorp",
    "employees": [
        {"name": "Alice", "role": "Developer"},
        {"name": "Bob", "role": "Designer"}
    ],
    "founded": 2020
}
```

## Error Handling

### Try-Catch-Finally
```sentra
try {
    // Code that might throw an error
    let result = riskyOperation()
    log(result)
} catch (error) {
    // Handle the error
    log("Error caught: " + error)
} finally {
    // Always executed
    log("Cleanup code")
}
```

### Throwing Errors
```sentra
fn divide(a, b) {
    if b == 0 {
        throw "Division by zero error"
    }
    return a / b
}

try {
    let result = divide(10, 0)
} catch (e) {
    log("Error: " + e)
}
```

### Error Propagation
```sentra
fn validateAge(age) {
    if age < 0 {
        throw "Age cannot be negative"
    }
    if age > 150 {
        throw "Age seems unrealistic"
    }
    return true
}

fn processUser(userData) {
    try {
        validateAge(userData["age"])
        // Process user
    } catch (e) {
        log("Validation failed: " + e)
        throw e  // Re-throw to propagate
    }
}
```

## Modules

### Creating Modules
```sentra
// math_utils.sn
export fn factorial(n) {
    if n <= 1 {
        return 1
    }
    return n * factorial(n - 1)
}

export fn fibonacci(n) {
    if n <= 1 {
        return n
    }
    return fibonacci(n - 1) + fibonacci(n - 2)
}

export const PI = 3.14159
```

### Importing Modules
```sentra
// Import entire module
import "math_utils"

let fact5 = math_utils.factorial(5)
log(fact5)  // 120

// Import specific functions
import { factorial, PI } from "math_utils"

log(factorial(6))  // 720
log(PI)           // 3.14159

// Import with alias
import { factorial as fact } from "math_utils"
log(fact(7))      // 5040
```

### Module Resolution
```sentra
// Relative imports
import "./utils/helpers"      // Same directory
import "../lib/common"        // Parent directory

// Absolute imports (from module root)
import "std/math"             // Standard library
import "security/scanner"     // Built-in security module
```

## Concurrency

### Goroutines (Async Functions)
```sentra
// Launch async task
go fn() {
    // Async work
    for (let i = 0; i < 10; i = i + 1) {
        log("Async: " + i)
        sleep(100)  // Sleep 100ms
    }
}()

// Continue with main program
log("Main program continues...")
```

### Channels
```sentra
// Create channel
let ch = make_channel()

// Send data (in goroutine)
go fn() {
    ch <- "Hello from goroutine"
}()

// Receive data
let msg = <-ch
log(msg)  // "Hello from goroutine"

// Buffered channel
let buf_ch = make_channel(5)  // Buffer size 5
```

### Channel Select
```sentra
let ch1 = make_channel()
let ch2 = make_channel()

go fn() { ch1 <- "one" }()
go fn() { ch2 <- "two" }()

select {
    case msg1 = <-ch1:
        log("Received: " + msg1)
    case msg2 = <-ch2:
        log("Received: " + msg2)
    default:
        log("No messages ready")
}
```

## Standard Library

### Core Functions

#### I/O Functions
```sentra
log("Hello, World!")           // Print to console
let input = readline()          // Read user input
print("No newline")            // Print without newline
```

#### Type Conversion
```sentra
let numStr = str(42)           // Number to string: "42"
let strNum = int("42")         // String to integer: 42
let strFloat = float("3.14")   // String to float: 3.14
```

#### String Functions
```sentra
len("hello")                   // 5
upper("hello")                 // "HELLO"
lower("HELLO")                 // "hello"
trim("  space  ")              // "space"
split("a,b,c", ",")           // ["a", "b", "c"]
join(["a", "b", "c"], "-")    // "a-b-c"
substring("hello", 1, 3)       // "el"
indexOf("hello", "ll")         // 2
replace("hello", "ll", "xx")   // "hexxo"
```

#### Array Functions
```sentra
let arr = [3, 1, 4, 1, 5]
len(arr)                       // 5
push(arr, 9)                   // Add to end
pop(arr)                       // Remove from end
shift(arr)                     // Remove from beginning
unshift(arr, 2)                // Add to beginning
sort(arr)                      // Sort in place
reverse(arr)                   // Reverse in place
slice(arr, 1, 3)              // Sub-array
concat(arr1, arr2)            // Combine arrays
```

#### Map Functions
```sentra
let map = {"a": 1, "b": 2}
keys(map)                      // ["a", "b"]
values(map)                    // [1, 2]
has(map, "a")                  // true
delete(map, "b")              // Remove key
merge(map1, map2)             // Combine maps
```

#### Math Functions
```sentra
abs(-5)                        // 5
min(3, 7)                      // 3
max(3, 7)                      // 7
floor(3.7)                     // 3
ceil(3.2)                      // 4
round(3.5)                     // 4
sqrt(16)                       // 4
pow(2, 8)                      // 256
random()                       // Random 0-1
randomInt(1, 10)              // Random integer 1-10
```

#### Time Functions
```sentra
time()                         // Current timestamp (ms)
sleep(1000)                    // Sleep for 1000ms
now()                          // Current date/time string
parseTime("2024-01-01")       // Parse time string
formatTime(timestamp, format)  // Format timestamp
```

### Security Functions
See [Security Module Documentation](SECURITY_MODULES.md) for comprehensive security function reference.

## Best Practices

### Code Style
```sentra
// Use descriptive variable names
let userAge = 25  // Good
let a = 25        // Bad

// Use consistent indentation
fn processData(data) {
    if data != nil {
        for item in data {
            processItem(item)
        }
    }
}

// Comment complex logic
// Calculate compound interest using formula: A = P(1 + r/n)^(nt)
let amount = principal * pow(1 + rate/n, n * time)
```

### Error Handling
```sentra
// Always handle potential errors
fn safeDiv(a, b) {
    if b == 0 {
        return nil
    }
    return a / b
}

// Use try-catch for risky operations
try {
    let data = parseJSON(jsonString)
    processData(data)
} catch (e) {
    log("Failed to parse JSON: " + e)
}
```

### Performance Tips
```sentra
// Cache array length in loops
let len = len(bigArray)
for (let i = 0; i < len; i = i + 1) {
    // Process array[i]
}

// Use appropriate data structures
// Maps for lookups, arrays for ordered data
let lookup = {}  // O(1) access
let ordered = [] // O(n) search

// Avoid deep nesting
// Refactor into functions
fn processItem(item) {
    // Logic here
}

for item in items {
    processItem(item)
}
```

## Advanced Topics

### Reflection
```sentra
let obj = {"name": "Alice", "age": 30}

// Type checking
log(type(obj))              // "map"

// Dynamic property access
let prop = "name"
log(obj[prop])              // "Alice"

// Check if function
let f = greet
if type(f) == "function" {
    f("World")
}
```

### Meta-programming
```sentra
// Dynamic function creation
fn createGetter(property) {
    return fn(obj) {
        return obj[property]
    }
}

let getName = createGetter("name")
let person = {"name": "Bob", "age": 25}
log(getName(person))  // "Bob"
```

### Memory Management
```sentra
// Sentra uses automatic memory management
// No manual allocation/deallocation needed

// Help the garbage collector
let bigData = loadData()
processData(bigData)
bigData = nil  // Clear reference when done
```

## Language Limitations

Current limitations of Sentra:
1. No class-based OOP (use functions and maps)
2. No native regex support (use string functions)
3. No multi-line strings (concatenate lines)
4. Limited file I/O (security focused)
5. Stack limit of ~50k iterations per loop

## Examples

### Complete Program Example
```sentra
// Simple web server route handler simulation
fn handleRequest(request) {
    let method = request["method"]
    let path = request["path"]
    
    match path {
        "/" => {
            return {"status": 200, "body": "Welcome!"}
        }
        "/api/users" => {
            if method == "GET" {
                return {"status": 200, "body": getUsers()}
            } else if method == "POST" {
                return {"status": 201, "body": createUser(request["body"])}
            }
        }
        _ => {
            return {"status": 404, "body": "Not Found"}
        }
    }
}

fn getUsers() {
    return [
        {"id": 1, "name": "Alice"},
        {"id": 2, "name": "Bob"}
    ]
}

fn createUser(data) {
    // Validate and create user
    if !data["name"] {
        throw "Name is required"
    }
    return {"id": 3, "name": data["name"]}
}

// Test the handler
let request = {
    "method": "GET",
    "path": "/api/users",
    "body": {}
}

try {
    let response = handleRequest(request)
    log("Status: " + response["status"])
    log("Body: " + str(response["body"]))
} catch (e) {
    log("Error: " + e)
}
```

## Conclusion

Sentra provides a simple yet powerful programming environment optimized for security tasks. Its built-in security modules, clean syntax, and robust standard library make it an excellent choice for security automation, compliance checking, and defensive security tools.

---

{: .fs-6 .fw-300 }
For detailed information about built-in functions and modules, check out the Standard Library reference.

[← Back to Reference](../){: .btn .btn-outline .mr-2 }
[Standard Library Reference →](../stdlib/){: .btn .btn-primary }

---

## Related Documentation

- [Tutorial: Language Basics](../../tutorial/language-basics/) - Learn with examples
- [Standard Library Reference](../stdlib/) - All built-in functions  
- [Quick Reference](../quick/) - Cheat sheet for common operations
- [Examples on GitHub](https://github.com/sentra-language/sentra/tree/main/examples) - Real-world code