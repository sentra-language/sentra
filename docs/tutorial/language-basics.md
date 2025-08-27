---
layout: default
title: Language Basics
parent: Tutorial
nav_order: 3
---

# Data Types and Variables

Sentra is a dynamically typed language with several built-in data types. Let's explore each one in detail.

## Variable Declaration

### Variable Keywords
```sentra
let mutable_var = "I can change"       // Mutable variable
const CONSTANT = "I never change"      // Immutable constant
var legacy_var = "Old style"           // Legacy (avoid)
```

### Naming Rules
```sentra
// Valid names
let userName = "john"
let user_name = "jane"  
let userAge2 = 25
let _private = "hidden"

// Invalid names (will cause errors)
// let 2user = "invalid"     // Cannot start with number
// let user-name = "invalid" // Cannot contain hyphens
// let let = "invalid"       // Cannot use keywords
```

## Numbers

Sentra treats all numbers as floating-point internally but displays integers without decimals.

```sentra
// Integer-like numbers
let age = 25
let score = 100
let negative = -42

// Decimal numbers
let pi = 3.14159
let price = 19.99
let temperature = -5.5

// Scientific notation
let big_number = 1.23e6      // 1,230,000
let small_number = 4.56e-3   // 0.00456

log("Age: " + str(age))               // Age: 25
log("Pi: " + str(pi))                 // Pi: 3.14159
log("Big number: " + str(big_number)) // Big number: 1230000
```

### Number Operations
```sentra
let a = 10
let b = 3

log("Addition: " + str(a + b))        // 13
log("Subtraction: " + str(a - b))     // 7
log("Multiplication: " + str(a * b))  // 30
log("Division: " + str(a / b))        // 3.333...
log("Modulo: " + str(a % b))          // 1

// Comparison
log("Equal: " + str(a == b))          // false
log("Not equal: " + str(a != b))      // true
log("Greater: " + str(a > b))         // true
log("Less or equal: " + str(a <= b))  // false
```

### Math Functions
```sentra
let x = 16
let y = 3.7

log("Absolute: " + str(abs(-5)))      // 5
log("Square root: " + str(sqrt(x)))   // 4
log("Power: " + str(pow(2, 3)))       // 8
log("Floor: " + str(floor(y)))        // 3
log("Ceiling: " + str(ceil(y)))       // 4
log("Round: " + str(round(y)))        // 4
log("Min: " + str(min(10, 5)))        // 5
log("Max: " + str(max(10, 5)))        // 10
log("Random: " + str(random()))       // 0-1 random number
```

## Strings

Strings are sequences of characters enclosed in double quotes.

```sentra
let name = "Alice"
let message = "Hello, World!"
let empty = ""
let multiline = "Line 1\nLine 2\nLine 3"

// Escape sequences
let escaped = "She said \"Hello!\" to me"
let path = "C:\\Users\\Alice\\Documents"
let special = "Tab:\t Newline:\n Backslash:\\"

log(message)        // Hello, World!
log(multiline)      // Prints on multiple lines
log(escaped)        // She said "Hello!" to me
```

### String Concatenation
```sentra
let first = "John"
let last = "Doe"
let full = first + " " + last

log("Full name: " + full)             // Full name: John Doe

// With numbers
let age = 30
let info = "I am " + str(age) + " years old"
log(info)                             // I am 30 years old
```

### String Functions
```sentra
let text = "  Hello, Sentra!  "

log("Original: '" + text + "'")
log("Length: " + str(len(text)))              // 17
log("Uppercase: " + upper(text))              // "  HELLO, SENTRA!  "
log("Lowercase: " + lower(text))              // "  hello, sentra!  "
log("Trimmed: '" + trim(text) + "'")          // "Hello, Sentra!"

// Substring operations
let sentence = "The quick brown fox"
log("Starts with 'The': " + str(starts_with(sentence, "The")))  // true
log("Ends with 'fox': " + str(ends_with(sentence, "fox")))      // true
log("Contains 'quick': " + str(contains(sentence, "quick")))     // true

// Split and join
let words = split(sentence, " ")
log("Words: " + str(words))                   // ["The", "quick", "brown", "fox"]
let rejoined = join(words, "-")
log("Rejoined: " + rejoined)                  // "The-quick-brown-fox"

// Replace
let replaced = replace(sentence, "quick", "slow")
log("Replaced: " + replaced)                  // "The slow brown fox"
```

## Booleans

Boolean values represent true or false.

```sentra
let is_sunny = true
let is_raining = false
let is_nice_weather = is_sunny && !is_raining

log("Sunny: " + str(is_sunny))               // true
log("Raining: " + str(is_raining))           // false
log("Nice weather: " + str(is_nice_weather)) // true
```

### Boolean Operations
```sentra
let a = true
let b = false

// Logical operators
log("AND: " + str(a && b))        // false
log("OR: " + str(a || b))         // true
log("NOT a: " + str(!a))          // false
log("NOT b: " + str(!b))          // true

// Comparison results are booleans
let x = 5
let y = 10
log("x < y: " + str(x < y))       // true
log("x == y: " + str(x == y))     // false
```

### Truthiness
```sentra
// These values are "falsy" (equivalent to false)
let falsy_values = [false, 0, "", null]

// These values are "truthy" (equivalent to true)
let truthy_values = [true, 1, -1, "hello", [1,2,3], {"key": "value"}]

// Using in conditions
let value = ""
if (value) {
    log("This won't print")
} else {
    log("Empty string is falsy")
}
```

## Null

Null represents the absence of a value.

```sentra
let nothing = null
let result = null

log("Nothing: " + str(nothing))      // null

// Check for null
if (result == null) {
    log("Result is null")
}

// Functions can return null
fn find_user(id) {
    if (id == 1) {
        return {"name": "Alice", "age": 30}
    }
    return null  // User not found
}

let user = find_user(999)
if (user == null) {
    log("User not found")
} else {
    log("Found user: " + user["name"])
}
```

## Arrays

Arrays are ordered collections of values.

```sentra
// Creating arrays
let numbers = [1, 2, 3, 4, 5]
let strings = ["apple", "banana", "cherry"]
let mixed = [1, "hello", true, null]
let empty = []

log("Numbers: " + str(numbers))      // [1, 2, 3, 4, 5]
log("Mixed: " + str(mixed))          // [1, "hello", true, null]
```

### Array Access and Modification
```sentra
let fruits = ["apple", "banana", "orange"]

// Access by index (0-based)
log("First fruit: " + fruits[0])     // apple
log("Last fruit: " + fruits[2])      // orange

// Modify elements
fruits[1] = "grape"
log("Modified: " + str(fruits))      // ["apple", "grape", "orange"]

// Array length
log("Length: " + str(len(fruits)))   // 3
```

### Array Functions
```sentra
let numbers = [3, 1, 4, 1, 5]

// Add elements
push(numbers, 9)                     // Add to end
unshift(numbers, 2)                  // Add to beginning
log("After adding: " + str(numbers)) // [2, 3, 1, 4, 1, 5, 9]

// Remove elements
let last = pop(numbers)              // Remove from end
let first = shift(numbers)           // Remove from beginning
log("Removed: " + str(first) + ", " + str(last)) // 2, 9
log("After removing: " + str(numbers)) // [3, 1, 4, 1, 5]

// Sorting
sort(numbers)
log("Sorted: " + str(numbers))       // [1, 1, 3, 4, 5]

// Reversing
reverse(numbers)
log("Reversed: " + str(numbers))     // [5, 4, 3, 1, 1]

// Slicing
let subset = slice(numbers, 1, 4)    // From index 1 to 3
log("Subset: " + str(subset))        // [4, 3, 1]

// Joining
let text = join(numbers, ", ")
log("Joined: " + text)               // "5, 4, 3, 1, 1"
```

### Iterating Over Arrays
```sentra
let colors = ["red", "green", "blue"]

// For-in loop
for (let color in colors) {
    log("Color: " + color)
}

// Traditional for loop
for (let i = 0; i < len(colors); i = i + 1) {
    log("Color " + str(i) + ": " + colors[i])
}
```

## Maps (Objects/Dictionaries)

Maps are collections of key-value pairs.

```sentra
// Creating maps
let person = {
    "name": "Alice",
    "age": 30,
    "city": "New York",
    "married": true
}

let empty_map = {}

log("Person: " + str(person))
```

### Map Access and Modification
```sentra
let car = {
    "brand": "Toyota",
    "model": "Camry",
    "year": 2020
}

// Access values
log("Brand: " + car["brand"])        // Toyota
log("Year: " + str(car["year"]))     // 2020

// Modify values
car["year"] = 2021
car["color"] = "blue"                // Add new key
log("Updated car: " + str(car))

// Check if key exists
if ("color" in car) {
    log("Car has color: " + car["color"])
}
```

### Iterating Over Maps
```sentra
let student = {
    "name": "Bob",
    "grade": 85,
    "subject": "Math"
}

// Iterate over keys
for (let key in student) {
    log(key + ": " + str(student[key]))
}

// Get all keys as array (if supported)
let keys = keys(student)
log("Keys: " + str(keys))
```

### Nested Data Structures
```sentra
let company = {
    "name": "TechCorp",
    "employees": [
        {
            "name": "Alice",
            "position": "Developer",
            "skills": ["Python", "JavaScript", "Sentra"]
        },
        {
            "name": "Bob", 
            "position": "Designer",
            "skills": ["Photoshop", "Figma"]
        }
    ],
    "locations": {
        "headquarters": "San Francisco",
        "branches": ["New York", "London", "Tokyo"]
    }
}

// Access nested data
log("Company: " + company["name"])
log("First employee: " + company["employees"][0]["name"])
log("HQ: " + company["locations"]["headquarters"])
log("First branch: " + company["locations"]["branches"][0])

// Modify nested data
company["employees"][0]["skills"].push("Go")
log("Updated skills: " + str(company["employees"][0]["skills"]))
```

## Type Checking and Conversion

### Type Checking
```sentra
let value = 42

log("Type: " + type(value))          // number

// Check types
if (type(value) == "number") {
    log("It's a number!")
}

let examples = [42, "hello", true, null, [1,2,3], {"key": "value"}]
for (let item in examples) {
    log("Value: " + str(item) + ", Type: " + type(item))
}
```

### Type Conversion
```sentra
// To string
let num = 42
let str_num = str(num)               // "42"

// To number
let text = "123"
let number = num(text)               // 123

let decimal_text = "3.14"
let decimal = num(decimal_text)      // 3.14

// To boolean
let bool_from_num = bool(1)          // true
let bool_from_zero = bool(0)         // false
let bool_from_str = bool("hello")    // true
let bool_from_empty = bool("")       // false

log("String: " + str_num)
log("Number: " + str(number))
log("Bool from 1: " + str(bool_from_num))
log("Bool from empty: " + str(bool_from_empty))
```

## Best Practices

### Naming Conventions
```sentra
// Use descriptive names
let user_count = 10           // Good
let x = 10                    // Bad

// Use camelCase or snake_case consistently
let firstName = "John"        // camelCase
let first_name = "John"       // snake_case

// Constants in UPPER_CASE
const MAX_USERS = 100
const API_URL = "https://api.example.com"
```

### Defensive Programming
```sentra
fn safe_divide(a, b) {
    if (type(a) != "number" || type(b) != "number") {
        log("Error: Both arguments must be numbers")
        return null
    }
    
    if (b == 0) {
        log("Error: Division by zero")
        return null
    }
    
    return a / b
}

let result = safe_divide(10, 2)
if (result != null) {
    log("Result: " + str(result))
}
```

### Working with Unknown Data
```sentra
fn display_user(user) {
    if (user == null) {
        log("No user provided")
        return
    }
    
    let name = user["name"] || "Unknown"
    let age = user["age"] || 0
    
    log("User: " + name + ", Age: " + str(age))
}

display_user({"name": "Alice", "age": 30})
display_user({"name": "Bob"})
display_user(null)
```

## Next Steps

Now that you understand Sentra's data types:

1. [Learn about the Standard Library](../standard-library/) - Built-in functions for common tasks
2. [Network Programming](../network-module/) - TCP/UDP, HTTP, WebSocket capabilities
3. [Security Module](../security-module/) - Security tools and vulnerability scanning
4. [Read the Language Reference](../../reference/language/) - Complete syntax guide

---

{: .fs-6 .fw-300 }
Now that you understand Sentra's data types, let's explore the built-in functions in the Standard Library.

[← Previous: Your First Program](../first-program/){: .btn .btn-outline .mr-2 }
[Next: Standard Library →](../standard-library/){: .btn .btn-primary }