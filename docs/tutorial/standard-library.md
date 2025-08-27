---
layout: default
title: Standard Library
parent: Tutorial
nav_order: 4
---

# Standard Library
{: .fs-9 }

Learn about Sentra's built-in functions and standard library modules for basic operations.
{: .fs-6 .fw-300 }

---

## Built-in Functions

### String Operations

```sentra
// String manipulation
let text = "Hello, Sentra!"
log("Original: " + text)
log("Uppercase: " + upper(text))
log("Lowercase: " + lower(text))
log("Length: " + str(len(text)))

// String searching
let sentence = "The quick brown fox"
log("Contains 'quick': " + str(contains(sentence, "quick")))
log("Starts with 'The': " + str(starts_with(sentence, "The")))
log("Ends with 'fox': " + str(ends_with(sentence, "fox")))

// String splitting and joining
let words = split(sentence, " ")
log("Words: " + str(words))
let rejoined = join(words, "-")
log("Rejoined: " + rejoined)
```

### Array Operations

```sentra
// Array creation and manipulation
let numbers = [1, 2, 3, 4, 5]
log("Original array: " + str(numbers))

// Adding elements
push(numbers, 6)
unshift(numbers, 0)
log("After adding: " + str(numbers))

// Removing elements
let last = pop(numbers)
let first = shift(numbers)
log("Removed first: " + str(first) + ", last: " + str(last))
log("After removing: " + str(numbers))

// Array operations
sort(numbers)
log("Sorted: " + str(numbers))
reverse(numbers)
log("Reversed: " + str(numbers))

// Slicing
let subset = slice(numbers, 1, 4)
log("Subset [1:4]: " + str(subset))
```

### Math Operations

```sentra
// Basic math functions
let x = 16
let y = 3.7

log("Absolute value of -5: " + str(abs(-5)))
log("Square root of " + str(x) + ": " + str(sqrt(x)))
log("2 to the power of 3: " + str(pow(2, 3)))
log("Floor of " + str(y) + ": " + str(floor(y)))
log("Ceiling of " + str(y) + ": " + str(ceil(y)))
log("Round " + str(y) + ": " + str(round(y)))
log("Min of 10 and 5: " + str(min(10, 5)))
log("Max of 10 and 5: " + str(max(10, 5)))
log("Random number: " + str(random()))
```

### File I/O Operations

```sentra
// File operations
let content = "Hello from Sentra!\nThis is a test file."

// Write to file
file_write("test.txt", content)
log("File written successfully")

// Read from file
if (file_exists("test.txt")) {
    let data = file_read("test.txt")
    log("File contents:")
    log(data)
} else {
    log("File not found")
}

// File information
let stats = file_stat("test.txt")
log("File size: " + str(stats["size"]) + " bytes")
log("Modified: " + str(stats["modified"]))
```

### Type Operations

```sentra
// Type checking and conversion
let values = [42, "hello", true, null, [1, 2, 3], {"key": "value"}]

for (let value in values) {
    log("Value: " + str(value) + ", Type: " + type(value))
}

// Type conversion
let number = 42
let text = "123"
let flag = true

log("Number to string: " + str(number))
log("String to number: " + str(num(text)))
log("Boolean to string: " + str(flag))
log("Number to boolean: " + str(bool(1)))
log("Empty string to boolean: " + str(bool("")))
```

---

## Date and Time

```sentra
// Current timestamp
let now = time()
log("Current timestamp: " + str(now))

// Sleep function
log("Waiting 2 seconds...")
sleep(2000)  // Sleep for 2000 milliseconds
log("Done waiting!")
```

---

## Environment and System

```sentra
// Environment variables
let path = env("PATH")
log("PATH variable: " + (path || "Not set"))

let home = env("HOME") || env("USERPROFILE")
log("Home directory: " + (home || "Unknown"))

// Custom environment variable
let debug = env("DEBUG") == "true"
if (debug) {
    log("Debug mode enabled")
}
```

---

## JSON Operations

```sentra
// JSON parsing and generation
let data = {
    "name": "Sentra",
    "version": "1.0.0",
    "features": ["networking", "security", "automation"]
}

// Convert to JSON string
let json_string = json_stringify(data)
log("JSON: " + json_string)

// Parse JSON string
let parsed = json_parse(json_string)
log("Parsed name: " + parsed["name"])
log("Features: " + str(parsed["features"]))
```

---

## Practical Example: Log Parser

Here's a practical example using multiple standard library functions:

```sentra
// Log file parser
fn parse_log_file(filename) {
    if (!file_exists(filename)) {
        log("Error: Log file '" + filename + "' not found")
        return null
    }
    
    let content = file_read(filename)
    let lines = split(content, "\n")
    let stats = {
        "total_lines": 0,
        "error_count": 0,
        "warning_count": 0,
        "info_count": 0
    }
    
    for (let line in lines) {
        if (len(trim(line)) == 0) {
            continue  // Skip empty lines
        }
        
        stats["total_lines"] = stats["total_lines"] + 1
        
        let upper_line = upper(line)
        if (contains(upper_line, "ERROR")) {
            stats["error_count"] = stats["error_count"] + 1
        } else if (contains(upper_line, "WARN")) {
            stats["warning_count"] = stats["warning_count"] + 1
        } else if (contains(upper_line, "INFO")) {
            stats["info_count"] = stats["info_count"] + 1
        }
    }
    
    return stats
}

// Create sample log file
let sample_log = `2024-01-01 10:00:01 INFO Application started
2024-01-01 10:00:02 INFO Loading configuration
2024-01-01 10:00:03 WARN Configuration file not found, using defaults
2024-01-01 10:00:04 ERROR Failed to connect to database
2024-01-01 10:00:05 INFO Retrying database connection
2024-01-01 10:00:06 INFO Database connected successfully`

file_write("app.log", sample_log)

// Parse the log file
let results = parse_log_file("app.log")
if (results) {
    log("Log Analysis Results:")
    log("Total lines: " + str(results["total_lines"]))
    log("Errors: " + str(results["error_count"]))
    log("Warnings: " + str(results["warning_count"]))
    log("Info messages: " + str(results["info_count"]))
}
```

---

## Next Steps

Now that you understand Sentra's standard library:

- [Network Module](../network-module/) - TCP/UDP, HTTP, WebSocket programming
- [Security Module](../security-module/) - Security tools and cryptography
- [Project Management](../project-management/) - Managing larger projects
- [Language Reference](../../reference/language/) - Complete syntax documentation

---

{: .fs-6 .fw-300 }
Now that you know the standard library, let's learn about Sentra's powerful network programming capabilities.

[← Previous: Language Basics](../language-basics/){: .btn .btn-outline .mr-2 }
[Next: Network Module →](../network-module/){: .btn .btn-primary }

---

## Function Reference

### String Functions
- `upper(string)` - Convert to uppercase
- `lower(string)` - Convert to lowercase 
- `len(string)` - Get string length
- `trim(string)` - Remove whitespace
- `split(string, separator)` - Split into array
- `join(array, separator)` - Join array into string
- `contains(string, substring)` - Check if contains
- `starts_with(string, prefix)` - Check if starts with
- `ends_with(string, suffix)` - Check if ends with
- `replace(string, old, new)` - Replace text

### Array Functions
- `push(array, item)` - Add to end
- `pop(array)` - Remove from end
- `unshift(array, item)` - Add to beginning  
- `shift(array)` - Remove from beginning
- `slice(array, start, end)` - Get subset
- `sort(array)` - Sort in place
- `reverse(array)` - Reverse in place

### Math Functions
- `abs(number)` - Absolute value
- `sqrt(number)` - Square root
- `pow(base, exponent)` - Power
- `floor(number)` - Round down
- `ceil(number)` - Round up
- `round(number)` - Round to nearest
- `min(a, b)` - Minimum value
- `max(a, b)` - Maximum value
- `random()` - Random 0-1

### File Functions
- `file_read(path)` - Read file contents
- `file_write(path, content)` - Write to file
- `file_exists(path)` - Check if exists
- `file_stat(path)` - Get file information

### Utility Functions
- `type(value)` - Get type name
- `str(value)` - Convert to string
- `num(value)` - Convert to number
- `bool(value)` - Convert to boolean
- `time()` - Current timestamp
- `sleep(milliseconds)` - Pause execution
- `env(name)` - Get environment variable
- `json_parse(string)` - Parse JSON
- `json_stringify(object)` - Generate JSON