---
layout: default
title: Your First Program
parent: Tutorial
nav_order: 2
---

# Your First Sentra Program

Let's write and run your first Sentra program!

## Hello, World!

Create a file called `hello.sn`:

```sentra
// hello.sn - Your first Sentra program
log("Hello, World!")
```

Run it:
```bash
sentra run hello.sn
```

Output:
```
Hello, World!
```

Congratulations! You've just run your first Sentra program.

## Understanding the Code

```sentra
// This is a comment
log("Hello, World!")
```

- `//` starts a line comment
- `log()` is a built-in function that prints to the console
- Strings are enclosed in double quotes `""`
- Statements end with a newline (no semicolon required)

## Variables and Values

```sentra
// Variables
let name = "Sentra"
let version = 1.0
let isAwesome = true

log("Language: " + name)
log("Version: " + str(version))
log("Awesome: " + str(isAwesome))
```

### Variable Types
- `let` - Creates a mutable variable
- `const` - Creates an immutable constant
- `var` - Creates a variable (legacy, use `let`)

```sentra
const PI = 3.14159
let radius = 5
let area = PI * radius * radius

log("Area of circle: " + str(area))
```

## Data Types

### Numbers
```sentra
let integer = 42
let decimal = 3.14
let negative = -10

// Arithmetic
let sum = 10 + 5        // 15
let difference = 10 - 3  // 7
let product = 4 * 6      // 24
let quotient = 15 / 3    // 5
let remainder = 17 % 5   // 2
```

### Strings
```sentra
let firstName = "John"
let lastName = "Doe"
let fullName = firstName + " " + lastName

log("Full name: " + fullName)

// String methods
log("Uppercase: " + upper(fullName))
log("Lowercase: " + lower(fullName))
log("Length: " + str(len(fullName)))
```

### Booleans
```sentra
let isTrue = true
let isFalse = false
let result = isTrue && !isFalse

log("Result: " + str(result))
```

## Basic Operations

### Comparison
```sentra
let a = 10
let b = 20

log("a == b: " + str(a == b))  // false
log("a != b: " + str(a != b))  // true
log("a < b: " + str(a < b))    // true
log("a > b: " + str(a > b))    // false
log("a <= b: " + str(a <= b))  // true
log("a >= b: " + str(a >= b))  // false
```

### Logical Operations
```sentra
let x = true
let y = false

log("x && y: " + str(x && y))  // false
log("x || y: " + str(x || y))  // true
log("!x: " + str(!x))          // false
```

## Functions

```sentra
// Function definition
fn greet(name) {
    return "Hello, " + name + "!"
}

// Function call
let message = greet("World")
log(message)

// Function with multiple parameters
fn add(a, b) {
    return a + b
}

let sum = add(5, 3)
log("5 + 3 = " + str(sum))
```

## Control Flow

### If Statements
```sentra
let age = 18

if (age >= 18) {
    log("You are an adult")
} else {
    log("You are a minor")
}

// Multiple conditions
let score = 85

if (score >= 90) {
    log("Grade: A")
} else if (score >= 80) {
    log("Grade: B")
} else if (score >= 70) {
    log("Grade: C")
} else {
    log("Grade: F")
}
```

### Loops
```sentra
// While loop
let count = 0
while (count < 5) {
    log("Count: " + str(count))
    count = count + 1
}

// For loop with array
let numbers = [1, 2, 3, 4, 5]
for (let num in numbers) {
    log("Number: " + str(num))
}
```

## Working with Arrays

```sentra
// Create an array
let fruits = ["apple", "banana", "orange"]

// Access elements
log("First fruit: " + fruits[0])
log("Second fruit: " + fruits[1])

// Add elements
push(fruits, "grape")
log("Fruits: " + str(fruits))

// Array length
log("Number of fruits: " + str(len(fruits)))

// Iterate over array
for (let fruit in fruits) {
    log("I like " + fruit)
}
```

## Working with Maps

```sentra
// Create a map
let person = {
    "name": "Alice",
    "age": 30,
    "city": "New York"
}

// Access values
log("Name: " + person["name"])
log("Age: " + str(person["age"]))

// Add/modify values
person["email"] = "alice@example.com"
person["age"] = 31

// Iterate over map
for (let key in person) {
    log(key + ": " + str(person[key]))
}
```

## File I/O

```sentra
// Write to a file
let content = "Hello from Sentra!"
file_write("output.txt", content)
log("File written successfully")

// Read from a file
let data = file_read("output.txt")
log("File contents: " + data)

// Check if file exists
if (file_exists("output.txt")) {
    log("File exists!")
} else {
    log("File not found")
}
```

## Error Handling

```sentra
// Try-catch for error handling
try {
    let data = file_read("nonexistent.txt")
    log("File content: " + data)
} catch (error) {
    log("Error: Could not read file")
}
```

## Putting It All Together

Here's a complete program that demonstrates multiple concepts:

```sentra
// calculator.sn - A simple calculator program

fn calculator() {
    log("=== Simple Calculator ===")
    
    // Get user input (simulated)
    let num1 = 10
    let num2 = 5
    let operation = "+"
    
    log("Calculating: " + str(num1) + " " + operation + " " + str(num2))
    
    let result = 0
    
    if (operation == "+") {
        result = num1 + num2
    } else if (operation == "-") {
        result = num1 - num2
    } else if (operation == "*") {
        result = num1 * num2
    } else if (operation == "/") {
        if (num2 != 0) {
            result = num1 / num2
        } else {
            log("Error: Division by zero!")
            return
        }
    } else {
        log("Error: Unknown operation!")
        return
    }
    
    log("Result: " + str(result))
    
    // Save result to file
    let output = str(num1) + " " + operation + " " + str(num2) + " = " + str(result)
    file_write("calculation.txt", output)
    log("Result saved to calculation.txt")
}

calculator()
```

## Next Steps

Now that you understand the basics:

1. [Learn about data types in detail]({{ site.baseurl }}/data-types)
2. [Explore network programming]({{ site.baseurl }}/network-programming)
3. [Learn project management]({{ site.baseurl }}/project-management)
4. [Read the language reference]({{ site.baseurl }}/LANGUAGE_REFERENCE)

## Practice Exercises

Try these exercises to reinforce what you've learned:

### Exercise 1: Temperature Converter
```sentra
fn celsius_to_fahrenheit(celsius) {
    return (celsius * 9 / 5) + 32
}

let temp_c = 25
let temp_f = celsius_to_fahrenheit(temp_c)
log(str(temp_c) + "°C = " + str(temp_f) + "°F")
```

### Exercise 2: Find Maximum
```sentra
fn find_max(numbers) {
    if (len(numbers) == 0) {
        return null
    }
    
    let max_val = numbers[0]
    for (let i = 1; i < len(numbers); i = i + 1) {
        if (numbers[i] > max_val) {
            max_val = numbers[i]
        }
    }
    return max_val
}

let nums = [3, 7, 2, 9, 1, 5]
let maximum = find_max(nums)
log("Maximum value: " + str(maximum))
```

### Exercise 3: Count Words
```sentra
fn count_words(text) {
    let words = split(text, " ")
    return len(words)
}

let sentence = "The quick brown fox jumps over the lazy dog"
let word_count = count_words(sentence)
log("Word count: " + str(word_count))
```

Keep practicing, and you'll master Sentra in no time!

---

{: .fs-6 .fw-300 }
Now that you understand the basics, let's learn about Sentra's data types and language features in detail.

[← Previous: Installation](../installation/){: .btn .btn-outline .mr-2 }
[Next: Language Basics →](../language-basics/){: .btn .btn-primary }