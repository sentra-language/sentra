---
layout: default
title: Standard Library
parent: Reference
nav_order: 2
---

# Sentra Standard Library Reference

Complete reference for all built-in functions in Sentra.

## Table of Contents

1. [I/O Functions](#io-functions)
2. [Type Functions](#type-functions)
3. [String Functions](#string-functions)
4. [Number Functions](#number-functions)
5. [Array Functions](#array-functions)
6. [Map Functions](#map-functions)
7. [Math Functions](#math-functions)
8. [Time Functions](#time-functions)
9. [File Functions](#file-functions)
10. [Network Functions](#network-functions)
11. [Security Functions](#security-functions)
12. [System Functions](#system-functions)
13. [Concurrency Functions](#concurrency-functions)

---

## I/O Functions

### log(value)
Prints a value to console with newline.
```sentra
log("Hello, World!")  // Outputs: Hello, World!
log(42)              // Outputs: 42
log([1, 2, 3])       // Outputs: [1, 2, 3]
```

### print(value)
Prints a value to console without newline.
```sentra
print("Hello, ")
print("World!")  // Outputs: Hello, World!
```

### readline()
Reads a line from standard input.
```sentra
print("Enter your name: ")
let name = readline()
log("Hello, " + name)
```

---

## Type Functions

### type(value)
Returns the type of a value as a string.
```sentra
type(42)          // "number"
type("hello")     // "string"
type(true)        // "boolean"
type([])          // "array"
type({})          // "map"
type(nil)         // "nil"
type(log)         // "function"
```

### str(value)
Converts any value to a string representation.
```sentra
str(42)           // "42"
str(true)         // "true"
str([1, 2, 3])    // "[1, 2, 3]"
str({"a": 1})     // "{a: 1}"
```

### int(value)
Converts a value to an integer.
```sentra
int("42")         // 42
int(3.14)         // 3
int(true)         // 1
int(false)        // 0
// Throws error for invalid conversions
```

### float(value)
Converts a value to a floating-point number.
```sentra
float("3.14")     // 3.14
float(42)         // 42.0
float("42.5")     // 42.5
// Throws error for invalid conversions
```

### bool(value)
Converts a value to a boolean.
```sentra
bool(1)           // true
bool(0)           // false
bool("")          // false
bool("hello")     // true
bool(nil)         // false
bool([])          // false
bool([1])         // true
```

---

## String Functions

### len(string)
Returns the length of a string.
```sentra
len("hello")      // 5
len("")           // 0
len("你好")        // 2 (Unicode aware)
```

### upper(string)
Converts a string to uppercase.
```sentra
upper("hello")    // "HELLO"
upper("Hello123") // "HELLO123"
```

### lower(string)
Converts a string to lowercase.
```sentra
lower("HELLO")    // "hello"
lower("Hello123") // "hello123"
```

### trim(string)
Removes leading and trailing whitespace.
```sentra
trim("  hello  ") // "hello"
trim("\n\thello\n") // "hello"
```

### split(string, delimiter)
Splits a string into an array.
```sentra
split("a,b,c", ",")      // ["a", "b", "c"]
split("hello world", " ") // ["hello", "world"]
split("a-b-c", "-")      // ["a", "b", "c"]
```

### join(array, delimiter)
Joins array elements into a string.
```sentra
join(["a", "b", "c"], ",")     // "a,b,c"
join(["hello", "world"], " ")  // "hello world"
join([1, 2, 3], "-")           // "1-2-3"
```

### substring(string, start, end)
Extracts a substring.
```sentra
substring("hello", 0, 2)   // "he"
substring("hello", 1, 4)   // "ell"
substring("hello", 2, 5)   // "llo"
```

### indexOf(string, substring)
Returns the index of first occurrence, or -1 if not found.
```sentra
indexOf("hello", "ll")     // 2
indexOf("hello", "x")      // -1
indexOf("hello", "o")      // 4
```

### contains(string, substring)
Checks if string contains substring.
```sentra
contains("hello", "ll")    // true
contains("hello", "x")     // false
```

### replace(string, old, new)
Replaces all occurrences of substring.
```sentra
replace("hello", "l", "x")     // "hexxo"
replace("hello world", "o", "0") // "hell0 w0rld"
```

### startsWith(string, prefix)
Checks if string starts with prefix.
```sentra
startsWith("hello", "he")  // true
startsWith("hello", "hi")  // false
```

### endsWith(string, suffix)
Checks if string ends with suffix.
```sentra
endsWith("hello", "lo")    // true
endsWith("hello", "la")    // false
```

### repeat(string, count)
Repeats a string n times.
```sentra
repeat("ab", 3)    // "ababab"
repeat("-", 10)    // "----------"
```

---

## Number Functions

### isNaN(value)
Checks if value is Not-a-Number.
```sentra
isNaN(0/0)         // true
isNaN(42)          // false
isNaN("hello")     // true
```

### isFinite(value)
Checks if value is a finite number.
```sentra
isFinite(42)       // true
isFinite(1/0)      // false
isFinite(-1/0)     // false
```

### parseInt(string, base)
Parses integer with specified base.
```sentra
parseInt("10", 10)  // 10
parseInt("10", 2)   // 2 (binary)
parseInt("FF", 16)  // 255 (hex)
```

### parseFloat(string)
Parses floating-point number.
```sentra
parseFloat("3.14")    // 3.14
parseFloat("3.14abc") // 3.14
parseFloat("abc")     // NaN
```

---

## Array Functions

### len(array)
Returns the length of an array.
```sentra
len([1, 2, 3])     // 3
len([])            // 0
```

### push(array, value)
Adds element to end of array.
```sentra
let arr = [1, 2]
push(arr, 3)       // arr is now [1, 2, 3]
```

### pop(array)
Removes and returns last element.
```sentra
let arr = [1, 2, 3]
let last = pop(arr)  // last = 3, arr = [1, 2]
```

### shift(array)
Removes and returns first element.
```sentra
let arr = [1, 2, 3]
let first = shift(arr)  // first = 1, arr = [2, 3]
```

### unshift(array, value)
Adds element to beginning of array.
```sentra
let arr = [2, 3]
unshift(arr, 1)    // arr is now [1, 2, 3]
```

### slice(array, start, end)
Returns a shallow copy of portion of array.
```sentra
let arr = [1, 2, 3, 4, 5]
slice(arr, 1, 3)   // [2, 3]
slice(arr, 2, 5)   // [3, 4, 5]
```

### concat(array1, array2)
Combines two arrays.
```sentra
concat([1, 2], [3, 4])  // [1, 2, 3, 4]
concat([], [1])         // [1]
```

### reverse(array)
Reverses array in place.
```sentra
let arr = [1, 2, 3]
reverse(arr)       // arr is now [3, 2, 1]
```

### sort(array)
Sorts array in place.
```sentra
let arr = [3, 1, 2]
sort(arr)          // arr is now [1, 2, 3]
```

### find(array, predicate)
Returns first element matching predicate.
```sentra
let arr = [1, 2, 3, 4, 5]
find(arr, fn(x) { return x > 3 })  // 4
```

### filter(array, predicate)
Returns new array with elements matching predicate.
```sentra
let arr = [1, 2, 3, 4, 5]
filter(arr, fn(x) { return x % 2 == 0 })  // [2, 4]
```

### map(array, function)
Returns new array with function applied to each element.
```sentra
let arr = [1, 2, 3]
map(arr, fn(x) { return x * 2 })  // [2, 4, 6]
```

### reduce(array, function, initial)
Reduces array to single value.
```sentra
let arr = [1, 2, 3, 4]
reduce(arr, fn(acc, x) { return acc + x }, 0)  // 10
```

### forEach(array, function)
Executes function for each element.
```sentra
let arr = [1, 2, 3]
forEach(arr, fn(x) { log(x) })  // Logs 1, 2, 3
```

### includes(array, value)
Checks if array contains value.
```sentra
includes([1, 2, 3], 2)  // true
includes([1, 2, 3], 5)  // false
```

---

## Map Functions

### keys(map)
Returns array of map keys.
```sentra
let m = {"a": 1, "b": 2}
keys(m)            // ["a", "b"]
```

### values(map)
Returns array of map values.
```sentra
let m = {"a": 1, "b": 2}
values(m)          // [1, 2]
```

### has(map, key)
Checks if map has key.
```sentra
let m = {"a": 1}
has(m, "a")        // true
has(m, "b")        // false
```

### delete(map, key)
Removes key from map.
```sentra
let m = {"a": 1, "b": 2}
delete(m, "a")     // m is now {"b": 2}
```

### merge(map1, map2)
Combines two maps (map2 overwrites map1 for conflicts).
```sentra
merge({"a": 1}, {"b": 2})        // {"a": 1, "b": 2}
merge({"a": 1}, {"a": 2, "b": 3}) // {"a": 2, "b": 3}
```

### clone(map)
Creates shallow copy of map.
```sentra
let m1 = {"a": 1}
let m2 = clone(m1)
m2["b"] = 2        // m1 is unchanged
```

---

## Math Functions

### abs(number)
Returns absolute value.
```sentra
abs(-5)            // 5
abs(5)             // 5
abs(-3.14)         // 3.14
```

### min(a, b)
Returns minimum of two numbers.
```sentra
min(3, 7)          // 3
min(-5, -2)        // -5
```

### max(a, b)
Returns maximum of two numbers.
```sentra
max(3, 7)          // 7
max(-5, -2)        // -2
```

### floor(number)
Rounds down to nearest integer.
```sentra
floor(3.7)         // 3
floor(-3.2)        // -4
```

### ceil(number)
Rounds up to nearest integer.
```sentra
ceil(3.2)          // 4
ceil(-3.7)         // -3
```

### round(number)
Rounds to nearest integer.
```sentra
round(3.5)         // 4
round(3.4)         // 3
round(-3.5)        // -4
```

### sqrt(number)
Returns square root.
```sentra
sqrt(16)           // 4
sqrt(2)            // 1.414...
```

### pow(base, exponent)
Returns base raised to exponent.
```sentra
pow(2, 8)          // 256
pow(3, 3)          // 27
pow(10, -2)        // 0.01
```

### exp(number)
Returns e raised to the power.
```sentra
exp(1)             // 2.718... (e)
exp(0)             // 1
```

### log(number)
Returns natural logarithm.
```sentra
log(2.718)         // ~1
log(10)            // 2.302...
```

### log10(number)
Returns base-10 logarithm.
```sentra
log10(100)         // 2
log10(1000)        // 3
```

### sin(radians)
Returns sine of angle in radians.
```sentra
sin(0)             // 0
sin(3.14159/2)     // 1
```

### cos(radians)
Returns cosine of angle in radians.
```sentra
cos(0)             // 1
cos(3.14159)       // -1
```

### tan(radians)
Returns tangent of angle in radians.
```sentra
tan(0)             // 0
tan(3.14159/4)     // ~1
```

### random()
Returns random number between 0 and 1.
```sentra
random()           // 0.7234... (random)
```

### randomInt(min, max)
Returns random integer between min and max (inclusive).
```sentra
randomInt(1, 10)   // Random from 1-10
randomInt(0, 100)  // Random from 0-100
```

---

## Time Functions

### time()
Returns current timestamp in milliseconds.
```sentra
let start = time()
// ... do work ...
let elapsed = time() - start
log("Took " + elapsed + "ms")
```

### now()
Returns current date/time as string.
```sentra
now()              // "2024-01-15 14:30:45"
```

### sleep(milliseconds)
Pauses execution for specified milliseconds.
```sentra
log("Start")
sleep(1000)        // Wait 1 second
log("End")
```

### parseTime(string)
Parses time string to timestamp.
```sentra
parseTime("2024-01-15")           // Timestamp
parseTime("2024-01-15 14:30:00")  // Timestamp
```

### formatTime(timestamp, format)
Formats timestamp to string.
```sentra
let ts = time()
formatTime(ts, "YYYY-MM-DD")      // "2024-01-15"
formatTime(ts, "HH:mm:ss")        // "14:30:45"
```

---

## File Functions

### file_read(path)
Reads entire file as string.
```sentra
let content = file_read("data.txt")
log(content)
```

### file_write(path, content)
Writes content to file.
```sentra
file_write("output.txt", "Hello, World!")
```

### file_exists(path)
Checks if file exists.
```sentra
if file_exists("config.json") {
    let config = parseJSON(file_read("config.json"))
}
```

### file_delete(path)
Deletes a file.
```sentra
file_delete("temp.txt")
```

### file_copy(source, dest)
Copies file from source to destination.
```sentra
file_copy("original.txt", "backup.txt")
```

### file_move(source, dest)
Moves/renames file.
```sentra
file_move("old.txt", "new.txt")
```

### dir_list(path)
Lists directory contents.
```sentra
let files = dir_list("./")
for file in files {
    log(file)
}
```

### dir_create(path)
Creates directory.
```sentra
dir_create("./output")
```

### dir_exists(path)
Checks if directory exists.
```sentra
if !dir_exists("./logs") {
    dir_create("./logs")
}
```

---

## Network Functions

### http_get(url)
Makes HTTP GET request.
```sentra
let response = http_get("https://api.example.com/data")
log(response["status"])  // 200
log(response["body"])     // Response body
```

### http_post(url, data)
Makes HTTP POST request.
```sentra
let response = http_post("https://api.example.com/users", {
    "name": "Alice",
    "email": "alice@example.com"
})
```

### net_scan(host, ports)
Scans network ports.
```sentra
let scan = net_scan("192.168.1.1", "1-1000")
log("Open ports: " + str(scan["open_ports"]))
```

### dns_lookup(domain)
Performs DNS lookup.
```sentra
let ips = dns_lookup("example.com")
log("IPs: " + str(ips))
```

### ping(host)
Pings a host.
```sentra
let result = ping("google.com")
log("Response time: " + result["time"] + "ms")
```

---

## Security Functions

### hash(algorithm, data)
Computes cryptographic hash.
```sentra
hash("md5", "hello")       // MD5 hash
hash("sha256", "hello")    // SHA256 hash
hash("sha512", "hello")    // SHA512 hash
```

### hmac(algorithm, data, key)
Computes HMAC.
```sentra
hmac("sha256", "message", "secret-key")
```

### encrypt(algorithm, data, key)
Encrypts data.
```sentra
let encrypted = encrypt("aes256", "sensitive data", "encryption-key")
```

### decrypt(algorithm, data, key)
Decrypts data.
```sentra
let decrypted = decrypt("aes256", encrypted, "encryption-key")
```

### base64_encode(data)
Encodes to Base64.
```sentra
base64_encode("hello")     // "aGVsbG8="
```

### base64_decode(data)
Decodes from Base64.
```sentra
base64_decode("aGVsbG8=")  // "hello"
```

### uuid()
Generates UUID.
```sentra
uuid()  // "550e8400-e29b-41d4-a716-446655440000"
```

### password_hash(password)
Creates secure password hash.
```sentra
let hash = password_hash("mypassword")
```

### password_verify(password, hash)
Verifies password against hash.
```sentra
if password_verify("mypassword", hash) {
    log("Password correct")
}
```

---

## System Functions

### env(variable)
Gets environment variable.
```sentra
let home = env("HOME")
let path = env("PATH")
```

### exec(command)
Executes system command.
```sentra
let result = exec("ls -la")
log(result["stdout"])
```

### exit(code)
Exits program with code.
```sentra
if error {
    log("Fatal error!")
    exit(1)
}
exit(0)  // Success
```

### args()
Returns command-line arguments.
```sentra
let arguments = args()
for arg in arguments {
    log(arg)
}
```

### platform()
Returns platform information.
```sentra
let info = platform()
log("OS: " + info["os"])          // "linux", "windows", "darwin"
log("Arch: " + info["arch"])      // "amd64", "arm64", etc.
```

---

## Concurrency Functions

### go(function)
Launches function as goroutine.
```sentra
go fn() {
    // Runs asynchronously
    for (let i = 0; i < 10; i = i + 1) {
        log("Async: " + i)
        sleep(100)
    }
}()
```

### make_channel(buffer_size)
Creates a channel for communication.
```sentra
let ch = make_channel()      // Unbuffered
let buf_ch = make_channel(10) // Buffered with size 10
```

### send(channel, value)
Sends value to channel (blocks if full).
```sentra
let ch = make_channel()
go fn() {
    send(ch, "Hello from goroutine")
}()
```

### receive(channel)
Receives value from channel (blocks if empty).
```sentra
let msg = receive(ch)
log(msg)  // "Hello from goroutine"
```

### select(cases)
Non-blocking channel operations.
```sentra
select([
    {"channel": ch1, "action": "receive"},
    {"channel": ch2, "action": "receive"},
    {"default": fn() { log("No data ready") }}
])
```

### mutex_create()
Creates a mutex for synchronization.
```sentra
let mutex = mutex_create()
```

### mutex_lock(mutex)
Locks a mutex.
```sentra
mutex_lock(mutex)
// Critical section
mutex_unlock(mutex)
```

### mutex_unlock(mutex)
Unlocks a mutex.
```sentra
mutex_unlock(mutex)
```

### wait_group_create()
Creates a wait group.
```sentra
let wg = wait_group_create()
```

### wait_group_add(wg, delta)
Adds to wait group counter.
```sentra
wait_group_add(wg, 1)
```

### wait_group_done(wg)
Decrements wait group counter.
```sentra
wait_group_done(wg)
```

### wait_group_wait(wg)
Waits for counter to reach zero.
```sentra
wait_group_wait(wg)
```

---

## JSON Functions

### parseJSON(string)
Parses JSON string to object.
```sentra
let data = parseJSON('{"name": "Alice", "age": 30}')
log(data["name"])  // "Alice"
```

### toJSON(object)
Converts object to JSON string.
```sentra
let obj = {"name": "Bob", "age": 25}
let json = toJSON(obj)  // '{"name":"Bob","age":25}'
```

---

## Regular Expression Functions

### regex_match(pattern, string)
Tests if string matches pattern.
```sentra
regex_match("^[a-z]+$", "hello")  // true
regex_match("^[0-9]+$", "hello")  // false
```

### regex_find(pattern, string)
Finds first match.
```sentra
regex_find("[0-9]+", "abc123def")  // "123"
```

### regex_find_all(pattern, string)
Finds all matches.
```sentra
regex_find_all("[0-9]+", "a1b22c333")  // ["1", "22", "333"]
```

### regex_replace(pattern, string, replacement)
Replaces matches with replacement.
```sentra
regex_replace("[0-9]+", "a1b2c3", "X")  // "aXbXcX"
```

---

## Error Handling Functions

### try(function)
Executes function and catches errors.
```sentra
let result = try(fn() {
    return riskyOperation()
})

if result["error"] != nil {
    log("Error: " + result["error"])
} else {
    log("Success: " + result["value"])
}
```

### throw(message)
Throws an error.
```sentra
if invalid {
    throw("Invalid input")
}
```

### assert(condition, message)
Asserts condition is true.
```sentra
assert(x > 0, "x must be positive")
assert(arr != nil, "array cannot be nil")
```

---

## Utility Functions

### range(start, end, step)
Creates array of numbers.
```sentra
range(1, 5, 1)     // [1, 2, 3, 4]
range(0, 10, 2)    // [0, 2, 4, 6, 8]
range(10, 0, -1)   // [10, 9, 8, 7, 6, 5, 4, 3, 2, 1]
```

### zip(array1, array2)
Combines two arrays into array of pairs.
```sentra
zip([1, 2, 3], ["a", "b", "c"])  // [[1, "a"], [2, "b"], [3, "c"]]
```

### enumerate(array)
Returns array with indices.
```sentra
enumerate(["a", "b", "c"])  // [[0, "a"], [1, "b"], [2, "c"]]
```

### deepClone(value)
Creates deep copy of value.
```sentra
let obj1 = {"a": {"b": 1}}
let obj2 = deepClone(obj1)
obj2["a"]["b"] = 2  // obj1 is unchanged
```

### memoize(function)
Creates memoized version of function.
```sentra
let fib = memoize(fn(n) {
    if n <= 1 { return n }
    return fib(n-1) + fib(n-2)
})
```

---

## Notes

1. **Error Handling**: Most functions that can fail will throw errors that can be caught with try-catch blocks.

2. **Type Safety**: Functions validate input types and throw errors for invalid types.

3. **Performance**: Built-in functions are implemented in Go for optimal performance.

4. **Security**: Security functions use industry-standard algorithms and implementations.

5. **Concurrency**: Concurrency functions follow Go's CSP model with channels and goroutines.

---

{: .fs-6 .fw-300 }
For a quick overview of common functions, check out the Quick Reference guide.

[← Previous: Language Reference](../language/){: .btn .btn-outline .mr-2 }
[Next: Quick Reference →](../quick/){: .btn .btn-primary }

---

## Related Documentation

- [Tutorial: Standard Library](../../tutorial/standard-library/) - Learn with hands-on examples
- [Tutorial: Network Module](../../tutorial/network-module/) - Network function examples
- [Tutorial: Security Module](../../tutorial/security-module/) - Security function examples  
- [Language Reference](../language/) - Complete syntax guide