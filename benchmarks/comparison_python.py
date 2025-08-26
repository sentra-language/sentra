#!/usr/bin/env python3
# Python equivalent benchmark for comparison

import time

print("=== Python Performance Benchmarks ===")
print("")

start_time = time.time()

# Arithmetic benchmark
print("1. Arithmetic Operations")
iterations = 10000
result = 0

for i in range(iterations):
    result = result + i * 2 - 1
    result = result / 2
    result = result % 1000

print(f"Arithmetic test completed: {iterations} iterations")
print(f"Result: {result}")
print("")

# Array operations
print("2. Array Operations")
arr = []
for i in range(1000):
    arr.append(i)

print(f"Array creation completed: {len(arr)} elements")

# Array access
sum_val = 0
for val in arr:
    sum_val += val

print(f"Array sum: {sum_val}")
print("")

# Map operations
print("3. Map Operations")
map_obj = {}
for i in range(500):
    map_obj[f"key_{i}"] = i * 2

print("Map creation completed: 500 entries")

# Map access test
map_sum = 0
for i in range(500):
    map_sum += map_obj[f"key_{i}"]

print(f"Map sum: {map_sum}")
print("")

# Function calls
print("4. Function Call Overhead")
def simple_add(a, b):
    return a + b

call_result = 0
for i in range(5000):
    call_result = simple_add(i, call_result)

print(f"Function calls completed: {call_result}")
print("")

# String operations
print("5. String Operations")
str_result = ""
for i in range(100):
    str_result += "test"

print(f"String concatenation completed: length {len(str_result)}")
print("")

end_time = time.time()
print("=== All benchmarks completed successfully ===")
print(f"Total time: {end_time - start_time:.3f} seconds")