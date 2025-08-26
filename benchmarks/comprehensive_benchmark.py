#!/usr/bin/env python3
# Comprehensive benchmark for Python
# Equivalent to Sentra benchmark for fair comparison

import time

print("=== PYTHON COMPREHENSIVE BENCHMARK ===")
print("")

# Test 1: Arithmetic Operations (50k iterations)
print("Test 1: Arithmetic operations...")
start_time = time.time() * 1000  # Convert to milliseconds

sum_val = 0
for i in range(50000):
    sum_val = sum_val + i * 2 - 1
    sum_val = sum_val / 1.1
    sum_val = sum_val % 10000

arithmetic_time = time.time() * 1000 - start_time
print(f"Arithmetic (50k ops): {arithmetic_time:.0f}ms")

# Test 2: Array Operations
print("")
print("Test 2: Array operations...")
start_time = time.time() * 1000

arr = []
for i in range(5000):
    arr.append(i)
    arr.append(i * 2)

total = 0
for val in arr:
    total = total + val

array_time = time.time() * 1000 - start_time
print(f"Array (10k elements): {array_time:.0f}ms")

# Test 3: Map (Dictionary) Operations
print("")
print("Test 3: Map operations...")
start_time = time.time() * 1000

map_data = {}
for i in range(2000):
    map_data[f"key{i}"] = i * 10
    map_data[f"data{i}"] = i * 20

map_count = 0
for key in map_data:
    map_count = map_count + 1

map_time = time.time() * 1000 - start_time
print(f"Map (4k entries): {map_time:.0f}ms")

# Test 4: String Operations
print("")
print("Test 4: String operations...")
start_time = time.time() * 1000

text = "benchmark"
for i in range(1000):
    text = text + f" test {i}"
    if len(text) > 50000:
        text = "reset"

string_time = time.time() * 1000 - start_time
print(f"String (1k concatenations): {string_time:.0f}ms")

# Test 5: Function Calls
print("")
print("Test 5: Function calls...")

def calculate(a, b):
    return a * b + (a - b)

start_time = time.time() * 1000

func_result = 0
for i in range(10000):
    func_result = func_result + calculate(i, i + 1)

function_time = time.time() * 1000 - start_time
print(f"Function calls (10k): {function_time:.0f}ms")

# Test 6: Nested Loops
print("")
print("Test 6: Nested loops...")
start_time = time.time() * 1000

nested_sum = 0
for i in range(100):
    for j in range(100):
        nested_sum = nested_sum + i * j

nested_time = time.time() * 1000 - start_time
print(f"Nested loops (10k iterations): {nested_time:.0f}ms")

# Total time
total_time = arithmetic_time + array_time + map_time + string_time + function_time + nested_time
print("")
print("=== BENCHMARK COMPLETE ===")
print(f"Total execution time: {total_time:.0f}ms")
print("Platform: Python (CPython)")