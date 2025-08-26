#!/usr/bin/env python3
# Intensive Python benchmark for comparison

import time

print("=== Python Intensive Benchmarks ===")
print("")

start_time = time.time()

# Computational benchmark - Prime number generation
print("1. Prime Number Generation (Sieve of Eratosthenes)")
limit = 1000
is_prime = [True] * (limit + 1)
primes = []

# Sieve algorithm
for i in range(2, int(limit**0.5) + 1):
    if is_prime[i]:
        for j in range(i*i, limit + 1, i):
            is_prime[j] = False

# Collect primes
for i in range(2, limit + 1):
    if is_prime[i]:
        primes.append(i)

print(f"Found {len(primes)} primes up to {limit}")
print("")

# Recursive benchmark - Factorial calculation
print("2. Recursive Factorial Calculation")
def factorial(n):
    if n <= 1:
        return 1
    return n * factorial(n - 1)

fact_result = factorial(10)
print(f"Factorial of 10: {fact_result}")
print("")

# Data structure intensive - Matrix operations
print("3. Matrix Operations")
matrix_size = 50
matrix = []

# Create matrix
for i in range(matrix_size):
    row = []
    for j in range(matrix_size):
        row.append(i + j)
    matrix.append(row)

# Matrix sum
matrix_sum = 0
for i in range(matrix_size):
    for j in range(matrix_size):
        matrix_sum += matrix[i][j]

print(f"Matrix sum ({matrix_size}x{matrix_size}): {matrix_sum}")
print("")

end_time = time.time()
print("=== Intensive benchmarks completed ===")
print(f"Total time: {end_time - start_time:.3f} seconds")