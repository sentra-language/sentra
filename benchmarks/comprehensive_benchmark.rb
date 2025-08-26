#!/usr/bin/env ruby
# Comprehensive benchmark for Ruby
# Equivalent to Sentra benchmark for fair comparison

puts "=== RUBY COMPREHENSIVE BENCHMARK ==="
puts ""

# Test 1: Arithmetic Operations (50k iterations)
puts "Test 1: Arithmetic operations..."
start_time = Time.now.to_f * 1000

sum = 0
50000.times do |i|
  sum = sum + i * 2 - 1
  sum = sum / 1.1
  sum = sum % 10000
end

arithmetic_time = Time.now.to_f * 1000 - start_time
puts "Arithmetic (50k ops): #{arithmetic_time.round}ms"

# Test 2: Array Operations
puts ""
puts "Test 2: Array operations..."
start_time = Time.now.to_f * 1000

arr = []
5000.times do |i|
  arr.push(i)
  arr.push(i * 2)
end

total = 0
arr.each do |val|
  total = total + val
end

array_time = Time.now.to_f * 1000 - start_time
puts "Array (10k elements): #{array_time.round}ms"

# Test 3: Map (Hash) Operations
puts ""
puts "Test 3: Map operations..."
start_time = Time.now.to_f * 1000

map_data = {}
2000.times do |i|
  map_data["key#{i}"] = i * 10
  map_data["data#{i}"] = i * 20
end

map_count = 0
map_data.each_key do |key|
  map_count = map_count + 1
end

map_time = Time.now.to_f * 1000 - start_time
puts "Map (4k entries): #{map_time.round}ms"

# Test 4: String Operations
puts ""
puts "Test 4: String operations..."
start_time = Time.now.to_f * 1000

text = "benchmark"
1000.times do |i|
  text = text + " test #{i}"
  if text.length > 50000
    text = "reset"
  end
end

string_time = Time.now.to_f * 1000 - start_time
puts "String (1k concatenations): #{string_time.round}ms"

# Test 5: Function Calls
puts ""
puts "Test 5: Function calls..."

def calculate(a, b)
  a * b + (a - b)
end

start_time = Time.now.to_f * 1000

func_result = 0
10000.times do |i|
  func_result = func_result + calculate(i, i + 1)
end

function_time = Time.now.to_f * 1000 - start_time
puts "Function calls (10k): #{function_time.round}ms"

# Test 6: Nested Loops
puts ""
puts "Test 6: Nested loops..."
start_time = Time.now.to_f * 1000

nested_sum = 0
100.times do |i|
  100.times do |j|
    nested_sum = nested_sum + i * j
  end
end

nested_time = Time.now.to_f * 1000 - start_time
puts "Nested loops (10k iterations): #{nested_time.round}ms"

# Total time
total_time = arithmetic_time + array_time + map_time + string_time + function_time + nested_time
puts ""
puts "=== BENCHMARK COMPLETE ==="
puts "Total execution time: #{total_time.round}ms"
puts "Platform: Ruby (YARV)"