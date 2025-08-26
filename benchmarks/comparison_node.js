#!/usr/bin/env node
// Node.js equivalent benchmark for comparison

console.log("=== Node.js Performance Benchmarks ===");
console.log("");

const startTime = process.hrtime.bigint();

// Arithmetic benchmark
console.log("1. Arithmetic Operations");
const iterations = 10000;
let result = 0;

for (let i = 0; i < iterations; i++) {
    result = result + i * 2 - 1;
    result = result / 2;
    result = result % 1000;
}

console.log(`Arithmetic test completed: ${iterations} iterations`);
console.log(`Result: ${result}`);
console.log("");

// Array operations
console.log("2. Array Operations");
const arr = [];
for (let i = 0; i < 1000; i++) {
    arr.push(i);
}

console.log(`Array creation completed: ${arr.length} elements`);

// Array access
let sum = 0;
for (const val of arr) {
    sum += val;
}

console.log(`Array sum: ${sum}`);
console.log("");

// Map operations
console.log("3. Map Operations");
const mapObj = {};
for (let i = 0; i < 500; i++) {
    mapObj[`key_${i}`] = i * 2;
}

console.log("Map creation completed: 500 entries");

// Map access test
let mapSum = 0;
for (let i = 0; i < 500; i++) {
    mapSum += mapObj[`key_${i}`];
}

console.log(`Map sum: ${mapSum}`);
console.log("");

// Function calls
console.log("4. Function Call Overhead");
function simpleAdd(a, b) {
    return a + b;
}

let callResult = 0;
for (let i = 0; i < 5000; i++) {
    callResult = simpleAdd(i, callResult);
}

console.log(`Function calls completed: ${callResult}`);
console.log("");

// String operations
console.log("5. String Operations");
let strResult = "";
for (let i = 0; i < 100; i++) {
    strResult += "test";
}

console.log(`String concatenation completed: length ${strResult.length}`);
console.log("");

const endTime = process.hrtime.bigint();
console.log("=== All benchmarks completed successfully ===");
console.log(`Total time: ${Number(endTime - startTime) / 1000000}ms`);