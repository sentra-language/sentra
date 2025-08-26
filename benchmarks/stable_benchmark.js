// Stable benchmark for Node.js - equivalent to Sentra stable benchmark

console.log("=== NODE.JS STABLE BENCHMARK ===");
console.log("");

// Test 1: Arithmetic Operations (10k iterations)
console.log("Test 1: Arithmetic operations...");
let startTime = Date.now();

let sum = 0;
for (let i = 0; i < 10000; i++) {
    sum = sum + i * 2 - 1;
    sum = sum / 1.1;
    sum = sum % 10000;
}

let arithmeticTime = Date.now() - startTime;
console.log(`Arithmetic (10k ops): ${arithmeticTime}ms`);

// Test 2: Array Operations
console.log("");
console.log("Test 2: Array operations...");
startTime = Date.now();

let arr = [];
for (let i = 0; i < 1000; i++) {
    arr.push(i);
    arr.push(i * 2);
}

let total = 0;
for (let val of arr) {
    total = total + val;
}

let arrayTime = Date.now() - startTime;
console.log(`Array (2k elements): ${arrayTime}ms`);

// Test 3: Map Operations
console.log("");
console.log("Test 3: Map operations...");
startTime = Date.now();

let mapData = {};
for (let i = 0; i < 500; i++) {
    mapData[`key${i}`] = i * 10;
    mapData[`data${i}`] = i * 20;
}

let mapCount = 0;
for (let key in mapData) {
    mapCount = mapCount + 1;
}

let mapTime = Date.now() - startTime;
console.log(`Map (1k entries): ${mapTime}ms`);

// Test 4: String Operations
console.log("");
console.log("Test 4: String operations...");
startTime = Date.now();

let text = "benchmark";
for (let i = 0; i < 200; i++) {
    text = text + ` test ${i}`;
    if (text.length > 10000) {
        text = "reset";
    }
}

let stringTime = Date.now() - startTime;
console.log(`String (200 concatenations): ${stringTime}ms`);

// Test 5: Function Calls
console.log("");
console.log("Test 5: Function calls...");

function calculate(a, b) {
    return a * b + (a - b);
}

startTime = Date.now();

let funcResult = 0;
for (let i = 0; i < 2000; i++) {
    funcResult = funcResult + calculate(i, i + 1);
}

let functionTime = Date.now() - startTime;
console.log(`Function calls (2k): ${functionTime}ms`);

// Test 6: Nested Loops
console.log("");
console.log("Test 6: Nested loops...");
startTime = Date.now();

let nestedSum = 0;
for (let i = 0; i < 50; i++) {
    for (let j = 0; j < 50; j++) {
        nestedSum = nestedSum + i * j;
    }
}

let nestedTime = Date.now() - startTime;
console.log(`Nested loops (2.5k iterations): ${nestedTime}ms`);

// Total time
let totalTime = arithmeticTime + arrayTime + mapTime + stringTime + functionTime + nestedTime;
console.log("");
console.log("=== BENCHMARK COMPLETE ===");
console.log(`Total execution time: ${totalTime}ms`);
console.log("Platform: Node.js (V8)");