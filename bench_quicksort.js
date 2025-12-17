// Quicksort benchmark
function quicksort(arr, low, high) {
    if (low < high) {
        let pivot = partition(arr, low, high);
        quicksort(arr, low, pivot - 1);
        quicksort(arr, pivot + 1, high);
    }
}

function partition(arr, low, high) {
    let pivot = arr[high];
    let i = low - 1;
    for (let j = low; j < high; j++) {
        if (arr[j] <= pivot) {
            i++;
            [arr[i], arr[j]] = [arr[j], arr[i]];
        }
    }
    [arr[i + 1], arr[high]] = [arr[high], arr[i + 1]];
    return i + 1;
}

function generateArray(n) {
    let arr = [];
    let seed = 12345;
    for (let i = 0; i < n; i++) {
        seed = (seed * 1103515245 + 12345) % 2147483648;
        arr.push(seed % 10000);
    }
    return arr;
}

let arr = generateArray(10000);
quicksort(arr, 0, arr.length - 1);
console.log(arr[0]);
console.log(arr[5000]);
console.log(arr[9999]);
