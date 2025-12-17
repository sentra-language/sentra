function createGraph(nodes, edges) {
    let graph = [];
    for (let i = 0; i < nodes; i++) {
        graph.push([]);
    }
    
    let seed = 42;
    for (let e = 0; e < edges; e++) {
        seed = (seed * 1103515245 + 12345) % 2147483648;
        let from = seed % nodes;
        seed = (seed * 1103515245 + 12345) % 2147483648;
        let to = seed % nodes;
        graph[from].push(to);
    }
    return graph;
}

function dfs(graph, start, visited) {
    if (visited[start] === 1) {
        return 0;
    }
    visited[start] = 1;
    let count = 1;
    let neighbors = graph[start];
    for (let i = 0; i < neighbors.length; i++) {
        count += dfs(graph, neighbors[i], visited);
    }
    return count;
}

function newVisited(n) {
    return new Array(n).fill(0);
}

let nodes = 500;
let edges = 2000;
let graph = createGraph(nodes, edges);

let total = 0;
for (let run = 0; run < 50; run++) {
    let visited = newVisited(nodes);
    total += dfs(graph, 0, visited);
}
console.log(total);
