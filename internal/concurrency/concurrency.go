// Package concurrency provides concurrent execution and resource management for Sentra
package concurrency

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// ConcurrencyModule manages concurrent operations and resource pooling
type ConcurrencyModule struct {
	WorkerPools   map[string]*WorkerPool
	RateLimiters  map[string]*RateLimiter
	TaskQueues    map[string]*TaskQueue
	ConnectionPools map[string]*ConnectionPool
	Semaphores    map[string]*Semaphore
	Metrics       *ConcurrencyMetrics
	mu            sync.RWMutex
}

// WorkerPool manages a pool of worker goroutines
type WorkerPool struct {
	ID          string
	Size        int
	Jobs        chan Job
	Results     chan JobResult
	Workers     []*Worker
	Running     bool
	Ctx         context.Context
	Cancel      context.CancelFunc
	WaitGroup   sync.WaitGroup
	Created     time.Time
	TasksTotal  int64
	TasksDone   int64
}

// Worker represents a single worker goroutine
type Worker struct {
	ID       int
	Pool     *WorkerPool
	JobsChan chan Job
	Quit     chan bool
}

// Job represents a unit of work
type Job struct {
	ID       string
	Type     string
	Data     interface{}
	Timeout  time.Duration
	Priority int
	Created  time.Time
}

// JobResult represents the result of a job execution
type JobResult struct {
	JobID     string
	Success   bool
	Result    interface{}
	Error     error
	Duration  time.Duration
	WorkerID  int
	Completed time.Time
}

// TaskQueue manages prioritized task execution
type TaskQueue struct {
	ID       string
	Tasks    chan Task
	Priority chan Task
	High     chan Task
	Normal   chan Task
	Low      chan Task
	Running  bool
	mu       sync.RWMutex
}

// Task represents a queued task
type Task struct {
	ID       string
	Function func() (interface{}, error)
	Priority TaskPriority
	Timeout  time.Duration
	Retries  int
	Created  time.Time
}

// TaskPriority defines task execution priority
type TaskPriority int

const (
	LowPriority TaskPriority = iota
	NormalPriority
	HighPriority
	CriticalPriority
)

// RateLimiter controls the rate of operations
type RateLimiter struct {
	ID        string
	Rate      int           // operations per second
	Burst     int           // burst capacity
	Interval  time.Duration
	Tokens    chan struct{}
	LastRefill time.Time
	mu        sync.Mutex
}

// ConnectionPool manages reusable connections
type ConnectionPool struct {
	ID          string
	MaxSize     int
	MinSize     int
	Connections chan interface{}
	Factory     func() (interface{}, error)
	Validator   func(interface{}) bool
	Closer      func(interface{}) error
	Created     int64
	Active      int64
	Idle        int64
	mu          sync.RWMutex
}

// Semaphore controls access to limited resources
type Semaphore struct {
	ID       string
	Capacity int
	Current  int64
	ch       chan struct{}
	mu       sync.Mutex
}

// ConcurrencyMetrics tracks performance metrics
type ConcurrencyMetrics struct {
	WorkerPoolsActive    int64
	WorkersTotal         int64
	TasksQueued          int64
	TasksProcessing      int64
	TasksCompleted       int64
	TasksFailed          int64
	AvgProcessingTime    time.Duration
	ThroughputPerSecond  float64
	ResourceUtilization  float64
	GoroutineCount       int64
	MemoryUsage          int64
	mu                   sync.RWMutex
}

// NewConcurrencyModule creates a new concurrency module
func NewConcurrencyModule() *ConcurrencyModule {
	return &ConcurrencyModule{
		WorkerPools:     make(map[string]*WorkerPool),
		RateLimiters:    make(map[string]*RateLimiter),
		TaskQueues:      make(map[string]*TaskQueue),
		ConnectionPools: make(map[string]*ConnectionPool),
		Semaphores:      make(map[string]*Semaphore),
		Metrics:         &ConcurrencyMetrics{},
	}
}

// CreateWorkerPool creates a new worker pool
func (cm *ConcurrencyModule) CreateWorkerPool(id string, size int, bufferSize int) (*WorkerPool, error) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if size <= 0 {
		size = runtime.NumCPU()
	}

	ctx, cancel := context.WithCancel(context.Background())

	pool := &WorkerPool{
		ID:       id,
		Size:     size,
		Jobs:     make(chan Job, bufferSize),
		Results:  make(chan JobResult, bufferSize),
		Workers:  make([]*Worker, size),
		Running:  false,
		Ctx:      ctx,
		Cancel:   cancel,
		Created:  time.Now(),
	}

	// Create workers
	for i := 0; i < size; i++ {
		worker := &Worker{
			ID:       i,
			Pool:     pool,
			JobsChan: pool.Jobs,
			Quit:     make(chan bool),
		}
		pool.Workers[i] = worker
	}

	cm.WorkerPools[id] = pool
	atomic.AddInt64(&cm.Metrics.WorkerPoolsActive, 1)
	atomic.AddInt64(&cm.Metrics.WorkersTotal, int64(size))

	return pool, nil
}

// StartWorkerPool starts all workers in the pool
func (cm *ConcurrencyModule) StartWorkerPool(poolID string) error {
	cm.mu.RLock()
	pool, exists := cm.WorkerPools[poolID]
	cm.mu.RUnlock()

	if !exists {
		return fmt.Errorf("worker pool not found: %s", poolID)
	}

	if pool.Running {
		return fmt.Errorf("worker pool already running: %s", poolID)
	}

	pool.Running = true

	// Start workers
	for _, worker := range pool.Workers {
		pool.WaitGroup.Add(1)
		go cm.runWorker(worker)
	}

	return nil
}

// runWorker executes jobs in a worker goroutine
func (cm *ConcurrencyModule) runWorker(worker *Worker) {
	defer worker.Pool.WaitGroup.Done()

	for {
		select {
		case job := <-worker.JobsChan:
			startTime := time.Now()
			atomic.AddInt64(&cm.Metrics.TasksProcessing, 1)

			// Execute job with timeout
			result := cm.executeJob(job, worker)
			result.Duration = time.Since(startTime)
			result.WorkerID = worker.ID

			// Send result
			select {
			case worker.Pool.Results <- result:
				atomic.AddInt64(&worker.Pool.TasksDone, 1)
				atomic.AddInt64(&cm.Metrics.TasksProcessing, -1)
				if result.Success {
					atomic.AddInt64(&cm.Metrics.TasksCompleted, 1)
				} else {
					atomic.AddInt64(&cm.Metrics.TasksFailed, 1)
				}
			case <-worker.Pool.Ctx.Done():
				return
			}

		case <-worker.Quit:
			return

		case <-worker.Pool.Ctx.Done():
			return
		}
	}
}

// executeJob executes a single job
func (cm *ConcurrencyModule) executeJob(job Job, worker *Worker) JobResult {
	result := JobResult{
		JobID:     job.ID,
		Success:   false,
		Completed: time.Now(),
	}

	// Set timeout context if specified
	ctx := worker.Pool.Ctx
	if job.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, job.Timeout)
		defer cancel()
	}

	// Execute job based on type
	done := make(chan struct{})
	go func() {
		defer func() {
			if r := recover(); r != nil {
				result.Error = fmt.Errorf("job panicked: %v", r)
			}
			close(done)
		}()

		switch job.Type {
		case "port_scan":
			result.Result, result.Error = cm.executePortScan(job.Data)
		case "vuln_scan":
			result.Result, result.Error = cm.executeVulnScan(job.Data)
		case "hash_calculate":
			result.Result, result.Error = cm.executeHashCalculation(job.Data)
		case "network_probe":
			result.Result, result.Error = cm.executeNetworkProbe(job.Data)
		case "file_scan":
			result.Result, result.Error = cm.executeFileScan(job.Data)
		default:
			result.Error = fmt.Errorf("unknown job type: %s", job.Type)
		}

		if result.Error == nil {
			result.Success = true
		}
	}()

	// Wait for completion or timeout
	select {
	case <-done:
		return result
	case <-ctx.Done():
		result.Error = fmt.Errorf("job timed out")
		return result
	}
}

// Job execution functions (simplified implementations)
func (cm *ConcurrencyModule) executePortScan(data interface{}) (interface{}, error) {
	// Port scanning logic would be integrated with network module
	return fmt.Sprintf("Port scan completed for %v", data), nil
}

func (cm *ConcurrencyModule) executeVulnScan(data interface{}) (interface{}, error) {
	// Vulnerability scanning logic would be integrated with webclient module
	return fmt.Sprintf("Vulnerability scan completed for %v", data), nil
}

func (cm *ConcurrencyModule) executeHashCalculation(data interface{}) (interface{}, error) {
	// Hash calculation logic would be integrated with filesystem module
	return fmt.Sprintf("Hash calculated for %v", data), nil
}

func (cm *ConcurrencyModule) executeNetworkProbe(data interface{}) (interface{}, error) {
	// Network probing logic would be integrated with network module
	return fmt.Sprintf("Network probe completed for %v", data), nil
}

func (cm *ConcurrencyModule) executeFileScan(data interface{}) (interface{}, error) {
	// File scanning logic would be integrated with filesystem module
	return fmt.Sprintf("File scan completed for %v", data), nil
}

// SubmitJob submits a job to a worker pool
func (cm *ConcurrencyModule) SubmitJob(poolID string, job Job) error {
	cm.mu.RLock()
	pool, exists := cm.WorkerPools[poolID]
	cm.mu.RUnlock()

	if !exists {
		return fmt.Errorf("worker pool not found: %s", poolID)
	}

	if !pool.Running {
		return fmt.Errorf("worker pool not running: %s", poolID)
	}

	atomic.AddInt64(&pool.TasksTotal, 1)
	atomic.AddInt64(&cm.Metrics.TasksQueued, 1)

	select {
	case pool.Jobs <- job:
		atomic.AddInt64(&cm.Metrics.TasksQueued, -1)
		return nil
	case <-pool.Ctx.Done():
		return fmt.Errorf("worker pool shutting down")
	default:
		return fmt.Errorf("job queue full")
	}
}

// CreateRateLimiter creates a new rate limiter
func (cm *ConcurrencyModule) CreateRateLimiter(id string, rate int, burst int) (*RateLimiter, error) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if rate <= 0 {
		return nil, fmt.Errorf("rate must be positive")
	}

	rl := &RateLimiter{
		ID:       id,
		Rate:     rate,
		Burst:    burst,
		Interval: time.Second / time.Duration(rate),
		Tokens:   make(chan struct{}, burst),
		LastRefill: time.Now(),
	}

	// Fill initial tokens
	for i := 0; i < burst; i++ {
		rl.Tokens <- struct{}{}
	}

	// Start token refill goroutine
	go cm.refillTokens(rl)

	cm.RateLimiters[id] = rl
	return rl, nil
}

// refillTokens periodically refills rate limiter tokens
func (cm *ConcurrencyModule) refillTokens(rl *RateLimiter) {
	ticker := time.NewTicker(rl.Interval)
	defer ticker.Stop()

	for range ticker.C {
		rl.mu.Lock()
		select {
		case rl.Tokens <- struct{}{}:
			// Token added
		default:
			// Buffer full, skip
		}
		rl.LastRefill = time.Now()
		rl.mu.Unlock()
	}
}

// Acquire acquires a token from the rate limiter
func (cm *ConcurrencyModule) Acquire(limiterID string, timeout time.Duration) error {
	cm.mu.RLock()
	rl, exists := cm.RateLimiters[limiterID]
	cm.mu.RUnlock()

	if !exists {
		return fmt.Errorf("rate limiter not found: %s", limiterID)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	select {
	case <-rl.Tokens:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("rate limit timeout")
	}
}

// CreateConnectionPool creates a new connection pool
func (cm *ConcurrencyModule) CreateConnectionPool(id string, minSize, maxSize int,
	factory func() (interface{}, error),
	validator func(interface{}) bool,
	closer func(interface{}) error) (*ConnectionPool, error) {

	cm.mu.Lock()
	defer cm.mu.Unlock()

	pool := &ConnectionPool{
		ID:          id,
		MaxSize:     maxSize,
		MinSize:     minSize,
		Connections: make(chan interface{}, maxSize),
		Factory:     factory,
		Validator:   validator,
		Closer:      closer,
	}

	// Pre-fill with minimum connections
	for i := 0; i < minSize; i++ {
		conn, err := factory()
		if err != nil {
			return nil, fmt.Errorf("failed to create initial connection: %v", err)
		}
		pool.Connections <- conn
		atomic.AddInt64(&pool.Created, 1)
		atomic.AddInt64(&pool.Idle, 1)
	}

	cm.ConnectionPools[id] = pool
	return pool, nil
}

// GetConnection gets a connection from the pool
func (cm *ConcurrencyModule) GetConnection(poolID string, timeout time.Duration) (interface{}, error) {
	cm.mu.RLock()
	pool, exists := cm.ConnectionPools[poolID]
	cm.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("connection pool not found: %s", poolID)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	select {
	case conn := <-pool.Connections:
		atomic.AddInt64(&pool.Idle, -1)
		atomic.AddInt64(&pool.Active, 1)

		// Validate connection
		if pool.Validator != nil && !pool.Validator(conn) {
			// Create new connection if validation fails
			newConn, err := pool.Factory()
			if err != nil {
				return nil, err
			}
			return newConn, nil
		}

		return conn, nil

	case <-ctx.Done():
		// Try to create new connection if pool not at max
		if atomic.LoadInt64(&pool.Created) < int64(pool.MaxSize) {
			conn, err := pool.Factory()
			if err != nil {
				return nil, err
			}
			atomic.AddInt64(&pool.Created, 1)
			atomic.AddInt64(&pool.Active, 1)
			return conn, nil
		}
		return nil, fmt.Errorf("connection pool timeout")
	}
}

// ReturnConnection returns a connection to the pool
func (cm *ConcurrencyModule) ReturnConnection(poolID string, conn interface{}) error {
	cm.mu.RLock()
	pool, exists := cm.ConnectionPools[poolID]
	cm.mu.RUnlock()

	if !exists {
		return fmt.Errorf("connection pool not found: %s", poolID)
	}

	atomic.AddInt64(&pool.Active, -1)

	// Validate connection before returning
	if pool.Validator != nil && !pool.Validator(conn) {
		if pool.Closer != nil {
			pool.Closer(conn)
		}
		atomic.AddInt64(&pool.Created, -1)
		return nil
	}

	select {
	case pool.Connections <- conn:
		atomic.AddInt64(&pool.Idle, 1)
		return nil
	default:
		// Pool full, close connection
		if pool.Closer != nil {
			pool.Closer(conn)
		}
		atomic.AddInt64(&pool.Created, -1)
		return nil
	}
}

// CreateSemaphore creates a new semaphore
func (cm *ConcurrencyModule) CreateSemaphore(id string, capacity int) (*Semaphore, error) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	sem := &Semaphore{
		ID:       id,
		Capacity: capacity,
		ch:       make(chan struct{}, capacity),
	}

	cm.Semaphores[id] = sem
	return sem, nil
}

// AcquireSemaphore acquires a semaphore permit
func (cm *ConcurrencyModule) AcquireSemaphore(semID string, timeout time.Duration) error {
	cm.mu.RLock()
	sem, exists := cm.Semaphores[semID]
	cm.mu.RUnlock()

	if !exists {
		return fmt.Errorf("semaphore not found: %s", semID)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	select {
	case sem.ch <- struct{}{}:
		atomic.AddInt64(&sem.Current, 1)
		return nil
	case <-ctx.Done():
		return fmt.Errorf("semaphore acquisition timeout")
	}
}

// ReleaseSemaphore releases a semaphore permit
func (cm *ConcurrencyModule) ReleaseSemaphore(semID string) error {
	cm.mu.RLock()
	sem, exists := cm.Semaphores[semID]
	cm.mu.RUnlock()

	if !exists {
		return fmt.Errorf("semaphore not found: %s", semID)
	}

	select {
	case <-sem.ch:
		atomic.AddInt64(&sem.Current, -1)
		return nil
	default:
		return fmt.Errorf("semaphore not acquired")
	}
}

// CreateTaskQueue creates a prioritized task queue
func (cm *ConcurrencyModule) CreateTaskQueue(id string, bufferSize int) (*TaskQueue, error) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	queue := &TaskQueue{
		ID:       id,
		Tasks:    make(chan Task, bufferSize),
		Priority: make(chan Task, bufferSize),
		High:     make(chan Task, bufferSize/4),
		Normal:   make(chan Task, bufferSize/2),
		Low:      make(chan Task, bufferSize/4),
		Running:  false,
	}

	cm.TaskQueues[id] = queue
	return queue, nil
}

// StartTaskQueue starts processing tasks from the queue
func (cm *ConcurrencyModule) StartTaskQueue(queueID string) error {
	cm.mu.RLock()
	queue, exists := cm.TaskQueues[queueID]
	cm.mu.RUnlock()

	if !exists {
		return fmt.Errorf("task queue not found: %s", queueID)
	}

	if queue.Running {
		return fmt.Errorf("task queue already running: %s", queueID)
	}

	queue.Running = true

	// Start task dispatcher
	go cm.dispatchTasks(queue)

	return nil
}

// dispatchTasks dispatches tasks based on priority
func (cm *ConcurrencyModule) dispatchTasks(queue *TaskQueue) {
	for queue.Running {
		select {
		case task := <-queue.High:
			queue.Tasks <- task
		case task := <-queue.Normal:
			select {
			case highTask := <-queue.High:
				queue.Tasks <- highTask
			default:
				queue.Tasks <- task
			}
		case task := <-queue.Low:
			select {
			case highTask := <-queue.High:
				queue.Tasks <- highTask
			case normalTask := <-queue.Normal:
				queue.Tasks <- normalTask
			default:
				queue.Tasks <- task
			}
		}
	}
}

// EnqueueTask adds a task to the queue
func (cm *ConcurrencyModule) EnqueueTask(queueID string, task Task) error {
	cm.mu.RLock()
	queue, exists := cm.TaskQueues[queueID]
	cm.mu.RUnlock()

	if !exists {
		return fmt.Errorf("task queue not found: %s", queueID)
	}

	var targetQueue chan Task

	switch task.Priority {
	case CriticalPriority, HighPriority:
		targetQueue = queue.High
	case NormalPriority:
		targetQueue = queue.Normal
	case LowPriority:
		targetQueue = queue.Low
	default:
		targetQueue = queue.Normal
	}

	select {
	case targetQueue <- task:
		return nil
	default:
		return fmt.Errorf("task queue full")
	}
}

// GetMetrics returns current concurrency metrics
func (cm *ConcurrencyModule) GetMetrics() *ConcurrencyMetrics {
	cm.Metrics.mu.Lock()
	defer cm.Metrics.mu.Unlock()

	// Update runtime metrics
	cm.Metrics.GoroutineCount = int64(runtime.NumGoroutine())

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	cm.Metrics.MemoryUsage = int64(memStats.Alloc)

	// Calculate resource utilization
	totalWorkers := atomic.LoadInt64(&cm.Metrics.WorkersTotal)
	if totalWorkers > 0 {
		processing := atomic.LoadInt64(&cm.Metrics.TasksProcessing)
		cm.Metrics.ResourceUtilization = float64(processing) / float64(totalWorkers) * 100
	}

	return cm.Metrics
}

// StopWorkerPool stops a worker pool
func (cm *ConcurrencyModule) StopWorkerPool(poolID string, timeout time.Duration) error {
	cm.mu.RLock()
	pool, exists := cm.WorkerPools[poolID]
	cm.mu.RUnlock()

	if !exists {
		return fmt.Errorf("worker pool not found: %s", poolID)
	}

	pool.Running = false
	pool.Cancel()

	// Wait for workers to finish with timeout
	done := make(chan struct{})
	go func() {
		pool.WaitGroup.Wait()
		close(done)
	}()

	select {
	case <-done:
		atomic.AddInt64(&cm.Metrics.WorkerPoolsActive, -1)
		atomic.AddInt64(&cm.Metrics.WorkersTotal, -int64(pool.Size))
		return nil
	case <-time.After(timeout):
		return fmt.Errorf("worker pool shutdown timeout")
	}
}

// Cleanup stops all pools and releases resources
func (cm *ConcurrencyModule) Cleanup() {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	// Stop all worker pools
	for id := range cm.WorkerPools {
		cm.StopWorkerPool(id, 5*time.Second)
	}

	// Stop all task queues
	for _, queue := range cm.TaskQueues {
		queue.Running = false
	}

	// Close all connection pools
	for _, pool := range cm.ConnectionPools {
		for {
			select {
			case conn := <-pool.Connections:
				if pool.Closer != nil {
					pool.Closer(conn)
				}
			default:
				goto nextPool
			}
		}
		nextPool:
	}

	// Clear all maps
	cm.WorkerPools = make(map[string]*WorkerPool)
	cm.RateLimiters = make(map[string]*RateLimiter)
	cm.TaskQueues = make(map[string]*TaskQueue)
	cm.ConnectionPools = make(map[string]*ConnectionPool)
	cm.Semaphores = make(map[string]*Semaphore)
}