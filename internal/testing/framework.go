// internal/testing/framework.go
package testing

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

// TestResult represents the result of a single test
type TestResult struct {
	Name     string
	File     string
	Passed   bool
	Failed   bool
	Skipped  bool
	Duration time.Duration
	Error    error
	Message  string
}

// TestSuite represents a collection of tests
type TestSuite struct {
	Name        string
	File        string
	Tests       []TestCase
	BeforeAll   func() error
	AfterAll    func() error
	BeforeEach  func() error
	AfterEach   func() error
	Results     []TestResult
	StartTime   time.Time
	EndTime     time.Time
}

// TestCase represents a single test case
type TestCase struct {
	Name        string
	Description string
	Function    func(*TestContext) error
	Skip        bool
	Only        bool // For focused testing
	Timeout     time.Duration
}

// TestContext provides testing utilities to test functions
type TestContext struct {
	t            *TestRunner
	currentTest  *TestCase
	suite        *TestSuite
	assertions   int
	failures     []string
	logs         []string
}

// TestRunner manages test execution
type TestRunner struct {
	suites       []*TestSuite
	currentSuite *TestSuite
	config       *TestConfig
	reporter     TestReporter
	stats        *TestStats
}

// TestConfig holds configuration for test execution
type TestConfig struct {
	Verbose      bool
	Parallel     bool
	Filter       string
	Timeout      time.Duration
	FailFast     bool
	Coverage     bool
	OutputFormat string // "text", "json", "junit"
}

// TestStats tracks overall test statistics
type TestStats struct {
	TotalTests   int
	PassedTests  int
	FailedTests  int
	SkippedTests int
	TotalTime    time.Duration
	Suites       int
}

// TestReporter interface for different output formats
type TestReporter interface {
	StartSuite(suite *TestSuite)
	EndSuite(suite *TestSuite)
	TestPassed(result TestResult)
	TestFailed(result TestResult)
	TestSkipped(result TestResult)
	Summary(stats *TestStats)
}

// NewTestRunner creates a new test runner
func NewTestRunner(config *TestConfig) *TestRunner {
	if config == nil {
		config = &TestConfig{
			Verbose:      false,
			Parallel:     false,
			Timeout:      30 * time.Second,
			OutputFormat: "text",
		}
	}
	
	var reporter TestReporter
	switch config.OutputFormat {
	case "json":
		reporter = NewJSONReporter()
	case "junit":
		reporter = NewJUnitReporter()
	default:
		reporter = NewTextReporter(config.Verbose)
	}
	
	return &TestRunner{
		suites:   make([]*TestSuite, 0),
		config:   config,
		reporter: reporter,
		stats:    &TestStats{},
	}
}

// AddSuite adds a test suite to the runner
func (r *TestRunner) AddSuite(suite *TestSuite) {
	r.suites = append(r.suites, suite)
}

// Run executes all test suites
func (r *TestRunner) Run() *TestStats {
	startTime := time.Now()
	
	for _, suite := range r.suites {
		if r.shouldRunSuite(suite) {
			r.runSuite(suite)
			
			if r.config.FailFast && r.hasFailures(suite) {
				break
			}
		}
	}
	
	r.stats.TotalTime = time.Since(startTime)
	r.reporter.Summary(r.stats)
	
	return r.stats
}

// runSuite executes a single test suite
func (r *TestRunner) runSuite(suite *TestSuite) {
	r.currentSuite = suite
	suite.StartTime = time.Now()
	r.reporter.StartSuite(suite)
	
	// Run BeforeAll hook
	if suite.BeforeAll != nil {
		if err := suite.BeforeAll(); err != nil {
			// Mark all tests as failed if BeforeAll fails
			for _, test := range suite.Tests {
				result := TestResult{
					Name:    test.Name,
					File:    suite.File,
					Failed:  true,
					Error:   fmt.Errorf("BeforeAll failed: %v", err),
				}
				suite.Results = append(suite.Results, result)
				r.reporter.TestFailed(result)
			}
			return
		}
	}
	
	// Run tests
	for _, test := range suite.Tests {
		if r.shouldRunTest(&test) {
			r.runTest(suite, &test)
			
			if r.config.FailFast && r.hasTestFailure(&test, suite) {
				break
			}
		}
	}
	
	// Run AfterAll hook
	if suite.AfterAll != nil {
		suite.AfterAll()
	}
	
	suite.EndTime = time.Now()
	r.reporter.EndSuite(suite)
	r.updateStats(suite)
}

// runTest executes a single test
func (r *TestRunner) runTest(suite *TestSuite, test *TestCase) {
	if test.Skip {
		result := TestResult{
			Name:    test.Name,
			File:    suite.File,
			Skipped: true,
		}
		suite.Results = append(suite.Results, result)
		r.reporter.TestSkipped(result)
		return
	}
	
	// Create test context
	ctx := &TestContext{
		t:           r,
		currentTest: test,
		suite:       suite,
		assertions:  0,
		failures:    make([]string, 0),
		logs:        make([]string, 0),
	}
	
	// Run BeforeEach hook
	if suite.BeforeEach != nil {
		if err := suite.BeforeEach(); err != nil {
			result := TestResult{
				Name:   test.Name,
				File:   suite.File,
				Failed: true,
				Error:  fmt.Errorf("BeforeEach failed: %v", err),
			}
			suite.Results = append(suite.Results, result)
			r.reporter.TestFailed(result)
			return
		}
	}
	
	// Run the test
	startTime := time.Now()
	err := r.executeTest(test, ctx)
	duration := time.Since(startTime)
	
	// Run AfterEach hook
	if suite.AfterEach != nil {
		suite.AfterEach()
	}
	
	// Create result
	result := TestResult{
		Name:     test.Name,
		File:     suite.File,
		Duration: duration,
	}
	
	if err != nil || len(ctx.failures) > 0 {
		result.Failed = true
		result.Error = err
		if len(ctx.failures) > 0 {
			result.Message = strings.Join(ctx.failures, "\n")
		}
		r.reporter.TestFailed(result)
	} else {
		result.Passed = true
		r.reporter.TestPassed(result)
	}
	
	suite.Results = append(suite.Results, result)
}

// executeTest runs a test with timeout
func (r *TestRunner) executeTest(test *TestCase, ctx *TestContext) error {
	timeout := test.Timeout
	if timeout == 0 {
		timeout = r.config.Timeout
	}
	
	done := make(chan error, 1)
	go func() {
		done <- test.Function(ctx)
	}()
	
	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		return fmt.Errorf("test timed out after %v", timeout)
	}
}

// Helper methods for filtering
func (r *TestRunner) shouldRunSuite(suite *TestSuite) bool {
	if r.config.Filter == "" {
		return true
	}
	return strings.Contains(suite.Name, r.config.Filter) ||
	       strings.Contains(suite.File, r.config.Filter)
}

func (r *TestRunner) shouldRunTest(test *TestCase) bool {
	if test.Skip {
		return false
	}
	if r.config.Filter == "" {
		return true
	}
	return strings.Contains(test.Name, r.config.Filter)
}

func (r *TestRunner) hasFailures(suite *TestSuite) bool {
	for _, result := range suite.Results {
		if result.Failed {
			return true
		}
	}
	return false
}

func (r *TestRunner) hasTestFailure(test *TestCase, suite *TestSuite) bool {
	for _, result := range suite.Results {
		if result.Name == test.Name && result.Failed {
			return true
		}
	}
	return false
}

func (r *TestRunner) updateStats(suite *TestSuite) {
	r.stats.Suites++
	for _, result := range suite.Results {
		r.stats.TotalTests++
		if result.Passed {
			r.stats.PassedTests++
		} else if result.Failed {
			r.stats.FailedTests++
		} else if result.Skipped {
			r.stats.SkippedTests++
		}
	}
}

// TestContext methods for assertions
func (ctx *TestContext) Assert(condition bool, message string) {
	ctx.assertions++
	if !condition {
		ctx.failures = append(ctx.failures, fmt.Sprintf("Assertion failed: %s", message))
	}
}

func (ctx *TestContext) AssertEqual(expected, actual interface{}, message string) {
	ctx.assertions++
	if expected != actual {
		ctx.failures = append(ctx.failures, 
			fmt.Sprintf("AssertEqual failed: %s\nExpected: %v\nActual: %v", 
				message, expected, actual))
	}
}

func (ctx *TestContext) AssertNotEqual(expected, actual interface{}, message string) {
	ctx.assertions++
	if expected == actual {
		ctx.failures = append(ctx.failures, 
			fmt.Sprintf("AssertNotEqual failed: %s\nValues are equal: %v", 
				message, expected))
	}
}

func (ctx *TestContext) AssertNil(value interface{}, message string) {
	ctx.assertions++
	if value != nil {
		ctx.failures = append(ctx.failures, 
			fmt.Sprintf("AssertNil failed: %s\nValue is not nil: %v", 
				message, value))
	}
}

func (ctx *TestContext) AssertNotNil(value interface{}, message string) {
	ctx.assertions++
	if value == nil {
		ctx.failures = append(ctx.failures, 
			fmt.Sprintf("AssertNotNil failed: %s\nValue is nil", message))
	}
}

func (ctx *TestContext) AssertTrue(condition bool, message string) {
	ctx.assertions++
	if !condition {
		ctx.failures = append(ctx.failures, 
			fmt.Sprintf("AssertTrue failed: %s", message))
	}
}

func (ctx *TestContext) AssertFalse(condition bool, message string) {
	ctx.assertions++
	if condition {
		ctx.failures = append(ctx.failures, 
			fmt.Sprintf("AssertFalse failed: %s", message))
	}
}

func (ctx *TestContext) Fail(message string) {
	ctx.failures = append(ctx.failures, fmt.Sprintf("Test failed: %s", message))
}

func (ctx *TestContext) Log(message string) {
	ctx.logs = append(ctx.logs, message)
}

func (ctx *TestContext) Skip(reason string) {
	ctx.currentTest.Skip = true
	ctx.Log(fmt.Sprintf("Test skipped: %s", reason))
}

// DiscoverTests finds all test files in a directory
func DiscoverTests(dir string, pattern string) ([]string, error) {
	if pattern == "" {
		pattern = "*_test.sn"
	}
	
	matches, err := filepath.Glob(filepath.Join(dir, pattern))
	if err != nil {
		return nil, err
	}
	
	// Also search subdirectories
	subPattern := filepath.Join(dir, "**", pattern)
	subMatches, err := filepath.Glob(subPattern)
	if err == nil {
		matches = append(matches, subMatches...)
	}
	
	return matches, nil
}