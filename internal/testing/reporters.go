// internal/testing/reporters.go
package testing

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"strings"
	"time"
)

// TextReporter outputs human-readable test results
type TextReporter struct {
	verbose bool
	indent  int
}

func NewTextReporter(verbose bool) *TextReporter {
	return &TextReporter{
		verbose: verbose,
		indent:  0,
	}
}

func (r *TextReporter) StartSuite(suite *TestSuite) {
	fmt.Printf("\n📦 Running test suite: %s\n", suite.Name)
	if suite.File != "" {
		fmt.Printf("   File: %s\n", suite.File)
	}
	r.indent = 2
}

func (r *TextReporter) EndSuite(suite *TestSuite) {
	duration := suite.EndTime.Sub(suite.StartTime)
	fmt.Printf("   Suite completed in %v\n", duration)
	r.indent = 0
}

func (r *TextReporter) TestPassed(result TestResult) {
	symbol := "✓"
	color := "\033[32m" // Green
	reset := "\033[0m"
	
	fmt.Printf("%s%s%s %s%s (%v)\n", 
		strings.Repeat(" ", r.indent),
		color, symbol, result.Name, reset, result.Duration)
	
	if r.verbose && result.Message != "" {
		fmt.Printf("%s  %s\n", strings.Repeat(" ", r.indent+2), result.Message)
	}
}

func (r *TextReporter) TestFailed(result TestResult) {
	symbol := "✗"
	color := "\033[31m" // Red
	reset := "\033[0m"
	
	fmt.Printf("%s%s%s %s%s (%v)\n", 
		strings.Repeat(" ", r.indent),
		color, symbol, result.Name, reset, result.Duration)
	
	if result.Error != nil {
		fmt.Printf("%s  Error: %v\n", strings.Repeat(" ", r.indent+2), result.Error)
	}
	if result.Message != "" {
		lines := strings.Split(result.Message, "\n")
		for _, line := range lines {
			fmt.Printf("%s  %s\n", strings.Repeat(" ", r.indent+2), line)
		}
	}
}

func (r *TextReporter) TestSkipped(result TestResult) {
	symbol := "⊘"
	color := "\033[33m" // Yellow
	reset := "\033[0m"
	
	fmt.Printf("%s%s%s %s (skipped)%s\n", 
		strings.Repeat(" ", r.indent),
		color, symbol, result.Name, reset)
}

func (r *TextReporter) Summary(stats *TestStats) {
	fmt.Printf("\n" + strings.Repeat("=", 60) + "\n")
	fmt.Printf("📊 Test Results Summary\n")
	fmt.Printf(strings.Repeat("=", 60) + "\n")
	
	fmt.Printf("Total Tests:    %d\n", stats.TotalTests)
	
	if stats.PassedTests > 0 {
		fmt.Printf("\033[32m✓ Passed:       %d\033[0m\n", stats.PassedTests)
	}
	
	if stats.FailedTests > 0 {
		fmt.Printf("\033[31m✗ Failed:       %d\033[0m\n", stats.FailedTests)
	}
	
	if stats.SkippedTests > 0 {
		fmt.Printf("\033[33m⊘ Skipped:      %d\033[0m\n", stats.SkippedTests)
	}
	
	fmt.Printf("Test Suites:    %d\n", stats.Suites)
	fmt.Printf("Total Time:     %v\n", stats.TotalTime)
	
	if stats.FailedTests == 0 {
		fmt.Printf("\n\033[32m🎉 All tests passed!\033[0m\n")
	} else {
		fmt.Printf("\n\033[31m❌ Some tests failed.\033[0m\n")
	}
}

// JSONReporter outputs test results in JSON format
type JSONReporter struct {
	results []JSONTestResult
}

type JSONTestResult struct {
	Suite    string        `json:"suite"`
	Test     string        `json:"test"`
	Passed   bool          `json:"passed"`
	Failed   bool          `json:"failed"`
	Skipped  bool          `json:"skipped"`
	Duration time.Duration `json:"duration"`
	Error    string        `json:"error,omitempty"`
	Message  string        `json:"message,omitempty"`
}

type JSONSummary struct {
	Results      []JSONTestResult `json:"results"`
	TotalTests   int              `json:"total_tests"`
	PassedTests  int              `json:"passed_tests"`
	FailedTests  int              `json:"failed_tests"`
	SkippedTests int              `json:"skipped_tests"`
	TotalTime    time.Duration    `json:"total_time"`
}

func NewJSONReporter() *JSONReporter {
	return &JSONReporter{
		results: make([]JSONTestResult, 0),
	}
}

func (r *JSONReporter) StartSuite(suite *TestSuite) {
	// No output during execution for JSON
}

func (r *JSONReporter) EndSuite(suite *TestSuite) {
	// No output during execution for JSON
}

func (r *JSONReporter) TestPassed(result TestResult) {
	r.results = append(r.results, JSONTestResult{
		Test:     result.Name,
		Suite:    result.File,
		Passed:   true,
		Duration: result.Duration,
		Message:  result.Message,
	})
}

func (r *JSONReporter) TestFailed(result TestResult) {
	errorMsg := ""
	if result.Error != nil {
		errorMsg = result.Error.Error()
	}
	
	r.results = append(r.results, JSONTestResult{
		Test:     result.Name,
		Suite:    result.File,
		Failed:   true,
		Duration: result.Duration,
		Error:    errorMsg,
		Message:  result.Message,
	})
}

func (r *JSONReporter) TestSkipped(result TestResult) {
	r.results = append(r.results, JSONTestResult{
		Test:    result.Name,
		Suite:   result.File,
		Skipped: true,
		Message: result.Message,
	})
}

func (r *JSONReporter) Summary(stats *TestStats) {
	summary := JSONSummary{
		Results:      r.results,
		TotalTests:   stats.TotalTests,
		PassedTests:  stats.PassedTests,
		FailedTests:  stats.FailedTests,
		SkippedTests: stats.SkippedTests,
		TotalTime:    stats.TotalTime,
	}
	
	output, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		fmt.Printf("Error generating JSON output: %v\n", err)
		return
	}
	
	fmt.Println(string(output))
}

// JUnitReporter outputs test results in JUnit XML format
type JUnitReporter struct {
	testSuites []JUnitTestSuite
}

type JUnitTestSuites struct {
	XMLName    xml.Name         `xml:"testsuites"`
	TestSuites []JUnitTestSuite `xml:"testsuite"`
}

type JUnitTestSuite struct {
	XMLName   xml.Name        `xml:"testsuite"`
	Name      string          `xml:"name,attr"`
	Tests     int             `xml:"tests,attr"`
	Failures  int             `xml:"failures,attr"`
	Skipped   int             `xml:"skipped,attr"`
	Time      float64         `xml:"time,attr"`
	TestCases []JUnitTestCase `xml:"testcase"`
}

type JUnitTestCase struct {
	XMLName   xml.Name      `xml:"testcase"`
	Name      string        `xml:"name,attr"`
	ClassName string        `xml:"classname,attr"`
	Time      float64       `xml:"time,attr"`
	Failure   *JUnitFailure `xml:"failure,omitempty"`
	Skipped   *JUnitSkipped `xml:"skipped,omitempty"`
}

type JUnitFailure struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Content string `xml:",chardata"`
}

type JUnitSkipped struct {
	Message string `xml:"message,attr,omitempty"`
}

func NewJUnitReporter() *JUnitReporter {
	return &JUnitReporter{
		testSuites: make([]JUnitTestSuite, 0),
	}
}

func (r *JUnitReporter) StartSuite(suite *TestSuite) {
	// No output during execution for JUnit
}

func (r *JUnitReporter) EndSuite(suite *TestSuite) {
	junitSuite := JUnitTestSuite{
		Name:      suite.Name,
		Tests:     len(suite.Results),
		Time:      suite.EndTime.Sub(suite.StartTime).Seconds(),
		TestCases: make([]JUnitTestCase, 0),
	}
	
	for _, result := range suite.Results {
		testCase := JUnitTestCase{
			Name:      result.Name,
			ClassName: suite.Name,
			Time:      result.Duration.Seconds(),
		}
		
		if result.Failed {
			junitSuite.Failures++
			testCase.Failure = &JUnitFailure{
				Type:    "AssertionError",
				Message: result.Message,
			}
			if result.Error != nil {
				testCase.Failure.Content = result.Error.Error()
			}
		} else if result.Skipped {
			junitSuite.Skipped++
			testCase.Skipped = &JUnitSkipped{
				Message: result.Message,
			}
		}
		
		junitSuite.TestCases = append(junitSuite.TestCases, testCase)
	}
	
	r.testSuites = append(r.testSuites, junitSuite)
}

func (r *JUnitReporter) TestPassed(result TestResult) {
	// Handled in EndSuite
}

func (r *JUnitReporter) TestFailed(result TestResult) {
	// Handled in EndSuite
}

func (r *JUnitReporter) TestSkipped(result TestResult) {
	// Handled in EndSuite
}

func (r *JUnitReporter) Summary(stats *TestStats) {
	suites := JUnitTestSuites{
		TestSuites: r.testSuites,
	}
	
	output, err := xml.MarshalIndent(suites, "", "  ")
	if err != nil {
		fmt.Printf("Error generating JUnit XML output: %v\n", err)
		return
	}
	
	fmt.Println(xml.Header)
	fmt.Println(string(output))
}