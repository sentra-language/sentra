// Package network - HTTP client implementation
package network

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

// HTTPRequest represents an HTTP request
type HTTPRequest struct {
	Method  string
	URL     string
	Headers map[string]string
	Body    []byte
	Timeout time.Duration
}

// HTTPResponse represents an HTTP response
type HTTPResponse struct {
	StatusCode int
	Status     string
	Headers    map[string]string
	Body       string
	Error      error
}

// HTTPGet performs an HTTP GET request
func (n *NetworkModule) HTTPGet(url string) (*HTTPResponse, error) {
	return n.HTTPRequest("GET", url, nil, nil)
}

// HTTPPost performs an HTTP POST request
func (n *NetworkModule) HTTPPost(url string, body []byte, headers map[string]string) (*HTTPResponse, error) {
	return n.HTTPRequest("POST", url, headers, body)
}

// HTTPPut performs an HTTP PUT request
func (n *NetworkModule) HTTPPut(url string, body []byte, headers map[string]string) (*HTTPResponse, error) {
	return n.HTTPRequest("PUT", url, headers, body)
}

// HTTPDelete performs an HTTP DELETE request
func (n *NetworkModule) HTTPDelete(url string) (*HTTPResponse, error) {
	return n.HTTPRequest("DELETE", url, nil, nil)
}

// HTTPRequest performs a generic HTTP request
func (n *NetworkModule) HTTPRequest(method, url string, headers map[string]string, body []byte) (*HTTPResponse, error) {
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	var req *http.Request
	var err error

	if body != nil {
		req, err = http.NewRequest(method, url, bytes.NewBuffer(body))
	} else {
		req, err = http.NewRequest(method, url, nil)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	// Set default headers
	req.Header.Set("User-Agent", "Sentra/1.0")
	
	// Set custom headers
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	// Set Content-Type if not provided
	if _, ok := headers["Content-Type"]; !ok && body != nil {
		if json.Valid(body) {
			req.Header.Set("Content-Type", "application/json")
		} else {
			req.Header.Set("Content-Type", "text/plain")
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return &HTTPResponse{
			Error: err,
		}, err
	}
	defer resp.Body.Close()

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return &HTTPResponse{
			StatusCode: resp.StatusCode,
			Status:     resp.Status,
			Error:      err,
		}, err
	}

	// Convert headers to map
	respHeaders := make(map[string]string)
	for key, values := range resp.Header {
		respHeaders[key] = strings.Join(values, ", ")
	}

	return &HTTPResponse{
		StatusCode: resp.StatusCode,
		Status:     resp.Status,
		Headers:    respHeaders,
		Body:       string(respBody),
		Error:      nil,
	}, nil
}

// JSONRequest performs an HTTP request with JSON body
func (n *NetworkModule) JSONRequest(method, url string, data interface{}) (*HTTPResponse, error) {
	jsonBody, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JSON: %v", err)
	}

	headers := map[string]string{
		"Content-Type": "application/json",
		"Accept":       "application/json",
	}

	return n.HTTPRequest(method, url, headers, jsonBody)
}

// Download downloads a file from URL
func (n *NetworkModule) Download(url string) ([]byte, error) {
	resp, err := n.HTTPGet(url)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("download failed with status: %s", resp.Status)
	}

	return []byte(resp.Body), nil
}