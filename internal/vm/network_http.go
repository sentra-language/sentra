// Package vm - HTTP network functions for Sentra VM
package vm

import (
	"sentra/internal/network"
)

// RegisterHTTPFunctions registers HTTP-related functions to the VM
func RegisterHTTPFunctions(vm *EnhancedVM, netMod *network.NetworkModule) {
	httpFunctions := map[string]*NativeFunction{
		"http_get": {
			Name:  "http_get",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				url := ToString(args[0])
				resp, err := netMod.HTTPGet(url)
				if err != nil {
					return nil, err
				}
				
				result := &Map{Items: make(map[string]Value)}
				result.Items["status_code"] = float64(resp.StatusCode)
				result.Items["status"] = resp.Status
				result.Items["body"] = resp.Body
				result.Items["headers"] = convertHeadersToMap(resp.Headers)
				
				return result, nil
			},
		},
		
		"http_post": {
			Name:  "http_post",
			Arity: 3,
			Function: func(args []Value) (Value, error) {
				url := ToString(args[0])
				body := ToString(args[1])
				headers := extractHeaders(args[2])
				
				resp, err := netMod.HTTPPost(url, []byte(body), headers)
				if err != nil {
					return nil, err
				}
				
				result := &Map{Items: make(map[string]Value)}
				result.Items["status_code"] = float64(resp.StatusCode)
				result.Items["status"] = resp.Status
				result.Items["body"] = resp.Body
				result.Items["headers"] = convertHeadersToMap(resp.Headers)
				
				return result, nil
			},
		},
		
		"http_put": {
			Name:  "http_put",
			Arity: 3,
			Function: func(args []Value) (Value, error) {
				url := ToString(args[0])
				body := ToString(args[1])
				headers := extractHeaders(args[2])
				
				resp, err := netMod.HTTPPut(url, []byte(body), headers)
				if err != nil {
					return nil, err
				}
				
				result := &Map{Items: make(map[string]Value)}
				result.Items["status_code"] = float64(resp.StatusCode)
				result.Items["status"] = resp.Status
				result.Items["body"] = resp.Body
				result.Items["headers"] = convertHeadersToMap(resp.Headers)
				
				return result, nil
			},
		},
		
		"http_delete": {
			Name:  "http_delete",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				url := ToString(args[0])
				resp, err := netMod.HTTPDelete(url)
				if err != nil {
					return nil, err
				}
				
				result := &Map{Items: make(map[string]Value)}
				result.Items["status_code"] = float64(resp.StatusCode)
				result.Items["status"] = resp.Status
				result.Items["body"] = resp.Body
				result.Items["headers"] = convertHeadersToMap(resp.Headers)
				
				return result, nil
			},
		},
		
		"http_request": {
			Name:  "http_request",
			Arity: 4,
			Function: func(args []Value) (Value, error) {
				method := ToString(args[0])
				url := ToString(args[1])
				headers := extractHeaders(args[2])
				body := ToString(args[3])
				
				resp, err := netMod.HTTPRequest(method, url, headers, []byte(body))
				if err != nil {
					return nil, err
				}
				
				result := &Map{Items: make(map[string]Value)}
				result.Items["status_code"] = float64(resp.StatusCode)
				result.Items["status"] = resp.Status
				result.Items["body"] = resp.Body
				result.Items["headers"] = convertHeadersToMap(resp.Headers)
				
				return result, nil
			},
		},
		
		"http_download": {
			Name:  "http_download",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				url := ToString(args[0])
				data, err := netMod.Download(url)
				if err != nil {
					return nil, err
				}
				
				return string(data), nil
			},
		},
		
		"http_json": {
			Name:  "http_json",
			Arity: 3,
			Function: func(args []Value) (Value, error) {
				method := ToString(args[0])
				url := ToString(args[1])
				
				// Convert Sentra map to Go map for JSON encoding
				var data interface{}
				if m, ok := args[2].(*Map); ok {
					data = mapToInterface(m)
				} else {
					data = args[2]
				}
				
				resp, err := netMod.JSONRequest(method, url, data)
				if err != nil {
					return nil, err
				}
				
				result := &Map{Items: make(map[string]Value)}
				result.Items["status_code"] = float64(resp.StatusCode)
				result.Items["status"] = resp.Status
				result.Items["body"] = resp.Body
				result.Items["headers"] = convertHeadersToMap(resp.Headers)
				
				return result, nil
			},
		},
	}
	
	// Register all HTTP functions
	for name, fn := range httpFunctions {
		vm.AddBuiltinFunction(name, fn)
	}
}

// Helper function to extract headers from Sentra map
func extractHeaders(v Value) map[string]string {
	headers := make(map[string]string)
	
	if m, ok := v.(*Map); ok {
		for key, value := range m.Items {
			headers[key] = ToString(value)
		}
	}
	
	return headers
}

// Helper function to convert headers to Sentra map
func convertHeadersToMap(headers map[string]string) *Map {
	m := &Map{Items: make(map[string]Value)}
	
	for key, value := range headers {
		m.Items[key] = value
	}
	
	return m
}

// Helper function to convert Sentra map to interface{} for JSON
func mapToInterface(m *Map) map[string]interface{} {
	result := make(map[string]interface{})
	
	for key, value := range m.Items {
		switch v := value.(type) {
		case *Map:
			result[key] = mapToInterface(v)
		case *Array:
			arr := make([]interface{}, len(v.Elements))
			for i, elem := range v.Elements {
				if subMap, ok := elem.(*Map); ok {
					arr[i] = mapToInterface(subMap)
				} else {
					arr[i] = elem
				}
			}
			result[key] = arr
		default:
			result[key] = v
		}
	}
	
	return result
}