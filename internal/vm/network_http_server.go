// Package vm - HTTP server functions for Sentra VM
package vm

import (
	"sentra/internal/network"
)

// RegisterHTTPServerFunctions registers HTTP server-related functions to the VM
func RegisterHTTPServerFunctions(vm *EnhancedVM, netMod *network.NetworkModule) {
	httpServerFunctions := map[string]*NativeFunction{
		"http_server_create": {
			Name:  "http_server_create",
			Arity: 2,
			Function: func(args []Value) (Value, error) {
				address := ToString(args[0])
				port := int(ToNumber(args[1]))
				
				server, err := netMod.CreateHTTPServer(address, port)
				if err != nil {
					return nil, err
				}
				
				result := &Map{Items: make(map[string]Value)}
				result.Items["id"] = server.ID
				result.Items["address"] = server.Address
				result.Items["port"] = float64(server.Port)
				result.Items["running"] = false
				
				return result, nil
			},
		},
		
		"http_server_route": {
			Name:  "http_server_route",
			Arity: 4,
			Function: func(args []Value) (Value, error) {
				serverID := ToString(args[0])
				method := ToString(args[1])
				path := ToString(args[2])
				
				// The handler should be a function value
				// For now, we'll accept any value and create a simple handler
				// Full implementation would execute Sentra functions
				
				// Create wrapper that calls Sentra function
				handler := func(req *network.HTTPServerRequest) *network.HTTPServerResponse {
					// Convert request to Sentra map
					reqMap := &Map{Items: make(map[string]Value)}
					reqMap.Items["method"] = req.Method
					reqMap.Items["path"] = req.Path
					reqMap.Items["body"] = req.Body
					
					// Convert headers to map
					headersMap := &Map{Items: make(map[string]Value)}
					for k, v := range req.Headers {
						headersMap.Items[k] = v
					}
					reqMap.Items["headers"] = headersMap
					
					// Convert query params to map
					queryMap := &Map{Items: make(map[string]Value)}
					for k, v := range req.Query {
						queryMap.Items[k] = v
					}
					reqMap.Items["query"] = queryMap
					
					// Call the Sentra handler function
					// Note: This is simplified - in real implementation would need proper VM context
					response := &network.HTTPServerResponse{
						StatusCode: 200,
						Headers:    make(map[string]string),
						Body:       "OK",
					}
					
					// For now, return a simple response
					// Full implementation would execute the Sentra function
					return response
				}
				
				err := netMod.AddRoute(serverID, method, path, handler)
				if err != nil {
					return false, err
				}
				
				return true, nil
			},
		},
		
		"http_server_start": {
			Name:  "http_server_start",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				serverID := ToString(args[0])
				
				err := netMod.StartHTTPServer(serverID)
				if err != nil {
					return false, err
				}
				
				return true, nil
			},
		},
		
		"http_server_stop": {
			Name:  "http_server_stop",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				serverID := ToString(args[0])
				
				err := netMod.StopHTTPServer(serverID)
				if err != nil {
					return false, err
				}
				
				return true, nil
			},
		},
		
		"http_server_static": {
			Name:  "http_server_static",
			Arity: 3,
			Function: func(args []Value) (Value, error) {
				serverID := ToString(args[0])
				urlPath := ToString(args[1])
				directory := ToString(args[2])
				
				err := netMod.ServeStatic(serverID, urlPath, directory)
				if err != nil {
					return false, err
				}
				
				return true, nil
			},
		},
		
		"http_response": {
			Name:  "http_response",
			Arity: 3,
			Function: func(args []Value) (Value, error) {
				statusCode := int(ToNumber(args[0]))
				body := ToString(args[1])
				
				// Extract headers if provided
				headers := make(map[string]string)
				if m, ok := args[2].(*Map); ok {
					for key, value := range m.Items {
						headers[key] = ToString(value)
					}
				}
				
				result := &Map{Items: make(map[string]Value)}
				result.Items["status_code"] = float64(statusCode)
				result.Items["body"] = body
				result.Items["headers"] = convertHeadersToMap(headers)
				
				return result, nil
			},
		},
	}
	
	// Register all HTTP server functions
	for name, fn := range httpServerFunctions {
		vm.AddBuiltinFunction(name, fn)
	}
}