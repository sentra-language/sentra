// Package vm - WebSocket network functions for Sentra VM
package vm

import (
	"sentra/internal/network"
	"time"
)

// RegisterWebSocketFunctions registers WebSocket-related functions to the VM
func RegisterWebSocketFunctions(vm *EnhancedVM, netMod *network.NetworkModule) {
	wsFunctions := map[string]*NativeFunction{
		"ws_connect": {
			Name:  "ws_connect",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				url := ToString(args[0])
				conn, err := netMod.WebSocketConnect(url)
				if err != nil {
					return nil, err
				}
				
				result := &Map{Items: make(map[string]Value)}
				result.Items["id"] = conn.ID
				result.Items["url"] = conn.URL
				result.Items["connected"] = true
				
				return result, nil
			},
		},
		
		"ws_send": {
			Name:  "ws_send",
			Arity: 2,
			Function: func(args []Value) (Value, error) {
				connID := ToString(args[0])
				message := ToString(args[1])
				
				err := netMod.WebSocketSend(connID, message)
				if err != nil {
					return false, err
				}
				
				return true, nil
			},
		},
		
		"ws_send_binary": {
			Name:  "ws_send_binary",
			Arity: 2,
			Function: func(args []Value) (Value, error) {
				connID := ToString(args[0])
				data := []byte(ToString(args[1]))
				
				err := netMod.WebSocketSendBinary(connID, data)
				if err != nil {
					return false, err
				}
				
				return true, nil
			},
		},
		
		"ws_receive": {
			Name:  "ws_receive",
			Arity: 2,
			Function: func(args []Value) (Value, error) {
				connID := ToString(args[0])
				timeoutSeconds := ToNumber(args[1])
				
				timeout := time.Duration(timeoutSeconds) * time.Second
				message, err := netMod.WebSocketReceive(connID, timeout)
				if err != nil {
					return nil, err
				}
				
				return message, nil
			},
		},
		
		"ws_close": {
			Name:  "ws_close",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				connID := ToString(args[0])
				
				err := netMod.WebSocketClose(connID)
				if err != nil {
					return false, err
				}
				
				return true, nil
			},
		},
		
		"ws_ping": {
			Name:  "ws_ping",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				connID := ToString(args[0])
				
				err := netMod.WebSocketPing(connID)
				if err != nil {
					return false, err
				}
				
				return true, nil
			},
		},
		
		"ws_listen": {
			Name:  "ws_listen",
			Arity: 2,
			Function: func(args []Value) (Value, error) {
				address := ToString(args[0])
				port := int(ToNumber(args[1]))
				
				server, err := netMod.WebSocketListen(address, port)
				if err != nil {
					return nil, err
				}
				
				result := &Map{Items: make(map[string]Value)}
				result.Items["id"] = server.ID
				result.Items["address"] = server.Address
				result.Items["port"] = float64(server.Port)
				result.Items["listening"] = true
				
				return result, nil
			},
		},
	}
	
	// Register all WebSocket functions
	for name, fn := range wsFunctions {
		vm.AddBuiltinFunction(name, fn)
	}
}