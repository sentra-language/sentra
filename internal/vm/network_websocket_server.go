// Package vm - Enhanced WebSocket server functions for Sentra VM
package vm

import (
	"sentra/internal/network"
	"time"
)

// RegisterWebSocketServerFunctions registers enhanced WebSocket server functions to the VM
func RegisterWebSocketServerFunctions(vm *EnhancedVM, netMod *network.NetworkModule) {
	wsServerFunctions := map[string]*NativeFunction{
		"ws_server_accept": {
			Name:  "ws_server_accept",
			Arity: 2,
			Function: func(args []Value) (Value, error) {
				serverID := ToString(args[0])
				timeout := int(ToNumber(args[1]))
				
				client, err := netMod.WebSocketAccept(serverID, timeout)
				if err != nil {
					return nil, err
				}
				
				result := &Map{Items: make(map[string]Value)}
				result.Items["id"] = client.ID
				result.Items["server"] = true
				
				return result, nil
			},
		},
		
		"ws_server_broadcast": {
			Name:  "ws_server_broadcast",
			Arity: 2,
			Function: func(args []Value) (Value, error) {
				serverID := ToString(args[0])
				message := ToString(args[1])
				
				err := netMod.WebSocketBroadcast(serverID, message)
				if err != nil {
					return false, err
				}
				
				return true, nil
			},
		},
		
		"ws_server_get_clients": {
			Name:  "ws_server_get_clients",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				serverID := ToString(args[0])
				
				clientIDs, err := netMod.WebSocketGetClients(serverID)
				if err != nil {
					return nil, err
				}
				
				// Convert to Sentra array
				arr := &Array{Elements: make([]Value, len(clientIDs))}
				for i, id := range clientIDs {
					arr.Elements[i] = id
				}
				
				return arr, nil
			},
		},
		
		"ws_server_send_to": {
			Name:  "ws_server_send_to",
			Arity: 3,
			Function: func(args []Value) (Value, error) {
				serverID := ToString(args[0])
				clientID := ToString(args[1])
				message := ToString(args[2])
				
				err := netMod.WebSocketSendToClient(serverID, clientID, message)
				if err != nil {
					return false, err
				}
				
				return true, nil
			},
		},
		
		"ws_server_receive_from": {
			Name:  "ws_server_receive_from",
			Arity: 2,
			Function: func(args []Value) (Value, error) {
				serverID := ToString(args[0])
				clientID := ToString(args[1])
				
				message, err := netMod.WebSocketReceiveFromClient(serverID, clientID)
				if err != nil {
					return nil, err
				}
				
				return message, nil
			},
		},
		
		"ws_server_disconnect": {
			Name:  "ws_server_disconnect",
			Arity: 2,
			Function: func(args []Value) (Value, error) {
				serverID := ToString(args[0])
				clientID := ToString(args[1])
				
				err := netMod.WebSocketDisconnectClient(serverID, clientID)
				if err != nil {
					return false, err
				}
				
				return true, nil
			},
		},
		
		"ws_server_stop": {
			Name:  "ws_server_stop",
			Arity: 1,
			Function: func(args []Value) (Value, error) {
				serverID := ToString(args[0])
				
				err := netMod.WebSocketStopServer(serverID)
				if err != nil {
					return false, err
				}
				
				return true, nil
			},
		},
		
		"ws_server_wait_connection": {
			Name:  "ws_server_wait_connection",
			Arity: 2,
			Function: func(args []Value) (Value, error) {
				serverID := ToString(args[0])
				timeoutSec := ToNumber(args[1])
				
				// Try to get a connection with timeout
				endTime := time.Now().Add(time.Duration(timeoutSec) * time.Second)
				
				for time.Now().Before(endTime) {
					client, err := netMod.WebSocketAccept(serverID, 1)
					if err == nil {
						result := &Map{Items: make(map[string]Value)}
						result.Items["id"] = client.ID
						result.Items["connected"] = true
						return result, nil
					}
					time.Sleep(100 * time.Millisecond)
				}
				
				return nil, nil
			},
		},
	}
	
	// Register all WebSocket server functions
	for name, fn := range wsServerFunctions {
		vm.AddBuiltinFunction(name, fn)
	}
}