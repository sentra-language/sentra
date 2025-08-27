// Package network - Socket utility functions
package network

import "fmt"

// CloseListener closes a server listener
func (n *NetworkModule) CloseListener(listenerID string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	
	listener, exists := n.Listeners[listenerID]
	if !exists {
		return fmt.Errorf("listener not found: %s", listenerID)
	}
	
	var err error
	if listener.Listener != nil {
		err = listener.Listener.Close()
	} else if listener.UDPConn != nil {
		err = listener.UDPConn.Close()
	}
	
	listener.Active = false
	delete(n.Listeners, listenerID)
	return err
}

// CloseAny closes either a socket or a listener
func (n *NetworkModule) CloseAny(id string) error {
	// Try to close as socket first
	n.mu.RLock()
	_, isSocket := n.Sockets[id]
	_, isListener := n.Listeners[id]
	n.mu.RUnlock()
	
	if isSocket {
		return n.CloseSocket(id)
	} else if isListener {
		return n.CloseListener(id)
	}
	
	return fmt.Errorf("no socket or listener found with ID: %s", id)
}