package memory

// IntegratedMemoryModule combines stub and enhanced forensics
type IntegratedMemoryModule struct {
	*MemoryModule
	*EnhancedForensics
}

// NewIntegratedMemoryModule creates a module with real forensics capabilities
func NewIntegratedMemoryModule() *IntegratedMemoryModule {
	return &IntegratedMemoryModule{
		MemoryModule:      NewMemoryModule(),
		EnhancedForensics: NewEnhancedForensics(),
	}
}

// EnumProcesses returns real process information
func (m *IntegratedMemoryModule) EnumProcesses() interface{} {
	processes, err := m.EnhancedForensics.EnumerateProcesses()
	if err != nil {
		return []interface{}{}
	}
	
	// Convert to interface array for Sentra
	result := make([]interface{}, len(processes))
	for i, p := range processes {
		result[i] = map[string]interface{}{
			"pid":         p.PID,
			"name":        p.Name,
			"path":        p.Path,
			"ppid":        p.ParentPID,
			"workingset":  p.WorkingSet,
			"virtualsize": p.VirtualSize,
			"commandline": p.CommandLine,
			"threads":     p.Threads,
			"handles":     p.Handles,
		}
	}
	
	return result
}

// FindProcess returns processes matching a name
func (m *IntegratedMemoryModule) FindProcess(name string) interface{} {
	processes, err := m.EnhancedForensics.FindProcessByName(name)
	if err != nil {
		return []interface{}{}
	}
	
	result := make([]interface{}, len(processes))
	for i, p := range processes {
		result[i] = map[string]interface{}{
			"pid":         p.PID,
			"name":        p.Name,
			"path":        p.Path,
			"ppid":        p.ParentPID,
			"workingset":  p.WorkingSet,
			"virtualsize": p.VirtualSize,
			"commandline": p.CommandLine,
			"threads":     p.Threads,
			"handles":     p.Handles,
		}
	}
	
	return result
}

// GetProcessTree returns the process hierarchy
func (m *IntegratedMemoryModule) GetProcessTree() interface{} {
	tree, err := m.EnhancedForensics.GetProcessTree()
	if err != nil {
		return map[string]interface{}{
			"total": 0,
			"roots": 0,
			"tree":  []interface{}{},
		}
	}
	return tree
}

// AnalyzeProcessTree is an alias for GetProcessTree (used by VM)
func (m *IntegratedMemoryModule) AnalyzeProcessTree() map[string]interface{} {
	tree := m.GetProcessTree()
	if t, ok := tree.(map[string]interface{}); ok {
		return t
	}
	return map[string]interface{}{
		"total": 0,
		"roots": 0,
		"tree":  []interface{}{},
	}
}

// GetProcessInfo returns detailed process information
func (m *IntegratedMemoryModule) GetProcessInfo(pid int) map[string]interface{} {
	// Find process in our cache
	processes, err := m.EnhancedForensics.EnumerateProcesses()
	if err != nil {
		// Fall back to stub
		return m.MemoryModule.GetProcessInfo(pid)
	}
	
	for _, p := range processes {
		if p.PID == pid {
			return map[string]interface{}{
				"pid":          p.PID,
				"name":         p.Name,
				"path":         p.Path,
				"parent_pid":   p.ParentPID,
				"command_line": p.CommandLine,
				"threads":      p.Threads,
				"handles":      p.Handles,
				"memory": map[string]interface{}{
					"working_set_size": p.WorkingSet,
					"virtual_size":     p.VirtualSize,
				},
			}
		}
	}
	
	// Process not found, return default
	return map[string]interface{}{
		"pid":          pid,
		"name":         "unknown",
		"path":         "",
		"parent_pid":   0,
		"command_line": "",
		"threads":      0,
		"handles":      0,
		"memory": map[string]interface{}{
			"working_set_size": 0,
			"virtual_size":     0,
		},
	}
}

// GetRegions returns memory regions for a process
func (m *IntegratedMemoryModule) GetRegions(pid int) interface{} {
	regions, err := m.EnhancedForensics.GetMemoryRegions(pid)
	if err != nil {
		return []interface{}{}
	}
	
	result := make([]interface{}, len(regions))
	for i, r := range regions {
		result[i] = map[string]interface{}{
			"base_address": r.BaseAddress,
			"size":         r.Size,
			"protection":   r.Protection,
			"state":        r.State,
			"type":         r.Type,
		}
	}
	
	return result
}

// DetectHollowing checks for process hollowing
func (m *IntegratedMemoryModule) DetectHollowing(pid int) interface{} {
	isHollowed, indicators, err := m.EnhancedForensics.DetectProcessHollowing(pid)
	if err != nil {
		return false
	}
	
	if isHollowed {
		return map[string]interface{}{
			"detected":   true,
			"indicators": indicators,
		}
	}
	
	return false
}

// DetectInjection checks for code injection
func (m *IntegratedMemoryModule) DetectInjection(pid int) interface{} {
	indicators, err := m.EnhancedForensics.DetectCodeInjection(pid)
	if err != nil {
		return []interface{}{}
	}
	
	return indicators
}

// ScanMalware performs malware scanning
func (m *IntegratedMemoryModule) ScanMalware(pid int) interface{} {
	detections, err := m.EnhancedForensics.ScanForMalware(pid)
	if err != nil {
		return []interface{}{}
	}
	
	return detections
}

// GetChildren returns child processes
func (m *IntegratedMemoryModule) GetChildren(parentPID int) interface{} {
	children, err := m.EnhancedForensics.GetChildProcesses(parentPID)
	if err != nil {
		return []interface{}{}
	}
	
	result := make([]interface{}, len(children))
	for i, c := range children {
		result[i] = map[string]interface{}{
			"pid":  c.PID,
			"name": c.Name,
		}
	}
	
	return result
}