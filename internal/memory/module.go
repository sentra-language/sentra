package memory

import (
	"fmt"
)

// MemoryModule provides memory forensics functions for Sentra VM
type MemoryModule struct {
	forensics *MemoryForensics
}

// NewMemoryModule creates a new memory forensics module
func NewMemoryModule() *MemoryModule {
	return &MemoryModule{
		forensics: NewMemoryForensics(),
	}
}

// ListProcesses returns all running processes
func (mm *MemoryModule) ListProcesses() Value {
	processes, err := mm.forensics.EnumerateProcesses()
	if err != nil {
		return nil
	}
	
	var result []Value
	for _, proc := range processes {
		procMap := NewMap()
		procMap.Items["pid"] = float64(proc.PID)
		procMap.Items["name"] = proc.Name
		procMap.Items["path"] = proc.Path
		procMap.Items["command_line"] = proc.CommandLine
		procMap.Items["parent_pid"] = float64(proc.Parent)
		
		// Memory information
		if proc.Memory != nil {
			memMap := NewMap()
			memMap.Items["working_set"] = float64(proc.Memory.WorkingSetSize)
			memMap.Items["virtual_size"] = float64(proc.Memory.VirtualSize)
			memMap.Items["private_usage"] = float64(proc.Memory.PrivateUsage)
			procMap.Items["memory"] = memMap
		}
		
		// Modules
		if len(proc.Modules) > 0 {
			var modules []Value
			for _, mod := range proc.Modules {
				modMap := NewMap()
				modMap.Items["name"] = mod.Name
				modMap.Items["path"] = mod.Path
				modMap.Items["base_address"] = fmt.Sprintf("0x%X", mod.BaseAddr)
				modMap.Items["size"] = float64(mod.Size)
				modMap.Items["version"] = mod.Version
				modMap.Items["hash"] = mod.Hash
				modules = append(modules, modMap)
			}
			procMap.Items["modules"] = NewArrayFromSlice(modules)
		}
		
		result = append(result, procMap)
	}
	
	return NewArrayFromSlice(result)
}

// GetProcessInfo returns detailed information about a specific process
func (mm *MemoryModule) GetProcessInfo(pidValue Value) Value {
	pid := int(ToNumber(pidValue))
	
	proc, err := mm.forensics.GetProcessInfo(pid)
	if err != nil {
		return nil
	}
	
	procMap := NewMap()
	procMap.Items["pid"] = float64(proc.PID)
	procMap.Items["name"] = proc.Name
	procMap.Items["path"] = proc.Path
	procMap.Items["command_line"] = proc.CommandLine
	procMap.Items["parent_pid"] = float64(proc.Parent)
	
	// Children
	if len(proc.Children) > 0 {
		var children []Value
		for _, child := range proc.Children {
			children = append(children, float64(child))
		}
		procMap.Items["children"] = NewArrayFromSlice(children)
	}
	
	// Memory information
	if proc.Memory != nil {
		memMap := NewMap()
		memMap.Items["working_set_size"] = float64(proc.Memory.WorkingSetSize)
		memMap.Items["virtual_size"] = float64(proc.Memory.VirtualSize)
		memMap.Items["private_usage"] = float64(proc.Memory.PrivateUsage)
		memMap.Items["pagefile_usage"] = float64(proc.Memory.PagefileUsage)
		memMap.Items["peak_working_set"] = float64(proc.Memory.PeakWorkingSetSize)
		memMap.Items["peak_pagefile"] = float64(proc.Memory.PeakPagefileUsage)
		procMap.Items["memory"] = memMap
	}
	
	// Environment variables
	if len(proc.Environment) > 0 {
		envMap := NewMap()
		for key, value := range proc.Environment {
			envMap.Items[key] = value
		}
		procMap.Items["environment"] = envMap
	}
	
	// Start time
	procMap.Items["start_time"] = proc.StartTime.Format("2006-01-02 15:04:05")
	
	return procMap
}

// DumpProcessMemory creates a memory dump of a process
func (mm *MemoryModule) DumpProcessMemory(pidValue Value, outputPath string) Value {
	pid := int(ToNumber(pidValue))
	
	dump, err := mm.forensics.DumpProcessMemory(pid, outputPath)
	if err != nil {
		return nil
	}
	
	dumpMap := NewMap()
	dumpMap.Items["pid"] = float64(dump.PID)
	dumpMap.Items["process"] = dump.Process
	dumpMap.Items["dump_path"] = dump.DumpPath
	dumpMap.Items["size"] = float64(dump.Size)
	dumpMap.Items["hash"] = dump.Hash
	dumpMap.Items["timestamp"] = dump.Timestamp.Format("2006-01-02 15:04:05")
	
	// Memory regions
	if len(dump.Regions) > 0 {
		var regions []Value
		for _, region := range dump.Regions {
			regionMap := NewMap()
			regionMap.Items["base_address"] = fmt.Sprintf("0x%X", region.BaseAddress)
			regionMap.Items["size"] = float64(region.Size)
			regionMap.Items["protection"] = region.Protection
			regionMap.Items["state"] = region.State
			regionMap.Items["type"] = region.Type
			if region.Module != "" {
				regionMap.Items["module"] = region.Module
			}
			regions = append(regions, regionMap)
		}
		dumpMap.Items["regions"] = NewArrayFromSlice(regions)
	}
	
	return dumpMap
}

// GetMemoryRegions returns memory regions for a process
func (mm *MemoryModule) GetMemoryRegions(pidValue Value) Value {
	pid := int(ToNumber(pidValue))
	
	regions, err := mm.forensics.GetMemoryRegions(pid)
	if err != nil {
		return nil
	}
	
	var result []Value
	for _, region := range regions {
		regionMap := NewMap()
		regionMap.Items["base_address"] = fmt.Sprintf("0x%X", region.BaseAddress)
		regionMap.Items["size"] = float64(region.Size)
		regionMap.Items["protection"] = region.Protection
		regionMap.Items["state"] = region.State
		regionMap.Items["type"] = region.Type
		if region.Module != "" {
			regionMap.Items["module"] = region.Module
		}
		result = append(result, regionMap)
	}
	
	return NewArrayFromSlice(result)
}

// ScanForMalware scans process memory for malware signatures
func (mm *MemoryModule) ScanForMalware(pidValue Value) Value {
	pid := int(ToNumber(pidValue))
	
	// Use default signatures
	signatures := GetDefaultMalwareSignatures()
	
	detections, err := mm.forensics.ScanMemoryForMalware(pid, signatures)
	if err != nil {
		return NewArrayFromSlice([]Value{})
	}
	
	var result []Value
	for _, detection := range detections {
		result = append(result, detection)
	}
	
	return NewArrayFromSlice(result)
}

// DetectProcessHollowing detects process hollowing techniques
func (mm *MemoryModule) DetectProcessHollowing(pidValue Value) Value {
	pid := int(ToNumber(pidValue))
	
	detected, indicators, err := mm.forensics.DetectProcessHollowing(pid)
	if err != nil {
		return nil
	}
	
	resultMap := NewMap()
	resultMap.Items["detected"] = detected
	
	var indicatorValues []Value
	for _, indicator := range indicators {
		indicatorValues = append(indicatorValues, indicator)
	}
	resultMap.Items["indicators"] = NewArrayFromSlice(indicatorValues)
	
	return resultMap
}

// AnalyzeInjection analyzes a process for code injection
func (mm *MemoryModule) AnalyzeInjection(pidValue Value) Value {
	pid := int(ToNumber(pidValue))
	
	findings, err := mm.forensics.AnalyzeInjection(pid)
	if err != nil {
		return NewArrayFromSlice([]Value{})
	}
	
	var result []Value
	for _, finding := range findings {
		result = append(result, finding)
	}
	
	return NewArrayFromSlice(result)
}

// FindProcessByName finds processes by name
func (mm *MemoryModule) FindProcessByName(nameValue Value) Value {
	name := ToString(nameValue)
	
	processes, err := mm.forensics.EnumerateProcesses()
	if err != nil {
		return NewArrayFromSlice([]Value{})
	}
	
	var result []Value
	for _, proc := range processes {
		if proc.Name == name {
			procMap := NewMap()
			procMap.Items["pid"] = float64(proc.PID)
			procMap.Items["name"] = proc.Name
			procMap.Items["path"] = proc.Path
			procMap.Items["command_line"] = proc.CommandLine
			procMap.Items["parent_pid"] = float64(proc.Parent)
			result = append(result, procMap)
		}
	}
	
	return NewArrayFromSlice(result)
}

// GetProcessChildren gets child processes
func (mm *MemoryModule) GetProcessChildren(pidValue Value) Value {
	parentPid := int(ToNumber(pidValue))
	
	processes, err := mm.forensics.EnumerateProcesses()
	if err != nil {
		return NewArrayFromSlice([]Value{})
	}
	
	var result []Value
	for _, proc := range processes {
		if proc.Parent == parentPid {
			procMap := NewMap()
			procMap.Items["pid"] = float64(proc.PID)
			procMap.Items["name"] = proc.Name
			procMap.Items["path"] = proc.Path
			procMap.Items["command_line"] = proc.CommandLine
			result = append(result, procMap)
		}
	}
	
	return NewArrayFromSlice(result)
}

// AnalyzeProcessTree analyzes the entire process tree
func (mm *MemoryModule) AnalyzeProcessTree() Value {
	processes, err := mm.forensics.EnumerateProcesses()
	if err != nil {
		return nil
	}
	
	// Build process tree structure
	treeMap := NewMap()
	processMap := make(map[int]*ProcessInfo)
	childrenMap := make(map[int][]int)
	
	// Index processes and build parent-child relationships
	for _, proc := range processes {
		processMap[proc.PID] = proc
		if proc.Parent > 0 {
			childrenMap[proc.Parent] = append(childrenMap[proc.Parent], proc.PID)
		}
	}
	
	// Build tree starting from root processes (those without parents or parent not found)
	var roots []Value
	for _, proc := range processes {
		if proc.Parent == 0 || processMap[proc.Parent] == nil {
			rootNode := mm.buildProcessNode(proc, processMap, childrenMap)
			roots = append(roots, rootNode)
		}
	}
	
	treeMap.Items["roots"] = NewArrayFromSlice(roots)
	treeMap.Items["total_processes"] = float64(len(processes))
	
	return treeMap
}

// buildProcessNode builds a process tree node
func (mm *MemoryModule) buildProcessNode(proc *ProcessInfo, processMap map[int]*ProcessInfo, childrenMap map[int][]int) Value {
	node := NewMap()
	node.Items["pid"] = float64(proc.PID)
	node.Items["name"] = proc.Name
	node.Items["path"] = proc.Path
	node.Items["command_line"] = proc.CommandLine
	node.Items["parent_pid"] = float64(proc.Parent)
	
	// Memory info
	if proc.Memory != nil {
		memMap := NewMap()
		memMap.Items["working_set"] = float64(proc.Memory.WorkingSetSize)
		memMap.Items["virtual_size"] = float64(proc.Memory.VirtualSize)
		node.Items["memory"] = memMap
	}
	
	// Add children recursively
	if children, ok := childrenMap[proc.PID]; ok && len(children) > 0 {
		var childNodes []Value
		for _, childPid := range children {
			if childProc, ok := processMap[childPid]; ok {
				childNode := mm.buildProcessNode(childProc, processMap, childrenMap)
				childNodes = append(childNodes, childNode)
			}
		}
		node.Items["children"] = NewArrayFromSlice(childNodes)
		node.Items["child_count"] = float64(len(children))
	} else {
		node.Items["child_count"] = float64(0)
	}
	
	return node
}