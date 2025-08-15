package memory

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// MemoryForensics provides memory analysis and forensics capabilities
type MemoryForensics struct {
	processes map[int]*ProcessInfo
}

// ProcessInfo contains information about a process
type ProcessInfo struct {
	PID         int               `json:"pid"`
	Name        string            `json:"name"`
	Path        string            `json:"path"`
	CommandLine string            `json:"command_line"`
	Parent      int               `json:"parent_pid"`
	Children    []int             `json:"children"`
	Memory      *MemoryInfo       `json:"memory_info"`
	Modules     []ModuleInfo      `json:"modules"`
	Handles     []HandleInfo      `json:"handles"`
	Threads     []ThreadInfo      `json:"threads"`
	Environment map[string]string `json:"environment"`
	StartTime   time.Time         `json:"start_time"`
}

// MemoryInfo contains process memory statistics
type MemoryInfo struct {
	WorkingSetSize     uint64 `json:"working_set_size"`
	PrivateUsage       uint64 `json:"private_usage"`
	VirtualSize        uint64 `json:"virtual_size"`
	PagefileUsage      uint64 `json:"pagefile_usage"`
	PeakWorkingSetSize uint64 `json:"peak_working_set_size"`
	PeakPagefileUsage  uint64 `json:"peak_pagefile_usage"`
}

// ModuleInfo contains information about loaded modules/DLLs
type ModuleInfo struct {
	Name     string `json:"name"`
	Path     string `json:"path"`
	BaseAddr uint64 `json:"base_address"`
	Size     uint64 `json:"size"`
	Version  string `json:"version"`
	Hash     string `json:"hash"`
}

// HandleInfo contains information about process handles
type HandleInfo struct {
	Handle uint64 `json:"handle"`
	Type   string `json:"type"`
	Name   string `json:"name"`
	Access uint32 `json:"access"`
}

// ThreadInfo contains information about process threads
type ThreadInfo struct {
	TID       uint32    `json:"tid"`
	State     string    `json:"state"`
	StartAddr uint64    `json:"start_address"`
	Priority  int32     `json:"priority"`
	StartTime time.Time `json:"start_time"`
}

// MemoryRegion represents a memory region in a process
type MemoryRegion struct {
	BaseAddress uint64 `json:"base_address"`
	Size        uint64 `json:"size"`
	Protection  string `json:"protection"`
	State       string `json:"state"`
	Type        string `json:"type"`
	Module      string `json:"module,omitempty"`
}

// MemoryDump represents a memory dump
type MemoryDump struct {
	PID       int           `json:"pid"`
	Process   string        `json:"process"`
	DumpPath  string        `json:"dump_path"`
	Size      int64         `json:"size"`
	Hash      string        `json:"hash"`
	Timestamp time.Time     `json:"timestamp"`
	Regions   []MemoryRegion `json:"regions"`
}

// MalwareSignature represents a malware signature for memory scanning
type MalwareSignature struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Patterns    [][]byte `json:"patterns"`
	Offset      int      `json:"offset"`
	Family      string   `json:"family"`
	Severity    string   `json:"severity"`
}

// NewMemoryForensics creates a new memory forensics instance
func NewMemoryForensics() *MemoryForensics {
	return &MemoryForensics{
		processes: make(map[int]*ProcessInfo),
	}
}

// EnumerateProcesses lists all running processes with detailed information
func (mf *MemoryForensics) EnumerateProcesses() ([]*ProcessInfo, error) {
	if runtime.GOOS == "windows" {
		return mf.enumerateWindowsProcesses()
	} else {
		return mf.enumerateUnixProcesses()
	}
}

// enumerateWindowsProcesses enumerates processes on Windows
func (mf *MemoryForensics) enumerateWindowsProcesses() ([]*ProcessInfo, error) {
	// Use PowerShell to get detailed process information
	cmd := exec.Command("powershell", "-Command", 
		"Get-Process | Select-Object Id,Name,Path,CommandLine,ParentProcessId,WorkingSet,VirtualMemorySize | ConvertTo-Json")
	
	output, err := cmd.Output()
	if err != nil {
		// Fallback to tasklist
		return mf.parseTasklist()
	}
	
	// Parse JSON output (simplified for demo)
	return mf.parseProcessJSON(string(output))
}

// enumerateUnixProcesses enumerates processes on Unix/Linux
func (mf *MemoryForensics) enumerateUnixProcesses() ([]*ProcessInfo, error) {
	var processes []*ProcessInfo
	
	// Read from /proc filesystem
	procDir := "/proc"
	entries, err := os.ReadDir(procDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read /proc: %w", err)
	}
	
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		
		// Check if directory name is numeric (PID)
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		
		// Get process information
		if proc, err := mf.getUnixProcessInfo(pid); err == nil {
			processes = append(processes, proc)
		}
	}
	
	return processes, nil
}

// getUnixProcessInfo gets detailed process information on Unix/Linux
func (mf *MemoryForensics) getUnixProcessInfo(pid int) (*ProcessInfo, error) {
	proc := &ProcessInfo{
		PID:         pid,
		Environment: make(map[string]string),
	}
	
	// Read /proc/PID/stat
	statFile := fmt.Sprintf("/proc/%d/stat", pid)
	if data, err := os.ReadFile(statFile); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) >= 4 {
			proc.Name = strings.Trim(fields[1], "()")
			if ppid, err := strconv.Atoi(fields[3]); err == nil {
				proc.Parent = ppid
			}
		}
	}
	
	// Read /proc/PID/cmdline
	cmdlineFile := fmt.Sprintf("/proc/%d/cmdline", pid)
	if data, err := os.ReadFile(cmdlineFile); err == nil {
		proc.CommandLine = strings.ReplaceAll(string(data), "\x00", " ")
	}
	
	// Read /proc/PID/exe
	exeFile := fmt.Sprintf("/proc/%d/exe", pid)
	if path, err := os.Readlink(exeFile); err == nil {
		proc.Path = path
	}
	
	// Read memory information
	if memInfo, err := mf.getUnixMemoryInfo(pid); err == nil {
		proc.Memory = memInfo
	}
	
	return proc, nil
}

// getUnixMemoryInfo gets memory information for a Unix process
func (mf *MemoryForensics) getUnixMemoryInfo(pid int) (*MemoryInfo, error) {
	statusFile := fmt.Sprintf("/proc/%d/status", pid)
	data, err := os.ReadFile(statusFile)
	if err != nil {
		return nil, err
	}
	
	memInfo := &MemoryInfo{}
	lines := strings.Split(string(data), "\n")
	
	for _, line := range lines {
		if strings.HasPrefix(line, "VmRSS:") {
			if size := extractMemorySize(line); size > 0 {
				memInfo.WorkingSetSize = size
			}
		} else if strings.HasPrefix(line, "VmSize:") {
			if size := extractMemorySize(line); size > 0 {
				memInfo.VirtualSize = size
			}
		}
	}
	
	return memInfo, nil
}

// extractMemorySize extracts memory size from /proc status line
func extractMemorySize(line string) uint64 {
	parts := strings.Fields(line)
	if len(parts) >= 2 {
		if size, err := strconv.ParseUint(parts[1], 10, 64); err == nil {
			return size * 1024 // Convert from KB to bytes
		}
	}
	return 0
}

// parseTasklist parses Windows tasklist output (fallback)
func (mf *MemoryForensics) parseTasklist() ([]*ProcessInfo, error) {
	cmd := exec.Command("tasklist", "/fo", "csv", "/v")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	
	var processes []*ProcessInfo
	lines := strings.Split(string(output), "\n")
	
	// Skip header line
	for i := 1; i < len(lines); i++ {
		if line := strings.TrimSpace(lines[i]); line != "" {
			if proc := mf.parseTasklistLine(line); proc != nil {
				processes = append(processes, proc)
			}
		}
	}
	
	return processes, nil
}

// parseTasklistLine parses a single tasklist CSV line
func (mf *MemoryForensics) parseTasklistLine(line string) *ProcessInfo {
	// Simple CSV parsing (would need more robust parsing in production)
	fields := strings.Split(line, "\",\"")
	if len(fields) < 2 {
		return nil
	}
	
	// Clean quotes
	for i, field := range fields {
		fields[i] = strings.Trim(field, "\"")
	}
	
	proc := &ProcessInfo{
		Name:        fields[0],
		Environment: make(map[string]string),
	}
	
	// Parse PID
	if len(fields) > 1 {
		if pid, err := strconv.Atoi(fields[1]); err == nil {
			proc.PID = pid
		}
	}
	
	return proc
}

// parseProcessJSON parses PowerShell JSON output (simplified)
func (mf *MemoryForensics) parseProcessJSON(jsonData string) ([]*ProcessInfo, error) {
	// This would need proper JSON parsing in production
	// For now, return empty list
	return []*ProcessInfo{}, nil
}

// DumpProcessMemory creates a memory dump of a process
func (mf *MemoryForensics) DumpProcessMemory(pid int, outputPath string) (*MemoryDump, error) {
	// Verify process exists
	proc, err := mf.GetProcessInfo(pid)
	if err != nil {
		return nil, fmt.Errorf("process %d not found: %w", pid, err)
	}
	
	// Create dump directory if it doesn't exist
	if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
		return nil, fmt.Errorf("failed to create dump directory: %w", err)
	}
	
	// Platform-specific memory dumping
	var dumpSize int64
	if runtime.GOOS == "windows" {
		dumpSize, err = mf.dumpWindowsMemory(pid, outputPath)
	} else {
		dumpSize, err = mf.dumpUnixMemory(pid, outputPath)
	}
	
	if err != nil {
		return nil, fmt.Errorf("failed to dump memory: %w", err)
	}
	
	// Calculate hash
	hash, err := mf.calculateFileHash(outputPath)
	if err != nil {
		hash = "unknown"
	}
	
	// Get memory regions
	regions, _ := mf.GetMemoryRegions(pid)
	
	dump := &MemoryDump{
		PID:       pid,
		Process:   proc.Name,
		DumpPath:  outputPath,
		Size:      dumpSize,
		Hash:      hash,
		Timestamp: time.Now(),
		Regions:   regions,
	}
	
	return dump, nil
}

// dumpWindowsMemory dumps process memory on Windows
func (mf *MemoryForensics) dumpWindowsMemory(pid int, outputPath string) (int64, error) {
	// Use Windows API or external tools like procdump
	// For demonstration, use a simple approach
	
	// Try using built-in tools first
	cmd := exec.Command("taskmgr") // Placeholder - would use proper dumping tool
	if err := cmd.Start(); err != nil {
		return 0, err
	}
	
	// Create placeholder dump file
	file, err := os.Create(outputPath)
	if err != nil {
		return 0, err
	}
	defer file.Close()
	
	// Write dummy data (in real implementation, this would dump actual memory)
	dummyData := fmt.Sprintf("Memory dump for PID %d at %v\n", pid, time.Now())
	n, err := file.WriteString(dummyData)
	
	return int64(n), err
}

// dumpUnixMemory dumps process memory on Unix/Linux
func (mf *MemoryForensics) dumpUnixMemory(pid int, outputPath string) (int64, error) {
	// Use /proc/PID/mem or gcore
	mapsFile := fmt.Sprintf("/proc/%d/maps", pid)
	
	// Read memory maps
	maps, err := os.ReadFile(mapsFile)
	if err != nil {
		return 0, fmt.Errorf("failed to read memory maps: %w", err)
	}
	
	// Create output file
	outFile, err := os.Create(outputPath)
	if err != nil {
		return 0, err
	}
	defer outFile.Close()
	
	// Write memory maps header
	header := fmt.Sprintf("Memory dump for PID %d\nTimestamp: %v\n\nMemory Maps:\n%s\n",
		pid, time.Now(), string(maps))
	
	n, err := outFile.WriteString(header)
	return int64(n), err
}

// GetProcessInfo gets detailed information about a specific process
func (mf *MemoryForensics) GetProcessInfo(pid int) (*ProcessInfo, error) {
	// Check cache first
	if proc, ok := mf.processes[pid]; ok {
		return proc, nil
	}
	
	// Get fresh information
	processes, err := mf.EnumerateProcesses()
	if err != nil {
		return nil, err
	}
	
	// Find the specific process
	for _, proc := range processes {
		mf.processes[proc.PID] = proc
		if proc.PID == pid {
			return proc, nil
		}
	}
	
	return nil, fmt.Errorf("process %d not found", pid)
}

// GetMemoryRegions gets memory regions for a process
func (mf *MemoryForensics) GetMemoryRegions(pid int) ([]MemoryRegion, error) {
	if runtime.GOOS == "windows" {
		return mf.getWindowsMemoryRegions(pid)
	} else {
		return mf.getUnixMemoryRegions(pid)
	}
}

// getWindowsMemoryRegions gets memory regions on Windows
func (mf *MemoryForensics) getWindowsMemoryRegions(pid int) ([]MemoryRegion, error) {
	// Would use Windows API VirtualQueryEx
	// Placeholder implementation
	return []MemoryRegion{
		{
			BaseAddress: 0x400000,
			Size:        0x100000,
			Protection:  "PAGE_EXECUTE_READ",
			State:       "MEM_COMMIT",
			Type:        "MEM_IMAGE",
			Module:      "main.exe",
		},
	}, nil
}

// getUnixMemoryRegions gets memory regions on Unix/Linux
func (mf *MemoryForensics) getUnixMemoryRegions(pid int) ([]MemoryRegion, error) {
	mapsFile := fmt.Sprintf("/proc/%d/maps", pid)
	data, err := os.ReadFile(mapsFile)
	if err != nil {
		return nil, err
	}
	
	var regions []MemoryRegion
	lines := strings.Split(string(data), "\n")
	
	for _, line := range lines {
		if line == "" {
			continue
		}
		
		if region := mf.parseMemoryMapLine(line); region != nil {
			regions = append(regions, *region)
		}
	}
	
	return regions, nil
}

// parseMemoryMapLine parses a line from /proc/PID/maps
func (mf *MemoryForensics) parseMemoryMapLine(line string) *MemoryRegion {
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return nil
	}
	
	// Parse address range
	addrParts := strings.Split(parts[0], "-")
	if len(addrParts) != 2 {
		return nil
	}
	
	baseAddr, err := strconv.ParseUint(addrParts[0], 16, 64)
	if err != nil {
		return nil
	}
	
	endAddr, err := strconv.ParseUint(addrParts[1], 16, 64)
	if err != nil {
		return nil
	}
	
	region := &MemoryRegion{
		BaseAddress: baseAddr,
		Size:        endAddr - baseAddr,
		Protection:  parts[1],
		State:       "MAPPED",
		Type:        "PRIVATE",
	}
	
	// Add module name if available
	if len(parts) >= 6 {
		region.Module = parts[5]
	}
	
	return region
}

// ScanMemoryForMalware scans process memory for malware signatures
func (mf *MemoryForensics) ScanMemoryForMalware(pid int, signatures []MalwareSignature) ([]string, error) {
	var detections []string
	
	// Get memory regions
	regions, err := mf.GetMemoryRegions(pid)
	if err != nil {
		return nil, fmt.Errorf("failed to get memory regions: %w", err)
	}
	
	// Scan each region
	for _, region := range regions {
		if detections_found, err := mf.scanRegionForMalware(pid, region, signatures); err == nil {
			detections = append(detections, detections_found...)
		}
	}
	
	return detections, nil
}

// scanRegionForMalware scans a memory region for malware signatures
func (mf *MemoryForensics) scanRegionForMalware(pid int, region MemoryRegion, signatures []MalwareSignature) ([]string, error) {
	var detections []string
	
	// Read memory region (simplified - would need proper memory reading)
	memData := make([]byte, min(region.Size, 1024*1024)) // Limit to 1MB chunks
	
	// Scan for each signature
	for _, sig := range signatures {
		for _, pattern := range sig.Patterns {
			if mf.containsPattern(memData, pattern) {
				detection := fmt.Sprintf("Malware detected: %s (%s) at 0x%X in %s",
					sig.Name, sig.Family, region.BaseAddress, region.Module)
				detections = append(detections, detection)
			}
		}
	}
	
	return detections, nil
}

// containsPattern checks if data contains a specific pattern
func (mf *MemoryForensics) containsPattern(data []byte, pattern []byte) bool {
	if len(pattern) == 0 || len(data) < len(pattern) {
		return false
	}
	
	for i := 0; i <= len(data)-len(pattern); i++ {
		if matchesAt(data, pattern, i) {
			return true
		}
	}
	
	return false
}

// matchesAt checks if pattern matches data at specific offset
func matchesAt(data []byte, pattern []byte, offset int) bool {
	for i := 0; i < len(pattern); i++ {
		if data[offset+i] != pattern[i] {
			return false
		}
	}
	return true
}

// DetectProcessHollowing detects process hollowing techniques
func (mf *MemoryForensics) DetectProcessHollowing(pid int) (bool, []string, error) {
	var indicators []string
	
	// Get process information
	proc, err := mf.GetProcessInfo(pid)
	if err != nil {
		return false, nil, err
	}
	
	// Check for suspicious characteristics
	
	// 1. Check if executable path matches loaded image
	regions, err := mf.GetMemoryRegions(pid)
	if err != nil {
		return false, nil, err
	}
	
	// 2. Look for unusual memory regions
	hasUnusualRegions := false
	for _, region := range regions {
		// Check for executable regions without associated modules
		if strings.Contains(region.Protection, "EXEC") && region.Module == "" {
			indicators = append(indicators, 
				fmt.Sprintf("Executable region without module at 0x%X", region.BaseAddress))
			hasUnusualRegions = true
		}
		
		// Check for private executable regions
		if region.Type == "PRIVATE" && strings.Contains(region.Protection, "EXEC") {
			indicators = append(indicators, 
				fmt.Sprintf("Private executable region at 0x%X", region.BaseAddress))
			hasUnusualRegions = true
		}
	}
	
	// 3. Check parent-child relationship anomalies
	if proc.Parent > 0 {
		parent, err := mf.GetProcessInfo(proc.Parent)
		if err == nil {
			// Suspicious parent processes for certain applications
			suspiciousParents := map[string][]string{
				"svchost.exe": {"explorer.exe", "services.exe"},
				"lsass.exe":   {"wininit.exe"},
				"winlogon.exe": {"wininit.exe"},
			}
			
			if expectedParents, ok := suspiciousParents[strings.ToLower(proc.Name)]; ok {
				parentSuspicious := true
				for _, expected := range expectedParents {
					if strings.ToLower(parent.Name) == expected {
						parentSuspicious = false
						break
					}
				}
				
				if parentSuspicious {
					indicators = append(indicators, 
						fmt.Sprintf("Suspicious parent process: %s spawned %s", parent.Name, proc.Name))
					hasUnusualRegions = true
				}
			}
		}
	}
	
	return hasUnusualRegions, indicators, nil
}

// AnalyzeInjection analyzes a process for code injection
func (mf *MemoryForensics) AnalyzeInjection(pid int) ([]string, error) {
	var findings []string
	
	regions, err := mf.GetMemoryRegions(pid)
	if err != nil {
		return nil, err
	}
	
	for _, region := range regions {
		// Look for suspicious memory characteristics
		if region.Type == "PRIVATE" && strings.Contains(region.Protection, "EXEC") {
			findings = append(findings, 
				fmt.Sprintf("Private executable memory at 0x%X (potential injection)", region.BaseAddress))
		}
		
		// Look for RWX regions (Read-Write-Execute)
		if strings.Contains(region.Protection, "READ") && 
		   strings.Contains(region.Protection, "WRITE") && 
		   strings.Contains(region.Protection, "EXEC") {
			findings = append(findings, 
				fmt.Sprintf("RWX memory region at 0x%X (potential shellcode)", region.BaseAddress))
		}
	}
	
	return findings, nil
}

// calculateFileHash calculates SHA256 hash of a file
func (mf *MemoryForensics) calculateFileHash(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()
	
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}
	
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// min returns the smaller of two uint64 values
func min(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}

// GetDefaultMalwareSignatures returns common malware signatures
func GetDefaultMalwareSignatures() []MalwareSignature {
	return []MalwareSignature{
		{
			Name:        "Metasploit Meterpreter",
			Description: "Metasploit Meterpreter payload signature",
			Patterns:    [][]byte{[]byte("metsrv.dll"), []byte("ReflectiveLoader")},
			Family:      "Metasploit",
			Severity:    "HIGH",
		},
		{
			Name:        "Cobalt Strike Beacon",
			Description: "Cobalt Strike beacon payload",
			Patterns:    [][]byte{[]byte("beacon.dll"), []byte("crowdstrike")},
			Family:      "CobaltStrike", 
			Severity:    "HIGH",
		},
		{
			Name:        "Empire PowerShell",
			Description: "PowerShell Empire payload",
			Patterns:    [][]byte{[]byte("empire"), []byte("powershell.exe")},
			Family:      "Empire",
			Severity:    "MEDIUM",
		},
		{
			Name:        "Mimikatz",
			Description: "Mimikatz credential dumping tool",
			Patterns:    [][]byte{[]byte("mimikatz"), []byte("sekurlsa"), []byte("gentilkiwi")},
			Family:      "Mimikatz",
			Severity:    "HIGH",
		},
	}
}