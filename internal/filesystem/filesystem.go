// Package filesystem provides file system security operations for Sentra
package filesystem

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// FileSystemModule provides file system security operations
type FileSystemModule struct {
	Baselines    map[string]*FileBaseline
	Watchers     map[string]*FileWatcher
	ScanResults  []ScanResult
	mu           sync.RWMutex
}

// FileBaseline represents a file's security baseline
type FileBaseline struct {
	Path         string
	Size         int64
	Mode         os.FileMode
	ModTime      time.Time
	MD5Hash      string
	SHA1Hash     string
	SHA256Hash   string
	Permissions  string
	Owner        string
	Group        string
	Created      time.Time
}

// FileWatcher monitors file changes
type FileWatcher struct {
	Path         string
	Recursive    bool
	Events       []FileEvent
	LastScan     time.Time
	Active       bool
}

// FileEvent represents a file system event
type FileEvent struct {
	Type      string    // CREATED, MODIFIED, DELETED, MOVED
	Path      string
	OldPath   string    // For move events
	Timestamp time.Time
	Details   string
}

// ScanResult represents a security scan result
type ScanResult struct {
	Path         string
	Type         string // MALWARE, SUSPICIOUS, INTEGRITY, PERMISSION
	Severity     string // LOW, MEDIUM, HIGH, CRITICAL
	Description  string
	Evidence     string
	Timestamp    time.Time
}

// HashType represents different hash algorithms
type HashType string

const (
	MD5Hash    HashType = "md5"
	SHA1Hash   HashType = "sha1"
	SHA256Hash HashType = "sha256"
)

// NewFileSystemModule creates a new filesystem security module
func NewFileSystemModule() *FileSystemModule {
	return &FileSystemModule{
		Baselines:   make(map[string]*FileBaseline),
		Watchers:    make(map[string]*FileWatcher),
		ScanResults: make([]ScanResult, 0),
	}
}

// CreateBaseline creates a security baseline for a file or directory
func (fs *FileSystemModule) CreateBaseline(path string, recursive bool) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	return filepath.Walk(path, func(currentPath string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip inaccessible files
		}

		// Skip directories unless we want to baseline them too
		if info.IsDir() && currentPath != path {
			if !recursive {
				return filepath.SkipDir
			}
			return nil
		}

		baseline, err := fs.createFileBaseline(currentPath, info)
		if err != nil {
			return nil // Skip files we can't baseline
		}

		fs.Baselines[currentPath] = baseline
		return nil
	})
}

// createFileBaseline creates a baseline for a single file
func (fs *FileSystemModule) createFileBaseline(path string, info os.FileInfo) (*FileBaseline, error) {
	baseline := &FileBaseline{
		Path:        path,
		Size:        info.Size(),
		Mode:        info.Mode(),
		ModTime:     info.ModTime(),
		Permissions: info.Mode().String(),
		Created:     time.Now(), // Baseline creation time
	}

	// Calculate hashes for regular files
	if info.Mode().IsRegular() {
		hashes, err := fs.calculateFileHashes(path)
		if err != nil {
			return nil, err
		}
		baseline.MD5Hash = hashes["md5"]
		baseline.SHA1Hash = hashes["sha1"]
		baseline.SHA256Hash = hashes["sha256"]
	}

	return baseline, nil
}

// calculateFileHashes computes multiple hashes for a file
func (fs *FileSystemModule) calculateFileHashes(path string) (map[string]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Create hash writers
	md5Hash := md5.New()
	sha1Hash := sha1.New()
	sha256Hash := sha256.New()

	// Use MultiWriter to compute all hashes in one pass
	multiWriter := io.MultiWriter(md5Hash, sha1Hash, sha256Hash)

	// Copy file content to all hash writers
	_, err = io.Copy(multiWriter, file)
	if err != nil {
		return nil, err
	}

	return map[string]string{
		"md5":    hex.EncodeToString(md5Hash.Sum(nil)),
		"sha1":   hex.EncodeToString(sha1Hash.Sum(nil)),
		"sha256": hex.EncodeToString(sha256Hash.Sum(nil)),
	}, nil
}

// VerifyIntegrity checks file integrity against baseline
func (fs *FileSystemModule) VerifyIntegrity(path string) (*ScanResult, error) {
	fs.mu.RLock()
	baseline, exists := fs.Baselines[path]
	fs.mu.RUnlock()

	if !exists {
		return &ScanResult{
			Path:        path,
			Type:        "INTEGRITY",
			Severity:    "MEDIUM",
			Description: "No baseline exists for file",
			Timestamp:   time.Now(),
		}, nil
	}

	info, err := os.Stat(path)
	if err != nil {
		return &ScanResult{
			Path:        path,
			Type:        "INTEGRITY",
			Severity:    "HIGH",
			Description: "File no longer exists or is inaccessible",
			Evidence:    err.Error(),
			Timestamp:   time.Now(),
		}, nil
	}

	result := &ScanResult{
		Path:      path,
		Type:      "INTEGRITY",
		Severity:  "LOW",
		Timestamp: time.Now(),
	}

	var issues []string

	// Check size
	if info.Size() != baseline.Size {
		issues = append(issues, fmt.Sprintf("Size changed: %d -> %d", baseline.Size, info.Size()))
	}

	// Check modification time
	if !info.ModTime().Equal(baseline.ModTime) {
		issues = append(issues, fmt.Sprintf("Modified: %s -> %s", baseline.ModTime, info.ModTime()))
	}

	// Check permissions
	if info.Mode() != baseline.Mode {
		issues = append(issues, fmt.Sprintf("Permissions changed: %s -> %s", baseline.Permissions, info.Mode().String()))
	}

	// Check hashes for regular files
	if info.Mode().IsRegular() && (info.Size() != baseline.Size || !info.ModTime().Equal(baseline.ModTime)) {
		hashes, err := fs.calculateFileHashes(path)
		if err == nil {
			if hashes["sha256"] != baseline.SHA256Hash {
				issues = append(issues, "Content hash mismatch (SHA256)")
				result.Severity = "HIGH"
			}
		}
	}

	if len(issues) > 0 {
		result.Description = "File integrity violation"
		result.Evidence = strings.Join(issues, "; ")
		if result.Severity == "LOW" {
			result.Severity = "MEDIUM"
		}
	} else {
		result.Description = "File integrity verified"
		result.Severity = "INFO"
	}

	return result, nil
}

// ScanDirectory performs a comprehensive security scan
func (fs *FileSystemModule) ScanDirectory(path string, recursive bool) ([]ScanResult, error) {
	var results []ScanResult
	var mu sync.Mutex

	err := filepath.Walk(path, func(currentPath string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip inaccessible files
		}

		if info.IsDir() && currentPath != path && !recursive {
			return filepath.SkipDir
		}

		// Perform various security checks
		scanResults := fs.performSecurityChecks(currentPath, info)
		
		mu.Lock()
		results = append(results, scanResults...)
		mu.Unlock()

		return nil
	})

	if err != nil {
		return results, err
	}

	// Store results
	fs.mu.Lock()
	fs.ScanResults = append(fs.ScanResults, results...)
	fs.mu.Unlock()

	return results, nil
}

// performSecurityChecks runs various security checks on a file
func (fs *FileSystemModule) performSecurityChecks(path string, info os.FileInfo) []ScanResult {
	var results []ScanResult

	// Check file permissions
	if permResult := fs.checkPermissions(path, info); permResult != nil {
		results = append(results, *permResult)
	}

	// Check for suspicious files
	if suspResult := fs.checkSuspiciousFile(path, info); suspResult != nil {
		results = append(results, *suspResult)
	}

	// Check for malware signatures (basic)
	if info.Mode().IsRegular() {
		if malwareResult := fs.checkMalwareSignatures(path, info); malwareResult != nil {
			results = append(results, *malwareResult)
		}
	}

	return results
}

// checkPermissions analyzes file permissions for security issues
func (fs *FileSystemModule) checkPermissions(path string, info os.FileInfo) *ScanResult {
	mode := info.Mode()
	
	// Check for world-writable files
	if mode.Perm()&0002 != 0 {
		return &ScanResult{
			Path:        path,
			Type:        "PERMISSION",
			Severity:    "HIGH",
			Description: "World-writable file detected",
			Evidence:    fmt.Sprintf("Permissions: %s", mode.String()),
			Timestamp:   time.Now(),
		}
	}

	// Check for SUID/SGID files
	if mode&os.ModeSetuid != 0 {
		return &ScanResult{
			Path:        path,
			Type:        "PERMISSION",
			Severity:    "MEDIUM",
			Description: "SUID file detected",
			Evidence:    fmt.Sprintf("Permissions: %s", mode.String()),
			Timestamp:   time.Now(),
		}
	}

	if mode&os.ModeSetgid != 0 {
		return &ScanResult{
			Path:        path,
			Type:        "PERMISSION",
			Severity:    "MEDIUM",
			Description: "SGID file detected",
			Evidence:    fmt.Sprintf("Permissions: %s", mode.String()),
			Timestamp:   time.Now(),
		}
	}

	return nil
}

// checkSuspiciousFile checks for suspicious file names and locations
func (fs *FileSystemModule) checkSuspiciousFile(path string, info os.FileInfo) *ScanResult {
	basename := filepath.Base(path)
	ext := strings.ToLower(filepath.Ext(basename))
	
	// Suspicious extensions
	suspiciousExts := []string{
		".exe", ".bat", ".cmd", ".scr", ".pif", ".com",
		".dll", ".so", ".dylib", ".vbs", ".js", ".jar",
		".ps1", ".sh", ".py", ".pl", ".rb",
	}

	for _, suspExt := range suspiciousExts {
		if ext == suspExt {
			return &ScanResult{
				Path:        path,
				Type:        "SUSPICIOUS",
				Severity:    "MEDIUM",
				Description: "Potentially suspicious executable file",
				Evidence:    fmt.Sprintf("Extension: %s", ext),
				Timestamp:   time.Now(),
			}
		}
	}

	// Hidden files (starting with .)
	if strings.HasPrefix(basename, ".") && basename != "." && basename != ".." {
		return &ScanResult{
			Path:        path,
			Type:        "SUSPICIOUS",
			Severity:    "LOW",
			Description: "Hidden file detected",
			Evidence:    fmt.Sprintf("Filename: %s", basename),
			Timestamp:   time.Now(),
		}
	}

	// Suspicious filenames
	suspiciousNames := []string{
		"passwd", "shadow", "hosts", "backdoor", "keylogger",
		"trojan", "virus", "malware", "exploit", "payload",
	}

	lowerName := strings.ToLower(basename)
	for _, suspName := range suspiciousNames {
		if strings.Contains(lowerName, suspName) {
			return &ScanResult{
				Path:        path,
				Type:        "SUSPICIOUS",
				Severity:    "HIGH",
				Description: "Suspicious filename detected",
				Evidence:    fmt.Sprintf("Filename contains: %s", suspName),
				Timestamp:   time.Now(),
			}
		}
	}

	return nil
}

// checkMalwareSignatures performs basic malware signature detection
func (fs *FileSystemModule) checkMalwareSignatures(path string, info os.FileInfo) *ScanResult {
	// Skip large files for performance
	if info.Size() > 100*1024*1024 { // 100MB
		return nil
	}

	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()

	// Read first 4KB for signature detection
	buffer := make([]byte, 4096)
	n, err := file.Read(buffer)
	if err != nil && err != io.EOF {
		return nil
	}

	content := string(buffer[:n])
	contentLower := strings.ToLower(content)

	// Simple signature patterns
	malwarePatterns := []string{
		"eval(", "exec(", "system(", "shell_exec(",
		"cmd.exe", "powershell", "/bin/sh", "/bin/bash",
		"backdoor", "trojan", "keylogger", "rootkit",
		"metasploit", "meterpreter", "shellcode",
	}

	for _, pattern := range malwarePatterns {
		if strings.Contains(contentLower, pattern) {
			return &ScanResult{
				Path:        path,
				Type:        "MALWARE",
				Severity:    "CRITICAL",
				Description: "Potential malware signature detected",
				Evidence:    fmt.Sprintf("Pattern found: %s", pattern),
				Timestamp:   time.Now(),
			}
		}
	}

	return nil
}

// CalculateFileHash computes a specific hash for a file
func (fs *FileSystemModule) CalculateFileHash(path string, hashType HashType) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	var hasher io.Writer
	switch hashType {
	case MD5Hash:
		h := md5.New()
		hasher = h
		_, err = io.Copy(hasher, file)
		if err != nil {
			return "", err
		}
		return hex.EncodeToString(h.Sum(nil)), nil
	case SHA1Hash:
		h := sha1.New()
		hasher = h
		_, err = io.Copy(hasher, file)
		if err != nil {
			return "", err
		}
		return hex.EncodeToString(h.Sum(nil)), nil
	case SHA256Hash:
		h := sha256.New()
		hasher = h
		_, err = io.Copy(hasher, file)
		if err != nil {
			return "", err
		}
		return hex.EncodeToString(h.Sum(nil)), nil
	default:
		return "", fmt.Errorf("unsupported hash type: %s", hashType)
	}
}

// VerifyChecksum verifies a file against a known checksum
func (fs *FileSystemModule) VerifyChecksum(path string, expectedHash string, hashType HashType) (bool, error) {
	actualHash, err := fs.CalculateFileHash(path, hashType)
	if err != nil {
		return false, err
	}

	return strings.EqualFold(actualHash, expectedHash), nil
}

// WatchDirectory starts monitoring a directory for changes
func (fs *FileSystemModule) WatchDirectory(path string, recursive bool) (*FileWatcher, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	watcher := &FileWatcher{
		Path:      path,
		Recursive: recursive,
		Events:    make([]FileEvent, 0),
		LastScan:  time.Now(),
		Active:    true,
	}

	fs.Watchers[path] = watcher
	return watcher, nil
}

// CheckChanges detects changes since last scan for a watched directory
func (fs *FileSystemModule) CheckChanges(watcherPath string) ([]FileEvent, error) {
	fs.mu.RLock()
	watcher, exists := fs.Watchers[watcherPath]
	fs.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("no watcher found for path: %s", watcherPath)
	}

	var events []FileEvent
	lastScan := watcher.LastScan

	err := filepath.Walk(watcher.Path, func(currentPath string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		if info.IsDir() && currentPath != watcher.Path && !watcher.Recursive {
			return filepath.SkipDir
		}

		// Check if file was modified since last scan
		if info.ModTime().After(lastScan) {
			event := FileEvent{
				Type:      "MODIFIED",
				Path:      currentPath,
				Timestamp: info.ModTime(),
				Details:   fmt.Sprintf("Size: %d bytes", info.Size()),
			}
			events = append(events, event)
		}

		return nil
	})

	if err != nil {
		return events, err
	}

	// Update last scan time
	fs.mu.Lock()
	watcher.LastScan = time.Now()
	watcher.Events = append(watcher.Events, events...)
	fs.mu.Unlock()

	return events, nil
}

// GetFileInfo returns detailed file information
func (fs *FileSystemModule) GetFileInfo(path string) (map[string]interface{}, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	result := map[string]interface{}{
		"path":        path,
		"size":        info.Size(),
		"mode":        info.Mode().String(),
		"mod_time":    info.ModTime(),
		"is_dir":      info.IsDir(),
		"permissions": fmt.Sprintf("%o", info.Mode().Perm()),
	}

	// Add hashes for regular files
	if info.Mode().IsRegular() {
		hashes, err := fs.calculateFileHashes(path)
		if err == nil {
			result["md5"] = hashes["md5"]
			result["sha1"] = hashes["sha1"]
			result["sha256"] = hashes["sha256"]
		}
	}

	return result, nil
}

// CleanupWatcher removes a file system watcher
func (fs *FileSystemModule) CleanupWatcher(path string) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	
	if watcher, exists := fs.Watchers[path]; exists {
		watcher.Active = false
		delete(fs.Watchers, path)
	}
}

// GetBaselines returns all current baselines
func (fs *FileSystemModule) GetBaselines() map[string]*FileBaseline {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	
	// Return a copy to prevent concurrent modification
	result := make(map[string]*FileBaseline)
	for k, v := range fs.Baselines {
		result[k] = v
	}
	return result
}

// GetScanResults returns all scan results
func (fs *FileSystemModule) GetScanResults() []ScanResult {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	
	// Return a copy
	result := make([]ScanResult, len(fs.ScanResults))
	copy(result, fs.ScanResults)
	return result
}

// ClearScanResults clears all stored scan results
func (fs *FileSystemModule) ClearScanResults() {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	
	fs.ScanResults = fs.ScanResults[:0]
}