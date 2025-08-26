// Package ossec provides OS-level security capabilities for Sentra
package ossec

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// OSSecurityModule provides OS-level security operations
type OSSecurityModule struct {
	Platform string
	Arch     string
}

// ProcessInfo contains process information
type ProcessInfo struct {
	PID        int
	PPID       int
	Name       string
	User       string
	CPU        float64
	Memory     uint64
	Status     string
	StartTime  time.Time
	CommandLine string
}

// FileInfo contains file security information
type FileInfo struct {
	Path        string
	Size        int64
	Mode        os.FileMode
	Owner       string
	Group       string
	Modified    time.Time
	Hash        string
	Permissions string
}

// UserInfo contains user account information
type UserInfo struct {
	Username string
	UID      string
	GID      string
	HomeDir  string
	Shell    string
	Groups   []string
}

// ServiceInfo contains service/daemon information
type ServiceInfo struct {
	Name    string
	Status  string
	PID     int
	StartMode string
	User    string
}

// NewOSSecurityModule creates a new OS security module
func NewOSSecurityModule() *OSSecurityModule {
	return &OSSecurityModule{
		Platform: runtime.GOOS,
		Arch:     runtime.GOARCH,
	}
}

// GetProcessList returns list of running processes
func (o *OSSecurityModule) GetProcessList() ([]ProcessInfo, error) {
	processes := []ProcessInfo{}
	
	switch o.Platform {
	case "windows":
		return o.getWindowsProcesses()
	case "linux", "darwin":
		return o.getUnixProcesses()
	default:
		return processes, fmt.Errorf("unsupported platform: %s", o.Platform)
	}
}

// getWindowsProcesses gets Windows process list
func (o *OSSecurityModule) getWindowsProcesses() ([]ProcessInfo, error) {
	processes := []ProcessInfo{}
	
	// Use tasklist command without /v flag for better performance
	cmd := exec.Command("tasklist", "/fo", "csv")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	
	scanner := bufio.NewScanner(bytes.NewReader(output))
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		if lineNum == 1 {
			continue // Skip header
		}
		
		line := scanner.Text()
		fields := parseCSV(line)
		// Without /v flag, we have fewer fields: "Image Name","PID","Session Name","Session#","Mem Usage"
		if len(fields) >= 5 {
			pid, _ := strconv.Atoi(strings.Trim(fields[1], " "))
			mem := strings.ReplaceAll(fields[4], ",", "")
			mem = strings.ReplaceAll(mem, " K", "")
			memKB, _ := strconv.ParseUint(mem, 10, 64)
			
			proc := ProcessInfo{
				PID:    pid,
				Name:   strings.Trim(fields[0], "\""),
				Status: "Running", // Default status since we don't have this info without /v
				Memory: memKB * 1024,
				User:   fields[2], // Session name is the closest we have
			}
			processes = append(processes, proc)
		}
	}
	
	return processes, nil
}

// getUnixProcesses gets Unix/Linux process list
func (o *OSSecurityModule) getUnixProcesses() ([]ProcessInfo, error) {
	processes := []ProcessInfo{}
	
	// Use ps command
	cmd := exec.Command("ps", "aux")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	
	scanner := bufio.NewScanner(bytes.NewReader(output))
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		if lineNum == 1 {
			continue // Skip header
		}
		
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 11 {
			pid, _ := strconv.Atoi(fields[1])
			cpu, _ := strconv.ParseFloat(fields[2], 64)
			mem, _ := strconv.ParseFloat(fields[3], 64)
			
			// Join command parts
			command := strings.Join(fields[10:], " ")
			
			proc := ProcessInfo{
				PID:         pid,
				Name:        filepath.Base(fields[10]),
				User:        fields[0],
				CPU:         cpu,
				Memory:      uint64(mem * 1024 * 1024), // Convert to bytes
				Status:      fields[7],
				CommandLine: command,
			}
			processes = append(processes, proc)
		}
	}
	
	return processes, nil
}

// KillProcess terminates a process
func (o *OSSecurityModule) KillProcess(pid int, force bool) error {
	if o.Platform == "windows" {
		if force {
			return exec.Command("taskkill", "/F", "/PID", strconv.Itoa(pid)).Run()
		}
		return exec.Command("taskkill", "/PID", strconv.Itoa(pid)).Run()
	}
	
	// Unix/Linux
	process, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	
	if force {
		return process.Signal(syscall.SIGKILL)
	}
	return process.Signal(syscall.SIGTERM)
}

// GetOpenPorts returns list of open network ports
func (o *OSSecurityModule) GetOpenPorts() ([]map[string]interface{}, error) {
	ports := []map[string]interface{}{}
	
	switch o.Platform {
	case "windows":
		cmd := exec.Command("netstat", "-an")
		output, err := cmd.Output()
		if err != nil {
			return nil, err
		}
		
		scanner := bufio.NewScanner(bytes.NewReader(output))
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, "LISTENING") || strings.Contains(line, "ESTABLISHED") {
				fields := strings.Fields(line)
				if len(fields) >= 4 {
					port := map[string]interface{}{
						"protocol": fields[0],
						"local":    fields[1],
						"foreign":  fields[2],
						"state":    fields[3],
					}
					ports = append(ports, port)
				}
			}
		}
		
	case "linux", "darwin":
		cmd := exec.Command("netstat", "-tuln")
		output, err := cmd.Output()
		if err != nil {
			// Try ss command as fallback
			cmd = exec.Command("ss", "-tuln")
			output, err = cmd.Output()
			if err != nil {
				return nil, err
			}
		}
		
		scanner := bufio.NewScanner(bytes.NewReader(output))
		for scanner.Scan() {
			line := scanner.Text()
			fields := strings.Fields(line)
			if len(fields) >= 5 && (strings.HasPrefix(line, "tcp") || strings.HasPrefix(line, "udp")) {
				port := map[string]interface{}{
					"protocol": fields[0],
					"local":    fields[3],
					"foreign":  fields[4],
				}
				if len(fields) > 5 {
					port["state"] = fields[5]
				}
				ports = append(ports, port)
			}
		}
	}
	
	return ports, nil
}

// GetSystemInfo returns system information
func (o *OSSecurityModule) GetSystemInfo() map[string]interface{} {
	info := map[string]interface{}{
		"platform": o.Platform,
		"arch":     o.Arch,
		"hostname": getHostname(),
		"cpus":     runtime.NumCPU(),
		"goroutines": runtime.NumGoroutine(),
	}
	
	// Get memory info
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	info["memory"] = map[string]uint64{
		"alloc":      m.Alloc,
		"total":      m.TotalAlloc,
		"sys":        m.Sys,
		"gc_count":   uint64(m.NumGC),
	}
	
	// Get user info
	if currentUser, err := user.Current(); err == nil {
		info["user"] = map[string]string{
			"username": currentUser.Username,
			"uid":      currentUser.Uid,
			"gid":      currentUser.Gid,
			"home":     currentUser.HomeDir,
		}
	}
	
	// Get environment variables
	envVars := map[string]string{}
	for _, env := range os.Environ() {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) == 2 {
			// Only include non-sensitive environment variables
			key := parts[0]
			if !strings.Contains(strings.ToLower(key), "password") &&
			   !strings.Contains(strings.ToLower(key), "secret") &&
			   !strings.Contains(strings.ToLower(key), "key") &&
			   !strings.Contains(strings.ToLower(key), "token") {
				envVars[key] = parts[1]
			}
		}
	}
	info["env"] = envVars
	
	return info
}

// GetUsers returns list of system users
func (o *OSSecurityModule) GetUsers() ([]UserInfo, error) {
	users := []UserInfo{}
	
	switch o.Platform {
	case "windows":
		// Use net user command
		cmd := exec.Command("net", "user")
		output, err := cmd.Output()
		if err != nil {
			return nil, err
		}
		
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" && !strings.Contains(line, "-----") && 
			   !strings.Contains(line, "User accounts") && 
			   !strings.Contains(line, "The command completed") {
				// Parse user names from the output
				usernames := strings.Fields(line)
				for _, username := range usernames {
					users = append(users, UserInfo{
						Username: username,
					})
				}
			}
		}
		
	case "linux", "darwin":
		// Read /etc/passwd
		file, err := os.Open("/etc/passwd")
		if err != nil {
			return nil, err
		}
		defer file.Close()
		
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			fields := strings.Split(scanner.Text(), ":")
			if len(fields) >= 7 {
				// Skip system users (UID < 1000 on most systems)
				uid, _ := strconv.Atoi(fields[2])
				if uid >= 1000 || uid == 0 { // Include root and regular users
					user := UserInfo{
						Username: fields[0],
						UID:      fields[2],
						GID:      fields[3],
						HomeDir:  fields[5],
						Shell:    fields[6],
					}
					users = append(users, user)
				}
			}
		}
	}
	
	return users, nil
}

// GetServices returns list of system services
func (o *OSSecurityModule) GetServices() ([]ServiceInfo, error) {
	services := []ServiceInfo{}
	
	switch o.Platform {
	case "windows":
		// Use sc query command
		cmd := exec.Command("sc", "query", "state=", "all")
		output, err := cmd.Output()
		if err != nil {
			return nil, err
		}
		
		scanner := bufio.NewScanner(bytes.NewReader(output))
		var currentService ServiceInfo
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if strings.HasPrefix(line, "SERVICE_NAME:") {
				if currentService.Name != "" {
					services = append(services, currentService)
				}
				currentService = ServiceInfo{
					Name: strings.TrimPrefix(line, "SERVICE_NAME:"),
				}
			} else if strings.Contains(line, "STATE") {
				fields := strings.Fields(line)
				if len(fields) >= 4 {
					currentService.Status = fields[3]
				}
			}
		}
		if currentService.Name != "" {
			services = append(services, currentService)
		}
		
	case "linux":
		// Try systemctl first
		cmd := exec.Command("systemctl", "list-units", "--all", "--no-pager", "--plain")
		output, err := cmd.Output()
		if err == nil {
			scanner := bufio.NewScanner(bytes.NewReader(output))
			for scanner.Scan() {
				fields := strings.Fields(scanner.Text())
				if len(fields) >= 5 {
					service := ServiceInfo{
						Name:   fields[0],
						Status: fields[3],
					}
					services = append(services, service)
				}
			}
		} else {
			// Fallback to service command
			cmd = exec.Command("service", "--status-all")
			output, err = cmd.Output()
			if err != nil {
				return nil, err
			}
			
			scanner := bufio.NewScanner(bytes.NewReader(output))
			for scanner.Scan() {
				line := scanner.Text()
				if strings.Contains(line, "[") {
					status := "unknown"
					if strings.Contains(line, "[ + ]") {
						status = "running"
					} else if strings.Contains(line, "[ - ]") {
						status = "stopped"
					}
					
					name := strings.TrimSpace(line[5:])
					services = append(services, ServiceInfo{
						Name:   name,
						Status: status,
					})
				}
			}
		}
		
	case "darwin":
		// Use launchctl on macOS
		cmd := exec.Command("launchctl", "list")
		output, err := cmd.Output()
		if err != nil {
			return nil, err
		}
		
		scanner := bufio.NewScanner(bytes.NewReader(output))
		lineNum := 0
		for scanner.Scan() {
			lineNum++
			if lineNum == 1 {
				continue // Skip header
			}
			
			fields := strings.Fields(scanner.Text())
			if len(fields) >= 3 {
				pid, _ := strconv.Atoi(fields[0])
				service := ServiceInfo{
					Name:   fields[2],
					PID:    pid,
					Status: fields[1],
				}
				services = append(services, service)
			}
		}
	}
	
	return services, nil
}

// CheckFilePermissions checks file/directory permissions
func (o *OSSecurityModule) CheckFilePermissions(path string) (*FileInfo, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	
	fileInfo := &FileInfo{
		Path:        path,
		Size:        info.Size(),
		Mode:        info.Mode(),
		Modified:    info.ModTime(),
		Permissions: info.Mode().String(),
	}
	
	// Get owner information would require platform-specific implementation
	
	return fileInfo, nil
}

// FindSuspiciousFiles searches for potentially suspicious files
func (o *OSSecurityModule) FindSuspiciousFiles(directory string) ([]string, error) {
	suspicious := []string{}
	
	// Patterns that might indicate suspicious files
	suspiciousPatterns := []string{
		".exe", ".dll", ".so", ".dylib", // Executables
		".sh", ".bat", ".ps1", ".vbs",   // Scripts
		".tmp", ".temp",                  // Temporary files
		"passwd", "shadow", "hosts",      // System files
	}
	
	
	err := filepath.Walk(directory, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip inaccessible files
		}
		
		basename := filepath.Base(path)
		
		// Check for suspicious extensions
		for _, pattern := range suspiciousPatterns {
			if strings.HasSuffix(strings.ToLower(basename), pattern) {
				suspicious = append(suspicious, path)
				break
			}
		}
		
		// Check for hidden files
		if strings.HasPrefix(basename, ".") && basename != "." && basename != ".." {
			suspicious = append(suspicious, path)
		}
		
		// Check for unusual permissions
		if o.Platform != "windows" {
			mode := info.Mode()
			// World-writable files
			if mode.Perm()&0002 != 0 {
				suspicious = append(suspicious, path+" (world-writable)")
			}
			// SUID/SGID files
			if mode&os.ModeSetuid != 0 || mode&os.ModeSetgid != 0 {
				suspicious = append(suspicious, path+" (SUID/SGID)")
			}
		}
		
		return nil
	})
	
	return suspicious, err
}

// GetFirewallRules retrieves firewall rules
func (o *OSSecurityModule) GetFirewallRules() ([]string, error) {
	rules := []string{}
	
	switch o.Platform {
	case "windows":
		// Windows Firewall
		cmd := exec.Command("netsh", "advfirewall", "firewall", "show", "rule", "name=all")
		output, err := cmd.Output()
		if err != nil {
			return nil, err
		}
		rules = strings.Split(string(output), "\n")
		
	case "linux":
		// iptables
		cmd := exec.Command("iptables", "-L", "-n")
		output, err := cmd.Output()
		if err != nil {
			// Try ufw as fallback
			cmd = exec.Command("ufw", "status", "numbered")
			output, err = cmd.Output()
			if err != nil {
				return nil, err
			}
		}
		rules = strings.Split(string(output), "\n")
		
	case "darwin":
		// macOS pfctl
		cmd := exec.Command("pfctl", "-s", "rules")
		output, err := cmd.Output()
		if err != nil {
			return nil, err
		}
		rules = strings.Split(string(output), "\n")
	}
	
	return rules, nil
}

// GetScheduledTasks returns scheduled tasks/cron jobs
func (o *OSSecurityModule) GetScheduledTasks() ([]map[string]string, error) {
	tasks := []map[string]string{}
	
	switch o.Platform {
	case "windows":
		// Windows Task Scheduler
		cmd := exec.Command("schtasks", "/query", "/fo", "csv", "/v")
		output, err := cmd.Output()
		if err != nil {
			return nil, err
		}
		
		scanner := bufio.NewScanner(bytes.NewReader(output))
		lineNum := 0
		for scanner.Scan() {
			lineNum++
			if lineNum == 1 {
				continue // Skip header
			}
			
			fields := parseCSV(scanner.Text())
			if len(fields) >= 3 {
				task := map[string]string{
					"name":   fields[1],
					"status": fields[2],
				}
				if len(fields) > 8 {
					task["next_run"] = fields[3]
					task["user"] = fields[8]
				}
				tasks = append(tasks, task)
			}
		}
		
	case "linux", "darwin":
		// Crontab
		cmd := exec.Command("crontab", "-l")
		output, err := cmd.Output()
		if err == nil {
			lines := strings.Split(string(output), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line != "" && !strings.HasPrefix(line, "#") {
					tasks = append(tasks, map[string]string{
						"type": "cron",
						"entry": line,
					})
				}
			}
		}
		
		// Also check system cron
		cronDirs := []string{"/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.weekly"}
		for _, dir := range cronDirs {
			files, err := os.ReadDir(dir)
			if err == nil {
				for _, file := range files {
					tasks = append(tasks, map[string]string{
						"type": "system_cron",
						"location": filepath.Join(dir, file.Name()),
					})
				}
			}
		}
	}
	
	return tasks, nil
}

// ExecuteCommand executes a system command safely
func (o *OSSecurityModule) ExecuteCommand(command string, args []string, timeout time.Duration) (string, error) {
	cmd := exec.Command(command, args...)
	
	// Set timeout
	if timeout > 0 {
		timer := time.AfterFunc(timeout, func() {
			cmd.Process.Kill()
		})
		defer timer.Stop()
	}
	
	// Capture output
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	
	err := cmd.Run()
	if err != nil {
		return stderr.String(), err
	}
	
	return stdout.String(), nil
}

// MonitorFileChanges monitors file system changes
func (o *OSSecurityModule) MonitorFileChanges(path string, duration time.Duration) ([]string, error) {
	changes := []string{}
	
	// Initial snapshot
	initialState := make(map[string]time.Time)
	err := filepath.Walk(path, func(p string, info os.FileInfo, err error) error {
		if err == nil {
			initialState[p] = info.ModTime()
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	
	// Wait
	time.Sleep(duration)
	
	// Check for changes
	err = filepath.Walk(path, func(p string, info os.FileInfo, err error) error {
		if err == nil {
			if oldTime, exists := initialState[p]; exists {
				if !info.ModTime().Equal(oldTime) {
					changes = append(changes, fmt.Sprintf("Modified: %s", p))
				}
				delete(initialState, p)
			} else {
				changes = append(changes, fmt.Sprintf("Created: %s", p))
			}
		}
		return nil
	})
	
	// Check for deletions
	for p := range initialState {
		changes = append(changes, fmt.Sprintf("Deleted: %s", p))
	}
	
	return changes, err
}

// Helper functions

func getHostname() string {
	hostname, _ := os.Hostname()
	return hostname
}

func parseCSV(line string) []string {
	var fields []string
	var current strings.Builder
	inQuotes := false
	
	for _, r := range line {
		switch r {
		case '"':
			inQuotes = !inQuotes
		case ',':
			if !inQuotes {
				fields = append(fields, current.String())
				current.Reset()
			} else {
				current.WriteRune(r)
			}
		default:
			current.WriteRune(r)
		}
	}
	
	if current.Len() > 0 {
		fields = append(fields, current.String())
	}
	
	return fields
}

// CheckPrivileges checks if running with elevated privileges
func (o *OSSecurityModule) CheckPrivileges() bool {
	switch o.Platform {
	case "windows":
		// Check if running as administrator
		cmd := exec.Command("net", "session")
		err := cmd.Run()
		return err == nil
	case "linux", "darwin":
		// Check if running as root
		return os.Geteuid() == 0
	}
	return false
}

// GetInstalledSoftware returns list of installed software
func (o *OSSecurityModule) GetInstalledSoftware() ([]map[string]string, error) {
	software := []map[string]string{}
	
	switch o.Platform {
	case "windows":
		// Use wmic command
		cmd := exec.Command("wmic", "product", "get", "name,version", "/format:csv")
		output, err := cmd.Output()
		if err != nil {
			return nil, err
		}
		
		scanner := bufio.NewScanner(bytes.NewReader(output))
		for scanner.Scan() {
			line := scanner.Text()
			fields := strings.Split(line, ",")
			if len(fields) >= 3 && fields[1] != "Name" {
				software = append(software, map[string]string{
					"name":    fields[1],
					"version": fields[2],
				})
			}
		}
		
	case "linux":
		// Try different package managers
		if _, err := exec.LookPath("dpkg"); err == nil {
			cmd := exec.Command("dpkg", "-l")
			output, _ := cmd.Output()
			scanner := bufio.NewScanner(bytes.NewReader(output))
			for scanner.Scan() {
				line := scanner.Text()
				if strings.HasPrefix(line, "ii") {
					fields := strings.Fields(line)
					if len(fields) >= 3 {
						software = append(software, map[string]string{
							"name":    fields[1],
							"version": fields[2],
						})
					}
				}
			}
		} else if _, err := exec.LookPath("rpm"); err == nil {
			cmd := exec.Command("rpm", "-qa")
			output, _ := cmd.Output()
			lines := strings.Split(string(output), "\n")
			for _, line := range lines {
				if line != "" {
					software = append(software, map[string]string{
						"name": line,
					})
				}
			}
		}
		
	case "darwin":
		// Use system_profiler on macOS
		cmd := exec.Command("system_profiler", "SPApplicationsDataType", "-json")
		output, err := cmd.Output()
		if err != nil {
			return nil, err
		}
		// Would need JSON parsing here
		_ = output // Mark as used
		software = append(software, map[string]string{
			"info": "Application list available",
		})
	}
	
	return software, nil
}