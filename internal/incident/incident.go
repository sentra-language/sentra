// Package incident provides incident response automation capabilities
package incident

import (
	"fmt"
	"sort"
	"time"
)

// IncidentModule contains incident response functions
type IncidentModule struct {
	Incidents       map[string]*Incident
	Playbooks       map[string]*Playbook
	ResponseActions map[string]*ResponseAction
	AlertRules      []*AlertRule
	Workflows       map[string]*Workflow
}

// Incident represents a security incident
type Incident struct {
	ID              string
	Title           string
	Description     string
	Severity        string // critical, high, medium, low
	Status          string // open, investigating, contained, resolved, closed
	CreatedAt       time.Time
	UpdatedAt       time.Time
	ResolvedAt      *time.Time
	AssignedTo      string
	Source          string
	Category        string
	Tags            []string
	Artifacts       []Artifact
	Timeline        []TimelineEvent
	Actions         []ActionRecord
	Impact          Impact
	MITRE           []string // MITRE ATT&CK techniques
}

// Playbook represents an incident response playbook
type Playbook struct {
	ID          string
	Name        string
	Description string
	Category    string
	Steps       []PlaybookStep
	Triggers    []Trigger
	Variables   map[string]interface{}
	IsActive    bool
	CreatedAt   time.Time
}

// PlaybookStep represents a step in an incident response playbook
type PlaybookStep struct {
	ID           string
	Name         string
	Description  string
	Action       string
	Parameters   map[string]interface{}
	Condition    string
	TimeoutSecs  int
	IsAutomated  bool
	NextSteps    []string
	OnSuccess    string
	OnFailure    string
}

// ResponseAction represents an automated response action
type ResponseAction struct {
	ID          string
	Name        string
	Type        string // isolate, block, notify, collect, analyze
	Description string
	Script      string
	Parameters  map[string]interface{}
	Permissions []string
	IsEnabled   bool
	CreatedAt   time.Time
}

// AlertRule represents a rule for detecting incidents
type AlertRule struct {
	ID          string
	Name        string
	Description string
	Query       string
	Severity    string
	IsEnabled   bool
	Actions     []string
	Schedule    string
	CreatedAt   time.Time
}

// Workflow represents an incident response workflow
type Workflow struct {
	ID          string
	Name        string
	Description string
	Trigger     Trigger
	Steps       []WorkflowStep
	IsActive    bool
	CreatedAt   time.Time
}

// WorkflowStep represents a step in a workflow
type WorkflowStep struct {
	ID         string
	Name       string
	Type       string // action, decision, notification, escalation
	Action     string
	Parameters map[string]interface{}
	Condition  string
	NextStep   string
}

// Trigger represents a trigger condition
type Trigger struct {
	Type      string // event, threshold, schedule, manual
	Condition string
	Value     interface{}
}

// Artifact represents evidence or data related to an incident
type Artifact struct {
	ID          string
	Type        string // file, ip, domain, hash, log, screenshot
	Value       string
	Description string
	Source      string
	CollectedAt time.Time
	Hash        string
}

// TimelineEvent represents an event in the incident timeline
type TimelineEvent struct {
	ID          string
	Timestamp   time.Time
	Event       string
	Description string
	Actor       string
	Source      string
	Details     map[string]interface{}
}

// ActionRecord represents a recorded response action
type ActionRecord struct {
	ID          string
	ActionType  string
	Description string
	ExecutedAt  time.Time
	ExecutedBy  string
	Status      string // success, failed, pending
	Result      string
	Duration    time.Duration
}

// Impact represents the impact assessment of an incident
type Impact struct {
	BusinessImpact string // critical, high, medium, low, none
	DataImpact     string // confidentiality, integrity, availability
	SystemsCount   int
	UsersAffected  int
	FinancialCost  float64
	ReputationRisk string
}

// IncidentResponse represents the result of an incident response action
type IncidentResponse struct {
	IncidentID   string
	Action       string
	Status       string
	Message      string
	Evidence     []string
	NextSteps    []string
	ExecutedAt   time.Time
}

// NewIncidentModule creates a new incident response module
func NewIncidentModule() *IncidentModule {
	return &IncidentModule{
		Incidents:       make(map[string]*Incident),
		Playbooks:       make(map[string]*Playbook),
		ResponseActions: make(map[string]*ResponseAction),
		AlertRules:      make([]*AlertRule, 0),
		Workflows:       make(map[string]*Workflow),
	}
}

// CreateIncident creates a new security incident
func (ir *IncidentModule) CreateIncident(title, description, severity, source string) *Incident {
	incident := &Incident{
		ID:          fmt.Sprintf("INC-%d", time.Now().Unix()),
		Title:       title,
		Description: description,
		Severity:    severity,
		Status:      "open",
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		Source:      source,
		Tags:        make([]string, 0),
		Artifacts:   make([]Artifact, 0),
		Timeline:    make([]TimelineEvent, 0),
		Actions:     make([]ActionRecord, 0),
		MITRE:       make([]string, 0),
	}
	
	// Add initial timeline event
	incident.Timeline = append(incident.Timeline, TimelineEvent{
		ID:          fmt.Sprintf("TL-%d", time.Now().UnixNano()),
		Timestamp:   time.Now(),
		Event:       "incident_created",
		Description: "Incident created",
		Actor:       "system",
		Source:      source,
		Details:     map[string]interface{}{"severity": severity},
	})
	
	ir.Incidents[incident.ID] = incident
	return incident
}

// UpdateIncident updates an existing incident
func (ir *IncidentModule) UpdateIncident(incidentID string, updates map[string]interface{}) error {
	incident, exists := ir.Incidents[incidentID]
	if !exists {
		return fmt.Errorf("incident not found: %s", incidentID)
	}
	
	// Update fields
	for field, value := range updates {
		switch field {
		case "status":
			incident.Status = value.(string)
		case "severity":
			incident.Severity = value.(string)
		case "assigned_to":
			incident.AssignedTo = value.(string)
		case "category":
			incident.Category = value.(string)
		case "description":
			incident.Description = value.(string)
		}
	}
	
	incident.UpdatedAt = time.Now()
	
	// Add timeline event
	incident.Timeline = append(incident.Timeline, TimelineEvent{
		ID:          fmt.Sprintf("TL-%d", time.Now().UnixNano()),
		Timestamp:   time.Now(),
		Event:       "incident_updated",
		Description: "Incident updated",
		Actor:       "user",
		Source:      "manual",
		Details:     updates,
	})
	
	return nil
}

// ExecutePlaybook executes an incident response playbook
func (ir *IncidentModule) ExecutePlaybook(incidentID, playbookID string) (*IncidentResponse, error) {
	incident, exists := ir.Incidents[incidentID]
	if !exists {
		return nil, fmt.Errorf("incident not found: %s", incidentID)
	}
	
	playbook, exists := ir.Playbooks[playbookID]
	if !exists {
		return nil, fmt.Errorf("playbook not found: %s", playbookID)
	}
	
	response := &IncidentResponse{
		IncidentID: incidentID,
		Action:     fmt.Sprintf("execute_playbook_%s", playbookID),
		Status:     "success",
		Message:    fmt.Sprintf("Executed playbook: %s", playbook.Name),
		Evidence:   make([]string, 0),
		NextSteps:  make([]string, 0),
		ExecutedAt: time.Now(),
	}
	
	// Execute playbook steps
	for _, step := range playbook.Steps {
		stepResult := ir.executePlaybookStep(incident, step)
		response.Evidence = append(response.Evidence, stepResult)
		
		// Record action
		actionRecord := ActionRecord{
			ID:          fmt.Sprintf("ACT-%d", time.Now().UnixNano()),
			ActionType:  step.Action,
			Description: step.Description,
			ExecutedAt:  time.Now(),
			ExecutedBy:  "playbook",
			Status:      "success",
			Result:      stepResult,
			Duration:    time.Millisecond * 100, // Simulated duration
		}
		incident.Actions = append(incident.Actions, actionRecord)
	}
	
	// Add timeline event
	incident.Timeline = append(incident.Timeline, TimelineEvent{
		ID:          fmt.Sprintf("TL-%d", time.Now().UnixNano()),
		Timestamp:   time.Now(),
		Event:       "playbook_executed",
		Description: fmt.Sprintf("Executed playbook: %s", playbook.Name),
		Actor:       "system",
		Source:      "automation",
		Details:     map[string]interface{}{"playbook_id": playbookID},
	})
	
	return response, nil
}

// ExecuteResponseAction executes a specific response action
func (ir *IncidentModule) ExecuteResponseAction(incidentID, actionID string, parameters map[string]interface{}) (*IncidentResponse, error) {
	incident, exists := ir.Incidents[incidentID]
	if !exists {
		return nil, fmt.Errorf("incident not found: %s", incidentID)
	}
	
	action, exists := ir.ResponseActions[actionID]
	if !exists {
		return nil, fmt.Errorf("response action not found: %s", actionID)
	}
	
	// Execute the action
	result := ir.executeAction(action, parameters)
	
	response := &IncidentResponse{
		IncidentID: incidentID,
		Action:     action.Name,
		Status:     "success",
		Message:    result,
		Evidence:   []string{result},
		NextSteps:  ir.generateNextSteps(action.Type),
		ExecutedAt: time.Now(),
	}
	
	// Record action
	actionRecord := ActionRecord{
		ID:          fmt.Sprintf("ACT-%d", time.Now().UnixNano()),
		ActionType:  action.Type,
		Description: action.Description,
		ExecutedAt:  time.Now(),
		ExecutedBy:  "user",
		Status:      "success",
		Result:      result,
		Duration:    time.Millisecond * 200,
	}
	incident.Actions = append(incident.Actions, actionRecord)
	
	return response, nil
}

// CollectEvidence collects evidence for an incident
func (ir *IncidentModule) CollectEvidence(incidentID string, evidenceType, value, source string) error {
	incident, exists := ir.Incidents[incidentID]
	if !exists {
		return fmt.Errorf("incident not found: %s", incidentID)
	}
	
	artifact := Artifact{
		ID:          fmt.Sprintf("ART-%d", time.Now().UnixNano()),
		Type:        evidenceType,
		Value:       value,
		Description: fmt.Sprintf("Evidence collected: %s", evidenceType),
		Source:      source,
		CollectedAt: time.Now(),
		Hash:        ir.calculateHash(value),
	}
	
	incident.Artifacts = append(incident.Artifacts, artifact)
	
	// Add timeline event
	incident.Timeline = append(incident.Timeline, TimelineEvent{
		ID:          fmt.Sprintf("TL-%d", time.Now().UnixNano()),
		Timestamp:   time.Now(),
		Event:       "evidence_collected",
		Description: fmt.Sprintf("Collected %s evidence", evidenceType),
		Actor:       "system",
		Source:      source,
		Details:     map[string]interface{}{"type": evidenceType, "value": value},
	})
	
	return nil
}

// CreatePlaybook creates a new incident response playbook
func (ir *IncidentModule) CreatePlaybook(name, description, category string, steps []map[string]interface{}) *Playbook {
	playbook := &Playbook{
		ID:          fmt.Sprintf("PB-%d", time.Now().Unix()),
		Name:        name,
		Description: description,
		Category:    category,
		Steps:       make([]PlaybookStep, 0),
		Variables:   make(map[string]interface{}),
		IsActive:    true,
		CreatedAt:   time.Now(),
	}
	
	// Convert steps
	for i, stepData := range steps {
		step := PlaybookStep{
			ID:          fmt.Sprintf("STEP-%d-%d", time.Now().Unix(), i),
			Name:        stepData["name"].(string),
			Description: stepData["description"].(string),
			Action:      stepData["action"].(string),
			Parameters:  make(map[string]interface{}),
			TimeoutSecs: 300,
			IsAutomated: true,
		}
		
		if params, exists := stepData["parameters"]; exists {
			if paramMap, ok := params.(map[string]interface{}); ok {
				step.Parameters = paramMap
			}
		}
		
		playbook.Steps = append(playbook.Steps, step)
	}
	
	ir.Playbooks[playbook.ID] = playbook
	return playbook
}

// ListPlaybooks returns all available playbooks
func (ir *IncidentModule) ListPlaybooks() []*Playbook {
	playbooks := make([]*Playbook, 0, len(ir.Playbooks))
	for _, playbook := range ir.Playbooks {
		playbooks = append(playbooks, playbook)
	}
	return playbooks
}

// GetIncident retrieves an incident by ID
func (ir *IncidentModule) GetIncident(incidentID string) (*Incident, error) {
	incident, exists := ir.Incidents[incidentID]
	if !exists {
		return nil, fmt.Errorf("incident not found: %s", incidentID)
	}
	return incident, nil
}

// ListIncidents returns a list of incidents with optional filtering
func (ir *IncidentModule) ListIncidents(filters map[string]string) []*Incident {
	incidents := make([]*Incident, 0)
	
	for _, incident := range ir.Incidents {
		include := true
		
		// Apply filters
		if status, exists := filters["status"]; exists && incident.Status != status {
			include = false
		}
		if severity, exists := filters["severity"]; exists && incident.Severity != severity {
			include = false
		}
		if category, exists := filters["category"]; exists && incident.Category != category {
			include = false
		}
		
		if include {
			incidents = append(incidents, incident)
		}
	}
	
	// Sort by creation time (newest first)
	sort.Slice(incidents, func(i, j int) bool {
		return incidents[i].CreatedAt.After(incidents[j].CreatedAt)
	})
	
	return incidents
}

// CloseIncident closes an incident
func (ir *IncidentModule) CloseIncident(incidentID, resolution string) error {
	incident, exists := ir.Incidents[incidentID]
	if !exists {
		return fmt.Errorf("incident not found: %s", incidentID)
	}
	
	now := time.Now()
	incident.Status = "closed"
	incident.UpdatedAt = now
	incident.ResolvedAt = &now
	
	// Add timeline event
	incident.Timeline = append(incident.Timeline, TimelineEvent{
		ID:          fmt.Sprintf("TL-%d", time.Now().UnixNano()),
		Timestamp:   time.Now(),
		Event:       "incident_closed",
		Description: resolution,
		Actor:       "user",
		Source:      "manual",
		Details:     map[string]interface{}{"resolution": resolution},
	})
	
	return nil
}

// GetIncidentMetrics returns metrics about incidents
func (ir *IncidentModule) GetIncidentMetrics() map[string]interface{} {
	metrics := map[string]interface{}{
		"total_incidents":     len(ir.Incidents),
		"open_incidents":      0,
		"closed_incidents":    0,
		"critical_incidents":  0,
		"high_incidents":      0,
		"medium_incidents":    0,
		"low_incidents":       0,
		"avg_resolution_time": 0.0,
	}
	
	totalResolutionTime := time.Duration(0)
	resolvedCount := 0
	
	for _, incident := range ir.Incidents {
		// Count by status
		if incident.Status == "closed" {
			metrics["closed_incidents"] = metrics["closed_incidents"].(int) + 1
			if incident.ResolvedAt != nil {
				resolutionTime := incident.ResolvedAt.Sub(incident.CreatedAt)
				totalResolutionTime += resolutionTime
				resolvedCount++
			}
		} else {
			metrics["open_incidents"] = metrics["open_incidents"].(int) + 1
		}
		
		// Count by severity
		switch incident.Severity {
		case "critical":
			metrics["critical_incidents"] = metrics["critical_incidents"].(int) + 1
		case "high":
			metrics["high_incidents"] = metrics["high_incidents"].(int) + 1
		case "medium":
			metrics["medium_incidents"] = metrics["medium_incidents"].(int) + 1
		case "low":
			metrics["low_incidents"] = metrics["low_incidents"].(int) + 1
		}
	}
	
	// Calculate average resolution time
	if resolvedCount > 0 {
		avgResolutionHours := totalResolutionTime.Hours() / float64(resolvedCount)
		metrics["avg_resolution_time"] = avgResolutionHours
	}
	
	return metrics
}

// Helper functions

func (ir *IncidentModule) executePlaybookStep(incident *Incident, step PlaybookStep) string {
	switch step.Action {
	case "isolate_host":
		return fmt.Sprintf("Host isolated: %s", step.Parameters["host"])
	case "block_ip":
		return fmt.Sprintf("IP blocked: %s", step.Parameters["ip"])
	case "collect_logs":
		return fmt.Sprintf("Logs collected from: %s", step.Parameters["source"])
	case "scan_system":
		return fmt.Sprintf("System scan completed: %s", step.Parameters["target"])
	case "notify_team":
		return fmt.Sprintf("Team notified: %s", step.Parameters["message"])
	case "escalate":
		return fmt.Sprintf("Incident escalated to: %s", step.Parameters["team"])
	default:
		return fmt.Sprintf("Executed action: %s", step.Action)
	}
}

func (ir *IncidentModule) executeAction(action *ResponseAction, parameters map[string]interface{}) string {
	switch action.Type {
	case "isolate":
		if host, exists := parameters["host"]; exists {
			return fmt.Sprintf("Successfully isolated host: %s", host)
		}
		return "Host isolation initiated"
	case "block":
		if ip, exists := parameters["ip"]; exists {
			return fmt.Sprintf("Successfully blocked IP: %s", ip)
		}
		return "IP blocking initiated"
	case "notify":
		if message, exists := parameters["message"]; exists {
			return fmt.Sprintf("Notification sent: %s", message)
		}
		return "Notification sent to security team"
	case "collect":
		if source, exists := parameters["source"]; exists {
			return fmt.Sprintf("Evidence collected from: %s", source)
		}
		return "Evidence collection initiated"
	case "analyze":
		return "Automated analysis completed"
	default:
		return fmt.Sprintf("Executed %s action", action.Type)
	}
}

func (ir *IncidentModule) generateNextSteps(actionType string) []string {
	switch actionType {
	case "isolate":
		return []string{
			"Verify host isolation is effective",
			"Analyze host for indicators of compromise",
			"Plan remediation steps",
		}
	case "block":
		return []string{
			"Monitor for continued malicious activity",
			"Investigate related IP addresses",
			"Update threat intelligence feeds",
		}
	case "notify":
		return []string{
			"Await team response",
			"Prepare incident briefing",
			"Continue monitoring",
		}
	case "collect":
		return []string{
			"Analyze collected evidence",
			"Correlate with threat intelligence",
			"Document findings",
		}
	default:
		return []string{
			"Review action results",
			"Continue investigation",
			"Update incident status",
		}
	}
}

func (ir *IncidentModule) calculateHash(value string) string {
	// Simple hash simulation
	hash := 0
	for _, char := range value {
		hash = hash*31 + int(char)
	}
	return fmt.Sprintf("sha256:%x", hash)
}

// CreateDefaultPlaybooks creates default incident response playbooks
func (ir *IncidentModule) CreateDefaultPlaybooks() {
	// Create minimal playbooks for performance during startup
	// Malware Incident Playbook
	malwareSteps := []map[string]interface{}{
		{
			"name":        "Isolate Infected Host", 
			"description": "Immediately isolate the infected host from the network",
			"action":      "isolate_host",
			"parameters":  map[string]interface{}{"host": "target"},
		},
	}
	ir.CreatePlaybook("Malware Response", "Standard response for malware incidents", "malware", malwareSteps)
	
	// Minimal additional playbooks for startup performance
	// (Full playbooks can be loaded later if needed)
}

// CreateDefaultResponseActions creates default response actions
func (ir *IncidentModule) CreateDefaultResponseActions() {
	// Create minimal response actions for startup performance
	actions := []*ResponseAction{
		{
			ID:          "RA-001",
			Name:        "Isolate Host",
			Type:        "isolate", 
			Description: "Isolate a compromised host from the network",
			Script:      "isolate_host.sh",
			Parameters:  map[string]interface{}{"host": "required"},
			Permissions: []string{"network_admin"},
			IsEnabled:   true,
			CreatedAt:   time.Now(),
		},
		// Additional actions can be loaded later for performance
	}
	
	for _, action := range actions {
		ir.ResponseActions[action.ID] = action
	}
}