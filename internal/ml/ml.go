// Package ml provides machine learning capabilities for security analysis
package ml

import (
	"fmt"
	"math"
	"math/rand"
	"sort"
	"strings"
	"time"
)

// MLModule contains machine learning functions for security
type MLModule struct {
	Models         map[string]*Model
	TrainingData   []TrainingRecord
	AnomalyData    []AnomalyPoint
	ThreatProfiles map[string]*ThreatProfile
}

// Model represents a trained ML model
type Model struct {
	Name         string
	Type         string // "anomaly", "classification", "clustering"
	Accuracy     float64
	TrainedAt    time.Time
	Features     []string
	Parameters   map[string]interface{}
	IsActive     bool
}

// TrainingRecord represents a single training data point
type TrainingRecord struct {
	ID       string
	Features map[string]float64
	Label    string
	Weight   float64
	Source   string
}

// AnomalyPoint represents a data point for anomaly detection
type AnomalyPoint struct {
	Timestamp   time.Time
	Features    map[string]float64
	Score       float64
	IsAnomaly   bool
	Severity    string
	Description string
}

// ThreatProfile represents a behavioral threat profile
type ThreatProfile struct {
	Name            string
	ThreatType      string
	Indicators      []string
	Confidence      float64
	UpdatedAt       time.Time
	AttackPatterns  []AttackPattern
	Countermeasures []string
}

// AttackPattern represents a specific attack pattern
type AttackPattern struct {
	Name        string
	Description string
	Techniques  []string
	Signatures  []string
	Frequency   float64
}

// AnomalyResult represents the result of anomaly detection
type AnomalyResult struct {
	IsAnomalous     bool
	Score           float64
	Threshold       float64
	Features        map[string]float64
	Explanation     string
	Recommendations []string
}

// ClassificationResult represents the result of threat classification
type ClassificationResult struct {
	PredictedClass string
	Confidence     float64
	Probabilities  map[string]float64
	Features       []string
	ModelUsed      string
}

// BehaviorAnalysis represents behavioral analysis results
type BehaviorAnalysis struct {
	EntityID        string
	BehaviorType    string
	BaselineScore   float64
	CurrentScore    float64
	Deviation       float64
	TrendAnalysis   []TrendPoint
	RiskLevel       string
	Recommendations []string
}

// TrendPoint represents a point in behavioral trend analysis
type TrendPoint struct {
	Timestamp time.Time
	Value     float64
	Metric    string
}

// ModelMetrics represents model performance metrics
type ModelMetrics struct {
	Accuracy  float64
	Precision float64
	Recall    float64
	F1Score   float64
	AUC       float64
}

// NewMLModule creates a new machine learning module
func NewMLModule() *MLModule {
	return &MLModule{
		Models:         make(map[string]*Model),
		TrainingData:   make([]TrainingRecord, 0),
		AnomalyData:    make([]AnomalyPoint, 0),
		ThreatProfiles: make(map[string]*ThreatProfile),
	}
}

// DetectAnomalies performs anomaly detection on given data
func (ml *MLModule) DetectAnomalies(data map[string]interface{}, modelName string) (*AnomalyResult, error) {
	// Convert input data to feature vector
	features := ml.extractFeatures(data)
	
	// Get or create anomaly detection model
	model, exists := ml.Models[modelName]
	if !exists {
		model = ml.createDefaultAnomalyModel(modelName)
		ml.Models[modelName] = model
	}
	
	// Calculate anomaly score using statistical methods
	score := ml.calculateAnomalyScore(features, model)
	threshold := 0.8 // Default threshold
	
	isAnomalous := score > threshold
	
	result := &AnomalyResult{
		IsAnomalous:     isAnomalous,
		Score:           score,
		Threshold:       threshold,
		Features:        features,
		Explanation:     ml.generateAnomalyExplanation(features, score, isAnomalous),
		Recommendations: ml.generateAnomalyRecommendations(features, score, isAnomalous),
	}
	
	// Store anomaly data for future learning
	anomalyPoint := AnomalyPoint{
		Timestamp:   time.Now(),
		Features:    features,
		Score:       score,
		IsAnomaly:   isAnomalous,
		Severity:    ml.calculateSeverity(score),
		Description: result.Explanation,
	}
	ml.AnomalyData = append(ml.AnomalyData, anomalyPoint)
	
	return result, nil
}

// ClassifyThreat classifies a potential threat based on features
func (ml *MLModule) ClassifyThreat(features map[string]interface{}, modelName string) (*ClassificationResult, error) {
	// Extract and normalize features
	featureVector := ml.extractFeatures(features)
	
	// Get or create classification model
	model, exists := ml.Models[modelName]
	if !exists {
		model = ml.createDefaultClassificationModel(modelName)
		ml.Models[modelName] = model
	}
	
	// Perform classification using simple rule-based approach
	predictions := ml.classifyUsingRules(featureVector)
	
	// Find best prediction
	var bestClass string
	var maxConfidence float64
	
	for class, confidence := range predictions {
		if confidence > maxConfidence {
			maxConfidence = confidence
			bestClass = class
		}
	}
	
	result := &ClassificationResult{
		PredictedClass: bestClass,
		Confidence:     maxConfidence,
		Probabilities:  predictions,
		Features:       ml.getFeatureNames(featureVector),
		ModelUsed:      modelName,
	}
	
	return result, nil
}

// AnalyzeBehavior performs behavioral analysis on entity data
func (ml *MLModule) AnalyzeBehavior(entityID string, behaviorData []map[string]interface{}) (*BehaviorAnalysis, error) {
	if len(behaviorData) == 0 {
		return nil, fmt.Errorf("no behavior data provided for entity %s", entityID)
	}
	
	// Calculate baseline behavior
	baseline := ml.calculateBaseline(behaviorData)
	
	// Analyze current behavior
	current := ml.analyzeCurrent(behaviorData)
	
	// Calculate deviation from baseline
	deviation := math.Abs(current - baseline) / baseline
	
	// Generate trend analysis
	trends := ml.generateTrendAnalysis(behaviorData)
	
	// Determine risk level
	riskLevel := ml.calculateRiskLevel(deviation, trends)
	
	result := &BehaviorAnalysis{
		EntityID:        entityID,
		BehaviorType:    "security_behavior",
		BaselineScore:   baseline,
		CurrentScore:    current,
		Deviation:       deviation,
		TrendAnalysis:   trends,
		RiskLevel:       riskLevel,
		Recommendations: ml.generateBehaviorRecommendations(deviation, riskLevel),
	}
	
	return result, nil
}

// TrainModel trains a machine learning model with provided data
func (ml *MLModule) TrainModel(modelName, modelType string, trainingData []map[string]interface{}) (*ModelMetrics, error) {
	// Convert training data to internal format
	records := ml.convertTrainingData(trainingData)
	
	// Create or update model
	model := &Model{
		Name:       modelName,
		Type:       modelType,
		TrainedAt:  time.Now(),
		Features:   ml.extractFeatureNames(records),
		Parameters: make(map[string]interface{}),
		IsActive:   true,
	}
	
	// Simulate training process
	metrics := ml.simulateTraining(records, modelType)
	model.Accuracy = metrics.Accuracy
	
	// Store model
	ml.Models[modelName] = model
	
	// Store training data
	ml.TrainingData = append(ml.TrainingData, records...)
	
	return metrics, nil
}

// GetModelInfo returns information about a specific model
func (ml *MLModule) GetModelInfo(modelName string) (map[string]interface{}, error) {
	model, exists := ml.Models[modelName]
	if !exists {
		return nil, fmt.Errorf("model not found: %s", modelName)
	}
	
	info := map[string]interface{}{
		"name":       model.Name,
		"type":       model.Type,
		"accuracy":   model.Accuracy,
		"trained_at": model.TrainedAt.Format("2006-01-02 15:04:05"),
		"features":   model.Features,
		"is_active":  model.IsActive,
	}
	
	return info, nil
}

// ListModels returns a list of all available models
func (ml *MLModule) ListModels() []map[string]interface{} {
	models := make([]map[string]interface{}, 0, len(ml.Models))
	
	for _, model := range ml.Models {
		modelInfo := map[string]interface{}{
			"name":     model.Name,
			"type":     model.Type,
			"accuracy": model.Accuracy,
			"active":   model.IsActive,
		}
		models = append(models, modelInfo)
	}
	
	return models
}

// CreateThreatProfile creates a new threat profile based on patterns
func (ml *MLModule) CreateThreatProfile(name, threatType string, indicators []string) *ThreatProfile {
	profile := &ThreatProfile{
		Name:       name,
		ThreatType: threatType,
		Indicators: indicators,
		Confidence: 0.8,
		UpdatedAt:  time.Now(),
		AttackPatterns: ml.generateAttackPatterns(threatType),
		Countermeasures: ml.generateCountermeasures(threatType),
	}
	
	ml.ThreatProfiles[name] = profile
	return profile
}

// Helper functions

func (ml *MLModule) extractFeatures(data map[string]interface{}) map[string]float64 {
	features := make(map[string]float64)
	
	for key, value := range data {
		switch v := value.(type) {
		case float64:
			features[key] = v
		case int:
			features[key] = float64(v)
		case string:
			// Convert string to numeric features
			features[key+"_length"] = float64(len(v))
			features[key+"_entropy"] = ml.calculateEntropy(v)
		case bool:
			if v {
				features[key] = 1.0
			} else {
				features[key] = 0.0
			}
		}
	}
	
	return features
}

func (ml *MLModule) calculateEntropy(s string) float64 {
	if len(s) == 0 {
		return 0.0
	}
	
	freq := make(map[rune]int)
	for _, char := range s {
		freq[char]++
	}
	
	entropy := 0.0
	length := float64(len(s))
	
	for _, count := range freq {
		prob := float64(count) / length
		if prob > 0 {
			entropy -= prob * math.Log2(prob)
		}
	}
	
	return entropy
}

func (ml *MLModule) createDefaultAnomalyModel(name string) *Model {
	return &Model{
		Name:       name,
		Type:       "anomaly",
		Accuracy:   0.85,
		TrainedAt:  time.Now(),
		Features:   []string{"activity_count", "error_rate", "response_time"},
		Parameters: map[string]interface{}{"threshold": 0.8},
		IsActive:   true,
	}
}

func (ml *MLModule) createDefaultClassificationModel(name string) *Model {
	return &Model{
		Name:       name,
		Type:       "classification",
		Accuracy:   0.90,
		TrainedAt:  time.Now(),
		Features:   []string{"request_rate", "error_pattern", "ip_reputation"},
		Parameters: map[string]interface{}{"classes": []string{"benign", "malicious", "suspicious"}},
		IsActive:   true,
	}
}

func (ml *MLModule) calculateAnomalyScore(features map[string]float64, model *Model) float64 {
	// Simple statistical anomaly detection
	score := 0.0
	count := 0
	
	for _, value := range features {
		// Normalize value and calculate deviation from expected range
		normalized := math.Tanh(value / 100.0) // Simple normalization
		deviation := math.Abs(normalized - 0.5) * 2 // Expected center at 0.5
		score += deviation
		count++
	}
	
	if count > 0 {
		score = score / float64(count)
	}
	
	// Add some randomness for demonstration
	score += (rand.Float64() - 0.5) * 0.2
	
	return math.Max(0, math.Min(1, score))
}

func (ml *MLModule) classifyUsingRules(features map[string]float64) map[string]float64 {
	predictions := make(map[string]float64)
	
	// Rule-based classification
	suspiciousScore := 0.0
	maliciousScore := 0.0
	benignScore := 1.0
	
	for key, value := range features {
		if strings.Contains(key, "error") && value > 0.5 {
			suspiciousScore += 0.3
			maliciousScore += 0.2
			benignScore -= 0.2
		}
		if strings.Contains(key, "rate") && value > 0.8 {
			maliciousScore += 0.4
			benignScore -= 0.3
		}
		if strings.Contains(key, "entropy") && value > 4.0 {
			suspiciousScore += 0.2
		}
	}
	
	// Normalize scores
	total := suspiciousScore + maliciousScore + benignScore
	if total > 0 {
		predictions["suspicious"] = suspiciousScore / total
		predictions["malicious"] = maliciousScore / total
		predictions["benign"] = benignScore / total
	} else {
		predictions["benign"] = 1.0
		predictions["suspicious"] = 0.0
		predictions["malicious"] = 0.0
	}
	
	return predictions
}

func (ml *MLModule) calculateBaseline(data []map[string]interface{}) float64 {
	if len(data) == 0 {
		return 0.0
	}
	
	total := 0.0
	count := 0
	
	for _, record := range data {
		for _, value := range record {
			if v, ok := value.(float64); ok {
				total += v
				count++
			} else if v, ok := value.(int); ok {
				total += float64(v)
				count++
			}
		}
	}
	
	if count > 0 {
		return total / float64(count)
	}
	
	return 0.0
}

func (ml *MLModule) analyzeCurrent(data []map[string]interface{}) float64 {
	// Use the last few records as "current" behavior
	recentCount := int(math.Min(5, float64(len(data))))
	if recentCount == 0 {
		return 0.0
	}
	
	recentData := data[len(data)-recentCount:]
	return ml.calculateBaseline(recentData)
}

func (ml *MLModule) generateTrendAnalysis(data []map[string]interface{}) []TrendPoint {
	trends := make([]TrendPoint, 0)
	
	for i, record := range data {
		timestamp := time.Now().Add(-time.Duration(len(data)-i) * time.Hour)
		value := 0.0
		count := 0
		
		for _, v := range record {
			if fv, ok := v.(float64); ok {
				value += fv
				count++
			} else if iv, ok := v.(int); ok {
				value += float64(iv)
				count++
			}
		}
		
		if count > 0 {
			value = value / float64(count)
		}
		
		trends = append(trends, TrendPoint{
			Timestamp: timestamp,
			Value:     value,
			Metric:    "composite_score",
		})
	}
	
	return trends
}

func (ml *MLModule) calculateRiskLevel(deviation float64, trends []TrendPoint) string {
	if deviation > 0.5 {
		return "high"
	} else if deviation > 0.3 {
		return "medium"
	} else if deviation > 0.1 {
		return "low"
	}
	return "minimal"
}

func (ml *MLModule) calculateSeverity(score float64) string {
	if score > 0.8 {
		return "critical"
	} else if score > 0.6 {
		return "high"
	} else if score > 0.4 {
		return "medium"
	}
	return "low"
}

func (ml *MLModule) generateAnomalyExplanation(features map[string]float64, score float64, isAnomalous bool) string {
	if !isAnomalous {
		return "Behavior appears normal based on learned patterns"
	}
	
	// Find the most contributing features
	var maxFeature string
	var maxValue float64
	
	for feature, value := range features {
		if value > maxValue {
			maxValue = value
			maxFeature = feature
		}
	}
	
	return fmt.Sprintf("Anomaly detected (score: %.2f). Primary contributor: %s (%.2f)", 
		score, maxFeature, maxValue)
}

func (ml *MLModule) generateAnomalyRecommendations(features map[string]float64, score float64, isAnomalous bool) []string {
	recommendations := make([]string, 0)
	
	if !isAnomalous {
		recommendations = append(recommendations, "Continue monitoring normal behavior patterns")
		return recommendations
	}
	
	recommendations = append(recommendations, "Investigate the source of anomalous behavior")
	recommendations = append(recommendations, "Review recent system changes or events")
	
	if score > 0.9 {
		recommendations = append(recommendations, "Consider immediate security response")
	}
	
	return recommendations
}

func (ml *MLModule) generateBehaviorRecommendations(deviation float64, riskLevel string) []string {
	recommendations := make([]string, 0)
	
	switch riskLevel {
	case "high":
		recommendations = append(recommendations, "Immediate investigation required")
		recommendations = append(recommendations, "Consider temporary access restrictions")
	case "medium":
		recommendations = append(recommendations, "Enhanced monitoring recommended")
		recommendations = append(recommendations, "Review user activity patterns")
	case "low":
		recommendations = append(recommendations, "Continue standard monitoring")
	case "minimal":
		recommendations = append(recommendations, "Behavior within normal parameters")
	}
	
	return recommendations
}

func (ml *MLModule) convertTrainingData(data []map[string]interface{}) []TrainingRecord {
	records := make([]TrainingRecord, 0, len(data))
	
	for i, record := range data {
		features := ml.extractFeatures(record)
		
		label := "unknown"
		if labelValue, exists := record["label"]; exists {
			if labelStr, ok := labelValue.(string); ok {
				label = labelStr
			}
		}
		
		trainingRecord := TrainingRecord{
			ID:       fmt.Sprintf("record_%d", i),
			Features: features,
			Label:    label,
			Weight:   1.0,
			Source:   "user_provided",
		}
		
		records = append(records, trainingRecord)
	}
	
	return records
}

func (ml *MLModule) extractFeatureNames(records []TrainingRecord) []string {
	featureSet := make(map[string]bool)
	
	for _, record := range records {
		for feature := range record.Features {
			featureSet[feature] = true
		}
	}
	
	features := make([]string, 0, len(featureSet))
	for feature := range featureSet {
		features = append(features, feature)
	}
	
	sort.Strings(features)
	return features
}

func (ml *MLModule) simulateTraining(records []TrainingRecord, modelType string) *ModelMetrics {
	// Simulate training metrics based on data size and type
	dataSize := len(records)
	baseAccuracy := 0.7
	
	if dataSize > 100 {
		baseAccuracy = 0.85
	} else if dataSize > 50 {
		baseAccuracy = 0.8
	}
	
	// Add some randomness
	accuracy := baseAccuracy + (rand.Float64()-0.5)*0.1
	precision := accuracy + (rand.Float64()-0.5)*0.05
	recall := accuracy + (rand.Float64()-0.5)*0.05
	
	f1Score := 2 * (precision * recall) / (precision + recall)
	auc := accuracy + 0.05
	
	return &ModelMetrics{
		Accuracy:  math.Max(0, math.Min(1, accuracy)),
		Precision: math.Max(0, math.Min(1, precision)),
		Recall:    math.Max(0, math.Min(1, recall)),
		F1Score:   math.Max(0, math.Min(1, f1Score)),
		AUC:       math.Max(0, math.Min(1, auc)),
	}
}

func (ml *MLModule) getFeatureNames(features map[string]float64) []string {
	names := make([]string, 0, len(features))
	for name := range features {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func (ml *MLModule) generateAttackPatterns(threatType string) []AttackPattern {
	patterns := make([]AttackPattern, 0)
	
	switch threatType {
	case "malware":
		patterns = append(patterns, AttackPattern{
			Name:        "file_injection",
			Description: "Malicious file injection pattern",
			Techniques:  []string{"process_injection", "dll_hijacking"},
			Signatures:  []string{"suspicious_file_access", "abnormal_network_traffic"},
			Frequency:   0.7,
		})
	case "network_attack":
		patterns = append(patterns, AttackPattern{
			Name:        "port_scanning",
			Description: "Network reconnaissance pattern",
			Techniques:  []string{"tcp_scan", "udp_scan", "stealth_scan"},
			Signatures:  []string{"multiple_connection_attempts", "unusual_port_access"},
			Frequency:   0.8,
		})
	case "privilege_escalation":
		patterns = append(patterns, AttackPattern{
			Name:        "credential_abuse",
			Description: "Privilege escalation pattern",
			Techniques:  []string{"credential_dumping", "token_manipulation"},
			Signatures:  []string{"admin_access_attempts", "system_file_modification"},
			Frequency:   0.6,
		})
	}
	
	return patterns
}

func (ml *MLModule) generateCountermeasures(threatType string) []string {
	measures := make([]string, 0)
	
	switch threatType {
	case "malware":
		measures = append(measures, "Deploy endpoint detection and response")
		measures = append(measures, "Implement application whitelisting")
		measures = append(measures, "Enable real-time file scanning")
	case "network_attack":
		measures = append(measures, "Configure network segmentation")
		measures = append(measures, "Deploy intrusion prevention systems")
		measures = append(measures, "Implement rate limiting")
	case "privilege_escalation":
		measures = append(measures, "Enforce least privilege access")
		measures = append(measures, "Implement privileged access management")
		measures = append(measures, "Enable audit logging")
	default:
		measures = append(measures, "Implement comprehensive monitoring")
		measures = append(measures, "Deploy security automation")
	}
	
	return measures
}