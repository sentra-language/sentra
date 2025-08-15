// Package cryptoanalysis provides advanced cryptographic analysis for Sentra
package cryptoanalysis

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"math"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"
)

// CryptoAnalysisModule provides cryptographic security analysis
type CryptoAnalysisModule struct {
	Certificates     map[string]*CertificateAnalysis
	TLSConfigs       map[string]*TLSAnalysis
	CipherResults    map[string]*CipherAnalysis
	KeyAnalysis      map[string]*KeyStrengthAnalysis
	RandomnessTests  []RandomnessTest
	mu               sync.RWMutex
}

// CertificateAnalysis contains SSL/TLS certificate analysis
type CertificateAnalysis struct {
	Subject            string
	Issuer             string
	SerialNumber       string
	NotBefore          time.Time
	NotAfter           time.Time
	DNSNames           []string
	IPAddresses        []string
	KeyAlgorithm       string
	KeySize            int
	SignatureAlgorithm string
	IsCA               bool
	IsSelfSigned       bool
	IsExpired          bool
	DaysUntilExpiry    int
	Vulnerabilities    []string
	Weaknesses         []string
	TrustLevel         string
	CertificateChain   []*x509.Certificate
}

// TLSAnalysis contains TLS configuration analysis
type TLSAnalysis struct {
	Host               string
	Port               int
	SupportedVersions  []string
	SupportedCiphers   []string
	PreferredCipher    string
	SupportsHTTP2      bool
	Certificate        *CertificateAnalysis
	VulnerableProtocols []string
	WeakCiphers        []string
	SecurityLevel      string
	Recommendations    []string
}

// CipherAnalysis contains cipher analysis results
type CipherAnalysis struct {
	Algorithm    string
	KeySize      int
	Mode         string
	Strength     string
	Vulnerabilities []string
	Recommended  bool
	Description  string
}

// KeyStrengthAnalysis analyzes cryptographic key strength
type KeyStrengthAnalysis struct {
	KeyType       string
	KeySize       int
	Algorithm     string
	Entropy       float64
	Strength      string
	Weaknesses    []string
	TimeToBreak   string
	Recommended   bool
}

// RandomnessTest tests for randomness quality
type RandomnessTest struct {
	TestName    string
	Data        []byte
	Entropy     float64
	ChiSquare   float64
	Passed      bool
	Description string
	Timestamp   time.Time
}

// CipherSuite represents a TLS cipher suite
type CipherSuite struct {
	ID                uint16
	Name              string
	KeyExchange       string
	Authentication    string
	Encryption        string
	MAC               string
	Strength          string
	Vulnerable        bool
	Recommendation    string
}

// NewCryptoAnalysisModule creates a new crypto analysis module
func NewCryptoAnalysisModule() *CryptoAnalysisModule {
	return &CryptoAnalysisModule{
		Certificates:    make(map[string]*CertificateAnalysis),
		TLSConfigs:      make(map[string]*TLSAnalysis),
		CipherResults:   make(map[string]*CipherAnalysis),
		KeyAnalysis:     make(map[string]*KeyStrengthAnalysis),
		RandomnessTests: make([]RandomnessTest, 0),
	}
}

// AnalyzeCertificate analyzes an X.509 certificate
func (ca *CryptoAnalysisModule) AnalyzeCertificate(certData string) (*CertificateAnalysis, error) {
	// Parse PEM or DER encoded certificate
	var cert *x509.Certificate
	var err error

	if strings.Contains(certData, "BEGIN CERTIFICATE") {
		// PEM format
		block, _ := pem.Decode([]byte(certData))
		if block == nil {
			return nil, fmt.Errorf("failed to parse PEM certificate")
		}
		cert, err = x509.ParseCertificate(block.Bytes)
	} else {
		// Try as hex-encoded DER
		derBytes, hexErr := hex.DecodeString(certData)
		if hexErr == nil {
			cert, err = x509.ParseCertificate(derBytes)
		} else {
			// Try as base64-encoded DER
			derBytes, b64Err := base64.StdEncoding.DecodeString(certData)
			if b64Err != nil {
				return nil, fmt.Errorf("failed to decode certificate data")
			}
			cert, err = x509.ParseCertificate(derBytes)
		}
	}

	if err != nil {
		return nil, err
	}

	analysis := &CertificateAnalysis{
		Subject:            cert.Subject.String(),
		Issuer:             cert.Issuer.String(),
		SerialNumber:       cert.SerialNumber.String(),
		NotBefore:          cert.NotBefore,
		NotAfter:           cert.NotAfter,
		DNSNames:           cert.DNSNames,
		KeyAlgorithm:       cert.PublicKeyAlgorithm.String(),
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		IsCA:               cert.IsCA,
		IsSelfSigned:       cert.Subject.String() == cert.Issuer.String(),
		IsExpired:          time.Now().After(cert.NotAfter),
		Vulnerabilities:    make([]string, 0),
		Weaknesses:         make([]string, 0),
	}

	// Convert IP addresses
	for _, ip := range cert.IPAddresses {
		analysis.IPAddresses = append(analysis.IPAddresses, ip.String())
	}

	// Calculate days until expiry
	if !analysis.IsExpired {
		analysis.DaysUntilExpiry = int(time.Until(cert.NotAfter).Hours() / 24)
	}

	// Analyze key size
	analysis.KeySize = ca.getKeySize(cert.PublicKey)

	// Check for vulnerabilities and weaknesses
	ca.checkCertificateVulnerabilities(analysis, cert)

	// Determine trust level
	analysis.TrustLevel = ca.determineTrustLevel(analysis)

	// Store analysis
	ca.mu.Lock()
	certID := analysis.SerialNumber
	ca.Certificates[certID] = analysis
	ca.mu.Unlock()

	return analysis, nil
}

// getKeySize determines the key size from a public key
func (ca *CryptoAnalysisModule) getKeySize(pubKey interface{}) int {
	switch key := pubKey.(type) {
	case *rsa.PublicKey:
		return key.N.BitLen()
	default:
		return 0 // Unknown key type
	}
}

// checkCertificateVulnerabilities checks for known certificate vulnerabilities
func (ca *CryptoAnalysisModule) checkCertificateVulnerabilities(analysis *CertificateAnalysis, cert *x509.Certificate) {
	// Check key size
	if analysis.KeySize < 2048 {
		analysis.Weaknesses = append(analysis.Weaknesses, fmt.Sprintf("Weak key size: %d bits", analysis.KeySize))
	}

	// Check signature algorithm
	weakSigAlgos := []string{"MD5", "SHA1"}
	for _, weak := range weakSigAlgos {
		if strings.Contains(analysis.SignatureAlgorithm, weak) {
			analysis.Vulnerabilities = append(analysis.Vulnerabilities, fmt.Sprintf("Weak signature algorithm: %s", analysis.SignatureAlgorithm))
		}
	}

	// Check expiry
	if analysis.IsExpired {
		analysis.Vulnerabilities = append(analysis.Vulnerabilities, "Certificate has expired")
	} else if analysis.DaysUntilExpiry < 30 {
		analysis.Weaknesses = append(analysis.Weaknesses, fmt.Sprintf("Certificate expires soon: %d days", analysis.DaysUntilExpiry))
	}

	// Check for wildcard certificates
	for _, name := range analysis.DNSNames {
		if strings.HasPrefix(name, "*.") {
			analysis.Weaknesses = append(analysis.Weaknesses, "Wildcard certificate usage")
		}
	}

	// Check validity period
	validityPeriod := cert.NotAfter.Sub(cert.NotBefore)
	if validityPeriod > 365*24*time.Hour*2 { // More than 2 years
		analysis.Weaknesses = append(analysis.Weaknesses, "Long validity period")
	}
}

// determineTrustLevel determines the overall trust level of a certificate
func (ca *CryptoAnalysisModule) determineTrustLevel(analysis *CertificateAnalysis) string {
	if len(analysis.Vulnerabilities) > 0 {
		return "LOW"
	}
	if len(analysis.Weaknesses) > 2 {
		return "MEDIUM"
	}
	if analysis.KeySize >= 4096 && !analysis.IsSelfSigned {
		return "HIGH"
	}
	return "MEDIUM"
}

// AnalyzeTLSConfiguration analyzes TLS configuration of a host
func (ca *CryptoAnalysisModule) AnalyzeTLSConfiguration(host string, port int) (*TLSAnalysis, error) {
	analysis := &TLSAnalysis{
		Host:                host,
		Port:                port,
		SupportedVersions:   make([]string, 0),
		SupportedCiphers:    make([]string, 0),
		VulnerableProtocols: make([]string, 0),
		WeakCiphers:         make([]string, 0),
		Recommendations:     make([]string, 0),
	}

	// Test different TLS versions
	tlsVersions := map[uint16]string{
		tls.VersionTLS10: "TLS 1.0",
		tls.VersionTLS11: "TLS 1.1",
		tls.VersionTLS12: "TLS 1.2",
		tls.VersionTLS13: "TLS 1.3",
	}

	for version, versionName := range tlsVersions {
		if ca.testTLSVersion(host, port, version) {
			analysis.SupportedVersions = append(analysis.SupportedVersions, versionName)
			
			// Mark vulnerable versions
			if version <= tls.VersionTLS11 {
				analysis.VulnerableProtocols = append(analysis.VulnerableProtocols, versionName)
			}
		}
	}

	// Get certificate information
	if cert, err := ca.getCertificateFromHost(host, port); err == nil {
		analysis.Certificate = cert
	}

	// Test cipher suites
	ciphers := ca.getSupportedCiphers(host, port)
	analysis.SupportedCiphers = ciphers
	analysis.WeakCiphers = ca.identifyWeakCiphers(ciphers)

	// Determine security level
	analysis.SecurityLevel = ca.determineTLSSecurityLevel(analysis)

	// Generate recommendations
	ca.generateTLSRecommendations(analysis)

	// Store analysis
	ca.mu.Lock()
	hostKey := fmt.Sprintf("%s:%d", host, port)
	ca.TLSConfigs[hostKey] = analysis
	ca.mu.Unlock()

	return analysis, nil
}

// testTLSVersion tests if a specific TLS version is supported
func (ca *CryptoAnalysisModule) testTLSVersion(host string, port int, version uint16) bool {
	config := &tls.Config{
		MinVersion:         version,
		MaxVersion:         version,
		InsecureSkipVerify: true,
	}

	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 5 * time.Second},
		"tcp",
		fmt.Sprintf("%s:%d", host, port),
		config,
	)

	if err != nil {
		return false
	}

	conn.Close()
	return true
}

// getCertificateFromHost retrieves and analyzes certificate from a host
func (ca *CryptoAnalysisModule) getCertificateFromHost(host string, port int) (*CertificateAnalysis, error) {
	config := &tls.Config{
		InsecureSkipVerify: true,
	}

	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 10 * time.Second},
		"tcp",
		fmt.Sprintf("%s:%d", host, port),
		config,
	)

	if err != nil {
		return nil, err
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no certificates found")
	}

	cert := state.PeerCertificates[0]
	
	// Convert certificate to PEM for analysis
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	return ca.AnalyzeCertificate(string(certPEM))
}

// getSupportedCiphers gets list of supported cipher suites
func (ca *CryptoAnalysisModule) getSupportedCiphers(host string, port int) []string {
	var ciphers []string
	
	// Test connection to get preferred cipher
	config := &tls.Config{
		InsecureSkipVerify: true,
	}

	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 5 * time.Second},
		"tcp",
		fmt.Sprintf("%s:%d", host, port),
		config,
	)

	if err != nil {
		return ciphers
	}
	defer conn.Close()

	state := conn.ConnectionState()
	cipherName := tls.CipherSuiteName(state.CipherSuite)
	if cipherName != "" {
		ciphers = append(ciphers, cipherName)
	}

	return ciphers
}

// identifyWeakCiphers identifies weak cipher suites
func (ca *CryptoAnalysisModule) identifyWeakCiphers(ciphers []string) []string {
	var weakCiphers []string
	
	weakPatterns := []string{
		"RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "ADH", "AECDH",
	}

	for _, cipher := range ciphers {
		for _, pattern := range weakPatterns {
			if strings.Contains(cipher, pattern) {
				weakCiphers = append(weakCiphers, cipher)
				break
			}
		}
	}

	return weakCiphers
}

// determineTLSSecurityLevel determines overall TLS security level
func (ca *CryptoAnalysisModule) determineTLSSecurityLevel(analysis *TLSAnalysis) string {
	score := 0

	// Check TLS versions
	hasTLS13 := false
	hasTLS12 := false
	hasOldTLS := false

	for _, version := range analysis.SupportedVersions {
		switch version {
		case "TLS 1.3":
			hasTLS13 = true
			score += 3
		case "TLS 1.2":
			hasTLS12 = true
			score += 2
		case "TLS 1.1", "TLS 1.0":
			hasOldTLS = true
			score -= 2
		}
	}

	// Penalize for weak ciphers
	score -= len(analysis.WeakCiphers) * 2

	// Penalize for vulnerable protocols
	score -= len(analysis.VulnerableProtocols) * 3

	// Certificate score
	if analysis.Certificate != nil {
		switch analysis.Certificate.TrustLevel {
		case "HIGH":
			score += 2
		case "MEDIUM":
			score += 1
		case "LOW":
			score -= 2
		}
	}

	// Determine level
	if score >= 5 && hasTLS13 && !hasOldTLS {
		return "EXCELLENT"
	} else if score >= 3 && hasTLS12 && len(analysis.WeakCiphers) == 0 {
		return "GOOD"
	} else if score >= 0 {
		return "FAIR"
	} else {
		return "POOR"
	}
}

// generateTLSRecommendations generates security recommendations
func (ca *CryptoAnalysisModule) generateTLSRecommendations(analysis *TLSAnalysis) {
	// Check for old TLS versions
	if len(analysis.VulnerableProtocols) > 0 {
		analysis.Recommendations = append(analysis.Recommendations, 
			"Disable vulnerable TLS versions (TLS 1.0, TLS 1.1)")
	}

	// Check for weak ciphers
	if len(analysis.WeakCiphers) > 0 {
		analysis.Recommendations = append(analysis.Recommendations,
			"Remove weak cipher suites from configuration")
	}

	// Check for TLS 1.3
	supportsTLS13 := false
	for _, version := range analysis.SupportedVersions {
		if version == "TLS 1.3" {
			supportsTLS13 = true
			break
		}
	}
	if !supportsTLS13 {
		analysis.Recommendations = append(analysis.Recommendations,
			"Enable TLS 1.3 support for improved security")
	}

	// Certificate recommendations
	if analysis.Certificate != nil {
		if len(analysis.Certificate.Vulnerabilities) > 0 {
			analysis.Recommendations = append(analysis.Recommendations,
				"Address certificate vulnerabilities")
		}
		if analysis.Certificate.KeySize < 2048 {
			analysis.Recommendations = append(analysis.Recommendations,
				"Use certificates with key size of at least 2048 bits")
		}
	}
}

// AnalyzeCipher analyzes a specific encryption cipher
func (ca *CryptoAnalysisModule) AnalyzeCipher(algorithm string, keySize int, mode string) (*CipherAnalysis, error) {
	analysis := &CipherAnalysis{
		Algorithm:       algorithm,
		KeySize:         keySize,
		Mode:            mode,
		Vulnerabilities: make([]string, 0),
	}

	// Analyze different algorithms
	switch strings.ToUpper(algorithm) {
	case "AES":
		ca.analyzeAES(analysis)
	case "DES":
		ca.analyzeDES(analysis)
	case "3DES", "TRIPLEDES":
		ca.analyze3DES(analysis)
	case "RC4":
		ca.analyzeRC4(analysis)
	case "RSA":
		ca.analyzeRSA(analysis)
	default:
		analysis.Strength = "UNKNOWN"
		analysis.Description = "Unknown or unsupported algorithm"
	}

	// Store analysis
	ca.mu.Lock()
	cipherKey := fmt.Sprintf("%s-%d-%s", algorithm, keySize, mode)
	ca.CipherResults[cipherKey] = analysis
	ca.mu.Unlock()

	return analysis, nil
}

// analyzeAES analyzes AES encryption
func (ca *CryptoAnalysisModule) analyzeAES(analysis *CipherAnalysis) {
	analysis.Description = "Advanced Encryption Standard (AES)"
	
	switch analysis.KeySize {
	case 128:
		analysis.Strength = "GOOD"
		analysis.Recommended = true
	case 192:
		analysis.Strength = "VERY_GOOD"
		analysis.Recommended = true
	case 256:
		analysis.Strength = "EXCELLENT"
		analysis.Recommended = true
	default:
		analysis.Strength = "WEAK"
		analysis.Vulnerabilities = append(analysis.Vulnerabilities, "Invalid AES key size")
		analysis.Recommended = false
	}

	// Check mode
	switch strings.ToUpper(analysis.Mode) {
	case "ECB":
		analysis.Vulnerabilities = append(analysis.Vulnerabilities, "ECB mode is vulnerable to pattern analysis")
		analysis.Recommended = false
	case "CBC":
		analysis.Vulnerabilities = append(analysis.Vulnerabilities, "CBC mode vulnerable to padding oracle attacks")
	case "GCM":
		analysis.Strength = "EXCELLENT"
		analysis.Description += " with authenticated encryption"
	}
}

// analyzeDES analyzes DES encryption
func (ca *CryptoAnalysisModule) analyzeDES(analysis *CipherAnalysis) {
	analysis.Description = "Data Encryption Standard (DES) - DEPRECATED"
	analysis.Strength = "BROKEN"
	analysis.Recommended = false
	analysis.Vulnerabilities = append(analysis.Vulnerabilities, 
		"DES is cryptographically broken due to small key size (56 bits)")
}

// analyze3DES analyzes 3DES encryption
func (ca *CryptoAnalysisModule) analyze3DES(analysis *CipherAnalysis) {
	analysis.Description = "Triple DES (3DES)"
	analysis.Strength = "WEAK"
	analysis.Recommended = false
	analysis.Vulnerabilities = append(analysis.Vulnerabilities,
		"3DES is deprecated and should be replaced with AES")
}

// analyzeRC4 analyzes RC4 stream cipher
func (ca *CryptoAnalysisModule) analyzeRC4(analysis *CipherAnalysis) {
	analysis.Description = "RC4 Stream Cipher - BROKEN"
	analysis.Strength = "BROKEN"
	analysis.Recommended = false
	analysis.Vulnerabilities = append(analysis.Vulnerabilities,
		"RC4 has known biases and should not be used")
}

// analyzeRSA analyzes RSA encryption/signing
func (ca *CryptoAnalysisModule) analyzeRSA(analysis *CipherAnalysis) {
	analysis.Description = "RSA Public Key Cryptography"
	
	switch {
	case analysis.KeySize < 1024:
		analysis.Strength = "BROKEN"
		analysis.Recommended = false
		analysis.Vulnerabilities = append(analysis.Vulnerabilities, "RSA key size too small")
	case analysis.KeySize < 2048:
		analysis.Strength = "WEAK"
		analysis.Recommended = false
		analysis.Vulnerabilities = append(analysis.Vulnerabilities, "RSA key size below current recommendations")
	case analysis.KeySize == 2048:
		analysis.Strength = "GOOD"
		analysis.Recommended = true
	case analysis.KeySize >= 4096:
		analysis.Strength = "EXCELLENT"
		analysis.Recommended = true
	}
}

// AnalyzeKeyStrength analyzes cryptographic key strength
func (ca *CryptoAnalysisModule) AnalyzeKeyStrength(keyData []byte, keyType, algorithm string) (*KeyStrengthAnalysis, error) {
	analysis := &KeyStrengthAnalysis{
		KeyType:    keyType,
		Algorithm:  algorithm,
		KeySize:    len(keyData) * 8, // Convert bytes to bits
		Weaknesses: make([]string, 0),
	}

	// Calculate entropy
	analysis.Entropy = ca.calculateEntropy(keyData)

	// Analyze based on key type
	switch strings.ToUpper(keyType) {
	case "SYMMETRIC":
		ca.analyzeSymmetricKey(analysis)
	case "ASYMMETRIC", "PUBLIC", "PRIVATE":
		ca.analyzeAsymmetricKey(analysis)
	default:
		analysis.Strength = "UNKNOWN"
	}

	// Estimate time to break
	analysis.TimeToBreak = ca.estimateTimeToBreak(analysis.KeySize, algorithm)

	// Store analysis
	ca.mu.Lock()
	keyID := fmt.Sprintf("%s-%s-%d", keyType, algorithm, analysis.KeySize)
	ca.KeyAnalysis[keyID] = analysis
	ca.mu.Unlock()

	return analysis, nil
}

// calculateEntropy calculates the entropy of key data
func (ca *CryptoAnalysisModule) calculateEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}

	// Count frequency of each byte value
	freq := make(map[byte]int)
	for _, b := range data {
		freq[b]++
	}

	// Calculate entropy using Shannon entropy formula
	entropy := 0.0
	length := float64(len(data))

	for _, count := range freq {
		if count > 0 {
			p := float64(count) / length
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

// analyzeSymmetricKey analyzes symmetric key strength
func (ca *CryptoAnalysisModule) analyzeSymmetricKey(analysis *KeyStrengthAnalysis) {
	switch {
	case analysis.KeySize < 80:
		analysis.Strength = "BROKEN"
		analysis.Recommended = false
		analysis.Weaknesses = append(analysis.Weaknesses, "Key size too small for security")
	case analysis.KeySize < 128:
		analysis.Strength = "WEAK"
		analysis.Recommended = false
		analysis.Weaknesses = append(analysis.Weaknesses, "Key size below current recommendations")
	case analysis.KeySize == 128:
		analysis.Strength = "GOOD"
		analysis.Recommended = true
	case analysis.KeySize >= 256:
		analysis.Strength = "EXCELLENT"
		analysis.Recommended = true
	}

	// Check entropy
	if analysis.Entropy < 7.0 {
		analysis.Weaknesses = append(analysis.Weaknesses, "Low entropy detected - key may be predictable")
		if analysis.Strength != "BROKEN" {
			analysis.Strength = "WEAK"
		}
	}
}

// analyzeAsymmetricKey analyzes asymmetric key strength
func (ca *CryptoAnalysisModule) analyzeAsymmetricKey(analysis *KeyStrengthAnalysis) {
	algorithm := strings.ToUpper(analysis.Algorithm)
	
	switch algorithm {
	case "RSA":
		switch {
		case analysis.KeySize < 1024:
			analysis.Strength = "BROKEN"
			analysis.Recommended = false
		case analysis.KeySize < 2048:
			analysis.Strength = "WEAK"
			analysis.Recommended = false
		case analysis.KeySize == 2048:
			analysis.Strength = "GOOD"
			analysis.Recommended = true
		case analysis.KeySize >= 4096:
			analysis.Strength = "EXCELLENT"
			analysis.Recommended = true
		}
	case "ECC", "ECDSA":
		switch {
		case analysis.KeySize < 160:
			analysis.Strength = "BROKEN"
			analysis.Recommended = false
		case analysis.KeySize < 256:
			analysis.Strength = "WEAK"
			analysis.Recommended = false
		case analysis.KeySize >= 256:
			analysis.Strength = "GOOD"
			analysis.Recommended = true
		case analysis.KeySize >= 384:
			analysis.Strength = "EXCELLENT"
			analysis.Recommended = true
		}
	}
}

// estimateTimeToBreak estimates time required to break the key
func (ca *CryptoAnalysisModule) estimateTimeToBreak(keySize int, algorithm string) string {
	// Simplified estimation based on key size
	// Real calculations would be much more complex
	
	switch strings.ToUpper(algorithm) {
	case "AES", "SYMMETRIC":
		switch {
		case keySize < 80:
			return "Minutes to hours"
		case keySize < 128:
			return "Years"
		case keySize == 128:
			return "2^128 operations (infeasible)"
		case keySize >= 256:
			return "2^256 operations (impossible)"
		}
	case "RSA":
		switch {
		case keySize < 1024:
			return "Days to months"
		case keySize < 2048:
			return "Years to decades"
		case keySize >= 2048:
			return "Centuries to millennia"
		}
	}
	
	return "Unknown"
}

// TestRandomness tests the quality of random data
func (ca *CryptoAnalysisModule) TestRandomness(data []byte, testName string) (*RandomnessTest, error) {
	test := &RandomnessTest{
		TestName:  testName,
		Data:      data,
		Timestamp: time.Now(),
	}

	// Calculate entropy
	test.Entropy = ca.calculateEntropy(data)

	// Perform chi-square test
	test.ChiSquare = ca.chiSquareTest(data)

	// Determine if test passed
	test.Passed = test.Entropy > 7.0 && test.ChiSquare < 293.25 // 95% confidence level for 255 degrees of freedom

	// Set description
	if test.Passed {
		test.Description = "Data appears to have good randomness properties"
	} else {
		test.Description = "Data may have poor randomness properties"
		if test.Entropy <= 7.0 {
			test.Description += " (low entropy)"
		}
		if test.ChiSquare >= 293.25 {
			test.Description += " (failed chi-square test)"
		}
	}

	// Store test result
	ca.mu.Lock()
	ca.RandomnessTests = append(ca.RandomnessTests, *test)
	ca.mu.Unlock()

	return test, nil
}

// chiSquareTest performs a chi-square test for randomness
func (ca *CryptoAnalysisModule) chiSquareTest(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}

	// Count frequency of each byte value
	freq := make([]int, 256)
	for _, b := range data {
		freq[b]++
	}

	// Calculate expected frequency
	expected := float64(len(data)) / 256.0

	// Calculate chi-square statistic
	chiSquare := 0.0
	for _, count := range freq {
		diff := float64(count) - expected
		chiSquare += (diff * diff) / expected
	}

	return chiSquare
}

// GenerateSecureKey generates a cryptographically secure key
func (ca *CryptoAnalysisModule) GenerateSecureKey(keySize int) ([]byte, error) {
	key := make([]byte, keySize/8) // Convert bits to bytes
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}

	// Test the generated key for randomness
	_, _ = ca.TestRandomness(key, "Generated Key")

	return key, nil
}

// CreateSelfSignedCertificate creates a self-signed certificate for testing
func (ca *CryptoAnalysisModule) CreateSelfSignedCertificate(commonName string, keySize int) (string, string, error) {
	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return "", "", err
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour), // 1 year
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		DNSNames:     []string{commonName},
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return "", "", err
	}

	// Encode certificate to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Encode private key to PEM
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return "", "", err
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyDER,
	})

	return string(certPEM), string(keyPEM), nil
}

// GetAnalysisResults returns all stored analysis results
func (ca *CryptoAnalysisModule) GetAnalysisResults() map[string]interface{} {
	ca.mu.RLock()
	defer ca.mu.RUnlock()

	results := map[string]interface{}{
		"certificates":     len(ca.Certificates),
		"tls_configs":      len(ca.TLSConfigs),
		"cipher_analyses":  len(ca.CipherResults),
		"key_analyses":     len(ca.KeyAnalysis),
		"randomness_tests": len(ca.RandomnessTests),
	}

	return results
}

// ClearAnalysisResults clears all stored results
func (ca *CryptoAnalysisModule) ClearAnalysisResults() {
	ca.mu.Lock()
	defer ca.mu.Unlock()

	ca.Certificates = make(map[string]*CertificateAnalysis)
	ca.TLSConfigs = make(map[string]*TLSAnalysis)
	ca.CipherResults = make(map[string]*CipherAnalysis)
	ca.KeyAnalysis = make(map[string]*KeyStrengthAnalysis)
	ca.RandomnessTests = ca.RandomnessTests[:0]
}

// EncryptAES encrypts data using AES
func (ca *CryptoAnalysisModule) EncryptAES(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// DecryptAES decrypts AES encrypted data
func (ca *CryptoAnalysisModule) DecryptAES(ciphertext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// HashSHA256 computes SHA256 hash
func (ca *CryptoAnalysisModule) HashSHA256(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

// TestDESWeakness tests for DES weakness
func (ca *CryptoAnalysisModule) TestDESWeakness(key []byte) bool {
	if len(key) != 8 {
		return true // Invalid key size
	}
	
	// Test if it's one of the known weak DES keys
	// DES is inherently weak due to 56-bit effective key size
	_, err := des.NewCipher(key)
	if err != nil {
		return true // Invalid key
	}
	
	return true // DES is always considered weak
}