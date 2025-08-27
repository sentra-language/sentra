---
layout: default
title: Security Module
parent: Tutorial
nav_order: 6
---

# Security Module
{: .fs-9 }

Learn Sentra's built-in security tools for vulnerability scanning, cryptography, and threat detection.
{: .fs-6 .fw-300 }

---

## Port Scanning

### Basic Port Scanning

```sentra
// Simple port scan
fn basic_port_scan() {
    let target = "127.0.0.1"
    log("Scanning " + target + "...")
    
    let results = port_scan(target, 1, 1000, "TCP")
    let open_ports = []
    
    for (let port in results) {
        if (port["state"] == "open") {
            push(open_ports, port["port"])
            log("Port " + str(port["port"]) + " OPEN - " + port["service"])
        }
    }
    
    log("Found " + str(len(open_ports)) + " open ports")
    return open_ports
}

basic_port_scan()
```

### Advanced Port Scanner

```sentra
// Comprehensive port scanner with service detection
fn advanced_port_scanner(target, port_range_start, port_range_end) {
    log("Advanced scan of " + target + " (ports " + str(port_range_start) + "-" + str(port_range_end) + ")")
    
    let results = port_scan(target, port_range_start, port_range_end, "TCP")
    let scan_report = {
        "target": target,
        "open_ports": [],
        "filtered_ports": [],
        "closed_count": 0,
        "services": {}
    }
    
    for (let port in results) {
        if (port["state"] == "open") {
            push(scan_report["open_ports"], port["port"])
            scan_report["services"][str(port["port"])] = {
                "service": port["service"],
                "version": port["version"] || "Unknown",
                "banner": port["banner"] || ""
            }
            
            log("  " + str(port["port"]) + "/tcp OPEN  " + port["service"])
            if (port["banner"]) {
                log("    Banner: " + port["banner"])
            }
        } else if (port["state"] == "filtered") {
            push(scan_report["filtered_ports"], port["port"])
        } else {
            scan_report["closed_count"] = scan_report["closed_count"] + 1
        }
    }
    
    return scan_report
}

// Scan common ports
let scan_results = advanced_port_scanner("127.0.0.1", 20, 100)
log("Scan completed: " + str(len(scan_results["open_ports"])) + " open ports found")
```

---

## Network Discovery

### Host Discovery

```sentra
// Discover active hosts on network
fn network_discovery(network_cidr) {
    log("Discovering hosts on " + network_cidr + "...")
    
    let hosts = network_scan(network_cidr)
    let active_hosts = []
    
    for (let host in hosts) {
        if (host["status"] == "up") {
            push(active_hosts, host)
            log("Host found: " + host["ip"])
            log("  Hostname: " + (host["hostname"] || "Unknown"))
            log("  MAC: " + (host["mac"] || "Unknown"))
            log("  OS: " + (host["os"] || "Unknown"))
        }
    }
    
    log("Discovery complete: " + str(len(active_hosts)) + " active hosts")
    return active_hosts
}

// Discover local network (example)
// let discovered = network_discovery("192.168.1.0/24")
```

---

## SSL/TLS Analysis

### SSL Certificate Analysis

```sentra
// Analyze SSL/TLS configuration
fn ssl_analysis(hostname, port) {
    log("Analyzing SSL for " + hostname + ":" + str(port))
    
    let ssl_info = analyze_ssl(hostname, port)
    
    log("SSL Analysis Results:")
    log("  SSL Version: " + ssl_info["ssl_version"])
    log("  Cipher Suite: " + ssl_info["cipher_suite"])
    log("  Security Grade: " + ssl_info["grade"])
    
    // Certificate information
    let cert = ssl_info["certificate_info"]
    log("  Certificate:")
    log("    Subject: " + cert["subject"])
    log("    Issuer: " + cert["issuer"])
    log("    Valid From: " + cert["not_before"])
    log("    Valid Until: " + cert["not_after"])
    log("    Serial: " + cert["serial_number"])
    
    // Security issues
    if (len(ssl_info["security_issues"]) > 0) {
        log("  Security Issues:")
        for (let issue in ssl_info["security_issues"]) {
            log("    - " + issue)
        }
    } else {
        log("  No security issues found")
    }
    
    return ssl_info
}

// Analyze popular sites
let sites = ["github.com", "google.com", "stackoverflow.com"]
for (let site in sites) {
    ssl_analysis(site, 443)
    log("")  // Empty line between results
}
```

---

## Cryptography

### Hashing Functions

```sentra
// Hash data with different algorithms
fn hash_examples() {
    let data = "Sensitive data to hash"
    
    // Different hash algorithms
    let md5_hash = hash("md5", data)
    let sha1_hash = hash("sha1", data) 
    let sha256_hash = hash("sha256", data)
    let sha512_hash = hash("sha512", data)
    
    log("Original: " + data)
    log("MD5:    " + md5_hash)
    log("SHA1:   " + sha1_hash)
    log("SHA256: " + sha256_hash)
    log("SHA512: " + sha512_hash)
    
    return sha256_hash  // Return strongest hash
}

hash_examples()
```

### Encryption and Decryption

```sentra
// Symmetric encryption example
fn encryption_example() {
    let plaintext = "This is confidential information"
    let key = "my-secret-key-32-characters-long"
    
    log("Original: " + plaintext)
    
    // Encrypt data
    let encrypted = encrypt("aes256", plaintext, key)
    log("Encrypted: " + encrypted)
    
    // Decrypt data
    let decrypted = decrypt("aes256", encrypted, key)
    log("Decrypted: " + decrypted)
    
    // Verify integrity
    if (decrypted == plaintext) {
        log("Encryption/Decryption successful!")
    } else {
        log("ERROR: Decryption failed!")
    }
}

encryption_example()
```

### Digital Signatures

```sentra
// Digital signature example
fn digital_signature_example() {
    let message = "This message is authentic"
    let private_key = generate_keypair()["private"]
    let public_key = generate_keypair()["public"]
    
    // Sign message
    let signature = sign(message, private_key)
    log("Message: " + message)
    log("Signature: " + signature)
    
    // Verify signature
    let is_valid = verify(message, signature, public_key)
    log("Signature valid: " + str(is_valid))
}

// digital_signature_example()  // Uncomment if keypair functions available
```

---

## Vulnerability Detection

### Web Vulnerability Scanner

```sentra
// Basic web vulnerability scanner
fn web_vulnerability_scan(target_url) {
    log("Scanning " + target_url + " for vulnerabilities...")
    
    let vulnerabilities = []
    
    // Check for common issues
    try {
        // Test for directory traversal
        let traversal_response = http_get(target_url + "/../../../etc/passwd")
        if (contains(traversal_response["body"], "root:")) {
            push(vulnerabilities, "Directory Traversal - /etc/passwd accessible")
        }
        
        // Check for SQL injection indicators  
        let sqli_response = http_get(target_url + "?id=1'")
        if (contains(lower(sqli_response["body"]), "sql") || 
            contains(lower(sqli_response["body"]), "mysql")) {
            push(vulnerabilities, "Possible SQL Injection - Error messages exposed")
        }
        
        // Check security headers
        let headers = http_get(target_url)["headers"]
        if (!headers["X-Frame-Options"]) {
            push(vulnerabilities, "Missing X-Frame-Options header (Clickjacking risk)")
        }
        if (!headers["X-XSS-Protection"]) {
            push(vulnerabilities, "Missing X-XSS-Protection header")
        }
        if (!headers["X-Content-Type-Options"]) {
            push(vulnerabilities, "Missing X-Content-Type-Options header")
        }
        
    } catch (error) {
        log("Error during scan: " + error)
    }
    
    // Report results
    if (len(vulnerabilities) > 0) {
        log("Vulnerabilities found:")
        for (let vuln in vulnerabilities) {
            log("  - " + vuln)
        }
    } else {
        log("No obvious vulnerabilities detected")
    }
    
    return vulnerabilities
}

// Example scan
web_vulnerability_scan("https://httpbin.org")
```

---

## Intrusion Detection

### Network Intrusion Detection

```sentra
// Simple intrusion detection system
fn intrusion_detection() {
    log("Starting intrusion detection...")
    
    // Monitor network for suspicious activity
    let alerts = detect_intrusions("eth0", 30)  // Monitor for 30 seconds
    
    if (len(alerts) > 0) {
        log("SECURITY ALERTS:")
        for (let alert in alerts) {
            log("  [" + alert["severity"] + "] " + alert["alert_type"])
            log("    Source: " + alert["source_ip"])
            log("    Target: " + alert["target_ip"])
            log("    Description: " + alert["description"])
            log("    Time: " + str(alert["timestamp"]))
            log("")
        }
    } else {
        log("No suspicious activity detected")
    }
    
    return alerts
}

// intrusion_detection()  // Uncomment to run
```

---

## Compliance Checking

### Security Compliance Scanner

```sentra
// Check system for security compliance
fn security_compliance_check() {
    log("Running security compliance check...")
    
    let compliance_report = {
        "passed": [],
        "failed": [],
        "warnings": [],
        "score": 0
    }
    
    let total_checks = 0
    let passed_checks = 0
    
    // Check 1: Password policy
    total_checks = total_checks + 1
    if (check_password_policy()) {
        push(compliance_report["passed"], "Password policy meets requirements")
        passed_checks = passed_checks + 1
    } else {
        push(compliance_report["failed"], "Password policy is weak")
    }
    
    // Check 2: Firewall status
    total_checks = total_checks + 1
    if (check_firewall_status()) {
        push(compliance_report["passed"], "Firewall is active")
        passed_checks = passed_checks + 1
    } else {
        push(compliance_report["failed"], "Firewall is not active")
    }
    
    // Check 3: SSL/TLS configuration
    total_checks = total_checks + 1
    let ssl_config = check_ssl_configuration()
    if (ssl_config["secure"]) {
        push(compliance_report["passed"], "SSL/TLS configuration is secure")
        passed_checks = passed_checks + 1
    } else {
        push(compliance_report["failed"], "SSL/TLS configuration needs improvement")
        for (let issue in ssl_config["issues"]) {
            push(compliance_report["warnings"], "SSL: " + issue)
        }
    }
    
    // Calculate score
    compliance_report["score"] = (passed_checks * 100) / total_checks
    
    // Generate report
    log("=== Security Compliance Report ===")
    log("Overall Score: " + str(compliance_report["score"]) + "%")
    log("")
    
    if (len(compliance_report["passed"]) > 0) {
        log("PASSED CHECKS:")
        for (let check in compliance_report["passed"]) {
            log("  ✓ " + check)
        }
        log("")
    }
    
    if (len(compliance_report["failed"]) > 0) {
        log("FAILED CHECKS:")
        for (let check in compliance_report["failed"]) {
            log("  ✗ " + check)
        }
        log("")
    }
    
    if (len(compliance_report["warnings"]) > 0) {
        log("WARNINGS:")
        for (let warning in compliance_report["warnings"]) {
            log("  ⚠ " + warning)
        }
    }
    
    return compliance_report
}

// Helper functions (simplified implementations)
fn check_password_policy() {
    // Simulate password policy check
    return true  // Would check actual policy
}

fn check_firewall_status() {
    // Simulate firewall status check  
    return true  // Would check actual firewall
}

fn check_ssl_configuration() {
    // Simulate SSL configuration check
    return {"secure": true, "issues": []}  // Would check actual SSL config
}

security_compliance_check()
```

---

## Practical Example: Complete Security Assessment

```sentra
// Comprehensive security assessment tool
fn security_assessment(target) {
    log("=== Security Assessment of " + target + " ===")
    
    let assessment = {
        "target": target,
        "timestamp": time(),
        "port_scan": null,
        "ssl_analysis": null,
        "vulnerability_scan": null,
        "risk_score": 0,
        "recommendations": []
    }
    
    // 1. Port Scan
    log("1. Performing port scan...")
    assessment["port_scan"] = advanced_port_scanner(target, 1, 1000)
    
    // 2. SSL Analysis (if HTTPS port is open)
    let open_ports = assessment["port_scan"]["open_ports"]
    if (contains(open_ports, 443)) {
        log("2. Analyzing SSL configuration...")
        assessment["ssl_analysis"] = ssl_analysis(target, 443)
    }
    
    // 3. Web Vulnerability Scan (if HTTP/HTTPS is available)
    if (contains(open_ports, 80) || contains(open_ports, 443)) {
        log("3. Scanning for web vulnerabilities...")
        let protocol = contains(open_ports, 443) ? "https" : "http"
        assessment["vulnerability_scan"] = web_vulnerability_scan(protocol + "://" + target)
    }
    
    // 4. Calculate Risk Score
    let risk_factors = 0
    
    // High risk: Many open ports
    if (len(open_ports) > 10) {
        risk_factors = risk_factors + 3
        push(assessment["recommendations"], "Reduce number of exposed services")
    }
    
    // High risk: Insecure services
    let risky_ports = [21, 23, 513, 514, 515]  // FTP, Telnet, rsh, etc.
    for (let port in risky_ports) {
        if (contains(open_ports, port)) {
            risk_factors = risk_factors + 2
            push(assessment["recommendations"], "Disable insecure service on port " + str(port))
        }
    }
    
    // SSL issues
    if (assessment["ssl_analysis"] && len(assessment["ssl_analysis"]["security_issues"]) > 0) {
        risk_factors = risk_factors + len(assessment["ssl_analysis"]["security_issues"])
        push(assessment["recommendations"], "Fix SSL/TLS security issues")
    }
    
    // Web vulnerabilities
    if (assessment["vulnerability_scan"] && len(assessment["vulnerability_scan"]) > 0) {
        risk_factors = risk_factors + len(assessment["vulnerability_scan"])
        push(assessment["recommendations"], "Address web application vulnerabilities")
    }
    
    assessment["risk_score"] = risk_factors
    
    // 5. Generate Final Report
    log("\n=== ASSESSMENT SUMMARY ===")
    log("Target: " + target)
    log("Open Ports: " + str(len(open_ports)))
    log("Risk Score: " + str(assessment["risk_score"]) + "/10")
    
    if (assessment["risk_score"] >= 7) {
        log("Risk Level: HIGH")
    } else if (assessment["risk_score"] >= 4) {
        log("Risk Level: MEDIUM") 
    } else {
        log("Risk Level: LOW")
    }
    
    if (len(assessment["recommendations"]) > 0) {
        log("\nRECOMMENDATIONS:")
        for (let rec in assessment["recommendations"]) {
            log("- " + rec)
        }
    }
    
    return assessment
}

// Run assessment
let assessment_results = security_assessment("127.0.0.1")
```

---

## Next Steps

Now that you understand security tools:

- [Project Management](../project-management/) - Building larger security applications
- [Language Reference](../../reference/language/) - Complete function documentation
- [Examples on GitHub](https://github.com/sentra-language/sentra/tree/main/examples) - Real security tools
- [Back to Tutorial Overview](../) - See all available modules

---

{: .fs-6 .fw-300 }
With security tools mastered, let's learn how to structure and manage larger Sentra projects.

[← Previous: Network Module](../network-module/){: .btn .btn-outline .mr-2 }
[Next: Project Management →](../project-management/){: .btn .btn-primary }

---

## Security Function Reference

### Port Scanning
- `port_scan(host, start_port, end_port, protocol)` - Scan port range
- `network_scan(cidr)` - Discover hosts on network

### SSL/TLS Analysis
- `analyze_ssl(hostname, port)` - Analyze SSL configuration

### Cryptography  
- `hash(algorithm, data)` - Generate hash
- `encrypt(algorithm, plaintext, key)` - Encrypt data
- `decrypt(algorithm, ciphertext, key)` - Decrypt data
- `sign(message, private_key)` - Digital signature
- `verify(message, signature, public_key)` - Verify signature
- `generate_keypair()` - Generate key pair

### Security Monitoring
- `detect_intrusions(interface, duration)` - Network intrusion detection
- `analyze_traffic(interface, duration)` - Traffic analysis