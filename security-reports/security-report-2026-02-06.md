# Security Scan Report

**Target:** http://localhost:3000
**Generated:** 2026-02-06T21:40:30.074Z
**Duration:** 390.7s

## Executive Summary

**⚠️ CRITICAL:** 1 critical vulnerability found requiring immediate attention.
**🔴 HIGH:** 9 high severity issues should be addressed promptly.

A total of **16** security findings were identified across the scanned components.

**Overall Risk Level:** High (average risk score: 0.65)

## Findings Summary

### By Severity

| Severity | Count |
|----------|-------|
| 🔴 Critical | 1 |
| 🟠 High | 9 |
| 🟡 Medium | 1 |
| 🟢 Low | 5 |
| **Total** | **16** |

### By Category

| Category | Count |
|----------|-------|
| Container Vulnerability | 6 |
| OS Package Vulnerability | 4 |
| Broken Access Control | 4 |
| Security Misconfiguration | 1 |
| Security Vulnerability | 1 |


## Critical Findings

### 🔴 openssl: OpenSSL: Remote code execution or Denial of Service via oversized Initialization Vector in CMS parsing

**Category:** OS Package Vulnerability
**Risk Score:** 0.82 (Exploitability: 0.48, Confidence: 1.00)
**CVE:** [CVE-2025-15467](https://nvd.nist.gov/vuln/detail/CVE-2025-15467)
**CWE:** CWE-787
**Package:** libcrypto3@3.3.3-r0
**Fixed In:** 3.3.6-r0
**Sources:** Trivy Image
*Deduplicated from 14 occurrences*

**Evidence:**
```
libcrypto3@3.3.3-r0 in demo-vulnerable-api (demo-vulnerable-api (alpine 3.21.3))
```

**Reference:** https://avd.aquasec.com/nvd/cve-2025-15467

---

## High Severity Findings

### 🟠 Execute Command - Authentication Required: Test executing a command with valid authentication token

**Category:** Broken Access Control
**Risk Score:** 0.78 (Exploitability: 0.81, Confidence: 0.80)
**Endpoint:** `POST /api/execute`
**Sources:** AI Security Tester
*Deduplicated from 2 occurrences*

**Evidence:**
```
Request: POST /api/execute
Response Status: 200
Matched: Status code 200 matches expected, Missing security header: x-content-type-options, Missing security header: x-frame-options, Missing security header: strict-transport-security
Response: {"status":"executed","command":"ls /","output":"Command execution simulated"}
```

**Reference:** Implement proper authentication and authorization checks. Use middleware to verify access.

---

### 🟠 Debug Info - Authentication Required: Test getting debug info with valid authentication token

**Category:** Broken Access Control
**Risk Score:** 0.77 (Exploitability: 0.81, Confidence: 0.75)
**Endpoint:** `GET /api/debug`
**Sources:** AI Security Tester

**Evidence:**
```
Request: GET /api/debug
Response Status: 200
Matched: Status code 200 matches expected, Missing security header: x-content-type-options, Missing security header: x-frame-options, Missing security header: strict-transport-security
Response: {"env":{"NODE_ENV":"development","cwd":"/app","platform":"linux"},"users":["admin","user"],"activeSessions":0,"nodeVersion":"v18.20.8"}
```

**Reference:** Implement proper authentication and authorization checks. Use middleware to verify access.

---

### 🟠 File Read - Authentication Required: Test reading a file with valid authentication token

**Category:** Broken Access Control
**Risk Score:** 0.77 (Exploitability: 0.81, Confidence: 0.75)
**Endpoint:** `GET /api/file`
**Sources:** AI Security Tester

**Evidence:**
```
Request: GET /api/file
Response Status: 200
Matched: Status code 200 matches expected, Missing security header: x-content-type-options, Missing security header: x-frame-options, Missing security header: strict-transport-security
Response: {"path":"","content":"File read simulated","warning":"Path traversal vulnerabilities may exist"}
```

**Reference:** Implement proper authentication and authorization checks. Use middleware to verify access.

---

### 🟠 Data Retrieval by ID - Authentication Required: Test retrieving data by ID with valid authentication token

**Category:** Broken Access Control
**Risk Score:** 0.77 (Exploitability: 0.81, Confidence: 0.75)
**Endpoint:** `GET /api/data`
**Sources:** AI Security Tester

**Evidence:**
```
Request: GET /api/data
Response Status: 200
Matched: Status code 200 matches expected, Body contains "data", Missing security header: x-content-type-options, Missing security header: x-frame-options, Missing security header: strict-transport-security
Response: {"id":"","data":{"name":"Sample Data","value":42},"_debug_query":"SELECT * FROM data WHERE id = ''"}
```

**Reference:** Implement proper authentication and authorization checks. Use middleware to verify access.

---

### 🟠 cross-spawn: regular expression denial of service

**Category:** Container Vulnerability
**Risk Score:** 0.70 (Exploitability: 0.42, Confidence: 1.00)
**CVE:** [CVE-2024-21538](https://nvd.nist.gov/vuln/detail/CVE-2024-21538)
**CWE:** CWE-1333
**Package:** cross-spawn@7.0.3
**Fixed In:** 7.0.5, 6.0.6
**Sources:** Trivy Image

**Evidence:**
```
cross-spawn@7.0.3 in demo-vulnerable-api (Node.js)
```

**Reference:** https://avd.aquasec.com/nvd/cve-2024-21538

---

### 🟠 glob: glob: Command Injection Vulnerability via Malicious Filenames

**Category:** Container Vulnerability
**Risk Score:** 0.70 (Exploitability: 0.42, Confidence: 1.00)
**CVE:** [CVE-2025-64756](https://nvd.nist.gov/vuln/detail/CVE-2025-64756)
**CWE:** CWE-78
**Package:** glob@10.4.2
**Fixed In:** 11.1.0, 10.5.0
**Sources:** Trivy Image

**Evidence:**
```
glob@10.4.2 in demo-vulnerable-api (Node.js)
```

**Reference:** https://avd.aquasec.com/nvd/cve-2025-64756

---

### 🟠 npmcli: npm cli Incorrect Permission Assignment Local Privilege Escalation Vulnerability

**Category:** Container Vulnerability
**Risk Score:** 0.70 (Exploitability: 0.44, Confidence: 1.00)
**CVE:** [CVE-2026-0775](https://nvd.nist.gov/vuln/detail/CVE-2026-0775)
**CWE:** CWE-732
**Package:** npm@10.8.2
**Sources:** Trivy Image

**Evidence:**
```
npm@10.8.2 in demo-vulnerable-api (Node.js)
```

**Reference:** https://avd.aquasec.com/nvd/cve-2026-0775

---

### 🟠 node-tar: tar: node-tar: Arbitrary file overwrite and symlink poisoning via unsanitized linkpaths in archives

**Category:** Container Vulnerability
**Risk Score:** 0.70 (Exploitability: 0.42, Confidence: 1.00)
**CVE:** [CVE-2026-23745](https://nvd.nist.gov/vuln/detail/CVE-2026-23745)
**CWE:** CWE-22
**Package:** tar@6.2.1
**Fixed In:** 7.5.3
**Sources:** Trivy Image
*Deduplicated from 3 occurrences*

**Evidence:**
```
tar@6.2.1 in demo-vulnerable-api (Node.js)
```

**Reference:** https://avd.aquasec.com/nvd/cve-2026-23745

---

### 🟠 openssl: OpenSSL: Arbitrary code execution due to out-of-bounds write in PKCS#12 processing

**Category:** OS Package Vulnerability
**Risk Score:** 0.68 (Exploitability: 0.37, Confidence: 1.00)
**CVE:** [CVE-2025-69419](https://nvd.nist.gov/vuln/detail/CVE-2025-69419)
**CWE:** CWE-787
**Package:** libssl3@3.3.3-r0
**Fixed In:** 3.3.6-r0
**Sources:** Trivy Image
*Deduplicated from 12 occurrences*

**Evidence:**
```
libssl3@3.3.3-r0 in demo-vulnerable-api (demo-vulnerable-api (alpine 3.21.3))
```

**Reference:** https://avd.aquasec.com/nvd/cve-2025-69419

---

## Medium Severity Findings

### 🟡 In netstat in BusyBox through 1.37.0, local users can launch of networ ...

**Category:** OS Package Vulnerability
**Risk Score:** 0.57 (Exploitability: 0.34, Confidence: 1.00)
**CVE:** [CVE-2024-58251](https://nvd.nist.gov/vuln/detail/CVE-2024-58251)
**CWE:** CWE-150
**Package:** busybox@1.37.0-r12
**Fixed In:** 1.37.0-r14
**Sources:** Trivy Image
*Deduplicated from 4 occurrences*

**Evidence:**
```
busybox-binsh@1.37.0-r12 in demo-vulnerable-api (demo-vulnerable-api (alpine 3.21.3))
```

**Reference:** https://avd.aquasec.com/nvd/cve-2024-58251

---

## Low Severity Findings

### 🟢 X-Content-Type-Options Header Missing

**Category:** Security Misconfiguration
**Risk Score:** 0.50 (Exploitability: 0.43, Confidence: 1.00)
**Endpoint:** `GET undefined`
**CWE:** CWE-693
**Sources:** OWASP ZAP API
*Deduplicated from 5 occurrences*

**Reference:** https://learn.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/compatibility/gg622941(v=vs.85)
https://owasp.org/www-community/Security_Headers

---

### 🟢 HTTP Only Site

**Category:** Security Vulnerability
**Risk Score:** 0.49 (Exploitability: 0.43, Confidence: 0.95)
**Endpoint:** `POST undefined`
**CWE:** CWE-311
**Sources:** OWASP ZAP API

**Reference:** https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html
https://letsencrypt.org/

---

### 🟢 brace-expansion: juliangruber brace-expansion index.js expand redos

**Category:** Container Vulnerability
**Risk Score:** 0.47 (Exploitability: 0.35, Confidence: 1.00)
**CVE:** [CVE-2025-5889](https://nvd.nist.gov/vuln/detail/CVE-2025-5889)
**CWE:** CWE-400
**Package:** brace-expansion@2.0.1
**Fixed In:** 2.0.2, 1.1.12, 3.0.1, 4.0.1
**Sources:** Trivy Image

**Evidence:**
```
brace-expansion@2.0.1 in demo-vulnerable-api (Node.js)
```

**Reference:** https://avd.aquasec.com/nvd/cve-2025-5889

---

### 🟢 jsdiff: denial of service vulnerability in parsePatch and applyPatch

**Category:** Container Vulnerability
**Risk Score:** 0.47 (Exploitability: 0.35, Confidence: 1.00)
**CVE:** [CVE-2026-24001](https://nvd.nist.gov/vuln/detail/CVE-2026-24001)
**CWE:** CWE-400
**Package:** diff@5.2.0
**Fixed In:** 8.0.3, 5.2.2, 4.0.4, 3.5.1
**Sources:** Trivy Image

**Evidence:**
```
diff@5.2.0 in demo-vulnerable-api (Node.js)
```

**Reference:** https://avd.aquasec.com/nvd/cve-2026-24001

---

### 🟢 In tar in BusyBox through 1.37.0, a TAR archive can have filenames hid ...

**Category:** OS Package Vulnerability
**Risk Score:** 0.46 (Exploitability: 0.31, Confidence: 1.00)
**CVE:** [CVE-2025-46394](https://nvd.nist.gov/vuln/detail/CVE-2025-46394)
**CWE:** CWE-451
**Package:** busybox-binsh@1.37.0-r12
**Fixed In:** 1.37.0-r14
**Sources:** Trivy Image
*Deduplicated from 2 occurrences*

**Evidence:**
```
busybox-binsh@1.37.0-r12 in demo-vulnerable-api (demo-vulnerable-api (alpine 3.21.3))
```

**Reference:** https://avd.aquasec.com/nvd/cve-2025-46394

---

## Recommendations

1. Update vulnerable dependencies to their latest secure versions.
2. Review and harden security configurations, add missing security headers.
3. Implement proper authorization checks at all API endpoints.

---

*Generated by Security Bot*