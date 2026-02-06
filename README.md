# Security Bot

**Attack Feasibility Analyzer** - CLI-based automated security analysis tool for REST APIs. Goes beyond vulnerability detection to answer the key question: **"Is it safe to deploy?"**

Combines static analysis, container scanning, dynamic API testing, and AI-assisted behavioral testing to provide deployment verdicts with contextual remediation.

## What Makes This Different

Most security scanners answer: *"What vulnerabilities exist?"*

Security Bot answers: **"Can an attacker actually compromise the system?"**

| Traditional Scanner | Security Bot |
|---------------------|--------------|
| Lists vulnerabilities | Analyzes attack feasibility |
| Severity-based sorting | Risk = Impact × Exploitability × Reachability × Confidence |
| Generic recommendations | Contextual remediation with code examples |
| Pass/fail on severity | **Deployment verdict: SAFE / UNSAFE / REVIEW_REQUIRED** |

## Features

- **Attack Feasibility Analysis** - Multiplicative risk scoring: reachability × exploitability × impact × confidence
- **Deployment Verdicts** - Clear SAFE/UNSAFE/REVIEW_REQUIRED decisions with reasons
- **Attack Chain Detection** - Identifies multi-step attack paths (e.g., Auth Bypass → Data Exfiltration)
- **Confirmed Exploit Tracking** - AI/dynamic testing success = auto-critical priority
- **Endpoint Correlation** - Groups findings by attack surface area
- **Contextual Remediation** - Specific fixes with code examples, not generic advice
- **Multi-Scanner Integration** - Trivy (SAST), ZAP (DAST), Container scanning, AI behavioral testing

## Quick Start

```bash
# Install
npm install
npm run build

# Start demo vulnerable API
npm run demo

# Run attack feasibility analysis
npm run scan -- -t http://localhost:3000 -v
```

## Sample Output

```
═══════════════════════════════════════════════════════════
                    SCAN RESULTS
═══════════════════════════════════════════════════════════

  SECURITY VERDICT:

  ╔════════════════════════════════════════════════════════╗
  ║            ⛔  UNSAFE TO DEPLOY  ⛔                    ║
  ╚════════════════════════════════════════════════════════╝

  Reason: Confirmed exploitation: SQL Injection, Command Injection. Active attacks succeeded during testing.

  ⚡ 2 CONFIRMED EXPLOITS:
     • SQL Injection on POST /api/data
     • Command Injection on POST /api/execute

  Attack Surface (by endpoint):

  POST /api/execute
     Risk: ████████████████████ 95%
     ├── Command Injection
     └── Attack chain: Command Injection → Full System Compromise

  POST /api/data
     Risk: ██████████████████░░ 90%
     ├── SQL Injection
     └── Attack chain: Injection → System Compromise

═══════════════════════════════════════════════════════════
  DEPLOYMENT BLOCKED
  2 confirmed exploit(s) must be fixed before deployment.
═══════════════════════════════════════════════════════════
```

## Prerequisites

### Required

- **Node.js** >= 18.0.0
- **npm** >= 8.0.0

### Optional (for full scanning capabilities)

| Tool | Purpose | Installation |
|------|---------|--------------|
| **Docker** | Container scanning, ZAP/Trivy via containers | [docker.com](https://www.docker.com/get-started) |
| **Trivy** | Static analysis & container vulnerability scanning | [trivy docs](https://aquasecurity.github.io/trivy/latest/getting-started/installation/) |
| **OWASP ZAP** | Dynamic API security testing | [zaproxy.org](https://www.zaproxy.org/download/) |
| **Ollama** | Local LLM for AI-assisted behavioral testing | [ollama.ai](https://ollama.ai/) |

### Installing Prerequisites

**Windows (with winget):**
```bash
winget install Docker.DockerDesktop
winget install AquaSecurity.Trivy
winget install Ollama.Ollama
```

**macOS (with Homebrew):**
```bash
brew install --cask docker
brew install trivy
brew install ollama
```

**Linux (Ubuntu/Debian):**
```bash
# Docker
curl -fsSL https://get.docker.com | sh

# Trivy
sudo apt-get install wget apt-transport-https gnupg lsb-release
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
echo deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main | sudo tee -a /etc/apt/sources.list.d/trivy.list
sudo apt-get update && sudo apt-get install trivy

# Ollama
curl -fsSL https://ollama.ai/install.sh | sh
```

## Installation

```bash
npm install
npm run build
```

## Usage

```bash
# Run with tsx (development)
npm run dev -- scan [options]

# Or use the scan shortcut
npm run scan -- [options]

# Or directly
npx tsx src/cli/index.ts scan [options]
```

### Commands

#### `scan`

Run attack feasibility analysis against a target API.

```bash
sec-bot scan [options]
```

**Options:**

| Option | Description |
|--------|-------------|
| `-c, --config <path>` | Path to config file (default: `security.config.yml`) |
| `-t, --target <url>` | Target URL (overrides config) |
| `-o, --output <dir>` | Output directory for reports |
| `-f, --format <formats>` | Output formats, comma-separated: `markdown`, `json` |
| `--fail-on <severity>` | Legacy: fail on severity (now uses attack feasibility) |
| `-v, --verbose` | Enable verbose output with attack chains and remediations |
| `-q, --quiet` | Suppress non-essential output |
| `--skip-static` | Skip static analysis |
| `--skip-container` | Skip container scanning |
| `--skip-dynamic` | Skip dynamic API scanning |
| `--skip-ai` | Skip AI-assisted behavioral testing |
| `-h, --help` | Display help |

### Examples

```bash
# Full attack feasibility analysis
sec-bot scan -t http://localhost:3000 -v

# Quick scan (static + container only)
sec-bot scan -t http://localhost:3000 --skip-dynamic --skip-ai

# AI-focused testing
sec-bot scan -t http://localhost:3000 --skip-static --skip-container -v

# Output reports for CI/CD integration
sec-bot scan -t http://localhost:3000 -f json,markdown -o ./reports
```

### Exit Codes

| Code | Description |
|------|-------------|
| `0` | SAFE or REVIEW_REQUIRED - no confirmed exploits |
| `1` | UNSAFE - confirmed exploits detected, deployment blocked |
| `2` | Configuration error |

## How Attack Feasibility Works

Traditional scanners use simple severity (LOW/MEDIUM/HIGH/CRITICAL). Security Bot uses **multiplicative risk scoring**:

```
risk = impact × exploitability × reachability × confidence
```

### Risk Factors

| Factor | Description | Sources |
|--------|-------------|---------|
| **Reachability** | Can attacker access this? | Endpoint analysis, auth requirements |
| **Exploitability** | Is exploit demonstrated? | AI success, ZAP active scan, CVE data |
| **Impact** | What damage is possible? | Category mapping (RCE=1.0, XSS=0.75, etc.) |
| **Confidence** | How strong is evidence? | Source type, evidence quality, deduplication |

### Confirmed Exploits

When AI or dynamic testing **successfully exploits** a vulnerability:
- Automatically marked as confirmed
- Minimum feasibility score of 0.8
- Verdict becomes UNSAFE
- Prioritized for immediate remediation

## Reports

### Security Verdict

Every report leads with the deployment decision:

```markdown
## Security Verdict

╔══════════════════════════════════════════════════════════╗
║              ⛔  UNSAFE TO DEPLOY  ⛔                     ║
╚══════════════════════════════════════════════════════════╝

**Reason:** Confirmed exploitation: SQL Injection, Command Injection.

### ⚡ Confirmed Exploits

These vulnerabilities were **actively exploited** during testing:

- **SQL Injection** on `POST /api/data`
- **Command Injection** on `POST /api/execute`
```

### Attack Surface Analysis

```markdown
| Endpoint | Risk | Vulnerabilities | Attack Feasibility |
|----------|------|-----------------|-------------------|
| `POST /api/execute` | 🔴 95% | Command Injection | High |
| `POST /api/data` | 🔴 90% | SQL Injection | High |
| `GET /api/users/:id` | 🟠 65% | Broken Access Control | Medium |
```

### Contextual Remediation

Instead of generic advice, you get specific fixes:

```markdown
### 🚨 SQL Injection

**Endpoint:** `POST /api/data`
**Priority:** IMMEDIATE

**Fix:** Parameterize query on POST /api/data for parameter 'id'

**Example:**
```javascript
// Instead of:
db.query(`SELECT * FROM users WHERE id = ${id}`);

// Use:
db.query('SELECT * FROM users WHERE id = ?', [id]);
```

## Configuration

Create a `security.config.yml` file in your project root:

```yaml
version: "1.0"

target:
  baseUrl: http://localhost:3000
  healthEndpoint: /health

  # Endpoints for AI testing (if no OpenAPI spec)
  endpoints:
    - path: /api/login
      method: POST
      body:
        username: test
        password: test
    - path: /api/users
      method: GET
      params:
        id: "1"

auth:
  type: none
  # type: jwt
  # token: ${JWT_TOKEN}

scanners:
  static:
    enabled: true
    trivy:
      severityThreshold: MEDIUM

  container:
    enabled: true
    images:
      - my-app:latest

  dynamic:
    enabled: true
    zap:
      apiScanType: api
      maxDuration: 300

  ai:
    enabled: true
    provider: ollama
    model: llama3:8b
    baseUrl: http://localhost:11434
    maxTests: 15

thresholds:
  failOn: HIGH
  warnOn: MEDIUM

reporting:
  outputDir: ./security-reports
  formats:
    - markdown
    - json
  includeEvidence: true
```

## AI-Assisted Behavioral Testing

The AI scanner is the **key differentiator**. It:
- Understands endpoint semantics and business logic
- Generates context-aware attack payloads
- Confirms exploitation with actual requests
- Provides high-confidence findings

### Why AI Findings Matter More

| Source | Confidence | Why |
|--------|------------|-----|
| Static (Trivy) | Medium | Theoretical - pattern matching |
| Dynamic (ZAP) | High | Active testing, but generic |
| **AI Tester** | Very High | Context-aware behavioral testing |

When AI successfully exploits a vulnerability, it's a **confirmed attack path**.

### Recommended Models

| System | Model | Command |
|--------|-------|---------|
| 16GB+ RAM | llama3:8b | `ollama pull llama3` |
| 8GB RAM | llama3:8b-q4 | `ollama pull llama3:8b-q4_0` |
| GPU available | codellama:13b | `ollama pull codellama:13b` |

### Starting Ollama

```bash
# Start server
ollama serve

# Pull model
ollama pull llama3

# Verify
curl http://localhost:11434/api/tags
```

## Demo

A vulnerable demo API is included:

```bash
# Start demo API (intentionally vulnerable)
npm run demo

# Run full analysis
npm run scan -- -t http://localhost:3000 -v
```

Demo vulnerabilities:
- SQL Injection
- Command Injection
- Path Traversal
- IDOR (Broken Access Control)
- Information Disclosure
- Missing Security Headers

## Project Structure

```
sec-bot/
├── src/
│   ├── cli/           # CLI commands and options
│   ├── core/          # Config loader, logger, process runner
│   ├── orchestrator/  # Scan orchestration, environment management
│   ├── scanners/      # Scanner implementations (Trivy, ZAP, AI)
│   ├── findings/      # Attack analysis, risk scoring, remediation
│   │   ├── attack.analyzer.ts  # Attack feasibility analysis
│   │   ├── risk.engine.ts      # Risk scoring
│   │   └── normalizer.ts       # Finding normalization
│   ├── reports/       # Report generators with verdict
│   └── ai/            # LLM integration, behavioral testing
├── demo/              # Vulnerable demo API
└── security.config.yml
```

## CI/CD Integration

```yaml
# GitHub Actions example
- name: Security Analysis
  run: npm run scan -- -t ${{ env.API_URL }} -f json -o ./reports

- name: Check Verdict
  run: |
    if [ $? -eq 1 ]; then
      echo "::error::Deployment blocked - confirmed exploits detected"
      exit 1
    fi
```

## Troubleshooting

### "Trivy not found"
Security Bot can use Trivy via Docker. Ensure Docker is running, or:
```bash
sec-bot scan --skip-static --skip-container
```

### "ZAP not found"
Security Bot can use ZAP via Docker (`ghcr.io/zaproxy/zaproxy`). Or:
```bash
sec-bot scan --skip-dynamic
```

### "Ollama connection refused"
```bash
ollama serve  # Start the server first
```
Or skip AI testing:
```bash
sec-bot scan --skip-ai
```

### Low-confidence findings
Run with AI enabled - it provides the highest confidence through behavioral testing:
```bash
sec-bot scan -t http://localhost:3000 -v
```

## License

MIT
