# Security Bot

CLI-based automated security analysis tool for REST APIs running in Docker environments. Combines static analysis, container scanning, dynamic API testing, and AI-assisted vulnerability discovery.

## Features

- **Static Analysis** - Scan source code for vulnerabilities using Trivy
- **Container Scanning** - Detect vulnerabilities in Docker images
- **Dynamic API Testing** - Active scanning with OWASP ZAP
- **AI-Assisted Testing** - LLM-powered security test generation
- **Smart Deduplication** - Consolidate duplicate findings across scanners
- **Risk Scoring** - Prioritize findings by exploitability and confidence
- **Multiple Report Formats** - Markdown and JSON reports with CLI summary

## Prerequisites

### Required

- **Node.js** >= 18.0.0
- **npm** >= 8.0.0

### Optional (for full scanning capabilities)

| Tool | Purpose | Installation |
|------|---------|--------------|
| **Docker** | Container scanning, environment management | [docker.com](https://www.docker.com/get-started) |
| **Trivy** | Static analysis & container vulnerability scanning | [trivy docs](https://aquasecurity.github.io/trivy/latest/getting-started/installation/) |
| **OWASP ZAP** | Dynamic API security testing | [zaproxy.org](https://www.zaproxy.org/download/) |
| **Ollama** | Local LLM for AI-assisted testing | [ollama.ai](https://ollama.ai/) |

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

Run security scans against a target API.

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
| `--fail-on <severity>` | Fail if findings at this severity or above: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `-v, --verbose` | Enable debug output |
| `-q, --quiet` | Suppress non-essential output |
| `--skip-static` | Skip static analysis |
| `--skip-container` | Skip container scanning |
| `--skip-dynamic` | Skip dynamic API scanning |
| `--skip-ai` | Skip AI-assisted testing |
| `-h, --help` | Display help |

### Global Options

| Option | Description |
|--------|-------------|
| `-V, --version` | Output version number |
| `--no-color` | Disable colored output |
| `-h, --help` | Display help |

### Examples

```bash
# Scan a running API
sec-bot scan -t http://localhost:3000

# Scan with verbose output, fail on HIGH or above
sec-bot scan -t http://localhost:3000 -v --fail-on HIGH

# Scan using a custom config file
sec-bot scan -c ./my-config.yml

# Skip container and AI scanning
sec-bot scan -t http://localhost:3000 --skip-container --skip-ai

# Output only JSON report
sec-bot scan -t http://localhost:3000 -f json -o ./reports

# Run only static analysis
sec-bot scan --skip-container --skip-dynamic --skip-ai
```

### Exit Codes

| Code | Description |
|------|-------------|
| `0` | Scan completed, no findings at or above threshold |
| `1` | Findings detected at or above the `--fail-on` threshold |
| `2` | Configuration error |

## Configuration

Create a `security.config.yml` file in your project root:

```yaml
version: "1.0"

target:
  dockerCompose: ./docker-compose.yml
  # Or target a running API directly:
  # baseUrl: http://localhost:3000
  # openApiSpec: ./openapi.yaml
  healthEndpoint: /health
  healthTimeout: 60000

auth:
  type: none
  # type: jwt
  # token: ${JWT_TOKEN}
  # type: apikey
  # apiKey: ${API_KEY}
  # headerName: X-API-Key

scanners:
  static:
    enabled: true
    trivy:
      severityThreshold: MEDIUM
      ignoreUnfixed: false

  container:
    enabled: true
    images:
      - my-app:latest
    trivy:
      severityThreshold: HIGH

  dynamic:
    enabled: true
    zap:
      apiScanType: api
      maxDuration: 300

  ai:
    enabled: true
    provider: ollama
    model: llama3
    maxTests: 20

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

## AI-Assisted Testing

Security Bot can use LLMs to generate intelligent security test cases that go beyond traditional scanners.

### Supported Providers

| Provider | Configuration | Notes |
|----------|--------------|-------|
| **Ollama** (Local) | `provider: ollama` | Free, runs locally, privacy-friendly |
| **OpenAI** | `provider: openai` | Requires API key, cloud-based |
| **Anthropic** | `provider: anthropic` | Requires API key, cloud-based |

### Recommended Models for Ollama

For security testing, you need models with good reasoning capabilities and knowledge of security concepts. Here are recommendations based on your hardware:

#### High-End Systems (32GB+ RAM, GPU)

| Model | Size | Command | Best For |
|-------|------|---------|----------|
| **llama3:70b** | ~40GB | `ollama pull llama3:70b` | Best accuracy, comprehensive testing |
| **codellama:34b** | ~20GB | `ollama pull codellama:34b` | Code-focused security analysis |
| **mixtral:8x7b** | ~26GB | `ollama pull mixtral:8x7b` | Fast, good reasoning |

#### Mid-Range Systems (16GB RAM)

| Model | Size | Command | Best For |
|-------|------|---------|----------|
| **llama3:8b** | ~4.7GB | `ollama pull llama3` | Recommended default |
| **codellama:13b** | ~7GB | `ollama pull codellama:13b` | Good code understanding |
| **mistral:7b** | ~4GB | `ollama pull mistral` | Fast, efficient |

#### Low-End Systems (8GB RAM)

| Model | Size | Command | Best For |
|-------|------|---------|----------|
| **llama3:8b-q4** | ~4GB | `ollama pull llama3:8b-q4_0` | Quantized, lower memory |
| **phi3:mini** | ~2GB | `ollama pull phi3:mini` | Very fast, basic testing |
| **gemma:2b** | ~1.5GB | `ollama pull gemma:2b` | Minimal resources |

### Model Selection Tips

1. **For Injection Testing**: Use models with strong code understanding like `codellama` or `llama3`
2. **For Business Logic**: Larger models (13B+) reason better about complex scenarios
3. **For Speed**: Quantized models (q4, q5) run faster with minimal accuracy loss
4. **For Accuracy**: Full-precision larger models produce better results

### Configuration Examples

**Local Ollama (Recommended for privacy):**
```yaml
scanners:
  ai:
    enabled: true
    provider: ollama
    model: llama3
    baseUrl: http://localhost:11434
    maxTests: 20
```

**OpenAI:**
```yaml
scanners:
  ai:
    enabled: true
    provider: openai
    model: gpt-4
    # Set OPENAI_API_KEY environment variable
    maxTests: 20
```

**Anthropic:**
```yaml
scanners:
  ai:
    enabled: true
    provider: anthropic
    model: claude-3-sonnet-20240229
    # Set ANTHROPIC_API_KEY environment variable
    maxTests: 20
```

### Starting Ollama

Before running AI-assisted scans with Ollama:

```bash
# Start Ollama server
ollama serve

# In another terminal, pull your chosen model
ollama pull llama3

# Verify it's running
curl http://localhost:11434/api/tags
```

## Demo

A vulnerable demo API is included for testing:

```bash
# Start the vulnerable demo API
npm run demo

# In another terminal, run a scan against it
npm run scan -- -t http://localhost:3000 -v
```

The demo API includes intentional vulnerabilities:
- SQL Injection simulation
- Cross-Site Scripting (XSS)
- Insecure Direct Object References (IDOR)
- Command Injection simulation
- Information Disclosure
- Missing Security Headers
- Path Traversal simulation

## Running Tests

```bash
npm test
```

## Project Structure

```
sec-bot/
├── src/
│   ├── cli/           # CLI commands and options
│   ├── core/          # Config loader, logger, process runner
│   ├── orchestrator/  # Scan orchestration, environment management
│   ├── scanners/      # Scanner implementations (Trivy, ZAP, AI)
│   ├── findings/      # Finding normalization, deduplication, risk scoring
│   ├── reports/       # Report generators (JSON, Markdown, CLI)
│   └── ai/            # LLM integration, test generation
├── demo/              # Vulnerable demo API for testing
├── test/              # Integration tests
└── security.config.yml
```

## Troubleshooting

### "Trivy not found"
Install Trivy or skip static/container scanning:
```bash
sec-bot scan --skip-static --skip-container
```

### "ZAP not found"
Install OWASP ZAP or skip dynamic scanning:
```bash
sec-bot scan --skip-dynamic
```

### "Ollama connection refused"
Ensure Ollama is running:
```bash
ollama serve
```
Or skip AI scanning:
```bash
sec-bot scan --skip-ai
```

### "Docker not running"
Start Docker Desktop or skip container scanning:
```bash
sec-bot scan --skip-container
```

## License

MIT
