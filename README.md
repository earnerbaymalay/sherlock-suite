# Sherlock - Defensive OSINT & Attack Surface Management Suite

Sherlock is an asynchronous, modular OSINT and external attack surface management (ASM) suite designed for defensive security auditing of corporate domains, DNS infrastructure, TLS certificates, and web security posture.

## Key Features

- **Asynchronous Modular Engine**:
  - **DNS Infrastructure & Mail Hygiene**: Audits DNS records (A, AAAA, MX, NS, TXT, SOA, CAA), SPF email authentication flags, DMARC policies, and active subdomain discovery.
  - **Certificate Transparency Logs (crt.sh)**: Queries public CT logs to map all issued SSL/TLS certificates, historical hostnames, wildcards, and exposed staging/internal subdomains.
  - **Web Security Headers & TLS Audit**: Evaluates HSTS enforcement, Content-Security-Policy (CSP), X-Frame-Options, X-Content-Type-Options, Referrer-Policy, plain HTTP redirection, and server version leakage.
  - **RDAP Domain Lifecycle & Registrar**: Tracks domain registration dates, expiration timelines, registrar lock flags, and issues warnings on impending domain expirations.
  - **Surface Port Auditor**: Safe, non-intrusive TCP connectivity checks on standard web (80, 443) and administrative alternate ports (8080, 8443, 8000, 8888).
  - **Client & Vendor Due Diligence (Person & Business Modes)**: Defensive KYC/KYB identity vetting. Analyzes phone line carrier types (VOIP vs. mobile/landline), disposable burner emails, office CMRA / virtual mail-drops, global sanctions & PEP screening (OpenSanctions), corporate directorships (OpenCorporates), Australian Business Register (ABR) trust & trustee identification, and Australian court hearings & adverse media coverage.
- **Interactive Terminal User Interface (TUI)**:
  - Built with **Textual** featuring a modern terminal interface.
  - Live activity logging stream with colored severity badges.
  - Correlated findings data table with interactive modal inspection of recommendations and raw JSON payloads.
  - Discovered subdomains / hostnames table.
  - Real-time progress bar, risk score gauge (0–100), and quick filters.
  - Export to Markdown and JSON reports directly from the UI.
- **Headless CLI Mode**:
  - Run automated scans in CI/CD or scripting pipelines with `sherlock scan <domain>`.
  - Run client due diligence audits with `sherlock verify --type {business,person}`.
  - Multi-depth scanning: `quick`, `standard`, and `deep`.
  - Export reports to Markdown (`-o report.md`), JSON (`-j report.json`), and HTML (`-H report.html`).

---

## Installation & Setup

1. **Activate Python Environment**:
   ```bash
   cd /home/ebaymlay/.gemini/antigravity/scratch/sherlock_suite
   source .venv/bin/activate
   ```

2. **Install Sherlock**:
   ```bash
   uv pip install -e .
   ```

---

## Usage

### 1. Interactive Terminal User Interface (TUI)

Launch the interactive interface:
```bash
sherlock
# or
sherlock tui
```

**Keyboard Shortcuts**:
- `r`: Run Investigation
- `c`: Cancel Active Scan
- `e`: Export Reports (Markdown & JSON)
- `q`: Quit Sherlock
- `Tab` / `Shift+Tab`: Navigate controls
- `Enter` on a finding row: View finding remediation and raw data modal

### 2. Headless Automated CLI

```bash
# Standard scan
sherlock scan example.com

# Quick scan with report export
sherlock scan example.com -d quick -o report.md -j report.json

# Deep attack surface mapping
sherlock scan example.com -d deep

# Scan specific modules only
sherlock scan example.com -m dns_scanner,http_headers

# List available modules
sherlock modules
```

### 3. Client & Vendor Due Diligence (KYC / KYB)

Audit prospective clients, vendors, and individuals from partial contact information (email, phone, company, or name):

```bash
# Verify a business entity or corporate client
sherlock verify --type business \
  --company "Acme Holdings Pty Ltd" \
  --email "contact@acmeholdings.com.au" \
  --phone "+61298765432" \
  --domain "acmeholdings.com.au" \
  -o reports/acme_vetting.md

# Verify an individual principal / contractor (Person Mode)
sherlock verify --type person \
  --name "Alexander Smith" \
  --email "alex.smith@consultant.com" \
  --phone "+61412345678" \
  --company "Smith Family Trust" \
  -o reports/alex_smith_vetting.md
```

---

## Testing

Run the comprehensive pytest suite:
```bash
pytest -v
```
