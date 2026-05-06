# Security Scanner Modules

This directory contains the security scanning modules for Lycan Security v2.

## Available Modules

### 1. **Reconnaissance** (`reconnaissance.ts`)
- **Purpose**: DNS and email security configuration checks
- **Checks**:
  - MX records presence
  - SPF (Sender Policy Framework) records
  - DMARC email authentication policies
- **Severity**: Info to Medium
- **CWEs**: CWE-290 (Authentication Bypass), CWE-358 (Improperly Implemented Security)

### 2. **HTTP Security Headers** (`http_headers.ts`)
- **Purpose**: Validates security-related HTTP headers
- **Checks**:
  - HSTS (HTTP Strict Transport Security)
  - Content Security Policy (CSP)
  - X-Frame-Options (clickjacking protection)
  - X-Content-Type-Options (MIME sniffing)
  - Referrer-Policy
  - Permissions-Policy
  - Server version disclosure
  - HTTP to HTTPS redirects
- **Severity**: Info to High
- **CWEs**: CWE-79 (XSS), CWE-319 (Cleartext Transmission), CWE-1021 (Clickjacking)

### 3. **Port Scanning** (`port_scan.ts`)
- **Purpose**: Identifies open ports that may expose services
- **Checks**: Tests 12 critical ports (HTTP, HTTPS, SSH, FTP, MySQL, etc.)
- **Severity**: Low to Medium
- **CWEs**: CWE-200 (Information Disclosure), CWE-306 (Missing Authentication)

### 4. **SQL Injection** (`sqli.ts`) ⚠️
- **Purpose**: Detects SQL injection vulnerabilities
- **Method**:
  - Error-based detection (database error messages)
  - Time-based blind SQLi detection
  - Tests common endpoints: search, user, product, article pages
- **Payloads**: Classic OR-based, UNION, comment injection
- **Severity**: High to Critical
- **CWEs**: CWE-89 (SQL Injection)
- **⚠️ Important**: 
  - Only tests with safe, read-only payloads
  - Does NOT exploit or extract data
  - Designed for authorized testing only

### 5. **Cross-Site Scripting (XSS)** (`xss.ts`) ⚠️
- **Purpose**: Detects XSS vulnerabilities
- **Method**:
  - Reflected XSS detection
  - Tests input reflection in HTML responses
  - Checks for missing XSS protection headers
- **Payloads**: Script tags, event handlers, SVG-based, JavaScript protocol
- **Severity**: Low to Critical
- **CWEs**: CWE-79 (Cross-Site Scripting)
- **⚠️ Important**:
  - Uses non-exploitative payloads
  - Does NOT execute malicious scripts
  - Does NOT steal data or session tokens

## Module Interface

All modules must implement the following interface:

```typescript
interface Finding {
  module: string;              // Module identifier
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;               // Short title
  description: string;         // Detailed explanation
  remediation?: string;        // How to fix
  payload?: string;            // (Optional) Test payload used
  cwe?: string;                // (Optional) CWE identifier
}

export async function runModuleName(hostname: string): Promise<Finding[]>
```

## Ethical Usage Guidelines

### ⚠️ IMPORTANT - Legal and Ethical Constraints

These scanning modules are designed for:
- ✅ **Authorized security assessments** of domains you own or have explicit permission to test
- ✅ **Compliance and vulnerability management** for your own infrastructure
- ✅ **Educational purposes** in controlled environments

These modules must **NOT** be used for:
- ❌ Testing domains without explicit written permission
- ❌ Attacking or exploiting vulnerabilities
- ❌ Unauthorized penetration testing
- ❌ Any illegal or malicious activity

**By using these modules, you agree to:**
1. Only scan domains you own or have written authorization to test
2. Respect rate limits and avoid overwhelming target servers
3. Report findings responsibly
4. Comply with all applicable laws and regulations

**Disclaimer**: Unauthorized security testing may be illegal in your jurisdiction. The developers of this software are not responsible for misuse.

## Adding New Modules

To add a new security scanning module:

1. Create a new file: `backend/core/modules/your_module.ts`
2. Implement the `Finding` interface
3. Export an async function: `export async function runYourModule(hostname: string): Promise<Finding[]>`
4. Add the import in `worker.ts`
5. Add the case in the `runModule()` switch statement
6. Update this README with module documentation

## Rate Limiting

All modules implement rate limiting to avoid overwhelming target servers:
- 200ms delay between requests
- 5-10 second timeouts per request
- Maximum 3-6 endpoints tested per module

## Testing

Test modules individually:

```bash
cd backend
npm test -- modules/sqli.test.ts
```

## References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE - Common Weakness Enumeration](https://cwe.mitre.org/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
