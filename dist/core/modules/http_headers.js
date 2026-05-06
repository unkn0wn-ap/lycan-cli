"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.runHttpHeaders = runHttpHeaders;
const SECURITY_HEADERS = [
    {
        header: 'strict-transport-security',
        severity: 'high',
        title: 'Missing HTTP Strict Transport Security (HSTS)',
        description: 'HSTS header not found. Users may be downgraded to HTTP connections, enabling man-in-the-middle attacks.',
        remediation: 'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
        cwe: 'CWE-319',
    },
    {
        header: 'content-security-policy',
        severity: 'medium',
        title: 'Missing Content Security Policy (CSP)',
        description: 'No CSP header found. This increases the risk of XSS attacks by allowing execution of inline scripts.',
        remediation: 'Implement a strict CSP. Start with: Content-Security-Policy: default-src \'self\'',
        cwe: 'CWE-79',
    },
    {
        header: 'x-frame-options',
        severity: 'medium',
        title: 'Missing X-Frame-Options Header',
        description: 'The page can be embedded in iframes, enabling clickjacking attacks.',
        remediation: 'Add: X-Frame-Options: DENY',
        cwe: 'CWE-1021',
    },
    {
        header: 'x-content-type-options',
        severity: 'low',
        title: 'Missing X-Content-Type-Options Header',
        description: 'Browser MIME sniffing is enabled. Attackers may trick browsers into interpreting files as executable scripts.',
        remediation: 'Add: X-Content-Type-Options: nosniff',
        cwe: 'CWE-116',
    },
    {
        header: 'referrer-policy',
        severity: 'low',
        title: 'Missing Referrer-Policy Header',
        description: 'Without a Referrer-Policy, sensitive URL parameters may leak to third parties.',
        remediation: 'Add: Referrer-Policy: strict-origin-when-cross-origin',
        cwe: 'CWE-200',
    },
    {
        header: 'permissions-policy',
        severity: 'info',
        title: 'Missing Permissions-Policy Header',
        description: 'No Permissions-Policy header. Browser features (camera, microphone, geolocation) are unrestricted.',
        remediation: 'Add: Permissions-Policy: camera=(), microphone=(), geolocation=()',
        cwe: 'CWE-272',
    },
];
async function runHttpHeaders(hostname) {
    const findings = [];
    let headers = {};
    try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 10_000);
        const res = await fetch(`https://${hostname}`, {
            method: 'GET',
            redirect: 'follow',
            signal: controller.signal,
            headers: { 'User-Agent': 'Lycan-Security-Scanner/1.0' },
        });
        clearTimeout(timeout);
        res.headers.forEach((value, key) => {
            headers[key.toLowerCase()] = value;
        });
        console.log(`    [http_headers] Retrieved ${Object.keys(headers).length} headers from ${hostname}`);
        // Check each security header
        for (const check of SECURITY_HEADERS) {
            if (!headers[check.header]) {
                findings.push({
                    module: 'http_security',
                    severity: check.severity,
                    title: check.title,
                    description: check.description,
                    remediation: check.remediation,
                    cwe: check.cwe,
                });
            }
        }
        // Check for server information disclosure
        const serverHeader = headers['server'];
        if (serverHeader && /[0-9]/.test(serverHeader)) {
            findings.push({
                module: 'http_security',
                severity: 'low',
                title: 'Server Version Disclosure',
                description: `The Server header reveals version information: "${serverHeader}". This aids fingerprinting for targeted attacks.`,
                remediation: 'Configure your web server to hide version information.',
                cwe: 'CWE-200',
            });
        }
    }
    catch (err) {
        console.error('[http_headers] Fetch error:', err);
        // Fall back to HTTP
        try {
            const res = await fetch(`http://${hostname}`, {
                method: 'GET',
                redirect: 'manual',
                headers: { 'User-Agent': 'Lycan-Security-Scanner/1.0' },
            });
            res.headers.forEach((value, key) => { headers[key.toLowerCase()] = value; });
            if (!headers['location']?.startsWith('https')) {
                findings.push({
                    module: 'http_security',
                    severity: 'high',
                    title: 'HTTP Not Redirected to HTTPS',
                    description: `${hostname} serves content over HTTP without redirecting to HTTPS. Data in transit is not encrypted.`,
                    remediation: 'Configure a permanent redirect (301) from HTTP to HTTPS.',
                    cwe: 'CWE-319',
                });
            }
        }
        catch { /* ignore */ }
    }
    return findings;
}
