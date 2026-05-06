"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.runXss = runXss;
// Common XSS payloads (safe, detection-only)
const XSS_PAYLOADS = [
    {
        payload: '<script>alert(1)</script>',
        type: 'Script tag injection',
        pattern: /<script[^>]*>alert\(1\)<\/script>/i
    },
    {
        payload: '<img src=x onerror=alert(1)>',
        type: 'Event handler injection',
        pattern: /<img[^>]*onerror[^>]*alert/i
    },
    {
        payload: '"><script>alert(1)</script>',
        type: 'Attribute escape',
        pattern: /"><script[^>]*>alert\(1\)/i
    },
    {
        payload: '<svg/onload=alert(1)>',
        type: 'SVG-based XSS',
        pattern: /<svg[^>]*onload[^>]*alert/i
    },
    {
        payload: 'javascript:alert(1)',
        type: 'JavaScript protocol',
        pattern: /javascript:alert\(1\)/i
    },
];
// Content-Type patterns that should NOT reflect unescaped HTML
const VULNERABLE_CONTENT_TYPES = [
    'text/html',
    'application/xhtml+xml',
];
/**
 * Cross-Site Scripting (XSS) vulnerability scanner
 *
 * IMPORTANT: This is a passive scanner designed for:
 * - Owned domains with explicit permission
 * - Detection of reflected/stored XSS vulnerabilities
 * - Educational and legitimate security assessment purposes
 *
 * This scanner:
 * ✓ Tests common input reflection points
 * ✓ Uses safe, non-exploitative payloads
 * ✓ Checks for proper output encoding
 * ✗ Does NOT execute malicious scripts
 * ✗ Does NOT steal cookies or session data
 * ✗ Does NOT perform DOM-based XSS (requires browser)
 */
async function runXss(hostname) {
    const findings = [];
    // Common endpoints that might reflect user input
    const testEndpoints = [
        '/search?q=',
        '/?q=',
        '/results?query=',
        '/page?name=',
        '/user?name=',
        '/comment?text=',
    ];
    console.log(`    [xss] Testing ${testEndpoints.length} common endpoints on ${hostname}`);
    for (const endpoint of testEndpoints) {
        // Test a subset of payloads (not all)
        for (const { payload, type, pattern } of XSS_PAYLOADS.slice(0, 3)) {
            try {
                const url = `https://${hostname}${endpoint}${encodeURIComponent(payload)}`;
                const controller = new AbortController();
                const timeout = setTimeout(() => controller.abort(), 5000);
                const res = await fetch(url, {
                    method: 'GET',
                    redirect: 'manual',
                    signal: controller.signal,
                    headers: {
                        'User-Agent': 'Lycan-Security-Scanner/1.0',
                        'Accept': 'text/html,application/json',
                    },
                });
                clearTimeout(timeout);
                const contentType = res.headers.get('content-type') || '';
                const isHtml = VULNERABLE_CONTENT_TYPES.some(ct => contentType.toLowerCase().includes(ct));
                if (!isHtml) {
                    // Skip non-HTML responses
                    continue;
                }
                const body = await res.text();
                // Check if the payload is reflected unescaped in the response
                if (pattern.test(body)) {
                    findings.push({
                        module: 'xss',
                        severity: 'critical',
                        title: 'Reflected Cross-Site Scripting (XSS) Detected',
                        description: `The endpoint ${endpoint} reflects user input without proper sanitization or encoding. An attacker could inject malicious JavaScript that executes in victims' browsers.`,
                        payload: `${type}: ${payload}`,
                        remediation: 'Always HTML-encode user input before displaying it. Use context-appropriate encoding (HTML, JavaScript, URL). Implement Content Security Policy (CSP) headers.',
                        cwe: 'CWE-79',
                    });
                    console.log(`    [xss] ⚠️  Reflected XSS detected at ${endpoint}`);
                    // Only report once per endpoint
                    break;
                }
                // Check for unsafe reflection even if not exact match
                const unsafePatterns = [
                    /<script/i,
                    /onerror=/i,
                    /onload=/i,
                    /javascript:/i,
                ];
                if (body.includes(payload) || unsafePatterns.some(p => p.test(body))) {
                    // Payload appears in response but may be partially escaped
                    const alreadyReported = findings.some(f => f.title.includes(endpoint));
                    if (!alreadyReported) {
                        findings.push({
                            module: 'xss',
                            severity: 'high',
                            title: 'Potential XSS: Unsafe Input Reflection',
                            description: `The endpoint ${endpoint} reflects user input in the HTML response. While the payload may be partially escaped, there's a risk of XSS through encoding bypasses or DOM manipulation.`,
                            payload: `${type}: ${payload}`,
                            remediation: 'Ensure all user input is properly HTML-encoded. Use a Content Security Policy to mitigate XSS risks.',
                            cwe: 'CWE-79',
                        });
                        console.log(`    [xss] ⚠️  Potential XSS at ${endpoint}`);
                    }
                }
            }
            catch (err) {
                // Network errors are expected for invalid URLs
                continue;
            }
            // Rate limiting: wait between requests
            await new Promise(resolve => setTimeout(resolve, 200));
        }
    }
    // Additional check: Test for missing XSS protection headers
    try {
        const res = await fetch(`https://${hostname}`, {
            method: 'GET',
            redirect: 'follow',
            headers: { 'User-Agent': 'Lycan-Security-Scanner/1.0' },
        });
        const headers = res.headers;
        const csp = headers.get('content-security-policy');
        const xssProtection = headers.get('x-xss-protection');
        if (!csp) {
            // Already reported in http_headers module, so we can skip or add info severity
            // Uncomment if you want to report it here as well:
            /*
            findings.push({
              module: 'xss',
              severity: 'info',
              title: 'Missing Content Security Policy',
              description: 'No CSP header detected. This defense-in-depth measure helps prevent XSS attacks.',
              remediation: 'Implement a strict Content Security Policy.',
              cwe: 'CWE-79',
            });
            */
        }
        if (xssProtection === '0') {
            findings.push({
                module: 'xss',
                severity: 'low',
                title: 'XSS Protection Disabled',
                description: 'The X-XSS-Protection header is explicitly disabled. While deprecated in favor of CSP, this removes a legacy browser protection.',
                remediation: 'Remove the X-XSS-Protection: 0 header or set it to "1; mode=block".',
                cwe: 'CWE-79',
            });
        }
    }
    catch {
        // Ignore errors in header check
    }
    if (findings.length === 0) {
        console.log(`    [xss] No obvious XSS vulnerabilities detected`);
    }
    return findings;
}
