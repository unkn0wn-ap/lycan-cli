"use strict";
/**
 * Advanced CSRF (Cross-Site Request Forgery) Detection Module
 *
 * Checks for:
 * - Missing anti-CSRF tokens in forms
 * - Weak token implementation (predictable, not validated)
 * - Missing SameSite cookie attributes
 * - Lack of referer/origin header validation
 * - State-changing operations without protection
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.runAdvancedCsrf = runAdvancedCsrf;
const axios_1 = __importDefault(require("axios"));
const STATE_CHANGING_ENDPOINTS = [
    '/api/user/update',
    '/api/user/delete',
    '/api/user/password',
    '/api/account/delete',
    '/api/settings/update',
    '/api/profile/update',
    '/api/email/change',
    '/api/transfer',
    '/api/payment',
    '/api/order',
    '/admin/user/delete',
    '/admin/settings',
];
const FORM_ENDPOINTS = [
    '/login',
    '/register',
    '/contact',
    '/settings',
    '/profile',
    '/checkout',
    '/password-reset',
];
async function runAdvancedCsrf(hostname, config) {
    console.log(`[csrf] Running against ${hostname}`);
    const findings = [];
    const protocol = 'https://';
    const baseUrl = `${protocol}${hostname}`;
    try {
        // 1. Check for SameSite cookie attributes
        const cookieFindings = await checkCookieSameSite(baseUrl, hostname);
        findings.push(...cookieFindings);
        // 2. Test state-changing endpoints for CSRF protection
        const endpointFindings = await testStateChangingEndpoints(baseUrl, config);
        findings.push(...endpointFindings);
        // 3. Check forms for anti-CSRF tokens (enterprise/red_team only)
        if (config.userPlan === 'enterprise' || config.userPlan === 'red_team') {
            const formFindings = await checkFormProtection(baseUrl, config);
            findings.push(...formFindings);
        }
        // 4. Test for referer/origin header validation
        const headerFindings = await testRefererValidation(baseUrl, config);
        findings.push(...headerFindings);
        console.log(`[csrf] Completed with ${findings.length} findings`);
    }
    catch (error) {
        console.error('[csrf] Error:', error);
    }
    return findings;
}
async function checkCookieSameSite(baseUrl, hostname) {
    const findings = [];
    try {
        const response = await axios_1.default.get(baseUrl, {
            maxRedirects: 5,
            validateStatus: () => true,
            timeout: 10000,
        });
        const setCookieHeaders = response.headers['set-cookie'] || [];
        for (const cookieHeader of setCookieHeaders) {
            const cookieName = cookieHeader.split('=')[0];
            const hasSameSite = /SameSite=(Strict|Lax|None)/i.test(cookieHeader);
            const isSecure = /Secure/i.test(cookieHeader);
            const isHttpOnly = /HttpOnly/i.test(cookieHeader);
            // Critical: Session cookies without SameSite
            if (!hasSameSite && (cookieName.toLowerCase().includes('session') ||
                cookieName.toLowerCase().includes('token') ||
                cookieName.toLowerCase().includes('auth'))) {
                findings.push({
                    module: 'csrf',
                    severity: 'high',
                    title: `Missing SameSite Attribute on ${cookieName} Cookie`,
                    description: `The cookie "${cookieName}" does not have a SameSite attribute, making it vulnerable to CSRF attacks. Cookies without SameSite are sent with cross-site requests, allowing attackers to perform actions on behalf of authenticated users.`,
                    remediation: `Set the SameSite attribute to "Strict" or "Lax" on all session/auth cookies. Example: Set-Cookie: ${cookieName}=...; SameSite=Strict; Secure; HttpOnly`,
                    metadata: {
                        cookie: cookieName,
                        sameSite: 'none',
                        secure: isSecure,
                        httpOnly: isHttpOnly,
                    },
                });
            }
            // Medium: Any cookie without SameSite
            if (!hasSameSite && !cookieName.toLowerCase().includes('session')) {
                findings.push({
                    module: 'csrf',
                    severity: 'medium',
                    title: `Cookie Without SameSite Protection: ${cookieName}`,
                    description: `The cookie "${cookieName}" lacks SameSite protection, potentially allowing cross-site access.`,
                    remediation: `Add SameSite=Lax or SameSite=Strict to all cookies to prevent CSRF.`,
                    metadata: {
                        cookie: cookieName,
                        sameSite: 'none',
                    },
                });
            }
        }
    }
    catch (error) {
        // Silent fail - target may not be accessible
    }
    return findings;
}
async function testStateChangingEndpoints(baseUrl, config) {
    const findings = [];
    const endpointsToTest = config.userPlan === 'enterprise' || config.userPlan === 'red_team'
        ? STATE_CHANGING_ENDPOINTS
        : STATE_CHANGING_ENDPOINTS.slice(0, 5);
    for (const endpoint of endpointsToTest) {
        try {
            // Test POST without CSRF token
            const response = await axios_1.default.post(`${baseUrl}${endpoint}`, {
                test: 'csrf_probe',
            }, {
                headers: {
                    'Content-Type': 'application/json',
                    // Deliberately omit common CSRF headers
                },
                validateStatus: () => true,
                timeout: 8000,
                maxRedirects: 0,
            });
            // Only report if endpoint actually exists and processed the request
            // 404 = doesn't exist, 307/302 = redirect (likely to login), 401/403 = auth protected
            const isRealEndpoint = response.status >= 200 && response.status < 300 &&
                response.status !== 204;
            const hasProcessedRequest = response.data && JSON.stringify(response.data).length > 50;
            if (isRealEndpoint && hasProcessedRequest) {
                findings.push({
                    module: 'csrf',
                    severity: 'high',
                    title: `Potential CSRF on ${endpoint}`,
                    description: `The endpoint ${endpoint} accepted a POST request without apparent CSRF token validation. This could allow attackers to forge requests from victim browsers.`,
                    remediation: `Implement anti-CSRF tokens on all state-changing operations. Use frameworks like Django CSRF, Express CSRF, or implement custom token validation.`,
                    metadata: {
                        endpoint,
                        method: 'POST',
                        status: response.status,
                    },
                });
            }
        }
        catch (error) {
            // Endpoint doesn't exist or network error - skip
        }
    }
    return findings;
}
async function checkFormProtection(baseUrl, config) {
    const findings = [];
    const formsToCheck = config.userPlan === 'enterprise' || config.userPlan === 'red_team'
        ? FORM_ENDPOINTS
        : FORM_ENDPOINTS.slice(0, 3);
    for (const formPath of formsToCheck) {
        try {
            const response = await axios_1.default.get(`${baseUrl}${formPath}`, {
                validateStatus: () => true,
                timeout: 8000,
            });
            if (response.status === 200 && typeof response.data === 'string') {
                const html = response.data.toLowerCase();
                // Check for forms
                const hasForm = /<form/i.test(html);
                const hasPostForm = /<form[^>]*method=['"]?post/i.test(html);
                if (hasPostForm) {
                    // Look for common CSRF token patterns
                    const hasCsrfToken = /csrf|_token|authenticity_token|__requestverificationtoken/i.test(html);
                    if (!hasCsrfToken) {
                        findings.push({
                            module: 'csrf',
                            severity: 'medium',
                            title: `Form Without CSRF Token at ${formPath}`,
                            description: `The form at ${formPath} does not appear to include an anti-CSRF token. This could allow attackers to submit forged requests.`,
                            remediation: `Add CSRF tokens to all forms. Use hidden input fields with unpredictable tokens that are validated server-side.`,
                            metadata: {
                                endpoint: formPath,
                                method: 'POST',
                            },
                        });
                    }
                }
            }
        }
        catch (error) {
            // Skip inaccessible forms
        }
    }
    return findings;
}
async function testRefererValidation(baseUrl, config) {
    const findings = [];
    try {
        // Test if server validates Referer header
        const response = await axios_1.default.post(`${baseUrl}/api/test`, {
            probe: 'csrf',
        }, {
            headers: {
                'Referer': 'https://evil.com',
                'Origin': 'https://evil.com',
            },
            validateStatus: () => true,
            timeout: 8000,
            maxRedirects: 0,
        });
        // If request is accepted despite foreign referer, it's vulnerable
        if (response.status >= 200 && response.status < 400) {
            findings.push({
                module: 'csrf',
                severity: 'medium',
                title: 'Missing Referer/Origin Validation',
                description: 'The server accepts requests with foreign Referer/Origin headers, indicating lack of CSRF protection through header validation.',
                remediation: 'Implement server-side validation of Referer and Origin headers for state-changing operations. Reject requests from unexpected origins.',
                metadata: {
                    refererPolicy: 'not-validated',
                },
            });
        }
    }
    catch (error) {
        // Endpoint doesn't exist - not necessarily a vulnerability
    }
    return findings;
}
